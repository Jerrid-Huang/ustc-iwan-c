/*
 * iWAN kernel data plane supervisor (Linux only). See kdp.h for the design.
 *
 * division of labor vs the TUN pump (proxy.c run_pump):
 *   same: route expansion/hijack and rollback, process-level stop handling, 10s keepalive sends,
 *         IWAN_RX_STALE_MS death detection, three-state return code;
 *   different: no TUN fd, no reader/writer threads; the data plane is fully in the kernel, userspace only
 *         1s polls /dev/iwan's last_rx_ms + drains the optional events group every 1s.
 */

#if defined(__linux__)

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>	/* kdp_bind_ok: read interface/address state live from the kernel */
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../kernel/iwan_shm.h"
#include "common.h"
#include "genl_iwan.h"
#include "kdp.h"
#include "reply_route.h"
#include "protocol.h"
#include "echo.h"
#include "proxy.h"
#include "route.h"
#include "util.h"

/* Shared memory poll period (decision: 1s) and loop yield granularity (Ctrl-C response).
 * The death threshold/keepalive period are not copied here: use the same accessors exported by proxy.c, to avoid
 * the two data planes drifting on IWAN_RX_STALE_MS semantics. */
#define KDP_POLL_MS  1000u
#define KDP_SLEEP_MS 100u

/* The module always uses it (the DEVNAME in the SESSION_UP reply is authoritative; this is only used for the pre-startup
 * ownership precheck) */
#define KDP_DEV_DEFAULT "iwan0"

struct kdp {
    int         sockfd;
    genl_iwan  *genl;
    uint16_t    sid;
    uint32_t    tok;
    uint8_t     enc;
    const char *server;

    genl_iwan_session sess;
    char        dev[IFNAMSIZ];
    uint32_t    dev_mtu;

    const char *auth_tun_ip;
    uint16_t    auth_mtu;

    int             shm_fd;
    const uint8_t  *shm;
    size_t          shm_len;

    char    ogw[16];
    char    odev[16];
    char    ogw_metric[16];
    slist_t routes;
    slist_t routes6;
    bool    had_routes;

    /* Carrier NIC bind (filled by the caller, see kdp_bind in kdp.h): written into
     * sess.oif/sess.bind_ip, validity re-checked on every 1s tick. */
    kdp_bind bind;

    bool    session_up;
    bool    routes_up;
    bool    shm_ok;
    bool    events_ok;
    bool    session_lost;
    reply_route_state rr;      /* reply route (conntrack) state */
};

/* ------------------------------------------------------------ helpers */

static uint64_t ms_since(uint64_t now, uint64_t then)
{
    return now > then ? now - then : 0;
}

/* Process-level stop handling: the same set as run_pump (port_set_stop_handler + shared
 * g_stop/g_user_stop), so the reconnect loop's three-state semantics match exactly. */
static void kdp_on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
    g_user_stop = 1;
}

/* Same shape as run_pump's send_ctrl (same 24B signed control frame, same session socket).
 * In kernel mode the socket stays blocking (only one control frame every 10s); no GSO handling. */
/* ---------------------------------------------------------- bind validity
 *
 * Criteria are read live from the kernel each time (getifaddrs); no "last seen address/state" is stored:
 * the kernel is the source of truth for address and link state; a userspace cache only creates two truths.
 *   - bound IP: the address must still be on some local interface, and that interface must be UP with carrier;
 *   - bound NIC: the interface must exist, and be UP with carrier.
 * IFF_RUNNING is the link carrier (the same fact as IFF_LOWER_UP): when carrier is lost the device is still
 * UP, and the kernel-side outer lookup still succeeds, so packets are dropped by the link layer with no error returned -- this is
 * the data plane's only failure branch with no signal, and it can only be detected here. veth carrier is always up,
 * so the test range cannot hit this branch (a real NIC is required).
 */
static bool ifa_flags_ok(const char *name, unsigned flags, char *why,
                         size_t whysz)
{
    if (!(flags & IFF_UP)) {
        snprintf(why, whysz, "carrier NIC %s is down (flags=0x%x)", name, flags);
        return false;
    }
    if (!(flags & IFF_RUNNING)) {
        snprintf(why, whysz, "carrier NIC %s has no carrier (flags=0x%x)", name, flags);
        return false;
    }
    return true;
}

bool kdp_bind_ok(const kdp_bind *b, char *why, size_t whysz)
{
    struct ifaddrs *ifa0 = NULL;
    struct ifaddrs *ifa;
    bool seen_dev = false;
    bool ok = true;

    if (b == NULL || (b->oif == 0 && b->bind_ip == 0 && !b->bind_v6 &&
                      IN6_IS_ADDR_UNSPECIFIED(&b->bind_ip6)))
        return true;
    if (why != NULL && whysz != 0)
        why[0] = '\0';
    if (getifaddrs(&ifa0) != 0)
        return true;	/* state unknown: do nothing; the kernel side provides correctness as fallback */

    for (ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL)
            continue;
        if (b->bind_v6) {
            /* outer v6 bound IP: same criteria, the address is 16 bytes */
            const struct sockaddr_in6 *sin6;
            char a6[INET6_ADDRSTRLEN];

            if (ifa->ifa_addr == NULL ||
                ifa->ifa_addr->sa_family != AF_INET6)
                continue;
            sin6 = (const struct sockaddr_in6 *)(const void *)ifa->ifa_addr;
            if (!IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, &b->bind_ip6))
                continue;
            if (b->oif != 0 && if_nametoindex(ifa->ifa_name) != b->oif) {
                if (why != NULL && whysz != 0)
                    snprintf(why, whysz,
                             "bound egress IP %s is not on carrier NIC %s (it is on %s)",
                             inet_ntop(AF_INET6, &b->bind_ip6, a6,
                                       sizeof(a6)),
                             b->dev != NULL ? b->dev : "(ifindex)",
                             ifa->ifa_name);
                ok = false;
                seen_dev = true;
                break;
            }
            if (!ifa_flags_ok(ifa->ifa_name, ifa->ifa_flags, why, whysz))
                ok = false;
            seen_dev = true;
            break;
        }
        if (b->bind_ip != 0) {
            const struct sockaddr_in *sin;

            if (ifa->ifa_addr == NULL ||
                ifa->ifa_addr->sa_family != AF_INET)
                continue;
            sin = (const struct sockaddr_in *)(const void *)ifa->ifa_addr;
            if (ntohl(sin->sin_addr.s_addr) != b->bind_ip)
                continue;
            /* When a NIC is also given the two must point to the same interface (the kernel side likewise returns -EINVAL
             * and rejects; this reports a more specific reason one step earlier). */
            if (b->oif != 0 &&
                if_nametoindex(ifa->ifa_name) != b->oif) {
                if (why != NULL && whysz != 0) {
                    struct in_addr a;

                    a.s_addr = htonl(b->bind_ip);
                    snprintf(why, whysz,
                             "bound egress IP %s is not on carrier NIC %s (it is on %s)",
                             inet_ntop(AF_INET, &a,
                                       (char[INET_ADDRSTRLEN]){0},
                                       INET_ADDRSTRLEN),
                             b->dev != NULL ? b->dev : "(ifindex)",
                             ifa->ifa_name);
                }
                ok = false;
                seen_dev = true;
                break;
            }
            if (!ifa_flags_ok(ifa->ifa_name, ifa->ifa_flags, why, whysz))
                ok = false;
            seen_dev = true;
            break;
        }
        if (b->dev != NULL ? strcmp(ifa->ifa_name, b->dev) != 0
                           : if_nametoindex(ifa->ifa_name) != b->oif)
            continue;
        if (!ifa_flags_ok(ifa->ifa_name, ifa->ifa_flags, why, whysz))
            ok = false;
        seen_dev = true;
        break;
    }
    freeifaddrs(ifa0);
    if (!seen_dev) {
        if (why != NULL && whysz != 0) {
            if (b->bind_v6) {
                char a6[INET6_ADDRSTRLEN];

                snprintf(why, whysz, "bound egress IP %s is no longer in the local address table",
                         inet_ntop(AF_INET6, &b->bind_ip6, a6, sizeof(a6)));
            } else if (b->bind_ip != 0) {
                struct in_addr a;

                a.s_addr = htonl(b->bind_ip);
                snprintf(why, whysz,
                         "bound egress IP %s is no longer in the local address table",
                         inet_ntop(AF_INET, &a, (char[INET_ADDRSTRLEN]){0},
                                   INET_ADDRSTRLEN));
            } else {
                snprintf(why, whysz, "bound carrier NIC %s no longer exists",
                         b->dev != NULL ? b->dev : "(ifindex)");
            }
        }
        return false;
    }
    return ok;
}

void kdp_bind_wait(const kdp_bind *b)
{
    char why[256];

    for (;;) {
        if (kdp_bind_ok(b, why, sizeof(why)))
            return;
        log_err("kernel data plane: bind not usable yet (%s), waiting for recovery before the handshake", why);
        port_sleep_ms(1000);
        if (g_user_stop)
            return;
    }
}

static int kdp_send_ctrl(const struct kdp *k, uint8_t typ)
{
    buf_t pkt;
    size_t want;
    ssize_t r;

    buf_init(&pkt);
    if (typ == PT_ECHO_REQ) {
        /* The official client's ECHOREQ is 8+16+36=60 bytes: the tick in the payload lets the peer
         * echo it back verbatim so latency can be measured. Kernel data plane RX is in the kernel, ECHO_RES is unavailable,
         * so here we only send the payload and keep no statistics -- but the length and tick must match the official client,
         * otherwise the peer may treat it as a short frame. */
        iwan_echo_build(&pkt, typ, k->enc, k->sid, k->tok, NULL, now_us());
    } else {
        ctrl_hdr(&pkt, typ, k->enc, k->sid, k->tok);
    }
    want = pkt.len;
    r = port_send(k->sockfd, pkt.data, want, 0);
    buf_free(&pkt);
    return (r < 0 || (size_t)r != want) ? -1 : 0;
}

/* ------------------------------------------------------------ /dev/iwan */

static void kdp_shm_close(struct kdp *k)
{
    if (k->shm != NULL) {
        munmap((void *)(uintptr_t)k->shm, k->shm_len);
        k->shm = NULL;
    }
    if (k->shm_fd >= 0) {
        close(k->shm_fd);
        k->shm_fd = -1;
    }
    k->shm_ok = false;
}

/* Open and read-only map this netns's shared memory page. When /dev/iwan is absent, **report an explicit error**,
 * do not silently degrade to TUN (decision 6). Must be called before SESSION_UP: once a session is established,
 * the hook starts swallowing packets, and finding out then that monitoring is unavailable is too late. */
static bool kdp_shm_open(struct kdp *k, char *err, size_t errsz)
{
    void *p;
    long pg;
    uint32_t ver = 0;

    k->shm_fd = open("/dev/iwan", O_RDONLY | O_CLOEXEC);
    if (k->shm_fd < 0) {
        if (errno == ENOENT)
            snprintf(err, errsz,
                     "kernel data plane needs /dev/iwan (shared memory page), but the device does not exist.\n"
                     "  Please load a kernel module built from the same batch as this client"
                     " (sudo insmod kernel/iwan.ko),\n"
                     "  or switch to --data-plane tun");
        else if (errno == EACCES || errno == EPERM)
            snprintf(err, errsz,
                     "opening /dev/iwan was denied: %s (read permission on that device is required)",
                     strerror(errno));
        else
            snprintf(err, errsz, "opening /dev/iwan failed: %s", strerror(errno));
        return false;
    }
    pg = sysconf(_SC_PAGESIZE);
    k->shm_len = pg > 0 ? (size_t)pg : 4096u;
    p = mmap(NULL, k->shm_len, PROT_READ, MAP_SHARED, k->shm_fd, 0);
    if (p == MAP_FAILED) {
        snprintf(err, errsz, "mmap(/dev/iwan) failed: %s", strerror(errno));
        close(k->shm_fd);
        k->shm_fd = -1;
        return false;
    }
    k->shm = (const uint8_t *)p;
    memcpy(&ver, k->shm + IWAN_SHM_OFF_VERSION, sizeof(ver));
    if (ver != (uint32_t)IWAN_SHM_VERSION) {
        snprintf(err, errsz,
                 "/dev/iwan shared memory layout version %u does not match the %u this client expects:"
                 " the kernel module and the client were not built from the same batch",
                 ver, (unsigned)IWAN_SHM_VERSION);
        kdp_shm_close(k);
        return false;
    }
    k->shm_ok = true;
    return true;
}

/* Monotonic milliseconds of the last frame that passed the credential gate; 0 = never received / disconnected.
 * Same time base as now_ms() (ktime_get_mono_fast_ns converted); the aligned 64-bit read uses an
 * atomic builtin to avoid torn values on 32-bit platforms. */
static uint64_t kdp_shm_last_rx(const struct kdp *k)
{
    if (!k->shm_ok || k->shm == NULL)
        return 0;
    return __atomic_load_n(
        (const uint64_t *)(const void *)(k->shm + IWAN_SHM_OFF_LAST_RX_MS),
        __ATOMIC_RELAXED);
}

/* ------------------------------------------- pre-startup precheck (before the handshake) */

static bool kdp_precheck_device(char *err, size_t errsz);

/* Does the shared memory page say "this session is still in use recently"?
 *
 * Only three fields are used as criteria: enabled=1 (session-level data plane toggle), last_rx_ms non-zero, and
 * less than 2x keepalive ago (10s -> 20s). Reading the timestamp cannot distinguish "just established, no frame received yet" from
 * "a crash leftover that never received a frame", so a session is live only when "a frame was really received recently"; older sessions are
 * treated as leftover and still falling back to the SESSION_UP conflict check -- the precheck must never block leftover sessions, otherwise
 * after one SIGKILL the client can never start again (the scenario covered by the E2 test case).
 *
 * age_ms (may be NULL) receives "how many milliseconds since the last frame received"; 0 means never received. */
static bool kdp_session_is_live(const struct kdp *k, uint64_t *age_ms)
{
    uint32_t enabled = 0;
    uint64_t last_rx;
    uint64_t now;
    uint64_t age;

    if (age_ms != NULL)
        *age_ms = 0;
    if (!k->shm_ok || k->shm == NULL)
        return false;
    memcpy(&enabled, k->shm + IWAN_SHM_OFF_ENABLED, sizeof(enabled));
    last_rx = kdp_shm_last_rx(k);
    now = now_ms();
    age = (last_rx != 0 && now > last_rx) ? now - last_rx : 0;
    if (age_ms != NULL)
        *age_ms = age;
    return enabled != 0 && last_rx != 0 && now > last_rx &&
           age < (uint64_t)pump_keepalive_ms() * 10u;
}

/* Precheck body: the two things after the shared memory page is mapped (k->shm_ok) -- whether this netns
 * already has a live session, and iwan0 ownership. kdp_run and kdp_plane_precheck share the same criteria and
 * error text, so the two paths cannot drift. */
static bool kdp_precheck_core(const struct kdp *k, char *err, size_t errsz,
                              bool *busy)
{
    uint64_t age = 0;

    if (busy != NULL)
        *busy = false;
    if (kdp_session_is_live(k, &age)) {
        snprintf(err, errsz,
                 "this netns already has a live session: a peer frame was received %llu ms ago"
                 " (enabled=1, live window %u ms).\n"
                 "  Sessions of the iwan kernel module are **singleton per netns**: "
                 "a netns can have only one kernel session.\n"
                 "  Please stop that client first (Ctrl-C), or run in another netns; "
                 "if you are sure it is a crash leftover, clear it with sudo iwan_ctl session-down and retry.",
                 (unsigned long long)age, pump_keepalive_ms() * 10u);
        if (busy != NULL)
            *busy = true;
        return false;
    }
    return kdp_precheck_device(err, errsz);
}

bool kdp_plane_precheck(char *err, size_t errsz, bool *busy)
{
    struct kdp k;
    bool ok;

    if (busy != NULL)
        *busy = false;
    memset(&k, 0, sizeof k);
    k.shm_fd = -1;
    /* /dev/iwan missing / permission / layout version mismatch errors are reported by kdp_shm_open, identical
     * kdp_run's counterpart; here it is only borrowed for one temporary mapping, closed right after reading. */
    if (!kdp_shm_open(&k, err, errsz))
        return false;
    ok = kdp_precheck_core(&k, err, errsz, busy);
    kdp_shm_close(&k);
    return ok;
}

/* The module's SESSION_UP conflict error comes from kernel/iwan_netlink.c's extack
 * ("SESSION_UP conflicts with an existing session (<field> differs)", asserted in e2e). Use it to
 * "existing session" failures apart from "invalid parameter / device busy": the former must not fall back to TUN
 * (falling back would use the same account to kick that session out), the latter may. A wording change does not make it dangerous --
 * when unrecognized it is treated as "not busy"; falling back to TUN then fails out while iwan0 is held by the module. */
static bool kdp_err_is_conflict(const char *err)
{
    return err != NULL && strstr(err, "\xe5\x86\xb2\xe7\xaa\x81") != NULL;
}

/* --------------------------------------------------- device ownership precheck */

/* `ip -d link show dev iwan0`'s detail line gives kind (a TUN device is
 * "tun type tun ...", a module-created interface is "iwan"). ARPHRD is 65534 for both, so the name/
 * type cannot distinguish them; only this line can be inspected.
 *
 * Three outcomes:
 *   device does not exist  -> allow (SESSION_UP creates it on demand)
 *   kind == "iwan"    -> allow
 *   kind is something else -> hard error (case where local iwan0 is occupied as a TUN by a real tunnel)
 *   iproute2 gave no kind -> allow + debug hint (old iproute2; here the
 *                        SESSION_UP -EBUSY/-EEXIST path is the fallback) */
static bool kdp_precheck_device(char *err, size_t errsz)
{
    char *out;
    char kind[64] = "";
    bool have_detail = false;
    char *line;
    int lineno = 0;

    out = cmd_capture((char *[]){ "-d", "link", "show", "dev",
                                  KDP_DEV_DEFAULT, NULL });
    if (out == NULL) {
        /* Device does not exist, or `ip` itself is unavailable (continue in both cases: the routing code will
         * report the real cause afterwards) */
        return true;
    }
    line = out;
    while (line != NULL && *line != '\0') {
        char *nl = strchr(line, '\n');

        if (nl != NULL)
            *nl = '\0';
        if (lineno > 0) {
            const char *p = line;
            size_t i = 0;

            while (*p == ' ' || *p == '\t')
                p++;
            while (p[i] != '\0' && p[i] != ' ' && p[i] != '\t' &&
                   i + 1 < sizeof(kind)) {
                kind[i] = p[i];
                i++;
            }
            kind[i] = '\0';
            if (kind[0] != '\0') {
                have_detail = true;
                break;
            }
        }
        lineno++;
        if (nl == NULL)
            break;
        line = nl + 1;
    }

    if (have_detail && strcmp(kind, "iwan") != 0) {
        snprintf(err, errsz,
                 "%s already exists, but it is not a device created by the iwan kernel module"
                 " (ip -d shows type \"%s\"):\n"
                 "  The kernel data plane always uses %s; the module will not take over someone else's device"
                 " (it returns -EBUSY).\n"
                 "  Please delete it first (sudo ip link del %s) and retry, "
                 "or switch to --data-plane tun",
                 KDP_DEV_DEFAULT, kind, KDP_DEV_DEFAULT, KDP_DEV_DEFAULT);
        free(out);
        return false;
    }
    if (!have_detail)
        log_debug("kernel data plane: %s exists but ip -d gave no kind, "
                  "cannot precheck ownership (SESSION_UP is the fallback)", KDP_DEV_DEFAULT);
    free(out);
    return true;
}

/* --------------------------------------------------- session 5-tuple */

/* dport = server port, sport = actual local port, outer_src = local outer address,
 * all taken from the connected socket itself (getsockname/getpeername):
 *   - module TX uses SPORT as source port, RX matches "destination port = SPORT",
 *     outer_src is also the basis for the peer binding; getting either wrong causes drift;
 *   - session parameters are fixed from the first SESSION_UP, so the values taken here stay
 *     unchanged for the whole session lifetime (reconnect with a new port -> SESSION_DOWN first, see kdp_teardown). */
/* Parse the --server literal into a v6 address: accepts both a bare address and the [address] form (the same
 * cli_common.c check_server_ip set). A link-local literal with %scope is
 * rejected here: the kernel ABI's outer v6 attribute is only a 16-byte address with no scope_id, so a link-
 * local outer cannot be guaranteed to reach the right interface in the data plane. */
static bool kdp_server_ip6(const char *s, struct in6_addr *out)
{
    char buf[INET6_ADDRSTRLEN];
    size_t n;

    if (s == NULL)
        return false;
    n = strlen(s);
    if (n >= 2 && s[0] == '[' && s[n - 1] == ']') {
        s++;
        n -= 2;
    }
    if (n == 0 || n >= sizeof(buf) || memchr(s, '%', n) != NULL)
        return false;
    memcpy(buf, s, n);
    buf[n] = '\0';
    return inet_pton(AF_INET6, buf, out) == 1;
}

static bool kdp_socket_params(struct kdp *k, char *err, size_t errsz)
{
    struct sockaddr_storage local;
    struct sockaddr_storage peer;
    socklen_t sl;
    char src_s[INET6_ADDRSTRLEN + 8] = "";
    char dst_s[INET6_ADDRSTRLEN + 8] = "";

    memset(&local, 0, sizeof(local));
    memset(&peer, 0, sizeof(peer));
    sl = (socklen_t)sizeof(local);
    if (getsockname(k->sockfd, (struct sockaddr *)(void *)&local, &sl) != 0) {
        snprintf(err, errsz, "getsockname on the session socket failed: %s", strerror(errno));
        return false;
    }
    sl = (socklen_t)sizeof(peer);
    if (getpeername(k->sockfd, (struct sockaddr *)(void *)&peer, &sl) != 0) {
        snprintf(err, errsz, "getpeername on the session socket failed: %s", strerror(errno));
        return false;
    }
    if (local.ss_family != peer.ss_family) {
        snprintf(err, errsz,
                 "session socket has mismatched address families (local %d, peer %d)",
                 (int)local.ss_family, (int)peer.ss_family);
        return false;
    }
    if (local.ss_family == AF_INET) {
        const struct sockaddr_in *l4 =
            (const struct sockaddr_in *)(const void *)&local;
        const struct sockaddr_in *p4 =
            (const struct sockaddr_in *)(const void *)&peer;
        uint8_t b4[4];
        uint32_t src = ntohl(l4->sin_addr.s_addr);
        uint32_t dst = ntohl(p4->sin_addr.s_addr);

        /* The outer version is decided by the session family: a v4 session must explicitly zero the v6 side (the struct is
         * memset by the caller; clearing again here avoids relying on that precondition). */
        k->sess.outer_v6 = false;
        memset(&k->sess.outer_src6, 0, sizeof(k->sess.outer_src6));
        memset(&k->sess.outer_dst6, 0, sizeof(k->sess.outer_dst6));
        k->sess.outer_src = src;
        k->sess.outer_dst = dst;
        k->sess.sport = ntohs(l4->sin_port);
        k->sess.dport = ntohs(p4->sin_port);

        if (k->sess.sport == 0 || k->sess.dport == 0) {
            snprintf(err, errsz,
                     "session socket ports incomplete (sport=%u dport=%u): socket not connected?",
                     (unsigned)k->sess.sport, (unsigned)k->sess.dport);
            return false;
        }
        if (src == 0) {
            snprintf(err, errsz, "session socket local address is still 0.0.0.0: connect first");
            return false;
        }
        /* Loopback outer is unusable: a loopback packet sent by this host re-enters its own hook and is swallowed
         * (the same-host topology trap in CONTROL-PLANE.md and tests/tun_local_test.sh). */
        if ((src >> 24) == 127u || (dst >> 24) == 127u) {
            (void)inet_ntop(AF_INET, &l4->sin_addr, src_s, sizeof(src_s));
            (void)inet_ntop(AF_INET, &p4->sin_addr, dst_s, sizeof(dst_s));
            snprintf(err, errsz,
                     "outer address is a loopback address (local %s, peer %s): loopback packets re-enter "
                     "the local hook and are swallowed,\n  the kernel data plane cannot be used for same-host loopback topology. "
                     "Use two netns interconnected by veth (see kernel/tests/netlink_test.sh)",
                     src_s, dst_s);
            return false;
        }
        /* route_setup must install a /32 pin for the server via the physical gateway; the address must match the actual peer
         * otherwise outer packets hit the hijacked default dev iwan0 and are dropped by the loop check. */
        if (!s2ip4(k->server, b4)) {
            snprintf(err, errsz, "server address '%s' is not a valid IPv4 literal",
                     k->server);
            return false;
        }
        if (ip4_u32(b4) != dst) {
            (void)inet_ntop(AF_INET, &p4->sin_addr, dst_s, sizeof(dst_s));
            snprintf(err, errsz,
                     "--server %s does not match the socket's actual peer %s; "
                     "the outer address must match the server's /32 pin",
                     k->server, dst_s);
            return false;
        }
        return true;
    }
    if (local.ss_family == AF_INET6) {
        const struct sockaddr_in6 *l6 =
            (const struct sockaddr_in6 *)(const void *)&local;
        const struct sockaddr_in6 *p6 =
            (const struct sockaddr_in6 *)(const void *)&peer;
        struct in6_addr want;

        /* Outer v6: endpoints are taken directly from both ends of the connected socket (same source of truth as v4,
         * no need to consult the routing table again -- this is exactly the path the handshake takes) */
        k->sess.outer_v6 = true;
        k->sess.outer_src = 0;
        k->sess.outer_dst = 0;
        k->sess.outer_src6 = l6->sin6_addr;
        k->sess.outer_dst6 = p6->sin6_addr;
        k->sess.sport = ntohs(l6->sin6_port);
        k->sess.dport = ntohs(p6->sin6_port);

        if (k->sess.sport == 0 || k->sess.dport == 0) {
            snprintf(err, errsz,
                     "session socket ports incomplete (sport=%u dport=%u): socket not connected?",
                     (unsigned)k->sess.sport, (unsigned)k->sess.dport);
            return false;
        }
        if (IN6_IS_ADDR_UNSPECIFIED(&l6->sin6_addr)) {
            snprintf(err, errsz, "session socket local address is still ::: connect first");
            return false;
        }
        if (IN6_IS_ADDR_V4MAPPED(&l6->sin6_addr) ||
            IN6_IS_ADDR_V4MAPPED(&p6->sin6_addr)) {
            (void)inet_ntop(AF_INET6, &p6->sin6_addr, dst_s, sizeof(dst_s));
            snprintf(err, errsz,
                     "session socket is a v4-mapped address (peer %s): a v4 outer should use "
                     "AF_INET socket", dst_s);
            return false;
        }
        if (IN6_IS_ADDR_LINKLOCAL(&l6->sin6_addr) ||
            IN6_IS_ADDR_LINKLOCAL(&p6->sin6_addr)) {
            (void)inet_ntop(AF_INET6, &l6->sin6_addr, src_s, sizeof(src_s));
            (void)inet_ntop(AF_INET6, &p6->sin6_addr, dst_s, sizeof(dst_s));
            snprintf(err, errsz,
                     "outer v6 does not support link-local addresses (local %s, peer %s): the kernel ABI "
                     "outer v6 attribute\n  is only a 16-byte address without scope_id, so it cannot "
                     "be guaranteed to reach the right interface. Give the server a global or unique-local address",
                     src_s, dst_s);
            return false;
        }
        if (IN6_IS_ADDR_LOOPBACK(&l6->sin6_addr) ||
            IN6_IS_ADDR_LOOPBACK(&p6->sin6_addr)) {
            (void)inet_ntop(AF_INET6, &l6->sin6_addr, src_s, sizeof(src_s));
            (void)inet_ntop(AF_INET6, &p6->sin6_addr, dst_s, sizeof(dst_s));
            snprintf(err, errsz,
                     "outer address is a loopback address (local %s, peer %s): loopback packets re-enter "
                     "the local hook and are swallowed,\n  the kernel data plane cannot be used for same-host loopback topology.",
                     src_s, dst_s);
            return false;
        }
        if (!kdp_server_ip6(k->server, &want)) {
            snprintf(err, errsz,
                     "server address '%s' is not a valid IPv6 literal (an outer v6 session requires "
                     "a literal; link-local %%scope form is not supported)", k->server);
            return false;
        }
        if (!IN6_ARE_ADDR_EQUAL(&want, &p6->sin6_addr)) {
            (void)inet_ntop(AF_INET6, &p6->sin6_addr, dst_s, sizeof(dst_s));
            snprintf(err, errsz,
                     "--server %s does not match the socket's actual peer %s; "
                     "the outer address must match the server's /128 pin",
                     k->server, dst_s);
            return false;
        }
        return true;
    }
    snprintf(err, errsz,
             "session socket address family is unsupported (family=%d): the outer supports only IPv4 and IPv6",
             (int)local.ss_family);
    return false;
}

/* --------------------------------------------------- routes (same order as run_pump) */

static bool kdp_routes_up(struct kdp *k)
{
    if (k->had_routes) {
        if (!route_setup(k->dev, k->auth_tun_ip, k->auth_mtu, k->server,
                         k->ogw, k->odev, k->ogw_metric, &k->routes,
                         &k->routes6)) {
            /* route_setup already rolled back itself and logged */
            return false;
        }
        log_info("tun %s ready: %llu route%s", k->dev,
                 (unsigned long long)k->routes.n, k->routes.n == 1 ? "" : "s");
        for (size_t i = 0; i < k->routes.n; i++)
            log_debug("route %s -> dev %s", k->routes.v[i], k->dev);
    } else {
        if (!route_iface_up(k->dev, k->auth_tun_ip, k->auth_mtu)) {
            /* Matches run_pump's failure rollback (on Windows there is also v6-side cleanup;
             * the kernel data plane is Linux-only, and route_rollback_v6 is a no-op on Linux
             * with no extra semantics beyond that) */
            route_rollback_v6(k->dev, k->auth_tun_ip, &k->routes6);
            route_iface_down(k->dev);
            return false;
        }
        log_info("tun %s up with IP %s/24 (no route hijack)", k->dev,
                 k->auth_tun_ip);
    }
    if (k->routes6.n > 0) {
        route_setup6(k->dev, &k->routes6);
        for (size_t i = 0; i < k->routes6.n; i++)
            log_debug("route6 %s -> dev %s", k->routes6.v[i], k->dev);
    }
    k->routes_up = true;
    return true;
}

static void kdp_routes_down(struct kdp *k)
{
    if (!k->routes_up)
        return;
    route_teardown6(k->dev, k->auth_tun_ip, &k->routes6);
    if (k->had_routes)
        route_teardown(k->dev, k->server, k->ogw, k->odev, k->ogw_metric,
                       &k->routes);
    else
        route_iface_down(k->dev);
    k->routes_up = false;
}

/* --------------------------------------------------- optional events channel */

static void kdp_event_cb(void *ud, uint8_t ev, const uint8_t *frame, size_t len)
{
    (void)ud;
    (void)frame;   /* under IWAN_DEBUG_STRIP, log_debug is a no-op and its arguments are discarded */
    switch (ev) {
    case IWAN_EV_PEER_CLOSE:
        log_debug("kernel data plane: event PEER_CLOSE (peer closed actively)");
        break;
    case IWAN_EV_CTRL_FRAME:
        if (len > 0)
            log_debug("kernel data plane: event CTRL_FRAME type=0x%02x len=%llu",
                      (unsigned)frame[0], (unsigned long long)len);
        break;
    default:
        log_debug("kernel data plane: event %u len=%llu", (unsigned)ev,
                  (unsigned long long)len);
        break;
    }
}

/* ------------------------------------------------------------ exit */

/* Teardown order (decision 8): stop polling/events -> PT_CLOSE (before closing the socket) ->
 * tear down routes (route_iface_down/route_teardown depend on the device name, must run before deleting the interface) ->
 * SESSION_DOWN -> close fd. Any failure path executes the corresponding subset, and **never leaves an established
 * session behind** (a leftover session makes the hook keep swallowing packets; the user only sees "the network is broken"). */
static void kdp_teardown(struct kdp *k)
{
    char err[256];

    reply_route_teardown(&k->rr);

    if (k->session_up) {
        if (kdp_send_ctrl(k, PT_CLOSE) != 0)
            log_debug("kernel data plane: PT_CLOSE send failed: %s", strerror(errno));
        else
            /* Print unconditionally (same as the "stopped" log at the end of kdp_run, and proxy.c's TUN path):
             * this is the only client-side visible evidence that a farewell frame was sent to the peer, at most one line per session;
             * putting it behind debug_enabled() would make the default Release build (IWAN_DEBUG_STRIP=ON,
             * IWAN_DEBUG is not even parsed) never see it, and acceptance could not tell "not sent" from "sent but not logged". */
            err_printf("CLOSE sent\n");
    }
    kdp_routes_down(k);
    if (k->session_up && k->genl != NULL) {
        if (genl_iwan_session_down(k->genl, err, sizeof(err)) != 0) {
            log_err("kernel data plane: SESSION_DOWN failed: %s", err);
            log_err("  session and %s may be left over (the hook will keep swallowing packets): "
                    "run sudo ip link del %s and reload the module, or reboot",
                    k->dev, k->dev);
        } else {
            /* Re-check: GET_STATS has no NLM_F_DUMP; to judge "is there a session" look at
             * sid==0 && tok==0 (not DEVNAME -- it is "-" when there is no session). */
            genl_iwan_stats st;
            char e2[256];

            if (genl_iwan_get_stats(k->genl, &st, e2, sizeof(e2)) == 0 &&
                (st.sid != 0 || st.tok != 0))
                log_err("kernel data plane: session still present after SESSION_DOWN"
                        " (sid=0x%04x tok=0x%08x): the hook may keep swallowing packets, "
                        "run SESSION_DOWN manually once more", st.sid, st.tok);
        }
        k->session_up = false;
    }
    if (k->genl != NULL) {
        genl_iwan_close(k->genl);
        k->genl = NULL;
    }
    kdp_shm_close(k);
    slist_free(&k->routes);
    slist_free(&k->routes6);
}

/* ------------------------------------------------------------ main entry */

int kdp_run(int sockfd, const uint8_t xor_key[8], uint16_t sid, uint32_t tok,
            uint8_t enc, const char *server, const slist_t *route_targets,
            const slist_t *route_targets6, const char *auth_tun_ip,
            uint16_t auth_mtu, const kdp_bind *bind, bool *ns_busy)
{
    struct kdp k;
    char err[512];
    uint64_t t_up;
    uint64_t next_tick;
    uint64_t last_ka;
    uint64_t last_seen = 0;
    int ka_fail = 0;
    bool seen_rx = false;
    bool busy_local = false;
    unsigned stale;
    unsigned ka_ms;
    unsigned ka_fail_max;

    if (ns_busy != NULL)
        *ns_busy = false;

    memset(&k, 0, sizeof(k));
    k.sockfd = sockfd;
    k.sid = sid;
    k.tok = tok;
    k.enc = enc;
    k.server = server;
    k.auth_tun_ip = auth_tun_ip;
    k.auth_mtu = auth_mtu;
    k.shm_fd = -1;
    k.sess.sid = sid;
    k.sess.tok = tok;
    k.sess.enc = enc;
    memcpy(k.sess.key, xor_key, sizeof(k.sess.key));
    k.sess.mtu = auth_mtu;
    k.sess.sport = 0;
    if (bind != NULL) {
        k.bind = *bind;
        k.sess.oif = bind->oif;
        k.sess.bind_ip = bind->bind_ip;
        k.sess.bind_ip6 = bind->bind_ip6;
    }
    snprintf(k.dev, sizeof(k.dev), "%s", KDP_DEV_DEFAULT);
    slist_init(&k.routes);
    slist_init(&k.routes6);

    /* run_pump's first step: install stop handling before any blocking setup (the same
     * g_stop/g_user_stop semantics) */
    port_set_stop_handler(kdp_on_signal);

    if (expand_route_targets(route_targets, &k.routes) != 0) {
        kdp_teardown(&k);
        return -1;
    }
    if (expand_route_targets6(route_targets6, &k.routes6) != 0) {
        kdp_teardown(&k);
        return -1;
    }
    k.had_routes = k.routes.n > 0;
    if (k.had_routes) {
        if (!capture_default(k.ogw, k.odev, k.ogw_metric)) {
            log_err("cannot detect default route");
            kdp_teardown(&k);
            return -1;
        }
        log_debug("default route: via %s dev %s%s%s", k.ogw, k.odev,
                  k.ogw_metric[0] != '\0' ? " metric " : "", k.ogw_metric);
    }

    /* Pre-startup precheck 1: session 5-tuple (getsockname/getpeername) */
    if (!kdp_socket_params(&k, err, sizeof(err))) {
        log_err("kernel data plane: %s", err);
        kdp_teardown(&k);
        return -1;
    }
    /* "bound IP" mode: the outer source address is exactly that IP (the kernel-side iwan_carrier_resolve requires
     * the two to match, otherwise straight -EINVAL). The handshake socket was already bound to it (see
     * authenticate(), so normally the two values are equal; inequality means system routing pointed the connection
     * at another source address -- in that case the peer learned a different endpoint, and if the data plane then sends with the
     * bound address it disagrees with the peer's record, so it must be reported. */
    if (k.bind.bind_v6) {
        /* outer v6 "bound IP": the same check and text as the v4 branch below */
        if (!IN6_ARE_ADDR_EQUAL(&k.sess.outer_src6, &k.bind.bind_ip6)) {
            char a[INET6_ADDRSTRLEN], c[INET6_ADDRSTRLEN];

            log_err("kernel data plane: bound egress IP %s disagrees with the session socket source address %s "
                    "(the peer records the local endpoint from the handshake source address, but the data plane sends from the bound "
                    "address); programming the bound address",
                    inet_ntop(AF_INET6, &k.bind.bind_ip6, a, sizeof(a)),
                    inet_ntop(AF_INET6, &k.sess.outer_src6, c, sizeof(c)));
        }
        k.sess.outer_src6 = k.bind.bind_ip6;
    } else if (k.bind.bind_ip != 0) {
        if (k.sess.outer_src != k.bind.bind_ip) {
            struct in_addr a, c;

            a.s_addr = htonl(k.bind.bind_ip);
            c.s_addr = htonl(k.sess.outer_src);
            log_err("kernel data plane: bound egress IP %s disagrees with the session socket source address %s "
                    "(the peer records the local endpoint from the handshake source address, but the data plane sends from the bound "
                    "address); programming the bound address",
                    inet_ntop(AF_INET, &a, (char[INET_ADDRSTRLEN]){0},
                              INET_ADDRSTRLEN),
                    inet_ntop(AF_INET, &c, (char[INET_ADDRSTRLEN]){0},
                              INET_ADDRSTRLEN));
        }
        k.sess.outer_src = k.bind.bind_ip;
    }

    /* Precheck 2: /dev/iwan must exist and the version must match (no silent degradation to TUN) */
    if (!kdp_shm_open(&k, err, sizeof(err))) {
        log_err("kernel data plane: %s", err);
        kdp_teardown(&k);
        return -1;
    }
    /* Precheck 3: whether this netns already has a live session + iwan0 ownership (same as kdp_plane_precheck
     * criteria and text; on the normal path the caller already ran it before the handshake, this is the fallback for other callers
     * (OIDC etc.) and for races) */
    if (!kdp_precheck_core(&k, err, sizeof(err), &busy_local)) {
        log_err("kernel data plane: %s", err);
        if (ns_busy != NULL)
            *ns_busy = busy_local;
        kdp_teardown(&k);
        return -1;
    }

    k.genl = genl_iwan_open(err, sizeof(err));
    if (k.genl == NULL) {
        log_err("kernel data plane: %s", err);
        kdp_teardown(&k);
        return -1;
    }
    if (genl_iwan_session_up(k.genl, &k.sess, k.dev, sizeof(k.dev),
                             &k.dev_mtu, err, sizeof(err)) != 0) {
        char os[INET6_ADDRSTRLEN] = "";
        char od[INET6_ADDRSTRLEN] = "";

        log_err("kernel data plane: %s", err);
        /* Print the session parameters **we sent** verbatim: the rejection is either out of range
         * (typical: inner MTU exceeds the module max_mtu, default 1500 -- a metrics-profile build
         * IWAN_JUMBO_MTU raises the default MTU to the limit, visible at a glance in this line), or
         * inconsistent with an existing kernel session (compare with the module view from GET_STATS below). */
        if (k.sess.outer_v6) {
            (void)inet_ntop(AF_INET6, &k.sess.outer_src6, os, sizeof(os));
            (void)inet_ntop(AF_INET6, &k.sess.outer_dst6, od, sizeof(od));
        } else {
            struct in_addr a;

            a.s_addr = htonl(k.sess.outer_src);
            (void)inet_ntop(AF_INET, &a, os, sizeof(os));
            a.s_addr = htonl(k.sess.outer_dst);
            (void)inet_ntop(AF_INET, &a, od, sizeof(od));
        }
        log_err("kernel data plane: this SESSION_UP request sid=0x%04x enc=%u mtu=%u "
                "outer%s %s:%u -> %s:%u oif=%u bind_ip=%s flags=%s",
                (unsigned)sid, (unsigned)k.sess.enc, (unsigned)k.sess.mtu,
                k.sess.outer_v6 ? "v6" : "v4", os, (unsigned)k.sess.sport,
                od, (unsigned)k.sess.dport, (unsigned)k.sess.oif,
                (k.sess.outer_v6 ?
                     !IN6_IS_ADDR_UNSPECIFIED(&k.sess.bind_ip6) :
                     k.sess.bind_ip != 0) ? "yes" : "no",
                k.sess.mtu != 0 && k.sess.mtu > 1500u
                    ? "NOTE: MTU exceeds the module max_mtu default of 1500 and will certainly be rejected"
                    : "ok");
        /* "existing session" failures must not fall back to another data plane: falling back would take the same account and kick that
         * session out. Two criteria are OR-ed: the module's conflict extack, or the shared memory indeed showing
         * a live session (when the peer is silent only the former detects it). */
        if (ns_busy != NULL)
            *ns_busy = kdp_err_is_conflict(err) ||
                       kdp_session_is_live(&k, NULL);
        kdp_teardown(&k);
        return -1;
    }
    k.session_up = true;
    {
        /* inet_ntoa uses a static buffer, so two addresses in one printf overwrite each other;
         * the address string buffer is sized for v6 (the family is decided by outer_v6) */
        char os[INET6_ADDRSTRLEN] = "";
        char od[INET6_ADDRSTRLEN] = "";

        if (k.sess.outer_v6) {
            (void)inet_ntop(AF_INET6, &k.sess.outer_src6, os, sizeof(os));
            (void)inet_ntop(AF_INET6, &k.sess.outer_dst6, od, sizeof(od));
        } else {
            struct in_addr a;

            a.s_addr = htonl(k.sess.outer_src);
            (void)inet_ntop(AF_INET, &a, os, sizeof(os));
            a.s_addr = htonl(k.sess.outer_dst);
            (void)inet_ntop(AF_INET, &a, od, sizeof(od));
        }
        log_info("kernel data plane: session established dev=%s mtu=%u sid=0x%04x "
                 "outer%s %s:%u -> %s:%u", k.dev, (unsigned)k.dev_mtu,
                 (unsigned)sid, k.sess.outer_v6 ? "v6" : "v4", os,
                 (unsigned)k.sess.sport, od, (unsigned)k.sess.dport);
    }
    /* Reply route: only here is the carrier NIC ifindex obtained (device and carrier both settled), so it is installed here.
     * If the precondition check is not satisfied, reject this session -- that would mean the rules silently do not take effect (reply packets still go via the physical
     * NIC), which is harder to diagnose than an outright error. */
    if (bind != NULL && bind->reply_via_tunnel) {
        reply_route_opts  ro;
        genl_iwan_stats   rst;
        char              ifname[IF_NAMESIZE] = "";
        char              why[512];
        char              rerr[256];

        memset(&ro, 0, sizeof(ro));
        memset(&rst, 0, sizeof(rst));
        ro.tun = k.dev;
        ro.served4 = route_targets;
        ro.served6 = route_targets6;
        ro.kernel_plane = true;
        /* The carrier NIC ifindex is only exported in GET_STATS (the session reply has no such field),
         * so one extra query is made here; once the carrier is pinned it never changes. */
        if (genl_iwan_get_stats(k.genl, &rst, why, sizeof(why)) != 0 ||
            rst.carrier == 0 ||
            if_indextoname(rst.carrier, ifname) == NULL) {
            log_err("reply route: cannot get the carrier NIC (GET_STATS %s, carrier=%u), "
                    "cannot determine the inbound match interface; rejecting this session",
                    rst.carrier == 0 ? "read carrier=0" : "failed",
                    (unsigned)rst.carrier);
            kdp_teardown(&k);
            return -1;
        }
        ro.in_if = ifname;
        if (!reply_route_precheck(&ro, why, sizeof(why))) {
            log_err("reply route: precondition check failed, rejecting this session: %s", why);
            kdp_teardown(&k);
            return -1;
        }
        if (!reply_route_setup(&ro, &k.rr, rerr, sizeof(rerr))) {
            log_err("reply route: installing rules failed, rejecting this session: %s", rerr);
            kdp_teardown(&k);
            return -1;
        }
    }
    if (k.dev_mtu != 0 && k.dev_mtu != (uint32_t)auth_mtu)
        log_err("kernel data plane: reply MTU %u disagrees with negotiated MTU %u, "
                "configuring address/routes from the negotiated value", (unsigned)k.dev_mtu,
                (unsigned)auth_mtu);
    /* Device ownership: even if the module returned IWAN_A_DEV_OWNED this round there is no extra handling (an enum constant
     * cannot be probed with #ifdef); "someone else's interface" is covered by the precheck + SESSION_UP's -EBUSY. */

    /* events group is downgraded to optional/diagnostic: failing to get it only loses logs, the data plane is unaffected */
    if (genl_iwan_events_subscribe(k.genl, err, sizeof(err)) == 0) {
        k.events_ok = true;
    } else {
        log_debug("kernel data plane: events multicast group unavailable (affects diagnostic logs only): %s",
                  err);
    }

    /* Address/routes/MTU still belong to userspace: the module only creates the interface, sets it UP, and sets the MTU */
    if (!kdp_routes_up(&k)) {
        log_err("kernel data plane: address/route configuration failed, rolling back the established session");
        kdp_teardown(&k);
        return -1;
    }

    /* Same window as run_pump: if Ctrl-C was pressed during setup, do not start the data plane,
     * but roll back routes and the session cleanly first */
    if (g_user_stop) {
        log_info("kernel data plane: stop requested during setup; aborting");
        kdp_teardown(&k);
        return 0;
    }
    g_stop = 0;

    log_info("kernel data plane running (dev %s) -- press Ctrl-C to stop",
             k.dev);

    stale = (unsigned)pump_rx_stale_ms();       /* 0 = watchdog disabled */
    ka_ms = pump_keepalive_ms();
    ka_fail_max = pump_ka_fail_max();
    t_up = now_ms();
    next_tick = t_up;
    last_ka = t_up > ka_ms ? t_up - ka_ms : 0;  /* send the first keepalive immediately */

    while (!g_stop && !g_user_stop) {
        char bwhy[256];

        /* 0) Bind validity. The kernel only reacts to "outer lookup failure", and the bound egress IP
         *    being deleted does not constitute a lookup failure (measured: packets are still sent); same for the carrier NIC losing carrier
         *    -- this one can only be judged here. Invalid means "shut down the kernel part": teardown drops
         *    SESSION_DOWN and invalidates the route via iwan0; inner traffic is then carried by the next
         *    routing table entry; the reconnect loop waits for the bind to recover **before** re-handshaking
         *    (kdp_bind_wait). */
        if (!kdp_bind_ok(&k.bind, bwhy, sizeof(bwhy))) {
            log_err("kernel data plane: bind invalid (%s), disabling the data plane", bwhy);
            k.session_lost = true;
            break;
        }

        uint64_t now;
        uint64_t lr;

        port_sleep_ms(KDP_SLEEP_MS);
        now = now_ms();

        if (k.events_ok)
            (void)genl_iwan_events_drain(k.genl, kdp_event_cb, &k);

        if (now < next_tick)
            continue;
        next_tick = now + KDP_POLL_MS;

        /* 1) Liveness: the /dev/iwan timestamp (the kernel writes it for every frame that passes the gate, PT_CLOSE
         *    resets it to 0). Right after the session is established 0 also means "nothing received yet", so seen_rx
         *    distinguishes "never received" from "received and then reset to zero". */
        lr = kdp_shm_last_rx(&k);
        if (lr != 0) {
            if (!seen_rx) {
                seen_rx = true;
                log_info("kernel data plane: received the peer's first valid frame"
                         " (/dev/iwan timestamp is now non-zero)");
            }
            /* Receiving a **new** frame = the peer is alive, clear the "no answer" failure budget. The only valid criterion is
             * receiving a frame: one successful send does not prove the peer exists -- a connected UDP socket reports
             * ICMP port unreachable on alternate sends, the send in between succeeds, and clearing on "send succeeded"
             * would make the budget of 3 never be reached (measured: after the server disappears the log repeatedly
             * shows "retry 1/3", and death finally comes from the IWAN_RX_STALE_MS watchdog). */
            if (lr != last_seen)
                ka_fail = 0;
            last_seen = lr;
        } else if (seen_rx) {
            log_err("kernel data plane: /dev/iwan timestamp reset to zero"
                    " (peer PT_CLOSE / session cleared), session lost");
            k.session_lost = true;
            break;
        }
        if (stale != 0) {
            uint64_t quiet = seen_rx ? ms_since(now, last_seen)
                                     : ms_since(now, t_up);
            if (quiet > stale) {
                log_err("kernel data plane: no valid frame received for %llu ms"
                        " (IWAN_RX_STALE_MS=%u), session lost",
                        (unsigned long long)quiet, stale);
                k.session_lost = true;
                break;
            }
        }

        /* 2) keepalive sending is still in userspace (10s PT_ECHO_REQ, same parameters as the TUN pump) */
        if (ms_since(now, last_ka) >= ka_ms) {
            if (kdp_send_ctrl(&k, PT_ECHO_REQ) != 0) {
                int e = errno;

                if (++ka_fail >= (int)ka_fail_max) {
                    log_err("kernel data plane: keepalive failed %d times while no downlink frame arrived"
                            " (last error: %s); session lost", ka_fail,
                            strerror(e));
                    k.session_lost = true;
                    break;
                }
                err_printf("kernel data plane: keepalive send failed: %s"
                           " (accumulated %d/%u while no downlink frame arrived)\n", strerror(e),
                           ka_fail, ka_fail_max);
            }
            /* Advance the cadence whether or not it succeeded: a failure retries once per ka_ms, not on every
             * 1 second tick */
            last_ka = now_ms();
        }

        /* 3) Device deleted externally (ip link del / netns teardown): replaying the idempotent
         *    SESSION_UP recreates the NIC, but address/routes must run again. */
        if (if_nametoindex(k.dev) == 0) {
            log_err("kernel data plane: device %s deleted externally, replaying SESSION_UP to recreate",
                    k.dev);
            k.routes_up = false;   /* routes vanish together with the device */
            if (genl_iwan_session_up(k.genl, &k.sess, k.dev, sizeof(k.dev),
                                     &k.dev_mtu, err, sizeof(err)) != 0) {
                log_err("kernel data plane: recreating %s failed: %s; session lost", k.dev, err);
                k.session_lost = true;
                break;
            }
            if (!kdp_routes_up(&k)) {
                log_err("kernel data plane: address/route configuration failed after recreation; session lost");
                k.session_lost = true;
                break;
            }
            log_info("kernel data plane: %s recreated", k.dev);
        }
    }

    kdp_teardown(&k);

    /* Print unconditionally (deliberately not behind debug_enabled()): this is the only
     * user-visible closing log for "kernel data plane stopped", at most one line per session, no risk of flooding; behind the debug toggle,
     * the default Release build (IWAN_DEBUG_STRIP=ON, IWAN_DEBUG not even parsed) would never see
     * it -- after Ctrl-C the user would only see "stuck", and the acceptance script's exit-semantics assertions would have nothing to check. */
    err_printf("kernel data plane stopped (%s)\n",
               k.session_lost ? "session lost" : "user stop");
    /* 1 = session lost (reconnect); 0 = user stop -- same semantics as run_pump */
    return k.session_lost ? 1 : 0;
}

#endif /* __linux__ */
