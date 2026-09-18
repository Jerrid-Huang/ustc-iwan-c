#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"
#include "route.h"
#include "tun.h"
#include "util.h"

#ifdef _WIN32
/* Windows backend: winsock2 (via port.h, included above) must precede
 * iphlpapi.h. Route/address changes go through netsh (port_run_cmd);
 * default-route and adapter discovery use the IP Helper API. */
#  include <iphlpapi.h>
#  include <windows.h>
#elif defined(__APPLE__)
#  include <arpa/inet.h>
/* macOS backend: ifconfig/route/netstat via port_run_cmd. No iproute2
 * exists on macOS; utun interface names come from tun_ifname(). */
static bool mac_run(char *const argv[], const char *what)
{
    if (port_run_cmd(argv) == 0)
        return true;
    log_err("%s failed (%s)", what, argv[0]);
    return false;
}
#else
#  include <arpa/inet.h>
#endif

/* derived inner ULA (fd00::/96 + the inner IPv4, protocol.h) as text;
 * returns false when tun_ip is not a valid IPv4. */
static bool tun_ula_str(const char *tun_ip, char out[64])
{
    uint8_t v4[4], b6[16];
    if (!s2ip4(tun_ip, v4))
        return false;
    ip6_derive_ula(ip4_u32(v4), b6);
    snprintf(out, 64,
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             b6[0], b6[1], b6[2], b6[3], b6[4], b6[5], b6[6], b6[7],
             b6[8], b6[9], b6[10], b6[11], b6[12], b6[13], b6[14], b6[15]);
    return true;
}

/* true when `c` names the IPv4 default route (either spelling); used when
 * splitting the routes with/without the default to handle it specially. */
static bool is_default_v4(const char *c)
{
    return strcmp(c, "default") == 0 || strcmp(c, "0.0.0.0/0") == 0;
}

#ifdef _WIN32
/* R53-E-1: audit the wintun adapter's derived-ULA address surface.
 *
 * A crashed run (whose teardown never ran) leaves ITS ULA — derived
 * from that run's inner IPv4 — on the persistent adapter, and
 * route_teardown6 only ever deletes the CURRENT run's ULA, so once the
 * inner IPv4 changes the old ULA address can survive on the adapter.
 * R46-L2 (74437c5) first handled this by auto-deleting every
 * fd00::/96-shaped address that was not `cur`; that predicate had to be
 * pulled back, and this pass now only REPORTS (R53-E-1):
 *
 *   The shape test (byte0 = 0xfd, bytes 1..11 zero) selects EXACTLY
 *   the whole fd00::/96 space. `cur` is fd00:0:0:0:0:0:0:<inner IPv4>,
 *   so ANY fd00:0:0:0:0:0:0:yyyy address could equally be the derived
 *   ULA of SOME inner IPv4 — there is no byte-level marker that tells a
 *   history residue apart from an address the user configured by hand
 *   (say fd00::1/96). No additional enumerable signal helps either: the
 *   address row's prefix length is 96 both for our `netsh ... add
 *   address <ula>/96` and for a user's `/96` add; and the fd00::/96
 *   on-link route exists whenever EITHER was added with a /96 (and is
 *   absent exactly when a user added a bare /128 address) — route
 *   presence says only "some fd00::/96 address was added with a /96",
 *   never WHO added it. The "delete only isolated addresses" idea is
 *   therefore still unsound: a user's fd00::1/128 has no on-link /96
 *   route either, so it would again be auto-deleted (the R46 over-delete
 *   reproduced for /128-spelled user config). Over-deleting silently
 *   destroys user state — the mirror image of the over-retention that
 *   74437c5 itself promised to avoid ("any user-added global address
 *   ... left alone") — so the only sound policy is: NEVER auto-delete
 *   inside fd00::/96.
 *
 * Consequence (accepted): residue of prior inner IPv4s is no longer
 * cleaned automatically. Under-deletion is the safe direction — a
 * leftover fd00:: address is inert: the single shared fd00::/96
 * on-link route already makes the whole client pool reachable, that
 * route is kept by the R49-L5 v6 route sweep (all derived ULAs share
 * the same /96 network, so the route matches the sweep's current-ULA/96
 * whitelist entry) and is re-created by the `add` below — residue never
 * affects routing, it only accumulates as invisible addresses. This
 * pass compensates by LOGGING every such address on every run (debug
 * level), naming the manual cleanup command (`netsh interface ipv6
 * delete address interface=<tun> <addr>`). Best-effort: enumeration
 * failures are silent returns; this pass runs no commands at all. */
static void reconcile_stale_ula(const char *tun, const char *tun_ip)
{
    uint8_t v4[4], cur[16];
    if (!s2ip4(tun_ip, v4))
        return;
    ip6_derive_ula(ip4_u32(v4), cur);
    wchar_t wname[128];
    if (MultiByteToWideChar(CP_UTF8, 0, tun, -1, wname, 128) <= 0)
        return;
    NET_LUID luid;
    if (ConvertInterfaceAliasToLuid(wname, &luid) != NO_ERROR)
        return;
    PMIB_UNICASTIPADDRESS_TABLE tbl;
    if (GetUnicastIpAddressTable(AF_INET6, &tbl) != NO_ERROR)
        return;
    char ifa[32], ds[INET6_ADDRSTRLEN], cstr[INET6_ADDRSTRLEN];
    snprintf(ifa, sizeof ifa, "interface=%s", tun);
    inet_ntop(AF_INET6, cur, cstr, sizeof cstr);   /* cannot fail */
    for (ULONG i = 0; i < tbl->NumEntries; i++) {
        MIB_UNICASTIPADDRESS_ROW *r = &tbl->Table[i];
        if (r->InterfaceLuid.Value != luid.Value ||
            r->Address.si_family != AF_INET6)
            continue;
        const uint8_t *a = (const uint8_t *)&r->Address.Ipv6.sin6_addr;
        /* the derived-ULA space only: fd00::/96 (byte0 = 0xfd, bytes
         * 1..11 zero). Link-local, global and every other address is
         * never examined further. */
        if (a[0] != 0xfd)
            continue;
        if (!(a[1] == 0 && a[2] == 0 && a[3] == 0 && a[4] == 0 &&
              a[5] == 0 && a[6] == 0 && a[7] == 0 && a[8] == 0 &&
              a[9] == 0 && a[10] == 0 && a[11] == 0))
            continue;
        if (memcmp(a, cur, 16) == 0)
            continue;   /* the current run's own ULA: the add below is
                         * idempotent, nothing to do or to log */
        if (inet_ntop(AF_INET6, a, ds, sizeof ds) == NULL)
            continue;
        log_debug("route: fd00::/96 address %s on %s not deleted "
                  "(current derived ULA is %s): may be a user-"
                  "configured address or residue of a prior inner IPv4; "
                  "delete by hand if it is ours: netsh interface ipv6 "
                  "delete address %s %s", ds, tun, cstr, ifa, ds);
        /* ds/ifa/cstr are read only by log_debug above — the strict
         * gates build IWAN_DEBUG_STRIP (log_debug compiles out), so
         * the set-but-unused locals must be marked read */
        (void)ds;
        (void)ifa;
        (void)cstr;
    }
    FreeMibTable(tbl);
}
#endif /* _WIN32 */

/* best-effort: give the tunnel interface its IPv6 side (the derived
 * ULA/96). The /96 makes the whole client pool on-link, so the kernel
 * routes v6 return traffic into the tunnel without extra routes. */
static void tun_iface_up6(const char *tun, const char *tun_ip)
{
#ifdef _WIN32
    char ula[64], ula96[72], ifa[32];
    if (!tun_ula_str(tun_ip, ula))
        return;
    /* R53-E-1: before adding the current ULA, audit the derived-ULA
     * address surface (reconcile_stale_ula). Stale fd00::/96-shaped
     * addresses are REPORTED, never auto-deleted: any one of them is
     * byte-for-byte indistinguishable from a user-configured address in
     * that space, so R46-L2's auto-delete (74437c5) was an over-delete.
     * The add below is an append (netsh has no replace), so historical
     * ULAs may accumulate as inert residue; the per-run debug log names
     * the manual cleanup command. */
    reconcile_stale_ula(tun, tun_ip);
    /* netsh would default a bare address to no /96 prefix, breaking the
     * client-pool on-link semantics; pass the explicit /96 like Linux.
     * ula96[72] is provably enough: ula holds at most 63 chars + "/96".
     * "interface=" not "name=": netsh ipv6 add address takes
     * interface= (the ipv4 set address family takes name=). */
    snprintf(ula96, sizeof ula96, "%s/96", ula);
    snprintf(ifa, sizeof ifa, "interface=%s", tun);
    char *a[] = { "netsh", "interface", "ipv6", "add", "address", ifa,
                  ula96, NULL };
    (void)port_run_cmd(a);   /* idempotent; best-effort */
#elif defined(__APPLE__)
    char ula[64];
    if (!tun_ula_str(tun_ip, ula))
        return;
    const char *ifn = tun_ifname(tun);
    char *a[] = { "ifconfig", (char *)ifn, "inet6", ula, "prefixlen", "96",
                  NULL };
    (void)port_run_cmd(a);   /* best-effort */
#else
    char ula[64], ula96[72];
    if (!tun_ula_str(tun_ip, ula))
        return;
    snprintf(ula96, sizeof ula96, "%s/96", ula);
    (void)ip_run((char *[]){"-6", "addr", "add", ula96,
                            "dev", (char *)tun, NULL});
#endif
}

#ifdef _WIN32
/* ------------------------- Windows helpers ------------------------ */

/* Run netsh with NULL-terminated argv (argv[0] = "netsh"). Returns true
 * when netsh exited 0; logs the exit code otherwise. */
static bool netsh_run(char *const argv[], const char *what)
{
    int rc = port_run_cmd(argv);
    if (rc != 0) {
        log_err("%s failed (netsh exit %d)", what, rc);
        return false;
    }
    return true;
}

/* canonical "a.b.c.d/plen" prefix string (net masked to the network) */
static void prefix_str(uint32_t net, int prefix, char out[24])
{
    uint8_t b[4];
    u32_ip4(net, b);
    snprintf(out, 24, "%u.%u.%u.%u/%d", b[0], b[1], b[2], b[3], prefix);
}

#endif /* _WIN32 */

/* bring the tunnel interface up with an address and MTU (no routes):
 * addr flush / link up / mtu / addr add. Shared by route_setup (which
 * then installs routes) and the no-route-hijack pump path in proxy.c.
 * Returns false when a step failed (state partially applied). */
#ifdef _WIN32
bool route_iface_up(const char *tun, const char *tun_ip, uint16_t mtu)
{
    char namea[32], ifa[32], mtu_s[8], mtuarg[24];
    snprintf(namea, sizeof namea, "name=%s", tun);
    snprintf(ifa, sizeof ifa, "interface=%s", tun);
    snprintf(mtu_s, sizeof mtu_s, "%u", (unsigned)mtu);
    snprintf(mtuarg, sizeof mtuarg, "mtu=%s", mtu_s);
    char *a1[] = { "netsh", "interface", "ipv4", "set", "address", namea,
                   "static", (char *)tun_ip, "255.255.255.0", NULL };
    if (!netsh_run(a1, "iface up: set address"))
        return false;
    /* set subinterface takes "interface=" (unlike set address, which
     * takes "name="); "name=" here is rejected by netsh and silently
     * leaves the MTU at its default (65535 on wintun) */
    char *a2[] = { "netsh", "interface", "ipv4", "set", "subinterface",
                   ifa, mtuarg, NULL };
    if (!netsh_run(a2, "iface up: set mtu"))
        return false;
    tun_iface_up6(tun, tun_ip);   /* best-effort IPv6 side */
    return true;
}
#elif defined(__APPLE__)
bool route_iface_up(const char *tun, const char *tun_ip, uint16_t mtu)
{
    /* utun is point-to-point: the destination equals the local
     * address (client routes use -interface, never a gateway). */
    const char *ifn = tun_ifname(tun);
    char mtu_s[8];
    snprintf(mtu_s, sizeof mtu_s, "%u", (unsigned)mtu);
    char *a1[] = { "ifconfig", (char *)ifn, (char *)tun_ip, (char *)tun_ip,
                   "up", NULL };
    if (!mac_run(a1, "iface up: ifconfig")) {
        log_err("iface up: ifconfig %s %s %s up failed", ifn, tun_ip,
                tun_ip);
        return false;
    }
    char *a2[] = { "ifconfig", (char *)ifn, "mtu", mtu_s, NULL };
    if (!mac_run(a2, "iface up: mtu")) {
        log_err("iface up: mtu %s on %s failed", mtu_s, ifn);
        return false;
    }
    tun_iface_up6(tun, tun_ip);   /* best-effort IPv6 side */
    return true;
}
#else
bool route_iface_up(const char *tun, const char *tun_ip, uint16_t mtu)
{
    char mtu_s[8], ip24[64];
    snprintf(mtu_s, sizeof mtu_s, "%u", (unsigned)mtu);
    snprintf(ip24, sizeof ip24, "%s/24", tun_ip);
    char *a1[] = { "addr", "flush", "dev", (char *)tun, NULL };
    if (!ip_run(a1)) {
        log_err("iface up: addr flush dev %s failed", tun);
        return false;
    }
    char *a2[] = { "link", "set", (char *)tun, "up", NULL };
    if (!ip_run(a2)) {
        log_err("iface up: link set %s up failed", tun);
        return false;
    }
    char *a3[] = { "link", "set", "dev", (char *)tun, "mtu", mtu_s, NULL };
    if (!ip_run(a3)) {
        log_err("iface up: mtu %s on %s failed", mtu_s, tun);
        return false;
    }
    char *a4[] = { "addr", "add", ip24, "dev", (char *)tun, NULL };
    if (!ip_run(a4)) {
        log_err("iface up: addr add %s dev %s failed", ip24, tun);
        return false;
    }
    tun_iface_up6(tun, tun_ip);   /* best-effort IPv6 side */
    return true;
}
#endif /* _WIN32 */

/* take the tunnel interface down and flush its addresses (no routes).
 * Shared by route_teardown's tail and the no-route-hijack pump path. */
#ifdef _WIN32
/* forward decl: sweep_stale_routes is defined below (R46-L1) — this
 * function now also sweeps, so the no-route-hijack pump path reaches
 * the crash-leftover cleanup even though route_setup never ran */
static void sweep_stale_routes(const char *tun, const char *tun_ip,
                               const slist_t *routes6);

void route_iface_down(const char *tun)
{
    char namea[32];
    snprintf(namea, sizeof namea, "name=%s", tun);
    char *d1[] = { "netsh", "interface", "ipv4", "delete", "address",
                   namea, NULL };
    port_run_cmd(d1);   /* best-effort: no address left, or iface gone */
    /* R46-L1: this function is the teardown of the no-route-hijack pump
     * path (proxy.c teardown_routes calls route_iface_down when no
     * routes were hijacked), where route_setup — the sweep's only other
     * reachable site — never runs. A crashed route-hijack run's metric-0
     * default / stale proxy routes (netsh persistent) would otherwise
     * keep black-holing default traffic into the dead tunnel across an
     * unbounded number of pure-TUN runs. Sweep here too; it is
     * idempotent and, on the route_setup/route_teardown callers of this
     * function, only removes leftovers the explicit deletes missed
     * (nothing that is being kept is newly added after this point).
     * R49-L5: passes no tun_ip/routes6, so the v6 sweep keeps only
     * fe80::/64 — on this path route_teardown6 already deleted the
     * current config and the derived ULA/96 immediately before, so any
     * other on-link route left here is residue by definition. */
    sweep_stale_routes(tun, NULL, NULL);
}
#elif defined(__APPLE__)
void route_iface_down(const char *tun)
{
    const char *ifn = tun_ifname(tun);
    char *d1[] = { "ifconfig", (char *)ifn, "down", NULL };
    port_run_cmd(d1);   /* best-effort: device may be gone */
}
#else
void route_iface_down(const char *tun)
{
    char *d5[] = { "addr", "flush", "dev", (char *)tun, NULL };
    ip_run(d5);
    char *d6[] = { "link", "set", (char *)tun, "down", NULL };
    ip_run(d6);
}
#endif /* _WIN32 */

/* strict "A.B.C.D/n" parser: exact dotted-quad, 0 <= n <= 32, no
 * trailing garbage. net is filled in host byte order (unmasked).
 * Pure string parsing (s2ip4/strtol): shared by both backends. */
int cidr_parse(const char *s, uint32_t *net, int *prefix)
{
    const char *slash = strchr(s, '/');
    if (slash == NULL || slash == s || strchr(slash + 1, '/') != NULL)
        return -1;
    size_t ilen = (size_t)(slash - s);
    if (ilen == 0 || ilen >= 16)
        return -1;
    char ip[16];
    memcpy(ip, s, ilen);
    ip[ilen] = '\0';
    uint8_t b[4];
    if (!s2ip4(ip, b))
        return -1;
    char *pend;
    if (slash[1] < '0' || slash[1] > '9')
        return -1;   /* strict: reject "/ 8" and "/+8" */
    long p = strtol(slash + 1, &pend, 10);
    if (pend == slash + 1 || *pend != '\0' || p < 0 || p > 32)
        return -1;
    *net = ip4_u32(b);
    /* R23-F3 F2: a /0 that is not 0.0.0.0/0 is a typo, not a route — the
     * canonicalization later turns ANY /0 into a default route on all
     * three backends, so accepting "1.2.3.4/0" would silently replace the
     * real default with one via the tunnel. Only the true 0.0.0.0/0 is
     * legal. */
    if (p == 0 && *net != 0)
        return -1;
    *prefix = (int)p;
    return 0;
}

#ifndef _WIN32
static void copy_token(char *dst, size_t cap, const char *tok) {
    size_t n = strlen(tok);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, tok, n);
    dst[n] = '\0';
}
#endif

#ifdef _WIN32
bool capture_default(char gw[16], char dev[16], char metric[16])
{
    MIB_IPFORWARDROW best;
    IP_ADAPTER_ADDRESSES *aa = NULL;
    ULONG buflen = 0;
    DWORD rc;
    bool found = false;

    gw[0] = dev[0] = metric[0] = '\0';   /* metric: "" when absent */
    memset(&best, 0, sizeof best);
    /* best route to 0.0.0.0 == the default route; the returned row's
     * address fields are in network byte order (the adapter-index-map
     * parameter only exists on newer SDKs and is never needed) */
    if (GetBestRoute(0, 0, &best) != NO_ERROR)
        return false;

    rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL,
                              &buflen);
    if (rc != NO_ERROR && rc != ERROR_BUFFER_OVERFLOW)
        return false;
    if (buflen == 0)
        return false;
    aa = malloc(buflen);
    if (aa == NULL)
        oom_abort();
    rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, aa,
                              &buflen);
    if (rc != NO_ERROR) {
        free(aa);
        return false;
    }

    if (best.dwForwardNextHop != 0) {
        inet_ntop(AF_INET, &best.dwForwardNextHop, gw, 16);
    }
    for (IP_ADAPTER_ADDRESSES *p = aa; p != NULL; p = p->Next) {
        if (p->IfIndex != best.dwForwardIfIndex)
            continue;
        found = true;
        /* friendly name -> UTF-8; names longer than 15 bytes fall back
         * to the decimal interface index, which netsh accepts in the
         * interface= parameter (the historical "if<index>" spelling is
         * iproute2 syntax and netsh rejects it) */
        if (!WideCharToMultiByte(CP_UTF8, 0, p->FriendlyName, -1, dev, 16,
                                 NULL, NULL) || dev[0] == '\0')
            snprintf(dev, 16, "%lu", (unsigned long)p->IfIndex);
        if (gw[0] == '\0') {
            /* on-link default (nexthop 0.0.0.0): the gateway is the
             * interface's own address */
            for (IP_ADAPTER_UNICAST_ADDRESS *u = p->FirstUnicastAddress;
                 u != NULL; u = u->Next) {
                if (u->Address.lpSockaddr->sa_family != AF_INET)
                    continue;
                const struct sockaddr_in *sin =
                    (const struct sockaddr_in *)u->Address.lpSockaddr;
                inet_ntop(AF_INET, &sin->sin_addr, gw, 16);
                break;
            }
        }
        break;
    }
    if (!found) {
        free(aa);
        return false;
    }

    /* metric: total of the default row's metrics in the IPv4 forwarding
     * table (matching ifindex; the smallest total is the one in use) */
    ULONG tsz = 0;
    if (GetIpForwardTable(NULL, &tsz, FALSE) == ERROR_INSUFFICIENT_BUFFER &&
        tsz > 0) {
        MIB_IPFORWARDTABLE *tab = malloc(tsz);
        if (tab != NULL) {
            if (GetIpForwardTable(tab, &tsz, FALSE) == NO_ERROR) {
                uint64_t bestm = UINT64_MAX;
                for (DWORD i = 0; i < tab->dwNumEntries; i++) {
                    MIB_IPFORWARDROW *r = &tab->table[i];
                    if (r->dwForwardDest != 0 || r->dwForwardMask != 0)
                        continue;
                    if (r->dwForwardIfIndex != best.dwForwardIfIndex)
                        continue;
                    uint64_t m = (uint64_t)r->dwForwardMetric1 +
                                 r->dwForwardMetric2 + r->dwForwardMetric3 +
                                 r->dwForwardMetric4 + r->dwForwardMetric5;
                    if (m < bestm)
                        bestm = m;
                }
                if (bestm != UINT64_MAX) {
                    /* real route metrics are small; cap so the value
                     * always fits the 16-byte metric buffer */
                    if (bestm > UINT32_MAX)
                        bestm = UINT32_MAX;
                    snprintf(metric, 16, "%u", (unsigned)bestm);
                }
            }
            free(tab);
        }
    }
    free(aa);
    return gw[0] != '\0';
}
#elif defined(__APPLE__)
bool capture_default(char gw[16], char dev[16], char metric[16])
{
    char *args[] = { "netstat", "-rn", "-f", "inet", NULL };
    char *out = port_cmd_capture(args, 65536);
    if (out == NULL)
        return false;
    gw[0] = dev[0] = metric[0] = '\0';   /* metric: "" when absent */
    /* candidate default rows (gateway + interface), kept in netstat
     * order so a single-default host behaves exactly as before */
    char cand_gw[16][16];
    char cand_dev[16][16];
    size_t n = 0;
    char *lsave = NULL;
    /* modern netstat -rn prints no metric column (and the old one puts
     * it in the middle), so metric stays empty: on macOS the physical
     * default route is never deleted, only shadowed, so nothing needs
     * restoring with a metric. */
    for (char *line = strtok_r(out, "\n", &lsave); line != NULL;
         line = strtok_r(NULL, "\n", &lsave)) {
        char *save = NULL;
        char *tok = strtok_r(line, " \t\r", &save);
        if (tok == NULL || strcmp(tok, "default") != 0)
            continue;
        char *gt = strtok_r(NULL, " \t\r", &save);
        if (gt == NULL)
            continue;
        /* the interface is the LAST token; drop a trailing sticky '!'
         * marker that some rows carry */
        char *last = NULL;
        char *t;
        while ((t = strtok_r(NULL, " \t\r", &save)) != NULL)
            last = t;
        if (last == NULL)
            continue;
        size_t llen = strlen(last);
        if (llen > 0 && last[llen - 1] == '!')
            last[llen - 1] = '\0';
        /* the gateway must be a real IPv4 address: on-link defaults
         * (USB NICs, phone tethering) print "default link#14 ..." and
         * route(8) would reject the pin with an obscure error later */
        struct in_addr gwt;
        if (inet_pton(AF_INET, gt, &gwt) != 1) {
            log_err("capture_default: default gateway '%s' is not an "
                    "IPv4 address (on-link default via %s?); refusing "
                    "to hijack blindly",
                    gt, last);
            free(out);
            return false;
        }
        if (n < 16) {
            copy_token(cand_gw[n], 16, gt);
            copy_token(cand_dev[n], 16, last);
            n++;
        }
    }
    free(out);

    if (n == 0)
        return false;

    /* single default: byte-for-byte the historical result */
    if (n == 1) {
        copy_token(gw, 16, cand_gw[0]);
        copy_token(dev, 16, cand_dev[0]);
        return true;
    }

    /* multiple defaults: prefer a physical interface (enX: Wi-Fi or
     * Ethernet) so the server pin rides a real NIC, falling back to the
     * first valid row; among several physical ones keep the first in
     * netstat order for stability. */
    size_t best = 0;
    bool prefer_en = false;
    for (size_t i = 0; i < n; i++) {
        /* %llu, never %zu: msvcrt printf (Windows) lacks %zu (json.c:55) */
        log_info("capture_default: default candidate %llu: via %s on %s",
                 (unsigned long long)(i + 1), cand_gw[i], cand_dev[i]);
        if (!prefer_en && strncmp(cand_dev[i], "en", 2) == 0) {
            prefer_en = true;
            best = i;
        }
    }
    log_info("capture_default: %llu default route(s); choosing via %s on %s",
             (unsigned long long)n, cand_gw[best], cand_dev[best]);
    copy_token(gw, 16, cand_gw[best]);
    copy_token(dev, 16, cand_dev[best]);
    return true;
}
#else
bool capture_default(char gw[16], char dev[16], char metric[16]) {
    char *args[] = { "-4", "route", "show", "default", NULL };
    char *out = cmd_capture(args);
    if (out == NULL)
        return false;
    gw[0] = dev[0] = metric[0] = '\0';   /* metric: "" when absent */
    bool got_gw = false, got_dev = false;
    char *lsave = NULL;
    /* One default route per line ("default via 10.0.2.2 dev enp0s3
     * proto dhcp metric 100"). Parse LINE BY LINE and take the first
     * line carrying both via and dev: the old token-stream parse could
     * mix via/dev/metric from different default routes on multi-homed
     * hosts, yielding a wrong gateway for the server pin or a bogus
     * restore route at teardown. */
    for (char *line = strtok_r(out, "\n", &lsave); line != NULL;
         line = strtok_r(NULL, "\n", &lsave)) {
        char *save = NULL;
        char *line_gw = NULL, *line_dev = NULL, *line_metric = NULL;
        for (char *tok = strtok_r(line, " \t\r", &save); tok != NULL;
             tok = strtok_r(NULL, " \t\r", &save)) {
            if (strcmp(tok, "via") == 0) {
                line_gw = strtok_r(NULL, " \t\r", &save);
            } else if (strcmp(tok, "dev") == 0) {
                line_dev = strtok_r(NULL, " \t\r", &save);
            } else if (strcmp(tok, "metric") == 0) {
                line_metric = strtok_r(NULL, " \t\r", &save);
            }
        }
        if (line_gw != NULL && line_dev != NULL) {
            copy_token(gw, 16, line_gw);
            copy_token(dev, 16, line_dev);
            if (line_metric != NULL)
                copy_token(metric, 16, line_metric);
            got_gw = true;
            got_dev = true;
            break;
        }
        /* an on-link default (no via) still carries dev; without a
         * gateway we keep the historical behavior of failing the
         * capture (callers refuse to hijack routing blind) */
    }
    free(out);
    return got_gw && got_dev;
}
#endif /* _WIN32 */

#ifdef __linux__
static bool local_subnet(const char *dev, char out[24]) {
    char *args[] = { "-4", "addr", "show", "dev", (char *)dev, NULL };
    char *cap = cmd_capture(args);
    if (cap == NULL)
        return false;
    bool ok = false;
    char *lsave = NULL;
    for (char *line = strtok_r(cap, "\n", &lsave); line != NULL;
         line = strtok_r(NULL, "\n", &lsave)) {
        char *save = NULL;
        for (char *tok = strtok_r(line, " \t\r\n", &save); tok != NULL;
             tok = strtok_r(NULL, " \t\r\n", &save)) {
            if (strcmp(tok, "inet") != 0)
                continue;
            char *cidr = NULL;
            for (char *nt = strtok_r(NULL, " \t\r\n", &save); nt != NULL;
                 nt = strtok_r(NULL, " \t\r\n", &save)) {
                if (strchr(nt, '/') != NULL) {
                    cidr = nt;
                    break;
                }
            }
            if (cidr == NULL)
                break;
            /* parse "ip/plen" without mutating the cmd_capture buffer:
             * strndup the address part, then free it on every exit */
            char *slash = strchr(cidr, '/');
            if (slash == NULL)
                break;
            char *ip = strndup(cidr, (size_t)(slash - cidr));
            if (ip == NULL) {
                oom_abort();
                break;
            }
            uint8_t b[4];
            if (!s2ip4(ip, b)) {
                free(ip);
                break;
            }
            char *pend;
            long p = strtol(slash + 1, &pend, 10);
            free(ip);
            uint32_t plen;
            if (pend == slash + 1 || *pend != '\0' || p < 0)
                plen = 24;
            else if (p > 32)
                plen = 32;
            else
                plen = (uint32_t)p;
            uint32_t mask = plen == 0 ? 0 : ~((1u << (32 - plen)) - 1);
            uint32_t net = ip4_u32(b) & mask;
            uint8_t nb[4];
            u32_ip4(net, nb);
            snprintf(out, 24, "%u.%u.%u.%u/%u", nb[0], nb[1], nb[2], nb[3],
                     (unsigned)plen);
            ok = true;
            goto done;
        }
    }
done:
    free(cap);
    return ok;
}
#endif /* __linux__ */

#ifdef _WIN32
/* R45-L2: is an IPv6 next hop the unspecified address (::)? Windows
 * represents an on-link v6 route's (missing) gateway this way, exactly
 * like an on-link v4 route's 0.0.0.0. The address bytes are read
 * through the raw memory of the SOCKADDR_IN6 member so no SDK-specific
 * in6_addr sub-member names are needed (works on both the Windows SDK
 * and mingw-w64 IN6_ADDR layouts). */
static bool ip6_nexthop_unspec(const SOCKADDR_INET *nh)
{
    static const uint8_t zero[16] = {0};
    if (nh->si_family != AF_INET6)
        return false;
    const uint8_t *a = (const uint8_t *)&nh->Ipv6.sin6_addr;
    return memcmp(a, zero, sizeof zero) == 0;
}

/* R49-L5: exact IPv6 prefix match. Both sides are masked to the shorter
 * of their prefix lengths and compared with the LENGTHS THEMSELVES also
 * required equal, so fe80::/64 never matches fe80::/128 (or a host bit
 * set inside the network, e.g. an unmasked "fe80::1/64" spelling). A
 * masked byte comparison (not a string "contains") normalizes every
 * spelling of the same network. */
static bool ip6_prefix_eq(const uint8_t a[16], int plen_a,
                          const uint8_t b[16], int plen_b)
{
    if (plen_a != plen_b)
        return false;
    int full = plen_a / 8;
    if (memcmp(a, b, (size_t)full) != 0)
        return false;
    if (plen_a % 8) {
        uint8_t mask = (uint8_t)(0xFFu << (8 - (plen_a % 8)));
        if (((uint8_t)(a[full] ^ b[full]) & mask) != 0)
            return false;
    }
    return true;
}

/* R49-L5: one whitelist entry for the v6 sweep keep set. Kept routes are
 * exactly {fe80::/64} ∪ {the current derived ULA/96} ∪ {every prefix in
 * the current routes6 config}; anything else on-link (the user's removed
 * or crash-leftover >= /64 proxy prefixes) is swept like the v4 side
 * always did. The whitelist is bounded below (64): a config longer than
 * that is unrealistic, and an entry dropped off the tail is only deleted
 * and cleanly re-added by the following route_setup6 — never lost. */
struct kept6 {
    uint8_t addr[16];
    int plen;
};
#define KEPT6_MAX 64

/* is MIB prefix (raw IN6_ADDR bytes, prefix length in plen) in the keep
 * set? Only meaningful for on-link routes — the caller gates on nexthop
 * :: first, so a nexthop-bearing route is never preserved. */
static bool sweep6_keep(const uint8_t *addr, UCHAR plen,
                        const struct kept6 *keep, size_t nkeep)
{
    for (size_t k = 0; k < nkeep; k++) {
        if (ip6_prefix_eq(addr, (int)plen, keep[k].addr, keep[k].plen))
            return true;
    }
    return false;
}

/* Sweep stale routes still bound to OUR adapter (audit M2): a crash,
 * force-kill or power loss leaves the metric-0 default route and the
 * server /32 pin alive until the next reboot, because the wintun
 * adapter intentionally persists and the stack never reclaims them —
 * the machine would keep routing its default into a dead tunnel.
 * Runs at every setup, BEFORE new routes are added; the on-link
 * connected route the stack manages for the interface address is kept.
 *
 * R45-L2: the v4-only sweep also stranded the IPv6 side — the policy
 * routes route_setup6 installs (`netsh interface ipv6 add route ...`,
 * all on-link with nexthop ::) and, after a crash of a run that brought
 * the derived ULA up, their stale entries stay on the persistent wintun
 * adapter: on the next config a leftover ::/0 via tun black-holes IPv6.
 * The v6 arm mirrors the v4 shape but with a PRECISE keep set: an
 * on-link route is preserved only when it is exactly fe80::/64 (the
 * interface link-local), the current derived ULA fd00::/96 (derived from
 * tun_ip, so a changed inner IPv4's /96 ROUTE is swept here; the
 * address side of the residue is handled by reconcile_stale_ula
 * (R53-E-1: reported, never auto-deleted — fd00::/96-shaped addresses
 * are indistinguishable from user config), or one of the currently
 * configured routes6 prefixes. R49-L5 tightened this: the old "every
 * on-link >= /64" keep could not tell a stack route from a user
 * proxy-cidr6 prefix (both are on-link with no nexthop), so a >= /64 v6
 * proxy prefix the user REMOVED from config — or a crash left behind —
 * was never swept and the tool could not remove it. tun_ip/routes6 are
 * optional (NULL): the pump-path teardown (route_iface_down) has
 * neither at hand, and there the current config and ULA were just
 * deleted by route_teardown6, so keeping only fe80::/64 is exactly
 * right. */
static void sweep_stale_routes(const char *tun, const char *tun_ip,
                               const slist_t *routes6)
{
    wchar_t wname[128];
    if (MultiByteToWideChar(CP_UTF8, 0, tun, -1, wname, 128) <= 0)
        return;
    NET_LUID luid;
    if (ConvertInterfaceAliasToLuid(wname, &luid) != NO_ERROR)
        return;
    PMIB_IPFORWARD_TABLE2 tbl;
    if (GetIpForwardTable2(AF_INET, &tbl) != NO_ERROR)
        return;
    ULONG removed = 0;
    for (ULONG i = 0; i < tbl->NumEntries; i++) {
        MIB_IPFORWARD_ROW2 *r = &tbl->Table[i];
        if (r->InterfaceLuid.Value != luid.Value)
            continue;
        /* keep the on-link connected route (nexthop unset, prefix >=
         * /24): the stack manages it for the interface address */
        if (r->NextHop.si_family == AF_INET &&
            r->NextHop.Ipv4.sin_addr.s_addr == 0 &&
            r->DestinationPrefix.PrefixLength >= 24)
            continue;
        if (DeleteIpForwardEntry2(r) == NO_ERROR)
            removed++;
    }
    FreeMibTable(tbl);
    /* R45-L2: sweep the AF_INET6 table with the same shape (best-
     * effort: a failure to fetch/scan the v6 table must not un-sweep
     * the v4 removals already counted above). R49-L5: keep-set is the
     * exact whitelist below — fe80::/64 (interface link-local), the
     * current derived ULA/96 and the configured routes6 prefixes — not
     * "every on-link >= /64" (which permanently preserved user >= /64
     * proxy prefixes removed from config). The ULA and config sets are
     * dropped when their inputs are absent: the pump-path teardown
     * passes NULL for both because route_teardown6 already deleted the
     * current config and ULA just before, so only fe80::/64 must not be
     * touched. */
    struct kept6 keep[KEPT6_MAX];
    size_t nkeep = 0;
    {
        static const uint8_t fe80[16] = { 0xfe, 0x80 };
        memcpy(keep[nkeep].addr, fe80, sizeof fe80);
        keep[nkeep].plen = 64;
        nkeep++;
    }
    if (tun_ip != NULL) {
        uint8_t v4[4], ula[16];
        if (s2ip4(tun_ip, v4)) {
            ip6_derive_ula(ip4_u32(v4), ula);
            memcpy(keep[nkeep].addr, ula, sizeof ula);
            keep[nkeep].plen = 96;
            nkeep++;
        }
    }
    if (routes6 != NULL) {
        for (size_t i = 0; i < routes6->n && nkeep < KEPT6_MAX; i++) {
            const char *c = routes6->v[i];
            const char *slash = strchr(c, '/');
            char addr[64];
            size_t an;
            if (slash == NULL) {
                /* defensive: expand_route_targets6 never emits a bare
                 * v6 entry; a malformed one has no installed route to
                 * protect so it is simply not whitelisted */
                continue;
            }
            an = (size_t)(slash - c);
            if (an == 0 || an >= sizeof addr)
                continue;
            memcpy(addr, c, an);
            addr[an] = '\0';
            struct in6_addr a6;
            if (inet_pton(AF_INET6, addr, &a6) != 1)
                continue;
            int plen = atoi(slash + 1);
            if (plen < 0 || plen > 128)
                continue;
            memcpy(keep[nkeep].addr, &a6, sizeof a6);
            keep[nkeep].plen = plen;
            nkeep++;
        }
    }
    if (GetIpForwardTable2(AF_INET6, &tbl) == NO_ERROR) {
        for (ULONG i = 0; i < tbl->NumEntries; i++) {
            MIB_IPFORWARD_ROW2 *r = &tbl->Table[i];
            if (r->InterfaceLuid.Value != luid.Value)
                continue;
            /* keep only the exact whitelist above (all three entries
             * are on-link routes with nexthop :: like every v6 policy
             * route we install, so the on-link gate cannot mis-hit);
             * every other route on this adapter — including a >= /64
             * prefix no longer in config, or the black-hole ::/0 — is
             * residue and is deleted. The prefix compare is exact
             * (masked bytes + length), never a string contains, so
             * fe80::/64 cannot be confused with any other prefix. */
            if (ip6_nexthop_unspec(&r->NextHop) &&
                sweep6_keep(
                    (const uint8_t *)&r->DestinationPrefix.Prefix.Ipv6.
                        sin6_addr,
                    r->DestinationPrefix.PrefixLength, keep, nkeep))
                continue;
            if (DeleteIpForwardEntry2(r) == NO_ERROR)
                removed++;
        }
        FreeMibTable(tbl);
    }
    if (removed)
        log_info("route sweep: removed %lu stale route(s) from %s",
                 removed, tun);
}

bool route_setup(const char *tun, const char *tun_ip, uint16_t mtu,
                 const char *srv, const char *ogw, const char *odev,
                 const char *metric, const slist_t *routes_with_default,
                 const slist_t *routes6)
{
    char tun_if[32], nh[40];
    struct in_addr s4;

    /* audit M2: crash leftover cleanup. R49-L5: the sweep is fed the
     * current config so the v6 keep-set includes the configured prefixes
     * and the current derived ULA/96 — the ONLY things it must preserve;
     * removed/crashed >= /64 v6 proxy prefixes are swept here. */
    sweep_stale_routes(tun, tun_ip, routes6);

    (void)metric;   /* Windows keeps the physical default in the table;
                     * teardown deletes only our own route, so there is
                     * nothing to restore (see route_teardown) */
    snprintf(tun_if, sizeof tun_if, "interface=%s", tun);
    snprintf(nh, sizeof nh, "nexthop=%s", tun_ip);

    /* every step mutates system state, so a failure must stop the
     * sequence and undo what was applied (mirror the Linux sequence) */
    if (!route_iface_up(tun, tun_ip, mtu)) {
        /* R50-D1: route_iface_up failed BEFORE tun_iface_up6 ran, so no
         * ULA was added THIS run — but a previous same-shape ULA may
         * still be on the persistent adapter, and route_iface_down's
         * NULL-whitelist sweep would delete its /96 while leaving the
         * address (the pair would then be split for every later run).
         * Drop the current v6 side first so address and /96 vanish
         * together and the next run re-adds both cleanly. */
        route_rollback_v6(tun, tun_ip, routes6);
        route_iface_down(tun);   /* undo any partial bring-up */
        return false;            /* nothing applied yet */
    }

    /* the server-pinned /32 only exists in the IPv4 table; an IPv6
     * server address cannot be pinned via the (IPv4) default gateway */
    if (inet_pton(AF_INET, srv, &s4) == 1 &&
        (ntohl(s4.s_addr) >> 24) != 127) {
        char srv32[40], odev_if[32], pin_nh[40];
        snprintf(srv32, sizeof srv32, "%s/32", srv);
        snprintf(odev_if, sizeof odev_if, "interface=%s", odev);
        char *del[] = { "netsh", "interface", "ipv4", "delete", "route",
                        srv32, odev_if, NULL };
        port_run_cmd(del);   /* idempotent setup: drop any stale pin */
        char *pin[10];
        int pi = 0;
        pin[pi++] = "netsh";
        pin[pi++] = "interface";
        pin[pi++] = "ipv4";
        pin[pi++] = "add";
        pin[pi++] = "route";
        pin[pi++] = srv32;
        pin[pi++] = odev_if;
        if (strcmp(ogw, "0.0.0.0") != 0) {
            snprintf(pin_nh, sizeof pin_nh, "nexthop=%s", ogw);
            pin[pi++] = pin_nh;
        }
        pin[pi] = NULL;
        if (!netsh_run(pin, "route_setup: pin server route")) {
            /* R50-D1: route_iface_up already added the derived ULA +
             * its on-link /96; the R49-L5 sweep inside route_iface_down
             * (tun_ip/routes6 NULL) would delete the /96 but leave the
             * ULA ADDRESS on the persistent wintun adapter, and the next
             * same-inner-IPv4 run's `netsh add address <ula>/96` would
             * then fail (address already present) — the /96 is never
             * rebuilt and the v6 client pool's on-link route is lost
             * across runs. Delete the current v6 side first so address
             * and route vanish together. */
            route_rollback_v6(tun, tun_ip, routes6);
            route_iface_down(tun);
            return false;
        }
    }

    for (size_t i = 0; i < routes_with_default->n; i++) {
        const char *c = routes_with_default->v[i];
        if (is_default_v4(c)) {
            /* replace the default: a metric-0 route via the tunnel
             * outranks the physical default, which is never removed */
            char *del[] = { "netsh", "interface", "ipv4", "delete",
                            "route", "0.0.0.0/0", tun_if, NULL };
            port_run_cmd(del);   /* idempotent replace */
            char *add[] = { "netsh", "interface", "ipv4", "add", "route",
                            "0.0.0.0/0", tun_if, nh, "metric=0", NULL };
            if (!netsh_run(add, "route_setup: default via tun"))
                goto rollback;
        } else {
            uint32_t net;
            int prefix;
            if (cidr_parse(c, &net, &prefix) != 0) {
                log_err("route_setup: invalid route target '%s'", c);
                goto rollback;
            }
            /* canonical network address (host bits cleared) */
            uint32_t mask = prefix == 0
                                ? 0
                                : ~((1u << (32 - prefix)) - 1);
            char prefix_s[24];
            prefix_str(net & mask, prefix, prefix_s);
            /* netsh has no "replace" verb: delete-then-add makes setup
             * idempotent and clears routes a crashed run left behind */
            char *del[] = { "netsh", "interface", "ipv4", "delete",
                            "route", prefix_s, tun_if, NULL };
            port_run_cmd(del);
            char *add[] = { "netsh", "interface", "ipv4", "add", "route",
                            prefix_s, tun_if, nh, NULL };
            if (!netsh_run(add, "route_setup: add route"))
                goto rollback;
        }
    }
    return true;

rollback:
    /* the loop applied at least one route: drop every entry it may have
     * installed (route_teardown tolerates entries never applied), then
     * tear the device down below. R50-D1: route_iface_up already added
     * the derived ULA + its /96; route_teardown's tail (route_iface_down
     * -> NULL-whitelist sweep) would delete the /96 but leave the ULA
     * ADDRESS — the next same-inner-IPv4 run's `netsh add address`
     * would then fail and never rebuild the /96. Delete the current v6
     * side FIRST so address and /96 vanish together. */
    log_err("route_setup: rolling back applied routes");
    route_rollback_v6(tun, tun_ip, routes6);
    route_teardown(tun, srv, ogw, odev, metric, routes_with_default);
    return false;
}
#elif defined(__APPLE__)
/* macOS session state: whether THIS process actually installed the
 * server /32 pin during route_setup. route_teardown must never remove
 * a route this process did not install — the flag is set only after
 * `route add -host <srv>/32 <ogw>` succeeds and cleared by teardown,
 * so a failed-setup rollback removes only our own pin and a
 * pre-existing user/third-party host route is never touched. */
static bool srv_pin_installed;

/* true when `netstat -rn -f inet` already shows an identical server /32
 * pin (destination <srv> or <srv>/32) via the same gateway `ogw`. Used
 * only on the route_setup add-failure path to distinguish "already
 * covered by a pre-existing route" from a real failure. */
static bool mac_pin_exists(const char *srv, const char *ogw)
{
    char *args[] = { "netstat", "-rn", "-f", "inet", NULL };
    char *out = port_cmd_capture(args, 65536);
    if (out == NULL)
        return false;
    char srv32[64];
    snprintf(srv32, sizeof srv32, "%s/32", srv);
    bool found = false;
    char *lsave = NULL;
    for (char *line = strtok_r(out, "\n", &lsave); line != NULL;
         line = strtok_r(NULL, "\n", &lsave)) {
        char *save = NULL;
        char *tok = strtok_r(line, " \t\r", &save);
        if (tok == NULL)
            continue;
        /* destination may be printed as the bare address or the /32
         * spelling; match either */
        if (strcmp(tok, srv) != 0 && strcmp(tok, srv32) != 0)
            continue;
        /* the gateway is the token right after the destination */
        char *gt = strtok_r(NULL, " \t\r", &save);
        if (gt == NULL)
            continue;
        if (strcmp(gt, ogw) == 0) {
            found = true;
            break;
        }
    }
    free(out);
    return found;
}

bool route_setup(const char *tun, const char *tun_ip, uint16_t mtu,
                 const char *srv, const char *ogw, const char *odev,
                 const char *metric, const slist_t *routes_with_default,
                 const slist_t *routes6) {
    (void)metric;
    (void)routes6;   /* IPv6 policy routes are handled by route_setup6 */
    const char *ifn = tun_ifname(tun);
    struct in_addr s4;
    bool srv_v4 = inet_pton(AF_INET, srv, &s4) == 1;
    bool srv_lo = srv_v4 && (ntohl(s4.s_addr) >> 24) == 127;
    char srv32[64];
    snprintf(srv32, sizeof srv32, "%s/32", srv);

    /* every step mutates system state, so a failure must stop the
     * sequence and undo what was applied (mirror the Linux sequence) */
    if (!route_iface_up(tun, tun_ip, mtu)) {
        route_iface_down(tun);
        return false;
    }
    /* pin the server route via the physical gateway so the session
     * never loops back through the tunnel. NEVER delete a pre-existing
     * host route here: a bare add failing EEXIST while an identical pin
     * (same /32 via the same gateway) is already present is fine — that
     * route was not installed by us, so srv_pin_installed stays false
     * and teardown will not remove it. */
    if (srv_v4 && !srv_lo) {
        char *pin[] = { "route", "-n", "add", "-host", srv32,
                        (char *)ogw, NULL };
        if (mac_run(pin, "route_setup: pin server route")) {
            srv_pin_installed = true;
        } else if (!mac_pin_exists(srv, ogw)) {
            /* a real failure: no pre-existing matching pin to rely on */
            route_iface_down(tun);
            return false;
        }
    }

    for (size_t i = 0; i < routes_with_default->n; i++) {
        const char *c = routes_with_default->v[i];
        if (is_default_v4(c)) {
            /* the physical default is never removed: add ours
             * alongside (macOS convention, cf. OpenVPN/WireGuard).
             * Delete-then-add keeps setup idempotent. */
            char *d0[] = { "route", "-n", "delete", "default",
                           "-interface", (char *)ifn, NULL };
            port_run_cmd(d0);   /* best-effort */
            char *r2[] = { "route", "-n", "add", "default",
                           "-interface", (char *)ifn, NULL };
            if (!mac_run(r2, "route_setup: default via tun"))
                goto rollback;
        } else {
            uint32_t net;
            int prefix;
            if (cidr_parse(c, &net, &prefix) != 0) {
                log_err("route_setup: invalid route target '%s'", c);
                goto rollback;
            }
            /* canonical network address (host bits cleared): BSD radix
             * stores the literal address as the route key while lookups
             * match the MASKED key, so an unmasked target like
             * "10.0.1.5/24" installs a route that can never hit */
            uint32_t mask = prefix == 0
                                ? 0
                                : ~((1u << (32 - prefix)) - 1);
            uint32_t canon = net & mask;
            char netstr[24];
            snprintf(netstr, sizeof netstr, "%u.%u.%u.%u/%d",
                     (canon >> 24) & 0xFF, (canon >> 16) & 0xFF,
                     (canon >> 8) & 0xFF, canon & 0xFF, prefix);
            char *d3[] = { "route", "-n", "delete", "-net", netstr,
                           "-interface", (char *)ifn, NULL };
            port_run_cmd(d3);   /* idempotent setup */
            char *r3[] = { "route", "-n", "add", "-net", netstr,
                           "-interface", (char *)ifn, NULL };
            if (!mac_run(r3, "route_setup: add route"))
                goto rollback;
        }
    }
    return true;

rollback:
    log_err("route_setup: rolling back applied routes");
    /* route_teardown deletes the server pin only when srv_pin_installed
     * is set, which it is only after the pin add above succeeded — so a
     * failed-setup rollback removes only our own pin, never a
     * pre-existing user/third-party host route. */
    route_teardown(tun, srv, ogw, odev, metric, routes_with_default);
    return false;
}
#else
/* Linux/POSIX session state: whether THIS process actually installed the
 * tunnel default route and/or the server /32 pin during route_setup.
 * route_teardown must never remove a route this process did not install;
 * in particular, when route_setup fails BEFORE replacing the default, the
 * rollback must leave the pre-existing physical default(s) completely
 * untouched (an unqualified `route del default` would delete the real
 * default and strand the machine). Each flag is set only after the
 * matching install command succeeds and cleared by route_teardown, so a
 * later session starts clean. */
static bool srv_default_installed;
static bool srv_pin_installed;

/* R1-C-C-2: canonical "a.b.c.d/plen" network string. iproute2 (verified
 * on 6.3..6.17) rejects a prefix with host bits set at parse time
 * ("Invalid prefix for given prefix length"), and the permissive builds
 * store the masked key anyway — so `ip route` must be handed the network
 * address, not the raw user string ("10.0.0.5/24" -> "10.0.0.0/24").
 * Returns false when `c` is not A.B.C.D/n; the caller then keeps the raw
 * string (old behavior, never worse than before). */
static bool canon_v4_cidr(const char *c, char out[24]) {
    uint32_t net;
    int prefix;
    if (cidr_parse(c, &net, &prefix) != 0)
        return false;
    uint32_t mask = prefix == 0 ? 0 : ~((1u << (32 - prefix)) - 1);
    uint32_t canon = net & mask;
    snprintf(out, 24, "%u.%u.%u.%u/%d", (canon >> 24) & 0xFF,
             (canon >> 16) & 0xFF, (canon >> 8) & 0xFF, canon & 0xFF,
             prefix);
    return true;
}

bool route_setup(const char *tun, const char *tun_ip, uint16_t mtu,
                 const char *srv, const char *ogw, const char *odev,
                 const char *metric, const slist_t *routes_with_default,
                 const slist_t *routes6) {
    char srv32[64];
    struct in_addr s4;
    (void)routes6;   /* IPv6 policy routes are handled by route_setup6 */
    bool srv_v4 = inet_pton(AF_INET, srv, &s4) == 1;
    /* loopback servers (e.g. --server 127.0.0.1 when client and server
     * share a host) are local: no /32 pin is needed, and the kernel
     * rejects `ip route add 127.0.0.1/32 via <gw>` (EEXIST against the
     * local table), which would roll back the whole setup */
    bool srv_lo = srv_v4 && (ntohl(s4.s_addr) >> 24) == 127;
    snprintf(srv32, sizeof srv32, "%s/32", srv);
    char *fc[] = { "route", "flush", "cache", NULL };

    /* B-1/B-2: start a fresh session — neither the tunnel default nor
     * the server pin is installed yet, so if anything below fails before
     * we install them, the rollback (route_teardown) must not touch the
     * pre-existing routes (it only acts when the matching flag is set) */
    srv_default_installed = false;
    srv_pin_installed = false;

    /* every step mutates system state, so a failure must stop the
     * sequence and undo what was applied; a half-configured tunnel
     * (e.g. routes replaced but no srv route) would otherwise claim to
     * be up while the machine has no working path to the server */
    if (!route_iface_up(tun, tun_ip, mtu)) {
        route_iface_down(tun);   /* undo any partial bring-up */
        return false;            /* nothing applied yet */
    }
    /* the server-pinned /32 only exists in the IPv4 table; an IPv6
     * server address cannot be routed via the (IPv4) default gateway
     * and would fail every `ip route add` attempt, so skip it.
     * M4 (SUMMARY-2): `replace` not `add` — a pin left behind by a
     * crashed client would make every later connection fail with
     * EEXIST (and the stale pin blackholes server traffic) */
    if (srv_v4 && !srv_lo) {
        char *a5[] = { "route", "replace", srv32, "via", (char *)ogw, "dev",
                       (char *)odev, NULL };
        if (!ip_run(a5)) {
            log_err("route_setup: route replace %s via %s dev %s failed",
                    srv32, ogw, odev);
            route_iface_down(tun);
            return false;
        }
        /* B-2: remember that WE now own this /32 — teardown may only
         * remove it (and only via the same via/dev attributes) when this
         * flag is set, so a pre-existing /32 that we never replaced is
         * never deleted by us */
        srv_pin_installed = true;
    }

    for (size_t i = 0; i < routes_with_default->n; i++) {
        const char *c = routes_with_default->v[i];
        if (is_default_v4(c)) {
            char loc[24];
            if (local_subnet(odev, loc)) {
                char *r1[] = { "route", "replace", loc, "dev", (char *)odev,
                               NULL };
                if (!ip_run(r1)) {
                    log_err("route_setup: route replace %s dev %s failed "
                            "(local subnet must not route via the tunnel)",
                            loc, odev);
                    goto rollback_routes;
                }
                log_info("preserved local subnet %s", loc);
            } else {
                log_debug("route_setup: no local subnet on %s to preserve",
                          odev);
            }
            /* R1-C-C-1: deliberately NOT carrying `metric` here. A
             * metric-less replace installs a priority-0 tunnel default
             * that beats every metric>0 default (the hijack always
             * works) while the pre-VPN default stays in the table; if
             * the process dies the TUN device unregisters and takes its
             * route with it, so the untouched physical default
             * self-heals. Replacing the physical default at its own
             * metric instead would (a) lose it for good on a crash and
             * (b) fail to hijack when another lower-metric default
             * exists. The restore path below owns the pre-VPN entry. */
            char *r2[] = { "route", "replace", "default", "dev",
                           (char *)tun, NULL };
            if (!ip_run(r2)) {
                log_err("route_setup: route replace default dev %s failed",
                        tun);
                goto rollback_routes;
            }
            /* B-1: remember that we replaced the default with a tunnel
             * route (dev <tun>, no via). route_teardown may only delete
             * the default (and then restore the pre-VPN one) when this
             * flag is set, so a setup that fails before this point never
             * tears the pre-existing physical default away. */
            srv_default_installed = true;
        } else {
            char netstr[24];
            const char *target = c;
            if (canon_v4_cidr(c, netstr))
                target = netstr;
            char *r3[] = { "route", "replace", (char *)target, "dev",
                           (char *)tun, NULL };
            if (!ip_run(r3)) {
                log_err("route_setup: route replace %s dev %s failed", target,
                        tun);
                goto rollback_routes;
            }
        }
    }
    /* flush the route cache once, after every route is in place (the
     * per-route flush in the old code restarted the cache 1..N times
     * for no observable benefit) */
    ip_run(fc);
    return true;

rollback_routes:
    /* the loop replaced at least one route: restore the pre-VPN default
     * and drop every entry the loop may have installed (route_teardown
     * tolerates entries that were never applied), then tear the device
     * down below */
    log_err("route_setup: rolling back applied routes");
    route_teardown(tun, srv, ogw, odev, metric, routes_with_default);
    return false;
}
#endif /* _WIN32 */

/* R50-D1: restore the ULA/96 pair invariant on the Windows rollback
 * paths (see route.h). A setup/pump session that fails AFTER
 * tun_iface_up6 added the derived ULA address (and the on-link /96
 * route the stack attaches to it) rolls back through route_iface_down,
 * whose R49-L5 sweep keeps only fe80::/64 — it deletes the /96 route
 * but NOTHING deletes the ULA ADDRESS (address deletion lives in
 * route_teardown6, which the rollback never reaches; proxy.c's teardown6
 * only runs on the normal-close path). A later run with the same inner
 * IPv4 then sees the address already present: `netsh interface ipv6 add
 * address <ula>/96` fails, the /96 is never rebuilt and the v6 client
 * pool's on-link route is missing across runs. This helper deletes the
 * current run's routes6 prefixes and its derived ULA BEFORE the rollback
 * sweep runs, so BOTH legs of the pair disappear and the next run
 * re-adds address + /96 atomically. Every delete is best-effort with
 * "not present" at debug level; no-op on Apple/Linux (no persistent
 * adapter, v6 routes vanish with the tun device — the pair cannot be
 * split, and netstack re-derives everything on the next setup). */
void route_rollback_v6(const char *tun, const char *tun_ip,
                       const slist_t *routes6)
{
#ifdef _WIN32
    char ifa[32];
    snprintf(ifa, sizeof ifa, "interface=%s", tun);
    if (routes6 != NULL) {
        for (size_t i = 0; i < routes6->n; i++) {
            const char *c = routes6->v[i];
            /* none of these routes was installed by the failed session
             * (route_setup6 runs only after route_setup succeeds), so a
             * present one is a crash/stale leftover being cleaned — a
             * missing one is the common case and logs at debug only */
            char *d[] = { "netsh", "interface", "ipv6", "delete",
                          "route", (char *)c, ifa, NULL };
            if (port_run_cmd(d) != 0)
                log_debug("route_rollback_v6: del %s: not present", c);
        }
    }
    /* the derived ULA the current run added (or a previous same-shape
     * one a re-run preserved): delete the bare address, mirroring
     * route_teardown6's address arm */
    char ula[64];
    if (tun_ula_str(tun_ip, ula)) {
        char *u[] = { "netsh", "interface", "ipv6", "delete",
                      "address", ifa, ula, NULL };
        if (port_run_cmd(u) != 0)
            log_debug("route_rollback_v6: delete ULA %s: not present", ula);
    }
#else
    (void)tun;
    (void)tun_ip;
    (void)routes6;
#endif
}

#ifdef _WIN32
void route_teardown(const char *tun, const char *srv, const char *ogw,
                    const char *odev, const char *metric,
                    const slist_t *routes)
{
    char tun_if[32];

    (void)ogw;
    (void)metric;
    snprintf(tun_if, sizeof tun_if, "interface=%s", tun);
    for (size_t i = 0; i < routes->n; i++) {
        const char *c = routes->v[i];
        if (is_default_v4(c)) {
            /* the physical default was never removed, so deleting our
             * own 0.0.0.0/0 restores the pre-VPN routing automatically */
            char *d1[] = { "netsh", "interface", "ipv4", "delete",
                           "route", "0.0.0.0/0", tun_if, NULL };
            port_run_cmd(d1);   /* best-effort: ours may never have applied */
        } else {
            uint32_t net;
            int prefix;
            if (cidr_parse(c, &net, &prefix) != 0)
                continue;
            uint32_t mask = prefix == 0
                                ? 0
                                : ~((1u << (32 - prefix)) - 1);
            char prefix_s[24];
            prefix_str(net & mask, prefix, prefix_s);
            char *d2[] = { "netsh", "interface", "ipv4", "delete",
                           "route", prefix_s, tun_if, NULL };
            port_run_cmd(d2);   /* best-effort */
        }
    }
    /* drop the server pin installed on the physical NIC by route_setup */
    struct in_addr s4;
    if (inet_pton(AF_INET, srv, &s4) == 1 &&
        (ntohl(s4.s_addr) >> 24) != 127) {
        char srv32[40], odev_if[32];
        snprintf(srv32, sizeof srv32, "%s/32", srv);
        snprintf(odev_if, sizeof odev_if, "interface=%s", odev);
        char *d3[] = { "netsh", "interface", "ipv4", "delete", "route",
                       srv32, odev_if, NULL };
        port_run_cmd(d3);
    }
    route_iface_down(tun);
}
#elif defined(__APPLE__)
void route_teardown(const char *tun, const char *srv, const char *ogw,
                    const char *odev, const char *metric,
                    const slist_t *routes) {
    (void)ogw;
    (void)odev;
    (void)metric;
    const char *ifn = tun_ifname(tun);
    for (size_t i = 0; i < routes->n; i++) {
        const char *c = routes->v[i];
        if (is_default_v4(c)) {
            /* only OUR default is removed (interface-scoped); the
             * physical default was never touched */
            char *d1[] = { "route", "-n", "delete", "default",
                           "-interface", (char *)ifn, NULL };
            port_run_cmd(d1);   /* best-effort */
        } else {
            /* match route_setup's canonical form (host bits cleared):
             * deleting the raw user string can miss the installed key.
             * Also delete the raw string when it differs — a pre-fix
             * run may have stored an unmasked target. */
            uint32_t net;
            int prefix;
            char target[24];
            if (cidr_parse(c, &net, &prefix) == 0) {
                uint32_t mask = prefix == 0
                                    ? 0
                                    : ~((1u << (32 - prefix)) - 1);
                uint32_t canon = net & mask;
                snprintf(target, sizeof target, "%u.%u.%u.%u/%d",
                         (canon >> 24) & 0xFF, (canon >> 16) & 0xFF,
                         (canon >> 8) & 0xFF, canon & 0xFF, prefix);
            } else {
                snprintf(target, sizeof target, "%s", c);
            }
            char *d3[] = { "route", "-n", "delete", "-net", target,
                           "-interface", (char *)ifn, NULL };
            port_run_cmd(d3);   /* best-effort */
            if (strcmp(target, c) != 0) {
                char *d3b[] = { "route", "-n", "delete", "-net",
                                (char *)c, "-interface", (char *)ifn,
                                NULL };
                port_run_cmd(d3b);   /* legacy residue, best-effort */
            }
        }
    }
    char srv32[64];
    struct in_addr s4;
    snprintf(srv32, sizeof srv32, "%s/32", srv);
    /* only remove the server /32 pin this process actually installed:
     * srv_pin_installed is set by route_setup right after its
     * `route add -host <srv>/32 <ogw>` succeeds. Qualifying the delete
     * with the gateway makes route(8) target exactly the entry we
     * created, so a pre-existing /32 via another gateway is never
     * touched. Clear the flag whether or not the delete succeeds —
     * afterwards we no longer own a pin. */
    if (inet_pton(AF_INET, srv, &s4) == 1 &&
        (ntohl(s4.s_addr) >> 24) != 127 && srv_pin_installed) {
        char *d4[] = { "route", "-n", "delete", "-host", srv32,
                       (char *)ogw, NULL };
        port_run_cmd(d4);   /* best-effort */
        srv_pin_installed = false;
    }
    route_iface_down(tun);
}
#else
void route_teardown(const char *tun, const char *srv, const char *ogw,
                    const char *odev, const char *metric,
                    const slist_t *routes) {
    for (size_t i = 0; i < routes->n; i++) {
        const char *c = routes->v[i];
        if (is_default_v4(c)) {
            /* B-1: only ever remove a default that THIS process really
             * installed. route_setup sets srv_default_installed only
             * after `route replace default dev <tun>` succeeded, so when
             * setup failed before that step (rollback path) — or there
             * is simply no tunnel default from this session — the
             * pre-existing physical default(s) are left completely
             * untouched; the old unqualified `route del default` would
             * have deleted the real default and stranded the machine. */
            if (!srv_default_installed)
                continue;
            /* we did replace the default: clear the flag up front —
             * whether or not the delete below succeeds we no longer own
             * a tunnel default afterwards, so a later teardown (or a
             * fresh session) cannot act on stale state. */
            srv_default_installed = false;
            /* delete ONLY the tunnel default we installed, mirroring
             * setup's `route replace default dev <tun>`: qualifying with
             * `dev <tun>` means a multi-default host loses only our
             * entry (the old unqualified del was ambiguous there and
             * could remove an unrelated default on a single-default host
             * during a failed-setup rollback). */
            char *d1[] = { "route", "del", "default", "dev",
                           (char *)tun, NULL };
            if (!ip_run(d1)) {
                /* our tunnel default is already gone (crash cleanup, or
                 * the replace never took effect): leave whatever default
                 * is there alone */
                log_debug("route_teardown: no tunnel default on %s to "
                          "delete", tun);
                continue;
            }
            /* we removed it: restore the original via-gateway route,
             * keeping its metric (captured by capture_default) so route
             * precedence matches the pre-VPN state — a metric-less
             * restore would install a priority-0 default that shadows
             * (or is shadowed by) other defaults.
             *
             * R1-C-C-1: `replace`, NOT `add`. The kernel matches route
             * aliases by (prefix, dscp, fib_priority), so setup's
             * metric-less `replace default dev <tun>` does not replace a
             * DHCP default carrying e.g. metric 100 — both coexist and
             * the physical one is still in the table here. `add` would
             * then fail EEXIST and the device-only fallback below would
             * install a priority-0 on-link default that shadows the real
             * one: the host kept "a" default route but every off-link
             * packet went to ARP on the physical NIC (silent, host-wide
             * outage after a clean exit). `replace` is idempotent when
             * the original route is still present (rc=0, no change) and
             * re-creates it when it is genuinely gone, so the
             * destructive fallback is only reached when the kernel
             * really refuses the restore. */
            char *d2[10];
            int di = 0;
            d2[di++] = "route";
            d2[di++] = "replace";
            d2[di++] = "default";
            d2[di++] = "via";
            d2[di++] = (char *)ogw;
            d2[di++] = "dev";
            d2[di++] = (char *)odev;
            if (metric[0] != '\0') {
                d2[di++] = "metric";
                d2[di++] = (char *)metric;
            }
            d2[di] = NULL;
            if (!ip_run(d2)) {
                /* the original gateway may have vanished while the VPN
                 * was up (wifi switch, NIC down): fall back to a
                 * device-only default route so the machine is never
                 * left with NO default route at all */
                log_err("route_teardown: restore default via %s dev %s "
                        "failed — trying device-only default",
                        ogw, odev);
                char *d2b[] = { "route", "replace", "default", "dev",
                                (char *)odev, NULL };
                if (!ip_run(d2b))
                    log_err("route_teardown: NO default route after "
                            "teardown; fix manually: ip route add "
                            "default via %s dev %s", ogw, odev);
            }
        } else {
            /* only remove the entry we installed on the tunnel dev; an
             * unqualified del could clobber a same-prefix route on
             * another device. The target is canonicalized exactly like
             * route_setup installs it (R1-C-C-2), so the delete always
             * addresses the key the kernel actually stored */
            char netstr[24];
            const char *target = c;
            if (canon_v4_cidr(c, netstr))
                target = netstr;
            char *d3[] = { "route", "del", (char *)target, "dev",
                           (char *)tun, NULL };
            if (!ip_run(d3))
                log_debug("route_teardown: route del %s: not present",
                          target);
        }
    }
    char srv32[64];
    struct in_addr s4;
    snprintf(srv32, sizeof srv32, "%s/32", srv);
    /* B-2: only remove the server /32 pin this process actually
     * installed — srv_pin_installed is set by route_setup right after
     * `route replace <srv>/32 via <ogw> dev <odev>` succeeds. The delete
     * mirrors setup's via/dev attributes, so a pre-existing /32 that is
     * not ours (or one pinned via another gateway/device) is never
     * touched by the teardown. */
    if (inet_pton(AF_INET, srv, &s4) == 1 &&
        (ntohl(s4.s_addr) >> 24) != 127 && srv_pin_installed) {
        char *d4[] = { "route", "del", srv32, "via", (char *)ogw, "dev",
                       (char *)odev, NULL };
        if (!ip_run(d4))
            log_debug("route_teardown: route del %s: not present", srv32);
        srv_pin_installed = false;
    }
    route_iface_down(tun);
    char *fc[] = { "route", "flush", "cache", NULL };
    ip_run(fc);
}
#endif /* _WIN32 */

/* IPv6 proxy routes through the tunnel (see route.h: best-effort) */
void route_setup6(const char *tun, const slist_t *routes6)
{
    if (routes6 == NULL)
        return;
#ifdef _WIN32
    char ifa[32];
    snprintf(ifa, sizeof ifa, "interface=%s", tun);
    for (size_t i = 0; i < routes6->n; i++) {
        const char *c = routes6->v[i];
        /* R46-L3: mirror the v4 side (route_setup gives the default
         * route an explicit metric=0, outranking every physical default;
         * proxy-cidr prefixes stay metric-less — the v4 proxy-cidr arm
         * has no metric either, so the two sides stay fully symmetric).
         * Without it a same-prefix ::/0 on the tunnel competes by
         * EFFECTIVE metric, and a physical NIC with a lower v6
         * interface metric wins — the tunnel ::/0 silently loses.
         * R49-L5: netsh `add route` is an append, so a same-prefix
         * route left by an older config/crash (or by THIS run, when a
         * configured prefix is re-added on a reconnect) would either
         * be duplicated or shadow the new one; mirror the v4 default
         * arm and the Apple arm — pre-delete idempotently before the
         * add. "Not present" is the common case, so its failure is
         * debug-level only (port_run_cmd style, like the v4 arm's
         * `delete route` pre-step). */
        char *d[] = { "netsh", "interface", "ipv6", "delete", "route",
                      (char *)c, ifa, NULL };
        if (port_run_cmd(d) != 0)
            log_debug("route_setup6: pre-delete %s: not present", c);
        int na = 0;
        char *a[10];
        a[na++] = "netsh";
        a[na++] = "interface";
        a[na++] = "ipv6";
        a[na++] = "add";
        a[na++] = "route";
        a[na++] = (char *)c;
        a[na++] = ifa;
        if (strcmp(c, "::/0") == 0)
            a[na++] = "metric=0";
        a[na] = NULL;
        if (netsh_run(a, "route_setup6: add route"))
            continue;
        log_err("route_setup6: add %s failed", c);
    }
#elif defined(__APPLE__)
    const char *ifn = tun_ifname(tun);
    for (size_t i = 0; i < routes6->n; i++) {
        const char *c = routes6->v[i];
        char *d[] = { "route", "-n", "delete", "-inet6", (char *)c,
                      "-interface", (char *)ifn, NULL };
        port_run_cmd(d);   /* idempotent setup */
        char *a[] = { "route", "-n", "add", "-inet6", (char *)c,
                      "-interface", (char *)ifn, NULL };
        if (mac_run(a, "route_setup6: add route"))
            continue;
        log_err("route_setup6: add %s failed", c);
    }
#else
    /* R49-L2: `replace`, not `add`, mirroring the v4 arm's metric-less
     * `route replace ... dev <tun>` (see the R1-C-C-1 note in route_setup,
     * route.c ~line 1096). `add` was broken in two ways on any dual-stack
     * host that already has a physical IPv6 default: the kernel applies
     * IP6_RT_PRIO_USER (1024) to a v6 netlink route whose RTA_PRIORITY is
     * absent (inet6_rtm_newroute), so (a) a `add ::/0` collided with an
     * RA default at the same 1024 and rtnetlink answered EEXIST — the
     * tunnel ::/0 was never installed, and (b) even when the metrics
     * differed, the 1024 tunnel default lost to any lower-metric physical
     * default. The metric below is therefore written EXPLICITLY as
     * `metric 0`: on IPv6 an absent metric is 1024, NOT the priority-0 an
     * absent metric means on IPv4, so the v4 tradeoff (a priority-0
     * tunnel default that outranks every physical default while the
     * physical default stays in the table and self-heals when the TUN
     * unregisters) is only reproducible on v6 by naming metric 0. The
     * v4/v6 replace tradeoffs are otherwise shared: replace is idempotent
     * (a leftover from an old run — at any metric — is superseded in its
     * slot if identical or re-created), and neither side ever removes the
     * physical default because independent metrics keep both entries in
     * the table; the only shared edge is a pre-existing physical route AT
     * priority 0, which replace takes over exactly as the v4 arm does.
     * route_teardown6's `-6 route del <c> dev <tun>` already deletes the
     * priority-0 dev-<tun> entry and leaves any other default alone. */
    for (size_t i = 0; i < routes6->n; i++) {
        const char *c = routes6->v[i];
        char *a[] = { "-6", "route", "replace", (char *)c,
                      "dev", (char *)tun, "metric", "0", NULL };
        if (!ip_run(a))
            log_err("route_setup6: ip -6 route replace %s dev %s failed",
                    c, tun);
    }
#endif
}

void route_teardown6(const char *tun, const char *tun_ip,
                     const slist_t *routes6)
{
    if (routes6 == NULL)
        return;
#ifdef _WIN32
    char ifa[32];
    snprintf(ifa, sizeof ifa, "interface=%s", tun);
    for (size_t i = 0; i < routes6->n; i++) {
        const char *c = routes6->v[i];
        char *d[] = { "netsh", "interface", "ipv6", "delete", "route",
                      (char *)c, ifa, NULL };
        if (netsh_run(d, "route_teardown6: delete route"))
            continue;
        log_debug("route_teardown6: del %s: not present", c);
    }
    /* best-effort: also drop the derived ULA address. wintun adapters
     * are persistent objects, so a leftover ULA would stick to the next
     * run; delete is idempotent and failure is only logged (bare ULA,
     * no /96). */
    char ula[64];
    if (tun_ula_str(tun_ip, ula)) {
        char *u[] = { "netsh", "interface", "ipv6", "delete", "address",
                      ifa, ula, NULL };
        if (port_run_cmd(u) != 0)
            log_debug("route_teardown6: delete ULA %s: not present", ula);
    }
#elif defined(__APPLE__)
    (void)tun_ip;
    const char *ifn = tun_ifname(tun);
    for (size_t i = 0; i < routes6->n; i++) {
        const char *c = routes6->v[i];
        char *d[] = { "route", "-n", "delete", "-inet6", (char *)c,
                      "-interface", (char *)ifn, NULL };
        if (mac_run(d, "route_teardown6: delete route"))
            continue;
        log_debug("route_teardown6: del %s: not present", c);
    }
#else
    (void)tun_ip;
    for (size_t i = 0; i < routes6->n; i++) {
        const char *c = routes6->v[i];
        char *d[] = { "-6", "route", "del", (char *)c,
                      "dev", (char *)tun, NULL };
        if (!ip_run(d))
            log_debug("route_teardown6: ip -6 route del %s: not present", c);
    }
#endif
}
