#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"
#include "profile.h"
#include "protocol.h"

#define UDP_RXBATCH 64 /* recvmmsg drain batch size */
#include "server.h"
#include "tun.h"
#include "util.h"

/* The shared stop flag comes from util.c (atomic_bool, see util.h): the
 * SIGINT/SIGTERM/SIGHUP handler stores to it (relaxed, lock-free on every
 * supported target), the main loop reads it, and the TUN reader pool
 * receives &g_stop as its abort flag. No private copy — a second flag
 * would let the readers keep running after the loop stopped. */
static volatile sig_atomic_t g_child_pid = -1; /* root parent: the forked
                                                * server process */

/* root parent: forward termination signals to the child. The child owns
 * the graceful shutdown (and the cleanup after it); forwarding makes
 * kill <parent-pid>, SIGHUP from a dropped SSH session and systemd
 * KillMode=process all stop the server instead of being swallowed.
 * g_child_pid is sig_atomic_t: written by the main loop after the fork,
 * read from this async-signal context — a wider type would be a C11
 * data race. */
static void parent_fwd_signal(int sig)
{
    if (g_child_pid > 0)
        kill(g_child_pid, sig);
}

/* install one handler; returns 0 on success. Callers treat failure as
 * fatal: a server that cannot catch SIGINT/SIGTERM cannot shut down
 * gracefully, and a parent that cannot forward leaves the child running
 * and the NAT state stranded. */
static int install_sig(int sig, void (*handler)(int), int flags)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);
    return sigaction(sig, &sa, NULL);
}

struct opts {
    uint16_t port;
    char tun[IFNAMSIZ];
    char server_ip[16];
    char subnet[64];
    int mask;
    char dns[16];
    char users[256];
    char nat_if[64];
    char user[64];   /* drop root privileges to this account (A1) */
    bool no_tun;
};

static const struct option long_opts[] = {
    { "port",      required_argument, NULL, 'p' },
    { "tun",       required_argument, NULL, 't' },
    { "server-ip", required_argument, NULL, 's' },
    { "subnet",    required_argument, NULL, 'S' },
    { "dns",       required_argument, NULL, 'd' },
    { "users",     required_argument, NULL, 'u' },
    { "nat-if",    required_argument, NULL, 'n' },
    { "no-tun",    no_argument,       NULL, 'T' },
    { "user",      required_argument, NULL, 'U' },
    { "help",      no_argument,       NULL, 'h' },
    { NULL, 0, NULL, 0 },
};

static void on_signal(int sig)
{
    (void)sig;
    g_stop = true; /* shared atomic_bool (util.c): main loop + pool abort */
}

static void usage(const char *prog, FILE *out)
{
    fprintf(out, "usage: %s [options]\n", prog);
    fprintf(out, "  -p, --port <P>         UDP port to listen on (default 6001)\n");
    fprintf(out, "  -t, --tun <NAME>       TUN device name (default iwan-srv)\n");
    fprintf(out, "  -s, --server-ip <IP>   server/gateway IP on the TUN (default 198.18.0.1)\n");
    fprintf(out, "  -S, --subnet <IP/MASK> client subnet, mask 8-30 (default 198.18.0.0/16)\n");
    fprintf(out, "  -d, --dns <IP>         DNS server advertised to clients (default 114.114.114.114)\n");
    fprintf(out, "  -u, --users <FILE>     users file, one user:pass per line (default /etc/iwan/users.txt)\n");
    fprintf(out, "  -n, --nat-if <IF>      outbound interface for MASQUERADE (default eth0)\n");
    fprintf(out, "      --no-tun           (testing) skip TUN device\n");
    fprintf(out, "      --user <NAME>      drop root privileges to this user after setup (default nobody)\n");
    fprintf(out, "  -h, --help             show this help\n");
}

/* exit-code convention (matches iwan-client): usage errors exit 2 with
 * the usage text on stderr; runtime errors exit 1 */
static void usage_error(const char *prog, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    usage(prog, stderr);
    exit(2);
}

static void parse_opts(int argc, char **argv, struct opts *o)
{
    int c;

    while ((c = getopt_long(argc, argv, "p:t:s:S:d:u:n:Th", long_opts, NULL)) != -1) {
        switch (c) {
        case 'p':
            if (str_to_u16(optarg, &o->port) != 0)
                usage_error(argv[0], "error: invalid port '%s'", optarg);
            break;
        case 't':
            if (strlen(optarg) >= IFNAMSIZ)
                usage_error(argv[0],
                            "error: tun device name too long (max %d)",
                            IFNAMSIZ - 1);
            snprintf(o->tun, sizeof o->tun, "%s", optarg);
            break;
        case 's':
            snprintf(o->server_ip, sizeof o->server_ip, "%s", optarg);
            break;
        case 'S':
            snprintf(o->subnet, sizeof o->subnet, "%s", optarg);
            break;
        case 'd':
            snprintf(o->dns, sizeof o->dns, "%s", optarg);
            break;
        case 'u':
            snprintf(o->users, sizeof o->users, "%s", optarg);
            break;
        case 'n':
            snprintf(o->nat_if, sizeof o->nat_if, "%s", optarg);
            break;
        case 'T':
            o->no_tun = true;
            break;
        case 'U':
            snprintf(o->user, sizeof o->user, "%s", optarg);
            break;
        case 'h':
            usage(argv[0], stdout);
            exit(0);
        default:
            usage_error(argv[0], "error: unknown option");
        }
    }
    if (optind < argc)
        usage_error(argv[0], "error: unexpected argument '%s'", argv[optind]);
}

/* trim spaces/tabs/CR/LF at both ends, in place. */
static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == '\n' || end[-1] == '\r'))
        end--;
    *end = '\0';
    return s;
}

/* "ip/mask" -> network base (BE u32), mask, and normalized "net/mask" string. */
static int parse_subnet(const char *s, uint32_t *base, int *mask,
                        char *net, size_t net_sz)
{
    char ip_part[64];
    const char *slash = strchr(s, '/');
    size_t n;
    uint8_t ip[4];
    uint32_t mask32;

    if (!slash)
        return -1;
    n = (size_t)(slash - s);
    if (n == 0 || n >= sizeof ip_part)
        return -1;
    memcpy(ip_part, s, n);
    ip_part[n] = '\0';

    {
        char *mend;
        long m = strtol(slash + 1, &mend, 10);
        if (mend == slash + 1 || *mend != '\0' || m < 8 || m > 30)
            return -1;
        *mask = (int)m;
    }
    if (!s2ip4(ip_part, ip))
        return -1;

    mask32 = 0xFFFFFFFFu << (32 - *mask);
    *base = ip4_u32(ip) & mask32;
    if (net) {
        uint8_t b[4];
        u32_ip4(*base, b);
        snprintf(net, net_sz, "%u.%u.%u.%u/%d", b[0], b[1], b[2], b[3], *mask);
    }
    return 0;
}

/* one "user:pass" per line, '#' comments, whitespace trimmed. Returns count. */
static int load_users(const char *path, struct server_user *users, int max)
{
    FILE *f = fopen(path, "r");
    char line[512];
    int n = 0;

    if (!f)
        return -1;
    while (n < max && fgets(line, sizeof line, f)) {
        /* detect overlong lines BEFORE trim() strips the trailing '\n' */
        bool too_long = !strchr(line, '\n') && !feof(f);
        char *s = trim(line);
        if (too_long) {
            /* would be split across fgets calls and mis-parsed; skip the
             * remainder of this line entirely */
            int ch;
            fprintf(stderr, "warning: skipping overlong users line\n");
            while ((ch = fgetc(f)) != '\n' && ch != EOF)
                ;
            continue;
        }
        if (*s == '\0' || *s == '#')
            continue;
        char *colon = strchr(s, ':');
        if (!colon)
            continue;
        *colon = '\0';
        char *name = trim(s);
        char *pass = trim(colon + 1);
        if (*name == '\0')
            continue;
        if (strlen(name) >= sizeof users[n].name ||
            strlen(pass) >= sizeof users[n].pass) {
            fprintf(stderr,
                    "warning: skipping user '%s': name/pass exceeds %d chars\n",
                    name, SERVER_USER_MAX);
            continue;
        }
        if (*pass == '\0') {
            fprintf(stderr, "warning: skipping user '%s': empty password\n",
                    name);
            continue;
        }
        int dup = 0;
        for (int k = 0; k < n; k++)
            if (strcmp(users[k].name, name) == 0)
                dup = 1;
        if (dup) {
            fprintf(stderr, "warning: skipping duplicate user '%s'\n", name);
            continue;
        }
        snprintf(users[n].name, sizeof users[n].name, "%s", name);
        snprintf(users[n].pass, sizeof users[n].pass, "%s", pass);
        n++;
    }
    if (n >= max) {
        int ch, extra = 0;
        while ((ch = fgetc(f)) != EOF)
            if (ch != '\n' && ch != '\r' && ch != ' ' && ch != '\t') {
                extra = 1;
                break;
            }
        if (extra)
            fprintf(stderr,
                    "warning: users file has more than %d entries; "
                    "the rest are ignored\n", max);
    }
    fclose(f);
    memset(line, 0, sizeof line); /* scrub raw lines (passwords) from the stack */
    return n;
}

/* host state saved for exit cleanup (C3): original ip_forward value and
 * the MASQUERADE rule this instance actually added, so shutdown can undo
 * exactly what we changed. */
static int saved_ip_forward = -1; /* -1: not captured */
static char nat_subnet_saved[64];
static char nat_if_saved[64];
static bool nat_rule_added;
static bool fwd_rule_added;   /* our FORWARD ACCEPT for the tunnel subnet */

static void enable_ip_forward(void)
{
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "r");
    bool ok;

    /* capture the original value before overwriting, so exit cleanup can
     * restore it (C3) */
    if (f) {
        if (fscanf(f, "%d", &saved_ip_forward) != 1)
            saved_ip_forward = -1;
        fclose(f);
    }
    f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (!f) {
        fprintf(stderr, "warning: cannot enable ip_forward: %s\n", strerror(errno));
        return;
    }
    ok = fputs("1", f) != EOF;
    if (fclose(f) != 0)
        ok = false;
    if (!ok)
        fprintf(stderr, "warning: cannot enable ip_forward: %s\n", strerror(errno));
}

/* fork/execvp a NULL-terminated argv; returns exit status or -1. */
static int run_cmd(char *const argv[])
{
    pid_t pid = fork();
    int st = 0;

    if (pid < 0)
        return -1;
    if (pid == 0) {
        exec_sanitize();
        execvp(argv[0], argv);
        _exit(127);
    }
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return -1;
}

static void setup_nat(const char *subnet, const char *nat_if)
{
    char *chk[] = { "iptables", "-t", "nat", "-C", "POSTROUTING", "-s",
                    (char *)subnet, "-o", (char *)nat_if, "-j", "MASQUERADE", NULL };
    char *add[] = { "iptables", "-t", "nat", "-A", "POSTROUTING", "-s",
                    (char *)subnet, "-o", (char *)nat_if, "-j", "MASQUERADE", NULL };

    /* -C first: rule already present -> nothing to do */
    if (run_cmd(chk) != 0) {
        if (run_cmd(add) == 0) {
            /* remember what we added so exit cleanup can remove exactly
             * this rule (C3); a rule that was already present is not ours
             * to remove */
            snprintf(nat_subnet_saved, sizeof nat_subnet_saved, "%s", subnet);
            snprintf(nat_if_saved, sizeof nat_if_saved, "%s", nat_if);
            nat_rule_added = true;
            printf("iptables: MASQUERADE %s -> %s\n", subnet, nat_if);
        } else {
            fprintf(stderr,
                    "warning: iptables MASQUERADE failed (need root and iptables?)\n");
        }
    }

    /* FORWARD 放行:host 防火墙(Tailscale/UFW 等)可能 DROP 转发流量,
     * 隧道内 DNS 查询和出网数据都要穿过 FORWARD 链;放行隧道子网的
     * 转发,退出时删除(与 MASQUERADE 同生命周期)。 */
    if (subnet[0] != '\0') {
        char *fchk[] = { "iptables", "-C", "FORWARD", "-s", (char *)subnet,
                         "-j", "ACCEPT", NULL };
        char *fadd[] = { "iptables", "-I", "FORWARD", "-s", (char *)subnet,
                         "-j", "ACCEPT", NULL };
        if (run_cmd(fchk) != 0) {
            if (run_cmd(fadd) == 0) {
                fwd_rule_added = true;
                printf("iptables: FORWARD %s ACCEPT\n", subnet);
            } else {
                fprintf(stderr, "warning: iptables FORWARD ACCEPT failed "
                        "(tunnel forwarding may be firewalled)\n");
            }
        }
    }
}

/* Best-effort exit cleanup: restore ip_forward and drop the MASQUERADE rule
 * we added.  Failures are logged, never fatal.  A resident daemon that is
 * restarted is unaffected: setup_nat()'s -C guard skips re-adding a rule
 * that is still present, so this only ever removes what we added. */
static void server_cleanup_nat(void)
{
    if (saved_ip_forward >= 0) {
        FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
        bool ok;

        if (!f) {
            fprintf(stderr, "warning: cannot restore ip_forward: %s\n",
                    strerror(errno));
        } else {
            ok = fputs(saved_ip_forward ? "1" : "0", f) != EOF;
            if (fclose(f) != 0)
                ok = false;
            if (!ok)
                fprintf(stderr, "warning: cannot restore ip_forward: %s\n",
                        strerror(errno));
        }
    }

    if (nat_rule_added) {
        char *del[] = { "iptables", "-t", "nat", "-D", "POSTROUTING", "-s",
                        nat_subnet_saved, "-o", nat_if_saved, "-j",
                        "MASQUERADE", NULL };
        if (run_cmd(del) != 0)
            fprintf(stderr, "warning: iptables -D MASQUERADE failed\n");
    }

    if (fwd_rule_added) {
        char *fdel[] = { "iptables", "-D", "FORWARD", "-s",
                         nat_subnet_saved, "-j", "ACCEPT", NULL };
        if (run_cmd(fdel) != 0)
            fprintf(stderr, "warning: iptables -D FORWARD ACCEPT failed\n");
    }
}

/* shared tun_pool glue: downlink reader callback (one per queue) */
struct srv_pool_ud {
    struct server_ctx *ctx;
    int udp_fd;
};

static void srv_tun_pkt(void *ud, uint8_t *pkt, size_t len, bool last)
{
    struct srv_pool_ud *pu = ud;
    (void)last;
    PROF_ADD(g_prof_srv_tunr, len);
    handle_tun_downlink(pu->ctx, pkt, len, pu->udp_fd);
}

/* remove stale device, open, configure. Exits on failure. */
static int setup_tun(const char *name, const char *server_ip, int mask)
{
    int fd;
    char addr[64];

    if (!tun_name_valid(name)) {
        fprintf(stderr, "error: invalid tun device name '%s'\n", name);
        server_cleanup_nat();
        exit(1);
    }
    (void)ip_run_quiet((char *[]){"link", "del", (char *)name, NULL});
    fd = open_tun(name);
    if (fd < 0) {
        fprintf(stderr, "error: cannot open tun device %s: %s (run as root?)\n",
                name, strerror(errno));
        server_cleanup_nat();
        exit(1);
    }
    set_nonblock(fd);
    (void)ip_run((char *[]){"addr", "flush", "dev", (char *)name, NULL});
    (void)ip_run((char *[]){"link", "set", (char *)name, "up", NULL});
    snprintf(addr, sizeof addr, "%s/%d", server_ip, mask);
    /* the address assignment is load-bearing: without it the TUN has no
     * gateway and no client can reach the server, so fail startup (the
     * flush/link-up steps above are best-effort) */
    if (!ip_run((char *[]){"addr", "add", addr, "dev", (char *)name, NULL})) {
        fprintf(stderr, "error: cannot assign %s to tun device %s\n", addr,
                name);
        tun_close(fd);
        server_cleanup_nat();
        exit(1);
    }
    /* IPv6 side of the same tun: the derived ULA (fd00::/96 + the IPv4,
     * protocol.h) is what inner IPv6 return traffic is addressed to. The
     * /96 prefix makes the whole client pool on-link, so kernel routing
     * back into the tunnel works without extra routes. Best-effort: an
     * environment without IPv6 support must not kill the server. */
    {
        uint8_t v4[4], b6[16];
        char addr6[64];
        if (s2ip4(server_ip, v4)) {
            ip6_derive_ula(ip4_u32(v4), b6);
            snprintf(addr6, sizeof addr6,
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x/96",
                     b6[0], b6[1], b6[2], b6[3], b6[4], b6[5], b6[6], b6[7],
                     b6[8], b6[9], b6[10], b6[11], b6[12], b6[13], b6[14],
                     b6[15]);
            (void)ip_run((char *[]){"-6", "addr", "add", addr6,
                                    "dev", (char *)name, NULL});
        }
    }
    return fd;
}

/* Create `n` UDP sockets on one port with SO_REUSEPORT: the kernel
 * fans out incoming datagrams by 4-tuple hash, so each session's
 * packets land on ONE socket (inner TCP segments stay ordered per
 * thread) while the recv threads run in parallel. All sockets share
 * the same port, so replies from any of them look identical to the
 * client. Returns the number created (== n); fatal errors exit. */
static int setup_udp(uint16_t port, int *fds, int n)
{
    int one = 1, sz = 16 * 1024 * 1024;
    struct sockaddr_in addr;

    for (int i = 0; i < n; i++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);

        if (fd < 0) {
            perror("socket");
            server_cleanup_nat();
            exit(1);
        }
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        /* SO_RCVBUFFORCE (root only, before the fork drops privileges)
         * bypasses the net.core.rmem_max cap: a plain SO_RCVBUF request
         * is clamped to rmem_max (4MB here), and with the TUN write
         * occasionally stalling the recv thread the 4MB queue overflows
         * — measured 340k packets/s dropped at the kernel (UdpRcvbuf-
         * Errors), ~53% of arrivals, collapsing the inner TCP into an
         * RTO storm. Non-root deployments fall back to SO_RCVBUF. */
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof sz) != 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
        if (i == 0) {
            /* the kernel silently caps SO_RCVBUF at net.core.rmem_max;
             * with the default (212KB) the session buffer is far smaller
             * than the clients' aggregate in-flight window, so a burst
             * overflows it and the kernel drops UDP silently
             * (UdpRcvbufErrors) — the inner TCP then collapses into an
             * RTO storm. SO_RCVBUFFORCE (root, before the fork drops
             * privileges) bypasses the cap; the getsockopt below always
             * prints what actually took effect so a capped buffer is
             * visible even when the warning threshold is not crossed. */
            int actual = 0;
            socklen_t alen = sizeof actual;
            if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual, &alen) == 0) {
                fprintf(stderr, "udp rcvbuf: %d bytes (requested %d)\n",
                        actual, sz);
                if (actual < sz)
                    fprintf(stderr,
                            "warning: UDP rcvbuf capped at %d bytes by "
                            "net.core.rmem_max (%d requested); bursts past "
                            "the server's drain will drop. Raise it:\n"
                            "  sysctl -w net.core.rmem_max=16777216 "
                            "net.core.wmem_max=16777216\n",
                            actual, sz);
            }
        }
        set_nonblock(fd); /* never let sendto backpressure the loop */

        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);
        if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
            perror("bind");
            for (int j = 0; j < i; j++)
                close(fds[j]);
            server_cleanup_nat();
            exit(1);
        }
        fds[i] = fd;
    }
    return n;
}

/* wire the recvmmsg batch: one 64KiB iovec per slot plus peer storage */
static void setup_rx_batch(uint8_t *udp_buf, struct iovec *udp_iov,
                           struct mmsghdr *msgs,
                           struct sockaddr_in *peers)
{
    memset(msgs, 0, (size_t)UDP_RXBATCH * sizeof *msgs);
    for (int i = 0; i < UDP_RXBATCH; i++) {
        udp_iov[i].iov_base = udp_buf + (size_t)i * 65536;
        udp_iov[i].iov_len = 65536;
        msgs[i].msg_hdr.msg_iov = &udp_iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &peers[i];
        msgs[i].msg_hdr.msg_namelen = sizeof peers[i];
    }
}

/* One uplink recv thread: poll its SO_REUSEPORT socket + recvmmsg(64)
 * batch drain -> handle_udp. tid 0 is the primary: it also runs the
 * periodic housekeeping (tun pool AIMD tick, session purge, stats).
 * Shared state is safe: the session table is rwlock-protected, the rate
 * table has its own mutex (control types only), the tun fd accepts
 * concurrent atomic writes (EAGAIN retried with poll), and the stats
 * are per-thread. Exits on g_stop within one poll timeout. */
struct recv_thr_arg {
    struct server_ctx *ctx;
    const struct server_user *users;
    int nusers;
    int fd;
    unsigned tid;
    int poll_err;   /* primary: fatal poll failure */
};

static void *recv_thread_main(void *v)
{
    struct recv_thr_arg *a = v;
    struct pollfd pfd = { .fd = a->fd, .events = POLLIN, .revents = 0 };
    struct mmsghdr msgs[UDP_RXBATCH];
    struct sockaddr_in peers[UDP_RXBATCH];
    struct iovec iov[UDP_RXBATCH];
    uint8_t *buf;
    uint64_t last_purge = now_ms(), last_qctl = now_ms(), last_drops = 0;

    buf = malloc((size_t)UDP_RXBATCH * 65536);
    if (!buf) {
        log_err("uplink recv thread: out of memory");
        return NULL;
    }
    setup_rx_batch(buf, iov, msgs, peers);

    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        int pr = poll(&pfd, 1, 100);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            a->poll_err = 1;   /* fatal: exit non-zero for service mgrs */
            break;
        }
        if (pfd.revents & POLLERR) {
            /* A pending ICMP error (e.g. port-unreachable for a datagram
             * we sent to a client port that just closed) keeps POLLERR
             * asserted on a UDP socket. Plain recv/recvmmsg does NOT
             * consume the error queue, so without this the poll loop
             * busy-spins at 100% CPU and the socket stops delivering
             * data — measured: one of four REUSEPORT recv threads
             * wedged this way and every packet hashed to its socket
             * (including the client's OPEN) was silently lost. Drain
             * sk_error_queue via MSG_ERRQUEUE until empty. */
            char ebuf[512];
            struct sockaddr_in junk;
            struct iovec eiov = { .iov_base = ebuf, .iov_len = sizeof ebuf };
            struct msghdr emh = { .msg_name = &junk,
                                  .msg_namelen = sizeof junk,
                                  .msg_iov = &eiov, .msg_iovlen = 1 };
            while (recvmsg(a->fd, &emh, MSG_ERRQUEUE | MSG_DONTWAIT) > 0)
                ;
        }
        if (pfd.revents & (POLLIN | POLLERR)) {
            /* recvmmsg batch (64): drains up to 64 datagrams per syscall,
             * amortizing the per-packet recvfrom overhead that used to
             * be the loop's throughput ceiling — a full poll burst is
             * consumed in one syscall round */
            int last_v = 1;
            for (;;) {
                int v = recvmmsg(a->fd, msgs, UDP_RXBATCH, MSG_DONTWAIT,
                                 NULL);
                if (v > 0) {
                    for (int i = 0; i < v; i++) {
                        if (msgs[i].msg_len <= 0)
                            continue;
                        PROF_ADD(g_prof_srv_recv, (size_t)msgs[i].msg_len);
                        handle_udp(a->ctx, a->users, a->nusers,
                                   (const uint8_t *)msgs[i].msg_hdr.msg_iov[0]
                                       .iov_base,
                                   (size_t)msgs[i].msg_len, &peers[i], a->fd,
                                   a->tid);
                    }
                    last_v = v;
                    if (v < UDP_RXBATCH)
                        break; /* partial batch: drained */
                    continue;
                }
                if (v < 0 && errno == EINTR)
                    continue;
                last_v = v;
                break; /* EAGAIN: drained, or ICMP error */
            }
            /* diagnostic: poll reported readable but nothing was
             * drained — a transient race between poll and recvmmsg, or
             * a wedged receive path (see the MSG_ERRQUEUE drain above) */
            if (last_v <= 0 && (pfd.revents & POLLIN)) {
                static uint64_t last_pe2;
                uint64_t nowp = now_ms();
                if (nowp - last_pe2 >= 1000) {
                    last_pe2 = nowp;
                    log_debug("recv thread %u: POLLIN but recvmmsg=%d "
                              "errno=%d (fd=%d)", a->tid, last_v, errno,
                              a->fd);
                }
            }
        } else if (pfd.revents != 0) {
            /* unexpected poll event (POLLNVAL/POLLHUP on the socket):
             * would busy-spin without receiving anything — log it */
            static uint64_t last_pe;
            uint64_t nowp = now_ms();
            if (nowp - last_pe >= 1000) {
                last_pe = nowp;
                log_debug("recv thread %u: poll revents=0x%x (fd=%d)",
                          a->tid, pfd.revents, a->fd);
            }
        }

        if (a->tid == 0) {
            /* periodic housekeeping: primary thread only */
            uint64_t now = now_ms();
            if (a->ctx->qpool && now - last_qctl >= TUN_POOL_TICK_MS) {
                tun_pool_tick(a->ctx->qpool);
                last_qctl = now;
            }
            if (now - last_purge >= 1000) {
                {
                    static struct prof_state ps_recv, ps_tunw, ps_tunr, ps_dl;
                    if (prof_print("srv recv", &ps_recv, g_prof_srv_recv)) {
                        prof_print("srv tunw", &ps_tunw, g_prof_srv_tunw);
                        prof_print("srv tunr", &ps_tunr, g_prof_srv_tunr);
                        prof_print("srv dlsend", &ps_dl, g_prof_srv_dlsend);
                    }
                }
                purge_expired(a->ctx, now);
                if (debug_enabled())
                    server_up_stats_print();
                uint64_t drops = server_send_drops();
                if (drops != last_drops) {
                    fprintf(stderr, "udp send dropped %llu packets\n",
                            (unsigned long long)drops);
                    last_drops = drops;
                }
                last_purge = now;
            }
        }
    }
    free(buf);
    return NULL;
}

/* orderly shutdown: stop the TUN reader pool, close fds, and — in the
 * original root process — undo the NAT changes; returns the process
 * exit status (poll_err surfaces fatal runtime failures) */
static int server_shutdown(struct server_ctx *ctx, int tun_fd,
                           const int *udp_fds, int nfds, bool drop_child,
                           int poll_err)
{
    tun_pool_destroy(ctx->qpool); /* stops readers, detaches extra queues */
    ctx->qpool = NULL;
    tun_close(tun_fd);
    ctx->tun_fd = -1;
    for (int i = 0; i < nfds; i++)
        close(udp_fds[i]);
    if (!drop_child)
        server_cleanup_nat(); /* root process restores ip_forward + MASQUERADE */
    server_ctx_destroy(ctx);
    return poll_err ? 1 : 0;
}

int main(int argc, char **argv)
{
    struct opts o;
    struct server_ctx ctx;
    struct server_user users[SERVER_MAX_USERS];
    struct stat st;
    uint8_t sip[4], dip[4];
    uint32_t subnet_base;
    char subnet_net[64];
    int udp_fds[IWAN_SRV_THREADS_MAX];
    int nusers, tun_fd = -1, nfds;
    int poll_err = 0;   /* fatal poll failure: report exit != 0 */
    bool drop_child = false; /* A1: this process is the forked, de-privileged server */

    util_ignore_sigpipe();     /* EPIPE on a dead socket, not a SIGPIPE kill */
    prof_init();               /* IWAN_PROFILE=1: stage throughput prints */
    server_rate_limits_init(); /* IWAN_RATE_OPEN_MAX / IWAN_RATE_ECHO_MAX */

    /* uplink recv threads: SO_REUSEPORT fan-out across `recv_threads`
     * sockets (the kernel hashes each session to one socket, so inner
     * TCP segments stay ordered per thread). 4 threads clear the
     * single-threaded drain ceiling (~390k pps) on typical hosts; tune
     * with IWAN_SRV_THREADS (1..16). */
    int recv_threads = 4;
    {
        const char *rt = getenv("IWAN_SRV_THREADS");
        if (rt && *rt) {
            uint64_t v;
            if (parse_uint(rt, IWAN_SRV_THREADS_MAX, &v) != 0 || v < 1)
                fprintf(stderr, "warning: invalid IWAN_SRV_THREADS '%s' "
                        "(default 4)\n", rt);
            else
                recv_threads = (int)v;
        }
    }
    server_up_stats_set_threads(recv_threads);

    memset(&o, 0, sizeof o);
    o.port = 6001;
    strcpy(o.tun, "iwan-srv");
    strcpy(o.server_ip, "198.18.0.1");
    strcpy(o.subnet, "198.18.0.0/16");
    strcpy(o.dns, "114.114.114.114");
    strcpy(o.users, "/etc/iwan/users.txt");
    strcpy(o.nat_if, "eth0");
    strcpy(o.user, "nobody");

    parse_opts(argc, argv, &o);

    if (!o.no_tun && !tun_name_valid(o.tun)) {
        fprintf(stderr, "error: invalid tun device name '%s'\n", o.tun);
        return 1;
    }
    if (!s2ip4(o.server_ip, sip)) {
        fprintf(stderr, "error: invalid server IP '%s'\n", o.server_ip);
        return 1;
    }
    if (!s2ip4(o.dns, dip)) {
        fprintf(stderr, "error: invalid DNS IP '%s'\n", o.dns);
        return 1;
    }
    if (parse_subnet(o.subnet, &subnet_base, &o.mask, subnet_net,
                     sizeof subnet_net) != 0) {
        fprintf(stderr, "error: invalid subnet '%s' (want IP/MASK, mask 8-30)\n", o.subnet);
        return 1;
    }

    nusers = load_users(o.users, users, SERVER_MAX_USERS);
    if (nusers < 0) {
        fprintf(stderr, "error: cannot open users file %s: %s\n", o.users, strerror(errno));
        return 1;
    }
    if (nusers == 0) {
        fprintf(stderr, "error: no users loaded from %s\n", o.users);
        return 1;
    }
    printf("loaded %d users\n", nusers);
    if (stat(o.users, &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO))) {
        /* R2: a group/world-readable users file leaks credentials; refuse
         * to run unless the operator explicitly opts out with one of the
         * positive values (1/true/yes/on, case-insensitive) — anything
         * else, including "no", must NOT enable the override */
        const char *env = getenv("IWAN_ALLOW_INSECURE_USERS");
        bool allow = env && (strcasecmp(env, "1") == 0 ||
                             strcasecmp(env, "true") == 0 ||
                             strcasecmp(env, "yes") == 0 ||
                             strcasecmp(env, "on") == 0);
        if (!allow) {
            fprintf(stderr,
                    "error: %s is group/world readable (it contains "
                    "passwords); chmod 600 it, or set "
                    "IWAN_ALLOW_INSECURE_USERS=1 to override\n", o.users);
            return 1;
        }
        fprintf(stderr, "warning: %s is group/world readable; chmod 600 recommended\n",
                o.users);
    }

    memset(&ctx, 0, sizeof ctx);
    server_ctx_init(&ctx);
    memcpy(ctx.server_ip, sip, 4);
    memcpy(ctx.dns, dip, 4);
    ctx.ip_base = subnet_base + 2;                 /* first usable host */
    ctx.ip_end = (subnet_base | ~(0xFFFFFFFFu << (32 - o.mask))) - 1; /* pre-broadcast */
    ctx.next_ip = ctx.ip_base;
    snprintf(ctx.tun_name, sizeof ctx.tun_name, "%s", o.tun);
    ctx.tun_fd = -1;

    {
        uint32_t sipu = ip4_u32(sip), dipu = ip4_u32(dip);
        if (sipu >= ctx.ip_base && sipu <= ctx.ip_end) {
            fprintf(stderr, "error: --server-ip %s falls inside the client "
                            "pool; pick an address outside [first,last]\n",
                    o.server_ip);
            return 1;
        }
        if (dipu >= ctx.ip_base && dipu <= ctx.ip_end) {
            fprintf(stderr, "error: --dns %s falls inside the client pool\n",
                    o.dns);
            return 1;
        }
    }

    if (o.no_tun) {
        printf("no-tun mode: TCP echo mirror (bench harness)\n");
    } else {
        enable_ip_forward();
        setup_nat(subnet_net, o.nat_if);
        tun_fd = setup_tun(o.tun, o.server_ip, o.mask);
        ctx.tun_fd = tun_fd;
        printf("tun %s fd=%d\n", o.tun, tun_fd);
    }

    nfds = setup_udp(o.port, udp_fds, recv_threads);

    /* A1: drop root.  All root-only work (TUN setup, NAT rules, socket
     * bind) is done; from here on the server loop runs unprivileged.
     * The parent keeps root only long enough to undo the NAT changes
     * after the child exits.  Non-root deployments never fork and run
     * exactly as before. */
    if (geteuid() == 0) {
        fflush(NULL); /* never let the child duplicate buffered output */
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            server_cleanup_nat();
            return 1;
        }
        if (pid > 0) {
            /* parent: the child owns the server loop; wait for it, then
             * restore ip_forward and drop the MASQUERADE rule we added
             * (both need root). SIGINT/SIGTERM/SIGHUP/SIGQUIT are
             * forwarded to the child so any stop path reaches the
             * cleanup — ignoring them (as before) let kill <parent-pid>
             * or an SSH hangup strand the NAT state forever.
             *
             * The forwarded signals stay BLOCKED while the handlers and
             * g_child_pid are installed: a signal arriving in that
             * window must not be lost (handlers not yet up) or swallowed
             * without forwarding (g_child_pid still -1). Anything that
             * arrives meanwhile is delivered once the mask is restored,
             * with everything in place. */
            sigset_t mask, oldmask;
            sigemptyset(&mask);
            sigaddset(&mask, SIGINT);
            sigaddset(&mask, SIGTERM);
            sigaddset(&mask, SIGHUP);
            sigaddset(&mask, SIGQUIT);
            sigprocmask(SIG_BLOCK, &mask, &oldmask);
            if (install_sig(SIGINT, parent_fwd_signal, 0) != 0 ||
                install_sig(SIGTERM, parent_fwd_signal, 0) != 0 ||
                install_sig(SIGHUP, parent_fwd_signal, 0) != 0 ||
                install_sig(SIGQUIT, parent_fwd_signal, 0) != 0) {
                fprintf(stderr, "error: cannot install forwarding "
                        "handlers: %s\n", strerror(errno));
                sigprocmask(SIG_SETMASK, &oldmask, NULL);
                server_cleanup_nat();
                return 1;
            }
            g_child_pid = pid;
            /* SIGCHLD deliberately keeps its default disposition: the
             * parent reaps the child with waitpid below, and forwarding
             * it to the child would be meaningless (the child is the
             * one that exited). */
            sigprocmask(SIG_SETMASK, &oldmask, NULL);
            for (;;) {
                int st;
                if (waitpid(pid, &st, 0) < 0) {
                    if (errno == EINTR)
                        continue;
                    server_cleanup_nat();
                    return 1;
                }
                server_cleanup_nat();
                return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
            }
        }
        /* child: continue as the unprivileged server process */
        drop_child = true;
        {
            struct passwd pwb, *pw = NULL;
            char pwbuf[4096];

            if (getpwnam_r(o.user, &pwb, pwbuf, sizeof pwbuf, &pw) != 0 ||
                pw == NULL) {
                fprintf(stderr, "error: cannot resolve user '%s'\n", o.user);
                _exit(1);
            }
            if (setgroups(0, NULL) != 0 || setgid(pw->pw_gid) != 0 ||
                setuid(pw->pw_uid) != 0) {
                fprintf(stderr, "error: cannot drop privileges to user "
                        "'%s': %s\n", o.user, strerror(errno));
                _exit(1);
            }
            printf("dropped privileges to user %s (uid=%u gid=%u)\n",
                   o.user, (unsigned)pw->pw_uid, (unsigned)pw->pw_gid);
        }
    }
    /* signal handlers: installed after the fork so the root parent (which
     * forwards SIGINT/SIGTERM/SIGHUP/SIGQUIT while waiting) never takes
     * them; the server process — forked child or non-root deployment —
     * exits gracefully. SIGHUP (terminal hangup) stops the server the
     * same way SIGINT/SIGTERM do, so the parent's cleanup always runs.
     * SA_RESTART keeps poll() resuming instead of failing with EINTR. */
    if (install_sig(SIGINT, on_signal, SA_RESTART) != 0 ||
        install_sig(SIGTERM, on_signal, SA_RESTART) != 0 ||
        install_sig(SIGHUP, on_signal, SA_RESTART) != 0) {
        log_err("cannot install signal handlers: %s", strerror(errno));
        return 1;
    }

    if (!o.no_tun) {
        static struct srv_pool_ud pu; /* readers reference this for life */
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        int maxq = TUN_POOL_MAX;
        if (ncpu > 0 && ncpu < maxq)
            maxq = (int)ncpu;
        pu.ctx = &ctx;
        pu.udp_fd = udp_fds[0];
        /* eager full pool: uplink writers spread across the queue fds
         * (tun_pool_write_fd, tid % nq); starting at the recv-thread
         * count means the write-side fan-out is effective immediately
         * instead of waiting for the downlink-driven AIMD to grow the
         * pool (ACK-only downlink keeps it near 1 queue otherwise) */
        ctx.qpool = tun_pool_create(o.tun, tun_fd, maxq,
                                    recv_threads < maxq ? recv_threads : maxq,
                                    srv_tun_pkt, &pu, &g_stop);
        if (!ctx.qpool) {
            fprintf(stderr, "error: cannot start TUN reader pool\n");
            if (!drop_child)
                server_cleanup_nat(); /* parent (root) undoes NAT */
            return 1;
        }
        printf("tun reader pool: 1 queue (dynamic up to %d)\n", maxq);
        if (tun_steering_attach(tun_fd) == 0)
            printf("tun steering: eBPF flow hash attached\n");
    }
    printf("listening UDP 0.0.0.0:%u (%d recv thread%s)\n",
           (unsigned)o.port, recv_threads, recv_threads > 1 ? "s" : "");
    printf("server ready.\n");
    fflush(stdout);   /* readiness contract: callers grep the log */

    /* uplink recv threads: worker threads own udp_fds[1..], the primary
     * runs inline below on udp_fds[0] (and does the periodic
     * housekeeping). The args live on main's stack for the whole run. */
    pthread_t workers[IWAN_SRV_THREADS_MAX];
    struct recv_thr_arg args[IWAN_SRV_THREADS_MAX];
    int nworkers = recv_threads - 1;
    int ncreated = 0;   /* only threads actually created get joined */

    for (int i = 0; i < nworkers; i++) {
        /* workers take args[1..nworkers]; args[0] is reserved for the
         * primary thread below. Sharing args[0] here raced the primary's
         * initialization: worker 0 could read the overwritten values and
         * become a second thread on udp_fds[0] (two consumers fighting
         * over one socket -> POLLIN/recvmmsg-EAGAIN busy loop) while
         * udp_fds[1] had no consumer at all (~25% of packets lost). */
        args[i + 1] = (struct recv_thr_arg){ &ctx, users, nusers,
                                             udp_fds[i + 1],
                                             (unsigned)(i + 1), 0 };
        if (pthread_create(&workers[i], NULL, recv_thread_main,
                           &args[i + 1]) != 0) {
            log_err("cannot start uplink recv thread %d: %s", i + 1,
                    strerror(errno));
            atomic_store_explicit(&g_stop, true, memory_order_relaxed);
            break;
        }
        ncreated++;
    }
    args[0] = (struct recv_thr_arg){ &ctx, users, nusers, udp_fds[0], 0, 0 };
    recv_thread_main(&args[0]);   /* primary loop, inline */
    poll_err = args[0].poll_err;

    /* join ONLY the threads that were created: pthread_create failure
     * leaves the remaining workers[] entries uninitialized, and joining
     * them is UB (EINVAL at best, crash at worst) on the degraded path */
    for (int i = 0; i < ncreated; i++)
        pthread_join(workers[i], NULL);   /* exit within one poll timeout */

    return server_shutdown(&ctx, tun_fd, udp_fds, nfds, drop_child,
                           poll_err);
}
