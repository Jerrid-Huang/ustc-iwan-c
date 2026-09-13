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
    fprintf(out, "  -T, --no-tun           (testing) skip TUN device\n");
    fprintf(out, "      --user <NAME>      drop root privileges to this user after setup (default nobody)\n");
    fprintf(out, "  -h, --help             show this help\n");
    fprintf(out, "  note: repeating an option is allowed: the LAST value wins\n");
    fprintf(out, "        (no 'cannot be used multiple times' error, unlike iwan-client)\n");
    /* R37 R5 (L20-1): environment matrix. Only the variables this binary
     * really reads (getenv/env_bool sites reachable from main) are listed;
     * the wording is kept in sync with README.md's matrix. */
    fprintf(out, "  Environment (read once at startup):\n");
    fprintf(out, "    IWAN_DEBUG=1        verbose debug logging (default: off; ignored\n");
    fprintf(out, "                        by IWAN_DEBUG_STRIP builds)\n");
    fprintf(out, "    IWAN_PROFILE=1      print stage throughput counters at exit\n");
    fprintf(out, "                        (default: off; ignored by IWAN_DEBUG_STRIP\n");
    fprintf(out, "                        builds)\n");
    fprintf(out, "    IWAN_SRV_THREADS=N  uplink UDP receive threads, 1..16 (default: 4;\n");
    fprintf(out, "                        a bad value warns and keeps 4)\n");
    fprintf(out, "    IWAN_SRV_TUN_SINGLE=1  use one TUN queue instead of the multi-queue\n");
    fprintf(out, "                        fan-out (A/B benchmark switch; default: off)\n");
    fprintf(out, "    IWAN_ALLOW_INSECURE_USERS=1  accept a group/world-readable users\n");
    fprintf(out, "                        file instead of refusing to start (default:\n");
    fprintf(out, "                        off; only 1/true/yes/on enable it)\n");
    fprintf(out, "    IWAN_RATE_OPEN_MAX=N  OPEN frames per source per second, 1..65535\n");
    fprintf(out, "                        (default: 20)\n");
    fprintf(out, "    IWAN_RATE_ECHO_MAX=N  PING and ECHO frames each per source per\n");
    fprintf(out, "                        second, 1..65535 (default: 60)\n");
    fprintf(out, "    IWAN_RATE_MISS_MAX=N  per-source per-second budget for\n");
    fprintf(out, "                        unknown-session DATA/CLOSE frames; over-budget\n");
    fprintf(out, "                        frames are dropped on a lock-free fast path\n");
    fprintf(out, "                        (default: 2000, 1..65535)\n");
    fprintf(out, "    Flags: 0/false/no/off (case-insensitive) are off, any other\n");
    fprintf(out, "    non-empty value is on; IWAN_SRV_TUN_SINGLE is the exception, its\n");
    fprintf(out, "    off spellings are case-sensitive. Invalid numbers fall back to the\n");
    fprintf(out, "    default with a warning.\n");
    fprintf(out, "    Also read: SSL_CERT_FILE (the only CA file source chosen by an\n");
    fprintf(out, "    environment variable), SSL_CERT_DIR (never read as a CA directory;\n");
    fprintf(out, "    before helper exec it is only kept or dropped by owner/permission -\n");
    fprintf(out, "    a non-root-owned or group/other-writable path is unset)\n");
}

/* exit-code convention (matches iwan-client): usage errors exit 2 with
 * the usage text on stderr; runtime errors exit 1.
 * R37-F3 (R3-M5): this is a variadic printf wrapper forwarding `fmt` to
 * vfprintf, so it carries the same compile-time format checking as the
 * shared loggers (IWAN_PRINTF_LIKE, util.h). `fmt` is argument 2. On a
 * function *definition* GCC wants the attribute before the declarator. */
static void IWAN_PRINTF_LIKE(2, 3)
usage_error(const char *prog, const char *fmt, ...)
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
            /* M4: same guard as -t — a legal IPv4 dotted quad is at most
             * 15 chars (exactly fills the 16-byte buffer incl. NUL), so
             * anything >= sizeof is an invalid address that snprintf would
             * silently truncate and s2ip4 afterwards would happily accept
             * (e.g. "192.168.100.1000" -> ".100") */
            if (strlen(optarg) >= sizeof o->server_ip)
                usage_error(argv[0],
                            "error: server IP too long: '%s' (max 15)", optarg);
            snprintf(o->server_ip, sizeof o->server_ip, "%s", optarg);
            break;
        case 'S':
            snprintf(o->subnet, sizeof o->subnet, "%s", optarg);
            break;
        case 'd':
            /* M4: same over-length interception as -s (see above) */
            if (strlen(optarg) >= sizeof o->dns)
                usage_error(argv[0],
                            "error: DNS IP too long: '%s' (max 15)", optarg);
            snprintf(o->dns, sizeof o->dns, "%s", optarg);
            break;
        case 'u':
            /* M5: same over-length guard as -t — a too-long path would be
             * silently truncated and open the wrong users file */
            if (strlen(optarg) >= sizeof o->users)
                usage_error(argv[0],
                            "error: users file path too long (max %zu)",
                            sizeof o->users - 1);
            snprintf(o->users, sizeof o->users, "%s", optarg);
            break;
        case 'n':
            /* M5: same over-length guard as -t — a truncated interface name
             * would target the wrong NIC in iptables MASQUERADE */
            if (strlen(optarg) >= sizeof o->nat_if)
                usage_error(argv[0],
                            "error: NAT interface name too long (max %zu)",
                            sizeof o->nat_if - 1);
            snprintf(o->nat_if, sizeof o->nat_if, "%s", optarg);
            break;
        case 'T':
            o->no_tun = true;
            break;
        case 'U':
            /* M5: same over-length guard as -t — a truncated account name
             * would fail the getpwnam exact match and open the wrong user */
            if (strlen(optarg) >= sizeof o->user)
                usage_error(argv[0],
                            "error: user name too long (max %zu)",
                            sizeof o->user - 1);
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
static char fwd_subnet_saved[64]; /* subnet of the FORWARD ACCEPT we added:
                                   * kept separate from nat_subnet_saved so
                                   * cleanup removes exactly this rule even
                                   * when the MASQUERADE rule pre-existed
                                   * (M2 — see setup_nat) */

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
    pid_t w;
    int st = 0;

    if (pid < 0)
        return -1;
    if (pid == 0) {
        exec_sanitize();
        execvp(argv[0], argv);
        _exit(127);
    }
    while ((w = waitpid(pid, &st, 0)) < 0 && errno == EINTR)
        ;
    /* R37 R5 WG-D (R4-L4): a non-EINTR waitpid failure (ECHILD after a
     * SIGCHLD handler with SA_NOCLDWAIT, EINVAL, ...) used to fall through
     * with st still 0 => WIFEXITED(0) true and WEXITSTATUS(0) == 0 =>
     * run_cmd reported success for a command whose exit status is unknown.
     * iptables_ensure() then read that as "the -C rule already exists",
     * skipped the -A and printed no warning: the server believed
     * MASQUERADE was in place while NAT was silently broken. Same rule as
     * util.c's ip_run() (R3-L7) and port.c's port_run_cmd: unknown status
     * is failure. */
    if (w < 0)
        return -1;
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return -1;
}

/* iptables rule ensure: "-C" check first (already present -> nothing
 * to do), otherwise add. Returns 1 when WE added the rule (so exit
 * cleanup removes exactly it, not a pre-existing one), 0 when it was
 * already present, -1 when the add failed (caller logs its own
 * warning). */
static int iptables_ensure(char *const chk[], char *const add[])
{
    if (run_cmd(chk) == 0)
        return 0;
    return run_cmd(add) == 0 ? 1 : -1;
}

static void setup_nat(const char *subnet, const char *nat_if)
{
    int rc;
    char *chk[] = { "iptables", "-t", "nat", "-C", "POSTROUTING", "-s",
                    (char *)subnet, "-o", (char *)nat_if, "-j", "MASQUERADE", NULL };
    char *add[] = { "iptables", "-t", "nat", "-A", "POSTROUTING", "-s",
                    (char *)subnet, "-o", (char *)nat_if, "-j", "MASQUERADE", NULL };

    rc = iptables_ensure(chk, add);
    if (rc == 1) {
        /* remember what we added so exit cleanup can remove exactly
         * this rule (C3); a rule that was already present is not ours
         * to remove */
        snprintf(nat_subnet_saved, sizeof nat_subnet_saved, "%s", subnet);
        snprintf(nat_if_saved, sizeof nat_if_saved, "%s", nat_if);
        nat_rule_added = true;
        printf("iptables: MASQUERADE %s -> %s\n", subnet, nat_if);
    } else if (rc < 0) {
        fprintf(stderr,
                "warning: iptables MASQUERADE failed (need root and iptables?)\n");
    }

    /* FORWARD 放行:host 防火墙(Tailscale/UFW 等)可能 DROP 转发流量,
     * 隧道内 DNS 查询和出网数据都要穿过 FORWARD 链;放行隧道子网的
     * 转发,退出时删除(与 MASQUERADE 同生命周期)。 */
    if (subnet[0] != '\0') {
        char *fchk[] = { "iptables", "-C", "FORWARD", "-s", (char *)subnet,
                         "-j", "ACCEPT", NULL };
        char *fadd[] = { "iptables", "-I", "FORWARD", "-s", (char *)subnet,
                         "-j", "ACCEPT", NULL };
        rc = iptables_ensure(fchk, fadd);
        if (rc == 1) {
            fwd_rule_added = true;
            /* M2: remember THIS FORWARD rule's own subnet.  nat_subnet_saved
             * is only written when we also added the MASQUERADE rule; when
             * that rule pre-existed (nat_subnet_saved == "") we still added
             * the FORWARD ACCEPT and cleanup must remove exactly it — using
             * nat_subnet_saved there would `iptables -D FORWARD -s ""` (fails)
             * and leak the rule forever. */
            snprintf(fwd_subnet_saved, sizeof fwd_subnet_saved, "%s", subnet);
            printf("iptables: FORWARD %s ACCEPT\n", subnet);
        } else if (rc < 0) {
            fprintf(stderr, "warning: iptables FORWARD ACCEPT failed "
                    "(tunnel forwarding may be firewalled)\n");
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
        /* M2: delete with fwd_subnet_saved (the subnet we actually added),
         * never nat_subnet_saved — see setup_nat. */
        char *fdel[] = { "iptables", "-D", "FORWARD", "-s",
                         fwd_subnet_saved, "-j", "ACCEPT", NULL };
        if (run_cmd(fdel) != 0)
            fprintf(stderr, "warning: iptables -D FORWARD ACCEPT failed\n");
    }
}

/* shared tun_pool glue: downlink reader callback (one per queue) */
/* A1: downlink sendmmsg batch — each queue gets its own batch state;
 * packets are staged (hdr + payload COPY, the reader's TLS buffer is
 * reused for the next read) and flushed with ONE sendmmsg on the
 * reader's flush signal or when the batch fills. Sparse traffic adds no
 * latency: the reader fires the flush signal right after draining its
 * burst. Same drop contract as the per-packet path: UDP datagrams are
 * never retransmitted, so unsent data segments recover by TCP RTO and
 * pure ACKs regenerate. */
#define SRV_DL_BATCH 64
#define SRV_DL_SLOT  1500   /* inner MTU; larger packets bypass the batch */
struct srv_dl_batch {
    uint8_t hdrs[SRV_DL_BATCH][IWAN_HDR_LEN];
    uint8_t pl[SRV_DL_BATCH][SRV_DL_SLOT];
    struct sockaddr_in peers[SRV_DL_BATCH];
    struct iovec iovs[SRV_DL_BATCH * 2];
    struct mmsghdr msgs[SRV_DL_BATCH];
    int n;
};

struct srv_pool_ud {
    struct server_ctx *ctx;
    const int *udp_fds;    /* A2: per-reader send socket (qid % nfds) */
    int nfds;
    struct srv_dl_batch b[TUN_POOL_MAX];  /* one batch state per queue */
};

/* flush the batch with one sendmmsg. On EAGAIN the unsent remainder is
 * RETAINED at the front of the batch for the next flush (backpressure,
 * not loss — dropping up to SRV_DL_BATCH packets at once on a single
 * congestion event amplified every client's RTO simultaneously, R28-C1).
 * The reader retries on its next TUN read; a permanently-full peer
 * simply backpressures (bounded at SRV_DL_BATCH, see the guard in
 * srv_tun_pkt). */
static void srv_dl_flush(struct srv_dl_batch *b, int fd)
{
    int n = b->n, sent = 0;

    if (n == 0)
        return;
    while (sent < n) {
        int r = port_sendmmsg(fd, &b->msgs[sent], (unsigned)(n - sent), 0);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            break;   /* EAGAIN / fatal: keep the rest */
        for (int i = 0; i < r; i++)
            PROF_ADD(g_prof_srv_dlsend,
                     b->iovs[(size_t)(sent + i) * 2 + 1].iov_len);
        sent += r;
    }
    if (sent == n) {
        b->n = 0;
        return;
    }
    /* compact [sent..n) to the front; the retained msgs/iovs must be
     * re-pointed after the sub-array memmoves (hdrs/pl/peers moved too).
     * msg_name/msg_namelen are re-pointed as well: the moved msgs[] array
     * still references the OLD b->peers[] cell addresses, and since the UDP
     * fds are unconnected, msg_name is authoritative for delivery — keeping
     * it stale would send the retained downlink to the WRONG client once the
     * next srv_tun_pkt re-staging overwrites those old cells. */
    {
        int kept = n - sent;
        /* whole-array forms: keeps the fortified memmove bound sane (the
         * [i][0] spellings model a single row and trip -Wstringop-overflow) */
        memmove(b->hdrs, b->hdrs + sent, (size_t)kept * IWAN_HDR_LEN);
        memmove(b->pl, b->pl + sent, (size_t)kept * SRV_DL_SLOT);
        memmove(b->peers, b->peers + sent,
                (size_t)kept * sizeof b->peers[0]);
        memmove(b->msgs, &b->msgs[sent], (size_t)kept * sizeof b->msgs[0]);
        memmove(b->iovs, &b->iovs[sent * 2],
                (size_t)kept * 2 * sizeof b->iovs[0]);
        for (int i = 0; i < kept; i++) {
            size_t hl = b->iovs[i * 2].iov_len;
            size_t plen = b->iovs[i * 2 + 1].iov_len;
            b->iovs[i * 2].iov_base = b->hdrs[i];
            b->iovs[i * 2].iov_len = hl;
            b->iovs[i * 2 + 1].iov_base = b->pl[i];
            b->iovs[i * 2 + 1].iov_len = plen;
            b->msgs[i].msg_hdr.msg_iov = &b->iovs[i * 2];
            b->msgs[i].msg_hdr.msg_name = &b->peers[i];
            b->msgs[i].msg_hdr.msg_namelen = sizeof b->peers[0];
        }
        b->n = kept;
    }
}

static void srv_tun_pkt(void *ud, uint8_t *pkt, size_t len, bool last)
{
    struct srv_pool_ud *pu = ud;
    int qid = tun_reader_qid();
    struct srv_dl_batch *b;
    struct server_sess_snap snap;
    uint8_t hdr[IWAN_HDR_LEN];
    int fd;

    if (qid < 0 || qid >= TUN_POOL_MAX)
        qid = 0;
    b = &pu->b[qid];
    fd = pu->udp_fds[qid % pu->nfds];
    PROF_ADD(g_prof_srv_tunr, len);

    if (len < 20) {
        /* too small for an inner header: drop (previous staged packets
         * still flush on the reader's signal below) */
    } else if (len > SRV_DL_SLOT) {
        /* oversized (never on an MTU-1500 TUN): flush first so per-queue
         * ordering is preserved, then prep + direct-send */
        srv_dl_flush(b, fd);
        handle_tun_downlink(pu->ctx, pkt, len, fd);
    } else if (tun_prep_downlink(pu->ctx, pkt, len, &snap, hdr)) {
        if (b->n >= SRV_DL_BATCH) {
            /* R28-C1: the send buffer is full and the retained batch is at
             * capacity (the flush could not drain it) — drop just this one
             * packet rather than overflow the batch arrays. */
            server_add_send_drops(1);
        } else {
            int i = b->n;
            memcpy(b->hdrs[i], hdr, IWAN_HDR_LEN);
            memcpy(b->pl[i], pkt, len);
            b->peers[i] = snap.peer;
            b->iovs[i * 2].iov_base = b->hdrs[i];
            b->iovs[i * 2].iov_len = IWAN_HDR_LEN;
            b->iovs[i * 2 + 1].iov_base = b->pl[i];
            b->iovs[i * 2 + 1].iov_len = len;
            memset(&b->msgs[i], 0, sizeof b->msgs[i]);
            b->msgs[i].msg_hdr.msg_name = &b->peers[i];
            b->msgs[i].msg_hdr.msg_namelen = sizeof b->peers[i];
            b->msgs[i].msg_hdr.msg_iov = &b->iovs[i * 2];
            b->msgs[i].msg_hdr.msg_iovlen = 2;
            b->n++;
            if (b->n == SRV_DL_BATCH)
                srv_dl_flush(b, fd);
        }
    }
    if (last)
        srv_dl_flush(b, fd);
}

/* open and configure the tun. Exits on failure. */
static int setup_tun(const char *name, const char *server_ip, int mask)
{
    int fd;
    char addr[64];

    /* No pre-delete: our TUN devices are non-persistent (open_tun never
     * sets TUNSETPERSIST), so the kernel removes them when we exit —
     * including on a crash. This is the MAIN-device creation, so open_tun
     * sets IFF_TUN_EXCL: if `name` is already in use (any interface type,
     * including a tun owned by another process), TUNSETIFF fails EBUSY
     * and startup aborts instead of silently attaching to — and then
     * flushing the addresses of — a device we do not own. (The extra
     * queue fds opened later via tun_attach_many deliberately skip EXCL;
     * they attach to the device created here.) main() already validated
     * the name shape (tun_name_valid). */
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
    _Atomic int *poll_err;   /* M3-6: shared fatal-poll flag (all
                              * threads OR into it; main aggregates) */
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
        /* M3: without the fatal flag this was a silent black hole — a
         * worker returned with its SO_REUSEPORT socket never consumed
         * (every datagram the kernel hashed to it lost forever), and the
         * primary's OOM (tid==0, runs inline in main) still let main
         * print "server ready" and exit 0.  Same contract as the
         * poll-fatal path below: flag it AND stop the loop, so main's
         * aggregation (shutdown_poll_err) makes the process exit non-zero. */
        atomic_store_explicit(a->poll_err, 1, memory_order_relaxed);
        atomic_store_explicit(&g_stop, true, memory_order_relaxed);
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
            atomic_store_explicit(a->poll_err, 1, memory_order_relaxed);
            /* M8 (SUMMARY-2): a thread exiting without the stop flag
             * would leave main deadlocked in pthread_join (whose comment
             * promises "exit within one poll timeout") — set it so the
             * shutdown path completes */
            atomic_store_explicit(&g_stop, true, memory_order_relaxed);
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
                /* R37 WG1a: `v` would shadow recv_thread_main's parameter
                 * `void *v` under -Wshadow -Werror (no semantic change) */
                int nready = recvmmsg(a->fd, msgs, UDP_RXBATCH, MSG_DONTWAIT,
                                      NULL);
                if (nready > 0) {
                    for (int i = 0; i < nready; i++) {
                        if (msgs[i].msg_len <= 0)
                            continue;
                        PROF_ADD(g_prof_srv_recv, (size_t)msgs[i].msg_len);
                        handle_udp(a->ctx, a->users, a->nusers,
                                   (const uint8_t *)msgs[i].msg_hdr.msg_iov[0]
                                       .iov_base,
                                   (size_t)msgs[i].msg_len, &peers[i], a->fd,
                                   a->tid);
                    }
                    last_v = nready;
                    if (nready < UDP_RXBATCH)
                        break; /* partial batch: drained */
                    continue;
                }
                if (nready < 0 && errno == EINTR)
                    continue;
                last_v = nready;
                break; /* EAGAIN: drained, or ICMP error */
            }
            /* diagnostic: poll reported readable but nothing was
             * drained — a transient race between poll and recvmmsg, or
             * a wedged receive path (see the MSG_ERRQUEUE drain above) */
            if (last_v <= 0 && (pfd.revents & POLLIN)) {
                static _Thread_local uint64_t last_pe2;
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
            static _Thread_local uint64_t last_pe;
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
#ifndef IWAN_DEBUG_STRIP
                {
                    static struct prof_state ps_recv, ps_tunw, ps_tunr,
                        ps_dl;
                    if (prof_print("srv recv", &ps_recv, g_prof_srv_recv)) {
                        prof_print("srv tunw", &ps_tunw, g_prof_srv_tunw);
                        prof_print("srv tunr", &ps_tunr, g_prof_srv_tunr);
                        prof_print("srv dlsend", &ps_dl, g_prof_srv_dlsend);
                    }
                }
#endif
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
    /* H-3: queue fds pre-opened in the root section (before fork+setuid)
     * and handed to tun_pool_create_pre; `pre` lives on main's stack and
     * is inherited by the child across the fork. maxq/initq are computed
     * once in the root section and reused for the pool after the fork. */
    int pre[TUN_POOL_MAX];
    int npre = 0;
    int maxq = TUN_POOL_MAX;
    int initq = 0;
    _Atomic int poll_err = 0;   /* M3-6: fatal poll flag aggregated from
                                 * all recv threads (exit != 0 for mgrs) */
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
    ctx.tun_fd = -1;

    {
        uint32_t sipu = ip4_u32(sip);
        if (sipu >= ctx.ip_base && sipu <= ctx.ip_end) {
            fprintf(stderr, "error: --server-ip %s falls inside the client "
                            "pool; pick an address outside [first,last]\n",
                    o.server_ip);
            return 1;
        }
    }

    /* M5: server_ip must lie INSIDE the advertised --subnet: an out-of-
     * subnet gateway is unconditionally broken (every client would be
     * configured with an unreachable next hop). subnet_base/mask are
     * already parsed (above); a plain per-bit AND is the membership test. */
    {
        uint32_t mask32 = 0xFFFFFFFFu << (32 - o.mask);
        uint32_t sipu = ip4_u32(sip);
        if ((sipu & mask32) != subnet_base) {
            fprintf(stderr, "error: --server-ip %s is outside --subnet %s "
                            "(must be within %s)\n",
                    o.server_ip, o.subnet, subnet_net);
            return 1;
        }
    }

    /* R37 R1-D-2: a --dns OUTSIDE the client pool is only warned about,
     * never fatal. T_DNS/T_IP hand the resolver to the client as a
     * tunnel-reachable address, and a public resolver outside --subnet
     * (exactly the documented default 114.114.114.114) is reached
     * through the tunnel — making that fatal meant the usage's own
     * default combination could never start. An in-pool --dns is a
     * different case and stays fatal (L31): the pool allocator
     * (server.c next_ip) only skips addresses held by a live session and
     * never reserves ctx.dns, so it WILL hand the DNS address out on an
     * OPEN — measured: the first client got tun == dns == 198.18.0.2 and
     * the fourth got .5 with -d 198.18.0.5. A resolver address shared
     * with a client is a guaranteed conflict, not a warning. */
    {
        uint32_t mask32 = 0xFFFFFFFFu << (32 - o.mask);
        uint32_t dipu = ip4_u32(dip);
        if (dipu >= ctx.ip_base && dipu <= ctx.ip_end) {
            fprintf(stderr, "error: --dns %s falls inside the client pool "
                            "of --subnet %s; it is not reserved by the pool "
                            "allocator, so a client would be handed the "
                            "same address (pick a DNS outside the pool)\n",
                    o.dns, o.subnet);
            return 1;
        }
        if ((dipu & mask32) != subnet_base)
            fprintf(stderr, "warning: --dns %s is outside --subnet %s; "
                            "clients can reach it only if the tunnel/routes "
                            "allow it\n",
                    o.dns, subnet_net);
    }

    if (o.no_tun) {
        printf("no-tun mode: TCP echo mirror (bench harness)\n");
    } else {
        enable_ip_forward();
        setup_nat(subnet_net, o.nat_if);
        tun_fd = setup_tun(o.tun, o.server_ip, o.mask);
        ctx.tun_fd = tun_fd;
        printf("tun %s fd=%d\n", o.tun, tun_fd);
        /* M1: attach the eBPF flow-hash steering HERE, while still root.
         * It is a root-only BPF_PROG_LOAD syscall + TUNSETSTEERINGEBPF
         * ioctl — no thread interaction, safe to do before the fork.  After
         * the fork/drop below an unprivileged process would hit EPERM and
         * silently fall back to the kernel's degenerate automq flow hash
         * (the exact problem this feature exists to fix).  Failure is
         * non-fatal: the kernel keeps automq (tun.c logs the reason). */
        if (tun_steering_attach(tun_fd) == 0)
            printf("tun steering: eBPF flow hash attached\n");
        else
            printf("tun steering: eBPF flow hash NOT attached "
                   "(kernel automq fallback; see tun.c log)\n");

        /* H-3: pre-open the extra queue fds HERE, while still root, so a
         * default root deployment actually gets a multi-queue fan-out.
         * tun_pool_add -> tun_attach -> open("/dev/net/tun")+TUNSETIFF
         * afterwards (in the forked setuid child, which has lost
         * CAP_NET_ADMIN) fails EPERM, silently pinning the server to a
         * single queue. tun_attach_many opens up to initq-1 extra queue
         * fds on the device we just created; the fds cross the fork below
         * (inherited by the child) and are handed to tun_pool_create_pre,
         * which takes ownership of them (pool closes them on destroy; the
         * root parent does NOT close them — it just waits/forwards).  Only
         * the extra queues we create ourselves are touched; existing
         * devices are never modified.  On a non-root deployment
         * tun_attach_many returns 0 and the pool falls back to attaching
         * at creation time (unchanged behavior).  The pool geometry
         * (maxq/initq) is computed here once so it is available both for
         * the pre-open and for the pool creation after the fork. */
        {
            long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
            maxq = TUN_POOL_MAX;
            if (ncpu > 0 && ncpu < maxq)
                maxq = (int)ncpu;
            initq = recv_threads < maxq ? recv_threads : maxq;
            npre = tun_attach_many(o.tun, pre, initq - 1);
            if (npre > 0)
                printf("tun: pre-opened %d extra queue fd%s while root\n",
                       npre, npre > 1 ? "s" : "");
            else
                printf("tun: no pre-opened extra queue fds "
                       "(non-root or queue setup limited)\n");
        }
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
                /* R24-f3 F3: the server child is already forked; without
                 * this it would keep running as an orphan while we just
                 * stripped the NAT rules it depends on. Kill + reap it. */
                kill(pid, SIGKILL);
                (void)waitpid(pid, NULL, 0);
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
                /* R37 WG1a: `st` must not shadow the `struct stat st` of
                 * the parent branch under -Wshadow -Werror */
                int wst;
                if (waitpid(pid, &wst, 0) < 0) {
                    if (errno == EINTR)
                        continue;
                    server_cleanup_nat();
                    return 1;
                }
                server_cleanup_nat();
                return WIFEXITED(wst) ? WEXITSTATUS(wst) : 1;
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
        /* maxq/initq were computed once in the root section above (H-3)
         * so the same geometry drives both the queue pre-open and this
         * pool. */
        pu.ctx = &ctx;
        pu.udp_fds = udp_fds;
        pu.nfds = nfds;
        /* eager full pool: uplink writers spread across the queue fds
         * (tun_pool_write_fd, tid % nq); starting at the recv-thread
         * count means the write-side fan-out is effective immediately
         * instead of waiting for the downlink-driven AIMD to grow the
         * pool (ACK-only downlink keeps it near 1 queue otherwise).
         * tun_pool_create_pre first consumes the queue fds pre-opened in
         * the root section (via tun_attach_many), then falls back to
         * tun_attach for any shortfall (non-root deployments). */
        ctx.qpool = tun_pool_create_pre(o.tun, tun_fd, maxq, initq,
                                        npre > 0 ? pre : NULL, npre,
                                        srv_tun_pkt, &pu, &g_stop);
        if (!ctx.qpool) {
            fprintf(stderr, "error: cannot start TUN reader pool\n");
            if (!drop_child)
                server_cleanup_nat(); /* parent (root) undoes NAT */
            return 1;
        }
        /* M1: report the REAL queue count (tun_pool_queues) instead of the
         * requested initq — eager multi-queue fill (tun_pool_add ->
         * open /dev/net/tun per queue) still degrades when /dev/net/tun
         * access is limited, and claiming initq queues would then lie
         * about the actual fan-out. */
        int nq = tun_pool_queues(ctx.qpool);
        printf("tun reader pool: %d queue%s (dynamic up to %d)\n",
               nq, nq > 1 ? "s" : "", maxq);
        if (nq < initq)
            fprintf(stderr,
                    "warning: tun reader pool: only %d queue(s) (wanted %d); "
                    "/dev/net/tun access or queue setup limited -- steering "
                    "may be single-queue\n", nq, initq);
    }
    /* L23: report the port the kernel actually bound to udp_fds[0], not
     * the requested one. `-p 0` asks for an ephemeral port, and with
     * SO_REUSEPORT each socket is bound independently — measured: the
     * kernel picked FOUR different ephemeral ports for the four recv
     * sockets, so the old "listening UDP 0.0.0.0:0" line advertised a
     * port that does not exist and no single port reaches the whole
     * fan-out. Keep running (--port 0 stays accepted) but make the log
     * honest and call the unusable fan-out out loud. */
    {
        struct sockaddr_in ba;
        socklen_t blen = sizeof ba;
        uint16_t bound_port = o.port;
        if (getsockname(udp_fds[0], (struct sockaddr *)&ba, &blen) == 0)
            bound_port = ntohs(ba.sin_port);
        for (int i = 1; i < nfds; i++) {
            struct sockaddr_in b2;
            socklen_t l2 = sizeof b2;
            if (getsockname(udp_fds[i], (struct sockaddr *)&b2, &l2) == 0 &&
                ntohs(b2.sin_port) != bound_port) {
                fprintf(stderr,
                        "warning: SO_REUSEPORT sockets bound to different "
                        "ports (fd[0]=%u, fd[%d]=%u); with an ephemeral "
                        "--port 0 there is no single port clients can "
                        "connect to -- pass a fixed --port\n",
                        (unsigned)bound_port, i,
                        (unsigned)ntohs(b2.sin_port));
                break;
            }
        }
        printf("listening UDP 0.0.0.0:%u (%d recv thread%s)\n",
               (unsigned)bound_port, recv_threads,
               recv_threads > 1 ? "s" : "");
    }
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
                                             (unsigned)(i + 1),
                                             &poll_err };
        if (pthread_create(&workers[i], NULL, recv_thread_main,
                           &args[i + 1]) != 0) {
            log_err("cannot start uplink recv thread %d: %s", i + 1,
                    strerror(errno));
            atomic_store_explicit(&g_stop, true, memory_order_relaxed);
            /* R25-f2 F2-A: without this the process would exit 0 after
             * "server ready" with zero (or too few) recv threads — a
             * silent startup black hole. Surface it as a fatal poll error
             * so server_shutdown returns non-zero. */
            atomic_store_explicit(&poll_err, 1, memory_order_relaxed);
            break;
        }
        ncreated++;
    }
    args[0] = (struct recv_thr_arg){ &ctx, users, nusers, udp_fds[0], 0,
                                     &poll_err };
    recv_thread_main(&args[0]);   /* primary loop, inline */

    /* join ONLY the threads that were created: pthread_create failure
     * leaves the remaining workers[] entries uninitialized, and joining
     * them is UB (EINVAL at best, crash at worst) on the degraded path */
    for (int i = 0; i < ncreated; i++)
        pthread_join(workers[i], NULL);   /* exit within one poll timeout */

    /* M3-6: aggregate AFTER the join so a worker's fatal poll failure
     * in its final window is not lost (previously only the primary's
     * flag was surfaced and a secondary fatal still exited 0) */
    int shutdown_poll_err = atomic_load(&poll_err);
    return server_shutdown(&ctx, tun_fd, udp_fds, nfds, drop_child,
                           shutdown_poll_err);
}
