#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"
#include "protocol.h"
#include "server.h"
#include "tun.h"
#include "util.h"

static volatile sig_atomic_t g_stop;

struct opts {
    uint16_t port;
    char tun[IFNAMSIZ];
    char server_ip[16];
    char subnet[64];
    int mask;
    char dns[16];
    char users[256];
    char nat_if[64];
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
    { "help",      no_argument,       NULL, 'h' },
    { NULL, 0, NULL, 0 },
};

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void usage(const char *prog)
{
    printf("usage: %s [options]\n", prog);
    printf("  -p, --port <P>         UDP port to listen on (default 6001)\n");
    printf("  -t, --tun <NAME>       TUN device name (default iwan-srv)\n");
    printf("  -s, --server-ip <IP>   server/gateway IP on the TUN (default 198.18.0.1)\n");
    printf("  -S, --subnet <IP/MASK> client subnet, mask 8-30 (default 198.18.0.0/16)\n");
    printf("  -d, --dns <IP>         DNS server advertised to clients (default 114.114.114.114)\n");
    printf("  -u, --users <FILE>     users file, one user:pass per line (default /etc/iwan/users.txt)\n");
    printf("  -n, --nat-if <IF>      outbound interface for MASQUERADE (default eth0)\n");
    printf("      --no-tun           (testing) skip TUN device\n");
    printf("  -h, --help             show this help\n");
}

static void parse_opts(int argc, char **argv, struct opts *o)
{
    int c;

    while ((c = getopt_long(argc, argv, "p:t:s:S:d:u:n:Th", long_opts, NULL)) != -1) {
        switch (c) {
        case 'p':
            if (str_to_u16(optarg, &o->port) != 0) {
                fprintf(stderr, "error: invalid port '%s'\n", optarg);
                exit(1);
            }
            break;
        case 't':
            if (strlen(optarg) >= IFNAMSIZ) {
                fprintf(stderr, "error: tun device name too long (max %d)\n",
                        IFNAMSIZ - 1);
                exit(1);
            }
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
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(1);
        }
    }
    if (optind < argc) {
        fprintf(stderr, "error: unexpected argument '%s'\n", argv[optind]);
        usage(argv[0]);
        exit(1);
    }
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
    return n;
}

static void enable_ip_forward(void)
{
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    bool ok;

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
        if (run_cmd(add) == 0)
            printf("iptables: MASQUERADE %s -> %s\n", subnet, nat_if);
        else
            fprintf(stderr,
                    "warning: iptables MASQUERADE failed (need root and iptables?)\n");
    }
}

/* ---- dynamic TUN reader pool ----
 * One IFF_MULTI_QUEUE device, up to TUN_MAXQ queue fds, each drained by
 * its own thread. A controller in the main loop (qpool_tick, 500ms)
 * grows/shrinks the pool with TCP-style AIMD on the poll-timeout busy
 * signal. Reader threads only touch ctx->sess under its lock (downlink
 * snapshots) and their own atomic counters. */
#define TUN_MAXQ 8
#define TUN_QCTL_MS 500
#define TUN_BUSY_GROW 0.85
#define TUN_BUSY_SHRINK 0.60

struct tun_reader {
    struct tun_qpool *pool;
    int fd;
    pthread_t th;
    volatile int stop;
    atomic_uint_fast64_t count;
    atomic_uint_fast64_t waits; /* poll timeouts in current window */
};

struct tun_qpool {
    struct tun_reader qs[TUN_MAXQ];
    struct server_ctx *ctx;
    int udp_fd;
    int nq;
    int maxq;
    char tunname[IFNAMSIZ];
};

static int open_tun_mq(const char *name)
{
    int fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr;
    if (fd < 0)
        return -1;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void *tun_reader_main(void *ud)
{
    struct tun_reader *q = ud;
    struct tun_qpool *pool = q->pool;
    struct pollfd pfd = { .fd = q->fd, .events = POLLIN };
    static _Thread_local uint8_t buf[65536];
    uint64_t local = 0;

    while (!q->stop) {
        int pr = poll(&pfd, 1, 100);
        if (pr < 0 && errno != EINTR)
            break;
        if (pr == 0) {
            if (local) {
                atomic_fetch_add(&q->count, local);
                local = 0;
            }
            atomic_fetch_add(&q->waits, 1);
            continue;
        }
        if (pfd.revents & POLLIN) {
            ssize_t r;
            uint64_t woke = now_ms();
            int npk = 0;
            while ((r = read(q->fd, buf, sizeof buf)) > 0) {
                handle_tun_downlink(pool->ctx, buf, (size_t)r, q->fd,
                                    pool->udp_fd);
                local++;
                npk++;
            }
            /* diagnostic (IWAN_DEBUG=1): reader wake -> drain latency.
             * A late wake (poll slept far past the packet's arrival) or a
             * slow drain pinpoints the downlink (ACK) path delay. */
            if (debug_enabled() && npk > 0) {
                static _Thread_local uint64_t last_print;
                if (woke - last_print >= 250) {
                    last_print = woke;
                    fprintf(stderr,
                            "[reader] q=%d wake=%llu pkts=%d "
                            "last_poll_was_%s\n",
                            (int)(q - pool->qs),
                            (unsigned long long)woke, npk,
                            pr == 0 ? "timeout" : "event");
                }
            }
        }
    }
    /* drain the ring before exiting: packets already queued on this fd
     * would otherwise be lost when qpool_del detaches+closes it, stalling
     * the client flow until TCP RTO retransmits */
    for (;;) {
        ssize_t r = read(q->fd, buf, sizeof buf);
        if (r <= 0)
            break;
        handle_tun_downlink(pool->ctx, buf, (size_t)r, q->fd, pool->udp_fd);
        local++;
    }
    if (local)
        atomic_fetch_add(&q->count, local);
    return NULL;
}

static int qpool_add(struct tun_qpool *pool)
{
    int fd;

    if (pool->nq >= pool->maxq)
        return -1;
    fd = open_tun_mq(pool->tunname);
    if (fd < 0)
        return -1;
    set_nonblock(fd);
    {
        struct tun_reader *q = &pool->qs[pool->nq];
        q->pool = pool;
        q->fd = fd;
        q->stop = 0;
        atomic_store(&q->count, 0);
        atomic_store(&q->waits, 0);
        if (pthread_create(&q->th, NULL, tun_reader_main, q) != 0) {
            close(fd);
            return -1;
        }
    }
    pool->nq++;
    return 0;
}

/* drop the newest queue; queue 0 (the device owner) is never dropped */
static void qpool_del(struct tun_qpool *pool)
{
    int i;

    if (pool->nq <= 1)
        return;
    i = pool->nq - 1;
    pool->qs[i].stop = 1;
    pthread_join(pool->qs[i].th, NULL);
    ioctl(pool->qs[i].fd, TUNSETQUEUE, (void *)(long)IFF_DETACH_QUEUE);
    close(pool->qs[i].fd);
    pool->nq--;
}

static struct tun_qpool *qpool_create(struct server_ctx *ctx, int udp_fd,
                                      const char *tunname, int fd0, int maxq)
{
    struct tun_qpool *pool = calloc(1, sizeof *pool);
    struct tun_reader *q;

    if (!pool)
        return NULL;
    pool->ctx = ctx;
    pool->udp_fd = udp_fd;
    pool->maxq = maxq > TUN_MAXQ ? TUN_MAXQ : (maxq < 1 ? 1 : maxq);
    snprintf(pool->tunname, sizeof pool->tunname, "%s", tunname);
    q = &pool->qs[0];
    q->pool = pool;
    q->fd = fd0;
    q->stop = 0;
    atomic_store(&q->count, 0);
    atomic_store(&q->waits, 0);
    if (pthread_create(&q->th, NULL, tun_reader_main, q) != 0) {
        free(pool);
        return NULL;
    }
    pool->nq = 1;
    return pool;
}

static void qpool_destroy(struct tun_qpool *pool)
{
    int i;

    if (!pool)
        return;
    for (i = 0; i < pool->nq; i++)
        pool->qs[i].stop = 1;
    for (i = 0; i < pool->nq; i++)
        pthread_join(pool->qs[i].th, NULL);
    for (i = 1; i < pool->nq; i++) {
        ioctl(pool->qs[i].fd, TUNSETQUEUE, (void *)(long)IFF_DETACH_QUEUE);
        close(pool->qs[i].fd);
    }
    close(pool->qs[0].fd);
    free(pool);
}

/* AIMD controller: poll-timeout busy signal drives queue count */
static void qpool_tick(struct tun_qpool *pool)
{
    static int slow_start = 1;
    static int idle_cycles = 0;
    uint64_t wsum = 0;
    double busy;
    int target;

    for (int i = 0; i < pool->nq; i++)
        wsum += atomic_exchange(&pool->qs[i].waits, 0);
    busy = 1.0 - (double)wsum /
                  ((double)TUN_QCTL_MS / 100.0 * (double)pool->nq);
    if (busy < 0)
        busy = 0;
    if (busy > 1)
        busy = 1;

    target = pool->nq;
    if (busy > TUN_BUSY_GROW) {
        idle_cycles = 0;
        if (slow_start) {
            target = pool->nq * 2;
            if (target >= 4)
                slow_start = 0;
        } else {
            target = pool->nq + 1;
        }
    } else if (busy < TUN_BUSY_SHRINK) {
        idle_cycles++;
        if (idle_cycles >= 4 && pool->nq > 1) {
            /* conservative shrink: only after 2s of sustained idle, so
             * brief load gaps (test pauses, app think time) do not drop
             * queued packets of live flows */
            target = pool->nq / 2;
            if (target < 1)
                target = 1;
            idle_cycles = 0;
        }
    } else {
        idle_cycles = 0;
    }
    if (target > pool->maxq)
        target = pool->maxq;

    while (pool->nq < target) {
        if (qpool_add(pool) != 0)
            break;
        srv_log("tun reader pool: %d queues", pool->nq);
    }
    while (pool->nq > target && pool->nq > 1) {
        qpool_del(pool);
        srv_log("tun reader pool: %d queues", pool->nq);
    }
}

/* remove stale device, open, configure. Exits on failure. */
static int setup_tun(const char *name, const char *server_ip, int mask)
{
    int fd;
    char addr[64];

    (void)ip_run_quiet((char *[]){"link", "del", (char *)name, NULL});
    fd = open_tun_mq(name);
    if (fd < 0) {
        fprintf(stderr, "error: cannot open tun device %s: %s (run as root?)\n",
                name, strerror(errno));
        exit(1);
    }
    set_nonblock(fd);
    (void)ip_run((char *[]){"addr", "flush", "dev", (char *)name, NULL});
    (void)ip_run((char *[]){"link", "set", (char *)name, "up", NULL});
    snprintf(addr, sizeof addr, "%s/%d", server_ip, mask);
    (void)ip_run((char *[]){"addr", "add", addr, "dev", (char *)name, NULL});
    return fd;
}

static int setup_udp(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1, sz = 4 * 1024 * 1024;
    struct sockaddr_in addr;

    if (fd < 0) {
        perror("socket");
        exit(1);
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
    set_nonblock(fd); /* never let sendto backpressure stall the loop */

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        exit(1);
    }
    return fd;
}

int main(int argc, char **argv)
{
    struct opts o;
    struct server_ctx ctx;
    struct server_user users[SERVER_MAX_USERS];
    struct sigaction sa;
    struct pollfd fds[2];
    struct stat st;
    uint8_t sip[4], dip[4];
    uint32_t subnet_base;
    char subnet_net[64];
    uint8_t udp_buf[65536];
    uint64_t last_purge;
    int nusers, tun_fd = -1, udp_fd, nfds, pr;
    uint64_t last_drops = 0, last_qctl = 0;

    memset(&o, 0, sizeof o);
    o.port = 6001;
    strcpy(o.tun, "iwan-srv");
    strcpy(o.server_ip, "198.18.0.1");
    strcpy(o.subnet, "198.18.0.0/16");
    strcpy(o.dns, "114.114.114.114");
    strcpy(o.users, "/etc/iwan/users.txt");
    strcpy(o.nat_if, "eth0");

    parse_opts(argc, argv, &o);

    if (!o.no_tun && !valid_tun_name(o.tun)) {
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
    if (stat(o.users, &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO)))
        fprintf(stderr, "warning: %s is group/world readable; chmod 600 recommended\n",
                o.users);

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
        printf("no-tun mode: data plane disabled\n");
    } else {
        enable_ip_forward();
        setup_nat(subnet_net, o.nat_if);
        tun_fd = setup_tun(o.tun, o.server_ip, o.mask);
        ctx.tun_fd = tun_fd;
        printf("tun %s fd=%d\n", o.tun, tun_fd);
    }

    udp_fd = setup_udp(o.port);
    if (!o.no_tun) {
        ctx.qpool = qpool_create(&ctx, udp_fd, o.tun, tun_fd, TUN_MAXQ);
        if (!ctx.qpool) {
            fprintf(stderr, "error: cannot start TUN reader pool\n");
            return 1;
        }
        printf("tun reader pool: 1 queue (dynamic up to %d)\n", TUN_MAXQ);
    }
    printf("listening UDP 0.0.0.0:%u\n", (unsigned)o.port);
    printf("server ready.\n");

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fds[0].fd = udp_fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    nfds = 1;
    last_purge = now_ms();
    last_qctl = now_ms();

    while (!g_stop) {
        pr = poll(fds, nfds, 100);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }

        if (fds[0].revents & (POLLIN | POLLERR)) {
            for (;;) {
                struct sockaddr_in peer;
                socklen_t plen = sizeof peer;
                ssize_t n = recvfrom(udp_fd, udp_buf, sizeof udp_buf, 0,
                                     (struct sockaddr *)&peer, &plen);
                if (n > 0) {
                    handle_udp(&ctx, users, nusers, udp_buf, (size_t)n, &peer,
                               udp_fd);
                    continue;
                }
                if (n < 0 && errno == EINTR)
                    continue;
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                    continue; /* ICMP error (e.g. ECONNREFUSED): drain the
                               * queued errors before parking in poll */
                break; /* EAGAIN: drained */
            }
        }

        uint64_t now = now_ms();
        if (ctx.qpool && now - last_qctl >= TUN_QCTL_MS) {
            qpool_tick(ctx.qpool);
            last_qctl = now;
        }
        if (now - last_purge >= 1000) {
            purge_expired(&ctx, now);
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

    qpool_destroy(ctx.qpool);   /* stops readers, closes all queue fds */
    ctx.qpool = NULL;
    ctx.tun_fd = -1;
    close(udp_fd);
    server_ctx_destroy(&ctx);
    return 0;
}
