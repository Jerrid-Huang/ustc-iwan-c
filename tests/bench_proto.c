/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iWAN unidirectional capacity generator -- inner runs tcp / udp / raw IP (IP protocol 253)
 *
 * Usage:
 *   bench_proto send --proto tcp|udp|raw --target A.B.C.D --port P
 *                    [--size N] [--duration S] [--threads K]
 *   bench_proto recv --proto tcp|udp|raw --bind A.B.C.D --port P
 *                    [--duration S] [--threads K] [--idle-ms M]
 *
 * Meaning of --size (differs per protocol; defaults below):
 *   udp = UDP payload, default 1200, max 65507 (IPv4 total 65535 minus 20B IP header
 *         and 8B UDP header; same value as IWAN_UDP_GSO_UNIT in src/common/protocol.h);
 *   raw = **whole packet** length (including the 20-byte IP header), default 1200, max 65535 => payload
 *         max 65515. SIZE_RAW=1220 in tests/bench_proto.sh uses exactly this convention
 *         (whole packet 1220 / payload 1200);
 *   tcp = bytes per write, default 65536, no limit (kernel splits by MSS).
 * Inner MTU max is 65499 (IWAN_MTU_MAX in src/common/protocol.h) => udp payload above
 * 65471, or raw whole packet above 65499, gets fragmented in the inner layer; you then measure the fragment path, not a single big packet.
 *
 * Output (stdout, machine-parsable, summarized into a table by tests/bench_proto.sh):
 *   READY  proto=<p> role=recv addr=<ip>:<port> rcvbuf=<n> threads=<k>
 *   RESULT proto=<p> role=send bytes=<> pkts=<> secs=<> gbps=<> pps=<> errs=<> threads=<> size=<>
 *   RESULT proto=<p> role=recv bytes=<> pkts=<> secs=<> gbps=<> pps=<> bad=<>
 *          conns=<> idle=<0|1> remote=<ip> chg=<n> maxsize=<>
 *
 *   size/maxsize use the payload convention (kept at end of line; existing fields and order unchanged): send's size
 *   is the **payload sent per packet** (raw already excludes the 20B IP header; tcp is bytes per write); recv's
 *   maxsize is the largest single-packet payload received (tcp: most bytes read by one recv) --
 *   if the receive buffer cannot hold a packet, the kernel silently truncates and undercounts bytes, and maxsize becomes clearly too small;
 *   that is the log evidence for checking "the big packet really arrived".
 *
 *   remote/chg detect bypass: the first remote address received (UDP/raw = packet source address,
 *   TCP = connection peer) and how many times it changed. If inner traffic bypasses the tunnel and crosses the veth directly,
 *   this is recorded as 172.31.201.x or similar instead of the tunnel address.
 *
 * There is also a self-test entry (no privileges needed): bench_proto selftest -- checks the raw-mode
 * IP header it builds (including checksum self-check) and the --size-limit big packet (length/fill/buffer capacity).
 *
 * Semantics (why measured this way):
 *   - Unidirectional saturation: the sender uses a **blocking** socket, so kernel backpressure => counts are "what the link actually accepted";
 *     no illusion of "sent 100 Gbps, received 2 Gbps"; loss shows up as the tx/rx counter difference.
 *   - goodput secs use receiver-side "last packet - first packet", not process runtime, excluding connection setup/startup;
 *     pps uses the same window. Baseline (direct lo) and tunnel (TUN) use the same ruler, so they compare fairly.
 *   - raw mode: src/id/checksum in the IP header are left 0 for the kernel to fill from the route (Linux raw_send_hdrinc
 *     behavior; id is filled by ip_select_ident() only when 0), payload starts with an 8-byte magic
 *     prefix, and the receiver validates every packet and counts bad -- foreign traffic is exposed immediately instead of being
 *     counted in the numbers.
 *   - Receiver ends after idle-ms with no packets (default 700ms): packets still in flight at the tail are counted,
 *     so the two sides need no exact handshake.
 *
 * Note: _GNU_SOURCE is defined centrally by CMakeLists.txt:179; do not define it again in this file
 * (clang reports -Wmacro-redefined under -Werror).
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define RAW_PROTO 253
#define MAX_THREADS 64
#define MAGIC_LEN 8
/*
 * Two hard --size limits (see file header). Use protocol limits, not "what inner MTU should be":
 * exceeding them must fail loudly, not rely on kernel EMSGSIZE and certainly not silently truncate.
 */
#define MAX_UDP_SIZE 65507      /* UDP payload: 65535 - 20(IP) - 8(UDP) */
#define MAX_RAW_SIZE 65535      /* raw whole packet: hard limit of the IPv4 total-length field */
/*
 * Receive buffer is sized by the larger of the two limits (the raw whole packet). It used to be 1400
 * (based on "inner MTU 1400"); with a big MTU, recvfrom **silently truncates**: when the buffer is smaller than
 * the peer packet, the kernel copies only buf bytes and returns that length; bad does not grow, it looks lossless, but byte counts
 * are undercounted -- far harder to diagnose than an error. Do not put it on the stack: 64 reader threads x 64KiB would blow the stack;
 * each reader thread mallocs its own (dgram_reader).
 */
#define DGRAM_BUF 65535
static const char MAGIC[MAGIC_LEN] = { 'I', 'W', 'A', 'N', 'B', 'N', 'C', 'H' };

struct cfg {
    const char *proto;
    const char *ip;         /* send: destination; recv: bind address */
    int port;
    int size;               /* --size: udp=UDP payload; raw=whole packet (incl. 20B IP header);
                             * tcp=bytes per write. See file header. */
    int duration;           /* run duration in seconds */
    int threads;            /* tcp: connections; udp/raw: concurrent sender threads */
    int idle_ms;            /* recv: idle time before finishing */
};

struct result {
    atomic_ullong bytes;
    atomic_ullong pkts;
    atomic_ullong errs;
    atomic_ullong bad;
    atomic_ullong conns;
    atomic_llong first_ms;  /* recv: first-packet time (ms since CLOCK_MONOTONIC) */
    atomic_llong last_ms;   /* recv: last-packet time */
    /* recv: first remote address received (network order, 0 = none yet) and change count.
     * UDP/raw: packet source address; TCP: connection peer. Its purpose is **bypass detection**:
     * if inner traffic bypasses the tunnel and crosses the veth directly, this is 172.31.201.2 or similar,
     * not the tunnel address -- more reliable than bytes alone. */
    atomic_uint remote_first;
    atomic_ullong remote_chg;
    /* recv: largest single-packet payload received (raw excludes 20B IP header). Used only to:
     * reveal silent truncation when the buffer is too small: the value sticks at buffer size, and logs
     * immediately show "the claimed big packet was really only 1400". */
    atomic_ullong max_payload;
};

struct worker {
    const struct cfg *c;
    struct result *r;
    struct sockaddr_in dst; /* send only */
    int fd;                 /* tcp recv (accepted connection) */
};

/*
 * g_deadline is a plain double; two happens-before edges make it safe:
 *   send: main thread writes g_deadline, then release-writes g_go; workers acquire-read g_go;
 *   recv: main thread writes g_deadline, then pthread_create; creation gives workers visibility.
 * Afterwards all threads only read it, so no atomic type is needed.
 */
static atomic_bool g_go;
static atomic_bool g_stop;
static atomic_bool g_idle_stop;
static atomic_int g_workers_ready;
static double g_deadline;

static double now_s(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static long long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void die(const char *msg)
{
    fprintf(stderr, "error: %s\n", msg);
    exit(2);
}

static void die_errno(const char *what)
{
    fprintf(stderr, "error: %s: %s\n", what, strerror(errno));
    exit(2);
}

/* Receive-side window accounting: updated only on real data, so spinning cannot move first-packet time earlier. */
static void recv_stamp(struct result *r, unsigned long long bytes)
{
    long long t = now_ms();
    unsigned long long prev;

    if (atomic_load_explicit(&r->first_ms, memory_order_relaxed) == 0)
        atomic_store_explicit(&r->first_ms, t, memory_order_relaxed);
    atomic_store_explicit(&r->last_ms, t, memory_order_relaxed);
    atomic_fetch_add_explicit(&r->bytes, bytes, memory_order_relaxed);
    atomic_fetch_add_explicit(&r->pkts, 1, memory_order_relaxed);
    /* Max single-packet payload (monotonic): must load + CAS; a direct store lets a late smaller
     * value overwrite the big one, looking like "no big packet was received". */
    prev = atomic_load_explicit(&r->max_payload, memory_order_relaxed);
    while (bytes > prev &&
           !atomic_compare_exchange_weak_explicit(&r->max_payload, &prev, bytes,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed))
        ;                               /* prev was refreshed to current; retry compare */
}

static void fill_payload(unsigned char *buf, int size, unsigned long long seq)
{
    memset(buf, 0x5a, (size_t)size);
    memcpy(buf, MAGIC, MAGIC_LEN);
    /* Big-endian sequence number: directly usable when debugging reorder/duplicates */
    for (int i = 0; i < 8; i++)
        buf[MAGIC_LEN + i] = (unsigned char)((seq >> (56 - 8 * i)) & 0xff);
}

/* Wait for fd readable/writable, at most 200ms. false means timeout or interruption; caller returns to loop head
 * and rechecks the deadline -- every hot loop must go through here; never allow "block indefinitely in a
 * syscall" paths (such a path hangs the whole benchmark when the peer is SIGKILLed). */
static bool wait_fd(int fd, short events)
{
    struct pollfd p = { .fd = fd, .events = events, .revents = 0 };

    return poll(&p, 1, 200) > 0;
}

static int raw_socket(int type)
{
    int fd = socket(AF_INET, type, RAW_PROTO);

    if (fd < 0 && (errno == EPERM || errno == EACCES))
        die("raw socket requires root or CAP_NET_RAW (IP protocol 253)");
    if (fd < 0)
        die_errno("socket(SOCK_RAW)");
    return fd;
}

static void resolve(const char *ip, int port, struct sockaddr_in *out)
{
    memset(out, 0, sizeof *out);
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &out->sin_addr) != 1) {
        fprintf(stderr, "error: not a valid IPv4 address: %s\n", ip);
        exit(2);
    }
}

/*
 * Sum byte by byte, assembling 16-bit words in network order.
 *
 * Do not "optimize" this into reading the buffer as uint16_t*: that violates strict aliasing with the earlier write via struct iphdr *
 * and under -O2 gcc hoists the read before the write. Measured (caught by selftest): the computed
 * checksum omitted daddr, wrote 0xb1f1 instead of the correct 0x9fde, and every packet was
 * dropped by the peer. Byte reads use unsigned char, which may alias anything, so the compiler must
 * preserve order.
 */
static uint32_t sum_net16(const void *p, int bytes)
{
    const unsigned char *b = (const unsigned char *)p;
    uint32_t sum = 0;

    for (int i = 0; i + 1 < bytes; i += 2)
        sum += ((uint32_t)b[i] << 8) | (uint32_t)b[i + 1];
    while (sum >> 16)
        sum = (sum & 0xffffU) + (sum >> 16);
    return sum;
}

/* Return value is host order, assigned directly to iph->check; bytes in memory are the network-order checksum */
static uint16_t ip_checksum(const void *p, int bytes)
{
    return ntohs((uint16_t)~sum_net16(p, bytes));
}

/*
 * With IP_HDRINCL the kernel does **not** fill the source address: packets with 0 in the header are treated on lo
 * as martian-source and dropped; measured symptom: "sender 7 Gbps, receiver zero packets".
 * Use one UDP connect to borrow the kernel's route lookup, then getsockname to get the source address --
 * connect only looks up the route and sends nothing, so the peer need not exist.
 */
static struct in_addr resolve_src(const struct sockaddr_in *dst)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in me;
    socklen_t sl = (socklen_t)sizeof me;

    if (fd < 0)
        die_errno("socket(SOCK_DGRAM)");
    if (connect(fd, (const struct sockaddr *)dst, sizeof *dst) != 0) {
        close(fd);
        die_errno("raw mode source-address lookup failed (no route to target?)");
    }
    memset(&me, 0, sizeof me);
    if (getsockname(fd, (struct sockaddr *)&me, &sl) != 0) {
        close(fd);
        die_errno("getsockname");
    }
    close(fd);
    return me.sin_addr;
}

/* Build a raw IPv4 packet (20-byte header + payload). src/id/checksum filled explicitly, not relying on the kernel. */
static void build_raw_ipv4(unsigned char *buf, int size, unsigned long long seq,
                           struct in_addr src, struct in_addr dst)
{
    struct iphdr *ip = (struct iphdr *)buf;
    int payload = size - (int)sizeof *ip;

    fill_payload(buf + sizeof *ip, payload, seq);
    memset(ip, 0, sizeof *ip);
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons((uint16_t)size);
    ip->id = htons((uint16_t)(seq & 0xffff));
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = RAW_PROTO;
    ip->check = 0;
    ip->saddr = src.s_addr;
    ip->daddr = dst.s_addr;
    ip->check = ip_checksum(buf, (int)sizeof *ip);
}

/* Record/compare first remote address (shared by readers; atomic network-order int avoids string races) */
static void note_remote(struct result *r, const struct sockaddr_in *peer)
{
    unsigned int a = peer->sin_addr.s_addr;
    unsigned int prev = atomic_load_explicit(&r->remote_first,
                                             memory_order_relaxed);

    if (prev == 0)
        atomic_store_explicit(&r->remote_first, a, memory_order_relaxed);
    else if (prev != a)
        atomic_fetch_add_explicit(&r->remote_chg, 1, memory_order_relaxed);
}


/* ---------------------------------------------------------------- sender side */

static void *send_tcp(void *arg)
{
    struct worker *w = arg;
    const struct cfg *c = w->c;
    unsigned char *buf;
    unsigned long long seq = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        die_errno("socket(SOCK_STREAM)");
    if (connect(fd, (const struct sockaddr *)&w->dst, sizeof w->dst) != 0)
        die_errno("connect (peer not listening?)");
    buf = malloc((size_t)c->size);
    if (buf == NULL)
        die("malloc failed");

    atomic_fetch_add_explicit(&g_workers_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&g_go, memory_order_acquire))
        usleep(200);                        /* wait for the main thread's start signal */

    while (now_s() < g_deadline) {
        ssize_t n;

        fill_payload(buf, c->size, seq++);
        /* A blocking send stays in the syscall forever when the peer does not read (bypassing the deadline),
         * so use "wait writable + MSG_DONTWAIT"; backpressure semantics unchanged: wait when the buffer is full. */
        if (!wait_fd(fd, POLLOUT))
            continue;
        n = send(fd, buf, (size_t)c->size, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (n <= 0) {
            /* Connection is dead: flooding on is pointless; leave the error for the summary side to judge */
            atomic_fetch_add_explicit(&w->r->errs, 1, memory_order_relaxed);
            break;
        }
        atomic_fetch_add_explicit(&w->r->bytes, (unsigned long long)n,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&w->r->pkts, 1, memory_order_relaxed);
    }
    free(buf);
    close(fd);
    return NULL;
}

static void *send_dgram(void *arg)
{
    struct worker *w = arg;
    const struct cfg *c = w->c;
    bool raw = strcmp(c->proto, "raw") == 0;
    unsigned char *buf;
    int sndbuf = 8 << 20;
    int fd = raw ? raw_socket(SOCK_RAW) : socket(AF_INET, SOCK_DGRAM, 0);
    unsigned long long seq = 0;
    int payload;
    struct in_addr src = { 0 };

    if (fd < 0)
        die_errno("socket(SOCK_DGRAM)");
    if (raw && setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &(int){ 1 }, sizeof(int)) != 0)
        die_errno("setsockopt(IP_HDRINCL)");
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);

    buf = calloc(1, (size_t)c->size);
    if (buf == NULL)
        die("calloc failed");
    payload = raw ? c->size - (int)sizeof(struct iphdr) : c->size;
    if (raw)
        src = resolve_src(&w->dst);

    atomic_fetch_add_explicit(&g_workers_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&g_go, memory_order_acquire))
        usleep(200);

    while (now_s() < g_deadline) {
        ssize_t n;

        if (raw) {
            build_raw_ipv4(buf, c->size, seq++, src, w->dst.sin_addr);
        } else {
            fill_payload(buf, c->size, seq++);
        }
        if (!wait_fd(fd, POLLOUT))
            continue;
        n = sendto(fd, buf, (size_t)c->size, MSG_DONTWAIT,
                   (const struct sockaddr *)&w->dst, sizeof w->dst);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;               /* buffer full: not an error, backpressure */
            /* Connectionless protocol: a single failure (route/ICMP port unreachable) must not end the run */
            unsigned long long e = atomic_fetch_add_explicit(
                &w->r->errs, 1, memory_order_relaxed) + 1;

            if (e > 10000)
                break;                  /* stop spinning if it keeps failing */
            usleep(1000);
            continue;
        }
        atomic_fetch_add_explicit(&w->r->bytes, (unsigned long long)payload,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&w->r->pkts, 1, memory_order_relaxed);
    }
    free(buf);
    close(fd);
    return NULL;
}

/* ---------------------------------------------------------------- receiver side */

/*
 * Raw IP receive buffers **include the 20-byte IP header** (always true for raw sockets); the magic prefix is
 * after it. Without skipping it, every packet is marked bad and bytes stay 0, with the same symptom as "totally
 * broken". Non-root cannot run raw, so this can only be caught by code review + selftest.
 */
static bool payload_ok(const unsigned char *buf, ssize_t n, bool raw)
{
    if (raw) {
        const struct iphdr *ip = (const struct iphdr *)(const void *)buf;

        if (n < (ssize_t)(sizeof *ip + MAGIC_LEN))
            return false;
        if (ip->version != 4 || ip->protocol != RAW_PROTO)
            return false;
        buf += sizeof *ip;
        n -= (ssize_t)sizeof *ip;
    }
    return n >= MAGIC_LEN && memcmp(buf, MAGIC, MAGIC_LEN) == 0;
}

/*
 * Datagram receive reader: multiple threads share one fd (the kernel wakes one per packet,
 * each packet is consumed once). So recv getting EAGAIN is **normal contention** and must continue,
 * not exit as an error -- otherwise K readers kick each other out on the first packet.
 */
static void *dgram_reader(void *arg)
{
    struct worker *w = arg;
    /* One per reader, sized to the protocol max (--size can reach 65471+ with a big MTU) */
    unsigned char *buf = malloc(DGRAM_BUF);
    /* Raw IP reports **payload** bytes (consistent with udp/tcp), so subtract the IP header */
    const ssize_t off =
        (strcmp(w->c->proto, "raw") == 0) ? (ssize_t)sizeof(struct iphdr) : 0;

    if (buf == NULL)
        die("malloc failed");
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed) &&
           now_s() < g_deadline) {
        struct pollfd p = { .fd = w->fd, .events = POLLIN, .revents = 0 };
        ssize_t n;

        /* Must wait with timeout: when blocked directly in recv, g_stop set by the idle decision
         * only takes effect at the hard limit, wasting 5 seconds at shutdown (looks like a hang). */
        if (poll(&p, 1, 200) <= 0)
            continue;
        /* MSG_DONTWAIT is required, not an optimization: with K readers sharing one fd,
         * after poll reports readable another thread may grab the packet first. If the fd blocks, the loser
         * stays in recv **forever** (the EAGAIN branch never runs),
         * and pthread_join at shutdown hangs -- measured hangs over 300 seconds.
         * With MSG_DONTWAIT the loser immediately gets EAGAIN and returns to the loop head. */
        {
            struct sockaddr_in peer;
            socklen_t pl = (socklen_t)sizeof peer;

            memset(&peer, 0, sizeof peer);
            n = recvfrom(w->fd, buf, DGRAM_BUF, MSG_DONTWAIT,
                         (struct sockaddr *)&peer, &pl);
            if (n >= 0 && pl == (socklen_t)sizeof peer)
                note_remote(w->r, &peer);
        }
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            break;
        }
        if (!payload_ok(buf, n, off != 0)) {
            atomic_fetch_add_explicit(&w->r->bad, 1, memory_order_relaxed);
            continue;
        }
        recv_stamp(w->r, (unsigned long long)(n - off));
    }
    free(buf);
    return NULL;
}

static void *recv_dgram(void *arg)
{
    struct worker *w = arg;
    const struct cfg *c = w->c;
    struct sockaddr_in me;
    pthread_t th[MAX_THREADS];
    struct worker ws[MAX_THREADS];
    bool raw = strcmp(c->proto, "raw") == 0;
    int rcvbuf = 16 << 20, got = -1, n;
    socklen_t sl = (socklen_t)sizeof got;
    int fd = raw ? raw_socket(SOCK_RAW) : socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0)
        die_errno("socket(SOCK_DGRAM)");
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    /* raw mode must **not** bind a port: a raw socket's bind port becomes a receive filter
     * (compares the first 4 bytes of the packet), and raw IP has no port concept => zero packets received.
     * Non-root cannot run raw, so this pitfall only appears on a real host; document it clearly. */
    resolve(c->ip, raw ? 0 : c->port, &me);
    if (bind(fd, (const struct sockaddr *)&me, sizeof me) != 0)
        die_errno("bind (port already in use?)");
    (void)getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &got, &sl);
    printf("READY proto=%s role=recv addr=%s:%d rcvbuf=%d threads=%d\n", c->proto,
           c->ip, raw ? 0 : c->port, got, c->threads);
    fflush(stdout);

    /* Multiple readers are not a luxury: single-thread recv tops out near 1.1 Mpps; on lo with 1200-byte
     * packets it saturates before the link (measured: single thread 3.58 Gbps lossless; with 4 sender threads rx drops 29%
     * -- that is "receiver cannot keep up", not link loss, and is easily misread). */
    n = c->threads < 1 ? 1 : c->threads;
    for (int i = 0; i < n; i++) {
        ws[i].c = c;
        ws[i].r = w->r;
        ws[i].fd = fd;
        if (pthread_create(&th[i], NULL, dgram_reader, &ws[i]) != 0)
            die("pthread_create failed");
    }
    for (int i = 0; i < n; i++)
        pthread_join(th[i], NULL);
    close(fd);
    return NULL;
}

static void *recv_one_tcp(void *arg)
{
    struct worker *w = arg;
    unsigned char *buf = malloc(1 << 20);

    if (buf == NULL)
        die("malloc failed");
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        struct pollfd p = { .fd = w->fd, .events = POLLIN, .revents = 0 };
        ssize_t n;

        /* Like recv_dgram: wait with timeout; leave as soon as g_stop is set */
        if (poll(&p, 1, 200) <= 0)
            continue;
        /* Also MSG_DONTWAIT: when the peer RSTs the connection or stops sending after SIGKILL,
         * a blocking recv passes g_stop and stays forever, hanging the join at shutdown. */
        n = recv(w->fd, buf, 1 << 20, MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            break;
        }
        if (n == 0)
            break;                      /* peer closed normally */
        recv_stamp(w->r, (unsigned long long)n);
    }
    free(buf);
    close(w->fd);
    return NULL;
}

static void *recv_tcp(void *arg)
{
    struct worker *w = arg;
    const struct cfg *c = w->c;
    struct sockaddr_in me;
    pthread_t th[MAX_THREADS];
    struct worker ws[MAX_THREADS];
    int rcvbuf = 16 << 20, got = -1, n = 0;
    socklen_t sl = (socklen_t)sizeof got;
    int lfd = socket(AF_INET, SOCK_STREAM, 0);

    if (lfd < 0)
        die_errno("socket(SOCK_STREAM)");
    (void)setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    (void)setsockopt(lfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    resolve(c->ip, c->port, &me);
    if (bind(lfd, (const struct sockaddr *)&me, sizeof me) != 0)
        die_errno("bind (port already in use?)");
    if (listen(lfd, 64) != 0)
        die_errno("listen");
    /* accept must also be bounded: if a queued connection is RST by the peer after poll reports readable, a blocking
     * accept waits for the next connection; neither g_stop nor the deadline stops it. */
    {
        int fl = fcntl(lfd, F_GETFL, 0);

        if (fl < 0 || fcntl(lfd, F_SETFL, fl | O_NONBLOCK) < 0)
            die_errno("fcntl(O_NONBLOCK)");
    }
    (void)getsockopt(lfd, SOL_SOCKET, SO_RCVBUF, &got, &sl);
    printf("READY proto=%s role=recv addr=%s:%d rcvbuf=%d\n", c->proto, c->ip,
           c->port, got);
    fflush(stdout);

    while (!atomic_load_explicit(&g_stop, memory_order_relaxed) &&
           now_s() < g_deadline) {
        struct pollfd p = { .fd = lfd, .events = POLLIN, .revents = 0 };
        int fd;

        /* The listen fd also needs a timeout: g_stop cannot wake it from a blocking accept */
        if (poll(&p, 1, 200) <= 0)
            continue;
        fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            break;
        }
        {
            struct sockaddr_in peer;
            socklen_t pl = (socklen_t)sizeof peer;

            if (getpeername(fd, (struct sockaddr *)&peer, &pl) == 0)
                note_remote(w->r, &peer);
        }
        if (n < c->threads && n < MAX_THREADS) {
            ws[n].c = c;
            ws[n].r = w->r;
            ws[n].fd = fd;
            if (pthread_create(&th[n], NULL, recv_one_tcp, &ws[n]) != 0)
                die("pthread_create failed");
            n++;
            atomic_store_explicit(&w->r->conns, (unsigned long long)n,
                                  memory_order_relaxed);
        } else {
            close(fd);                  /* accept only the agreed count; close extras */
        }
    }
    close(lfd);
    for (int k = 0; k < n; k++)
        pthread_join(th[k], NULL);
    return NULL;
}

/* ---------------------------------------------------------------- main flow */

static int parse_int(const char *s, const char *what)
{
    char *end = NULL;
    long v = strtol(s, &end, 10);

    if (end == NULL || *end != '\0' || v <= 0 || v > (1 << 30)) {
        fprintf(stderr, "error: invalid value for %s: %s\n", what, s);
        exit(2);
    }
    return (int)v;
}

static void usage(void)
{
    fprintf(stderr,
            "Usage:\n"
            "  bench_proto send --proto tcp|udp|raw --target A.B.C.D --port P\n"
            "                    [--size N] [--duration S] [--threads K]\n"
            "  bench_proto recv --proto tcp|udp|raw --bind A.B.C.D --port P\n"
            "                    [--duration S] [--threads K] [--idle-ms M]\n"
            "  --size: udp = UDP payload (<= 65507, default 1200)\n"
            "          raw = whole-packet length, incl. 20B IP header (<= 65535, default 1200)\n"
            "          tcp = bytes per write (default 65536)\n");
    exit(2);
}
/* Self-test: raw sockets need CAP_NET_RAW, so end-to-end cannot run as non-root, but "wrong header" is a
 * silent-failure defect class; at least block it before launch. Needs no privileges. */
static int selftest(void)
{
    unsigned char buf[2048];
    struct iphdr *ip = (struct iphdr *)buf;
    struct in_addr src = { 0 }, dst = { 0 };
    const int size = 1220;
    uint32_t sum = 0;
    int bad = 0;

    if (inet_pton(AF_INET, "10.1.2.3", &src) != 1 ||
        inet_pton(AF_INET, "10.9.9.9", &dst) != 1)
        die("selftest: inet_pton failed");
    memset(buf, 0, sizeof buf);
    build_raw_ipv4(buf, size, 0x1122334455667788ULL, src, dst);

#define CHK(cond, desc)                                                        \
    do {                                                                       \
        if (cond) {                                                            \
            printf("  ok   %s\n", desc);                                       \
        } else {                                                               \
            printf("  FAIL %s\n", desc);                                       \
            bad++;                                                             \
        }                                                                      \
    } while (0)

    CHK(ip->version == 4 && ip->ihl == 5, "version/IHL = 4/5");
    CHK((int)ntohs(ip->tot_len) == size, "tot_len = whole-packet length");
    CHK(ip->protocol == RAW_PROTO, "protocol = 253");
    CHK(ip->saddr == src.s_addr, "source address filled explicitly (0 is dropped as martian on lo)");
    CHK(ip->daddr == dst.s_addr, "destination address correct");
    CHK(ip->id != 0, "id is nonzero (kernel must not fill it)");
    CHK(memcmp(buf + sizeof *ip, MAGIC, MAGIC_LEN) == 0, "payload magic prefix correct");
    CHK(payload_ok(buf, size, true), "payload_ok accepts raw packet with IP header");
    CHK(!payload_ok(buf, size, false), "payload_ok rejects when IP header is not skipped (offset must be right)");
    {
        unsigned char wrong[2048];   /* cannot be named bad: it would shadow the counter above */

        memcpy(wrong, buf, (size_t)size);
        ((struct iphdr *)(void *)wrong)->protocol = 6;
        CHK(!payload_ok(wrong, size, true), "packet with wrong protocol rejected");
    }
    sum = sum_net16(buf, (int)sizeof *ip);
    CHK(sum == 0xffffU, "IP header checksum self-check (network-order 16-bit sum = 0xffff)");
    if (sum != 0xffffU) {
        printf("       diagnostic: first 20 header bytes =");
        for (int i = 0; i < (int)sizeof *ip; i++)
            printf(" %02x", buf[i]);
        printf("\n       folded network-order sum = %04x (should be ffff), check field bytes = %02x %02x\n",
               sum, buf[10], buf[11]);
    }
    /*
     * Also self-check the big packet (--size limit): raw cannot run end-to-end as non-root, and "length field
     * is only 16 bits", "payload does not reach the last byte", "receive buffer cannot hold it" only surface on big
     * packets, and all fail silently. Use the heap: 65535 does not fit in buf[].
     */
    {
        const int jsize = MAX_RAW_SIZE;         /* whole-packet limit 65535 */
        unsigned char *j = malloc((size_t)jsize);

        if (j == NULL)
            die("selftest: malloc failed");
        build_raw_ipv4(j, jsize, 0xdeadbeefcafef00dULL, src, dst);
        CHK(((struct iphdr *)(void *)j)->tot_len == htons((uint16_t)jsize),
            "big packet tot_len = whole-packet length (16-bit field exactly at max)");
        CHK(sum_net16(j, (int)sizeof(struct iphdr)) == 0xffffU,
            "big packet IP header checksum self-check");
        CHK(payload_ok(j, jsize, true), "big packet accepted (includes IP header)");
        CHK(j[jsize - 1] == 0x5a, "big packet payload fills to the last byte (length not undercounted)");
        CHK(memcmp(j + sizeof(struct iphdr) + MAGIC_LEN,
                   "\xde\xad\xbe\xef\xca\xfe\xf0\x0d", 8) == 0,
            "big packet sequence is big-endian after the magic");
        CHK(jsize <= DGRAM_BUF, "receive buffer holds the maximum whole packet");
        free(j);
    }
#undef CHK
    printf("selftest: %s (%d failures)\n", bad == 0 ? "PASS" : "FAIL", bad);
    return bad == 0 ? 0 : 1;
}



int main(int argc, char **argv)
{
    struct cfg c = { .proto = NULL, .ip = NULL, .port = 0, .size = 0,
                     .duration = 5, .threads = 4, .idle_ms = 700 };
    struct result res;
    struct worker ws[MAX_THREADS];
    pthread_t th[MAX_THREADS];
    const char *role;
    bool is_recv;
    int nthreads = 1;

    memset(&res, 0, sizeof res);
    memset(ws, 0, sizeof ws);
    if (argc < 2)
        usage();
    role = argv[1];
    if (strcmp(role, "selftest") == 0)
        return selftest();
    if (strcmp(role, "send") != 0 && strcmp(role, "recv") != 0)
        usage();
    is_recv = strcmp(role, "recv") == 0;

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];

        if (i + 1 >= argc)
            usage();
        i++;
        if (strcmp(a, "--proto") == 0)
            c.proto = argv[i];
        else if (strcmp(a, "--port") == 0)
            c.port = parse_int(argv[i], "--port");
        else if (strcmp(a, "--size") == 0)
            c.size = parse_int(argv[i], "--size");
        else if (strcmp(a, "--duration") == 0)
            c.duration = parse_int(argv[i], "--duration");
        else if (strcmp(a, "--threads") == 0)
            c.threads = parse_int(argv[i], "--threads");
        else if (strcmp(a, "--idle-ms") == 0)
            c.idle_ms = parse_int(argv[i], "--idle-ms");
        else if (strcmp(a, "--target") == 0 || strcmp(a, "--bind") == 0)
            c.ip = argv[i];
        else
            usage();
    }
    if (c.proto == NULL || c.ip == NULL || c.port == 0)
        usage();
    if (strcmp(c.proto, "tcp") != 0 && strcmp(c.proto, "udp") != 0 &&
        strcmp(c.proto, "raw") != 0) {
        fprintf(stderr, "error: --proto must be tcp/udp/raw: %s\n", c.proto);
        return 2;
    }
    if (c.threads > MAX_THREADS)
        die("--threads exceeds the limit 64");
    if (c.size == 0)
        c.size = strcmp(c.proto, "tcp") == 0 ? (1 << 16) : 1200;
    if (strcmp(c.proto, "raw") == 0 &&
        (c.size < (int)sizeof(struct iphdr) + MAGIC_LEN + 8 ||
         c.size > MAX_RAW_SIZE))
        die("--size for raw is the whole-packet length (including 20-byte IP header), max 65535"
            "(payload 16..65515)");
    if (strcmp(c.proto, "udp") == 0 &&
        (c.size < MAGIC_LEN + 8 || c.size > MAX_UDP_SIZE))
        die("--size for udp is the UDP payload, max 65507 (16..65507,"
            "plus 28 bytes IP/UDP header must not exceed 65535)");

    atomic_store(&g_go, false);
    atomic_store(&g_stop, false);
    atomic_store(&g_idle_stop, false);
    atomic_store(&g_workers_ready, 0);

    if (is_recv) {
        pthread_t mon;

        /* Hard limit = duration + 5s: recv must finish even if all senders hang */
        g_deadline = now_s() + (double)c.duration + 5.0;
        /* Must fill worker before creating the thread: it reads c/r immediately */
        ws[0].c = &c;
        ws[0].r = &res;
        if (pthread_create(&mon, NULL,
                           strcmp(c.proto, "tcp") == 0 ? recv_tcp : recv_dgram,
                           &ws[0]) != 0)
            die("pthread_create failed");
        for (;;) {
            long long last = atomic_load_explicit(&res.last_ms,
                                                  memory_order_relaxed);
            unsigned long long pkts = atomic_load_explicit(&res.pkts,
                                                           memory_order_relaxed);

            if (pkts > 0 && last > 0 && now_ms() - last > c.idle_ms) {
                atomic_store(&g_idle_stop, true);
                printf("IDLE_STOP proto=%s waited_ms=%d\n", c.proto, c.idle_ms);
                fflush(stdout);
                break;
            }
            if (now_s() >= g_deadline)
                break;
            usleep(50 * 1000);
        }
        atomic_store(&g_stop, true);
        pthread_join(mon, NULL);
    } else {
        void *(*fn)(void *) = strcmp(c.proto, "tcp") == 0 ? send_tcp
                                                          : send_dgram;
        struct sockaddr_in dst;
        double t_barrier;

        resolve(c.ip, c.port, &dst);
        nthreads = c.threads;
        for (int i = 0; i < nthreads; i++) {
            ws[i].c = &c;
            ws[i].r = &res;
            ws[i].dst = dst;
            if (pthread_create(&th[i], NULL, fn, &ws[i]) != 0)
                die("pthread_create failed");
        }
        /* Start line: wait for all threads ready (tcp includes connection setup, not counted in window) */
        t_barrier = now_s() + 10.0;
        while (atomic_load_explicit(&g_workers_ready, memory_order_acquire) <
                   nthreads &&
               now_s() < t_barrier)
            usleep(1000);
        if (atomic_load(&g_workers_ready) < nthreads)
            die("worker threads not ready within 10s (common tcp cause: peer not listening)");
        g_deadline = now_s() + (double)c.duration;
        atomic_store(&g_go, true);
        for (int i = 0; i < nthreads; i++)
            pthread_join(th[i], NULL);
    }

    {
        unsigned long long bytes = atomic_load(&res.bytes);
        unsigned long long pkts = atomic_load(&res.pkts);

        if (is_recv) {
            long long f = atomic_load(&res.first_ms);
            long long l = atomic_load(&res.last_ms);
            double secs = (f > 0 && l >= f) ? (double)(l - f) / 1000.0 : 0.0;
            struct in_addr ra;
            char rb[INET_ADDRSTRLEN] = "-";

            ra.s_addr = atomic_load(&res.remote_first);
            if (ra.s_addr != 0)
                (void)inet_ntop(AF_INET, &ra, rb, sizeof rb);
            if (secs < 1e-3)
                secs = 1e-3;
            printf("RESULT proto=%s role=recv bytes=%llu pkts=%llu secs=%.3f "
                   "gbps=%.3f pps=%.0f bad=%llu conns=%llu idle=%d remote=%s "
                   "chg=%llu maxsize=%llu\n",
                   c.proto, bytes, pkts, secs,
                   (double)bytes * 8.0 / secs / 1e9, (double)pkts / secs,
                   atomic_load(&res.bad), atomic_load(&res.conns),
                   atomic_load(&g_idle_stop) ? 1 : 0, rb,
                   atomic_load(&res.remote_chg),
                   atomic_load(&res.max_payload));
        } else {
            double secs = (double)c.duration;
            /* End-of-line size is per-packet payload: raw --size is the whole packet, subtract the IP header here,
             * otherwise the log convention does not match recv's maxsize. */
            int payload = strcmp(c.proto, "raw") == 0
                              ? c.size - (int)sizeof(struct iphdr) : c.size;

            printf("RESULT proto=%s role=send bytes=%llu pkts=%llu secs=%.3f "
                   "gbps=%.3f pps=%.0f errs=%llu threads=%d size=%d\n",
                   c.proto, bytes, pkts, secs,
                   (double)bytes * 8.0 / secs / 1e9, (double)pkts / secs,
                   atomic_load(&res.errs), nthreads, payload);
        }
    }
    return 0;
}
