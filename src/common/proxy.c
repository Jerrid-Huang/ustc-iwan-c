#include <errno.h>
#include <pthread.h>
#include <signal.h>   /* SIGINT for on_signal (mingw provides it) */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* POSIX-only headers: on Windows getaddrinfo/gai_strerror/inet_ntop
 * come from port.h (ws2tcpip), UDP_SEGMENT is defined locally there. */
#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "common.h"
#include "crypto.h"
#include "ipv4.h"
#include "profile.h"
#include "protocol.h"
#include "proxy.h"
#include "route.h"
#include "tun.h"
#include "util.h"

struct pump_tx_buf;   /* Windows send-thread batch-buffer pool (defined below) */

/* [prof] per-stage timing accumulators (whole-run; printed at teardown).
 * IWAN_PUMP_PROF=1 enables the printout. PP_SEND_SYS/RETRY/PACE are
 * sub-stages of PP_SEND (send time minus them = lock/build overhead). */
#define PUMP_PROF_N 11
enum {
    PP_COPY_XOR = 0,  /* uplink: per-packet copy + XOR into batch */
    PP_ENQ,           /* uplink: per-batch SPSC enqueue */
    PP_SEND,          /* uplink: per-batch UDP send (incl. lock/GSO) */
    PP_RECV,          /* downlink: recvmmsg batch drain */
    PP_TUNWRITE,      /* downlink: per-packet wintun write */
    PP_SEND_SYS,      /* send sub: time inside port_sendmmsg/port_sendmsg */
    PP_SEND_RETRY,    /* send sub: time inside pump_send_retry (EAGAIN wait) */
    PP_SEND_PACE,     /* send sub: time inside pace_take */
    PP_SENDWAIT,      /* sender sub: blocked on ready_sem (idle/starve) */
    PP_POLLWAIT,      /* recv sub: parked in port_poll (no downlink) */
    PP_DLPKT,         /* downlink: whole per-packet loop (incl tun_write) */
};
typedef struct { uint64_t us; uint64_t n; } pump_prof_t;

/* [prof] send-path accounting: datagrams sent, sendmmsg/sendmsg call
 * count, and EAGAIN/ENOBUFS backpressure hits (tell whether PP_SEND's
 * time is syscalls, retry-waits, or lock/build overhead) */
atomic_uint_fast64_t g_prof_send_dgrams;    /* datagrams inside PP_SEND */
atomic_uint_fast64_t g_prof_send_syscalls;  /* port_sendmmsg/port_sendmsg */
atomic_uint_fast64_t g_prof_send_eagain;    /* EAGAIN/ENOBUFS/EPERM hits */
/* [prof] recv-loop accounting: recvmmsg call count is PP_RECV.n; these
 * split it into real datagrams vs empty spins, and count auth failures */
atomic_uint_fast64_t g_prof_recv_dgrams;    /* sum of v over recvmmsg calls */
atomic_uint_fast64_t g_prof_recv_empty;     /* EAGAIN (no data) iterations */
atomic_uint_fast64_t g_prof_recv_badtok;    /* datagrams with bad sid/token */
/* [prof] wintun read-side GSO probe: if the kernel TSO'd into wintun we
 * would see packets > 1508B (up to 64KB); current slots only hold
 * PUMP_SLOT=2048 so oversized candidates get dropped and counted here */
atomic_uint_fast64_t g_prof_tun_rbig;       /* wintun packets > 1508B */
atomic_uint_fast64_t g_prof_tun_rdrop;      /* wintun packets > PUMP_SLOT */
static uint32_t g_prof_tun_rmax;            /* max wintun packet len (B),
                                             * written by single reader */
/* [prof] wintun reader-thread accounting (defined in tun_win.c):
 * wait = parked in WaitForSingleObject (idle + wake latency),
 * timeouts = WAIT_TIMEOUT idle wakes, wakeups = signaled wakes,
 * pkts = packets drained, drain = drain-loop time, allocfail =
 * tun_write AllocateSendPacket first-try failures (TX ring full) */
#ifdef _WIN32
extern atomic_uint_fast64_t g_tun_wait_us, g_tun_timeouts, g_tun_wakeups,
                            g_tun_pkts, g_tun_drain_us, g_tun_allocfail;
#endif

static inline void pump_prof_add(pump_prof_t *p, uint64_t us)
{
    p->us += us;
    p->n++;
}

#ifdef _WIN32
#define PUMP_TX_POOL 4
#define PUMP_SPSC_CAP 16
typedef struct {
    volatile unsigned head;  /* consumer-owned pop index */
    volatile unsigned tail;  /* producer-owned push index */
    unsigned mask;           /* PUMP_SPSC_CAP - 1 */
    struct pump_tx_buf *slots[PUMP_SPSC_CAP];
} pump_spsc_ring_t;
#endif

typedef struct {
    int      tun_fd;   /* downlink write fd (queue 0, device owner) */
    int      sockfd;
    uint8_t  xor_key[8];
    uint16_t sid;
    uint32_t tok;
    uint8_t  enc;
    size_t   gso_mss;   /* last UDP_SEGMENT value set, 0 = none */
    int      gso_ok;    /* 1 = UDP_SEGMENT usable, 0 = failed, -1 = untried */
    pthread_mutex_t send_lock; /* serializes GSO/sendmmsg on the shared socket */
    struct tun_pool *pool;
    pace_bucket pace;   /* aggregate send pacing (util.h); serialized by
                         * send_lock — the bucket is not thread-safe */
    bool session_lost;  /* set by udp2tun_thread when the tunnel is
                         * considered dead (keepalive failures / no
                         * downlink); distinguishes failure from the
                         * user's Ctrl-C so run_pump can report it */
    pump_prof_t prof[PUMP_PROF_N];   /* [prof] stage timers (whole-run) */
#ifdef _WIN32
    /* Windows dedicated UDP sender thread: the wintun reader builds
     * GSO batches in a pool of buffers, enqueues the finished batch,
     * and this thread does the actual send syscalls — so the per-batch
     * WSASend/GSO cost no longer stalls wintun reads. The single sender
     * keeps the batch intact (no per-worker fragmentation). The reader
     * and sender are strictly 1:1, so two SPSC pointer rings + counting
     * semaphores replace the mutex/cond queue. */
    pump_spsc_ring_t free_ring;   /* consumer -> producer (free buffers) */
    pump_spsc_ring_t ready_ring;  /* producer -> consumer (batches) */
    HANDLE free_sem;              /* count of free buffers */
    HANDLE ready_sem;             /* count of ready batches */
    struct pump_tx_buf *tx_pool[PUMP_TX_POOL]; /* batch buffer pool */
    struct pump_tx_buf *cur_buf;  /* reader's in-progress batch */
    pthread_t sender_thread;
    int sender_stop;
#endif
} pump_ctx_t;

static void pump_prof_print(const pump_ctx_t *ctx)
{
    static const char *const names[PUMP_PROF_N] = {
        "copy+xor", "enqueue", "send", "recv", "tun_write",
        "send_sys", "send_retry", "send_pace",
        "send_wait", "poll_wait", "dl_pkt"
    };
    if (!getenv("IWAN_PUMP_PROF"))
        return;
    for (int i = 0; i < PUMP_PROF_N; i++) {
        if (ctx->prof[i].n == 0)
            continue;
        fprintf(stderr, "[pump-prof] %-10s n=%-10llu avg_us=%.3f total_ms=%.1f\n",
                names[i], (unsigned long long)ctx->prof[i].n,
                (double)ctx->prof[i].us / (double)ctx->prof[i].n,
                (double)ctx->prof[i].us / 1000.0);
    }
    fprintf(stderr,
            "[pump-prof] send-ctr  dgrams=%-8llu syscalls=%-8llu "
            "eagain=%-8llu\n",
            (unsigned long long)atomic_load(&g_prof_send_dgrams),
            (unsigned long long)atomic_load(&g_prof_send_syscalls),
            (unsigned long long)atomic_load(&g_prof_send_eagain));
    fprintf(stderr,
            "[pump-prof] recv-ctr  dgrams=%-8llu empty=%-8llu "
            "badtok=%-8llu\n",
            (unsigned long long)atomic_load(&g_prof_recv_dgrams),
            (unsigned long long)atomic_load(&g_prof_recv_empty),
            (unsigned long long)atomic_load(&g_prof_recv_badtok));
    fprintf(stderr,
            "[pump-prof] tun-rx    rmax=%-5u rbig=%-8llu rdrop=%-8llu\n",
            g_prof_tun_rmax,
            (unsigned long long)atomic_load(&g_prof_tun_rbig),
            (unsigned long long)atomic_load(&g_prof_tun_rdrop));
#ifdef _WIN32
    {
        unsigned long long wk =
            (unsigned long long)atomic_load(&g_tun_wakeups);
        unsigned long long pk =
            (unsigned long long)atomic_load(&g_tun_pkts);
        fprintf(stderr,
                "[pump-prof] tun-read  wait_ms=%-8llu drain_ms=%-7llu "
                "wake=%-8llu to=%-7llu pkts=%-9llu rpc=%.2f afail=%llu\n",
                (unsigned long long)atomic_load(&g_tun_wait_us) / 1000,
                (unsigned long long)atomic_load(&g_tun_drain_us) / 1000,
                wk,
                (unsigned long long)atomic_load(&g_tun_timeouts),
                pk,
                wk ? (double)pk / (double)wk : 0.0,
                (unsigned long long)atomic_load(&g_tun_allocfail));
    }
#endif
}

atomic_uint_fast64_t g_prof_pump_tx, g_prof_pump_rx;   /* [prof] tunnel bytes */

/* send one control frame on the shared socket. Must hold send_lock and
 * clear any lingering UDP_SEGMENT first: with GSO active and an mss
 * smaller than the frame, the kernel would split the 24-byte control
 * packet into several datagrams and the server would drop the corrupt
 * frame (same hazard send_batch documents for the per-message path). */
static int send_ctrl(pump_ctx_t *ctx, uint8_t typ, uint8_t enc, uint16_t sid,
                     uint32_t tok) {
    buf_t pkt;
    buf_init(&pkt);
    ctrl_hdr(&pkt, typ, enc, sid, tok);
    size_t want = pkt.len;
    pthread_mutex_lock(&ctx->send_lock);
    if (ctx->gso_mss != 0) {
        int z = 0;
        port_setsockopt(ctx->sockfd, SOL_UDP, UDP_SEGMENT, &z, sizeof z);
        ctx->gso_mss = 0;
    }
    ssize_t r = port_send(ctx->sockfd, pkt.data, want, 0);
    pthread_mutex_unlock(&ctx->send_lock);
    buf_free(&pkt);
    if (r < 0 || (size_t)r != want)
        return -1;
    return 0;
}

#define PUMP_BATCH 32
#define PUMP_SLOT  2048
#define PUMP_KEEPALIVE_MS 10000u
/* keepalive send must fail this many times in a row before the tunnel
 * is declared dead: a transient network blip (wifi roam, carrier
 * hiccup) must not kill the session, while a persistent failure means
 * the socket is gone */
#define PUMP_KA_FAIL_MAX 3
/* no downlink for this long => session lost: the server purged or
 * rebooted the session. Not all servers answer ECHO_REQ keepalives (a
 * live-but-silent session then produces no downlink at all), so the
 * threshold is overridable: IWAN_RX_STALE_MS (default 120s, 10s..24h).
 *
 * 120s (not 60s): the USTC servers answer every ECHO_REQ, so a long
 * downlink silence means the return path is dropping UDP, not that the
 * session died — and the 60s default caused spurious reconnects on the
 * mobile line (6 consecutive keepalives lost inside one window), which
 * the Rust reference client never exhibits (it has no downlink-stale
 * check at all). 120s = 12 consecutive unanswered keepalives. */
#define PUMP_RX_STALE_MS_DEFAULT 120000u

/* parsed once per process: the pump loop would otherwise re-run
 * getenv+strtoul on every iteration; 0 disables the watchdog (aligned
 * with the README contract and socks.c) */
static unsigned pump_rx_stale_ms(void)
{
    static unsigned cached;
    static int parsed;

    if (parsed)
        return cached;
    parsed = 1;
    cached = (unsigned)env_ms_range("IWAN_RX_STALE_MS",
                                    PUMP_RX_STALE_MS_DEFAULT, 10000,
                                    86400000, 1);
    return cached;
}
#define PUMP_POLL_CEIL_MS 1000  /* cap on the recvmmsg park timeout */
#define RX_BATCH 64             /* recvmmsg batch size (iov/msgs arrays) */
#define PUMP_SEND_RETRY_MS  5    /* EAGAIN/ENOBUFS retry budget per flush:
                                  * beyond it, yield to the receive path */

/* aggregate send-rate pacing: shared token bucket from util.h
 * (pace_bucket / pace_bucket_init / pace_take), same policy as socks.c.
 * The bucket is not thread-safe, so pace_take runs under send_lock. */

/* flush a TX batch after this much time instead of always waiting for it
 * to fill: bounds the added latency under sustained load (batch fill) */
#ifndef PUMP_MAX_LAT_US
#define PUMP_MAX_LAT_US 20
#endif

/* EAGAIN/ENOBUFS backpressure wait shared by the two TX paths: sleep
 * for the remaining retry budget (poll for writability; with the 5ms
 * budget the remaining-time cap always binds), then report whether the
 * budget is spent. Returns 1 when the caller should retry the send, 0
 * when it must give up and yield to the receive path (which drains the
 * socket and clears the backpressure). NOTE: mirrors the retry skeleton
 * of socks.c socks_send_batch2 — keep the two in sync. */
static int pump_send_retry(pump_ctx_t *ctx, uint64_t retry_t0)
{
    uint64_t el = now_ms() - retry_t0;
    if (el >= PUMP_SEND_RETRY_MS)
        return 0;
    struct pollfd pfd = { .fd = ctx->sockfd, .events = POLLOUT };
    port_poll(&pfd, 1, (int)(PUMP_SEND_RETRY_MS - el));
    return 1;
}

/* send a packet batch; retry partial sends and EAGAIN instead of dropping.
 * A full socket buffer backpressures the TUN read loop (kernel TCP then
 * throttles the app); only fatal errors stop the pump.
 * NOTE: structurally identical to socks.c socks_send_batch2 (GSO +
 * sendmmsg + EAGAIN budget) — keep the two in sync when changing retry
 * or pacing semantics. */
static void send_batch(pump_ctx_t *ctx, struct mmsghdr *msgs, unsigned n)
{
    unsigned sent = 0;
    uint64_t retry_t0 = now_ms();

    /* a lingering UDP_SEGMENT value would silently split any datagram
     * longer than the mss, so disable it before the per-message path */
    if (ctx->gso_mss != 0) {
        int z = 0;
        port_setsockopt(ctx->sockfd, SOL_UDP, UDP_SEGMENT, &z, sizeof z);
        ctx->gso_mss = 0;
    }

    while (sent < n && !g_stop) {
        atomic_fetch_add(&g_prof_send_syscalls, 1);
        uint64_t s0 = now_us();
        ssize_t sm = port_sendmmsg(ctx->sockfd, msgs + sent, n - sent, 0);
        pump_prof_add(&ctx->prof[PP_SEND_SYS], now_us() - s0);
        if (sm > 0) {
            sent += (unsigned)sm;
            continue;
        }
        if (sm == 0)
            return;   /* cannot happen for UDP; guard against a busy loop */
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ENOBUFS || errno == EPERM) {
            /* EPERM: netfilter OUTPUT DROP returns EPERM for the
             * dropped datagram — transient per-packet, retry like
             * EAGAIN. The wait lives in pump_send_retry: poll at most
             * the remaining retry budget (with the 5ms budget the
             * remaining time always binds), then stop retrying once it
             * is spent — an unbounded retry here wedges the pump, while
             * the receive thread (udp2tun) keeps draining the socket so
             * backpressure clears once we stop hammering it. poll()
             * already waited for writability, so no post-poll usleep. */
            atomic_fetch_add(&g_prof_send_eagain, 1);
            uint64_t r0 = now_us();
            int rv = pump_send_retry(ctx, retry_t0);
            pump_prof_add(&ctx->prof[PP_SEND_RETRY], now_us() - r0);
            if (!rv)
                return;
            continue;
        }
        err_printf("[TUN->UDP] sendmmsg: %s\n", strerror(errno));
        g_stop = 1;
        return;
    }
}

/* send one GSO unit: the kernel splits the (contiguous) payload into
 * mss-sized UDP datagrams at transmit time. Only used when every packet
 * in the batch has the same length, so segment boundaries coincide with
 * datagram boundaries and the wire output is identical to sendmmsg.
 * Same retry/backpressure semantics as send_batch.
 * NOTE: structurally identical to socks.c socks_send_batch2 (GSO +
 * sendmmsg + EAGAIN budget) — keep the two in sync when changing retry
 * or pacing semantics. */
static int send_gso(pump_ctx_t *ctx, struct iovec *iov, unsigned n,
                    size_t mss)
{
    size_t total = 0;
    uint64_t retry_t0 = now_ms();
    for (unsigned i = 0; i < n; i++)
        total += iov[i].iov_len;

    if (ctx->gso_ok == -1) {
        int m = (int)mss;
        /* port_setsockopt translates UDP_SEGMENT to WSAIoctl
         * (SIO_UDP_NETSEGMENT) on Windows and fails with EOPNOTSUPP on
         * older systems, so the sendmmsg fallback below works unchanged */
        ctx->gso_ok = port_setsockopt(ctx->sockfd, SOL_UDP, UDP_SEGMENT,
                                      &m, sizeof m) == 0;
        if (!ctx->gso_ok) {
            err_printf("[TUN->UDP] UDP_SEGMENT unsupported, using sendmmsg\n");
            return 0;
        }
        ctx->gso_mss = mss;
    } else if (ctx->gso_ok && ctx->gso_mss != mss) {
        /* re-arm a WORKING GSO socket for a new mss; once GSO is known
         * unavailable (e.g. SIO_UDP_NETSEGMENT rejected on Windows)
         * re-probing on every distinct batch size would just spam
         * WSAEOPNOTSUPP — stay on the sendmmsg fallback */
        int m = (int)mss;
        if (port_setsockopt(ctx->sockfd, SOL_UDP, UDP_SEGMENT, &m,
                            sizeof m) != 0) {
            ctx->gso_ok = 0;
            return 0;
        }
        ctx->gso_mss = mss;
    }
    if (!ctx->gso_ok)
        return 0;

    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = iov;
    mh.msg_iovlen = n;
    while (!g_stop) {
        atomic_fetch_add(&g_prof_send_syscalls, 1);
        uint64_t s0 = now_us();
        ssize_t r = port_sendmsg(ctx->sockfd, &mh, 0);
        pump_prof_add(&ctx->prof[PP_SEND_SYS], now_us() - s0);
        if (r == (ssize_t)total)
            return 1;
        if (r >= 0) {
            /* partial (unexpected for UDP GSO): skip what was sent */
            size_t skip = (size_t)r;
            while (n > 0 && skip >= iov[0].iov_len) {
                skip -= iov[0].iov_len;
                iov++;
                n--;
            }
            if (n == 0)
                return 1;
            if (skip > 0) {
                /* cannot resume mid-packet; drop the partial unit */
                return 1;
            }
            continue;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ENOBUFS || errno == EPERM) {
            /* EPERM: netfilter OUTPUT DROP returns EPERM for the
             * dropped datagram — transient per-packet, retry like
             * EAGAIN (same budget-bounded wait as send_batch: poll at
             * most the remaining retry budget, then yield to the
             * receive path) */
            atomic_fetch_add(&g_prof_send_eagain, 1);
            uint64_t r0 = now_us();
            int rv = pump_send_retry(ctx, retry_t0);
            pump_prof_add(&ctx->prof[PP_SEND_RETRY], now_us() - r0);
            if (!rv)
                return 1;   /* bounded: let the receive path drain */
            continue;
        }
        err_printf("[TUN->UDP] sendmsg GSO failed: %s; disabling "
                "UDP_SEGMENT\n", strerror(errno));
        /* a hard GSO error means the feature is unusable on this
         * socket, not that the tunnel died: disable it and fall back
         * to the per-message sendmmsg path (send_batch) for this batch
         * and all future ones */
        ctx->gso_ok = 0;
        ctx->gso_mss = 0;
        {
            int z = 0;
            port_setsockopt(ctx->sockfd, SOL_UDP, UDP_SEGMENT, &z,
                            sizeof z);
        }
        return 0;
    }
    return 1;
}

/* ---- uplink: one pool reader thread per queue, shared TX socket ----
 * The tun_pool hands each reader its own packet stream (kernel flow-hash
 * steering); packets are XOR'd into a thread-local batch and flushed to
 * the shared UDP socket under send_lock (UDP_SEGMENT and sendmmsg on one
 * socket must not interleave). On Windows a dedicated sender thread runs
 * the send syscalls (see pump_tx_send below); the batch is enqueued whole
 * so GSO batching is never fragmented across workers. */
typedef struct {
    uint8_t *batch;
    struct iovec iov[PUMP_BATCH];
    struct mmsghdr msgs[PUMP_BATCH];
    uint8_t hdr[8];
    unsigned n;
    uint64_t t0;
} pump_tx_t;

#ifdef _WIN32
/* one pool-owned batch buffer: filled by the wintun reader, sent by the
 * dedicated sender thread, then returned to the free list */
struct pump_tx_buf {
    struct pump_tx_buf *next;
    pump_tx_t tx;
};
#endif

static _Thread_local pump_tx_t g_tx;   /* Linux per-reader batch */

/* Build the msgs[] iovec entries and send one finished batch under
 * send_lock; GSO fast path when uniform. q->n is left untouched (the
 * caller/Linux path resets it, the Windows sender releases the buffer). */
static void pump_tx_send(pump_ctx_t *ctx, pump_tx_t *q)
{
    unsigned n = q->n;
    if (n == 0)
        return;
    atomic_fetch_add(&g_prof_send_dgrams, n);
    for (unsigned i = 0; i < n; i++) {
        q->msgs[i].msg_hdr.msg_iov = &q->iov[i];
        q->msgs[i].msg_hdr.msg_iovlen = 1;
    }
    /* GSO fast path: uniform batch -> one sendmsg, kernel segments;
     * wire output is identical because segment boundaries align with
     * the (equal) datagram boundaries. Falls back to sendmmsg when
     * UDP_SEGMENT is unavailable or sizes differ. */
    int use_gso = 0;
    if (n >= 2) {
        size_t l0 = q->iov[0].iov_len;
        int uniform = 1;
        for (unsigned i = 1; i < n; i++) {
            if (q->iov[i].iov_len != l0) {
                uniform = 0;
                break;
            }
        }
        /* a GSO unit's total length must fit the 16-bit UDP length
         * field AND stay under the loopback-safe ceiling (software GSO
         * drops larger units on some kernels); oversized (jumbo) batches
         * fall back to sendmmsg. The mss floor keeps the armed unit
         * above every non-batch frame on the socket (control 24B,
         * tunnel-DNS <= 307B): while UDP_SEGMENT is armed the kernel
         * splits any longer datagram (see IWAN_GSO_MSS_MIN). */
        use_gso = uniform && l0 >= IWAN_GSO_MSS_MIN &&
                  (size_t)n * l0 <= IWAN_UDP_GSO_UNIT &&
                  (size_t)n * l0 <= IWAN_GSO_UNIT_SAFE;
    }
    uint64_t t0 = now_us();
    pthread_mutex_lock(&ctx->send_lock);
    if (use_gso && send_gso(ctx, q->iov, n, q->iov[0].iov_len) == 0)
        use_gso = 0;   /* UDP_SEGMENT unavailable: fall back */
    if (!use_gso)
        send_batch(ctx, q->msgs, n);
    /* aggregate send pacing (util.h). MUST hold send_lock: multiple
     * reader threads share the bucket, which is not thread-safe; the
     * pacing sleep under the lock is exactly the aggregate-pacing
     * semantic (see util.h pace_bucket). */
    {
        uint64_t p0 = now_us();
        pace_take(&ctx->pace, (int)n);
        pump_prof_add(&ctx->prof[PP_SEND_PACE], now_us() - p0);
    }
    pthread_mutex_unlock(&ctx->send_lock);
    pump_prof_add(&ctx->prof[PP_SEND], now_us() - t0);
}

#ifndef _WIN32
/* flush one batch to the socket inline (Linux: the reader thread owns
 * the thread-local batch and there is no dedicated sender) */
static void pump_flush(pump_ctx_t *ctx, pump_tx_t *q)
{
    unsigned n = q->n;
    if (n == 0)
        return;
    pump_tx_send(ctx, q);
    q->n = 0;
}

/* tun_pool callback: one thread-local batch per reader thread */
static void pump_tun_pkt(void *ud, uint8_t *pkt, size_t len, bool last)
{
    pump_ctx_t *ctx = ud;
    pump_tx_t *q = &g_tx;

    if (last) {
        /* queue drained: send the partial batch instead of holding it */
        if (q->n > 0)
            pump_flush(ctx, q);
        return;
    }
    /* slot size 8+PUMP_SLOT is a hard boundary: a zero-length or
     * oversized inner packet must never be copied into the batch
     * buffer, or it would clobber the adjacent slot (heap overflow).
     * The pool's last=true flush signal carries len==0, so this check
     * lives after the drain path above. */
    if (len == 0 || len > PUMP_SLOT) {
        log_debug("pump: drop packet, len %zu out of [1, %d]", len,
                  PUMP_SLOT);
        return;
    }
    if (q->n == 0) {
        if (!q->batch) {
            /* one slot per packet: 8-byte iWAN header followed by the
             * (XOR'd) payload, contiguous and 8-byte aligned, so the
             * final wire packet is a single iovec with no assembly */
            const size_t slot = 8 + PUMP_SLOT;
            q->batch = malloc((size_t)PUMP_BATCH * slot);
            if (!q->batch) {
                log_err("out of memory");
                g_stop = 1;
                return;
            }
            memset(q->msgs, 0, sizeof q->msgs);
            pkt_hdr(ctx->enc ? PT_DATA_ENC : PT_DATA, ctx->enc, ctx->sid,
                    ctx->tok, q->hdr);
        }
        q->t0 = now_us();   /* first packet of this batch */
    }
    if (g_stop)
        return;
    {
        const size_t slot = 8 + PUMP_SLOT;
        uint8_t *s = q->batch + (size_t)q->n * slot;
        uint64_t t0 = now_us();
        memcpy(s, q->hdr, 8);
        memcpy(s + 8, pkt, len);   /* pool hands over its scratch buffer */
        xor_crypt(s + 8, len, ctx->xor_key, 8);
        pump_prof_add(&ctx->prof[PP_COPY_XOR], now_us() - t0);
        PROF_ADD(g_prof_pump_tx, len);
        q->iov[q->n].iov_base = s;
        q->iov[q->n].iov_len = len + 8;
        q->n++;
    }
    /* latency cap: under sustained load, stop filling this batch after
     * PUMP_MAX_LAT_US so no packet waits a full batch (32 x
     * inter-arrival) before being sent */
    if (q->n == PUMP_BATCH || now_us() - q->t0 >= PUMP_MAX_LAT_US)
        pump_flush(ctx, q);
}
#else /* _WIN32 */

/* ---------- dedicated UDP sender thread (SPSC) ---------- */
/* Strictly one producer (wintun reader) and one consumer (sender):
 * two pointer rings + counting semaphores, no mutex/cond on the hot
 * path. The pool has 4 batch buffers and the rings hold 16 slots, so
 * the ready ring can never fill (pool < ring capacity). */
static inline int pump_spsc_push(pump_spsc_ring_t *r,
                                 struct pump_tx_buf *b)
{
    unsigned t = r->tail;
    unsigned next = (t + 1) & r->mask;
    if (next == r->head)   /* full */
        return 0;
    r->slots[t] = b;
    __sync_synchronize();   /* release: slot before tail */
    r->tail = next;
    return 1;
}

static inline struct pump_tx_buf *pump_spsc_pop(pump_spsc_ring_t *r)
{
    unsigned h = r->head;
    if (h == r->tail)
        return NULL;
    struct pump_tx_buf *b = r->slots[h];
    __sync_synchronize();   /* acquire: slot before head */
    r->head = (h + 1) & r->mask;
    return b;
}

static struct pump_tx_buf *pump_tx_acquire(pump_ctx_t *ctx)
{
    WaitForSingleObject(ctx->free_sem, INFINITE);
    return pump_spsc_pop(&ctx->free_ring);
}

static void pump_tx_release(pump_ctx_t *ctx, struct pump_tx_buf *b)
{
    b->tx.n = 0;
    pump_spsc_push(&ctx->free_ring, b);
    ReleaseSemaphore(ctx->free_sem, 1, NULL);
}

static int pump_tx_enqueue(pump_ctx_t *ctx, struct pump_tx_buf *b)
{
    if (!pump_spsc_push(&ctx->ready_ring, b))
        return -1;   /* cannot happen: pool(4) < ring cap(16) */
    ReleaseSemaphore(ctx->ready_sem, 1, NULL);
    return 0;
}

static struct pump_tx_buf *pump_tx_dequeue(pump_ctx_t *ctx)
{
    for (;;) {
        if (ctx->sender_stop) {
            /* stop requested: drain whatever is left, then exit */
            return pump_spsc_pop(&ctx->ready_ring);
        }
        uint64_t w0 = now_us();
        WaitForSingleObject(ctx->ready_sem, INFINITE);
        pump_prof_add(&ctx->prof[PP_SENDWAIT], now_us() - w0);
        struct pump_tx_buf *b = pump_spsc_pop(&ctx->ready_ring);
        if (b != NULL)
            return b;
        /* spurious token (stop wake): loop */
    }
}

/* reader finished a batch: hand it to the sender thread whole */
static void pump_flush_w(pump_ctx_t *ctx, struct pump_tx_buf *b)
{
    if (b->tx.n == 0) {
        pump_tx_release(ctx, b);
        return;
    }
    uint64_t t0 = now_us();
    if (pump_tx_enqueue(ctx, b) != 0)
        pump_tx_release(ctx, b);
    pump_prof_add(&ctx->prof[PP_ENQ], now_us() - t0);
}

/* tun_pool callback on Windows: the (single) wintun reader fills a batch
 * buffer from the pool, then hands the whole batch to the sender thread */
static void pump_tun_pkt(void *ud, uint8_t *pkt, size_t len, bool last)
{
    pump_ctx_t *ctx = ud;

    if (last) {
        if (ctx->cur_buf != NULL && ctx->cur_buf->tx.n > 0)
            pump_flush_w(ctx, ctx->cur_buf);
        ctx->cur_buf = NULL;
        return;
    }
    if (len > (uint32_t)g_prof_tun_rmax)
        g_prof_tun_rmax = (uint32_t)len;   /* single reader thread */
    if (len > 1508)
        atomic_fetch_add(&g_prof_tun_rbig, 1);
    if (len == 0 || len > PUMP_SLOT) {
        if (len > PUMP_SLOT)
            atomic_fetch_add(&g_prof_tun_rdrop, 1);
        log_debug("pump: drop packet, len %zu out of [1, %d]", len,
                  PUMP_SLOT);
        return;
    }
    if (ctx->cur_buf == NULL) {
        ctx->cur_buf = pump_tx_acquire(ctx);
        if (ctx->cur_buf == NULL)
            return;   /* stopped */
        ctx->cur_buf->tx.n = 0;
        ctx->cur_buf->tx.t0 = now_us();
    }
    pump_tx_t *q = &ctx->cur_buf->tx;
    if (g_stop)
        return;
    {
        const size_t slot = 8 + PUMP_SLOT;
        uint8_t *s = q->batch + (size_t)q->n * slot;
        uint64_t t0 = now_us();
        memcpy(s, q->hdr, 8);
        memcpy(s + 8, pkt, len);   /* wintun scratch, copied out */
        xor_crypt(s + 8, len, ctx->xor_key, 8);
        pump_prof_add(&ctx->prof[PP_COPY_XOR], now_us() - t0);
        PROF_ADD(g_prof_pump_tx, len);
        q->iov[q->n].iov_base = s;
        q->iov[q->n].iov_len = len + 8;
        q->n++;
    }
    if (q->n == PUMP_BATCH || now_us() - q->t0 >= PUMP_MAX_LAT_US) {
        pump_flush_w(ctx, ctx->cur_buf);
        ctx->cur_buf = NULL;
    }
}

static void pump_sender_free(pump_ctx_t *ctx);   /* fwd: used by start's err path */

static void *pump_sender_main(void *ud)
{
    pump_ctx_t *ctx = ud;
    for (;;) {
        struct pump_tx_buf *b = pump_tx_dequeue(ctx);
        if (b == NULL)
            break;   /* stopped and drained */
        pump_tx_send(ctx, &b->tx);
        pump_tx_release(ctx, b);
    }
    return NULL;
}

static int pump_sender_start(pump_ctx_t *ctx)
{
    int pooln = (int)(sizeof ctx->tx_pool / sizeof ctx->tx_pool[0]);
    const size_t slot = 8 + PUMP_SLOT;

    ctx->free_ring.head = 0;
    ctx->free_ring.tail = 0;
    ctx->free_ring.mask = PUMP_SPSC_CAP - 1;
    ctx->ready_ring.head = 0;
    ctx->ready_ring.tail = 0;
    ctx->ready_ring.mask = PUMP_SPSC_CAP - 1;
    ctx->cur_buf = NULL;
    ctx->sender_stop = 0;

    ctx->free_sem = CreateSemaphore(NULL, 0, PUMP_SPSC_CAP, NULL);
    ctx->ready_sem = CreateSemaphore(NULL, 0, PUMP_SPSC_CAP, NULL);
    if (ctx->free_sem == NULL || ctx->ready_sem == NULL)
        goto err;

    for (int i = 0; i < pooln; i++) {
        struct pump_tx_buf *b = calloc(1, sizeof *b);
        if (b == NULL)
            goto err;
        b->tx.batch = malloc((size_t)PUMP_BATCH * slot);
        if (b->tx.batch == NULL) {
            free(b);
            goto err;
        }
        memset(b->tx.msgs, 0, sizeof b->tx.msgs);
        pkt_hdr(ctx->enc ? PT_DATA_ENC : PT_DATA, ctx->enc, ctx->sid,
                ctx->tok, b->tx.hdr);
        ctx->tx_pool[i] = b;
        pump_spsc_push(&ctx->free_ring, b);
        ReleaseSemaphore(ctx->free_sem, 1, NULL);
    }
    if (pthread_create(&ctx->sender_thread, NULL, pump_sender_main, ctx) != 0)
        goto err;
    return 0;
err:
    pump_sender_free(ctx);
    return -1;
}

static void pump_sender_stop(pump_ctx_t *ctx)
{
    ctx->sender_stop = 1;
    ReleaseSemaphore(ctx->ready_sem, 1, NULL);   /* wake if blocked */
    pthread_join(ctx->sender_thread, NULL);
}

static void pump_sender_free(pump_ctx_t *ctx)
{
    int pooln = (int)(sizeof ctx->tx_pool / sizeof ctx->tx_pool[0]);
    for (int i = 0; i < pooln; i++) {
        if (ctx->tx_pool[i] != NULL) {
            free(ctx->tx_pool[i]->tx.batch);
            free(ctx->tx_pool[i]);
            ctx->tx_pool[i] = NULL;
        }
    }
    if (ctx->free_sem != NULL) {
        CloseHandle(ctx->free_sem);
        ctx->free_sem = NULL;
    }
    if (ctx->ready_sem != NULL) {
        CloseHandle(ctx->ready_sem);
        ctx->ready_sem = NULL;
    }
}
#endif /* _WIN32 */


/* Free this reader thread's TLS batch on thread exit (registered via
 * tun_pool_set_exit_cb). Runs on the exiting reader thread itself, so
 * the g_tx access is genuinely thread-local; tun.c invokes it strictly
 * after the final flush callback, so no pending pump_flush can touch
 * the freed buffer. (Windows: g_tx is unused, this is a no-op.) */
static void pump_reader_exit(void)
{
    if (g_tx.batch) {
        free(g_tx.batch);
        g_tx.batch = NULL;
    }
    g_tx.n = 0;
}

static void *udp2tun_thread(void *ud) {
    pump_ctx_t *ctx = ud;
#ifndef _WIN32
#  ifdef __APPLE__
    pthread_setname_np("udp2tun");
#  else
    pthread_setname_np(pthread_self(), "udp2tun");
#  endif
#endif
    /* recvmmsg with MSG_DONTWAIT drains whatever is queued (zero latency
     * tail), then poll() parks until data or the keepalive deadline.
     * A non-NULL timeout argument must NOT be passed to recvmmsg: the
     * kernel checks it only after the first datagram and it never bounds
     * the first-message wait (documented bug). */
    const size_t slot = 8 + PUMP_SLOT;
    const int rxbatch = RX_BATCH;
    uint8_t *batch = malloc((size_t)rxbatch * slot);
    struct iovec iov[RX_BATCH];
    struct mmsghdr msgs[RX_BATCH];
    uint64_t last_ka = now_ms() > PUMP_KEEPALIVE_MS
                           ? now_ms() - PUMP_KEEPALIVE_MS
                           : 0;
    uint64_t last_rx = now_ms();   /* any downlink resets the stale clock */
    int ka_fail = 0;
    int i;

    if (!batch) {
        log_err("out of memory");
        ctx->session_lost = true;   /* abnormal exit: let the caller
                                     * re-auth instead of silently
                                     * reporting "user stopped" */
        g_stop = 1;   /* the downlink thread is dead: stop the pump */
        return NULL;
    }
    memset(msgs, 0, sizeof msgs);   /* msg_name/msg_control must be NULL */
    for (i = 0; i < rxbatch; i++) {
        iov[i].iov_base = batch + (size_t)i * slot;
        iov[i].iov_len = slot;
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    while (!g_stop) {
        uint64_t now = now_ms();
        if (pump_rx_stale_ms() != 0 && now - last_rx > pump_rx_stale_ms()) {
            /* the server answers our ECHO_REQ keepalives, so a live
             * session always produces downlink within ~10s; 60s of
             * silence means the session is gone (server purge/reboot)
             * even if the socket itself still sends */
            log_err("[UDP->TUN] no downlink for %llu ms; session lost",
                    (unsigned long long)(now - last_rx));
            ctx->session_lost = true;
            g_stop = 1;
            break;
        }
        if (now >= last_ka + PUMP_KEEPALIVE_MS) {
            if (send_ctrl(ctx, PT_ECHO_REQ, ctx->enc, ctx->sid,
                          ctx->tok) != 0) {
                int e = errno;
                /* transient errors (roaming, carrier hiccup) recover;
                 * only repeated failures declare the socket dead */
                if (++ka_fail >= PUMP_KA_FAIL_MAX) {
                    log_err("[UDP->TUN] keepalive send err: %s (%d "
                            "consecutive); session lost",
                            strerror(e), ka_fail);
                    ctx->session_lost = true;
                    g_stop = 1;
                    break;
                }
                err_printf("[UDP->TUN] keepalive send err: %s (retry "
                        "%d/%d)\n", strerror(e), ka_fail,
                        PUMP_KA_FAIL_MAX);
            } else {
                ka_fail = 0;
            }
            last_ka = now_ms();
        }
        uint64_t t_recv = now_us();
        int v = port_recvmmsg(ctx->sockfd, msgs, (unsigned)rxbatch,
                              MSG_DONTWAIT, NULL);
        pump_prof_add(&ctx->prof[PP_RECV], now_us() - t_recv);
        if (v > 0)
            atomic_fetch_add(&g_prof_recv_dgrams, (uint64_t)v);
        if (v < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                atomic_fetch_add(&g_prof_recv_empty, 1);
                uint64_t ka_ms = last_ka + PUMP_KEEPALIVE_MS;
                uint64_t now_msv = now_ms();
                int to = ka_ms > now_msv ? (int)(ka_ms - now_msv) : 1;
                if (to > PUMP_POLL_CEIL_MS)
                    to = PUMP_POLL_CEIL_MS;
                struct pollfd pfd = { .fd = ctx->sockfd, .events = POLLIN };
                uint64_t pw0 = now_us();
                int pr = port_poll(&pfd, 1, to);
                pump_prof_add(&ctx->prof[PP_POLLWAIT], now_us() - pw0);
                if (pr < 0 && errno != EINTR) {
                    err_printf("[UDP->TUN] poll err\n");
                    ctx->session_lost = true;   /* abnormal: reconnect */
                    g_stop = 1;   /* any pump-fatal error stops the tunnel */
                    break;
                }
                continue;
            }
            if (errno == EINTR || errno == ECONNREFUSED)
                continue;   /* EINTR: signal; ECONNREFUSED: one-shot
                             * connected-UDP ICMP artifact (Linux side;
                             * Windows is silenced via SIO_UDP_CONNRESET)
                             * — the keepalive logic detects real loss */
            log_err("[UDP->TUN] recv err: %s (%d)", strerror(errno),
                    errno);
            ctx->session_lost = true;   /* abnormal: reconnect */
            g_stop = 1;   /* any pump-fatal error stops the tunnel */
            break;
        }
        last_rx = now_ms();   /* any datagram resets the stale clock */
        {
            static struct prof_state pst_rx, pst_tx;
            if (prof_print("cli rx", &pst_rx, g_prof_pump_rx))
                prof_print("cli tx", &pst_tx, g_prof_pump_tx);
        }
        uint64_t dl0 = now_us();
        for (i = 0; i < v; i++) {
            ssize_t n = msgs[i].msg_len;
            uint8_t *m = batch + (size_t)i * slot;
            if (n < 8 || (msgs[i].msg_hdr.msg_flags & MSG_TRUNC))
                continue;
            uint8_t t = m[0];
            uint16_t psid = (uint16_t)((m[2] << 8) | m[3]);
            uint32_t ptok = ((uint32_t)m[4] << 24) | ((uint32_t)m[5] << 16) |
                            ((uint32_t)m[6] << 8) | (uint32_t)m[7];
            /* mirror receive_vpn: sid/token must match BEFORE any
             * control action — an unauthenticated PT_CLOSE must not be
             * able to tear the tunnel down */
            if (psid != ctx->sid || ptok != ctx->tok) {
                atomic_fetch_add(&g_prof_recv_badtok, 1);
                continue;
            }
            if (t == PT_CLOSE) {
                /* control packets carry the 16-byte header sig */
                if (!verify_sig(m, (size_t)n))
                    continue;
                log_err("[UDP->TUN] server sent CLOSE");
                ctx->session_lost = true;   /* re-auth + re-run */
                g_stop = 1;
                break;
            }
            if (t == PT_ECHO_REQ) {
                if (!verify_sig(m, (size_t)n))
                    continue;
                if (send_ctrl(ctx, PT_ECHO_RES, ctx->enc, ctx->sid,
                              ctx->tok) != 0) {
                    log_err("[UDP->TUN] keepalive response err: %s",
                            strerror(errno));
                    ctx->session_lost = true;
                    g_stop = 1;
                    break;
                }
                continue;
            }
            if (t != PT_DATA && t != PT_DATA_ENC)
                continue;
            if (t == PT_DATA && ctx->enc) {
                err_printf("[UDP->TUN] plaintext data on encrypted session, drop\n");
                continue;
            }
            if (t == PT_DATA_ENC)
                xor_crypt(m + 8, (size_t)(n - 8), ctx->xor_key, 8);
            PROF_ADD(g_prof_pump_rx, (size_t)(n - 8));
            /* validate the inner IPv4 packet before injecting it into the
             * TUN device (same gate as the SOCKS path): a malformed frame
             * must not reach the kernel stack */
            uint32_t saddr, daddr;
            if (ipv4_pkt_ok(m + 8, (size_t)(n - 8), &saddr, &daddr) != 0) {
                log_debug("drop inner packet: bad IPv4 header (%zu bytes)",
                          (size_t)(n - 8));
                continue;
            }
            /* write with unbounded EAGAIN retry: silent loss here costs
             * inner TCP retransmits */
            uint64_t tw0 = now_us();
            int wr = tun_write_retry(ctx->tun_fd, m + 8, (size_t)(n - 8), 0,
                                     &g_stop);
            pump_prof_add(&ctx->prof[PP_TUNWRITE], now_us() - tw0);
            if (wr != 0) {
                if (!g_stop)
                    log_err("tun write: %s", strerror(errno));
                /* device gone (ENODEV/EIO): the session is unrecoverable
                 * from this end too — reconnect (rc=1) rather than
                 * reporting a clean user stop */
                ctx->session_lost = true;
                g_stop = 1;
                break;
            }
        }
        pump_prof_add(&ctx->prof[PP_DLPKT], now_us() - dl0);
    }
    free(batch);
    return NULL;
}

static void on_signal(int sig) {
    if (sig == SIGINT)
        err_printf("\nSIGINT -- shutting down...\n");
    g_stop = 1;
    g_user_stop = 1;
}

static void install_signals(void) {
    /* process-wide stop handler: SIGINT/SIGTERM/SIGHUP via sigaction on
     * POSIX, console ctrl events (normalized to SIGINT) on Windows.
     * No save/restore — the old code installed with NULL oldact, and
     * the handler lives for the process lifetime either way. */
    port_set_stop_handler(on_signal);
}

static bool slist_has(const slist_t *s, const char *str) {
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->v[i], str) == 0)
            return true;
    return false;
}

static void push_unique(slist_t *s, const char *str) {
    if (!slist_has(s, str))
        slist_push(s, str);
}

static int expand_route_targets(const slist_t *targets, slist_t *out) {
    if (targets == NULL)
        return 0;
    for (size_t i = 0; i < targets->n; i++) {
        const char *raw = targets->v[i];
        char *t = xstrdup(raw == NULL ? "" : raw);
        char *p = t;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        size_t l = strlen(p);
        while (l > 0 && (p[l - 1] == ' ' || p[l - 1] == '\t' ||
                         p[l - 1] == '\r' || p[l - 1] == '\n'))
            p[--l] = '\0';
        if (*p == '\0') {
            free(t);
            continue;
        }
        if (strcmp(p, "default") == 0) {
            push_unique(out, p);
        } else if (strchr(p, '/') != NULL) {
            /* --proxy-cidr entries must be well-formed A.B.C.D/n; a bad
             * prefix used to reach `ip route` verbatim and fail silently,
             * so reject it here instead */
            uint32_t net;
            int prefix;
            if (cidr_parse(p, &net, &prefix) != 0) {
                log_err("invalid CIDR route target '%s'", p);
                free(t);
                return -1;
            }
            push_unique(out, p);
        } else {
            struct in_addr a4;
            if (inet_pton(AF_INET, p, &a4) == 1) {
                char r32[64];
                snprintf(r32, sizeof r32, "%s/32", p);
                push_unique(out, r32);
            } else {
                struct addrinfo hints;
                memset(&hints, 0, sizeof hints);
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                struct addrinfo *res = NULL;
                int rc = getaddrinfo(p, NULL, &hints, &res);
                if (rc != 0) {
                    log_err("resolve domain %s: %s", p, gai_strerror(rc));
                    free(t);
                    return -1;
                }
                int found = 0;
                for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
                    if (ai->ai_family != AF_INET)
                        continue;
                    char ip[INET_ADDRSTRLEN];
                    const struct sockaddr_in *sin =
                        (const struct sockaddr_in *)ai->ai_addr;
                    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip);
                    char r32[64];
                    snprintf(r32, sizeof r32, "%s/32", ip);
                    push_unique(out, r32);
                    found = 1;
                }
                freeaddrinfo(res);
                if (!found) {
                    log_err("domain has no IPv4 address: %s", p);
                    free(t);
                    return -1;
                }
            }
        }
        free(t);
    }
    return 0;
}

/* IPv6 route targets: "<v6-cidr>" or a bare IPv6 address (-> /128), or
 * a domain resolved AF_INET6 (-> /128 per address). Returns 0 on
 * success, -1 on a malformed target (rejected before it reaches
 * `ip -6 route` verbatim). */
static int expand_route_targets6(const slist_t *targets, slist_t *out)
{
    if (targets == NULL)
        return 0;
    for (size_t i = 0; i < targets->n; i++) {
        const char *p = targets->v[i];
        char *t = xstrdup(p == NULL ? "" : p);
        char *q = t;
        while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')
            q++;
        size_t l = strlen(q);
        while (l > 0 && (q[l - 1] == ' ' || q[l - 1] == '\t' ||
                         q[l - 1] == '\r' || q[l - 1] == '\n'))
            q[--l] = '\0';
        if (*q == '\0') {
            free(t);
            continue;
        }
        if (strchr(q, '/') != NULL) {
            char addr[64];
            size_t an = (size_t)(strchr(q, '/') - q);
            long plen;
            char *end;
            if (an == 0 || an >= sizeof addr) {
                log_err("invalid IPv6 CIDR route target '%s'", q);
                free(t);
                return -1;
            }
            memcpy(addr, q, an);
            addr[an] = '\0';
            struct in6_addr a6;
            if (inet_pton(AF_INET6, addr, &a6) != 1) {
                log_err("invalid IPv6 CIDR route target '%s'", q);
                free(t);
                return -1;
            }
            plen = strtol(q + an + 1, &end, 10);
            if (*end != '\0' || plen < 0 || plen > 128) {
                log_err("invalid IPv6 CIDR route target '%s'", q);
                free(t);
                return -1;
            }
            push_unique(out, q);
        } else {
            struct in6_addr a6;
            if (inet_pton(AF_INET6, q, &a6) == 1) {
                char r128[64];
                snprintf(r128, sizeof r128, "%s/128", q);
                push_unique(out, r128);
            } else {
                /* domain: resolve AF_INET6 */
                struct addrinfo hints;
                memset(&hints, 0, sizeof hints);
                hints.ai_family = AF_INET6;
                hints.ai_socktype = SOCK_STREAM;
                struct addrinfo *res = NULL;
                int rc = getaddrinfo(q, NULL, &hints, &res);
                if (rc != 0) {
                    log_err("resolve domain %s: %s", q, gai_strerror(rc));
                    free(t);
                    return -1;
                }
                int found = 0;
                for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
                    if (ai->ai_family != AF_INET6)
                        continue;
                    char ip[INET6_ADDRSTRLEN];
                    const struct sockaddr_in6 *s6 =
                        (const struct sockaddr_in6 *)ai->ai_addr;
                    inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof ip);
                    char r128[64];
                    /* precision cap: inet_ntop emits at most 45 visible
                     * chars, and mingw -Wformat-truncation cannot bound
                     * a bare %s here (45+4=49 < 64 is provable) */
                    snprintf(r128, sizeof r128, "%.45s/128", ip);
                    push_unique(out, r128);
                    found = 1;
                }
                freeaddrinfo(res);
                if (!found) {
                    log_err("domain has no IPv6 address: %s", q);
                    free(t);
                    return -1;
                }
            }
        }
        free(t);
    }
    return 0;
}

static void teardown_routes(const char *tun, const char *tun_ip,
                            const char *srv, const char *ogw,
                            const char *odev, const char *ogw_metric,
                            const slist_t *routes, bool had_routes,
                            const slist_t *routes6) {
    route_teardown6(tun, tun_ip, routes6);
    if (had_routes) {
        route_teardown(tun, srv, ogw, odev, ogw_metric, routes);
    } else {
        route_iface_down(tun);
    }
}

int run_pump(int tun_fd, const char *tun_name, int sockfd,
             const uint8_t xor_key[8], uint16_t sid, uint32_t tok, uint8_t enc,
             const char *server, const slist_t *route_targets,
             const slist_t *route_targets6,
             const char *auth_tun_ip, uint16_t auth_mtu) {
    char ogw[16] = "", odev[16] = "", ogw_metric[16] = "";

    slist_t routes;
    slist_init(&routes);
    if (expand_route_targets(route_targets, &routes) != 0) {
        slist_free(&routes);
        return -1;
    }
    slist_t routes6;
    slist_init(&routes6);
    if (expand_route_targets6(route_targets6, &routes6) != 0) {
        slist_free(&routes);
        slist_free(&routes6);
        return -1;
    }

    bool had_routes = routes.n > 0;
    if (had_routes) {
        /* the default route is only needed when the tunnel hijacks it;
         * a pure-TUN run (no route targets) must not require one */
        if (!capture_default(ogw, odev, ogw_metric)) {
            log_err("cannot detect default route");
            slist_free(&routes);
            return -1;
        }
        log_debug("default route: via %s dev %s%s%s", ogw, odev,
                  ogw_metric[0] ? " metric " : "", ogw_metric);
        if (!route_setup(tun_name, auth_tun_ip, auth_mtu, server, ogw, odev,
                         ogw_metric, &routes)) {
            /* route_setup already rolled back and logged; a half-configured
             * tunnel must not start pumping */
            slist_free(&routes);
            slist_free(&routes6);
            return -1;
        }
        log_info("tun %s ready: %zu route%s", tun_name, routes.n,
                 routes.n == 1 ? "" : "s");
        for (size_t i = 0; i < routes.n; i++)
            log_debug("route %s -> dev %s", routes.v[i], tun_name);
    } else {
        if (!route_iface_up(tun_name, auth_tun_ip, auth_mtu)) {
            /* address/MTU assignment failed: undo the partial bring-up
             * instead of claiming the tunnel is up */
            route_iface_down(tun_name);
            slist_free(&routes);
            slist_free(&routes6);
            return -1;
        }
        log_info("tun %s up with IP %s/24 (no route hijack)", tun_name,
                 auth_tun_ip);
    }
    /* IPv6 policy routes through the tunnel (best-effort; the derived
     * ULA/96 on the interface was added by route_iface_up) */
    if (routes6.n > 0) {
        route_setup6(tun_name, &routes6);
        for (size_t i = 0; i < routes6.n; i++)
            log_debug("route6 %s -> dev %s", routes6.v[i], tun_name);
    }

    g_stop = 0;
    install_signals();

    pump_ctx_t ctx;
    memset(ctx.prof, 0, sizeof ctx.prof);
    ctx.tun_fd = tun_fd;
    ctx.sockfd = sockfd;
    ctx.sid = sid;
    ctx.tok = tok;
    ctx.enc = enc;
    ctx.gso_mss = 0;
    ctx.gso_ok = -1;
    memcpy(ctx.xor_key, xor_key, 8);
    pthread_mutex_init(&ctx.send_lock, NULL);
    pace_bucket_init(&ctx.pace);
#ifdef _WIN32
    int sender_started = 0;
    /* The wintun reader may start producing the moment the pool is
     * created, so the sender queue/pool must exist first. */
    if (pump_sender_start(&ctx) != 0) {
        log_err("cannot start TUN UDP sender thread");
        g_stop = 1;
        goto fail;
    }
    sender_started = 1;
    log_info("TUN UDP sender thread started");
#endif

    {
        /* multiqueue uplink: attach min(ncpu, TUN_POOL_MAX) queues up
         * front. No AIMD here: the bulk uplink load sits between the
         * single-queue and multi-queue capacities, which makes the
         * adaptive pool hunt 1<->2 queues instead of scaling.
         * IWAN_PUMP_QUEUES overrides the count for testing. */
        long ncpu = port_cpu_count();
        int maxq = TUN_POOL_MAX;
        if (ncpu > 0 && ncpu < maxq)
            maxq = (int)ncpu;
        const char *qv = getenv("IWAN_PUMP_QUEUES");
        if (qv) {
            long qn = strtol(qv, NULL, 10);
            if (qn > 0 && qn <= TUN_POOL_MAX)
                maxq = (int)qn;
        }
        ctx.pool = tun_pool_create(tun_name, tun_fd, maxq, maxq,
                                   pump_tun_pkt, &ctx, &g_stop);
        if (!ctx.pool) {
            log_err("cannot start TUN reader pool");
            goto fail;
        }
        /* each reader thread frees its TLS batch on exit (tun.c invokes
         * this on the exiting thread, after the final flush) */
        tun_pool_set_exit_cb(ctx.pool, pump_reader_exit);
        log_info("TUN reader pool: %d queues",
                 tun_pool_queues(ctx.pool));
    }
    if (tun_steering_attach(tun_fd) == 0)
        log_info("tun steering: eBPF flow hash attached");
    else
        log_debug("tun steering: eBPF unavailable, kernel automq");

    pthread_t t2;
    if (pthread_create(&t2, NULL, udp2tun_thread, &ctx) != 0) {
        g_stop = 1;
        tun_pool_destroy(ctx.pool);
        goto fail;
    }

    log_info("TUN proxy running -- press Ctrl-C to stop");
    {
        uint64_t prof_last = now_ms();
        while (!g_stop) {
            port_sleep_us(100 * 1000);
            uint64_t nm = now_ms();
            if (getenv("IWAN_PUMP_PROF") && nm - prof_last >= 1000) {
                pump_prof_print(&ctx);
                prof_last = nm;
            }
        }
    }

#ifdef _WIN32
    tun_pool_destroy(ctx.pool);   /* stop the wintun reader first */
    pump_sender_stop(&ctx);       /* then drain + stop the sender */
#else
    tun_pool_destroy(ctx.pool);
#endif
    pthread_join(t2, NULL);
#ifdef _WIN32
    pump_sender_free(&ctx);
#endif

    teardown_routes(tun_name, auth_tun_ip, server, ogw, odev,
                    ogw_metric, &routes, had_routes, &routes6);

    send_ctrl(&ctx, PT_CLOSE, enc, sid, tok);
    if (debug_enabled())
        err_printf("CLOSE sent\n");

    pump_prof_print(&ctx);
    pthread_mutex_destroy(&ctx.send_lock);
    slist_free(&routes);
    slist_free(&routes6);
    /* 1 = session lost (keepalive failures / no downlink): the caller
     * may re-authenticate and re-run the pump; 0 = user stopped it */
    return ctx.session_lost ? 1 : 0;

fail:
    /* shared failure cleanup: undo routes, free the route lists, destroy
     * the TX lock. The failing site handles its own prefix first (the
     * pthread_create path destroys the live pool and sets g_stop; the
     * pool-create path has no pool to destroy) — the tail below is
     * identical in both. */
#ifdef _WIN32
    if (sender_started) {
        pump_sender_stop(&ctx);
        pump_sender_free(&ctx);
    }
#endif
    pump_prof_print(&ctx);
    teardown_routes(tun_name, auth_tun_ip, server, ogw, odev,
                    ogw_metric, &routes, had_routes, &routes6);
    slist_free(&routes);
    slist_free(&routes6);
    pthread_mutex_destroy(&ctx.send_lock);
    return -1;
}