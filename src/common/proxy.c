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
#include "protocol.h"
#include "proxy.h"
#include "route.h"
#include "tun.h"
#include "util.h"

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
} pump_ctx_t;

static void eprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

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
 * threshold is overridable: IWAN_RX_STALE_MS (default 60s, 10s..24h). */
#define PUMP_RX_STALE_MS_DEFAULT 60000u

static unsigned pump_rx_stale_ms(void)
{
    const char *v = getenv("IWAN_RX_STALE_MS");
    char *end;
    unsigned long n;

    if (!v || !v[0])
        return PUMP_RX_STALE_MS_DEFAULT;
    n = strtoul(v, &end, 10);
    if (end == v || *end != '\0' || n < 10000 || n > 86400000) {
        log_err("IWAN_RX_STALE_MS: invalid value '%s' (10s..24h); "
                "using default", v);
        return PUMP_RX_STALE_MS_DEFAULT;
    }
    return (unsigned)n;
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
        ssize_t sm = port_sendmmsg(ctx->sockfd, msgs + sent, n - sent, 0);
        if (sm > 0) {
            sent += (unsigned)sm;
            continue;
        }
        if (sm == 0)
            return;   /* cannot happen for UDP; guard against a busy loop */
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
            /* poll must never outlive the retry budget: cap the wait at
             * the remaining budget (min(100ms, budget-left); with the
             * 5ms budget the remaining time always binds) and stop
             * retrying once it is spent — an unbounded retry here
             * wedges the pump, while the receive thread (udp2tun) keeps
             * draining the socket so backpressure clears once we stop
             * hammering it. poll() already waited for writability, so
             * no post-poll usleep. */
            uint64_t el = now_ms() - retry_t0;
            if (el >= PUMP_SEND_RETRY_MS)
                return;
            struct pollfd pfd = { .fd = ctx->sockfd, .events = POLLOUT };
            port_poll(&pfd, 1, (int)(PUMP_SEND_RETRY_MS - el));
            continue;
        }
        eprintf("[TUN->UDP] sendmmsg: %s\n", strerror(errno));
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
            eprintf("[TUN->UDP] UDP_SEGMENT unsupported, using sendmmsg\n");
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
        ssize_t r = port_sendmsg(ctx->sockfd, &mh, 0);
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
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
            /* same budget-bounded wait as send_batch: poll at most the
             * remaining retry budget, then yield to the receive path */
            uint64_t el = now_ms() - retry_t0;
            if (el >= PUMP_SEND_RETRY_MS)
                return 1;   /* bounded: let the receive path drain */
            struct pollfd pfd = { .fd = ctx->sockfd, .events = POLLOUT };
            port_poll(&pfd, 1, (int)(PUMP_SEND_RETRY_MS - el));
            continue;
        }
        eprintf("[TUN->UDP] sendmsg: %s\n", strerror(errno));
        g_stop = 1;
        return 1;
    }
    return 1;
}

/* ---- uplink: one pool reader thread per queue, shared TX socket ----
 * The tun_pool hands each reader its own packet stream (kernel flow-hash
 * steering); packets are XOR'd into a thread-local batch and flushed to
 * the shared UDP socket under send_lock (UDP_SEGMENT and sendmmsg on one
 * socket must not interleave). */
typedef struct {
    uint8_t *batch;
    struct iovec iov[PUMP_BATCH];
    struct mmsghdr msgs[PUMP_BATCH];
    uint8_t hdr[8];
    unsigned n;
    uint64_t t0;
} pump_tx_t;

static _Thread_local pump_tx_t g_tx;

/* flush one batch to the socket; GSO fast path when uniform */
static void pump_flush(pump_ctx_t *ctx, pump_tx_t *q)
{
    unsigned n = q->n;
    if (n == 0)
        return;
    q->n = 0;
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
    pthread_mutex_lock(&ctx->send_lock);
    if (use_gso && send_gso(ctx, q->iov, n, q->iov[0].iov_len) == 0)
        use_gso = 0;   /* UDP_SEGMENT unavailable: fall back */
    if (!use_gso)
        send_batch(ctx, q->msgs, n);
    /* aggregate send pacing (util.h). MUST hold send_lock: multiple
     * reader threads share the bucket, which is not thread-safe; the
     * pacing sleep under the lock is exactly the aggregate-pacing
     * semantic (see util.h pace_bucket). */
    pace_take(&ctx->pace, (int)n);
    pthread_mutex_unlock(&ctx->send_lock);
}

/* tun_pool callback: one thread-local batch per reader thread */
static void pump_tun_pkt(void *ud, const uint8_t *pkt, size_t len, bool last)
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
        memcpy(s, q->hdr, 8);
        memcpy(s + 8, pkt, len);   /* pool hands over its scratch buffer */
        xor_crypt(s + 8, len, ctx->xor_key, 8);
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

/* Free this reader thread's TLS batch on thread exit (registered via
 * tun_pool_set_exit_cb). Runs on the exiting reader thread itself, so
 * the g_tx access is genuinely thread-local; tun.c invokes it strictly
 * after the final flush callback, so no pending pump_flush can touch
 * the freed buffer. */
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
        if (now - last_rx > pump_rx_stale_ms()) {
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
                eprintf("[UDP->TUN] keepalive send err: %s (retry "
                        "%d/%d)\n", strerror(e), ka_fail,
                        PUMP_KA_FAIL_MAX);
            } else {
                ka_fail = 0;
            }
            last_ka = now_ms();
        }
        int v = port_recvmmsg(ctx->sockfd, msgs, (unsigned)rxbatch,
                              MSG_DONTWAIT, NULL);
        if (v < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                uint64_t ka_ms = last_ka + PUMP_KEEPALIVE_MS;
                uint64_t now_msv = now_ms();
                int to = ka_ms > now_msv ? (int)(ka_ms - now_msv) : 1;
                if (to > PUMP_POLL_CEIL_MS)
                    to = PUMP_POLL_CEIL_MS;
                struct pollfd pfd = { .fd = ctx->sockfd, .events = POLLIN };
                int pr = port_poll(&pfd, 1, to);
                if (pr < 0 && errno != EINTR) {
                    eprintf("[UDP->TUN] poll err\n");
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
            g_stop = 1;   /* any pump-fatal error stops the tunnel */
            break;
        }
        last_rx = now_ms();   /* any datagram resets the stale clock */
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
            if (psid != ctx->sid || ptok != ctx->tok)
                continue;
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
                eprintf("[UDP->TUN] plaintext data on encrypted session, drop\n");
                continue;
            }
            if (t == PT_DATA_ENC)
                xor_crypt(m + 8, (size_t)(n - 8), ctx->xor_key, 8);
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
            if (tun_write_retry(ctx->tun_fd, m + 8, (size_t)(n - 8), 0,
                                &g_stop) != 0) {
                if (!g_stop)
                    log_err("tun write: %s", strerror(errno));
                g_stop = 1;
                break;
            }
        }
    }
    free(batch);
    return NULL;
}

static void on_signal(int sig) {
    if (sig == SIGINT)
        eprintf("\nSIGINT -- shutting down...\n");
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

static void teardown_routes(const char *tun, const char *srv, const char *ogw,
                            const char *odev, const char *ogw_metric,
                            const slist_t *routes, bool had_routes) {
    if (had_routes) {
        route_teardown(tun, srv, ogw, odev, ogw_metric, routes);
    } else {
        route_iface_down(tun);
    }
}

int run_pump(int tun_fd, const char *tun_name, int sockfd,
             const uint8_t xor_key[8], uint16_t sid, uint32_t tok, uint8_t enc,
             const char *server, const slist_t *route_targets,
             const char *auth_tun_ip, uint16_t auth_mtu) {
    char ogw[16] = "", odev[16] = "", ogw_metric[16] = "";

    slist_t routes;
    slist_init(&routes);
    if (expand_route_targets(route_targets, &routes) != 0) {
        slist_free(&routes);
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
            return -1;
        }
        log_info("tun %s up with IP %s/24 (no route hijack)", tun_name,
                 auth_tun_ip);
    }

    g_stop = 0;
    install_signals();

    pump_ctx_t ctx;
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
            teardown_routes(tun_name, server, ogw, odev, ogw_metric, &routes,
                            had_routes);
            slist_free(&routes);
            pthread_mutex_destroy(&ctx.send_lock);
            return -1;
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
        teardown_routes(tun_name, server, ogw, odev, ogw_metric, &routes,
                        had_routes);
        slist_free(&routes);
        pthread_mutex_destroy(&ctx.send_lock);
        return -1;
    }

    log_info("TUN proxy running -- press Ctrl-C to stop");
    while (!g_stop)
        port_sleep_us(100 * 1000);

    tun_pool_destroy(ctx.pool);
    pthread_join(t2, NULL);

    teardown_routes(tun_name, server, ogw, odev, ogw_metric, &routes,
                    had_routes);

    send_ctrl(&ctx, PT_CLOSE, enc, sid, tok);
    if (debug_enabled())
        eprintf("CLOSE sent\n");

    pthread_mutex_destroy(&ctx.send_lock);
    slist_free(&routes);
    /* 1 = session lost (keepalive failures / no downlink): the caller
     * may re-authenticate and re-run the pump; 0 = user stopped it */
    return ctx.session_lost ? 1 : 0;
}