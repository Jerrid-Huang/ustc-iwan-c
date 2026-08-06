#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "common.h"
#include "crypto.h"
#include "protocol.h"
#include "proxy.h"
#include "route.h"
#include "tun.h"
#include "util.h"

static volatile sig_atomic_t g_stop = 0;

typedef struct {
    int      tun_fd;
    int      sockfd;
    uint8_t  xor_key[8];
    uint16_t sid;
    uint32_t tok;
    uint8_t  enc;
    size_t   gso_mss;   /* last UDP_SEGMENT value set, 0 = none */
    int      gso_ok;    /* 1 = UDP_SEGMENT usable, 0 = failed, -1 = untried */
} pump_ctx_t;

static void eprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static int send_ctrl(int sockfd, uint8_t typ, uint8_t enc, uint16_t sid,
                     uint32_t tok) {
    buf_t pkt;
    buf_init(&pkt);
    ctrl_hdr(&pkt, typ, enc, sid, tok);
    size_t want = pkt.len;
    ssize_t r = send(sockfd, pkt.data, want, 0);
    buf_free(&pkt);
    if (r < 0 || (size_t)r != want)
        return -1;
    return 0;
}

#define PUMP_BATCH 32
#define PUMP_SLOT  2048

/* flush a TX batch after this much time instead of always waiting for it
 * to fill: bounds the added latency under sustained load (batch fill) */
#ifndef PUMP_MAX_LAT_US
#define PUMP_MAX_LAT_US 20
#endif

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

/* send a packet batch; retry partial sends and EAGAIN instead of dropping.
 * A full socket buffer backpressures the TUN read loop (kernel TCP then
 * throttles the app); only fatal errors stop the pump. */
static void send_batch(pump_ctx_t *ctx, struct mmsghdr *msgs, unsigned n)
{
    unsigned sent = 0;

    /* a lingering UDP_SEGMENT value would silently split any datagram
     * longer than the mss, so disable it before the per-message path */
    if (ctx->gso_mss != 0) {
        int z = 0;
        setsockopt(ctx->sockfd, SOL_UDP, UDP_SEGMENT, &z, sizeof z);
        ctx->gso_mss = 0;
    }

    while (sent < n && !g_stop) {
        ssize_t sm = sendmmsg(ctx->sockfd, msgs + sent, n - sent, 0);
        if (sm > 0) {
            sent += (unsigned)sm;
            continue;
        }
        if (sm == 0)
            return;   /* cannot happen for UDP; guard against a busy loop */
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
            struct pollfd pfd = { .fd = ctx->sockfd, .events = POLLOUT };
            int pr = poll(&pfd, 1, 100);
            /* if poll claims writable but EAGAIN persists, back off
             * briefly instead of busy-spinning */
            if (pr > 0 && (pfd.revents & POLLOUT))
                usleep(1000);
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
 * Same retry/backpressure semantics as send_batch. */
static int send_gso(pump_ctx_t *ctx, struct iovec *iov, unsigned n,
                    size_t mss)
{
    size_t total = 0;
    for (unsigned i = 0; i < n; i++)
        total += iov[i].iov_len;

    if (ctx->gso_ok == -1) {
        int m = (int)mss;
        ctx->gso_ok = setsockopt(ctx->sockfd, SOL_UDP, UDP_SEGMENT,
                                 &m, sizeof m) == 0;
        if (!ctx->gso_ok) {
            eprintf("[TUN->UDP] UDP_SEGMENT unsupported, using sendmmsg\n");
            return 0;
        }
        ctx->gso_mss = mss;
    } else if (ctx->gso_mss != mss) {
        int m = (int)mss;
        if (setsockopt(ctx->sockfd, SOL_UDP, UDP_SEGMENT, &m, sizeof m) != 0) {
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
        ssize_t r = sendmsg(ctx->sockfd, &mh, 0);
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
            struct pollfd pfd = { .fd = ctx->sockfd, .events = POLLOUT };
            int pr = poll(&pfd, 1, 100);
            if (pr > 0 && (pfd.revents & POLLOUT))
                usleep(1000);
            continue;
        }
        eprintf("[TUN->UDP] sendmsg: %s\n", strerror(errno));
        g_stop = 1;
        return 1;
    }
    return 1;
}

static void *tun2udp_thread(void *ud) {
    pump_ctx_t *ctx = ud;
    /* one slot per packet: 8-byte iWAN header followed by the (XOR'd)
     * payload, contiguous and 8-byte aligned. read() lands on slot+8,
     * so the final wire packet is a single iovec with no assembly. */
    const size_t slot = 8 + PUMP_SLOT;
    uint8_t *batch = malloc((size_t)PUMP_BATCH * slot);
    struct iovec iov[PUMP_BATCH];
    struct mmsghdr msgs[PUMP_BATCH];
    uint8_t hdr[8];
    if (!batch) {
        log_err("out of memory");
        return NULL;
    }
    memset(msgs, 0, sizeof msgs);
    pkhdr(PT_DATA_ENC, ctx->enc, ctx->sid, ctx->tok, hdr);
    while (!g_stop) {
        int n = 0;
        uint64_t t0 = 0;
        while (n < PUMP_BATCH) {
            uint8_t *s = batch + (size_t)n * slot;
            ptrdiff_t r = tun_read(ctx->tun_fd, s + 8, PUMP_SLOT);
            if (r < 0) {
                if (errno == EAGAIN)
                    break;
                if (errno == EINTR)
                    continue;
                goto out;
            }
            if (r == 0)
                goto out;
            if (n == 0)
                t0 = now_us();   /* first packet of this batch */
            memcpy(s, hdr, 8);
            xor_crypt(s + 8, (size_t)r, ctx->xor_key, 8);
            iov[n].iov_base = s;
            iov[n].iov_len = (size_t)r + 8;
            n++;
            /* latency cap: under sustained load, stop filling this batch
             * after PUMP_MAX_LAT_US so no packet waits a full batch
             * (32 x inter-arrival) before being sent */
            if (now_us() - t0 >= PUMP_MAX_LAT_US)
                break;
        }
        if (n == 0) {
            struct pollfd pfd = { .fd = ctx->tun_fd, .events = POLLIN };
            int pr = poll(&pfd, 1, 1000);
            if (pr < 0 && errno != EINTR)
                goto out;
            continue;
        }
        for (int i = 0; i < n; i++) {
            msgs[i].msg_hdr.msg_iov = &iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }
        /* GSO fast path: uniform batch -> one sendmsg, kernel segments;
         * wire output is identical because segment boundaries align with
         * the (equal) datagram boundaries. Falls back to sendmmsg when
         * UDP_SEGMENT is unavailable or sizes differ. */
        int use_gso = 0;
        if (n >= 2) {
            size_t l0 = iov[0].iov_len;
            int uniform = 1;
            for (int i = 1; i < n; i++) {
                if (iov[i].iov_len != l0) {
                    uniform = 0;
                    break;
                }
            }
            /* a GSO unit's total length must fit the 16-bit UDP length
             * field; oversized (jumbo) batches fall back to sendmmsg */
            use_gso = uniform && l0 >= 8 &&
                      (size_t)n * l0 <= 65507;
        }
        if (use_gso && send_gso(ctx, iov, (unsigned)n, iov[0].iov_len) == 0)
            use_gso = 0;   /* UDP_SEGMENT unavailable: fall back */
        if (!use_gso)
            send_batch(ctx, msgs, (unsigned)n);
    }
out:
    free(batch);
    return NULL;
}

/* write one inner packet to the TUN device, waiting for writability
 * (poll) instead of dropping on EAGAIN; silent loss here costs inner TCP
 * retransmits. Fatal errors stop the pump. */
static void tun_write_retry(pump_ctx_t *ctx, const uint8_t *pkt, size_t n)
{
    while (n > 0 && !g_stop) {
        ptrdiff_t w = tun_write(ctx->tun_fd, pkt, n);
        if (w > 0) {
            pkt += w;
            n -= (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR)
            continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = ctx->tun_fd, .events = POLLOUT };
            int pr = poll(&pfd, 1, 100);
            /* if poll claims writable but EAGAIN persists, back off
             * briefly instead of busy-spinning */
            if (pr > 0 && (pfd.revents & POLLOUT))
                usleep(1000);
            continue;
        }
        log_err("tun write: %s", strerror(errno));
        g_stop = 1;
        return;
    }
}

static void *udp2tun_thread(void *ud) {
    pump_ctx_t *ctx = ud;
    /* recvmmsg with MSG_DONTWAIT drains whatever is queued (zero latency
     * tail), then poll() parks until data or the keepalive deadline.
     * A non-NULL timeout argument must NOT be passed to recvmmsg: the
     * kernel checks it only after the first datagram and it never bounds
     * the first-message wait (documented bug). */
    const size_t slot = 8 + PUMP_SLOT;
    const int rxbatch = 64;
    uint8_t *batch = malloc((size_t)rxbatch * slot);
    struct iovec iov[64];
    struct mmsghdr msgs[64];
    uint64_t last_ka = now_ms() > 10000 ? now_ms() - 10000 : 0;
    int i;

    if (!batch) {
        log_err("out of memory");
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
        if (now >= last_ka + 10000) {
            if (send_ctrl(ctx->sockfd, PT_ECHO_REQ, ctx->enc, ctx->sid,
                          ctx->tok) != 0) {
                eprintf("[UDP->TUN] keepalive send err\n");
                break;
            }
            last_ka = now_ms();
        }
        int v = recvmmsg(ctx->sockfd, msgs, (unsigned)rxbatch,
                         MSG_DONTWAIT, NULL);
        if (v < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* park until data arrives or the next keepalive is due */
                uint64_t ka_ms = last_ka + 10000;
                uint64_t now_msv = now_ms();
                int to = ka_ms > now_msv ? (int)(ka_ms - now_msv) : 1;
                if (to > 1000)
                    to = 1000;
                struct pollfd pfd = { .fd = ctx->sockfd, .events = POLLIN };
                int pr = poll(&pfd, 1, to);
                if (pr < 0 && errno != EINTR) {
                    eprintf("[UDP->TUN] poll err\n");
                    break;
                }
                continue;
            }
            if (errno == EINTR)
                continue;
            eprintf("[UDP->TUN] recv err\n");
            break;
        }
        for (i = 0; i < v; i++) {
            ssize_t n = msgs[i].msg_len;
            uint8_t *m = batch + (size_t)i * slot;
            if (n < 8 || (msgs[i].msg_hdr.msg_flags & MSG_TRUNC))
                continue;
            uint8_t t = m[0];
            if (t == PT_CLOSE) {
                eprintf("[UDP->TUN] server sent CLOSE\n");
                g_stop = 1;
                break;
            }
            if (t != PT_DATA && t != PT_DATA_ENC)
                continue;
            uint16_t psid = (uint16_t)((m[2] << 8) | m[3]);
            uint32_t ptok = ((uint32_t)m[4] << 24) | ((uint32_t)m[5] << 16) |
                            ((uint32_t)m[6] << 8) | (uint32_t)m[7];
            if (psid != ctx->sid || ptok != ctx->tok)
                continue;   /* mirror receive_vpn: sid/token must match */
            if (t == PT_DATA_ENC) {
                xor_crypt(m + 8, (size_t)(n - 8), ctx->xor_key, 8);
                tun_write_retry(ctx, m + 8, (size_t)(n - 8));
            } else if (t == PT_DATA) {
                tun_write_retry(ctx, m + 8, (size_t)(n - 8));
            } else if (t == PT_ECHO_REQ) {
                if (send_ctrl(ctx->sockfd, PT_ECHO_RES, ctx->enc, ctx->sid,
                              ctx->tok) != 0) {
                    eprintf("[UDP->TUN] keepalive response err\n");
                    g_stop = 1;
                    break;
                }
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
}

static void install_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
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
        if (strcmp(p, "default") == 0 || strchr(p, '/') != NULL) {
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
                            const char *odev, const slist_t *routes,
                            bool had_routes) {
    if (had_routes) {
        route_teardown(tun, srv, ogw, odev, routes);
    } else {
        char *f1[] = { "addr", "flush", "dev", (char *)tun, NULL };
        char *f2[] = { "link", "set", (char *)tun, "down", NULL };
        ip_run(f1);
        ip_run(f2);
    }
}

int run_pump(int tun_fd, const char *tun_name, int sockfd,
             const uint8_t xor_key[8], uint16_t sid, uint32_t tok, uint8_t enc,
             const char *server, const slist_t *route_targets,
             const char *auth_tun_ip, uint16_t auth_mtu) {
    char ogw[16], odev[16];
    if (!capture_default(ogw, odev)) {
        log_err("cannot detect default route");
        return -1;
    }
    log_debug("default route: via %s dev %s", ogw, odev);

    slist_t routes;
    slist_init(&routes);
    if (expand_route_targets(route_targets, &routes) != 0) {
        slist_free(&routes);
        return -1;
    }

    bool had_routes = routes.n > 0;
    if (had_routes) {
        route_setup(tun_name, auth_tun_ip, auth_mtu, server, ogw, odev,
                    &routes);
        log_info("tun %s ready: %zu route%s", tun_name, routes.n,
                 routes.n == 1 ? "" : "s");
        for (size_t i = 0; i < routes.n; i++)
            log_debug("route %s -> dev %s", routes.v[i], tun_name);
    } else {
        char mtu_s[8], ip24[64];
        snprintf(mtu_s, sizeof mtu_s, "%u", (unsigned)auth_mtu);
        snprintf(ip24, sizeof ip24, "%s/24", auth_tun_ip);
        char *f1[] = { "addr", "flush", "dev", (char *)tun_name, NULL };
        char *f2[] = { "link", "set", (char *)tun_name, "up", NULL };
        char *f3[] = { "link", "set", "dev", (char *)tun_name, "mtu", mtu_s,
                       NULL };
        char *f4[] = { "addr", "add", ip24, "dev", (char *)tun_name, NULL };
        ip_run(f1);
        ip_run(f2);
        ip_run(f3);
        ip_run(f4);
        log_info("tun %s up with IP %s/24 (no route hijack)", tun_name,
                 auth_tun_ip);
    }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 300000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

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

    pthread_t t1, t2;
    if (pthread_create(&t1, NULL, tun2udp_thread, &ctx) != 0) {
        teardown_routes(tun_name, server, ogw, odev, &routes, had_routes);
        slist_free(&routes);
        return -1;
    }
    if (pthread_create(&t2, NULL, udp2tun_thread, &ctx) != 0) {
        g_stop = 1;
        pthread_join(t1, NULL);
        teardown_routes(tun_name, server, ogw, odev, &routes, had_routes);
        slist_free(&routes);
        return -1;
    }

    log_info("TUN proxy running -- press Ctrl-C to stop");
    while (!g_stop)
        usleep(200 * 1000);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    teardown_routes(tun_name, server, ogw, odev, &routes, had_routes);

    send_ctrl(sockfd, PT_CLOSE, enc, sid, tok);
    if (debug_enabled())
        eprintf("CLOSE sent\n");

    slist_free(&routes);
    return 0;
}