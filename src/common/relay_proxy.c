/* Local SOCKS5 + HTTP forwarding proxy for TUN mode.
 *
 * Every accepted connection is re-opened on the local kernel stack, so
 * the traffic obeys the TUN routing rules (default route / --proxy-cidr
 * selection) like any other system traffic. The tunnel data plane is
 * untouched: no lwIP, no session sockets — this file only bridges the
 * listener to kernel sockets.
 *
 * Protocol surface (one shared port):
 *   SOCKS5 greeting + RFC1929 auth + CONNECT (ATYP 1/3/4)
 *   HTTP CONNECT (tunnel) and absolute-URI forwarding (the original
 *   request line is sent verbatim — RFC 7230 servers accept absolute
 *   URIs on a proxy connection)
 *
 * Thread model: one accept thread; two GLOBAL direction threads
 * (poll-based event loop) shared by all connections — up thread
 * (client -> upstream) and down thread (upstream -> client).
 * relay_proxy_stop closes the listener; live connections are reaped
 * when their sockets close at process exit.
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "addr.h"
#include "common.h"
#include "crypto.h"
#include "port.h"
#include "profile.h"
#include "proto_parse.h"
#include "relay_proxy.h"
#include "util.h"

#define RP_HANDSHAKE_TIMEOUT_MS 30000u
#define RP_CONNECT_TIMEOUT_MS   10000u
#define RP_BUF                  65536
/* M6a: cap on concurrent per-connection threads. Each accepted
 * connection runs its handshake on its own thread; beyond this cap
 * the accept thread sheds the new connection (close, no thread). */
#define RP_MAX_CONNS            256

struct RelayProxy {
    int          listener;   /* -1 = stopped */
    atomic_bool  stop;
    char        *token;      /* RFC1929 password copy; NULL = no auth */
};

/* per-process current proxy (connection threads read the token copy).
 * relay_proxy_stop deliberately does NOT free the struct: detached
 * connection threads may still be reading it. One proxy per process. */
struct RelayProxy *g_rp_current;

/* M6a: number of live per-connection threads (incremented by the
 * accept thread before the thread is spawned, decremented by
 * rp_conn_main on EVERY exit path). */
static atomic_int g_rp_conn_n;

/* ---- handshake watchdog (M6b) ----
 * RP_HANDSHAKE_TIMEOUT_MS remains the ceiling for a SINGLE poll, but
 * a slow sender could previously renew that window forever and pin a
 * connection thread indefinitely. Every handshake poll now draws from
 * an absolute budget of RP_HS_TOTAL_MS that starts when the
 * connection enters rp_conn_main; once the budget is gone the poll
 * fails and the connection is closed. Handshake input is additionally
 * capped at RP_HS_INPUT_MAX cumulative bytes (a handshake never needs
 * anywhere near this; the cap bounds parser-facing memory churn). */
#define RP_HS_TOTAL_MS  30000u
#define RP_HS_INPUT_MAX 65536u

struct rp_hs {
    uint64_t deadline;      /* absolute now_ms() deadline */
    size_t   in;            /* cumulative handshake bytes read */
};

static void rp_hs_init(struct rp_hs *hs)
{
    hs->deadline = now_ms() + RP_HS_TOTAL_MS;
    hs->in = 0;
}

/* Wait for readability within the handshake: the poll timeout is the
 * remaining absolute budget capped at RP_HANDSHAKE_TIMEOUT_MS (the
 * per-poll ceiling still applies — the total budget is independent).
 * Returns 1 when the fd is readable, 0 on timeout or exhausted
 * budget (the caller must close). */
static int rp_hs_poll(const struct rp_hs *hs, int fd)
{
    uint64_t now = now_ms();
    uint64_t left = hs->deadline > now ? hs->deadline - now : 0;
    struct pollfd pfd;

    if (left == 0)
        return 0;
    if (left > RP_HANDSHAKE_TIMEOUT_MS)
        left = RP_HANDSHAKE_TIMEOUT_MS;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    return port_poll(&pfd, 1, (int)left) > 0 ? 1 : 0;
}

/* recv with the handshake input cap: behaves like port_recv, but a
 * read that pushes the cumulative handshake input past RP_HS_INPUT_MAX
 * fails with EMSGSIZE. Callers treat any non-EAGAIN error as fatal,
 * so the over-cap case closes the connection. */
static ssize_t rp_hs_recv(struct rp_hs *hs, int fd, void *buf, size_t len)
{
    ssize_t r = port_recv(fd, buf, len, 0);
    if (r > 0) {
        hs->in += (size_t)r;
        if (hs->in > RP_HS_INPUT_MAX) {
            errno = EMSGSIZE;
            return -1;
        }
    }
    return r;
}

/* ---- RFC1929 brute-force lockout (M6c/L6) ----
 * Same semantics as the SOCKS-mode table in socks_flow.c: only
 * WELL-FORMED RFC1929 frames that fail the token check count
 * (protocol violations are not auth attempts, so a probe flood cannot
 * lock a legitimate user out); RP_FAIL_MAX failures inside
 * RP_FAIL_WINDOW_MS lock the source out for another window; a
 * successful auth clears the source; locked sources are dropped at
 * accept() time. Two differences: the table holds 64 entries (L6:
 * the SOCKS table's 16 was too small for a shared-NAT world), and it
 * is mutex-guarded — unlike the single-threaded SOCKS event loop,
 * every relay proxy connection runs on its own thread.
 *
 * Key: the peer IPv4 as-is; an IPv6 peer is merged to its /64 prefix
 * so one subnet cannot fill the table with 2^64 /128 aliases. The
 * listener is IPv4-only today, so the v6 path is defensive only. */
#define RP_FAIL_TRACK_MAX  64
#define RP_FAIL_MAX        5
#define RP_FAIL_WINDOW_MS  60000u

typedef struct {
    uint8_t  v6;                /* key is an IPv6 /64 prefix */
    uint32_t k0, k1;            /* opaque key words (see rp_fail_key_of) */
} rp_fail_key;

typedef struct {
    rp_fail_key key;
    int      fail;
    uint64_t first_fail_ms;
    uint64_t blocked_until_ms;  /* 0 = not blocked */
} rp_fail_rec;

static rp_fail_rec g_rp_fail[RP_FAIL_TRACK_MAX];
static pthread_mutex_t g_rp_fail_mu = PTHREAD_MUTEX_INITIALIZER;

static bool rp_key_eq(const rp_fail_key *a, const rp_fail_key *b)
{
    return a->v6 == b->v6 && a->k0 == b->k0 && a->k1 == b->k1;
}

/* Extract the lockout key from a peer address. Byte-order is
 * irrelevant: the words are used only as an opaque comparison key.
 * Returns false for unknown families (no tracking for that peer). */
static bool rp_fail_key_of(const struct sockaddr_storage *ss,
                           rp_fail_key *k)
{
    memset(k, 0, sizeof *k);
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)ss;
        memcpy(&k->k0, &a->sin_addr, 4);
        return true;
    }
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)ss;
        /* first 8 bytes = /64 prefix (not s6_addr: mingw's IN6_ADDR
         * lacks the POSIX member name) */
        memcpy(&k->k0, &a->sin6_addr, 4);
        memcpy(&k->k1, (const uint8_t *)&a->sin6_addr + 4, 4);
        k->v6 = 1;
        return true;
    }
    return false;
}

static void rp_fail_note(const rp_fail_key *key, bool success)
{
    rp_fail_rec *e = NULL, *oldest = &g_rp_fail[0];
    uint64_t now;

    if (!key)
        return;             /* getpeername failed: nothing to track */
    now = now_ms();
    pthread_mutex_lock(&g_rp_fail_mu);
    if (success) {
        for (int i = 0; i < RP_FAIL_TRACK_MAX; i++) {
            if (rp_key_eq(&g_rp_fail[i].key, key)) {
                memset(&g_rp_fail[i], 0, sizeof g_rp_fail[i]);
                break;
            }
        }
        pthread_mutex_unlock(&g_rp_fail_mu);
        return;
    }
    for (int i = 0; i < RP_FAIL_TRACK_MAX; i++) {
        rp_fail_rec *r = &g_rp_fail[i];
        if (rp_key_eq(&r->key, key)) {
            e = r;
            break;
        }
        /* empty slot wins; otherwise keep the oldest first_fail_ms
         * (the entry that would age out first) */
        if (r->first_fail_ms == 0 ||
            r->first_fail_ms < oldest->first_fail_ms)
            oldest = r;
    }
    if (!e)
        e = oldest;
    /* fresh entry, or the previous burst aged out of the window */
    if (e->first_fail_ms == 0 ||
        now - e->first_fail_ms > RP_FAIL_WINDOW_MS) {
        e->key = *key;
        e->fail = 1;
        e->first_fail_ms = now;
        e->blocked_until_ms = 0;
        pthread_mutex_unlock(&g_rp_fail_mu);
        return;
    }
    e->key = *key;
    e->fail++;
    if (e->fail >= RP_FAIL_MAX)
        e->blocked_until_ms = now + RP_FAIL_WINDOW_MS;
    pthread_mutex_unlock(&g_rp_fail_mu);
}

static bool rp_fail_blocked(const rp_fail_key *key)
{
    uint64_t now;

    if (!key)
        return false;
    now = now_ms();
    pthread_mutex_lock(&g_rp_fail_mu);
    for (int i = 0; i < RP_FAIL_TRACK_MAX; i++) {
        const rp_fail_rec *r = &g_rp_fail[i];
        if (rp_key_eq(&r->key, key) && r->blocked_until_ms != 0 &&
            r->blocked_until_ms > now) {
            pthread_mutex_unlock(&g_rp_fail_mu);
            return true;
        }
    }
    pthread_mutex_unlock(&g_rp_fail_mu);
    return false;
}

/* ---- target resolution/connect (kernel stack) ---- */

/* literal IPv4/IPv6: connect directly, no resolution. The connect is
 * synchronous: immediate success is taken, EINPROGRESS is polled for
 * writability within RP_CONNECT_TIMEOUT_MS and then SO_ERROR is
 * checked. NOTE: no port_set_nonblock here — the literal paths are
 * blocking-style (the domain path below sets nonblock because it must
 * try many addresses). */
static int rp_connect_literal(int af, const void *addr, uint16_t port,
                              int *fd_out)
{
    struct sockaddr_storage ss;
    socklen_t salen;
    int fd = port_socket(af, SOCK_STREAM, 0);

    if (fd < 0)
        return -1;
    memset(&ss, 0, sizeof ss);
    if (af == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in *)&ss;
        sa->sin_family = AF_INET;
        memcpy(&sa->sin_addr, addr, 4);
        sa->sin_port = htons(port);
        salen = sizeof *sa;
    } else {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)&ss;
        sa->sin6_family = AF_INET6;
        memcpy(&sa->sin6_addr, addr, 16);
        sa->sin6_port = htons(port);
        salen = sizeof *sa;
    }
    if (port_connect(fd, (struct sockaddr *)&ss, salen) == 0 ||
        errno == EINPROGRESS) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        if (errno == EINPROGRESS) {
            if (port_poll(&pfd, 1, RP_CONNECT_TIMEOUT_MS) <= 0) {
                port_close(fd);
                return -1;
            }
            int soerr = 0;
            socklen_t sl = sizeof soerr;
            if (port_getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr,
                                &sl) != 0 || soerr != 0) {
                port_close(fd);
                return -1;
            }
        }
        *fd_out = fd;
        return 0;
    }
    port_close(fd);
    return -1;
}

/* M7: the SSRF gate is on by default; IWAN_RELAY_ALLOW_LOOPBACK=1 is
 * an explicit operator opt-out for deployments that must reach host-
 * local services through the relay. Read once in relay_proxy_start
 * before any connection thread exists (plain static: no race). */
static bool g_rp_ssrf_off;

/* M7 (SSRF gate): true when the target address (literal or resolved)
 * points at the proxy host's own loopback or a link-local range. An
 * authenticated NON-loopback peer must not use the relay as a
 * springboard into services bound to the local host; a loopback peer
 * (local user) is exempt, keeping today's local usage unchanged. */
static bool rp_target_blocked(bool guard, int af, const uint8_t *p)
{
    if (!guard)
        return false;
    if (af == 4)
        return p[0] == 127 ||              /* 127.0.0.0/8 */
               (p[0] == 169 && p[1] == 254);   /* 169.254.0.0/16 */
    if (af == 6) {
        static const uint8_t lo[16] = { 0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 1 };
        static const uint8_t v4map[12] = { 0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0xff, 0xff };
        if (memcmp(p, lo, 16) == 0)
            return true;                    /* ::1 */
        if (p[0] == 0xfe && (p[1] & 0xc0) == 0x80)
            return true;                    /* fe80::/10 */
        /* ::ffff:a.b.c.d: the mapped v4 address obeys the v4 rules,
         * else a crafted AAAA ::ffff:127.0.0.1 would bypass the gate */
        if (memcmp(p, v4map, 12) == 0)
            return p[12] == 127 ||
                   (p[12] == 169 && p[13] == 254);
    }
    return false;
}

static int rp_connect_target(int *fd_out, const char *host, uint16_t port,
                             bool have_ip4, const uint8_t ip4[4],
                             bool have_ip6, const uint8_t ip6[16],
                             bool guard)
{
    struct addrinfo hints, *res = NULL, *ai;
    char port_s[8];
    int last = -1;
    bool blocked = false;   /* a candidate was refused by the gate */

    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    snprintf(port_s, sizeof port_s, "%u", (unsigned)port);

    if (have_ip4) {
        /* literal IPv4: connect directly, no resolution. The gate
         * sees the literal bytes before any connect attempt. */
        if (rp_target_blocked(guard, 4, ip4))
            return -2;
        return rp_connect_literal(AF_INET, ip4, port, fd_out);
    }
    if (have_ip6) {
        if (rp_target_blocked(guard, 6, ip6))
            return -2;
        return rp_connect_literal(AF_INET6, ip6, port, fd_out);
    }
    /* domain: resolve, then try every address (v4 and v6). The gate
     * must judge each RESOLVED address — checking only the hostname
     * would let DNS rebinding slip through. */
    if (getaddrinfo(host, port_s, &hints, &res) != 0)
        return -1;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        int fd;
        if (ai->ai_family == AF_INET) {
            const struct sockaddr_in *sa =
                (const struct sockaddr_in *)ai->ai_addr;
            if (rp_target_blocked(guard, 4,
                                  (const uint8_t *)&sa->sin_addr)) {
                blocked = true;
                continue;
            }
        } else if (ai->ai_family == AF_INET6) {
            const struct sockaddr_in6 *sa =
                (const struct sockaddr_in6 *)ai->ai_addr;
            if (rp_target_blocked(guard, 6,
                                  (const uint8_t *)&sa->sin6_addr)) {
                blocked = true;
                continue;
            }
        }
        fd = port_socket(ai->ai_family, SOCK_STREAM, 0);
        if (fd < 0)
            continue;
        port_set_nonblock(fd, true);
        if (port_connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            last = fd;
        else if (errno == EINPROGRESS) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            if (port_poll(&pfd, 1, RP_CONNECT_TIMEOUT_MS) > 0) {
                int soerr = 0;
                socklen_t sl = sizeof soerr;
                if (port_getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr,
                                    &sl) == 0 && soerr == 0)
                    last = fd;
            }
        }
        if (last >= 0)
            break;
        port_close(fd);
    }
    freeaddrinfo(res);
    if (last < 0)
        return blocked ? -2 : -1;
    port_set_nonblock(last, false);   /* relay threads want blocking */
    *fd_out = last;
    return 0;
}

/* ---- SOCKS5 ---- */

/* read exactly `want` bytes, waiting through EAGAIN. Windows accept()
 * inherits the listener's nonblocking mode (unlike Linux), so the
 * handshake reads must poll instead of treating EAGAIN as fatal.
 * Polls draw from the handshake budget (M6b) and reads count toward
 * the handshake input cap. */
static bool rp_read_full(int fd, uint8_t *buf, size_t want,
                         struct rp_hs *hs)
{
    size_t got = 0;
    while (got < want) {
        ssize_t r = rp_hs_recv(hs, fd, buf + got, want - got);
        if (r > 0) {
            got += (size_t)r;
            continue;
        }
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (rp_hs_poll(hs, fd) <= 0)
                return false;
            continue;
        }
        return false;
    }
    return true;
}

static void rp_socks_reply(int fd, uint8_t rep)
{
    uint8_t r[10] = {5, rep, 0, 1, 0, 0, 0, 0, 0, 0};
    if (port_send(fd, r, sizeof r, 0) != (ssize_t)sizeof r)
        err_printf("rp_socks_reply send failed rep=%u errno=%d\n", rep,
                   errno);
}

/* returns 0 on success with the upstream connected; -1 on failure.
 * Frame parsing (greeting / RFC1929 / CONNECT) is delegated to
 * proto_parse.c — the same parsers as SOCKS mode.
 *
 * fk: peer lockout key (NULL when getpeername failed — no tracking);
 * hs: handshake watchdog state; guard: SSRF gate armed for this
 * connection (M7). */
static int rp_handle_socks(int fd, const uint8_t *first, size_t first_n,
                           const char *token, struct rp_hs *hs,
                           const rp_fail_key *fk, bool guard)
{
    /* L7: 512 could not hold a maximal legal exchange (RFC1929 frame
     * with 255-byte user + 255-byte pass alone is 513 bytes) plus a
     * pipelined greeting/CONNECT, so legitimate clients could never
     * finish auth. 2048 covers greeting (257) + auth (513) + CONNECT
     * (262) with slack. The `n > sizeof b` entry bound below follows
     * the new size automatically. */
    uint8_t b[2048];
    size_t n = first_n;
    pp_target t;
    uint8_t method = 0, cmd = 0, rep = 0;

    if (n < 2)
        return -1;
    /* pre-auth bound: `first` holds up to a full 4096B read but every
     * parser below works out of b[2048] (later reads all guard
     * n >= sizeof b). An oversized first packet is not a valid SOCKS5
     * greeting — refuse it before the copy. */
    if (n > sizeof b)
        return -1;
    memcpy(b, first, n);
    if (pp_socks_greeting(b, n, token != NULL, &method) != 0) {
        /* greeting may span reads: [5, nmethods, methods...] */
        size_t want = 2 + (size_t)b[1];
        if (want > sizeof b || !rp_read_full(fd, b + n, want - n, hs))
            return -1;
        n = want;
        if (pp_socks_greeting(b, n, token != NULL, &method) != 0)
            return -1;
    }
    if (method == 0xff) {
        uint8_t no[2] = {5, 0xff};
        (void)port_send(fd, no, 2, 0);
        return -1;
    }
    /* consume the greeting so a pipelined CONNECT frame is aligned */
    {
        size_t g = 2 + (size_t)b[1];
        memmove(b, b + g, n - g);
        n -= g;
    }
    if (token || method == 2) {
        uint8_t ok[2] = {5, 2};
        (void)port_send(fd, ok, 2, 0);
        /* RFC1929: [1, ulen, user..., plen, pass...]. Token-less mode
         * accepts any well-formed frame (courtesy — a client that
         * offered only 0x02, e.g. curl -U, must not be rejected). */
        char user[64];
        const uint8_t *pass;
        size_t plen;
        for (;;) {
            int pr = pp_socks_auth_frame(b, n, user, sizeof user,
                                         &pass, &plen);
            if (pr > 0) {
                uint8_t rr[2] = {1, 0};
                if (token) {
                    size_t tlen = strlen(token);
                    if (plen != tlen ||
                        ct_eq(pass, (const uint8_t *)token, tlen) == 0) {
                        rr[1] = 1;
                        /* M6c: a well-formed frame with the wrong
                         * token is a counted auth failure */
                        rp_fail_note(fk, false);
                    }
                }
                (void)port_send(fd, rr, 2, 0);
                if (rr[1] != 0)
                    return -1;
                if (token)
                    rp_fail_note(fk, true);   /* success clears */
                /* consume the auth frame */
                {
                    size_t flen = 2 + (size_t)b[1] + 1 + plen;
                    memmove(b, b + flen, n - flen);
                    n -= flen;
                }
                break;
            }
            if (pr == 0)
                return -1;      /* complete but malformed */
            if (n >= sizeof b)
                return -1;
            {
                ssize_t r = rp_hs_recv(hs, fd, b + n, sizeof b - n);
                if (r > 0) {
                    n += (size_t)r;
                    continue;
                }
                if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if (rp_hs_poll(hs, fd) <= 0)
                        return -1;
                    continue;
                }
                return -1;
            }
        }
    } else {
        uint8_t ok[2] = {5, 0};
        (void)port_send(fd, ok, 2, 0);
    }

    /* CONNECT request [5, CMD, RSV, ATYP, addr..., port] */
    for (;;) {
        if (pp_socks_request(b, n, &cmd, &rep, &t) == 0) {
            /* L5: per-connection metadata is too noisy for the
             * unconditional error log — debug only */
            log_debug("socks: request ok cmd=%u af=%u port=%u\n", cmd,
                      t.af, t.port);
            break;
        }
        if (n >= sizeof b)
            return -1;
        {
            ssize_t r = rp_hs_recv(hs, fd, b + n, sizeof b - n);
            if (r > 0) {
                n += (size_t)r;
                continue;
            }
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (rp_hs_poll(hs, fd) <= 0)
                    return -1;
                continue;
            }
            return -1;
        }
    }
    if (rep != 0) {
        rp_socks_reply(fd, rep);
        return -1;
    }
    {
        int up = -1;
        int rc = rp_connect_target(&up, t.host, t.port, t.af == 4,
                                   (const uint8_t *)&t.ip4, t.af == 6,
                                   t.ip6, guard);
        if (rc == 0) {
            rp_socks_reply(fd, 0);
            return up;           /* caller relays on fd <-> up */
        }
        /* M7: a gate refusal is "not allowed" (rep 2), everything
         * else stays a general failure */
        rp_socks_reply(fd, rc == -2 ? 2 : 5);
        return -1;
    }
}

/* ---- HTTP ---- */

/* returns the connected upstream fd, or -1 */
static int rp_handle_http(int fd, const uint8_t *first, size_t first_n,
                          struct rp_hs *hs, bool guard)
{
    uint8_t buf[8192];
    size_t n = first_n, hdr_end;
    ssize_t r;

    /* first packet must contain the request line and method token */
    if (first_n < 8)
        return -1;
    memcpy(buf, first, first_n);
    /* read until \r\n\r\n */
    hdr_end = (size_t)-1;
    while (n < sizeof buf - 1) {
        for (size_t i = 4; i <= n; i++) {
            if (buf[i - 4] == '\r' && buf[i - 3] == '\n' &&
                buf[i - 2] == '\r' && buf[i - 1] == '\n') {
                hdr_end = i;
                break;
            }
        }
        if (hdr_end != (size_t)-1)
            break;
        r = rp_hs_recv(hs, fd, buf + n, sizeof buf - 1 - n);
        if (r > 0) {
            n += (size_t)r;
            continue;
        }
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (rp_hs_poll(hs, fd) <= 0)
                return -1;
            continue;
        }
        return -1;
    }
    if (hdr_end == (size_t)-1)
        return -1;

    /* method token */
    size_t mn = 0;
    while (mn < hdr_end && buf[mn] != ' ')
        mn++;
    if (mn == 0 || mn >= hdr_end)
        return -1;
    bool is_connect = (mn == 7 && memcmp(buf, "CONNECT", 7) == 0);

    /* target starts after the first space (skip repeats) */
    size_t ts = mn + 1;
    while (ts < hdr_end && buf[ts] == ' ')
        ts++;
    if (ts >= hdr_end)
        return -1;
    const char *tgt = (const char *)buf + ts;
    size_t tlen = 0;
    for (size_t i = ts; i < hdr_end; i++) {
        if (buf[i] == '\r' || buf[i] == '\n') {
            tlen = i - ts;
            break;
        }
    }
    if (tlen == 0)
        return -1;

    /* target parsing (CONNECT authority / absolute URI with scheme
     * stripped) is shared with SOCKS mode via proto_parse.c */
    pp_target t;
    if (pp_http_target(tgt, tlen, is_connect, &t) != 0)
        return -1;

    int up = -1;
    /* the gate also covers absolute-URI forwards: same SSRF surface,
     * same target-connection path */
    if (rp_connect_target(&up, t.host, t.port, t.af == 4,
                          (const uint8_t *)&t.ip4, t.af == 6,
                          t.ip6, guard) != 0) {
        static const char bad[] = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        (void)port_send(fd, bad, sizeof bad - 1, 0);
        return -1;
    }
    if (is_connect) {
        static const char ok[] =
            "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (port_send(fd, ok, sizeof ok - 1, 0) < 0) {
            port_close(up);
            return -1;
        }
        return up;
    }
    /* absolute-URI forward: send the original request head verbatim
     * (RFC 7230 servers accept absolute-form on a proxy connection) */
    if (port_send(up, buf, hdr_end, 0) != (ssize_t)hdr_end) {
        port_close(up);
        return -1;
    }
    return up;
}

/* ---- event-loop relay: two GLOBAL direction threads ----
 *
 * Up thread: client -> upstream. Down thread: upstream -> client.
 * Each direction owns an array of entries and one poll() event loop:
 *   - nonblocking recv with a write-through fast path: when no backlog
 *     exists the chunk is sent immediately (zero pend, zero extra
 *     poll round-trip); only a partial/EAGAIN send leaves a remainder
 *     in the pending buffer, and once anything is pending the loop
 *     stops reading that pass so the kernel socket buffer stays the
 *     backpressure point (pend is bounded by RP_PEND_LIMIT)
 *   - POLLOUT is registered while pending data exists; POLLIN is
 *     dropped once more than RP_PEND_LIMIT bytes are pending
 *   - registration is picked up by a bounded poll timeout (100 ms):
 *     the pollset is rebuilt every iteration, so a connection added
 *     while the loop was parked is serviced within one timeout. An
 *     evfd wakeup was tried first but two threads parked on one evfd
 *     race on its counter (the first drain makes the second thread's
 *     wakeup check fail and it sleeps forever), and one evfd per
 *     thread breaks the Windows/macOS process-level singleton
 *     substitute — the bounded timeout is portable and race-free.
 * End semantics: any end condition on one direction half-closes the
 * other (SHUT_WR) and retires the entry; the sockets and the conn are
 * closed when both direction threads retired (atomic dirs 2 -> 0).
 * The handshake still runs in the per-connection thread
 * (rp_conn_main); only the data relay is global. */

#define RP_PEND_LIMIT (1u << 20)   /* stop reading while >1MB pending */
#define RP_POLL_MS    100          /* registration pickup bound */

struct rp_ent {
    int from, to;
    uint8_t *pend;              /* read but not yet sent; lazy alloc */
    size_t plen, pcap;
    bool from_eof;              /* recv returned 0 / error on `from` */
    bool wr_closed;             /* SHUT_WR already sent to `to` */
};

struct rp_conn {
    int c, u;
    atomic_int dirs;            /* 2 -> 0: both threads retired */
    struct rp_ent up, dn;      /* up thread owns .up, down owns .dn */
};

static struct rp_conn **g_rp_up, **g_rp_dn;
static size_t g_rp_up_n, g_rp_up_cap, g_rp_dn_n, g_rp_dn_cap;
static pthread_mutex_t g_rp_mu = PTHREAD_MUTEX_INITIALIZER;
static atomic_int g_rp_stop;

/* [prof] relay byte counters (up = client->upstream, dn = reverse) */
atomic_uint_fast64_t g_prof_rp_up_recv, g_prof_rp_up_send;
atomic_uint_fast64_t g_prof_rp_dn_recv, g_prof_rp_dn_send;
atomic_uint_fast64_t g_prof_rp_pend;   /* bytes appended to pend */
atomic_uint_fast64_t g_prof_rp_iters, g_prof_rp_poll0;   /* TEMP loop */

static bool rp_arr_add(struct rp_conn ***arr, size_t *n, size_t *cap,
                        struct rp_conn *cn)
{
    if (*n == *cap) {
        size_t nc = *cap ? *cap * 2 : 16;
        struct rp_conn **na = realloc(*arr, nc * sizeof *na);
        if (!na)
            return false;
        *arr = na;
        *cap = nc;
    }
    (*arr)[(*n)++] = cn;
    return true;
}

/* hand the connected pair to the global relay; on failure both sockets
 * are closed here and the caller must not touch them again */
static void rp_add(int c, int u)
{
    struct rp_conn *cn = calloc(1, sizeof *cn);
    if (!cn) {
        port_close(c);
        port_close(u);
        return;
    }
    cn->c = c;
    cn->u = u;
    cn->up.from = c;
    cn->up.to = u;
    cn->dn.from = u;
    cn->dn.to = c;
    atomic_store(&cn->dirs, 2);
    port_set_nonblock(c, true);
    port_set_nonblock(u, true);

    pthread_mutex_lock(&g_rp_mu);
    bool ok = rp_arr_add(&g_rp_up, &g_rp_up_n, &g_rp_up_cap, cn);
    if (ok)
        ok = rp_arr_add(&g_rp_dn, &g_rp_dn_n, &g_rp_dn_cap, cn);
    if (!ok) {
        for (size_t i = 0; i < g_rp_up_n; i++)
            if (g_rp_up[i] == cn) {
                g_rp_up[i] = g_rp_up[--g_rp_up_n];
                break;
            }
        for (size_t i = 0; i < g_rp_dn_n; i++)
            if (g_rp_dn[i] == cn) {
                g_rp_dn[i] = g_rp_dn[--g_rp_dn_n];
                break;
            }
    }
    pthread_mutex_unlock(&g_rp_mu);
    if (!ok) {
        port_close(c);
        port_close(u);
        free(cn);
        return;
    }
}

/* one direction thread retires its entry: the sockets are closed and
 * the conn freed when BOTH threads have retired. Must run under
 * g_rp_mu (the last release frees the conn, and the first release
 * must not read the atomic after that free). */
static void rp_release(struct rp_conn *cn)
{
    if (atomic_fetch_sub(&cn->dirs, 1) == 1) {
        port_close(cn->c);
        port_close(cn->u);
        free(cn->up.pend);
        free(cn->dn.pend);
        free(cn);
    }
}

static bool rp_pend(struct rp_ent *e, const uint8_t *p, size_t n)
{
    if (e->plen + n > e->pcap) {
        size_t nc = e->pcap ? e->pcap : 65536;
        while (nc < e->plen + n)
            nc *= 2;
        uint8_t *np = realloc(e->pend, nc);
        if (!np)
            return false;
        e->pend = np;
        e->pcap = nc;
    }
    memcpy(e->pend + e->plen, p, n);
    e->plen += n;
    if (atomic_load_explicit(&g_prof_on, memory_order_relaxed))
        atomic_fetch_add(&g_prof_rp_pend, (uint64_t)n);
    return true;
}

/* flush the pending buffer; on a hard send error the remaining data is
 * dropped and the entry is half-closed */
static void rp_flush(struct rp_ent *e, bool up_dir)
{
    while (e->plen > 0) {
        ssize_t w = port_send(e->to, e->pend, e->plen, 0);
        if (w > 0) {
            if (atomic_load_explicit(&g_prof_on, memory_order_relaxed))
                atomic_fetch_add(up_dir ? &g_prof_rp_up_send
                                        : &g_prof_rp_dn_send,
                                 (uint64_t)w);
            e->plen -= (size_t)w;
            memmove(e->pend, e->pend + w, e->plen);
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                      errno == EINTR))
            return;             /* retry on the next POLLOUT */
        e->plen = 0;            /* hard error: drop, half-close */
        e->from_eof = true;
        return;
    }
}

static void *rp_dir_main(void *ud)
{
    bool up_dir = ((intptr_t)ud != 0);
#ifndef _WIN32
#  ifdef __APPLE__
    pthread_setname_np(up_dir ? "relay-up" : "relay-dn");
#  else
    pthread_setname_np(pthread_self(), up_dir ? "relay-up" : "relay-dn");
#  endif
#endif
    struct rp_conn ***arrp = up_dir ? &g_rp_up : &g_rp_dn;
    size_t *np = up_dir ? &g_rp_up_n : &g_rp_dn_n;
    struct pollfd *pf = NULL;
    size_t pfcap = 0, pf_n = 0;
    int *slot_from = NULL, *slot_to = NULL;
    size_t slotcap = 0;
    bool pf_dirty = true;
    struct rp_conn **snap = NULL;
    size_t snapcap = 0;
    uint8_t buf[RP_BUF];
    static _Thread_local struct prof_state pst;
    const char *tag = up_dir ? "rp up recv" : "rp dn recv";

    while (!atomic_load(&g_rp_stop)) {
        pthread_mutex_lock(&g_rp_mu);
        size_t n = *np;
        if (n > snapcap) {
            struct rp_conn **ns = realloc(snap, n * sizeof *ns);
            if (!ns) {
                pthread_mutex_unlock(&g_rp_mu);
                return NULL;
            }
            snap = ns;
            snapcap = n;
        }
        memcpy(snap, *arrp, n * sizeof *snap);
        pthread_mutex_unlock(&g_rp_mu);

        if (n * 2 > pfcap) {
            struct pollfd *n2 = realloc(pf, (n * 2) * sizeof *n2);
            if (!n2)
                return NULL;
            pf = n2;
            pfcap = n * 2;
        }
        if (n > slotcap) {
            int *ns = realloc(slot_from, n * sizeof *ns);
            if (!ns)
                return NULL;
            slot_from = ns;
            ns = realloc(slot_to, n * sizeof *ns);
            if (!ns)
                return NULL;
            slot_to = ns;
            slotcap = n;
            pf_dirty = true;
        }
        /* cached pollset: rebuild only when an entry's registration
         * state changed (from_eof, pend crossing the cap, add/retire).
         * slot_from[i]/slot_to[i] map entry i to its pollfd index, so
         * the per-entry event lookup is O(1) instead of an O(n*k)
         * fd scan on every loop iteration. */
        if (pf_dirty) {
            size_t k = 0;
            for (size_t i = 0; i < n; i++) {
                struct rp_ent *e = up_dir ? &snap[i]->up : &snap[i]->dn;
                slot_from[i] = slot_to[i] = -1;
                if (!e->from_eof &&
                    e->plen + (size_t)RP_BUF <= RP_PEND_LIMIT) {
                    pf[k].fd = e->from;
                    pf[k].events = POLLIN;
                    pf[k].revents = 0;
                    slot_from[i] = (int)k;
                    k++;
                }
                if (e->plen > 0) {
                    pf[k].fd = e->to;
                    pf[k].events = POLLOUT;
                    pf[k].revents = 0;
                    slot_to[i] = (int)k;
                    k++;
                }
            }
            pf_n = k;
            pf_dirty = false;
        }
        int pr = port_poll(pf, pf_n, RP_POLL_MS);
        if (atomic_load_explicit(&g_prof_on, memory_order_relaxed)) {
            atomic_fetch_add(&g_prof_rp_iters, 1);
            if (pr == 0)
                atomic_fetch_add(&g_prof_rp_poll0, 1);
        }
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;              /* poll failed: stop relaying */
        }
        if (prof_print(tag, &pst,
                       up_dir ? g_prof_rp_up_recv : g_prof_rp_dn_recv)) {
            static _Thread_local struct prof_state pst2, pst3;
            prof_print(up_dir ? "rp up send" : "rp dn send", &pst2,
                       up_dir ? g_prof_rp_up_send : g_prof_rp_dn_send);
            prof_print("rp pend", &pst3, g_prof_rp_pend);
            /* %llu, never %zu: msvcrt printf (Windows) lacks %zu and
             * newer MinGW-w64 toolchains reject it under -Werror */
            fprintf(stderr, "[prof] loop iters=%llu poll0=%llu "
                    "n=%llu pfn=%llu dirty=%d\n",
                    (unsigned long long)g_prof_rp_iters,
                    (unsigned long long)g_prof_rp_poll0,
                    (unsigned long long)n, (unsigned long long)pf_n,
                    (int)pf_dirty);
        }

        for (size_t i = 0; i < n; i++) {
            struct rp_conn *cn = snap[i];
            struct rp_ent *e = up_dir ? &cn->up : &cn->dn;
            bool in = slot_from[i] >= 0 &&
                      (pf[slot_from[i]].revents &
                       (POLLIN | POLLHUP | POLLERR));
            if (in && !e->from_eof &&
                e->plen + (size_t)sizeof buf <= RP_PEND_LIMIT) {
                for (;;) {
                    /* per-pass check: the loop reads multiple chunks;
                     * stop BEFORE a read that could not fit in pend
                     * (data would have nowhere to go) */
                    if (e->plen + (size_t)sizeof buf > RP_PEND_LIMIT)
                        break;
                    ssize_t r = port_recv(e->from, buf, sizeof buf, 0);
                    if (r > 0) {
                        if (atomic_load_explicit(&g_prof_on,
                                                 memory_order_relaxed))
                            atomic_fetch_add(up_dir ? &g_prof_rp_up_recv
                                                    : &g_prof_rp_dn_recv,
                                             (uint64_t)r);
                        if (e->plen == 0) {
                            /* fast path, zero pend: write straight
                             * through. Only a partial/EAGAIN send
                             * leaves a remainder in pend (bounded —
                             * see RP_PEND_LIMIT below). Ordering is
                             * safe: pend is empty, so nothing is
                             * queued ahead of this data. */
                            size_t off = 0;
                            for (;;) {
                                ssize_t w = port_send(e->to, buf + off,
                                                      (size_t)r - off, 0);
                                if (w > 0) {
                                    off += (size_t)w;
                                    if (atomic_load_explicit(
                                            &g_prof_on,
                                            memory_order_relaxed))
                                        atomic_fetch_add(
                                            up_dir ? &g_prof_rp_up_send
                                                   : &g_prof_rp_dn_send,
                                            (uint64_t)w);
                                    if (off == (size_t)r)
                                        break;
                                    continue;
                                }
                                if (w < 0 &&
                                    (errno == EAGAIN ||
                                     errno == EWOULDBLOCK ||
                                     errno == EINTR))
                                    break;
                                e->plen = 0;   /* hard send error */
                                e->from_eof = true;
                                break;
                            }
                            if (e->from_eof)
                                break;
                            if (off < (size_t)r) {
                                size_t rem = (size_t)r - off;
                                if (e->plen + rem > RP_PEND_LIMIT)
                                    break;   /* cap: stay in the kernel
                                              * buffer (backpressure) */
                                if (!rp_pend(e, buf + off, rem)) {
                                    /* OOM: drop, half-close */
                                    e->plen = 0;
                                    e->from_eof = true;
                                    break;
                                }
                                /* `to` is congested: the remainder
                                 * goes to pend (bounded by the cap
                                 * check) and we keep reading — one
                                 * pass drains the kernel buffer, so
                                 * the read rate no longer depends on
                                 * the poll round frequency */
                            }
                        } else {
                            /* backlog: append in order, flush on
                             * POLLOUT. One chunk per pass keeps the
                             * kernel buffer as the backpressure point
                             * and pend bounded. */
                            if (e->plen + (size_t)r > RP_PEND_LIMIT)
                                break;
                            if (!rp_pend(e, buf, (size_t)r)) {
                                e->plen = 0;   /* OOM: drop, half-close */
                                e->from_eof = true;
                                break;
                            }
                        }
                        continue;
                    }
                    if (r == 0) {
                        e->from_eof = true;
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        /* drained */
                    } else if (errno == EINTR) {
                        continue;
                    } else {
                        e->from_eof = true;   /* read error: half-close */
                    }
                    break;
                }
            }
            /* rhythm optimization: flush pending data immediately
             * after the drain instead of waiting for the next poll
             * round's POLLOUT event — one poll round-trip saved per
             * chunk whenever the peer is congested (the POLLOUT
             * registration stays as the retry path for a still-full
             * peer). */
            if (e->plen > 0)
                rp_flush(e, up_dir);
        }

        /* registration-state check: pend/EOF changes alter which fds
         * need POLLIN/POLLOUT, so a stale pollset would miss POLLOUT
         * wakeups (or spin on an EOF fd). O(n) compare, rebuild only
         * on change. */
        if (!pf_dirty) {
            for (size_t i = 0; i < n; i++) {
                struct rp_ent *e = up_dir ? &snap[i]->up : &snap[i]->dn;
                bool f_need = !e->from_eof &&
                              e->plen + (size_t)RP_BUF <= RP_PEND_LIMIT;
                bool t_need = e->plen > 0;
                if (f_need != (slot_from[i] >= 0) ||
                    t_need != (slot_to[i] >= 0)) {
                    pf_dirty = true;
                    break;
                }
            }
        }
        if (n != pf_n)
            pf_dirty = true;   /* array changed: pollset is stale */
        pthread_mutex_lock(&g_rp_mu);
        for (size_t i = 0; i < n; i++) {
            struct rp_conn *cn = snap[i];
            struct rp_ent *e = up_dir ? &cn->up : &cn->dn;
            if (e->from_eof && e->plen == 0) {
                if (!e->wr_closed) {
                    port_shutdown(e->to, 1);
                    e->wr_closed = true;
                }
                for (size_t j = 0; j < *np; j++)
                    if ((*arrp)[j] == cn) {
                        (*arrp)[j] = (*arrp)[--*np];
                        break;
                    }
                rp_release(cn);
            }
        }
        pthread_mutex_unlock(&g_rp_mu);
    }
    free(pf);
    free(snap);
    free(slot_from);
    free(slot_to);
    return NULL;
}

/* per-connection accept handoff: the fd plus what the accept thread
 * already knows about the peer (heap-owned; rp_conn_main frees it on
 * every exit path) */
struct rp_conn_arg {
    int         fd;
    bool        peer_loop;   /* peer is loopback: exempt from M7 gate */
    bool        have_key;    /* fk valid (getpeername + known family) */
    rp_fail_key fk;
};

static void *rp_conn_main(void *ud)
{
    struct rp_conn_arg *ca = ud;
    int fd = ca->fd;
    struct RelayProxy *rp = g_rp_current;
    bool guard = !g_rp_ssrf_off && !ca->peer_loop;
    struct rp_hs hs;
    uint8_t first[4096];
    ssize_t n;
    int up = -1;

    /* M6b: the whole handshake draws from one absolute budget that
     * starts here (connection entry), not per read */
    rp_hs_init(&hs);

    if (rp_hs_poll(&hs, fd) <= 0)
        goto out;
    n = rp_hs_recv(&hs, fd, first, sizeof first);
    if (n <= 0)
        goto out;

    if (first[0] == 5) {
        up = rp_handle_socks(fd, first, (size_t)n, rp->token, &hs,
                             ca->have_key ? &ca->fk : NULL, guard);
    } else {
        /* parity with socks_flow: a token-requiring relay must not
         * silently accept unauthenticated HTTP traffic (HTTP clients
         * cannot do RFC1929) */
        if (rp->token)
            goto out;
        up = rp_handle_http(fd, first, (size_t)n, &hs, guard);
    }
    if (up < 0)
        goto out;

    /* handshake done here, then hand the pair to the two GLOBAL
     * direction threads. rp_add owns (or closed) both sockets from
     * now on. */
    rp_add(fd, up);
    /* M6a: success exit — this thread stops tracking the connection
     * (the global relay owns it now) */
    atomic_fetch_sub(&g_rp_conn_n, 1);
    free(ca);
    return NULL;

out:
    /* M6a: failure exit — every path through here decrements exactly
     * once (the accept thread's increment is consumed below) */
    if (up >= 0)
        port_close(up);
    port_close(fd);
    atomic_fetch_sub(&g_rp_conn_n, 1);
    free(ca);
    return NULL;
}

/* M7: is the proxy CLIENT itself on loopback? Local users keep today's
 * unfiltered behavior; only remote peers get the target gate. */
static bool rp_peer_is_loopback(const struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)ss;
        const uint8_t *p = (const uint8_t *)&a->sin_addr;
        return p[0] == 127;
    }
    if (ss->ss_family == AF_INET6) {
        static const uint8_t lo[16] = { 0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 1 };
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)ss;
        return memcmp(&a->sin6_addr, lo, 16) == 0;
    }
    return false;
}

static void *rp_accept_main(void *ud)
{
    struct RelayProxy *rp = ud;
#ifndef _WIN32
#  ifdef __APPLE__
    pthread_setname_np("rp-accept");
#  else
    pthread_setname_np(pthread_self(), "rp-accept");
#  endif
#endif
    while (!atomic_load(&rp->stop)) {
        struct pollfd pfd = { .fd = rp->listener, .events = POLLIN };
        int pr = port_poll(&pfd, 1, 1000);
        if (pr < 0 && errno != EINTR)
            break;
        if (pr <= 0)
            continue;
        int fd = port_accept(rp->listener, NULL, NULL);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            break;
        }

        /* M6c/L6: drop sources locked out for RFC1929 brute force
         * before spending a thread or a byte on them */
        struct sockaddr_storage pss;
        socklen_t pslen = sizeof pss;
        rp_fail_key fk;
        memset(&pss, 0, sizeof pss);
        bool have_key =
            getpeername(fd, (struct sockaddr *)&pss, &pslen) == 0 &&
            rp_fail_key_of(&pss, &fk);
        if (have_key && rp_fail_blocked(&fk)) {
            log_debug("rp: dropping peer (auth failure lockout)");
            port_close(fd);
            continue;
        }

        /* M6a: shed new connections once the per-connection thread
         * cap is hit — close immediately, no reply, no thread */
        if (atomic_load(&g_rp_conn_n) >= RP_MAX_CONNS) {
            log_debug("rp: connection cap %d reached, dropping",
                      RP_MAX_CONNS);
            port_close(fd);
            continue;
        }

        struct rp_conn_arg *ca = malloc(sizeof *ca);
        if (!ca) {
            port_close(fd);
            continue;
        }
        ca->fd = fd;
        ca->peer_loop = have_key && rp_peer_is_loopback(&pss);
        ca->have_key = have_key;
        ca->fk = fk;

        /* M6a: count before the spawn so concurrent accepts cannot
         * overshoot the cap; rp_conn_main decrements on every exit */
        atomic_fetch_add(&g_rp_conn_n, 1);

        pthread_t th;
        if (pthread_create(&th, NULL, rp_conn_main, ca) != 0) {
            atomic_fetch_sub(&g_rp_conn_n, 1);
            port_close(fd);
            free(ca);
            continue;
        }
        pthread_detach(th);
    }
    return NULL;
}

int relay_proxy_start(const char *listen_str, const char *auth_token,
                      bool open_proxy, bool allow_remote,
                      struct RelayProxy **out)
{
    struct RelayProxy *rp;
    struct sockaddr_in listen;
    int fd, one = 1;
    pthread_t accept_th;

    *out = NULL;
    if (!listen_str || parse_host_port(listen_str, &listen) != 0) {
        log_err("relay proxy: invalid listen address '%s'",
                listen_str ? listen_str : "");
        return -1;
    }
    bool loop = listen.sin_addr.s_addr == htonl(INADDR_LOOPBACK);
    if (!loop && !allow_remote) {
        log_err("relay proxy: refusing non-loopback bind %s; "
                "pass --allow-remote to override", listen_str);
        return -1;
    }
    if (!loop && !auth_token && !open_proxy) {
        log_err("relay proxy: --allow-remote requires --socks-token or "
                "--socks-no-token");
        return -1;
    }

    /* M7: SSRF gate opt-out (IWAN_RELAY_ALLOW_LOOPBACK=1). Read once,
     * here, strictly before any connection thread exists. */
    {
        const char *v = getenv("IWAN_RELAY_ALLOW_LOOPBACK");
        g_rp_ssrf_off = v != NULL && strcmp(v, "1") == 0;
    }

    rp = calloc(1, sizeof *rp);
    if (!rp)
        return -1;
    rp->listener = -1;
    if (auth_token)
        rp->token = xstrdup(auth_token);
    fd = port_socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        goto fail;
    port_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (port_bind(fd, (struct sockaddr *)&listen, sizeof listen) < 0) {
        log_err("relay proxy: bind %s: %s", listen_str, strerror(errno));
        port_close(fd);
        goto fail;
    }
    if (port_listen(fd, 64) < 0) {
        log_err("relay proxy: listen %s: %s", listen_str, strerror(errno));
        port_close(fd);
        goto fail;
    }
    port_set_nonblock(fd, true);
    rp->listener = fd;
    g_rp_current = rp;

    /* start the two global direction threads up front */
    atomic_store(&g_rp_stop, 0);
    pthread_t tu, td;
    if (pthread_create(&tu, NULL, rp_dir_main, (void *)(intptr_t)1) != 0 ||
        pthread_create(&td, NULL, rp_dir_main, (void *)(intptr_t)0) != 0) {
        atomic_store(&g_rp_stop, 1);
        log_err("relay proxy: relay threads: %s", strerror(errno));
        goto fail;
    }
    pthread_detach(tu);
    pthread_detach(td);

    if (pthread_create(&accept_th, NULL, rp_accept_main, rp) != 0) {
        port_close(fd);
        rp->listener = -1;
        goto fail;
    }
    pthread_detach(accept_th);
    log_info("SOCKS5+HTTP proxy on %s (follows TUN routes)", listen_str);
    *out = rp;
    return 0;

fail:
    free(rp->token);
    free(rp);
    return -1;
}

void relay_proxy_stop(struct RelayProxy *rp)
{
    if (!rp)
        return;
    atomic_store(&rp->stop, true);
    if (rp->listener >= 0) {
        port_close(rp->listener);
        rp->listener = -1;
    }
    /* the global direction threads observe stop on their next
     * poll timeout (RP_POLL_MS) */
    atomic_store(&g_rp_stop, 1);
    /* detached accept thread exits on its next poll; in-flight relay
     * threads keep their own sockets until process exit. The struct is
     * deliberately NOT freed: a live connection thread may still read
     * rp->token (one proxy per process — the leak is bounded by the
     * process lifetime). */
}
