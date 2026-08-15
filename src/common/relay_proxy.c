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

struct RelayProxy {
    int          listener;   /* -1 = stopped */
    atomic_bool  stop;
    char        *token;      /* RFC1929 password copy; NULL = no auth */
};

/* per-process current proxy (connection threads read the token copy).
 * relay_proxy_stop deliberately does NOT free the struct: detached
 * connection threads may still be reading it. One proxy per process. */
struct RelayProxy *g_rp_current;

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

static int rp_connect_target(int *fd_out, const char *host, uint16_t port,
                             bool have_ip4, const uint8_t ip4[4],
                             bool have_ip6, const uint8_t ip6[16])
{
    struct addrinfo hints, *res = NULL, *ai;
    char port_s[8];
    int last = -1;

    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    snprintf(port_s, sizeof port_s, "%u", (unsigned)port);

    if (have_ip4) {
        /* literal IPv4: connect directly, no resolution */
        return rp_connect_literal(AF_INET, ip4, port, fd_out);
    }
    if (have_ip6) {
        return rp_connect_literal(AF_INET6, ip6, port, fd_out);
    }
    /* domain: resolve, then try every address (v4 and v6) */
    if (getaddrinfo(host, port_s, &hints, &res) != 0)
        return -1;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        int fd = port_socket(ai->ai_family, SOCK_STREAM, 0);
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
        return -1;
    port_set_nonblock(last, false);   /* relay threads want blocking */
    *fd_out = last;
    return 0;
}

/* ---- SOCKS5 ---- */

static bool rp_read_full(int fd, uint8_t *buf, size_t want)
{
    size_t got = 0;
    while (got < want) {
        ssize_t r = port_recv(fd, buf + got, want - got, 0);
        if (r <= 0)
            return false;
        got += (size_t)r;
    }
    return true;
}

static void rp_socks_reply(int fd, uint8_t rep)
{
    uint8_t r[10] = {5, rep, 0, 1, 0, 0, 0, 0, 0, 0};
    (void)port_send(fd, r, sizeof r, 0);
}

/* returns 0 on success with the upstream connected; -1 on failure.
 * Frame parsing (greeting / RFC1929 / CONNECT) is delegated to
 * proto_parse.c — the same parsers as SOCKS mode. */
static int rp_handle_socks(int fd, const uint8_t *first, size_t first_n,
                           const char *token)
{
    uint8_t b[512];
    size_t n = first_n;
    pp_target t;
    uint8_t method = 0, cmd = 0, rep = 0;

    if (n < 2)
        return -1;
    memcpy(b, first, n);
    if (pp_socks_greeting(b, n, token != NULL, &method) != 0) {
        /* greeting may span reads: [5, nmethods, methods...] */
        size_t want = 2 + (size_t)b[1];
        if (want > sizeof b || !rp_read_full(fd, b + n, want - n))
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
                        ct_eq(pass, (const uint8_t *)token, tlen) == 0)
                        rr[1] = 1;
                }
                (void)port_send(fd, rr, 2, 0);
                if (rr[1] != 0)
                    return -1;
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
                ssize_t r = port_recv(fd, b + n, sizeof b - n, 0);
                if (r <= 0)
                    return -1;
                n += (size_t)r;
            }
        }
    } else {
        uint8_t ok[2] = {5, 0};
        (void)port_send(fd, ok, 2, 0);
    }

    /* CONNECT request [5, CMD, RSV, ATYP, addr..., port] */
    for (;;) {
        if (pp_socks_request(b, n, &cmd, &rep, &t) == 0)
            break;
        if (n >= sizeof b)
            return -1;
        {
            ssize_t r = port_recv(fd, b + n, sizeof b - n, 0);
            if (r <= 0)
                return -1;
            n += (size_t)r;
        }
    }
    if (rep != 0) {
        rp_socks_reply(fd, rep);
        return -1;
    }
    {
        int up = -1;
        rep = 5;
        if (rp_connect_target(&up, t.host, t.port, t.af == 4,
                              (const uint8_t *)&t.ip4, t.af == 6,
                              t.ip6) == 0) {
            rep = 0;
            rp_socks_reply(fd, rep);
            return up;           /* caller relays on fd <-> up */
        }
        rp_socks_reply(fd, rep);
        return -1;
    }
}

/* ---- HTTP ---- */

/* returns the connected upstream fd, or -1 */
static int rp_handle_http(int fd, const uint8_t *first, size_t first_n)
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
        r = port_recv(fd, buf + n, sizeof buf - 1 - n, 0);
        if (r <= 0)
            return -1;
        n += (size_t)r;
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
    if (rp_connect_target(&up, t.host, t.port, t.af == 4,
                          (const uint8_t *)&t.ip4, t.af == 6,
                          t.ip6) != 0) {
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

static void *rp_conn_main(void *ud)
{
    int fd = (int)(intptr_t)ud;
    struct RelayProxy *rp = g_rp_current;
    uint8_t first[4096];
    ssize_t n;
    int up = -1;

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    if (port_poll(&pfd, 1, RP_HANDSHAKE_TIMEOUT_MS) <= 0)
        goto out;
    n = port_recv(fd, first, sizeof first, 0);
    if (n <= 0)
        goto out;

    if (first[0] == 5)
        up = rp_handle_socks(fd, first, (size_t)n, rp->token);
    else
        up = rp_handle_http(fd, first, (size_t)n);
    if (up < 0)
        goto out;

    /* handshake done here, then hand the pair to the two GLOBAL
     * direction threads. rp_add owns (or closed) both sockets from
     * now on. */
    rp_add(fd, up);
    return NULL;

out:
    if (up >= 0)
        port_close(up);
    port_close(fd);
    return NULL;
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
        pthread_t th;
        if (pthread_create(&th, NULL, rp_conn_main,
                           (void *)(intptr_t)fd) != 0) {
            port_close(fd);
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
