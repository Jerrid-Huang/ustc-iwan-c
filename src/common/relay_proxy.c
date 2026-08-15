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
 * Thread model: one accept thread; two relay threads per connection
 * (one per direction, blocking recv/send so backpressure is handled by
 * the kernel buffers); the connection thread joins both and closes the
 * sockets. relay_proxy_stop closes the listener; live connections are
 * reaped when their sockets close at process exit.
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
#include "proto_parse.h"
#include "relay_proxy.h"
#include "util.h"

#define RP_HANDSHAKE_TIMEOUT_MS 30000u
#define RP_CONNECT_TIMEOUT_MS   10000u
#define RP_BUF                  65536

struct RelayProxy {
    int          listener;   /* -1 = stopped */
    pthread_t    accept_th;
    atomic_bool  stop;
    char        *token;      /* RFC1929 password copy; NULL = no auth */
};

/* per-process current proxy (connection threads read the token copy).
 * relay_proxy_stop deliberately does NOT free the struct: detached
 * connection threads may still be reading it. One proxy per process. */
struct RelayProxy *g_rp_current;

/* constant-time byte compare (auth token) */
static int rp_ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= a[i] ^ b[i];
    return d == 0;
}

/* ---- target resolution/connect (kernel stack) ---- */

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
        int fd = port_socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof sa);
            sa.sin_family = AF_INET;
            memcpy(&sa.sin_addr, ip4, 4);
            sa.sin_port = htons(port);
            if (port_connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0 ||
                errno == EINPROGRESS) {
                struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                if (errno == EINPROGRESS) {
                    if (port_poll(&pfd, 1, RP_CONNECT_TIMEOUT_MS) <= 0) {
                        port_close(fd);
                        return -1;
                    }
                    int soerr = 0;
                    socklen_t sl = sizeof soerr;
                    if (port_getsockopt(fd, SOL_SOCKET, SO_ERROR,
                                        &soerr, &sl) != 0 || soerr != 0) {
                        port_close(fd);
                        return -1;
                    }
                }
                *fd_out = fd;
                return 0;
            }
            port_close(fd);
        }
        return -1;
    }
    if (have_ip6) {
        int fd = port_socket(AF_INET6, SOCK_STREAM, 0);
        if (fd >= 0) {
            struct sockaddr_in6 sa;
            memset(&sa, 0, sizeof sa);
            sa.sin6_family = AF_INET6;
            memcpy(&sa.sin6_addr, ip6, 16);
            sa.sin6_port = htons(port);
            if (port_connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0 ||
                errno == EINPROGRESS) {
                struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                if (errno == EINPROGRESS) {
                    if (port_poll(&pfd, 1, RP_CONNECT_TIMEOUT_MS) <= 0) {
                        port_close(fd);
                        return -1;
                    }
                    int soerr = 0;
                    socklen_t sl = sizeof soerr;
                    if (port_getsockopt(fd, SOL_SOCKET, SO_ERROR,
                                        &soerr, &sl) != 0 || soerr != 0) {
                        port_close(fd);
                        return -1;
                    }
                }
                *fd_out = fd;
                return 0;
            }
            port_close(fd);
        }
        return -1;
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
    if (token) {
        uint8_t ok[2] = {5, 2};
        (void)port_send(fd, ok, 2, 0);
        /* RFC1929: [1, ulen, user..., plen, pass...] */
        char user[64];
        const uint8_t *pass;
        size_t plen;
        for (;;) {
            int pr = pp_socks_auth_frame(b, n, user, sizeof user,
                                         &pass, &plen);
            if (pr > 0) {
                size_t tlen = strlen(token);
                uint8_t rr[2] = {1, 0};
                if (plen != tlen ||
                    rp_ct_eq(pass, (const uint8_t *)token, tlen) == 0)
                    rr[1] = 1;
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

/* ---- connection relay ---- */

struct rp_dir {
    int from, to;
};

static void *rp_relay_dir(void *ud)
{
    struct rp_dir d = *(struct rp_dir *)ud;
    uint8_t buf[RP_BUF];
    for (;;) {
        ssize_t r = port_recv(d.from, buf, sizeof buf, 0);
        if (r <= 0)
            break;
        const uint8_t *p = buf;
        size_t left = (size_t)r;
        while (left > 0) {
            ssize_t w = port_send(d.to, p, left, 0);
            if (w <= 0)
                goto out;
            p += w;
            left -= (size_t)w;
        }
    }
out:
    port_shutdown(d.to, 1);   /* SHUT_WR: let the peer see EOF */
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

    {
        struct rp_dir d1 = { fd, up }, d2 = { up, fd };
        pthread_t t1, t2;
        if (pthread_create(&t1, NULL, rp_relay_dir, &d1) != 0)
            goto out;
        if (pthread_create(&t2, NULL, rp_relay_dir, &d2) != 0) {
            /* unwind without pthread_cancel (winpthreads): closing the
             * sockets makes the first thread's recv/send fail */
            port_shutdown(fd, 2);
            port_shutdown(up, 2);
            pthread_join(t1, NULL);
            goto out;
        }
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
    }

out:
    if (up >= 0)
        port_close(up);
    port_close(fd);
    return NULL;
}

static void *rp_accept_main(void *ud)
{
    struct RelayProxy *rp = ud;
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
    if (pthread_create(&rp->accept_th, NULL, rp_accept_main, rp) != 0) {
        port_close(fd);
        rp->listener = -1;
        goto fail;
    }
    pthread_detach(rp->accept_th);
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
    /* detached accept thread exits on its next poll; in-flight relay
     * threads keep their own sockets until process exit. The struct is
     * deliberately NOT freed: a live connection thread may still read
     * rp->token (one proxy per process — the leak is bounded by the
     * process lifetime). */
}
