/*
 * Relay RFC1929 authentication-loop test harness (root-free, no TUN).
 *
 * Regression harness for R47-FIXA-I1 (the F0 / R47-FIXA-H1 fix at
 * relay_proxy.c rp_handle_socks: `pr > 0` -> `pr == 1`).
 *
 * The existing socks_handshake harness drives socks_flow.c (the lwIP
 * SOCKS-mode netstack) and NEVER reaches the relay's own authentication
 * loop, which is exactly why the pr==2 crasher was invisible to CI. This
 * harness drives the REAL relay: it starts a real relay_proxy_start()
 * instance on 127.0.0.1 (production code: accept thread -> rp_conn_main
 * -> rp_handle_socks, the RFC1929 loop of relay_proxy.c) and then acts
 * as a real SOCKS5 client against it, speaking the wire protocol
 * byte-for-byte.
 *
 * The pr==2 case: a COMPLETE RFC1929 frame whose username length is 64
 * (0x40) fills the relay's 64-byte `user` buffer exactly. The parser
 * (pp_socks_auth_frame, proto_parse.c) returns 2 for ulen >= usz — the
 * frame is well-formed, so it is an auth attempt (R37 R1-B-5: counted in
 * the peer lockout), NOT a protocol violation. Before F0/3e7c12b the
 * relay's `if (pr > 0)` treated pr==2 as a valid frame and evaluated
 * pp_socks_auth_ok() with UNINITIALIZED pass/plen (the pr==2 branch does
 * not write them): with a token -> wild-pointer read (SEGV / ASan
 * report); without a token -> `2 + user_len + 1 + garbage_plen` memmove
 * underflow (ASan OOB / crash). On the fixed code, pr==2 lands in its
 * own counted branch: reply {1,1}, no uninitialized use, peer failure
 * counter +1.
 *
 * Cases (relay_proxy.c in the current tree; each case must run as a
 * fresh PROCESS so the file-static peer lockout table starts clean —
 * tests/relay_socks_harness.py handles that):
 *
 *   tokpr2    token mode: 5 x pr==2 -> each answers {5,2} then {1,1}
 *             (counted), then the 6th connection from the same peer
 *             (127.0.0.1) is dropped at accept() with NO reply —
 *             proving pr==2 counts toward the lockout, plus the {1,1}
 *             wire contract and (under ASan/UBSan, 434ef80) the crash.
 *   notokpr2  no-token (courtesy) mode: a pr==2 frame answers {1,1}
 *             and is still counted (no crash).
 *   pr0       token mode: 10 x malformed frame (ulen=0, R46-L4) each
 *             answers {1,1}, then an 11th connection is STILL served
 *             (not blocked) — malformed frames must NOT count.
 *
 *   http_upgrade_exempt
 *             R53-A-1: courtesy (no-token) mode, HTTP absolute-URI
 *             forward of a request with `Upgrade: websocket` +
 *             `Connection: Upgrade` through the REAL relay to a raw-TCP
 *             capture upstream; the upstream must receive the head
 *             VERBATIM — Connection: Upgrade survives, no injected
 *             Connection: close (the R52-B1 rewrite must exempt
 *             Upgrade/101 handshakes; a rewrite would make every strict
 *             origin reply 400 and kill WS-over-proxy).
 *   http_overflow_fallback
 *             R53-A-3: courtesy mode, a mixed-line-ending head (4000 x
 *             "A\n" + CRLFCRLF, 8045 B < the 8191 B handshake cap) whose
 *             exact rewritten size would exceed the conn_head buffer;
 *             the upstream must receive it VERBATIM — no truncation, no
 *             half-rewrite, no injected Connection: close (the explicit
 *             need>outcap fallback).
 *   http_space_upgrade
 *             R54-WG1-1: courtesy mode, WS absolute-URI request spelled
 *             `Upgrade : websocket` (OWS before the colon, RFC 7230
 *             §3.2-allowed and real-world reachable). The Upgrade
 *             detector must tolerate that OWS so the R53-A-1 exemption
 *             still fires: upstream receives the head VERBATIM
 *             (Connection: Upgrade preserved, no injected close) and a
 *             strict origin can answer 101.
 *   http_space_conn
 *             R54-WG1-1 (same family as R53-A-2): courtesy mode, a
 *             NON-Upgrade absolute-URI request bearing
 *             `Connection : keep-alive` (OWS before the colon). The
 *             Connection detector must tolerate that OWS in BOTH the
 *             pre-scan and the emit loop: upstream receives the exact
 *             rewrite — that line dropped, exactly ONE canonical
 *             `Connection: close` injected, never a duplicate Connection.
 *   http_space_both
 *             R54-WG1-1: courtesy mode, BOTH fields spaced
 *             (`Upgrade : websocket` + `Connection : Upgrade`); the
 *             Upgrade exemption must still fire and forward VERBATIM.
 *
 * Exit code 0 only when every step of the case passed.
 *
 * This binary exists ONLY for tests; it must never be shipped.
 */

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"       /* port.h: winsock2.h + windows.h first */
#include "relay_proxy.h"

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

static int g_fails;

static void note_ok(const char *fmt, ...)
{
    va_list ap;
    (void)fmt;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}

static void note_fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "FAIL: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    g_fails++;
}

/* ---- tiny SOCKS5 test client (loopback, blocking + recv timeout) ---- */

static int cli_connect(uint16_t port)
{
    int fd = (int)port_socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        note_fail("socket: %s", strerror(errno));
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (port_connect(fd, (const struct sockaddr *)&a, sizeof a) != 0) {
        note_fail("connect: %s", strerror(errno));
        port_close(fd);
        return -1;
    }
    /* the whole case must answer within a few seconds; a blocked peer
     * (lockout drop) answers with EOF/RST, never with {5,2} */
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    port_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return fd;
}

static int cli_send_all(int fd, const uint8_t *p, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t w = (ssize_t)port_send(fd, p + done, n - done, 0);
        if (w > 0) {
            done += (size_t)w;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        return -1;
    }
    return 0;
}

/* 1 = got exactly want bytes; 0 = EOF/error before want (peer closed,
 * e.g. the lockout drop); -1 = error */
static int cli_recv_exact(int fd, uint8_t *b, size_t want)
{
    size_t got = 0;
    while (got < want) {
        ssize_t r = (ssize_t)port_recv(fd, b + got, want - got, 0);
        if (r > 0) {
            got += (size_t)r;
            continue;
        }
        if (r == 0)
            return 0;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;   /* timeout: treat as "no reply" for blocked drop */
        return -1;
    }
    return 1;
}

/* ---- wire frames ---- */

/* GREETING: offer RFC1929 username/password only (the relay's token
 * mode picks method 2 from this; courtesy mode also takes it). */
static size_t frame_greeting(uint8_t *b)
{
    b[0] = 5; b[1] = 1; b[2] = 0x02; return 3;
}

/* RFC1929 frame with a 64-byte (0x40) username: the parser returns 2
 * (complete frame, username does not fit the 64-byte user buffer). */
static size_t frame_pr2(uint8_t *b)
{
    b[0] = 1; b[1] = 64;
    memset(b + 2, 'U', 64);
    b[66] = 2; b[67] = 'x'; b[68] = 'y';
    return 69;
}

/* RFC1929 frame with ulen=0: malformed (R46-L4), parser returns 0. */
static size_t frame_pr0(uint8_t *b)
{
    b[0] = 1; b[1] = 0; return 2;
}

/* RFC1929 frame with a small username + wrong password (pr==1) is not
 * used by the current cases (pr==2 and pr==0 cover the regressions); the
 * shared attempt()/reply machinery above would serve it unchanged. */

/* One full handshake attempt over a fresh connection: greeting then
 * `frm`/`flen`. Every served attempt answers {5,2} (method selection)
 * first and then the 2-byte auth reply. `want_reply` is the expected
 * auth reply, or NULL when the peer is expected to be lockout-dropped
 * (no {5,2}, no reply at all). Returns 0 on expected behaviour, -1
 * otherwise. */
static int attempt(uint16_t port, const uint8_t *frm, size_t flen,
                   const uint8_t *want_reply, const char *what)
{
    int fd = cli_connect(port);
    if (fd < 0)
        return -1;
    uint8_t g[8];
    size_t gl = frame_greeting(g);
    int send_err = (cli_send_all(fd, g, gl) != 0 ||
                    cli_send_all(fd, frm, flen) != 0);
    if (send_err && want_reply) {
        /* served peer: the connection must stay healthy; a send error
         * there is a real failure */
        note_fail("%s: send failed", what);
        port_close(fd);
        return -1;
    }
    if (send_err) {
        /* drop case: the server's lockout close() happens right after
         * accept(), so its RST can be observed on send() instead of
         * recv() when the two race. A send error before any reply is
         * still the drop (the client never sees {5,2}); only a complete
         * reply proves the peer was served, and that is checked below. */
        note_ok("PASS %s: dropped (RST raced the send)", what);
        port_close(fd);
        return 0;
    }
    uint8_t r[8];
    int bad = 0;
    if (want_reply) {
        static const uint8_t sel[2] = {5, 2};
        /* method selection first, then the auth verdict */
        int rv = cli_recv_exact(fd, r, 2);
        if (rv == 1 && r[0] == sel[0] && r[1] == sel[1]) {
            rv = cli_recv_exact(fd, r, 2);
            if (rv == 1 && r[0] == want_reply[0] && r[1] == want_reply[1]) {
                note_ok("PASS %s: reply {%d,%d}",
                        what, want_reply[0], want_reply[1]);
            } else {
                note_fail("%s: expected {%d,%d} auth reply, got rv=%d "
                          "r={%d,%d}",
                          what, want_reply[0], want_reply[1], rv, r[0], r[1]);
                bad = 1;
            }
        } else {
            note_fail("%s: expected {5,2} method selection, got rv=%d "
                      "r={%d,%d}", what, rv, r[0], r[1]);
            bad = 1;
        }
    } else {
        /* blocked peer: dropped at accept() (port_close on the accepted
         * fd) -> the client sees EOF (0), ECONNRESET (-1) or a recv
         * timeout (0) — never the {5,2}+{1,1} replies. Only a full
         * 2-byte reply proves the peer was served. */
        int rv = cli_recv_exact(fd, r, 2);
        if (rv != 1) {
            note_ok("PASS %s: dropped (no reply, recv=%d%s)", what,
                    rv, rv == -1 ? " ECONNRESET" : "");
        } else {
            note_fail("%s: peer answered (r={%d,%d}) but should be blocked",
                      what, r[0], r[1]);
            bad = 1;
        }
    }
    port_close(fd);
    return bad;
}

/* ---- R53-A-1 / R53-A-3: raw-TCP capture upstream for the HTTP
 * absolute-URI forward path.
 *
 * The harness has no capture-upstream mode, so the case itself IS the
 * upstream: a plain loopback TCP server the relay connects to (the
 * authority in the forwarded request's absolute URI) that accepts one
 * connection and captures every byte the relay forwards. Everything here
 * is blocking and runs on the harness thread while the REAL relay works
 * in its own threads — there is no cross-thread state to share.
 *
 * Both HTTP cases run in courtesy (token = NULL) mode: a token-mode
 * relay refuses plain HTTP (HTTP clients cannot do RFC1929; see
 * rp_conn_main). */

static int cap_upstream_listen(uint16_t *port_out)
{
    int fd = (int)port_socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        note_fail("cap: upstream socket: %s", strerror(errno));
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (port_bind(fd, (const struct sockaddr *)&a, sizeof a) != 0) {
        note_fail("cap: upstream bind: %s", strerror(errno));
        port_close(fd);
        return -1;
    }
    socklen_t al = sizeof a;
    if (getsockname(PORT_FD_ARG(fd), (struct sockaddr *)&a, &al) != 0) {
        note_fail("cap: upstream getsockname: %s", strerror(errno));
        port_close(fd);
        return -1;
    }
    *port_out = (uint16_t)ntohs(a.sin_port);
    if (port_listen(fd, 2) != 0) {
        note_fail("cap: upstream listen: %s", strerror(errno));
        port_close(fd);
        return -1;
    }
    return fd;
}

/* Accept the relay's outbound connection and read everything it
 * forwards. Returns 0 with a heap copy in *out / *out_n, or -1. The relay
 * connects promptly after parsing the request head (10 s poll cap turns
 * a relay/forward failure into a clean FAIL, not a hang). After the head
 * the relay keeps the duplex pipe OPEN (no EOF), so capture ends on a
 * quiet recv: a full timeout with no more data means everything arrived
 * (the cases below forward one request head in a single burst). */
static int cap_upstream_capture(int lfd, uint8_t **out, size_t *out_n)
{
    struct pollfd pfd = { .fd = PORT_FD_ARG(lfd), .events = POLLIN };
    int pr = port_poll(&pfd, 1, 10000);
    if (pr <= 0) {
        note_fail("cap: upstream accept: relay never connected "
                  "(poll rc=%d %s)", pr, strerror(errno));
        return -1;
    }
    int cfd = port_accept(lfd, NULL, NULL);
    if (cfd < 0) {
        note_fail("cap: upstream accept: %s", strerror(errno));
        return -1;
    }
    struct timeval rtv = { .tv_sec = 2, .tv_usec = 0 };
    port_setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof rtv);

    size_t cap = 8192, n = 0;
    uint8_t *b = (uint8_t *)malloc(cap);
    if (!b) {
        note_fail("cap: malloc(%zu) failed", cap);
        port_close(cfd);
        return -1;
    }
    for (;;) {
        if (n == cap) {
            size_t ncap = cap * 2;
            uint8_t *nb = (uint8_t *)realloc(b, ncap);
            if (!nb) {
                note_fail("cap: realloc(%zu) failed", ncap);
                free(b);
                port_close(cfd);
                return -1;
            }
            b = nb;
            cap = ncap;
        }
        ssize_t r = (ssize_t)port_recv(cfd, b + n, cap - n, 0);
        if (r > 0) {
            n += (size_t)r;
            continue;
        }
        if (r == 0)
            break;   /* relay closed its upstream side (not expected) */
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT)
            break;   /* quiet: capture complete */
        note_fail("cap: upstream recv: %s", strerror(errno));
        free(b);
        port_close(cfd);
        return -1;
    }
    port_close(cfd);
    *out = b;
    *out_n = n;
    return 0;
}

static bool mem_contains(const uint8_t *hay, size_t hn, const char *needle)
{
    size_t nn = strlen(needle);
    if (nn == 0 || nn > hn)
        return false;
    for (size_t i = 0; i + nn <= hn; i++) {
        if (memcmp(hay + i, needle, nn) == 0)
            return true;
    }
    return false;
}

/* ---- relay instance management ---- */

static uint16_t pick_port(void)
{
    int fd = (int)port_socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (port_bind(fd, (const struct sockaddr *)&a, sizeof a) != 0) {
        fprintf(stderr, "harness: probe bind failed\n");
        exit(2);
    }
    socklen_t al = sizeof a;
    if (getsockname(PORT_FD_ARG(fd), (struct sockaddr *)&a, &al) != 0) {
        fprintf(stderr, "harness: probe getsockname failed\n");
        exit(2);
    }
    port_close(fd);
    return (uint16_t)ntohs(a.sin_port);
}

static struct RelayProxy *relay_start(const char *token, uint16_t port)
{
    char listen[64];
    snprintf(listen, sizeof listen, "127.0.0.1:%u", (unsigned)port);
    struct RelayProxy *rp = NULL;
    if (relay_proxy_start(listen, token, false, false, &rp) != 0 || !rp) {
        fprintf(stderr, "harness: relay_proxy_start(%s) failed\n", listen);
        return NULL;
    }
    return rp;
}

/* ---- cases (each in a fresh process: static lockout table is clean) ---- */

static int case_tokpr2(const char *token, uint16_t port)
{
    struct RelayProxy *rp = relay_start(token, port);
    if (!rp)
        return 1;
    uint8_t f[128];
    size_t fl = frame_pr2(f);
    static const uint8_t fail11[2] = {1, 1};
    int bad = 0;
    for (int i = 1; i <= 5; i++) {
        char what[64];
        snprintf(what, sizeof what, "tokpr2 failure #%d (pr==2 counted)", i);
        if (attempt(port, f, fl, fail11, what) != 0)
            bad = 1;
    }
    /* 6th connection from the same peer must be lockout-dropped */
    if (attempt(port, f, fl, NULL, "tokpr2 6th attempt (lockout drop)") != 0)
        bad = 1;
    relay_proxy_stop(rp);
    printf("RESULT tokpr2: %s\n", bad ? "FAIL" : "PASS");
    return bad;
}

static int case_notokpr2(uint16_t port)
{
    struct RelayProxy *rp = relay_start(NULL, port);   /* courtesy mode */
    if (!rp)
        return 1;
    uint8_t f[128];
    size_t fl = frame_pr2(f);
    static const uint8_t fail11[2] = {1, 1};
    int bad = 0;
    if (attempt(port, f, fl, fail11, "notok pr==2 (courtesy, counted)") != 0)
        bad = 1;
    relay_proxy_stop(rp);
    printf("RESULT notokpr2: %s\n", bad ? "FAIL" : "PASS");
    return bad;
}

static int case_pr0(const char *token, uint16_t port)
{
    struct RelayProxy *rp = relay_start(token, port);
    if (!rp)
        return 1;
    uint8_t f[128];
    size_t fl = frame_pr0(f);
    static const uint8_t fail11[2] = {1, 1};
    int bad = 0;
    for (int i = 1; i <= 10; i++) {
        char what[64];
        snprintf(what, sizeof what, "pr0 malformed #%d (not counted)", i);
        if (attempt(port, f, fl, fail11, what) != 0)
            bad = 1;
    }
    /* 10 malformed frames must NOT trip the lockout: an 11th connection
     * with a mismatched-token frame is still served a {1,1} reply. */
    if (attempt(port, f, fl, fail11,
                "pr0 11th attempt (peer NOT blocked)") != 0)
        bad = 1;
    relay_proxy_stop(rp);
    printf("RESULT pr0: %s\n", bad ? "FAIL" : "PASS");
    return bad;
}

/* R53-A-1: an Upgrade request must be forwarded verbatim — the R52-B1
 * `Connection: close` rewrite would corrupt a 101 handshake (a compliant
 * origin only answers 101 to a request that still bears
 * `Connection: Upgrade`). The upstream must see the client's exact head:
 * `Connection: Upgrade` preserved, no injected/rewritten close. */
static int case_http_upgrade_exempt(uint16_t port)
{
    uint16_t uport = 0;
    int lfd = cap_upstream_listen(&uport);
    if (lfd < 0)
        return 1;
    struct RelayProxy *rp = relay_start(NULL, port);   /* courtesy mode */
    if (!rp) {
        port_close(lfd);
        return 1;
    }
    char head[512];
    size_t hlen = (size_t)snprintf(
        head, sizeof head,
        "GET http://127.0.0.1:%u/u HTTP/1.1\r\n"
        "Host: u.local\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "\r\n", (unsigned)uport);
    int bad = 1;
    int fd = cli_connect(port);
    if (fd < 0) {
        note_fail("http_upgrade_exempt: relay connect failed");
    } else {
        if (cli_send_all(fd, (const uint8_t *)head, hlen) != 0) {
            note_fail("http_upgrade_exempt: head send failed");
        } else {
            uint8_t *up = NULL;
            size_t upn = 0;
            int cr = cap_upstream_capture(lfd, &up, &upn);
            if (cr != 0) {
                note_fail("http_upgrade_exempt: upstream capture failed");
            } else if (upn == hlen && memcmp(up, head, hlen) == 0) {
                note_ok("PASS http_upgrade_exempt: upstream got the %zu-byte "
                        "head VERBATIM: Connection: Upgrade preserved, "
                        "no Connection: close injected", upn);
                bad = 0;
            } else {
                note_fail("http_upgrade_exempt: upstream got %zu bytes, "
                          "expected %zu verbatim (Connection: Upgrade=%d, "
                          "Connection: close=%d)",
                          upn, hlen,
                          mem_contains(up, upn, "Connection: Upgrade"),
                          mem_contains(up, upn, "Connection: close"));
            }
            free(up);
        }
        port_close(fd);
    }
    relay_proxy_stop(rp);
    port_close(lfd);
    printf("RESULT http_upgrade_exempt: %s\n", bad ? "FAIL" : "PASS");
    return bad;
}

/* R53-A-3: a mixed-line-ending head whose exact rewritten size would
 * exceed conn_head (8224) is forwarded verbatim. 4000 x "A\n" lines give
 * a ~8045 B head that fits the relay's 8191 B handshake cap, but the
 * lone-\n -> \r\n rewrite needs ~12 KiB out; the exact `need` precompute
 * detects the overflow and falls back to the ORIGINAL head, never a
 * truncated / half-rewritten / close-injected stream. */
static int case_http_overflow_fallback(uint16_t port)
{
    uint16_t uport = 0;
    int lfd = cap_upstream_listen(&uport);
    if (lfd < 0)
        return 1;
    struct RelayProxy *rp = relay_start(NULL, port);   /* courtesy mode */
    if (!rp) {
        port_close(lfd);
        return 1;
    }
    char head[9000];
    size_t o = (size_t)snprintf(
        head, sizeof head,
        "GET http://127.0.0.1:%u/ooo HTTP/1.1\r\n", (unsigned)uport);
    for (int i = 0; i < 4000; i++) {
        head[o++] = 'A';
        head[o++] = '\n';
    }
    memcpy(head + o, "\r\n\r\n", 4);
    o += 4;
    size_t hlen = o;
    if (hlen >= 8191) {
        /* the case must exercise the fallback, not the 431 over-cap path */
        note_fail("http_overflow_fallback: head too long (%zu >= 8191)",
                  hlen);
        relay_proxy_stop(rp);
        port_close(lfd);
        return 1;
    }
    int bad = 1;
    int fd = cli_connect(port);
    if (fd < 0) {
        note_fail("http_overflow_fallback: relay connect failed");
    } else {
        if (cli_send_all(fd, (const uint8_t *)head, hlen) != 0) {
            note_fail("http_overflow_fallback: head send failed");
        } else {
            uint8_t *up = NULL;
            size_t upn = 0;
            int cr = cap_upstream_capture(lfd, &up, &upn);
            if (cr != 0) {
                note_fail("http_overflow_fallback: upstream capture failed");
            } else if (upn == hlen && memcmp(up, head, hlen) == 0) {
                note_ok("PASS http_overflow_fallback: %zu-byte mixed-EOL "
                        "head forwarded VERBATIM (need>outcap explicit "
                        "fallback: no truncation, no half-rewrite, no "
                        "Connection: close)", upn);
                bad = 0;
            } else {
                note_fail("http_overflow_fallback: upstream got %zu bytes, "
                          "expected %zu verbatim (Connection: close=%d)",
                          upn, hlen,
                          mem_contains(up, upn, "Connection: close"));
            }
            free(up);
        }
        port_close(fd);
    }
    relay_proxy_stop(rp);
    port_close(lfd);
    printf("RESULT http_overflow_fallback: %s\n", bad ? "FAIL" : "PASS");
    return bad;
}

/* R54-WG1-1: `Upgrade : websocket` — RFC 7230 §3.2 lets a sender place
 * optional whitespace (OWS: SP/HTAB) between the field name and the
 * colon, and real clients do. The R53-A-1 upgrade detector used to
 * require the colon at exactly index 7, so this spelling escaped the
 * exemption and the R52-B1 rewrite dropped `Connection: Upgrade` while
 * injecting `Connection: close` — a strict RFC 7230 §6.7 origin then
 * answers 400 and the WS-over-proxy handshake dies. The upstream must
 * receive the client's exact head VERBATIM. */
static int case_http_space_upgrade(uint16_t port)
{
    uint16_t uport = 0;
    int lfd = cap_upstream_listen(&uport);
    if (lfd < 0)
        return 1;
    struct RelayProxy *rp = relay_start(NULL, port);   /* courtesy mode */
    if (!rp) {
        port_close(lfd);
        return 1;
    }
    char head[512];
    size_t hlen = (size_t)snprintf(
        head, sizeof head,
        "GET http://127.0.0.1:%u/chat HTTP/1.1\r\n"
        "Host: ws.local\r\n"
        "Upgrade : websocket\r\n"
        "Connection: Upgrade\r\n"
        "\r\n", (unsigned)uport);
    int bad = 1;
    int fd = cli_connect(port);
    if (fd < 0) {
        note_fail("http_space_upgrade: relay connect failed");
    } else {
        if (cli_send_all(fd, (const uint8_t *)head, hlen) != 0) {
            note_fail("http_space_upgrade: head send failed");
        } else {
            uint8_t *up = NULL;
            size_t upn = 0;
            int cr = cap_upstream_capture(lfd, &up, &upn);
            if (cr != 0) {
                note_fail("http_space_upgrade: upstream capture failed");
            } else if (upn == hlen && memcmp(up, head, hlen) == 0) {
                note_ok("PASS http_space_upgrade: upstream got the "
                        "%zu-byte head VERBATIM despite `Upgrade :` OWS: "
                        "Connection: Upgrade preserved, no Connection: "
                        "close injected", upn);
                bad = 0;
            } else {
                note_fail("http_space_upgrade: upstream got %zu bytes, "
                          "expected %zu verbatim (Connection: "
                          "Upgrade=%d, Connection: close=%d)",
                          upn, hlen,
                          mem_contains(up, upn, "Connection: Upgrade"),
                          mem_contains(up, upn, "Connection: close"));
            }
            free(up);
        }
        port_close(fd);
    }
    relay_proxy_stop(rp);
    port_close(lfd);
    printf("RESULT http_space_upgrade: %s\n", bad ? "FAIL" : "PASS");
    return bad;
}

/* R54-WG1-1 (same family as R53-A-2): a NON-Upgrade absolute-URI request
 * whose Connection field carries OWS before the colon (`Connection :
 * keep-alive`). Both the pre-scan and the emit loop used to require the
 * colon at exactly index 10, so this spelling was NOT recognized as a
 * Connection field: the original line was forwarded unchanged AND a
 * second `Connection: close` was appended — two Connection headers on
 * the wire (per RFC 7230 §3.2 a field name is a single token; a proxy
 * MUST NOT forward a duplicate Connection field family). The rewrite must
 * drop the OWS-spelled line and inject exactly ONE canonical
 * `Connection: close`. */
static int case_http_space_conn(uint16_t port)
{
    uint16_t uport = 0;
    int lfd = cap_upstream_listen(&uport);
    if (lfd < 0)
        return 1;
    struct RelayProxy *rp = relay_start(NULL, port);   /* courtesy mode */
    if (!rp) {
        port_close(lfd);
        return 1;
    }
    char head[512];
    size_t hlen = (size_t)snprintf(
        head, sizeof head,
        "GET http://127.0.0.1:%u/connsp HTTP/1.1\r\n"
        "Host: conn.local\r\n"
        "Connection : keep-alive\r\n"
        "\r\n", (unsigned)uport);
    /* the exact expected rewrite: the `Connection : keep-alive` line is
     * dropped and ONE canonical `Connection: close` replaces the blank
     * line before the terminator */
    char want[512];
    size_t wlen = (size_t)snprintf(
        want, sizeof want,
        "GET http://127.0.0.1:%u/connsp HTTP/1.1\r\n"
        "Host: conn.local\r\n"
        "Connection: close\r\n"
        "\r\n", (unsigned)uport);
    int bad = 1;
    int fd = cli_connect(port);
    if (fd < 0) {
        note_fail("http_space_conn: relay connect failed");
    } else {
        if (cli_send_all(fd, (const uint8_t *)head, hlen) != 0) {
            note_fail("http_space_conn: head send failed");
        } else {
            uint8_t *up = NULL;
            size_t upn = 0;
            int cr = cap_upstream_capture(lfd, &up, &upn);
            if (cr != 0) {
                note_fail("http_space_conn: upstream capture failed");
            } else if (upn == wlen && memcmp(up, want, wlen) == 0) {
                note_ok("PASS http_space_conn: `Connection : keep-alive` "
                        "dropped, exactly one canonical `Connection: "
                        "close` injected (%zu-byte rewrite, no duplicate "
                        "Connection)", upn);
                bad = 0;
            } else {
                note_fail("http_space_conn: upstream got %zu bytes, "
                          "expected the %zu-byte rewrite (kept `Connection "
                          ": keep-alive`=%d, `Connection: close`=%d)",
                          upn, wlen,
                          mem_contains(up, upn, "Connection : keep-alive"),
                          mem_contains(up, upn, "Connection: close"));
            }
            free(up);
        }
        port_close(fd);
    }
    relay_proxy_stop(rp);
    port_close(lfd);
    printf("RESULT http_space_conn: %s\n", bad ? "FAIL" : "PASS");
    return bad;
}

/* R54-WG1-1: BOTH header fields carry OWS before the colon. The Upgrade
 * exemption must still fire (verbatim forward) — if either detector
 * missed its spelling, the rewrite would drop `Connection : Upgrade`
 * and inject `Connection: close`, corrupting the 101 handshake. */
static int case_http_space_both(uint16_t port)
{
    uint16_t uport = 0;
    int lfd = cap_upstream_listen(&uport);
    if (lfd < 0)
        return 1;
    struct RelayProxy *rp = relay_start(NULL, port);   /* courtesy mode */
    if (!rp) {
        port_close(lfd);
        return 1;
    }
    char head[512];
    size_t hlen = (size_t)snprintf(
        head, sizeof head,
        "GET http://127.0.0.1:%u/chat HTTP/1.1\r\n"
        "Host: ws.local\r\n"
        "Upgrade : websocket\r\n"
        "Connection : Upgrade\r\n"
        "\r\n", (unsigned)uport);
    int bad = 1;
    int fd = cli_connect(port);
    if (fd < 0) {
        note_fail("http_space_both: relay connect failed");
    } else {
        if (cli_send_all(fd, (const uint8_t *)head, hlen) != 0) {
            note_fail("http_space_both: head send failed");
        } else {
            uint8_t *up = NULL;
            size_t upn = 0;
            int cr = cap_upstream_capture(lfd, &up, &upn);
            if (cr != 0) {
                note_fail("http_space_both: upstream capture failed");
            } else if (upn == hlen && memcmp(up, head, hlen) == 0) {
                note_ok("PASS http_space_both: upstream got the "
                        "%zu-byte head VERBATIM (Upgrade + Connection both "
                        "spelled with OWS; exemption still fires, no "
                        "rewrite)", upn);
                bad = 0;
            } else {
                note_fail("http_space_both: upstream got %zu bytes, "
                          "expected %zu verbatim (Connection: "
                          "Upgrade=%d, Connection: close=%d)",
                          upn, hlen,
                          mem_contains(up, upn, "Connection: Upgrade"),
                          mem_contains(up, upn, "Connection: close"));
            }
            free(up);
        }
        port_close(fd);
    }
    relay_proxy_stop(rp);
    port_close(lfd);
    printf("RESULT http_space_both: %s\n", bad ? "FAIL" : "PASS");
    return bad;
}

int main(int argc, char **argv)
{
    const char *token = NULL;
    const char *casename = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            token = argv[++i];
        } else if (strcmp(argv[i], "--case") == 0 && i + 1 < argc) {
            casename = argv[++i];
        } else {
            fprintf(stderr, "usage: %s --case tokpr2|notokpr2|pr0|"
                    "http_upgrade_exempt|http_overflow_fallback|"
                    "http_space_upgrade|http_space_conn|http_space_both "
                    "[--token STR]\n", argv[0]);
            return 2;
        }
    }
    if (!casename) {
        fprintf(stderr, "harness: --case required\n");
        return 2;
    }
    if (strcmp(casename, "notokpr2") != 0 &&
        strcmp(casename, "http_upgrade_exempt") != 0 &&
        strcmp(casename, "http_overflow_fallback") != 0 &&
        strcmp(casename, "http_space_upgrade") != 0 &&
        strcmp(casename, "http_space_conn") != 0 &&
        strcmp(casename, "http_space_both") != 0 && !token) {
        fprintf(stderr, "harness: --token required for --case %s\n",
                casename);
        return 2;
    }

    port_socket_init();   /* WSAStartup on Windows; no-op on Linux */
    /* a lockout drop closes the connection mid-handshake: a send() on
     * the RST-ed socket must not kill the harness with SIGPIPE (Windows
     * has no SIGPIPE — port_ignore_sigpipe is a no-op there) */
    port_ignore_sigpipe();

    uint16_t port = pick_port();
    printf("LISTEN 127.0.0.1:%u\n", (unsigned)port);
    fflush(stdout);

    int rc = 0;
    if (strcmp(casename, "tokpr2") == 0)
        rc = case_tokpr2(token, port);
    else if (strcmp(casename, "notokpr2") == 0)
        rc = case_notokpr2(port);
    else if (strcmp(casename, "pr0") == 0)
        rc = case_pr0(token, port);
    else if (strcmp(casename, "http_upgrade_exempt") == 0)
        rc = case_http_upgrade_exempt(port);
    else if (strcmp(casename, "http_overflow_fallback") == 0)
        rc = case_http_overflow_fallback(port);
    else if (strcmp(casename, "http_space_upgrade") == 0)
        rc = case_http_space_upgrade(port);
    else if (strcmp(casename, "http_space_conn") == 0)
        rc = case_http_space_conn(port);
    else if (strcmp(casename, "http_space_both") == 0)
        rc = case_http_space_both(port);
    else {
        fprintf(stderr, "harness: unknown case '%s'\n", casename);
        return 2;
    }
    return rc == 0 ? 0 : 1;
}
