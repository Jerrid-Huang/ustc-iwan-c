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
 * relay_proxy_stop closes the listener; every connection is closed
 * and freed when both direction threads retire it (in_use reference
 * drops to zero), not just at process exit.
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
#include <sys/resource.h>
#include <sys/socket.h>
#endif

#include "addr.h"
#include "common.h"
#include "crypto.h"
#include "port.h"
#include "profile.h"
#include "proto_parse.h"
#include "lockout.h"
#include "relay_proxy.h"
#include "util.h"

#define RP_HANDSHAKE_TIMEOUT_MS 30000u
#define RP_CONNECT_TIMEOUT_MS   10000u
#define RP_BUF                  65536
/* M6a: cap on concurrent per-connection threads. Each accepted
 * connection runs its handshake on its own thread; beyond this cap
 * the accept thread sheds the new connection (close, no thread). */
#define RP_MAX_CONNS            256
/* R37 R1-B-2: cap on ESTABLISHED relayed connections (the handshake-thread
 * cap above is released as soon as a connection is handed to the relay, so
 * it never bounded the fd count). Two fds per connection + up to ~1 MiB
 * pend each, so this is the real fd-pressure bound; excess connections are
 * refused with a log line rather than silently black-holed. */
#define RP_MAX_ESTABLISHED      (RP_MAX_CONNS * 2)

struct RelayProxy {
    _Atomic int  listener;   /* -1 = stopped; written by stop/accept threads (R20 atomic) */
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

/* R37 R1-B-2: number of ESTABLISHED relayed connections (incremented by
 * rp_add once the pair is reserved, decremented when the rp_conn is
 * closed and freed in rp_reap_maybe, or on every rp_add failure path). */
static atomic_int g_rp_est_n;

/* R37 R5 (R3-L22): effective cap on the ESTABLISHED set. The compile-time
 * value (RP_MAX_ESTABLISHED) is only reachable when the process can hold
 * the whole handshake set at the same time as the established set:
 * RP_MAX_CONNS handshake threads, each holding an accepted fd plus —
 * while rp_connect_target runs — a second one (2*RP_MAX_CONNS fds), plus a
 * small working reserve. Under the common soft RLIMIT_NOFILE=1024 the old
 * fixed cap was unreachable: EMFILE arrived first and the client saw a
 * dropped handshake or a rep=5/502 instead of the intended "relay full"
 * refusal. relay_proxy_start() lowers g_rp_max_est to what the current
 * limit can actually hold and records the effective value; it is never
 * raised above the reviewed compile-time cap. */
/* R37 R6 (R6-M1) / R34-A2-1: RP_FD_RESERVE is an UPPER BOUND on the
 * reserve, NOT a fixed deduction. The R5 derivation subtracted the full
 * worst-case reserve (2*RP_MAX_CONNS + 64 = 576 fds) from every limit,
 * so any RLIMIT_NOFILE <= 578 collapsed the effective cap to 1
 * (measured cap=1/1/224/512 at ulimit -n 256/512/1024/4096): the first
 * established connection filled the relay and every later CONNECT got
 * rep=1 (SOCKS) or 503 (HTTP). macOS ships a default soft
 * RLIMIT_NOFILE of 256 and hardened Linux images 512, so that was the
 * COMMON case, not an edge case. relay_proxy_start() now scales the
 * reserve with the granted limit: limit/4, clamped at the ceiling
 * RP_FD_RESERVE, with a floor of min(lim/2, 2*RP_MAX_CONNS) —
 * R34-A2-1 — so the floor itself always fits the limit and a small
 * limit keeps a usable cap (lim=256 -> cap 64, lim=512 -> cap 128,
 * instead of the R33-B2-L2 collapse to 1). For
 * lim >= 2*RP_MAX_CONNS the reserve covers the whole instantaneous
 * handshake set and the "never overspend" bound is exact: established
 * (<= 2*room = lim - reserve) plus a full instantaneous handshake set
 * (<= reserve) can never exceed the limit, so no transient EMFILE
 * arises from fd pressure. For lim < 2*RP_MAX_CONNS the limit cannot
 * hold a full handshake set at all; the reserve takes
 * min(lim/2, 2*RP_MAX_CONNS), established + reserve <= lim stays exact
 * (2*room = lim - reserve), so the established set is never trimmed —
 * but a same-instant full handshake burst can still EMFILE. That
 * window is physically unavoidable below 2*RP_MAX_CONNS and self-heals
 * (the burst is momentary; the next poll/accept round has fds again);
 * the cap stays usable, which is the R6-M1 intent. */
#define RP_FD_RESERVE (2 * RP_MAX_CONNS + 64)
static int g_rp_max_est = RP_MAX_ESTABLISHED;

/* R37 R5 (R3-L21, R3-L22): the relay's refusal notices used to be one line
 * per connection, so a full relay (or a dead data plane) could be driven
 * into writing stderr at connection rate. Allow one line per second per
 * site — the same shape as the listener poll/accept warnings below.
 * now_ms() is monotonic 64-bit milliseconds, so the unsigned difference
 * cannot wrap.
 * R37 R6 (R6-4): the latch is a _Atomic uint64_t with relaxed load/store
 * — the same idiom as last_spawn_warn_ms below. The plain static it used
 * to be was a real data race (TSan): rp_note_est_full/rp_note_plane_down
 * are reached from every connection thread at once. Two racers may still
 * each print once inside the same second, which is harmless — the bound
 * is what matters. */
static bool rp_note_due(_Atomic uint64_t *last_ms)
{
    uint64_t now = now_ms();
    if (now - atomic_load_explicit(last_ms, memory_order_relaxed) < 1000)
        return false;
    atomic_store_explicit(last_ms, now, memory_order_relaxed);
    return true;
}

static void rp_note_est_full(void)
{
    static _Atomic uint64_t last_ms;
    if (rp_note_due(&last_ms))
        log_err("rp: relay connection limit %d reached, refusing connection",
                g_rp_max_est);
}

static void rp_note_plane_down(void)
{
    static _Atomic uint64_t last_ms;
    if (rp_note_due(&last_ms))
        log_err("rp: relay data plane is down (a direction thread "
                "exited); refusing new connection");
}

/* R37 R7 (R3-L21): take a slot in the established-connection set BEFORE any
 * success byte goes out, so a client that is told rep=0/200 really has a
 * slot. The R5 read-only pre-check (rp_est_full()) narrowed the window but
 * left it open: N threads could all read n < cap, only one could then win
 * the slot in rp_add(), and the losers had already answered "success" —
 * measured as "answered rep=0, then the pair is closed" (R6-A/R6-I).
 *
 * Returns true when a slot was taken; the caller MUST then either hand the
 * reservation to rp_add() (success) or release it (every failure path).
 * The release is centralised: rp_handle_socks()/rp_handle_http() only set
 * hs->reserved and rp_conn_main()'s `out:` label rolls it back, so a new
 * `return -1` inside a handler cannot forget it (5 scattered rollback
 * points were the R6 draft's main risk: one missed release = a permanent
 * count leak = every later connection refused). */
static bool rp_est_reserve(void)
{
    int n = atomic_load(&g_rp_est_n);

    while (n < g_rp_max_est) {
        if (atomic_compare_exchange_weak(&g_rp_est_n, &n, n + 1))
            return true;
        /* n was refreshed with the current value by the failed CAS */
    }
    return false;
}

/* Release a reservation that rp_add() did not consume.
 *
 * R38 (R8-P2-3): the caller's `reserved` token is one-shot — rp_add()
 * consumes it when it takes ownership and rp_conn_main()'s `out:` clears it
 * before releasing — so this decrement runs at most once per reservation.
 *
 * Deliberately NOT clamped at zero: a clamp would keep the counter from
 * going negative, but it cannot restore the cap (a success-path extra
 * release under-counts by one per connection, so the counter sits at 0
 * while the live set keeps growing) and it would blind the regression
 * sentinels that detect exactly that. Keep MINEST>=0, MAXEST<=cap and
 * REP0<=cap (WG-A3 F2 measured a double release admitting 116 concurrent
 * connections at cap=96 while the POST probe stayed green; REP0>cap is the
 * only client-visible signature of that class of bug). */
static void rp_est_release(void)
{
    atomic_fetch_sub(&g_rp_est_n, 1);
}

/* R12-T2 (R41-3-1): data-plane liveness gate for the SUCCESS reply.
 * Defined below (needs the g_rp_gen/g_rp_dir_dead_gen globals); declared
 * here so rp_handle_socks()/rp_handle_http() can refuse BEFORE rep=0/200
 * goes out. */
static bool rp_plane_dead(void);

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
    /* R37 R7 (R3-L21): set once rp_est_reserve() has taken a slot in
     * g_rp_est_n for THIS connection. rp_conn_main's `out:` label is the
     * single choke point that rolls it back when the handshake fails
     * after the slot was taken but before rp_add() consumed it; the
     * success path passes it to rp_add(), which owns the count from then
     * on. Exactly one of the two must happen, or the counter leaks (and a
     * leaked count permanently refuses connections once it reaches the
     * cap). */
    bool     reserved;
};

static void rp_hs_init(struct rp_hs *hs)
{
    hs->deadline = now_ms() + RP_HS_TOTAL_MS;
    hs->in = 0;
    hs->reserved = false;
}

/* Poll within the handshake budget for the requested events: the poll
 * timeout is the remaining absolute budget capped at
 * RP_HANDSHAKE_TIMEOUT_MS (the per-poll ceiling still applies — the
 * total budget is independent). EINTR is not a timeout: a signal-
 * interrupted poll is retried while budget remains (M1). Returns 1
 * when the desired event fired, 0 on timeout, budget exhaustion or a
 * hard poll error (the caller must close). */
static int rp_hs_poll_ev(const struct rp_hs *hs, int fd, short events)
{
    uint64_t now = now_ms();
    uint64_t left = hs->deadline > now ? hs->deadline - now : 0;
    struct pollfd pfd;

    if (left == 0)
        return 0;
    if (left > RP_HANDSHAKE_TIMEOUT_MS)
        left = RP_HANDSHAKE_TIMEOUT_MS;
    pfd.fd = PORT_FD_ARG(fd);
    pfd.events = events;
    pfd.revents = 0;
    for (;;) {
        int r = port_poll(&pfd, 1, (int)left);
        if (r >= 0 || errno != EINTR)
            return r > 0 ? 1 : 0;
        /* signal-interrupted poll: retry within the remaining budget */
        now = now_ms();
        left = hs->deadline > now ? hs->deadline - now : 0;
        if (left == 0)
            return 0;
        if (left > RP_HANDSHAKE_TIMEOUT_MS)
            left = RP_HANDSHAKE_TIMEOUT_MS;
    }
}

/* Wait for readability within the handshake (POLLIN, see
 * rp_hs_poll_ev). */
static int rp_hs_poll(const struct rp_hs *hs, int fd)
{
    return rp_hs_poll_ev(hs, fd, POLLIN);
}

/* Poll one fd for readiness within `timeout_ms`, retrying through
 * EINTR while budget remains (M1: connect waits must not treat a
 * signal-interrupted poll as a failed/skipped candidate). Returns the
 * poll result >= 0, or -1 on a hard error (caller checks > 0 for
 * ready). */
static int rp_poll_retry(struct pollfd *pfd, int timeout_ms)
{
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        uint64_t now = now_ms();
        int left = deadline > now ? (int)(deadline - now) : 0;
        if (left <= 0)
            return 0;
        int r = port_poll(pfd, 1, left);
        if (r >= 0 || errno != EINTR)
            return r;
    }
}

/* Write exactly `len` bytes on a possibly-nonblocking fd, drawing from
 * the handshake budget like rp_hs_poll: a short write (EAGAIN on a
 * Windows accept()-inherited nonblocking socket, or an OS-level short
 * write) is completed by polling POLLOUT and writing again; EINTR is
 * retried. Returns 0 when all bytes were written, -1 on timeout,
 * budget exhaustion or a hard error. Linux blocking sockets satisfy
 * this in a single write, so the loop is a no-op there. */
static int rp_send_full(const struct rp_hs *hs, int fd, const void *buf,
                        size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t w = port_send(fd, p + done, len - done, 0);
        if (w > 0) {
            done += (size_t)w;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                      errno == EINTR)) {
            if (rp_hs_poll_ev(hs, fd, POLLOUT) <= 0)
                return -1;
            continue;
        }
        return -1;              /* hard error */
    }
    return 0;
}

/* R23 (T2): payload-forwarding variant of rp_send_full, used ONLY at the
 * four call sites that forward USER PAYLOAD BYTES ALREADY READ OUT OF
 * the client socket (SOCKS CONNECT post-frame tail, HTTP CONNECT
 * post-header tail, HTTP absolute-URI head, HTTP request body). For
 * those bytes a failed send is unrecoverable data loss — the same
 * non-drop argument R21 (dbd5ccb) applied to the relay data plane — so
 * the transient send-pressure errors ENOBUFS/ENOMEM are retried (1 ms
 * backoff, then a POLLOUT wait drawn from the same handshake budget)
 * instead of failing the send: `done` is untouched (w<0 wrote nothing),
 * so no byte is dropped, duplicated or reordered. The HANDshake/CONTROL
 * call sites deliberately keep rp_send_full: their messages are small
 * generated setup replies (SOCKS rep/ver-select, HTTP 1xx/2xx/5xx) that
 * fit the one-shot setup window and that a client can retry with a fresh
 * connection, so a transient failure is allowed to fail the connect. */
static int rp_send_full_payload(const struct rp_hs *hs, int fd,
                                const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t w = port_send(fd, p + done, len - done, 0);
        if (w > 0) {
            done += (size_t)w;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                      errno == EINTR)) {
            if (rp_hs_poll_ev(hs, fd, POLLOUT) <= 0)
                return -1;
            continue;
        }
        if (w < 0 && (errno == ENOBUFS || errno == ENOMEM)) {
            /* transient kernel send-buffer / memory pressure: the socket
             * can stay POLLOUT-ready while the kernel keeps refusing, so
             * back off 1 ms (same as R21 rp_flush) before the bounded
             * POLLOUT wait */
            port_sleep_ms(1);
            if (rp_hs_poll_ev(hs, fd, POLLOUT) <= 0)
                return -1;
            continue;
        }
        return -1;              /* hard error */
    }
    return 0;
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
 * WELL-FORMED RFC1929 frames whose credentials fail count toward the
 * budget — wrong-token frames AND (R37 R1-B-5) well-shaped frames with
 * an oversized username are auth attempts; genuinely malformed frames
 * (VER!=1, zero-length ulen/plen) are protocol violations, not auth
 * attempts, so a probe flood cannot lock a legitimate user out
 * (R46-L4). RP_FAIL_MAX failures inside RP_FAIL_WINDOW_MS lock the
 * source out for another window; a successful auth clears the source;
 * locked sources are dropped at accept() time. Two differences: the
 * table holds 64 entries (L6: the SOCKS table's 16 was too small for a
 * shared-NAT world), and it is mutex-guarded — unlike the
 * single-threaded SOCKS event loop, every relay proxy connection runs
 * on its own thread.
 *
 * Key: the peer IPv4 as-is; an IPv6 peer is merged to its /64 prefix
 * so one subnet cannot fill the table with 2^64 /128 aliases. The
 * listener is IPv4-only today, so the v6 path is defensive only. */
#define RP_FAIL_TRACK_MAX  64
#define RP_FAIL_MAX        5
#define RP_FAIL_WINDOW_MS  60000u

typedef struct {
    uint8_t v6;                 /* key is an IPv6 /64 prefix */
    uint8_t k[8];               /* address words (opaque comparison key) */
} rp_fail_key;

static lockout_rec g_rp_fail[RP_FAIL_TRACK_MAX];
static pthread_mutex_t g_rp_fail_mu = PTHREAD_MUTEX_INITIALIZER;

static size_t rp_fail_key_bytes(const rp_fail_key *k,
                                uint8_t out[LOCKOUT_KEY_MAX])
{
    memset(out, 0, LOCKOUT_KEY_MAX);
    out[0] = k->v6;
    memcpy(&out[1], k->k, 8);
    return 9;
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
        memcpy(k->k, &a->sin_addr, 4);
        return true;
    }
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)ss;
        /* first 8 bytes = /64 prefix (not s6_addr: mingw's IN6_ADDR
         * lacks the POSIX member name) */
        memcpy(k->k, &a->sin6_addr, 8);
        k->v6 = 1;
        return true;
    }
    return false;
}

static void rp_fail_note(const rp_fail_key *key, bool success)
{
    /* M3-2: NULL guard first — rp_fail_key_bytes dereferences key (the
     * old code called it before this check, making the guard dead code
     * and the getpeername-failed path a latent crash) */
    if (!key)
        return;             /* getpeername failed: nothing to track */
    uint8_t b[LOCKOUT_KEY_MAX];
    size_t n = rp_fail_key_bytes(key, b);
    lockout_note(g_rp_fail, RP_FAIL_TRACK_MAX, b, n, success,
                 RP_FAIL_MAX, RP_FAIL_WINDOW_MS, &g_rp_fail_mu);
}

static bool rp_fail_blocked(const rp_fail_key *key)
{
    /* M3-2: same guard-first fix as rp_fail_note */
    if (!key)
        return false;
    uint8_t b[LOCKOUT_KEY_MAX];
    size_t n = rp_fail_key_bytes(key, b);
    return lockout_blocked(g_rp_fail, RP_FAIL_TRACK_MAX, b, n,
                           &g_rp_fail_mu);
}

/* ---- target resolution/connect (kernel stack) ---- */

/* literal IPv4/IPv6: connect directly, no resolution. The connect runs
 * nonblocking (R4-08-F3): on a blocking socket POSIX never returns
 * EINPROGRESS, so the old code's EINPROGRESS branch — the only place the
 * RP_CONNECT_TIMEOUT_MS bound was applied — was dead and a black-holed
 * literal target could pin a connection thread for the OS's ~130s
 * default timeout. Now it matches the domain path: nonblock connect,
 * poll for writability within RP_CONNECT_TIMEOUT_MS, check SO_ERROR,
 * then restore blocking before the fd is handed to the relay (which
 * expects blocking sockets). */

/* R46-L6: map a connect-failure errno to the RFC 1928 reply code the
 * relay sends: unreachable/timeout -> 4 (host unreachable), everything
 * else (ECONNREFUSED, ...) -> 5 (connection refused / general failure).
 * The categories mirror the lwIP SOCKS mode (socks_flow.c: NS_TERM_
 * TIMEOUT -> rep 4, an overall connect timeout -> rep 4, RST/other ->
 * rep 5). */
static uint8_t rp_conn_err_rep(int err)
{
    switch (err) {
    case EHOSTUNREACH:
    case ENETUNREACH:
    case ETIMEDOUT:
    case ECONNABORTED:
        return 4;
    default:
        return 5;
    }
}

static int rp_connect_literal(int af, const void *addr, uint16_t port,
                              int *fd_out, uint8_t *fail_rep)
{
    struct sockaddr_storage ss;
    socklen_t salen;
    int fd = port_socket(af, SOCK_STREAM, 0);

    if (fd < 0) {
        if (fail_rep)
            *fail_rep = 5;
        return -1;
    }
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
    if (port_set_nonblock(fd, true) != 0) {
        port_close(fd);
        if (fail_rep)
            *fail_rep = 5;
        return -1;
    }
    if (port_connect(fd, (struct sockaddr *)&ss, salen) == 0) {
        /* immediate success */
    } else if (errno == EINPROGRESS || errno == EINTR) {
        /* R37 R3-L3: POSIX says a signal-interrupted connect() on a
         * nonblocking socket does NOT abort the attempt — the connection
         * is still being established, so wait for POLLOUT like
         * EINPROGRESS instead of reporting "Interrupted system call" as
         * an immediate connect failure (a single-address host then failed
         * outright). */
        /* rp_poll_retry: EINTR keeps waiting within the timeout instead
         * of aborting the connect (M1) */
        struct pollfd pfd = { .fd = PORT_FD_ARG(fd), .events = POLLOUT };
        if (rp_poll_retry(&pfd, RP_CONNECT_TIMEOUT_MS) <= 0) {
            /* R46-L6: connect TIMED OUT — RFC 1928 host unreachable (4) */
            port_close(fd);
            if (fail_rep)
                *fail_rep = 4;
            return -1;
        }
        int soerr = 0;
        socklen_t sl = sizeof soerr;
        if (port_getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr,
                            &sl) != 0 || soerr != 0) {
            /* R46-L6: async connect failed — map the SO_ERROR like an
             * immediate errno (soerr==0 with a failed getsockopt reads
             * as a general failure) */
            port_close(fd);
            if (fail_rep)
                *fail_rep = soerr == 0 ? 5 : rp_conn_err_rep((int)soerr);
            return -1;
        }
    } else {
        port_close(fd);
        if (fail_rep)
            *fail_rep = rp_conn_err_rep(errno);
        return -1;
    }
    /* restore blocking for the relay threads; if the mode cannot be
     * restored, treat it as a connect failure — a stray nonblocking fd
     * would alias EAGAIN as a hard relay error (C-F4) */
    if (port_set_nonblock(fd, false) != 0) {
        port_close(fd);
        if (fail_rep)
            *fail_rep = 5;
        return -1;
    }
    *fd_out = fd;
    return 0;
}

/* M7: the SSRF gate is on by default; IWAN_RELAY_ALLOW_LOOPBACK=1 is
 * an explicit operator opt-out for deployments that must reach host-
 * local services through the relay. Read once in relay_proxy_start
 * before any connection thread exists (plain static: no race). */
static bool g_rp_ssrf_off;

/* M7 (SSRF gate): true when the target address (literal or resolved)
 * points at the proxy host's own loopback, 0.0.0.0, or a link-local
 * range. An authenticated NON-loopback peer must not use the relay as
 * a springboard into services bound to the local host; a loopback peer
 * (local user) is exempt, keeping today's local usage unchanged.
 *
 * 0.0.0.0 is blocked too (H1): on Linux connect(0.0.0.0) resolves to
 * loopback, so it is an alternate spelling of 127.0.0.1 that would
 * otherwise slip around the gate; a proxy must not be asked to reach
 * an unspecified address anyway. */
static bool rp_target_blocked(bool guard, int af, const uint8_t *p)
{
    if (!guard)
        return false;
    if (af == 4)
        return p[0] == 0 ||                /* 0.0.0.0/8 (connect->loopback) */
               p[0] == 127 ||              /* 127.0.0.0/8 */
               (p[0] == 169 && p[1] == 254);   /* 169.254.0.0/16 */
    if (af == 6) {
        static const uint8_t lo[16] = { 0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 1 };
        static const uint8_t unspec[16] = { 0 };   /* :: */
        static const uint8_t v4map[12] = { 0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0xff, 0xff };
        if (memcmp(p, lo, 16) == 0)
            return true;                    /* ::1 */
        /* :: — same rationale as the v4 0.0.0.0 check: on Linux
         * connect(AF_INET6,[::]) routes to loopback, so this is an
         * alternate spelling of ::1 that would bypass the gate; a
         * proxy must not be asked to reach an unspecified address
         * anyway. */
        if (memcmp(p, unspec, 16) == 0)
            return true;                    /* :: */
        if (p[0] == 0xfe && (p[1] & 0xc0) == 0x80)
            return true;                    /* fe80::/10 */
        /* ::ffff:a.b.c.d: the mapped v4 address obeys the v4 rules,
         * else a crafted AAAA ::ffff:127.0.0.1 / ::ffff:0.0.0.0 would
         * bypass the gate */
        if (memcmp(p, v4map, 12) == 0)
            return p[12] == 0 ||
                   p[12] == 127 ||
                   (p[12] == 169 && p[13] == 254);
    }
    return false;
}

/* Resolve (when needed) and connect to the target. Returns 0 with the
 * connected fd in *fd_out; on success also reports the ACTUAL upstream
 * socket family in *up_af (AF_INET/AF_INET6) when up_af != NULL — the
 * family the SOCKS reply's BND.ATYP must match (R46-L5: for a domain
 * target the RESOLVED address's family, not the request's ATYP; literal
 * targets always report their own family). Returns -2 when every
 * candidate was refused by the SSRF gate, -1 on any other failure; on
 * ANY failure, *fail_rep (when non-NULL) holds the RFC 1928 reply code
 * the SOCKS caller must send — 4 for DNS failure / connect timeout /
 * host unreachable, 5 for refused / general (R46-L6). */
static int rp_connect_target(int *fd_out, int *up_af, const char *host,
                             uint16_t port, bool have_ip4,
                             const uint8_t ip4[4], bool have_ip6,
                             const uint8_t ip6[16], bool guard,
                             uint8_t *fail_rep)
{
    struct addrinfo hints, *res = NULL, *ai;
    char port_s[8];
    int last = -1, last_af = 0;
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
        if (up_af)
            *up_af = AF_INET;
        return rp_connect_literal(AF_INET, ip4, port, fd_out, fail_rep);
    }
    if (have_ip6) {
        if (rp_target_blocked(guard, 6, ip6))
            return -2;
        if (up_af)
            *up_af = AF_INET6;
        return rp_connect_literal(AF_INET6, ip6, port, fd_out, fail_rep);
    }
    /* domain: resolve, then try every address (v4 and v6). The gate
     * must judge each RESOLVED address — checking only the hostname
     * would let DNS rebinding slip through. */
    if (getaddrinfo(host, port_s, &hints, &res) != 0) {
        /* R46-L6: resolution failure (NXDOMAIN, resolver timeout, ...)
         * is "host unreachable" per the lwIP SOCKS-mode semantics */
        if (fail_rep)
            *fail_rep = 4;
        return -1;
    }
    /* R46-L6: if every candidate fails, the error reply reports the
     * LAST candidate's cause (deterministic, mirrors the existing
     * last-fd model); per-candidate causes are mapped below */
    uint8_t cand_rep = 5;
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
        if (fd < 0) {
            cand_rep = 5;
            continue;
        }
        if (port_set_nonblock(fd, true) != 0) {
            port_close(fd);
            cand_rep = 5;
            continue;
        }
        if (port_connect(fd, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0) {
            last = fd;
            last_af = ai->ai_family;
        } else if (errno == EINPROGRESS || errno == EINTR) {
            /* R37 R3-L3: see rp_connect_literal — EINTR does not abort a
             * nonblocking connect */
            /* rp_poll_retry: EINTR keeps this candidate waiting within
             * the timeout instead of skipping it (M1) */
            struct pollfd pfd = { .fd = PORT_FD_ARG(fd), .events = POLLOUT };
            if (rp_poll_retry(&pfd, RP_CONNECT_TIMEOUT_MS) > 0) {
                int soerr = 0;
                socklen_t sl = sizeof soerr;
                if (port_getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr,
                                    &sl) == 0 && soerr == 0) {
                    last = fd;
                    last_af = ai->ai_family;
                } else {
                    /* async connect failed: soerr already holds the
                     * SO_ERROR read above (0 when the read failed) */
                    cand_rep = soerr == 0 ? 5
                                          : rp_conn_err_rep((int)soerr);
                }
            } else {
                cand_rep = 4;   /* connect timed out */
            }
        } else {
            cand_rep = rp_conn_err_rep(errno);
        }
        if (last >= 0) {
            /* restore blocking for the relay threads; a failed restore
             * rejects this candidate (a nonblocking fd would alias
             * EAGAIN as a hard relay error) rather than handing it on
             * (C-F4) */
            if (port_set_nonblock(fd, false) != 0) {
                port_close(fd);
                last = -1;
                cand_rep = 5;   /* restore failure is a general failure */
                continue;       /* try the next candidate */
            }
            break;
        }
        if (fail_rep)
            *fail_rep = cand_rep;
        port_close(fd);
    }
    freeaddrinfo(res);
    if (last < 0)
        return blocked ? -2 : -1;
    if (up_af)
        *up_af = last_af;
    *fd_out = last;
    return 0;
}

/* ---- SOCKS5 ---- */

/* read exactly `want` bytes, waiting through EAGAIN/EINTR. Windows
 * accept() inherits the listener's nonblocking mode (unlike Linux), so
 * the handshake reads must poll instead of treating EAGAIN as fatal;
 * EINTR is retried too (M1), exactly like the handshake poll loops.
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
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                      errno == EINTR)) {
            if (rp_hs_poll(hs, fd) <= 0)
                return false;
            continue;
        }
        return false;
    }
    return true;
}

static void rp_socks_reply(int fd, uint8_t rep, const struct rp_hs *hs,
                           bool v6)
{
    /* R45-L1: RFC 1928 requires BND.ATYP to match the target family —
     * answering a CONNECT ATYP=4 (IPv6) upstream with the fixed IPv4
     * frame made strict clients (JDK style) reject even a successful
     * tunnel. A v6 success now returns the 22-byte frame {5, rep, 0, 4,
     * 16x ::, 0, 0}: the proxy is not bound to a concrete source
     * address, so BND.ADDR/port are zero by convention, exactly like
     * the lwIP SOCKS mode's socks_reply6 (socks_flow.c). Error replies
     * (rep != 0) stay on the 10-byte v4 frame — RFC 1928 allows a zero
     * BND.ADDR there and v4 keeps maximum compatibility. */
    uint8_t r[22] = {5, rep, 0, v6 ? 4 : 1};
    size_t n = v6 ? sizeof r : 10;
    /* M3: rp_send_full completes short writes (Windows nonblocking
     * handshake replies) and verifies the full frame went out */
    if (rp_send_full(hs, fd, r, n) != 0)
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
     * finish auth. 4096 matches the size of the caller's first[] read
     * buffer (rp_conn_main), so a single first read that pipelines
     * greeting + CONNECT + >2 KB of early tunnel data is copied whole
     * instead of being refused by the `n > sizeof b` entry bound; the
     * excess is then forwarded upstream by the R4-08-F1 logic below.
     * The `n > sizeof b` bound still follows the buffer size. */
    uint8_t b[4096];
    size_t n = first_n;
    /* t is zero-initialized: pp_socks_request returns 0 with rep=1 and
     * skips writing *t when VER!=5, so the debug log below must not
     * read uninitialized af/port. */
    pp_target t = {0};
    uint8_t method = 0, cmd = 0, rep = 0;

    if (n == 0)
        return -1;              /* nothing at all is still fatal */
    /* pre-auth bound: b is sized to hold a full first[] read (4096B),
     * so a legitimate pipelined greeting never trips this; only a true
     * oversized first packet (impossible from the caller today) is
     * refused here. The later reads all guard n >= sizeof b. */
    if (n > sizeof b)
        return -1;
    memcpy(b, first, n);
    /* M2: a TCP-fragmented greeting whose first read returned only the
     * single 0x05 byte (n == 1) must not be hard-closed. b[1] is not
     * initialized yet, so first top up to the fixed 2-byte greeting
     * head ([ver, nmethods]) before computing the method-list length. */
    if (n == 1) {
        if (!rp_read_full(fd, b + n, 1, hs))
            return -1;
        n = 2;
    }
    if (pp_socks_greeting(b, n, token != NULL, &method) != 0) {
        /* greeting may span reads: [5, nmethods, methods...] */
        size_t want = 2 + (size_t)b[1];
        if (want > sizeof b || !rp_read_full(fd, b + n, want - n, hs))
            return -1;
        n = want;
        if (pp_socks_greeting(b, n, token != NULL, &method) != 0)
            return -1;
    }
    method = pp_socks_pick_method(token != NULL, method);
    if (method == 0xff) {
        uint8_t no[2] = {5, 0xff};
        (void)rp_send_full(hs, fd, no, sizeof no);
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
        (void)rp_send_full(hs, fd, ok, sizeof ok);
        /* RFC1929: [1, ulen, user..., plen, pass...]. Token-less mode
         * accepts any well-formed frame (courtesy — a client that
         * offered only 0x02, e.g. curl -U, must not be rejected). */
        char user[64];
        const uint8_t *pass;
        size_t plen;
        for (;;) {
            int pr = pp_socks_auth_frame(b, n, user, sizeof user,
                                         &pass, &plen);
            if (pr == 1) {
                /* M6c: a well-formed frame with the wrong token is
                 * a counted auth failure */
                /* R37 R1-B-7: must not shadow the greeting's `ok[2]`
                 * (build-wstrict's -Wshadow -Werror) */
                bool authed = pp_socks_auth_ok(pass, plen, token);
                uint8_t rr[2] = {1, authed ? 0 : 1};
                if (!authed)
                    rp_fail_note(fk, false);
                (void)rp_send_full(hs, fd, rr, sizeof rr);
                if (!authed)
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
            if (pr == 2) {
                /* R37 R1-B-5: pp_socks_auth_frame() returns 2 for a
                 * WELL-FORMED RFC1929 frame whose username exceeds our
                 * 64-byte buffer (RFC1929 ULEN is 1 byte, so up to 255
                 * is legal). That is a real brute-force auth attempt (a
                 * credential guess with an oversized user field), so the
                 * deliberate lockout count from R37 R1-B-5 is KEPT.
                 * R46-L4: this is the ONLY pr!=1 case that counts — see
                 * the pr==0 branch below. */
                uint8_t rr[2] = {1, 1};
                rp_fail_note(fk, false);
                (void)rp_send_full(hs, fd, rr, sizeof rr);
                return -1;      /* complete but oversized username */
            }
            if (pr == 0) {
                /* R46-L4: a genuinely malformed frame (VER!=1, ulen=0,
                 * plen=0) is a protocol violation, NOT an auth attempt.
                 * Answer {1,1} and close, but do NOT count it toward the
                 * peer's lockout budget — the M6c contract and the
                 * socks_flow equivalent (socks_flow.c auth_reject) only
                 * count well-formed wrong credentials, and tests/
                 * socks_handshake.py marks ulen=0/plen=0/VER!=1 as
                 * "not a lockout-counted failure". Before R46-L4 the
                 * relay counted every failure class here, so a probe
                 * flood of malformed frames could lock a legit user out
                 * on the relay while the same flood did nothing on the
                 * SOCKS side. */
                uint8_t rr[2] = {1, 1};
                (void)rp_send_full(hs, fd, rr, sizeof rr);
                return -1;      /* complete but malformed */
            }
            if (n >= sizeof b)
                return -1;
            {
                ssize_t r = rp_hs_recv(hs, fd, b + n, sizeof b - n);
                if (r > 0) {
                    n += (size_t)r;
                    continue;
                }
                if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                              errno == EINTR)) {
                    if (rp_hs_poll(hs, fd) <= 0)
                        return -1;
                    continue;
                }
                return -1;
            }
        }
    } else {
        uint8_t ok[2] = {5, 0};
        (void)rp_send_full(hs, fd, ok, sizeof ok);
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
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                          errno == EINTR)) {
                if (rp_hs_poll(hs, fd) <= 0)
                    return -1;
                continue;
            }
            return -1;
        }
    }
    if (rep != 0) {
        /* parser-level error (bad cmd/atyp): v4 reply keeps maximum
         * compatibility; RFC 1928 permits a zero BND.ADDR here */
        rp_socks_reply(fd, rep, hs, false);
        return -1;
    }
    /* R4-08-F1: bytes that arrived past the CONNECT frame were already
     * read out of the client socket during the handshake (rp_hs_recv
     * reads in multi-KB chunks), so they must be forwarded to the
     * upstream once it is connected — the relay's direction loop starts
     * from empty buffers and would otherwise silently drop this
     * pipelined tunnel data. Compute the consumed frame length the same
     * way the parser does (b[3] = ATYP). */
    {
        size_t frame_end;
        if (b[3] == 1)
            frame_end = 10;
        else if (b[3] == 4)
            frame_end = 22;
        else
            frame_end = 5 + (size_t)b[4] + 2;
        int up = -1;
        int up_af = 0;   /* actual upstream socket family (R46-L5) */
        uint8_t fail_rep = 5;   /* R46-L6: rep for the SOCKS error reply */
        int rc = rp_connect_target(&up, &up_af, t.host, t.port, t.af == 4,
                                   (const uint8_t *)&t.ip4, t.af == 6,
                                   t.ip6, guard, &fail_rep);
        if (rc == 0) {
            /* R37 R5 (R3-L21) / R37 R7: rp_add() binds the established set,
             * but it runs AFTER this reply. The old order answered rep=0
             * ("succeeded") and closed the pair a moment later when the set
             * was full, i.e. it lied to the client exactly when the relay
             * was busy. Refuse instead: rep=0x01 (general SOCKS server
             * failure) must be the client's first and only CONNECT reply,
             * and the upstream fd is released here so the refusal leaks
             * nothing. The upstream connect is already paid for because the
             * check deliberately sits after rp_connect_target().
             *
             * R37 R7: the check is now a real CAS reservation taken before
             * the reply, so there is no residual "another thread took the
             * last slot after I checked" window left — the losers of the
             * race are refused here, with rep=1, instead of being told
             * rep=0 and then disconnected. */
            if (!rp_est_reserve()) {
                rp_note_est_full();
                port_close(up);
                rp_socks_reply(fd, 1, hs, false);
                return -1;
            }
            /* R37 R7 (R3-L21): the slot is ours; rp_conn_main's `out:`
             * label releases it on any later failure, rp_add() consumes it
             * on success. Reply rep=0 only now that the slot is held, so
             * "success" can no longer be taken back. */
            hs->reserved = true;
            /* R12-T2 (R41-3-1): the reservation gates the cap-full
             * cause only; a DEAD data plane is the second way rp_add()
             * refuses after the reply. Refuse with rep=1 before any
             * rep=0 goes out — answering "established" and then closing
             * is the lie the review measured. `out:` rolls the
             * reservation back (hs->reserved is already set). */
            if (rp_plane_dead()) {
                rp_note_plane_down();
                rp_socks_reply(fd, 1, hs, false);
                port_close(up);
                return -1;
            }
            /* R45-L1 / R46-L5: a success reply's BND.ATYP must match the
             * family of the ACTUAL upstream socket — the literal family
             * for an ATYP=1/4 request (a literal v6 target gets the
             * 22-byte v6 frame, exactly as before R46-L5), and the
             * RESOLVED family for a domain (ATYP=3) request: a domain
             * that connected via IPv6 gets the 22-byte v6 frame even
             * though the request carried no family. This is the same
             * dispatch as the lwIP SOCKS mode, where a domain is keyed
             * on the DNS result's family (socks_flow.c target_af) — the
             * earlier comment claimed "the literal family the client
             * asked for governs, matching the lwIP side", which a domain
             * request (t.af == 0) made false. */
            rp_socks_reply(fd, 0, hs, up_af == AF_INET6);
            /* R37 R6 (K-5): rp_send_full, not a bare port_send. The
             * upstream socket is blocking here, so the old check could
             * not tell a SHORT write or an EINTR from a hard failure and
             * failed the connection closed — silently losing the bytes
             * already read out of the client socket. rp_send_full
             * completes EINTR/short writes (bounded by the handshake
             * budget) and still fails closed if the bytes cannot be
             * delivered at all. */
            if (n > frame_end &&
                /* R23 (T2): user payload already read out of the client
                 * socket (post-frame tail) — transient ENOBUFS/ENOMEM
                 * must not drop it (rp_send_full_payload); the SOCKS
                 * handshake replies above stay on rp_send_full (control,
                 * client-retryable) */
                rp_send_full_payload(hs, up, b + frame_end,
                                     n - frame_end) != 0) {
                port_close(up);
                return -1;
            }
            return up;           /* caller relays on fd <-> up */
        }
        /* M7: a gate refusal is "not allowed" (rep 2), everything else
         * is classified by cause (R46-L6): rp_connect_target mapped the
         * failure — DNS failure / connect timeout / host unreachable ->
         * rep 4 (host unreachable, RFC 1928), ECONNREFUSED / general ->
         * rep 5 — mirroring the lwIP SOCKS mode's reply codes. */
        rp_socks_reply(fd, rc == -2 ? 2 : fail_rep, hs, false);
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

    /* R4-08-F2: no minimum first-packet size here — a legitimately
     * fragmented HTTP request whose first recv() returned < 8 bytes is
     * read to the header terminator below, exactly like the SOCKS path
     * reads a full frame. (The scan guard `i = 4` below simply does
     * nothing until n >= 4.) */
    memcpy(buf, first, first_n);
    /* read until \r\n\r\n. L1: the scan must also run on the final
     * chunk — `n < sizeof buf - 1` skipped the batch that brought n to
     * 8191, so a legal ~8191-byte header whose terminator arrived in
     * that batch was misjudged as incomplete. With `n < sizeof buf`
     * the last (8191-byte) batch is scanned too; a terminator found
     * there breaks out before any further read. */
    hdr_end = (size_t)-1;
    while (n < sizeof buf) {
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
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                      errno == EINTR)) {
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
    if (rp_connect_target(&up, NULL, t.host, t.port, t.af == 4,
                          (const uint8_t *)&t.ip4, t.af == 6,
                          t.ip6, guard, NULL) != 0) {
        static const char bad[] = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        (void)rp_send_full(hs, fd, bad, sizeof bad - 1);
        return -1;
    }
    /* R37 R5 (R3-L21): the HTTP path had the same lie as SOCKS — it
     * answered 200 Connection Established (or forwarded the request) and
     * only then had rp_add() refuse the pair. Map "set full" to 503 before
     * any success bytes go out. */
    if (!rp_est_reserve()) {
        static const char busy[] = "HTTP/1.1 503 Service Unavailable\r\n"
                                   "Content-Length: 0\r\n\r\n";
        rp_note_est_full();
        port_close(up);
        (void)rp_send_full(hs, fd, busy, sizeof busy - 1);
        return -1;
    }
    /* R37 R7 (R3-L21): same as the SOCKS path — the slot is held before
     * the 200/forward bytes go out; every failure below is rolled back by
     * rp_conn_main's `out:` label, success is consumed by rp_add(). */
    hs->reserved = true;
    /* R12-T2 (R41-3-1): dead-plane gate, same as the SOCKS path — refuse
     * 503 BEFORE any success (200 / forwarded request) bytes go out,
     * since rp_add() would refuse immediately after them otherwise.
     * `out:` rolls the reservation back. */
    if (rp_plane_dead()) {
        static const char busy[] = "HTTP/1.1 503 Service Unavailable\r\n"
                                   "Content-Length: 0\r\n\r\n";
        rp_note_plane_down();
        port_close(up);
        (void)rp_send_full(hs, fd, busy, sizeof busy - 1);
        return -1;
    }
    if (is_connect) {
        static const char ok[] =
            "HTTP/1.1 200 Connection Established\r\n\r\n";
        /* M3: rp_send_full verifies the ENTIRE reply went out — the old
         * `< 0` check only caught hard errors, so a partial (EAGAIN
         * short-write on Windows nonblocking) 200 left the client
         * waiting for a CONNECT response */
        if (rp_send_full(hs, fd, ok, sizeof ok - 1) != 0) {
            port_close(up);
            return -1;
        }
        /* R4-08-F1: forward bytes already-read past the CONNECT header
         * (e.g. the first TLS bytes coalesced with the request) — they
         * are no longer in the client socket's kernel buffer and the
         * relay loop would start from empty. R37 R6 (K-5): rp_send_full,
         * same reason as in rp_handle_socks — a short write or EINTR on
         * this blocking upstream must not be read as a hard failure. */
        if (n > hdr_end &&
            /* R23 (T2): user payload already read out of the client
             * socket (first TLS bytes coalesced with the CONNECT
             * header) — transient ENOBUFS/ENOMEM must not drop it;
             * the 200 reply above stays on rp_send_full (control) */
            rp_send_full_payload(hs, up, buf + hdr_end,
                                 n - hdr_end) != 0) {
            port_close(up);
            return -1;
        }
        return up;
    }
    /* absolute-URI forward: send the original request head verbatim
     * (RFC 7230 servers accept absolute-form on a proxy connection).
     * R37 R6 (K-5): rp_send_full — the head is sent in one piece and a
     * short write/EINTR used to abort the forward. R23 (T2): the head
     * is the CLIENT'S OWN REQUEST BYTES (user payload, not a generated
     * control message), so the payload variant retries transient
     * ENOBUFS/ENOMEM instead of dropping them. */
    if (rp_send_full_payload(hs, up, buf, hdr_end) != 0) {
        port_close(up);
        return -1;
    }
    /* R4-08-F1: also forward the request body bytes that were coalesced
     * with the head into buf — same silent-drop hazard. R37 R6 (K-5):
     * rp_send_full here too; R23 (T2): payload variant (see above). */
    if (n > hdr_end &&
        rp_send_full_payload(hs, up, buf + hdr_end, n - hdr_end) != 0) {
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
 *     poll round-trip); only a partial / transient send (EAGAIN or
 *     R20-11: ENOBUFS/ENOMEM) leaves a remainder in the pending buffer,
 *     and once anything is pending the loop
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
    atomic_int in_use;          /* references held by rp_dir_main loop
                                 * iterations while they dereference cn:
                                 * +1 per snapshot entry under g_rp_mu,
                                 * -1 at the loop bottom; free waits for
                                 * the last reference (>=1 while any
                                 * iteration may still touch cn) */
    bool retired;               /* dirs hit 0; freed when the last
                                 * in_use reference drops (see
                                 * rp_reap_maybe) */
    struct rp_ent up, dn;      /* up thread owns .up, down owns .dn */
};

static struct rp_conn **g_rp_up, **g_rp_dn;
static size_t g_rp_up_n, g_rp_up_cap, g_rp_dn_n, g_rp_dn_cap;
static pthread_mutex_t g_rp_mu = PTHREAD_MUTEX_INITIALIZER;
static atomic_int g_rp_stop;
/* bumped under g_rp_mu whenever a connection array changes (add,
 * retire swap, rollback swap); direction threads rebuild their cached
 * pollset when the generation they built it from is stale (M7: a
 * same-round swap keeps the count unchanged, so a count-only check
 * misses it) */
static atomic_uint_fast64_t g_rp_arr_gen;

/* R37 R3 (WG-C, R1-B-3 structural): direction-thread liveness.
 *
 * The two global direction threads are the ONLY things that ever retire
 * an entry from their array (rp_release -> dirs 0 -> rp_reap_maybe ->
 * close/free + g_rp_est_n--). A thread that exited can never do that
 * again, so every entry registered in its array AFTER the exit would
 * keep dirs > 0 forever. rp_add therefore refuses to register into an
 * array whose owner is gone, and the exit itself retires everything
 * still registered (see cleanup: in rp_dir_main).
 *
 * The marker is per relay INSTANCE (`g_rp_gen`, bumped by every
 * relay_proxy_start): a marker left behind by a previous instance must
 * not poison a restarted relay. `g_rp_dir_dead_gen[0]` is the up
 * direction, `[1]` the down direction; the value is the generation in
 * which that thread exited, 0 = never / alive. Both the marker and the
 * reads in rp_add happen under g_rp_mu (g_rp_gen is atomic and is only
 * bumped before the instance's threads exist). */
static atomic_uint g_rp_gen = 1;         /* current relay instance (1-based) */
static unsigned g_rp_dir_dead_gen[2];    /* guarded by g_rp_mu */

/* [prof] relay byte counters (up = client->upstream, dn = reverse) */
atomic_uint_fast64_t g_prof_rp_up_recv, g_prof_rp_up_send;
atomic_uint_fast64_t g_prof_rp_dn_recv, g_prof_rp_dn_send;
atomic_uint_fast64_t g_prof_rp_pend;   /* bytes appended to pend */
atomic_uint_fast64_t g_prof_rp_iters, g_prof_rp_poll0;   /* TEMP loop */

/* R12-T2 (R41-3-1): has the current relay instance's data plane already
 * died? A direction thread writes g_rp_dir_dead_gen under g_rp_mu in its
 * cleanup:; rp_add() checks it while registering, but by then the success
 * reply (rep=0 / 200) went out — answering "established" right before
 * closing is the lie the review measured (LIE_COUNT(rep0_then_EOF) 6/6).
 * The existing reservation gates only the cap-full cause; this gate
 * closes the dead-plane cause at the SAME point (before the success
 * reply): the caller sends an honest failure reply instead.
 *
 * The read takes g_rp_mu — the marker's guard lock — so a reply-side
 * check that does not see the marker ran before the exit published it,
 * and the pair is then registered before the cleanup retires everything
 * (the "no window" invariant rp_add relies on). A stale marker from a
 * previous relay instance carries a different generation (g_rp_gen is
 * bumped before each instance's threads start), so it cannot poison a
 * restarted relay — the same test rp_add() applies. */
static bool rp_plane_dead(void)
{
    bool dead;
    pthread_mutex_lock(&g_rp_mu);
    unsigned gen = atomic_load(&g_rp_gen);
    dead = (g_rp_dir_dead_gen[0] == gen ||
            g_rp_dir_dead_gen[1] == gen);
    pthread_mutex_unlock(&g_rp_mu);
    return dead;
}

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
 * are closed here and the caller must not touch them again.
 *
 * R37 R7 (R3-L21): `reserved` says the caller already took a slot with
 * rp_est_reserve() before it answered success. From here on the count is
 * rp_add's to own: the pre-existing atomic_fetch_sub(&g_rp_est_n, 1) on
 * every failure path below is exactly the rollback of that reservation, so
 * no extra release is needed. The !reserved branch keeps the historical
 * check-and-take for any future caller that has not reserved (there is
 * none today; it is kept so the function cannot silently over-admit).
 *
 * R38 (R8-P2-3): the reservation is a ONE-SHOT TOKEN and rp_add() consumes
 * it at entry (clears the caller's flag), exactly like the ownership
 * transfer it already documents. Without that, a future extra release
 * written against the same flag ("the caller still thinks it owns the
 * slot") decremented the counter once per connection and silently removed
 * the established-set cap — see rp_est_release() below. */
static void rp_add(int c, int u, bool *reserved)
{
    struct rp_conn *cn;
    bool have_slot = *reserved;

    *reserved = false;   /* rp_add owns (or rolls back) the slot from here */

    /* R37 R1-B-2: RP_MAX_CONNS caps concurrent HANDSHAKE threads only —
     * an established-but-idle relayed connection was never bounded (600
     * idle connections = 1200 fds and climbing). That is enough fd
     * pressure to push the client (root under TUN) into EMFILE, which in
     * turn killed the accept thread (R1-B-1). Bound the established set
     * explicitly and refuse with a log line instead of silently
     * black-holing the peer. No idle timeout is added: SSH and other
     * long-lived idle sessions are legitimate. */
    /* R37 R5 (R3-L21) / R37 R7: both handlers now reserve the slot BEFORE
     * their success reply, so this branch is unreachable for the current
     * callers (they pass have_slot=true and the count they took is exactly
     * the one rp_add owns). It is kept for a caller that has not reserved:
     * it must still refuse rather than over-admit. */
    if (!have_slot) {
        if (atomic_load(&g_rp_est_n) >= g_rp_max_est) {
            rp_note_est_full();
            port_close(c);
            port_close(u);
            return;
        }
        atomic_fetch_add(&g_rp_est_n, 1);
    }

    cn = calloc(1, sizeof *cn);
    if (!cn) {
        atomic_fetch_sub(&g_rp_est_n, 1);
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
    /* R37 R1-B-4: a fd left in BLOCKING mode would stall the whole
     * direction thread (it serves every connection at once), so refuse
     * the connection instead of silently ignoring a failed fcntl —
     * rp_connect_target already treats the same failure as fatal. */
    if (port_set_nonblock(c, true) != 0 || port_set_nonblock(u, true) != 0) {
        log_err("rp: cannot switch connection to non-blocking mode: dropped");
        atomic_fetch_sub(&g_rp_est_n, 1);
        port_close(c);
        port_close(u);
        free(cn);
        return;
    }

    pthread_mutex_lock(&g_rp_mu);
    /* R37 R3 (WG-C, R1-B-3 structural): never register into an array
     * whose direction thread is gone for THIS relay instance — nobody
     * would ever retire that entry (its `dirs` count stays > 0, the
     * rp_conn is never closed/freed and g_rp_est_n never decrements).
     * The marker is written under this same mutex, so an entry is either
     * registered before the exit (and retired by rp_dir_main's cleanup)
     * or refused here — there is no window in between. */
    unsigned gen = atomic_load(&g_rp_gen);
    bool dead = g_rp_dir_dead_gen[0] == gen || g_rp_dir_dead_gen[1] == gen;
    bool ok = !dead && rp_arr_add(&g_rp_up, &g_rp_up_n, &g_rp_up_cap, cn);
    if (ok)
        ok = rp_arr_add(&g_rp_dn, &g_rp_dn_n, &g_rp_dn_cap, cn);
    if (ok)
        atomic_fetch_add(&g_rp_arr_gen, 1);
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
        atomic_fetch_add(&g_rp_arr_gen, 1);
    }
    pthread_mutex_unlock(&g_rp_mu);
    if (!ok) {
        /* R37 R5 (R4-L6): a dead data plane refuses every new connection,
         * so this notice must not be one line per connection either. */
        if (dead)
            rp_note_plane_down();
        atomic_fetch_sub(&g_rp_est_n, 1);   /* R1-B-2: undo the reservation */
        port_close(c);
        port_close(u);
        free(cn);
        return;
    }
}

/* free a retired conn once no loop iteration may still dereference
 * it: every iteration holds in_use >= 1 on its snapshot entries (added
 * under g_rp_mu, dropped at the loop bottom), so a retired conn with
 * in_use == 0 is unreferenced and safe to close and free. Must run
 * under g_rp_mu (the freeing thread may be the last holder; the
 * atomics are read before the free). */
static void rp_reap_maybe(struct rp_conn *cn)
{
    if (cn->retired && atomic_load(&cn->in_use) == 0) {
        port_close(cn->c);
        port_close(cn->u);
        free(cn->up.pend);
        free(cn->dn.pend);
        free(cn);
        atomic_fetch_sub(&g_rp_est_n, 1);   /* R1-B-2: connection gone */
    }
}

/* one direction thread retires its entry: when both have retired, the
 * conn is marked; the actual close+free happens when the last in_use
 * reference drops (not necessarily here — the caller still holds its
 * own reference until its loop bottom). Must run under g_rp_mu. */
static void rp_release(struct rp_conn *cn)
{
    if (atomic_fetch_sub(&cn->dirs, 1) == 1) {
        cn->retired = true;
        rp_reap_maybe(cn);
    }
}

/* drop every snapshot reference this loop iteration holds (early exit
 * / loop bottom); must run under g_rp_mu — the last reference out of
 * a retired conn closes and frees it */
static void rp_snap_unref_all(struct rp_conn **snap, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (atomic_fetch_sub(&snap[i]->in_use, 1) == 1)
            rp_reap_maybe(snap[i]);
}

/* R37 R2 (R1-B-3), reworked in R37 R3 (WG-C): a direction thread that
 * exits (realloc failure, poll hard error, stop) must RETIRE the entries
 * it still owns. Skipping that leaves this direction's `dirs` count above
 * zero forever, so rp_reap_maybe never closes the two sockets or frees the
 * rp_conn — and, since R1-B-2, g_rp_est_n never decrements either, so
 * RP_MAX_ESTABLISHED eventually refuses every new connection for the rest
 * of the process (a permanent relay outage, not just an fd leak).
 *
 * R3 makes this structural instead of per-site: the helper below is called
 * from the ONE exit point of rp_dir_main (cleanup:), so no early exit —
 * present or future — can forget it. It takes no snapshot: it walks the
 * LIVE array of this direction, which is exactly the set of entries this
 * direction has not released yet (the array doubles as the
 * "not yet retired" marker), so no entry can be released twice.
 * Must run under g_rp_mu. */
static void rp_dir_retire_all(bool up_dir, struct rp_conn ***arrp, size_t *np)
{
    while (*np > 0) {
        struct rp_conn *cn = (*arrp)[*np - 1];
        struct rp_ent *e = up_dir ? &cn->up : &cn->dn;

        if (!e->wr_closed) {
            port_shutdown(e->to, 1);   /* same half-close as from_eof */
            e->wr_closed = true;
        }
        (*np)--;
        atomic_fetch_add(&g_rp_arr_gen, 1);
        rp_release(cn);
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
#ifndef IWAN_DEBUG_STRIP
    if (atomic_load_explicit(&g_prof_on, memory_order_relaxed))
        atomic_fetch_add(&g_prof_rp_pend, (uint64_t)n);
#endif
    return true;
}

/* flush the pending buffer; on a hard send error the remaining data is
 * dropped and the entry is half-closed. EAGAIN/EWOULDBLOCK/EINTR (and,
 * per R20-11, the transient ENOBUFS/ENOMEM the UDP pump also retries)
 * leave plen intact for the next POLLOUT instead. */
static void rp_flush(struct rp_ent *e, bool up_dir)
{
    (void)up_dir;   /* only consumed by the prof counters (stripped) */
    while (e->plen > 0) {
        ssize_t w = port_send(e->to, e->pend, e->plen, 0);
        if (w > 0) {
#ifndef IWAN_DEBUG_STRIP
            if (atomic_load_explicit(&g_prof_on, memory_order_relaxed))
                atomic_fetch_add(up_dir ? &g_prof_rp_up_send
                                        : &g_prof_rp_dn_send,
                                 (uint64_t)w);
#endif
            e->plen -= (size_t)w;
            memmove(e->pend, e->pend + w, e->plen);
            continue;
        }
        if (w < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            return;             /* retry on the next POLLOUT */
        if (w < 0 && (errno == ENOBUFS || errno == ENOMEM)) {
            /* R20-11: send-buffer / memory pressure is transient and the
             * relay must not drop TCP bytes over it (the UDP pump treats
             * ENOBUFS exactly like EAGAIN — budgeted stall, never a
             * fatal). Unlike EAGAIN the socket can stay POLLOUT-ready
             * while the kernel keeps refusing, which would hot-spin this
             * poll loop — back off explicitly, then retry on the next
             * POLLOUT. plen is untouched (a send that returned -1 wrote
             * nothing), so no byte is dropped, duplicated or reordered. */
            port_sleep_ms(1);
            return;
        }
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
    unsigned long long built_gen = 0;
    struct rp_conn **snap = NULL;
    size_t snapcap = 0;
    /* R37 R3 (WG-C): the snapshot whose in_use references this iteration
     * holds (snap_refs) and its entry count. cleanup: needs both to drop
     * the references on an early exit. */
    size_t snap_n = 0;
    bool snap_refs = false;
    /* relay instance this thread belongs to (checked against
     * g_rp_dir_dead_gen when publishing our own death) */
    unsigned my_gen = atomic_load(&g_rp_gen);
    uint8_t buf[RP_BUF];
#ifndef IWAN_DEBUG_STRIP
    static _Thread_local struct prof_state pst;
    const char *tag = up_dir ? "rp up recv" : "rp dn recv";
#endif

    while (!atomic_load(&g_rp_stop)) {
        pthread_mutex_lock(&g_rp_mu);
        size_t n = *np;
        if (n > snapcap) {
            struct rp_conn **ns = realloc(snap, n * sizeof *ns);
            if (!ns) {
                /* R37 R3 (WG-C, R1-B-3): early exit — cleanup: retires
                 * this direction's entries and drops any snapshot refs.
                 * No reference has been taken yet at this point (the
                 * in_use bumps happen below), and the retire there walks
                 * the LIVE array, never this buffer: `snap` is still the
                 * old one of capacity snapcap < n, so its tail is realloc
                 * residue and its head is a stale snapshot. */
                pthread_mutex_unlock(&g_rp_mu);
                goto cleanup;   /* L3: free pf/slot buffers too */
            }
            snap = ns;
            snapcap = n;
        }
        /* M3-4: with no connections both snap and *arrp are NULL, and
         * memcpy(NULL, NULL, 0) is UB — it fires on every empty
         * snapshot under halting UBSan (relay aborting at startup) */
        if (n)
            memcpy(snap, *arrp, n * sizeof *snap);
        /* hold one reference per snapshot entry while this iteration
         * dereferences them outside g_rp_mu; dropped at the loop
         * bottom (or by cleanup: on an early exit). Under the same
         * critical section as the memcpy, so every snapshotted conn
         * is ref-protected before the lock is released. */
        for (size_t i = 0; i < n; i++)
            atomic_fetch_add(&snap[i]->in_use, 1);
        snap_n = n;
        snap_refs = true;
        /* M6: record the array generation inside the same critical
         * section as the snapshot. Read after the unlock it could pair
         * a fresh generation with a stale snapshot, making the gen check
         * below believe the pollset is current and skip a rebuild round
         * (a new index would then read realloc residue / uninitialized
         * values). Same lock, same instant, so built_gen always matches
         * the snapshot it was taken from. */
        unsigned long long cur_gen =
            atomic_load_explicit(&g_rp_arr_gen, memory_order_relaxed);
        pthread_mutex_unlock(&g_rp_mu);

        if (n * 2 > pfcap) {
            struct pollfd *n2 = realloc(pf, (n * 2) * sizeof *n2);
            if (!n2)
                goto cleanup;   /* L3 + R3: retire/unref handled there */
            pf = n2;
            pfcap = n * 2;
        }
        if (n > slotcap) {
            int *ns = realloc(slot_from, n * sizeof *ns);
            if (!ns)
                goto cleanup;   /* L3 + R3: retire/unref handled there */
            slot_from = ns;
            ns = realloc(slot_to, n * sizeof *ns);
            if (!ns)
                goto cleanup;   /* L3 + R3: retire/unref handled there */
            slot_to = ns;
            slotcap = n;
            pf_dirty = true;
        }
        /* cached pollset: rebuild only when an entry's registration
         * state changed (from_eof, pend crossing the cap, add/retire).
         * slot_from[i]/slot_to[i] map entry i to its pollfd index, so
         * the per-entry event lookup is O(1) instead of an O(n*k)
         * fd scan on every loop iteration. (cur_gen itself was read in
         * the snapshot's critical section above — see M6.) */
        /* M7: rebuild also when a connection array changed since this
         * pollset was built (a same-round add+retire keeps the count
         * unchanged, so a count-only check misses it); this also
         * removes the one-round delay after a retire */
        if (pf_dirty || cur_gen != built_gen) {
            size_t k = 0;
            for (size_t i = 0; i < n; i++) {
                struct rp_ent *e = up_dir ? &snap[i]->up : &snap[i]->dn;
                slot_from[i] = slot_to[i] = -1;
                if (!e->from_eof &&
                    e->plen + (size_t)RP_BUF <= RP_PEND_LIMIT) {
                    pf[k].fd = PORT_FD_ARG(e->from);
                    pf[k].events = POLLIN;
                    pf[k].revents = 0;
                    slot_from[i] = (int)k;
                    k++;
                }
                if (e->plen > 0) {
                    pf[k].fd = PORT_FD_ARG(e->to);
                    pf[k].events = POLLOUT;
                    pf[k].revents = 0;
                    slot_to[i] = (int)k;
                    k++;
                }
            }
            pf_n = k;
            pf_dirty = false;
            built_gen = cur_gen;
        }
        int pr = port_poll(pf, (nfds_t)pf_n, RP_POLL_MS);
#ifndef IWAN_DEBUG_STRIP
        if (atomic_load_explicit(&g_prof_on, memory_order_relaxed)) {
            atomic_fetch_add(&g_prof_rp_iters, 1);
            if (pr == 0)
                atomic_fetch_add(&g_prof_rp_poll0, 1);
        }
#endif
        if (pr < 0) {
            if (errno == EINTR) {
                /* drop this iteration's references before restarting:
                 * the next pass overwrites the snapshot buffer, so a
                 * reference left behind here would dangle forever */
                pthread_mutex_lock(&g_rp_mu);
                rp_snap_unref_all(snap, n);
                snap_refs = false;
                pthread_mutex_unlock(&g_rp_mu);
                continue;
            }
            /* R37 R3 (WG-C): a hard poll error ends this direction
             * thread. The old code stopped relaying without a single log
             * line (same "silent black hole" shape as R1-B-1); report it,
             * then let cleanup: retire the entries. */
            log_err("rp: %s poll failed: %s; stopping relay",
                    up_dir ? "up" : "down", strerror(errno));
            break;              /* poll failed: stop relaying */
        }
#ifndef IWAN_DEBUG_STRIP
        if (atomic_load_explicit(&g_prof_on, memory_order_relaxed) &&
            prof_print(tag, &pst,
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
#endif

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
#ifndef IWAN_DEBUG_STRIP
                        if (atomic_load_explicit(&g_prof_on,
                                                 memory_order_relaxed))
                            atomic_fetch_add(up_dir ? &g_prof_rp_up_recv
                                                    : &g_prof_rp_dn_recv,
                                             (uint64_t)r);
#endif
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
#ifndef IWAN_DEBUG_STRIP
                                    if (atomic_load_explicit(
                                            &g_prof_on,
                                            memory_order_relaxed))
                                        atomic_fetch_add(
                                            up_dir ? &g_prof_rp_up_send
                                                   : &g_prof_rp_dn_send,
                                            (uint64_t)w);
#endif
                                    if (off == (size_t)r)
                                        break;
                                    continue;
                                }
                                if (w < 0 &&
                                    (errno == EAGAIN ||
                                     errno == EWOULDBLOCK ||
                                     errno == EINTR ||
                                     /* R20-11: transient send-buffer /
                                      * memory pressure — same non-drop
                                      * classification as rp_flush below
                                      * (remainder goes to pend and waits
                                      * on POLLOUT, byte-identical) */
                                     errno == ENOBUFS ||
                                     errno == ENOMEM))
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
                    } else if (errno == ENOBUFS || errno == ENOMEM) {
                        /* R33-B2-L1: transient recv memory / socket-buffer
                         * pressure — same non-drop classification as the
                         * send side (R20-11/R22-A2-1), so a transient read
                         * error must NOT half-close the whole connection.
                         * Like the send side the fd can stay POLLIN-ready
                         * while the kernel keeps refusing, which would
                         * hot-spin this poll loop — back off explicitly
                         * (same port_sleep_ms(1) shape as rp_flush below),
                         * then read resumes on the next readable round. */
                        port_sleep_ms(1);
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
        /* M4: no count comparison here — n is the snapshot entry count
         * and pf_n is the built pollfd count (up to 2 slots per entry),
         * so any entry with pend (dual registration) makes n != pf_n
         * permanently true and would force a full rebuild every loop
         * under congestion, defeating the cache. Correctness is already
         * covered by the per-entry compare above and the generation
         * check (cur_gen vs built_gen) for array add/retire changes. */
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
                        atomic_fetch_add(&g_rp_arr_gen, 1);
                        break;
                    }
                rp_release(cn);
            }
        }
        /* drop this iteration's snapshot references; the last one to
         * leave a retired conn closes and frees it (rp_reap_maybe,
         * lock held) */
        rp_snap_unref_all(snap, n);
        snap_refs = false;
        pthread_mutex_unlock(&g_rp_mu);
    }
cleanup:
    /* R37 R3 (WG-C, R1-B-3 structural): SINGLE choke point for every
     * exit of this thread. Retiring here — instead of at each early exit
     * — is what makes the defect class impossible: a new `goto cleanup`
     * cannot forget it. rp_dir_retire_all() walks the LIVE array (the
     * `snap` buffer may be stale/realloc residue at the realloc-failure
     * exit) and releases every entry this direction still owns; nothing
     * else can have released them (the array doubles as the "not yet
     * retired" marker), so no entry is released twice.
     *
     * Order matters: retire first, then drop our own snapshot
     * references. rp_dir_retire_all() dereferences the entries, and
     * rp_snap_unref_all() may free one (the last reference out of a
     * retired conn) — dropping it first could free a conn the retire
     * still wants to touch. At the snap-realloc exit snap_refs is false
     * (no reference taken yet), so only the retire runs.
     *
     * Then publish this direction's death and take the relay down: from
     * here on nothing would ever retire an entry registered in this
     * array again (the post-exit registration hole the R3 review
     * named), so rp_add refuses new connections and g_rp_stop makes the
     * other direction thread retire its own array and exit too — the
     * whole data plane is torn down instead of silently leaking. */
    pthread_mutex_lock(&g_rp_mu);
    rp_dir_retire_all(up_dir, arrp, np);
    if (snap_refs) {
        rp_snap_unref_all(snap, snap_n);
        snap_refs = false;
    }
    /* L3: the local buffers are always released below (realloc-failure
     * early exits used to leak them) */
    bool expected_stop = atomic_load(&g_rp_stop) != 0;
    g_rp_dir_dead_gen[up_dir ? 1 : 0] = my_gen;   /* my_gen >= 1 */
    pthread_mutex_unlock(&g_rp_mu);
    if (!expected_stop) {
        log_err("rp: %s direction thread exited (relay data plane down; "
                "new connections refused)", up_dir ? "up" : "down");
        /* wind the other direction thread down as well */
        atomic_store(&g_rp_stop, 1);
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

    /* R37 R3-M1: the accepted fd is nonblocking (rp_accept_main), so the
     * budgeted poll below can report readiness while the read still
     * returns EAGAIN (spurious wakeup, or the peer's segment was already
     * discarded). Retry within the budget instead of dropping the
     * connection; every other handshake read/write already polls on
     * EAGAIN (rp_read_full / rp_send_full), so this is the only bare
     * first read. */
    for (;;) {
        if (rp_hs_poll(&hs, fd) <= 0)
            goto out;
        n = rp_hs_recv(&hs, fd, first, sizeof first);
        if (n >= 0)
            break;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            goto out;
    }
    if (n == 0)
        goto out;               /* peer closed before sending anything */

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
     * now on. R37 R7 (R3-L21): hs.reserved carries the slot taken before
     * the success reply; rp_add consumes the token (it clears the flag), so
     * this connection can never release that slot a second time (R38 P2-3). */
    rp_add(fd, up, &hs.reserved);
    /* M6a: success exit — this thread stops tracking the connection
     * (the global relay owns it now) */
    atomic_fetch_sub(&g_rp_conn_n, 1);
    free(ca);
    return NULL;

out:
    /* R37 R7 (R3-L21): THE single rollback point for a pre-reply slot
     * reservation. Every failure path inside rp_handle_socks()/
     * rp_handle_http() returns -1, which lands here, so no handler can
     * leak the count by forgetting a release (that leak would permanently
     * refuse every later connection once it reached the cap). rp_add()
     * owns the count on the success path, so this must NOT run then.
     * R38 (R8-P2-3): clear the one-shot token BEFORE releasing, so no
     * second trip through this label (or any future duplicate release
     * guarded by the same flag) can decrement g_rp_est_n twice. */
    if (hs.reserved) {
        hs.reserved = false;
        rp_est_release();
    }
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
    /* R37 R6 (K-1; twin of R4-L5 in socks.c): hard bound on CONSECUTIVE
     * "aborted request" retries inside this loop, reset by a successful
     * accept. ECONNABORTED/EPROTO belong to the NEW connection whose
     * request the kernel has ALREADY dequeued — the backlog is not under
     * pressure, so pacing them taxed an innocent client that arrived
     * inside the 50ms window (R6-K: 3 injected aborts => 149.6ms legal
     * client latency, 6 => 299.0ms). The bound only exists so that a
     * pathological source which keeps failing WITHOUT ever dequeuing
     * (e.g. an injected fault) cannot hold the loop: past the bound the
     * branch falls through to the same bounded 50ms pacing as the
     * resource class. (socks.c returns to wait_events() there; here
     * `continue` does reach poll(), but a non-empty backlog makes poll()
     * return immediately, so the explicit sleep is what actually bounds
     * it.) 64 is far above any real burst of aborted connections. */
    enum { ABORT_DRAIN_MAX = 64 };
    unsigned abort_drain = 0;
    while (!atomic_load(&rp->stop)) {
        struct pollfd pfd = { .fd = PORT_FD_ARG(rp->listener),
                              .events = POLLIN };
        int pr = port_poll(&pfd, 1, 1000);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            /* R37 R3-M2: poll(2) on the listener can fail TRANSIENTLY
             * (ENOMEM/ENOBUFS under memory pressure). The old code broke
             * out of the loop for any non-EINTR error: the accept thread
             * disappeared while the listener stayed open, so connect()
             * kept succeeding and nothing was ever accepted again — with
             * no log line at all (the same silent black hole R1-B-1
             * removed from the accept() path). Only a dead/invalid
             * listener fd is fatal. */
            if (errno == EBADF || errno == EINVAL || errno == ENOTSOCK) {
                log_err("rp: listener poll failed fatally (errno=%d): "
                        "relay listener stopped", errno);
                break;
            }
            /* R37 R3-M2: at least ONE visible line even in Release builds
             * (log_debug is compiled out there), then rate-limited to one
             * line per second so a persistent error cannot flood stderr —
             * same shape as the thread-spawn warning below. */
            static uint64_t last_poll_warn_ms;
            uint64_t pw = now_ms();
            if (pw - last_poll_warn_ms >= 1000) {
                last_poll_warn_ms = pw;
                log_err("rp: listener poll failed transiently (errno=%d): "
                        "backing off", errno);
            }
            port_sleep_ms(50);   /* bounded: no hot spin */
            continue;
        }
        /* R37 R3-L1: a listener that reports an error/hangup WITHOUT POLLIN
         * keeps poll() returning immediately while accept() finds nothing:
         * the old code spun at ~100% of a core (measured 501 ticks/5s).
         * Remember the condition, still TRY one accept() below (an error
         * report does not prove that no connection is pending), and back
         * off when accept() then says EAGAIN. */
        bool poll_err_only = !(pfd.revents & POLLIN) &&
                             (pfd.revents & (POLLERR | POLLHUP |
                                             POLLNVAL));
        int fd = port_accept(rp->listener, NULL, NULL);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (poll_err_only)
                    port_sleep_ms(50);   /* bounded: no hot spin */
                continue;
            }
            if (errno == EINTR)
                continue;
            /* R37 R6 (K-1): an error that belongs to the new connection
             * whose request the kernel has already discarded must not
             * trigger the backoff — drain the backlog instead. Past
             * ABORT_DRAIN_MAX consecutive aborts the branch falls through
             * to the paced path below (bounded: no hot spin). log_debug
             * only: an aborted peer is a normal event, not a fault. */
            if (errno == ECONNABORTED || errno == EPROTO) {
                log_debug("rp: accept aborted request (errno=%d), draining",
                          errno);
                if (++abort_drain <= ABORT_DRAIN_MAX)
                    continue;
            }
            /* R37 R1-B-1: every other error accept(2) returns on Linux is
             * TRANSIENT — EMFILE/ENFILE (fd table full), ENOBUFS/ENOMEM
             * (kernel memory pressure), ECONNABORTED (peer RST before we
             * accepted), EPROTO/ENETDOWN/EHOSTDOWN/ENETUNREACH (pending
             * network error). The old code `break`ed out of the loop for
             * all of them, and this thread is detached with no restart:
             * the listener stayed open, so connect() kept succeeding while
             * nothing was ever accepted again — a silent local-proxy black
             * hole until process exit, with no log line anywhere. Only a
             * dead/invalid listener fd is fatal now. */
            if (errno == EBADF || errno == EINVAL || errno == ENOTSOCK) {
                log_err("rp: listener accept failed fatally (errno=%d): "
                        "relay listener stopped", errno);
                break;
            }
            log_debug("rp: transient accept error (errno=%d), backing off",
                      errno);
            port_sleep_ms(50);   /* bounded: no hot spin under EMFILE */
            continue;
        }
        abort_drain = 0;   /* a real connection ended the aborted burst */

        /* R37 R3-M1: hand the connection thread a NONBLOCKING fd. Linux
         * accept() returns a blocking socket, and the handshake's reads
         * (rp_read_full -> rp_hs_recv -> port_recv) then block forever on
         * a peer that sends one byte and goes silent: the RP_HS_TOTAL_MS
         * budget only lives in rp_hs_poll(), which is reached when the
         * read returns EAGAIN. With the fd nonblocking, EAGAIN surfaces
         * and the existing budgeted poll loops close the connection at
         * the 30s deadline, so RP_MAX_CONNS half-open connections can no
         * longer pin every connection thread — and the relay — forever.
         * rp_add switches the same fd for the relay later, so this only
         * moves that switch before the handshake; a failed switch is
         * fatal for this connection (a blocking fd would reintroduce the
         * stall). */
        if (port_set_nonblock(fd, true) != 0) {
            log_err("rp: cannot switch accepted fd to non-blocking mode: "
                    "dropped");
            port_close(fd);
            continue;
        }

        /* M6c/L6: drop sources locked out for RFC1929 brute force
         * before spending a thread or a byte on them */
        struct sockaddr_storage pss;
        socklen_t pslen = sizeof pss;
        rp_fail_key fk;
        memset(&pss, 0, sizeof pss);
        bool have_key =
            getpeername(PORT_FD_ARG(fd), (struct sockaddr *)&pss,
                        &pslen) == 0 &&
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
        /* R37 L3 (HEAD-R2 §2.2): pthread_create returns the error number
         * and does NOT set errno, so a failure here must be reported with
         * strerror(rc). Rate-limited to one line per second — a thread
         * limit (EAGAIN) or OOM (ENOMEM) would otherwise flood the log
         * from this accept loop. */
        int crc = pthread_create(&th, NULL, rp_conn_main, ca);
        if (crc != 0) {
            static _Atomic uint64_t last_spawn_warn_ms;
            uint64_t nw = now_ms();
            if (nw - atomic_load_explicit(&last_spawn_warn_ms,
                                          memory_order_relaxed) >= 1000) {
                atomic_store_explicit(&last_spawn_warn_ms, nw,
                                      memory_order_relaxed);
                log_err("rp: cannot spawn connection thread (rc=%d: %s); "
                        "dropping connection", crc, strerror(crc));
            }
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
    /* H-1 (R14): the allow-remote guard judges the token's CONTENT, not
     * just the pointer — an empty string is "no token" too, so a remote
     * bind with `--socks-token ""` and no --socks-no-token must be
     * refused (empty must never be mistaken for a set password). */
    if (!loop && !(auth_token && *auth_token) && !open_proxy) {
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

    /* R37 R5 (R3-L22): derive the effective established cap from the fd
     * budget actually granted to this process, and record it. The reserve
     * covers the concurrent handshake set plus a small working margin; only
     * a LOWER value is taken (raising the cap above the reviewed
     * compile-time maximum is a deliberate fd-pressure decision that
     * belongs to the constant, not to the environment). Windows has no
     * getrlimit; there the compile-time value stays in force.
     * R37 R6 (R6-M1) / R34-A2-1: the reserve is scaled to the granted
     * limit (limit/4), floored at min(lim/2, 2*RP_MAX_CONNS) — NOT an
     * unconditional 2*RP_MAX_CONNS: the floor must itself fit the
     * granted limit, or a small lim (macOS 256 / hardened Linux 512)
     * collapses the cap to 1. With the min-floor, for lim >=
     * 2*RP_MAX_CONNS the reserve covers the whole INSTANTANEOUS
     * handshake set (R33-B2-L2: 2*RP_MAX_CONNS fds — RP_MAX_CONNS
     * handshake threads, accepted fd + connect-target fd each) and the
     * "never overspend" bound is exact: established set (<= 2*room =
     * lim - reserve) + a same-instant full handshake burst (<= reserve)
     * can never exceed the limit, so no transient EMFILE from fd
     * pressure. For lim < 2*RP_MAX_CONNS the limit cannot hold a full
     * handshake set: the reserve takes min(lim/2, 2*RP_MAX_CONNS),
     * established + reserve <= lim stays exact (2*room = lim - reserve),
     * so a same-instant full burst can still EMFILE — physically
     * unavoidable below 2*RP_MAX_CONNS, momentary and self-healing —
     * while the cap stays usable (the R6-M1 intent). -1 in the log
     * line means "not applicable" (Windows, or an infinite limit); both
     * values are printed so an operator can tell a scaled reserve from
     * the full one. */
    long long rp_reserve = -1;
    long long rp_rlim_cur = -1;
#ifndef _WIN32
    {
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 &&
            rl.rlim_cur != RLIM_INFINITY) {
            long long lim = (long long)rl.rlim_cur;
            long long reserve = lim / 4;
            if (reserve > RP_FD_RESERVE)
                reserve = RP_FD_RESERVE;
            /* R34-A2-1: the reserve floor is min(lim/2, 2*RP_MAX_CONNS),
             * not an unconditional 2*RP_MAX_CONNS — the floor must fit
             * the granted limit or it collapses the cap (R33-B2-L2 gave
             * cap=1 for any lim <= 515, the macOS 256 / hardened-Linux
             * 512 COMMON cases). For lim >= 2*RP_MAX_CONNS the reserve
             * >= 2*RP_MAX_CONNS covers the whole INSTANTANEOUS handshake
             * fd set (RP_MAX_CONNS handshake threads (M6a cap), each
             * holding an accepted fd plus a connect-target fd while
             * rp_connect_target runs = 2*RP_MAX_CONNS fds): established
             * (<= 2*room = lim - reserve) + handshake (<= reserve) can
             * never exceed lim, so no transient EMFILE from fd pressure.
             * For lim < 2*RP_MAX_CONNS the reserve takes lim/2 (which
             * fits the limit; 2*room = lim - reserve stays exact, so the
             * established set is never trimmed and the cap stays usable),
             * but it cannot hold a full handshake set: a same-instant
             * full burst can still EMFILE. That window is physically
             * unavoidable below 2*RP_MAX_CONNS and self-heals (the burst
             * is momentary; the next poll/accept round has fds again). */
            if (reserve < (long long)(lim / 2) &&
                (long long)(lim / 2) < (long long)(2 * RP_MAX_CONNS))
                reserve = (long long)(lim / 2);
            else if (reserve < (long long)(2 * RP_MAX_CONNS))
                reserve = (long long)(2 * RP_MAX_CONNS);
            long long room = (lim - reserve) / 2;
            if (room < 1)
                room = 1;
            if (room < g_rp_max_est)
                g_rp_max_est = (int)room;
            rp_reserve = reserve;
            rp_rlim_cur = lim;
        }
    }
#endif
    log_info("relay proxy: established-connection cap=%d "
             "(RLIMIT_NOFILE-derived: reserve=%d rlim_cur=%d, "
             "compile-time max=%d)",
             g_rp_max_est, (int)rp_reserve, (int)rp_rlim_cur,
             RP_MAX_ESTABLISHED);

    rp = calloc(1, sizeof *rp);
    if (!rp)
        return -1;
    rp->listener = -1;
    /* H-1 (R14): register an EMPTY token as NO token (rp->token = NULL),
     * unifying with the proxy's empty-string semantics so an empty value
     * can never be misread as "a password is set". rp_handle_socks /
     * pp_socks_auth_ok key off `token != NULL`: with NULL they select
     * method 0x00 / courtesy and validate the RFC1929 frame as nothing
     * (same as if --socks-token had never been passed). */
    if (auth_token && *auth_token)
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
    /* R37 R3 (WG-C): new relay instance — a death marker left behind by a
     * previous instance must not make rp_add refuse this one. Bumped
     * before any thread of this instance exists (no lock needed). */
    atomic_fetch_add(&g_rp_gen, 1);
    pthread_t tu, td;
    bool tu_created = false;
    {
        /* L11/C-6 (bughunt): create both threads before publishing
         * g_rp_current; if the second create fails the first is already
         * running and could dereference a dropped rp via rp_conn_main.
         * Create both, then publish; on failure stop, detach the
         * survivor and clear the pointer. */
        int rc = pthread_create(&tu, NULL, rp_dir_main, (void *)(intptr_t)1);
        if (rc == 0) {
            tu_created = true;
            rc = pthread_create(&td, NULL, rp_dir_main, (void *)(intptr_t)0);
        }
        if (rc != 0) {
            /* L2: detach the surviving up thread (else it stays a
             * zombie), close the listening fd, clear the pointer; stop
             * has already been raised for it to exit */
            atomic_store(&g_rp_stop, 1);
            /* R37 L3: strerror() must be fed the pthread_* RETURN CODE,
             * not errno (pthread_* do not touch errno — the old line
             * printed "Success" for a real EAGAIN/ENOMEM failure). */
            log_err("relay proxy: cannot start relay threads (rc=%d: %s)",
                    rc, strerror(rc));
            if (tu_created)
                pthread_detach(tu);
            g_rp_current = NULL;
            port_close(fd);
            rp->listener = -1;
            goto fail;
        }
    }
    pthread_detach(tu);
    pthread_detach(td);
    g_rp_current = rp;

    /* R37 L3: this spawn failure point previously had NO log line at all
     * (the relay silently never accepted anything). Report the pthread
     * return code, never errno. */
    int arc = pthread_create(&accept_th, NULL, rp_accept_main, rp);
    if (arc != 0) {
        /* M5/L2: accept failed — the two direction threads are already
         * detached and running with g_rp_stop=0 and g_rp_current=rp.
         * Without this cleanup g_rp_current would dangle past this rp's
         * free and the threads would spin forever on the 100ms poll,
         * so a caller retry would spawn a second pair relaying the same
         * array concurrently (data corruption). Stop them and clear the
         * dangling pointer, aligned with the relay-thread failure path
         * above, before closing the listener. */
        log_err("relay proxy: cannot start accept thread (rc=%d: %s); "
                "relay not started", arc, strerror(arc));
        atomic_store(&g_rp_stop, 1);
        g_rp_current = NULL;
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
    /* detached accept thread exits on its next poll. R37 R3 (WG-C):
     * the direction threads' cleanup: now retires every connection they
     * still own on the way out, so in-flight relayed connections are
     * half-closed, reaped and their fds closed at shutdown instead of
     * being kept until process exit. The struct is deliberately NOT
     * freed: a live connection thread may still read rp->token (one
     * proxy per process — the leak is bounded by the process
     * lifetime). */
}
