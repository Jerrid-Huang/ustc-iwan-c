#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* POSIX-only headers: on Windows the equivalents come from port.h
 * (winsock2/ws2tcpip) or are local defines (UDP_SEGMENT, MSG_*). */
#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <signal.h>
#ifdef __linux__
#include <sys/eventfd.h>
#endif
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "common.h"
#include "crypto.h"
#include "ipv4.h"
#include "tcpstack.h"


#include "protocol.h"
#include "socks.h"
#include "socks_internal.h"
#include "util.h"

Netstack g_ns;

/* FIND-R2-5: ns_flow_unref (bridge extension, declared in lwip_bridge.h —
 * R37 R1E-1 removed the local forward declarations from this file and
 * socks_flow.c) releases a flow's reference on a rebuildable conn slot.
 * Bounds-checked, idempotent: safe to call on any f->ns_idx value before
 * detaching a flow from the rebuilt stack. */

/* shared stop flag (util.h): written from the signal handler with a
 * relaxed atomic store (lock-free on every supported target) */
void on_sig(int sig) {
    (void)sig;
    atomic_store_explicit(&g_stop, true, memory_order_relaxed);
    atomic_store_explicit(&g_user_stop, true, memory_order_relaxed);
}

_Atomic int g_dns_evfd = -1;   /* DNS workers read/wake; main writes (R20: atomic) */
_Atomic int g_sockfd = -1; /* session UDP socket; R20 atomic (DNS-worker readers) */
SocksConfig *g_socks_cfg; /* SOCKS5 config; set by run_socks, read by flow handshake */
Flow *g_flows;            /* fixed MAX_FLOWS array, never NULL-terminated */

/* one GSO unit: max UDP payload (65535 - 20B IP - 8B UDP) */
#define SOCKS_KEEPALIVE_MS 10000u
/* keepalive send must fail this many times in a row before the session
 * is declared dead (transient blips recover; persistent failure means
 * the socket is gone) */
#define SOCKS_KA_FAIL_MAX 3
/* Downlink-silence watchdog: after this much silence the tunnel is
 * re-authenticated IN PLACE (see socks_reauth_tunnel) — the SOCKS
 * listener, client flows and inner TCP state are kept, so connections
 * survive the switch. 0 disables. The USTC server's relay intermittently
 * goes silent for minutes and then recovers; re-authing (server keeps
 * the inner IP across re-OPENs) restores the carrier without dropping
 * anything. */
#define SOCKS_RX_STALE_MS_DEFAULT 120000u

/* parsed once per process (the event loop would otherwise re-run
 * getenv+strtoul every iteration); 0 disables the watchdog */
static unsigned socks_rx_stale_ms(void)
{
    static unsigned cached;
    static int parsed;

    if (parsed)
        return cached;
    parsed = 1;
    /* R37 R1E-1: the lower bound used to be 10000 ms, exactly
     * SOCKS_KEEPALIVE_MS — a keepalive-only tunnel (no downlink payload for a
     * whole keepalive period, which is the normal idle case) was then judged
     * "stale" every 10s and re-authenticated in a loop. Keep the bound at
     * 3 keepalive periods so at least two keepalives are missed before the
     * tunnel is declared silent; proxy.c (TUN mode) uses the same floor. */
    cached = (unsigned)env_ms_range("IWAN_RX_STALE_MS",
                                    SOCKS_RX_STALE_MS_DEFAULT,
                                    3 * SOCKS_KEEPALIVE_MS,
                                    86400000, 1, "(0 to disable, "
                                                 "30s..24h)");
    return cached;
}
#define LISTEN_BACKLOG   64
#define SOCK_BUF_BYTES   (16 * 1024 * 1024)
#define POLL_CEIL_MS     1000   /* safety ceiling for the event wait */

/* event-driven wait: listener, VPN socket, and client flows; wakes on any
 * readable fd or the next netstack tick. Replaces fixed sleep polling. */
void wait_events(int listener, int sockfd, int dns_evfd, int timeout_ms)
{
    struct pollfd fds[3 + MAX_FLOWS];
    int n = 0;
    fds[n].fd = listener;
    fds[n].events = POLLIN;
    n++;
    fds[n].fd = sockfd;
    fds[n].events = POLLIN;
    n++;
    if (dns_evfd >= 0) {
        fds[n].fd = dns_evfd;
        fds[n].events = POLLIN;
        n++;
    }
    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &g_flows[i];
        if (!f->active)
            continue;
        /* L-6 defensive guard: the invariant is flow_alloc assigns fd
         * and flow_free closes it before clearing active, so an active
         * flow always has fd >= 0 — still, never let a negative fd into
         * the poll set (port_poll would treat it as an error slot);
         * skip it instead of registering it. Placed before the events
         * computation. */
        if (f->fd < 0)
            continue;
        fds[n].fd = f->fd;
        /* rx_paused (netstack ring full): do NOT register POLLIN — the
         * socket stays readable, so polling it would return instantly
         * and busy-spin the loop; the next netstack tick (<=100ms)
         * retries the reserve and clears the pause when room frees.
         * local_eof: the EOF/RST has already been consumed, so the
         * socket is ALSO permanently readable while nobody will ever
         * read it again (the client half-closed; upstream data keeps
         * flowing via service_local_outputs, which is unconditional).
         * Same busy-spin trap — leave events empty; the flow is reaped
         * by the peer FIN or the NS_FIN_WAIT timeout, whichever first.
         * ST_CLOSING (R06-FIND M-1, coordinated with service_local_inputs
         * in socks_flow.c, which has already stopped feeding input for
         * ST_CLOSING): after a connect failure/rejection the client keeps
         * writing replies it never reads, so the fd stays readable forever.
         * Without this check each poll round would read those bytes into
         * f->input with no cap (ST_CLOSING is outside the GREETING/REQUEST
         * HANDSHAKE_INPUT_MAX and the RESOLVING 1MB cap), letting a client
         * feed hundreds of MB in ~30s -> buf_ensure -> oom_abort. Closing
         * POLLIN here + A's feed stop together prevent the busy-spin and
         * the unbounded buffering; the ST_CLOSING flow is then force-reaped
         * by reap_flows after ST_CLOSING_TIMEOUT_MS (30s). POLLOUT below
         * stays enabled (f->output.len > 0), so any queued reply/data is
         * still delivered by service_local_outputs before the flow dies. */
        fds[n].events =
            (f->rx_paused || f->local_eof || f->state == ST_CLOSING)
                ? 0
                : POLLIN;
        if (f->output.len > 0 || f->rxq_waiting)
            fds[n].events |= POLLOUT;
        n++;
    }
    if (port_poll(fds, (nfds_t)n, timeout_ms) < 0 && errno != EINTR)
        log_err("poll: %s", strerror(errno));
}

void accept_connections(int listener) {
    /* R37 R5-WG-E: hard bound on CONSECUTIVE "aborted request" retries in
     * one call (incremented in the ECONNABORTED/EPROTO branch below, reset
     * by a successful accept). The kernel dequeues an aborted request, so a
     * real storm is bounded by the backlog; this counter makes the bound
     * EXPLICIT so that no pathological source of the error (one that keeps
     * failing without ever removing a request — e.g. an injected fault) can
     * hold the loop inside accept_connections() and spin. Measured with an
     * injector that fails every accept4() unconditionally: 137.4M accepts
     * and 93% of a core in 5s without this bound; with it the loop returns
     * to wait_events() and is paced by the poll timeout instead. 64 is far
     * above any real burst of aborted connections. */
    enum { ABORT_DRAIN_MAX = 64 };
    unsigned abort_drain = 0;
    for (;;) {
        /* L-5: with a large pended backlog the drain loop would accept
         * every pending client even after a stop signal; check the shared
         * stop flags each round and bail out (teardown still closes any
         * accepted flow via flow_free, so nothing leaks). */
        if (g_stop || g_user_stop)
            return;
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof peer;
        int cfd = port_accept(listener, (struct sockaddr *)&peer, &peerlen);
        if (cfd < 0) {
            /* the wrapper maps WSAEWOULDBLOCK -> EAGAIN, so this stays
             * valid on Windows */
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            /* R37 R3-M3: a signal-interrupted accept() is not a failure */
            if (errno == EINTR)
                continue;
            /* R37 R5-WG-E (R4-L5): an error that belongs to the NEW
             * connection whose request the kernel has ALREADY discarded
             * must not trigger the backoff. ECONNABORTED means the peer
             * gave up before we accepted: the backlog is NOT under
             * pressure and there is nothing left to back off from.
             * Sleeping here taxed an innocent client that arrived inside
             * the 50ms window (R4-E: p50 304us -> max 51282us) for a
             * connection that no longer exists. Drain instead: the next
             * accept() returns the next pending connection or EAGAIN
             * (-> return), so the loop stays bounded by the backlog.
             * EPROTO is kept here too: accept(2) reports it for the new
             * socket's protocol error, and the request is dequeued in the
             * same way. Deliberately NOT here (HEAD arbitration, R5):
             * EPERM (firewall) and the ENETDOWN/ENETUNREACH/
             * EHOSTUNREACH/ENOPROTOOPT/ETIMEDOUT family describe
             * conditions that can PERSIST and are not proof that a request
             * left the backlog; treating them as "just retry" is exactly
             * the shape that spun at 98-102% CPU before R3-M3, so they
             * stay in the paced (backoff) class below — 50ms there buys
             * "never a hot spin".
             * log_debug only (compiled OUT in Release): an aborted peer
             * is a normal event, not a fault, and must not flood stderr. */
            if (errno == ECONNABORTED || errno == EPROTO) {
                log_debug("accept SOCKS5 client: %s (retrying)",
                          strerror(errno));
                if (++abort_drain > ABORT_DRAIN_MAX)
                    return;   /* bounded: back to wait_events() to poll */
                continue;
            }
            /* R37 R3-M3/R5-WG-E: the paced class. EMFILE/ENFILE
             * (process/system fd table full) and ENOBUFS/ENOMEM (kernel
             * memory pressure) are true resource exhaustion and leave the
             * pending connection IN the backlog, so the caller's
             * poll -> accept -> log cycle would return immediately every
             * round: measured 98-102% CPU, 1.42M accepts/3s and 31.6 MiB
             * of stderr in 3s while every local client timed out. EPERM/
             * ENETDOWN/ENETUNREACH/EHOSTUNREACH/ENOPROTOOPT/ETIMEDOUT
             * (the man page's "network errors for the new socket" family;
             * EHOSTDOWN is omitted, mingw-w64's errno.h has no such name)
             * are grouped here on purpose: they can persist for as long as
             * the network/firewall condition does, so they get the same
             * ONE bounded sleep. Back off and then return — the main loop
             * must still run (under EMFILE it is the thing that releases
             * fds) but at ~20 cycles/s instead of a hot spin. The log is
             * rate-limited to one line per second so a persistent error
             * cannot flood stderr. */
            if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS ||
                errno == ENOMEM || errno == EPERM || errno == ENETDOWN ||
                errno == ENETUNREACH || errno == EHOSTUNREACH ||
                errno == ENOPROTOOPT || errno == ETIMEDOUT) {
                static uint64_t last_acc_backoff_ms;
                uint64_t acc_now = now_ms();
                if (acc_now - last_acc_backoff_ms >= 1000) {
                    last_acc_backoff_ms = acc_now;
                    log_err("accept SOCKS5 client: %s (backing off)",
                            strerror(errno));
                }
                port_sleep_ms(50);
                return;
            }
            /* Everything left is the listener fd itself being unusable
             * (EBADF not open / EINVAL not listening or bad addrlen /
             * ENOTSOCK not a socket / EOPNOTSUPP not SOCK_STREAM /
             * EFAULT impossible with our stack addr) plus anything this
             * list does not name. These are NOT transient, so they are
             * never folded into the silent retry set above, and they are
             * NEVER silently swallowed: one log_err per second (log_err,
             * not log_debug, so the line survives Release) keeps the
             * contract "EBADF stays fatal & visible" and hands the
             * condition back to the caller every round. The single
             * bounded sleep is kept ONLY because accept_connections runs
             * unconditionally each round while wait_events()'s poll() on
             * a closed fd reports POLLNVAL and returns IMMEDIATELY
             * (measured) — returning without pacing would turn a dead
             * listener into a 100% CPU spin, which is strictly worse than
             * one visible line per second. */
            static uint64_t last_acc_fatal_ms;
            uint64_t fatal_now = now_ms();
            if (fatal_now - last_acc_fatal_ms >= 1000) {
                last_acc_fatal_ms = fatal_now;
                log_err("accept SOCKS5 client: %s (listener fd unusable, "
                        "not retrying)", strerror(errno));
            }
            port_sleep_ms(50);
            return;
        }
        abort_drain = 0;   /* a real connection ended the aborted burst */
        /* Serve only loopback peers by default: an unauthenticated
         * remote peer would turn the host into an open proxy. Remote
         * peers are served only with an explicit --allow-remote bind
         * AND either RFC1929 credentials (--socks-token, required) or
         * the explicit open-proxy opt-out (--socks-no-token). The
         * non-loopback bind warning stays as a config-time hint; this
         * check is the enforcement. */
        if (!(g_socks_cfg && g_socks_cfg->allow_remote &&
              (g_socks_cfg->auth_token || g_socks_cfg->open_proxy))) {
            /* accept() already returned the peer address: an extra
             * getpeername() syscall here was pure overhead */
            if ((peer.sin_addr.s_addr & htonl(0xFF000000u)) !=
                htonl(0x7F000000u)) {
                char cip[INET_ADDRSTRLEN] = "";
                inet_ntop(AF_INET, &peer.sin_addr, cip, sizeof cip);
                log_debug("SOCKS5: closing non-loopback peer %s", cip);
                port_close(cfd);
                continue;
            }
        }
        if (auth_fail_blocked(peer.sin_addr.s_addr)) {
            char cip[INET_ADDRSTRLEN] = "";
            inet_ntop(AF_INET, &peer.sin_addr, cip, sizeof cip);
            log_debug("SOCKS5: dropping %s (auth failure lockout)", cip);
            port_close(cfd);
            continue;
        }
        int nodelay = 1;
        port_setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nodelay,
                        sizeof nodelay);
        if (port_set_nonblock(cfd, true) < 0) {
            /* FIONBIO/fcntl failure: without non-blocking mode this
             * connection would block the single-threaded event loop
             * (e.g. after a Windows FIONBIO error), so refuse it. */
            log_err("SOCKS5: set nonblock on accepted fd: %s",
                    strerror(errno));
            port_close(cfd);
            continue;
        }
        Flow *f = flow_alloc(&peer);
        if (!f) {
            port_close(cfd);
            continue;
        }
        f->fd = cfd;
    }
}

/* ---- VPN framing (mirrors netstack/tunnel.rs) ---- */

/* drain the whole tx queue: same size as the netstack's device queue
 * (NS_TX_MAX), so a full ring is drained in one pass */
#define SOCKS_MAX_PK NS_TX_MAX
#define SOCKS_SEND_RETRY_MS 5  /* EAGAIN/ENOBUFS retry budget per drain:
                                * beyond it, give the event loop its
                                * receive turn instead of wedging it */

/* Aggregate send-rate pacing (token bucket) is shared with proxy.c —
 * see pace_bucket in util.h. Enabled only via the environment variable
 * IWAN_SEND_PACING_PPS (default 0 = disabled). run_socks() initializes
 * the bucket and sock_drain_tx() accounts each batch with pace_take(). */

/* Send one accumulated batch: uniform batches (>=2 packets, total <= 65507)
 * go out as a single GSO sendmsg with a multi-iovec message (the kernel
 * treats the iovecs as one continuous stream and segments it; wire output
 * is identical to per-packet sends). Everything else goes via sendmmsg.
 * EAGAIN/ENOBUFS block on POLLOUT for a bounded budget instead of
 * dropping; only fatal errors stop the proxy. The bound matters: this
 * drain runs at the TOP of the event loop, and an unbounded retry would
 * starve receive_vpn — the ACK rcvbuf would overflow while we spin on a
 * full send buffer, and the livelock (no ACKs -> RTO -> more retries)
 * stalls the tunnel for seconds. Items left unsent are safe to lose:
 * the tx queue's eviction contract recovers data segments by RTO and
 * regenerates pure ACKs.
 *
 * Kernel-feature review (Linux 7.0, source-verified, measured on
 * loopback): io_uring SENDMSG (46 SQEs/enter) measured ~6% SLOWER than
 * this path (617-635 vs 664-688 MB/s) and has no sendmmsg equivalent for
 * mixed-length batches; SENDMSG_ZC / SO_ZEROCOPY are blocked structurally:
 * seg_compact() memmoves the retransmit slots and retransmit re-seals
 * them in place, both illegal while a zerocopy notification is
 * outstanding. This GSO+sendmmsg shape is the local optimum. */

/* One transient EAGAIN/ENOBUFS/EPERM drain stall (EINTR is handled by
 * the caller before this runs): emit a throttled diagnostic — one per
 * second per drain path, each call site keeps its own last_diag static,
 * so a GSO stall and a sendmmsg stall within the same second are both
 * reported — then wait up to 1ms for the socket to become writable
 * (writable means the buffer drained, so resend immediately; the old
 * poll-then-usleep inverted this and slept AFTER a writable poll).
 * Returns 1 to retry, or 0 when the bounded retry budget (shared by the
 * whole socks_send_batch2 drain via retry_t0) is exhausted: the caller
 * then returns whatever it has sent so far, giving the event loop its
 * receive turn (see the function comment). Same retry shape as proxy.c
 * send_gso / send_batch. */
static int socks_send_stall_wait(int sockfd, uint64_t retry_t0,
                                 uint64_t *last_diag, const char *diag_fmt,
                                 int npk, unsigned sent)
{
    uint64_t nowd = now_ms();
    if (nowd - *last_diag >= 1000) {
        *last_diag = nowd;
        log_err(diag_fmt, strerror(errno), npk, sent);
    }
    struct pollfd pfd = { .fd = sockfd, .events = POLLOUT };
    (void)port_poll(&pfd, 1, 1);
    if (now_ms() - retry_t0 >= SOCKS_SEND_RETRY_MS)
        return 0;
    return 1;
}

static int socks_send_batch2(int sockfd, SocksConfig *cfg,
                             struct iovec *iovs, struct mmsghdr *msgs,
                             int npk, size_t total, size_t mss)
{
    uint64_t retry_t0 = now_ms();
    if (npk >= 2 && mss >= IWAN_GSO_MSS_MIN &&
        total <= IWAN_UDP_GSO_UNIT &&
        total <= IWAN_GSO_UNIT_SAFE) {
        if (cfg->gso_ok == 0) {
            int m = (int)mss;
            /* port_setsockopt translates UDP_SEGMENT to the Windows
             * WSAIoctl(SIO_UDP_NETSEGMENT) GSO interface and fails with
             * EOPNOTSUPP on older systems, so the gso_ok == -1 fallback
             * below works unchanged on both platforms */
            cfg->gso_ok = port_setsockopt(sockfd, SOL_UDP, UDP_SEGMENT,
                                          &m, sizeof m) == 0 ? 1 : -1;
            if (cfg->gso_ok < 0)
                log_err("SOCKS UDP_SEGMENT unsupported, using sendmmsg");
            else
                cfg->gso_mss = mss;
        } else if (cfg->gso_ok > 0 && cfg->gso_mss != mss) {
            /* C1-style: a different mss re-arms the socket option (a
             * mixed-MTU stream is rare on the uplink; the probe cost
             * only bites per drain round with a changed mss) */
            int m = (int)mss;
            if (port_setsockopt(sockfd, SOL_UDP, UDP_SEGMENT, &m,
                                sizeof m) != 0)
                cfg->gso_ok = -1;
            else
                cfg->gso_mss = mss;
        } else if (cfg->gso_ok < 0) {
            /* M11 (SUMMARY-2): a cached failure is re-probed at most
             * once per second — the cause can be transient (temporary
             * resource exhaustion, a restored offload setting), and a
             * permanent disable would silently cap uplink throughput
             * for the process lifetime. Previously the disabled state
             * was never revisited. */
            static uint64_t last_gso_probe;
            uint64_t now = now_ms();
            if (now - last_gso_probe >= 1000) {
                last_gso_probe = now;
                int m = (int)mss;
                if (port_setsockopt(sockfd, SOL_UDP, UDP_SEGMENT, &m,
                                    sizeof m) == 0) {
                    cfg->gso_ok = 1;
                    cfg->gso_mss = mss;
                }
            }
        }
        if (cfg->gso_ok > 0) {
            struct msghdr mh;
            memset(&mh, 0, sizeof mh);
            mh.msg_iov = iovs;
            mh.msg_iovlen = (size_t)npk;
            while (!g_stop) {
                ssize_t r = port_sendmsg(sockfd, &mh, 0);
                if (r == (ssize_t)total)
                    return npk;
                if (r < 0 &&
                    (errno == EAGAIN || errno == EWOULDBLOCK ||
                     errno == ENOBUFS || errno == EINTR ||
                     errno == EPERM)) {
                    /* EPERM: netfilter OUTPUT DROP returns EPERM for
                     * the dropped datagram (firewall rule, not a dead
                     * tunnel) — transient per-packet, retry like
                     * EAGAIN; TCP retransmission covers the loss */
                    if (errno != EINTR) {
                        /* throttled diagnostic: identify which error
                         * wedges the drain under burst load */
                        static uint64_t last_diag;
                        if (!socks_send_stall_wait(sockfd, retry_t0,
                                                   &last_diag,
                                                   "SOCKS GSO EAGAIN: %s (npk=%d)",
                                                   npk, 0))
                            return 0;
                    }
                    continue;
                }
                /* hard error (EIO/EINVAL/EMSGSIZE/...): UDP_SEGMENT is
                 * unusable on this socket — a feature failure, NOT a
                 * dead tunnel. Disable GSO permanently and fall through
                 * to the per-message sendmmsg path for this batch and
                 * all future ones; only that path may declare the
                 * session lost. */
                log_err("SOCKS GSO send failed: %s; disabling "
                        "UDP_SEGMENT", strerror(errno));
                cfg->gso_ok = -1;
                cfg->gso_mss = 0;
                {
                    int z = 0;
                    port_setsockopt(sockfd, SOL_UDP, UDP_SEGMENT,
                                    &z, sizeof z);
                }
                goto per_msg;
            }
            return 0;
        }
    }
per_msg:

    /* per-message path: a lingering UDP_SEGMENT would silently split any
     * datagram longer than the mss, so clear it first */
    if (cfg->gso_mss != 0) {
        int z = 0;
        port_setsockopt(sockfd, SOL_UDP, UDP_SEGMENT, &z, sizeof z);
        cfg->gso_mss = 0;
    }
    memset(msgs, 0, (size_t)npk * sizeof *msgs);   /* zero msg_name etc */
    for (int k = 0; k < npk; k++) {
        msgs[k].msg_hdr.msg_iov = &iovs[k];
        msgs[k].msg_hdr.msg_iovlen = 1;
    }
    {
        unsigned sent = 0;
        while (sent < (unsigned)npk && !g_stop) {
            ssize_t sm = port_sendmmsg(sockfd, msgs + sent,
                                       (unsigned)npk - sent, 0);
            if (sm > 0) {
                sent += (unsigned)sm;
                continue;
            }
            if (sm == 0)
                return (int)sent;
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK ||
                errno == ENOBUFS || errno == EPERM) {
                /* EPERM: netfilter OUTPUT DROP returns EPERM for the
                 * dropped datagram — transient per-packet, retry like
                 * EAGAIN (send buffer full: poll up to 1ms for
                 * writability, then retry immediately (writable -> the
                 * buffer drained -> resend; same shape as the GSO path
                 * above and proxy.c send_batch). Never blocks the
                 * single event loop — receive_vpn must keep draining
                 * downlink (ACKs, keepalive replies) or the receive
                 * buffer
                 * overflows and the peer's segments (and our own ACK
                 * stream) get dropped, which triggers a retransmit
                 * storm upstream. Bounded: beyond the budget, return
                 * and let the main loop cycle (see the function
                 * comment). */
                static uint64_t last_diag;
                if (!socks_send_stall_wait(sockfd, retry_t0, &last_diag,
                                           "SOCKS sendmmsg EAGAIN: %s (npk=%d sent=%u)",
                                           npk, sent))
                    return (int)sent;
                continue;
            }
            if (errno == EMSGSIZE || errno == EINVAL) {
                /* R37 R3-M4: same classification as the GSO path above —
                 * a per-datagram reject (too large for the path MTU, or
                 * an option the datagram cannot carry) is a FEATURE
                 * failure of this batch, not a dead tunnel. Marking the
                 * session lost here forced a full re-auth and a
                 * reconnect storm while the tunnel was healthy (measured
                 * 6x EMSGSIZE -> 2x "tunnel session lost" -> 3x re-auth
                 * in 21s). The caller re-arms the unsent inner segments
                 * (sock_drain_tx), so returning `sent` drops only this
                 * batch's leftovers and keeps the session. */
                log_err("SOCKS sendmmsg: %s (batch dropped, session kept)",
                        strerror(errno));
                return (int)sent;
            }
            log_err("SOCKS sendmmsg: %s", strerror(errno));
            /* the tunnel socket itself is broken (not a transient
             * buffer condition): mark the session lost so the main
             * loop re-auths in place (or the legacy caller reconnects)
             * instead of killing the whole SOCKS proxy */
            cfg->session_lost = true;
            return (int)sent;
        }
        return (int)sent;
    }
}

/* drain the netstack device queue: ready packets are referenced by
 * pointer (zero-copy segment slots / inline control), batched, and sent
 * via GSO (uniform lengths) or sendmmsg. Framing + XOR were done at seal
 * time inside the stack.
 *
 * When the send path is blocked (ENOBUFS budget expired), the unsent
 * DATA segments are re-enqueued at the tail instead of being dropped
 * into RTO recovery: a dropped segment re-enters the still-full send
 * buffer on retransmit and the RTO doubling escalates into a 30s storm
 * under sustained backpressure. Pure-ACK control items are dropped —
 * the stack regenerates them. A re-enqueued segment whose slot moved in
 * a later compaction still delivers one of the ring's genuine
 * (seq, payload) pairs (payloads are immutable once sealed), so the peer
 * assembles a correct stream — at worst a duplicate it dedups by seq. */
static void sock_drain_tx(int sockfd, SocksConfig *cfg)
{
    struct iovec iovs[SOCKS_MAX_PK];
    struct mmsghdr msgs[SOCKS_MAX_PK];
    const TxItem *items[SOCKS_MAX_PK];
    size_t lens[SOCKS_MAX_PK];
    int npk = 0;
    const TxItem *it;

    while (npk < SOCKS_MAX_PK && (it = ns_tx_peek(&g_ns)) != NULL) {
        size_t l = ns_tx_item_len(it);
        items[npk] = it;
        lens[npk] = l;
        npk++;
        ns_tx_pop(&g_ns);
    }
    if (npk == 0)
        return;
    for (int k = 0; k < npk;) {
        size_t run_total = lens[k];
        int j = k;
        while (j + 1 < npk && lens[j + 1] == lens[k]) {
            if (run_total + lens[k] > IWAN_UDP_GSO_UNIT ||
                run_total + lens[k] > IWAN_GSO_UNIT_SAFE)
                break;   /* split oversized uniform run (also keeps GSO
                          * units under the loopback-safe ceiling) */
            run_total += lens[k];
            j++;
        }
        for (int m = k; m <= j; m++) {
            iovs[m].iov_base = (void *)ns_tx_item_buf(items[m]);
            iovs[m].iov_len = lens[m];
        }
        int sent = socks_send_batch2(sockfd, cfg, iovs + k, msgs + k,
                                     j - k + 1, run_total, lens[k]);
        /* pace the aggregate send rate: see pace_bucket in util.h
         * (IWAN_SEND_PACING_PPS, default off) */
        if (sent > 0)
            pace_take(&cfg->pace, sent);
        if (sent < j - k + 1) {
            /* blocked: re-enqueue the unsent data segments (see above);
             * the already-sent items of this run were sent in order and
             * are gone — re-enqueue from the first unsent one on */
            for (int m = k + sent; m < npk; m++)
                if (items[m]->seg)
                    ns_tx_rearm_seg(&g_ns, items[m]->seg, items[m]->conn);
            return;
        }
        k = j + 1;
    }
}

void send_vpn_keepalive(int sockfd, const SocksConfig *cfg,
                        uint64_t *last_ka) {
    if (now_ms() - *last_ka < SOCKS_KEEPALIVE_MS)
        return;
    buf_t p;
    buf_init(&p);
    ctrl_hdr(&p, PT_ECHO_REQ, cfg->encryption, cfg->sid, cfg->token);
    if (port_send(sockfd, p.data, p.len, 0) < 0) {
        /* transient failures (roaming, carrier hiccup) recover; the
         * main loop re-auths the tunnel once the counter hits the max */
        SocksConfig *c = (SocksConfig *)cfg;
        ++c->ka_fail;
        log_debug("SOCKS keepalive send failed: %s (retry %d/%d)",
                  strerror(errno), c->ka_fail, SOCKS_KA_FAIL_MAX);
    } else {
        ((SocksConfig *)cfg)->ka_fail = 0;
    }
    buf_free(&p);
    *last_ka = now_ms();
}

/* inner DATA dispatch: decrypt, validate, and inject a frame into the
 * netstack (or consume it as a tunnel-DNS response).
 * Returns 1 when the buffer was handed to lwIP (the RX pool owns it
 * until lwIP frees the pbuf), 0 when the caller must release it.
 * When copy is true the buffer is a plain scratch buffer (not a pool
 * slot), so delivery copies via ns_rx_packet instead of the
 * zero-copy ns_rx_packet_ref. */
static int vpn_handle_data(SocksConfig *cfg, uint8_t *b, size_t n,
                           bool copy)
{
    uint8_t t = b[0];
    size_t plen = n - 8;
    if (t == PT_DATA_ENC && !cfg->encryption) {
        /* symmetric gate (audit L14): plaintext session must not
         * accept encrypted frames either */
        log_err("VPN encrypted data on plaintext session, drop");
        return 0;
    }
    if (t == PT_DATA_ENC)
        xor_crypt(b + 8, plen, cfg->xor_key, 8);
    else if (cfg->encryption) {
        /* encrypted session must not accept plaintext frames */
        log_err("VPN plaintext data on encrypted session, drop");
        return 0;
    }
    if (debug_enabled() && t == PT_DATA_ENC) {
        char hex[100] = "";
        int hn = (int)plen < 32 ? (int)plen : 32;
        for (int i = 0; i < hn; i++)
            sprintf(hex + i * 3, "%02x ", b[8 + i]);
        log_debug("DATA decrypted (%lluB): %s...", (unsigned long long)plen,
                  hex);
    }
    uint32_t saddr, daddr;
    if (plen < 20 || plen > (size_t)cfg->mtu)
        return 0;
    if ((b[8] >> 4) == 6) {
        /* inner IPv6 (SOCKS targets over IPv6): R23-F1 — mirror the v4
         * M5 ingress filter: the downlink must be addressed to THIS
         * session's derived ULA and never claim it as source (defense in
         * depth on top of the server's H1 gate). */
        uint8_t s6[16], d6[16], want6[16];
        if (plen < 40 || ip6_pkt_ok(b + 8, plen, s6, d6) != 0)
            return 0;
        ip6_derive_ula(cfg->inner_ip, want6);
        if (memcmp(d6, want6, 16) != 0 || memcmp(s6, want6, 16) == 0)
            return 0;
    } else if (ipv4_pkt_ok(b + 8, plen, &saddr, &daddr) != 0) {
        return 0;
    } else {
        /* ingress filter (audit M5): a downlink frame must be
         * addressed to THIS session's IP and must never claim our own
         * address as source — anything else is an injector's forgery,
         * not traffic the stack solicited */
        if (daddr != cfg->inner_ip || saddr == cfg->inner_ip)
            return 0;
    }
    /* M1: inner UDP packets whose dst port belongs to a pending
     * tunnel DNS query are responses — consume them here, never
     * hand them to the TCP stack */
    if (dns_try_handle_response(b + 8, plen))
        return 0;
    if (copy)
        ns_rx_packet(&g_ns, b + 8, plen);   /* inner already XOR-decrypted
                                             * in place */
    else
        ns_rx_packet_ref(&g_ns, b, n);
    return 1;
}

/* one received VPN datagram: outer-header validation (type/sid/token),
 * control frames (CLOSE / ECHO_REQ), and inner-packet dispatch.
 * Returns -1 when the session must stop (server CLOSE), 0 when the
 * caller must release the RX buffer, 1 when the buffer was handed to
 * lwIP (RX pool owns it). */
static int vpn_handle_datagram(int sockfd, SocksConfig *cfg, uint8_t *b,
                               size_t n, bool copy)
{
    uint8_t t = b[0];
    uint16_t psid = (uint16_t)((b[2] << 8) | b[3]);
    uint32_t ptok = ((uint32_t)b[4] << 24) | ((uint32_t)b[5] << 16) |
                    ((uint32_t)b[6] << 8) | b[7];
    if (dbg_env("IWAN_RXDBG"))
        fprintf(stderr, "VRX: n=%llu t=%u\n", (unsigned long long)n, t);
    if (debug_enabled())
        log_debug("VPN RX type=%u n=%llu sid=%u tok=****%04x "
                  "(cfg sid=%u tok=****%04x)",
                  t, (unsigned long long)n, psid, ptok & 0xFFFFu, cfg->sid,
                  cfg->token & 0xFFFFu);
    if (psid != cfg->sid || ptok != cfg->token)
        return 0;
    /* A-4: a frame that passes the sid/token gate is a genuine downlink
     * for THIS session (ECHO_REQ / CLOSE / DATA/DATA_ENC) — the true
     * "session is alive" signal. The stale-session clock is reset HERE
     * (moved from receive_vpn's raw "v > 0" refresh, which spoofable
     * old/junk frames could keep asleep). The cfg parameter is available
     * here and last_rx is refreshed before type dispatch. */
    cfg->last_rx = now_ms();
    if (t == PT_CLOSE) {
        /* control packets carry the 16-byte header sig; never
         * let a spoofed sid/tok-only datagram kill the session */
        if (!verify_sig(b, n))
            return 0;
        log_err("VPN server closed the session (CLOSE)");
        cfg->session_lost = true;   /* re-auth + re-run (caller loop) */
        return -1;
    }    if (t == PT_ECHO_REQ) {
        if (!verify_sig(b, n))
            return 0;
        buf_t p;
        buf_init(&p);
        ctrl_hdr(&p, PT_ECHO_RES, cfg->encryption, cfg->sid, cfg->token);
        /* a failed reply is not worth tearing the session down for: the
         * next ECHO_REQ gets an answer (or the keepalive machinery
         * detects a dead socket) */
        if (port_send(sockfd, p.data, p.len, 0) < 0)
            log_err("SOCKS ECHO_RES send failed: %s", strerror(errno));
        buf_free(&p);
        return 0;
    }
    if (t != PT_DATA && t != PT_DATA_ENC)
        return 0;
    return vpn_handle_data(cfg, b, n, copy);
}

/* recvmmsg drain: one syscall per up-to-64 datagrams, MSG_DONTWAIT so
 * the poll in wait_events stays the only latency source (passing a
 * non-NULL timeout to recvmmsg does NOT bound the first packet's
 * wait, kernel do_recvmmsg bug). 2KB per slot covers any server
 * datagram (inner MTU <= 1500 + 8B header); oversized packets are
 * truncated and skipped via MSG_TRUNC.
 *
 * Kernel-feature review (Linux 7.0, source-verified, measured on
 * loopback): io_uring multishot recv + provided-buffer ring and
 * UDP_GRO were both evaluated and rejected. UDP_GRO coalesces
 * datagrams into one buffer, but our 8B outer header has no length
 * field and the inner IP header is XOR-encrypted, so frame
 * boundaries become unrecoverable. Multishot recv measured ~15%
 * SLOWER than this recvmmsg path (1686 vs 1996 MB/s) because per-CQE
 * handling costs more than the batched syscall it replaces, and the
 * provided-buffer ring hits an unavoidable consumer-vs-producer
 * race at full ring (spurious -ENOBUFS that kills the multishot,
 * kernel io_ring_buffer_select). Keep recvmmsg + poll. */
int receive_vpn(int sockfd, SocksConfig *cfg) {
    enum { RX_VLEN = 64, RX_SLOT = NS_RX_SLOT };
    /* R37 R1E-3: the recvmmsg iov_len below is what the kernel writes into
     * each zero-copy pool slot, so it must equal the bridge's slot capacity.
     * Referencing the header macro (instead of the private 2048 this file
     * used to carry) makes any drift a compile error rather than a pool
     * overflow. The copy-fallback scratch mirrors the same size. */
    _Static_assert(RX_SLOT == NS_RX_SLOT, "RX slot size must match the bridge pool");
    static struct iovec rx_iov[RX_VLEN];
    static struct mmsghdr rx_msgs[RX_VLEN];
    void *rx_bufs[RX_VLEN];
    /* R18 copy-fallback scratch: used only when the zero-copy RX pool
     * is exhausted (see the got==0 branch below). Not pool slots, so
     * they are re-pointed per drain just like the iov bases. */
    static uint8_t copy_buf[RX_VLEN][RX_SLOT];
    static struct iovec copy_iov[RX_VLEN];
    static struct mmsghdr copy_msgs[RX_VLEN];
    static int rx_init;

    if (!rx_init) {
        /* static: zero once; the iov bases are re-pointed at the pool
         * buffers on every drain below */
        memset(rx_msgs, 0, sizeof rx_msgs);
        memset(copy_msgs, 0, sizeof copy_msgs);
        rx_init = 1;
    }

    int budget = 256;
    for (;;) {
        /* yield to the other phases once 256 packets have been handled:
         * with a fast peer the socket never drains, and an unbounded
         * loop starves local reads and TX (echo-mode livelock) */
        if (budget <= 0)
            return 0;
        int got = ns_rx_buf_acquire(rx_bufs, RX_VLEN);
        if (got == 0) {
            /* R07-M2 / R18: the zero-copy RX pool (NS_RX_POOL=256) can be
             * fully held by lwIP OOSEQ pbufs (8 conns x 32 OOS = 256), so a
             * plain "return 0" would STOP reading and starve the tunnel's
             * in-order gap fillers for seconds. Fall back to a bounded
             * COPYING drain into static scratch (ns_rx_packet -> PBUF_POOL
             * + pbuf_take): gap fillers reach lwIP, the pool recycles, and
             * the normal path stays zero-copy with no capacity cliff. */
            for (;;) {
                if (budget <= 0)
                    return 0;
                for (int i = 0; i < RX_VLEN; i++) {
                    copy_iov[i].iov_base = copy_buf[i];
                    copy_iov[i].iov_len = RX_SLOT;
                    copy_msgs[i].msg_hdr.msg_iov = &copy_iov[i];
                    copy_msgs[i].msg_hdr.msg_iovlen = 1;
                }
                int v = port_recvmmsg(sockfd, copy_msgs, RX_VLEN,
                                      MSG_DONTWAIT, NULL);
                if (v < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                    errno != ECONNREFUSED && errno != EINTR) {
                    log_err("receive_vpn: recvmmsg (copy fallback): %s",
                            strerror(errno));
                    cfg->session_lost = true;
                    return -1;
                }
                if (v <= 0)
                    return 0;   /* drained (copy mode has no pool ownership) */
                budget -= v;
                for (int i = 0; i < v; i++) {
                    ssize_t n = copy_msgs[i].msg_len;
                    if (n < 8 || (copy_msgs[i].msg_hdr.msg_flags & MSG_TRUNC))
                        continue;   /* no pool slot to release in copy mode */
                    int r = vpn_handle_datagram(sockfd, cfg, copy_buf[i],
                                                (size_t)n, true);
                    if (r < 0)
                        return -1;   /* session lost (server CLOSE / fatal) */
                }
                if (v < RX_VLEN)
                    return 0;   /* partial batch: drained */
            }
        }
        for (int i = 0; i < got; i++) {
            rx_iov[i].iov_base = rx_bufs[i];
            rx_iov[i].iov_len = RX_SLOT;
            rx_msgs[i].msg_hdr.msg_iov = &rx_iov[i];
            rx_msgs[i].msg_hdr.msg_iovlen = 1;
        }
        int v = port_recvmmsg(sockfd, rx_msgs, (unsigned)got,
                              MSG_DONTWAIT, NULL);
        /* A-4: last_rx is NOT refreshed here merely because a datagram
         * was received — the old "v > 0 => refresh" rule let a peer
         * keep the stale-session watchdog asleep by flooding frames
         * whose sid/token gate then rejects them. It is refreshed
         * inside vpn_handle_datagram only AFTER the sid/token gate
         * passes (a genuinely valid session frame = the true "session is
         * alive" downlink signal). The RX-pool-exhausted path (got == 0)
         * never reaches here and does not refresh, as intended. */
        /* EINTR is tolerated (falls into the v <= 0 drained branch
         * below): Linux native recvmmsg returns -1/EINTR when a
         * stopping-class signal interrupts the syscall at entry with 0
         * received, whereas macOS/Windows normalize that to 0 — treating
         * it as a drop would reconnect the tunnel on Linux only. */
        if (v < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
            errno != ECONNREFUSED && errno != EINTR) {
            for (int i = 0; i < got; i++)
                ns_rx_buf_release(rx_bufs[i]);
            log_err("receive_vpn: recvmmsg: %s", strerror(errno));
            /* ECONNRESET is deliberately NOT tolerated here: socks is a
             * connected-type VPN tunnel, so a reset means real loss and
             * reconnect is correct — unlike the proxy's UDP->TUN pump,
             * which normalizes it to 0. */
            cfg->session_lost = true;   /* abnormal: reconnect, not a
                                         * clean user stop (run_socks
                                         * returns 1) */
            return -1;
        }
        if (v <= 0) {
            for (int i = 0; i < got; i++)
                ns_rx_buf_release(rx_bufs[i]);
            return 0;   /* drained (ECONNREFUSED: connected-UDP ICMP
                         * artifact; keepalives detect real loss) */
        }
        budget -= v;
        for (int i = 0; i < v; i++) {
            ssize_t n = rx_msgs[i].msg_len;
            if (n < 8 || (rx_msgs[i].msg_hdr.msg_flags & MSG_TRUNC)) {
                ns_rx_buf_release(rx_bufs[i]);
                continue;
            }
            int r = vpn_handle_datagram(sockfd, cfg, rx_bufs[i], (size_t)n,
                                        false);
            if (r < 0) {
                /* the handler did not take pool ownership: release the
                 * current slot too, or a PT_CLOSE (and any other fatal
                 * return) leaks it — 256 slots, init-once, and an
                 * in-place re-auth per CLOSE would exhaust the pool
                 * (SUMMARY-2 M9) */
                ns_rx_buf_release(rx_bufs[i]);
                for (int j = i + 1; j < got; j++)
                    ns_rx_buf_release(rx_bufs[j]);
                return -1;
            }
            if (r == 0)
                ns_rx_buf_release(rx_bufs[i]);
            /* r == 1: the RX pool owns the buffer until lwIP frees it */
        }
        for (int i = v; i < got; i++)
            ns_rx_buf_release(rx_bufs[i]);
        if (v < got)
            break;   /* partial batch: drained */
    }
    return 0;
}

/* Re-establish every active flow on a rebuilt netstack (only used when
 * the re-auth changed our inner IP/gateway/MTU). Flows with a target
 * (CONNECTING/ESTABLISHED) get a fresh inner connection on the new
 * tunnel; the success reply is not repeated (reply_sent). DNS-bound
 * flows fail (their workers were retired by dns_reset). */
static void socks_reauth_flows(void)
{
    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &g_flows[i];
        if (!f->active)
            continue;
        if (f->state == ST_RESOLVING) {
            /* R37 R1-A-10: no ns_flow_unref here. This function runs only
             * after ns_init(), which already wiped g_flow_ref; f->ns_idx is
             * the PRE-rebuild slot number, so the unref could only clear a
             * ref that an earlier-processed flow has just taken for its NEW
             * slot (same lowest-free allocation order), defeating the
             * FIND-R2-5/F03-1 ownership guard. Bare detach is the correct
             * pairing here. */
            f->ns_idx = -1;
            queue_socks_error(f, 4);
            set_flow_state(f, ST_CLOSING);
            continue;
        }
        if (f->ns_idx < 0)
            continue;   /* handshake states: nothing to re-establish */
        if (f->state != ST_CONNECTING && f->state != ST_ESTABLISHED) {
            f->ns_idx = -1;   /* stale index into the rebuilt stack
                               * (R37 R1-A-10: no unref, see above) */
            continue;
        }
        uint16_t port = f->tgt_port;
        uint8_t af = f->tgt_af;
        f->ns_idx = -1;
        /* R37 R1-A-10: no ns_flow_unref here either — the ref for the new
         * slot is taken by open_tcp_connection{6} below. */
        f->rx_paused = false;
        if (af == 6)
            open_tcp_connection6(f, f->tgt_ip6, port);
        else if (af == 4)
            open_tcp_connection(f, f->tgt_ip4, port);
    }
}

/* Re-auth the tunnel IN PLACE: the callback opens a fresh session and
 * refreshes cfg's session fields. On success returns the new UDP socket
 * fd (the caller closes the old one); on failure schedules a retry and
 * returns -1 (the proxy keeps running either way). */
static int socks_reauth_tunnel(SocksConfig *cfg)
{
    if (!cfg->reauth)
        return -1;
    uint32_t old_ip = cfg->inner_ip, old_gw = cfg->gateway;
    int old_mtu = cfg->mtu;
    int newfd = -1;
    if (cfg->reauth(cfg->reauth_ud, cfg, &newfd) != 0 || newfd < 0) {
        cfg->reauth_at = now_ms() + SOCKS_KEEPALIVE_MS;
        log_err("SOCKS: tunnel re-auth failed; retrying in %us",
                SOCKS_KEEPALIVE_MS / 1000);
        return -1;
    }
    cfg->last_rx = now_ms();
    cfg->ka_fail = 0;
    cfg->reauth_at = 0;
    cfg->session_lost = false;
    log_err("SOCKS: tunnel re-authenticated (sid 0x%04x, inner %u.%u.%u.%u)",
            cfg->sid, (cfg->inner_ip >> 24) & 0xff, (cfg->inner_ip >> 16) & 0xff,
            (cfg->inner_ip >> 8) & 0xff, cfg->inner_ip & 0xff);
    /* the tunnel-DNS workers are session-bound: retire them before the
     * old socket closes and reset the wait table for the new session */
    dns_stop();
    /* R25-f1 F1: publish g_dns_server_ip4 under the same DNS wait mutex the
     * workers snapshot under (R20 contract) — dns_stop/dns_reset self-lock,
     * but the write to g_dns_server_ip4 between them does not otherwise; an
     * unlocked write vs the worker's unlocked read is a formal data race
     * (the exact class R20 claimed fixed). */
    dns_session_lock();
    dns_set_server(cfg->dns);
    dns_session_unlock();
    dns_reset();
    uint8_t oh[8];
    pkt_hdr(cfg->encryption ? PT_DATA_ENC : PT_DATA, cfg->encryption,
            cfg->sid, cfg->token, oh);
    if (cfg->inner_ip == old_ip && cfg->gateway == old_gw &&
        cfg->mtu == old_mtu) {
        /* same carrier, fresh session: the tunnel is only the carrier, so
         * the lwIP stack and every inner connection survive untouched.
         * Drop the queued tx frames (their outer headers carry the old
         * sid/token); lwIP's RTO retransmits the same segments with the
         * new header. Old-session downlink frames are rejected by the
         * sid/token gate in receive_vpn. */
        /* R4-09-F3: dns_reset() above retired all in-flight DNS workers and
         * cleared the wait table, so a flow still in ST_RESOLVING can never
         * get a result — fail it now (matching the IP-change path) rather
         * than leave it hanging to the 30s handshake timeout with no reply. */
        for (int i = 0; i < MAX_FLOWS; i++) {
            Flow *f = &g_flows[i];
            if (f->active && f->state == ST_RESOLVING) {
                f->ns_idx = -1;
                queue_socks_error(f, 4);
                set_flow_state(f, ST_CLOSING);
            }
        }
        dns_session_lock();   /* R25-f1 F1: same R20 publish contract */
        ns_set_outer(&g_ns, oh, cfg->xor_key);
        dns_session_unlock();
        while (ns_tx_peek(&g_ns))
            ns_tx_pop(&g_ns);
        log_info("SOCKS: inner connections kept (same inner IP)");
    } else {
        /* the server re-assigned our inner IP: rebuild the stack and
         * re-establish every active flow on the new tunnel */
        /* FIND-R19-F5: netif_add failure must not be swallowed — return -1
         * so the caller re-auth retry schedule (reauth_at backoff) fixes
         * the stack instead of running receive_vpn against a dead netif. */
        dns_session_lock();   /* R20: publish under the DNS wait mutex */
        if (!ns_init(&g_ns, cfg->inner_ip, cfg->gateway, (uint16_t)cfg->mtu)) {
            dns_session_unlock();
            /* R24-f2 F1: this fresh session fd is NOT owned by the caller
             * (socks_reauth_swap bails on nfd<0 without installing it), so
             * close it here or it leaks one socket per failed re-auth. */
            port_close(newfd);
            log_err("SOCKS: stack rebuild failed");
            return -1;
        }
        ns_set_outer(&g_ns, oh, cfg->xor_key);
        dns_session_unlock();
        socks_reauth_flows();
        log_info("SOCKS: inner IP changed; flows re-established");
    }
    return newfd;
}

/* re-auth succeeded: swap the tunnel socket in place.
 * Ownership note (A-1): this closes the OLD fd and installs the new one
 * into *sockfd; run_socks's teardown then owns and closes the CURRENT
 * fd on exit, so the caller must never close either rendition. */
static void socks_reauth_swap(int *sockfd, int nfd, SocksConfig *cfg)
{
    if (nfd < 0)
        return;
    /* FIND-F02-1: the GSO cache lives on the SocksConfig but UDP_SEGMENT is
     * a per-SOCKET option — after swapping in a fresh session fd the old
     * gso_ok/gso_mss describe a socket that no longer exists (the new one
     * was never configured), so reset to untried and let the next send
     * batch re-probe. Otherwise the inline state machine would send long
     * datagrams as if GSO were armed: silent kernel IP fragmentation /
     * EMSGSIZE + throughput loss (and the M11 re-probe never sees it). */
    cfg->gso_ok = 0;   /* socks.h semantics: 0 = untried */
    cfg->gso_mss = 0;
    port_close(*sockfd);
    *sockfd = nfd;
    g_sockfd = nfd;
}

int run_socks(int sockfd, SocksConfig *cfg) {
    int listener;

    /* M1 stop guard: the ctrl handler is installed process-wide for
     * life (Windows has no per-session save/restore), so on a
     * reconnecting session a Ctrl-C pressed during the blocking
     * authenticate()/setup above has already set g_user_stop. Honor it
     * here and return 0 (the caller's "user stopped it" code) WITHOUT
     * clearing g_stop below, instead of swallowing the stop and
     * starting a fresh session. The main-loop condition also watches
     * g_user_stop, so a stop landing between this check and the loop
     * start is honored too. */
    if (g_user_stop) {
        /* A-1: run_socks owns sockfd from entry and every return path
         * must close it (callers no longer close after run_socks
         * returns), including this pre-setup stop. */
        port_close(sockfd);
        return 0;
    }

    /* runtime session-health state: memset-to-zero callers leave
     * last_rx = 0, which would read as "no downlink for 16 hours" */
    cfg->last_rx = now_ms();
    cfg->ka_fail = 0;
    cfg->session_lost = false;
    struct sockaddr_in laddr = cfg->listen_addr;

    g_socks_cfg = cfg;
    pace_bucket_init(&cfg->pace);   /* reads IWAN_SEND_PACING_PPS (0 = off) */

    listener = port_socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        log_err("socket SOCKS5 listener: %s", strerror(errno));
        port_close(sockfd);   /* A-1: own + close sockfd on every return */
        return -1;   /* R13-M-1: startup failure, NOT a clean user stop */
    }
    int one = 1;
    port_setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (port_bind(listener, (struct sockaddr *)&laddr, sizeof laddr) < 0) {
        log_err("bind SOCKS5 listener: %s", strerror(errno));
        port_close(listener);
        port_close(sockfd);   /* A-1: own + close sockfd on every return */
        return -1;   /* R13-M-1: startup failure, NOT a clean user stop */
    }
    if (laddr.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        if (cfg->allow_remote) {
            if (cfg->auth_token)
                log_err("WARNING: SOCKS5 proxy bound to a non-loopback "
                        "address; remote clients are served only with the "
                        "--socks-token password");
            else if (cfg->open_proxy)
                log_err("WARNING: OPEN SOCKS5 proxy bound to a non-loopback "
                        "address with no password (--socks-no-token); any "
                        "reachable client can use it");
            else
                log_err("WARNING: SOCKS5 proxy bound to a non-loopback "
                        "address but remote peers will still be rejected "
                        "(no --socks-token set: an open proxy would be "
                        "dangerous)");
        } else {
            log_err("error: refusing to bind SOCKS5 to non-loopback %s; "
                    "pass --allow-remote to override",
                    cfg->listen_str ? cfg->listen_str : "?");
            port_close(listener);
            port_close(sockfd);   /* A-1: own + close sockfd on every return */
            return -1;   /* R13-M-1: config/deploy failure, NOT user stop */
        }
    }
    if (port_listen(listener, LISTEN_BACKLOG) < 0) {
        log_err("listen SOCKS5: %s", strerror(errno));
        port_close(listener);
        port_close(sockfd);   /* A-1: own + close sockfd on every return */
        return -1;   /* R13-M-1: startup failure, NOT a clean user stop */
    }
    /* A-6: non-blocking mode is not optional here — a blocking listener
     * would freeze the single-threaded event loop on the first accept,
     * and a blocking session socket would stall sends. Refuse to start
     * (same style as the error paths above) rather than half-set-up.
     * sockfd is closed on these failure returns too: run_socks owns it
     * from entry and the callers no longer close it (A-1). */
    if (port_set_nonblock(listener, true) < 0) {
        log_err("SOCKS5: set nonblock on listener: %s", strerror(errno));
        port_close(listener);
        port_close(sockfd);
        return -1;   /* R13-M-1: startup failure, NOT a clean user stop */
    }
    if (port_set_nonblock(sockfd, true) < 0) {
        log_err("SOCKS5: set nonblock on session socket: %s",
                strerror(errno));
        port_close(listener);
        port_close(sockfd);
        return -1;   /* R13-M-1: startup failure, NOT a clean user stop */
    }
    {
        /* high-BDP tunnel: default UDP buffers (~212KB) overflow once
         * the TCP window keeps >~150 segments in flight, silently
         * dropping packets at full rate */
        int rbuf = SOCK_BUF_BYTES;
        port_setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rbuf, sizeof rbuf);
        port_setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &rbuf, sizeof rbuf);
        {
            /* Linux silently caps SO_RCVBUF at net.core.rmem_max, so the
             * 16MB request is a no-op on an unprivileged default system;
             * detect it and tell the operator instead of pretending. */
            int got = 0;
            socklen_t gl = sizeof got;
            if (port_getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &got, &gl) == 0 &&
                got < rbuf / 2) {
#ifdef __linux__
                log_err("SO_RCVBUF capped at %d (requested %d): raise "
                        "net.core.rmem_max/wmem_max for the high-BDP buffer",
                        got, rbuf);
#elif defined(__APPLE__) || defined(__FreeBSD__) || \
      defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
                log_err("SO_RCVBUF capped at %d (requested %d): raise "
                        "sysctl kern.ipc.maxsockbuf for the high-BDP buffer",
                        got, rbuf);
#else
                log_err("SO_RCVBUF capped at %d (requested %d): raise "
                        "the system socket buffer limit for the high-BDP buffer",
                        got, rbuf);
#endif
            }
        }
    }

    /* M1: tunnel DNS shares the session socket and the server-assigned
     * resolver (fallback 114.114.114.114 when the server sent none).
     * Both are fixed before any DNS worker can spawn (workers are only
     * created inside the event loop below). */
    g_sockfd = sockfd;
    /* R20 (R06 M-3): dns_set_server/ns_init/ns_set_outer publish the
     * session globals DNS workers build packets from (g_dns_server_ip4,
     * g_ns.ip/outer_hdr/xor_key) — write them under the DNS wait mutex so
     * the workers' locked snapshot reads are race-free (previously an
     * unlocked write vs unlocked read = formal C11 data race). */
    dns_session_lock();
    dns_set_server(cfg->dns);

    /* Rust prints the configured address (config.listen), not the bound one */
    const char *listen_s = cfg->listen_str ? cfg->listen_str : "?";

    /* FIND-R19-F5: netif_add failure is a real startup failure — close the
     * listener + session socket (A-1) and return the R13 three-state -1
     * instead of running receive_vpn against a half-built stack. */
    if (!ns_init(&g_ns, cfg->inner_ip, cfg->gateway, (uint16_t)cfg->mtu)) {
        dns_session_unlock();
        log_err("SOCKS: ns_init failed at startup");
        port_close(listener);
        port_close(sockfd);   /* A-1: own + close sockfd on every return */
        return -1;   /* R13-M-1: startup failure, NOT a clean user stop */
    }
    {
        uint8_t oh[8];
        pkt_hdr(cfg->encryption ? PT_DATA_ENC : PT_DATA, cfg->encryption,
                cfg->sid, cfg->token, oh);
        ns_set_outer(&g_ns, oh, cfg->xor_key);
    }
    dns_session_unlock();

    g_flows = calloc(MAX_FLOWS, sizeof *g_flows);
    if (!g_flows) {
        port_close(listener);
        port_close(sockfd);   /* A-1: own + close sockfd on every return */
        return -1;   /* R13-M-1: startup failure, NOT a clean user stop */
    }
    g_next_id = 1;
    /* clear any DNS state a previous session left behind (result ring,
     * wait table) so stale entries can never match a fresh session's
     * flows or queries; also retires workers that outlived it */
    dns_reset();
    atomic_store_explicit(&g_dns_evfd, port_evfd_create(),
                          memory_order_relaxed);

    /* run_socks must be re-entrant: clear any stale stop flag BEFORE
     * installing the handlers (a signal arriving between the two would
     * otherwise be dropped) */
    atomic_store_explicit(&g_stop, false, memory_order_relaxed);

#ifdef _WIN32
    /* Windows: console ctrl events go through the port layer, which
     * normalizes every stop event to SIGINT. The handler is
     * process-global: port_set_stop_handler replaces any previous
     * handler, and there is no per-session save/restore (a console
     * ctrl handler cannot be scoped to one run_socks instance). */
    port_set_stop_handler(on_sig);
#else
    struct sigaction sa, old_int, old_term, old_pipe;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sigaction(SIGINT, &sa, &old_int);
    sigaction(SIGTERM, &sa, &old_term);
    /* a SOCKS client dying mid-write must surface EPIPE on the next
     * write, not kill the proxy with the default SIGPIPE disposition;
     * save the previous disposition first so exit can restore it */
    sigaction(SIGPIPE, NULL, &old_pipe);
    signal(SIGPIPE, SIG_IGN);
#endif

    log_info("SOCKS5 listening on %s", listen_s);
    if (debug_enabled())
        log_debug("SOCKS5 network: IP %d.%d.%d.%d, gateway %d.%d.%d.%d, MTU %d",
                  (cfg->inner_ip >> 24) & 0xff, (cfg->inner_ip >> 16) & 0xff,
                  (cfg->inner_ip >> 8) & 0xff, cfg->inner_ip & 0xff,
                  (cfg->gateway >> 24) & 0xff, (cfg->gateway >> 16) & 0xff,
                  (cfg->gateway >> 8) & 0xff, cfg->gateway & 0xff, cfg->mtu);

    uint64_t last_ka = now_ms() - SOCKS_KEEPALIVE_MS;
    unsigned stale_ms = socks_rx_stale_ms();   /* parsed once, cached */

    while (!g_stop && !g_user_stop) {
        /* downlink-silence watchdog: re-auth the tunnel in place (the
         * listener, flows and inner TCP survive); the old behavior —
         * declaring the session lost and exiting — only applies when no
         * re-auth callback was provided. stale_ms == 0 disables it. */
        /* A-2: fold the watchdog into the reauth_at backoff — a stale
         * trigger while a previous re-auth is still backing off (a
         * failed auth sets reauth_at = now+10s) must NOT immediately
         * fire a second full re-auth. legacy (!cfg->reauth) keeps
         * reauth_at == 0 (socks_reauth_tunnel bails at its top and never
         * sets it), so that path is unchanged: still an immediate
         * session_lost/exit. */
        if (stale_ms != 0 && now_ms() - cfg->last_rx > stale_ms &&
            (cfg->reauth_at == 0 || now_ms() >= cfg->reauth_at)) {
            log_err("SOCKS: no downlink for %llu ms; re-authing tunnel",
                    (unsigned long long)(now_ms() - cfg->last_rx));
            int nfd = socks_reauth_tunnel(cfg);
            socks_reauth_swap(&sockfd, nfd, cfg);
            if (nfd < 0 && !cfg->reauth) {
                cfg->session_lost = true;
                g_stop = 1;
                break;
            }
        }
        /* a failed re-auth retries on this schedule */
        if (cfg->reauth_at != 0 && now_ms() >= cfg->reauth_at) {
            int nfd = socks_reauth_tunnel(cfg);
            socks_reauth_swap(&sockfd, nfd, cfg);
        }
        /* flush leftover tx items first: their segment pointers stay
         * valid only until receive_vpn's handle_rx drop/compact moves
         * the retransmit table */
        sock_drain_tx(sockfd, cfg);
        if (cfg->session_lost) {
            /* a hard send error killed the tunnel socket: re-auth in
             * place (callback) or legacy exit for the caller loop.
             * session_lost is cleared inside socks_reauth_tunnel on
             * success; on failure it stays cleared so the retry runs
             * on the reauth_at schedule instead of every loop round. */
            int nfd = socks_reauth_tunnel(cfg);
            socks_reauth_swap(&sockfd, nfd, cfg);
            if (nfd < 0 && !cfg->reauth) {
                break;
            } else if (nfd < 0) {
                cfg->session_lost = false;
            }
        }
        /* the queue drained: let lwIP retry output it held on ERR_MEM */
        ns_tx_kick(&g_ns);
        send_vpn_keepalive(sockfd, cfg, &last_ka);
        /* A-3: same reauth_at backoff as the stale watchdog — a failed
         * re-auth sets reauth_at (= now+10s) and does NOT reset ka_fail
         * (only success does), so without this gate every loop round
         * would re-auth again and blast the server. legacy keeps
         * reauth_at == 0 -> unchanged behavior. */
        if (cfg->ka_fail >= SOCKS_KA_FAIL_MAX &&
            (cfg->reauth_at == 0 || now_ms() >= cfg->reauth_at)) {
            log_err("SOCKS: %d consecutive keepalive send failures; "
                    "re-authing tunnel", cfg->ka_fail);
            int nfd = socks_reauth_tunnel(cfg);
            socks_reauth_swap(&sockfd, nfd, cfg);
            if (nfd < 0 && !cfg->reauth) {
                cfg->session_lost = true;
                g_stop = 1;
                break;
            }
        }
        accept_connections(listener);
        if (receive_vpn(sockfd, cfg) < 0) {
            /* server CLOSE / hard recv error: re-auth in place when a
             * callback exists, else legacy exit for the caller loop */
            int nfd = socks_reauth_tunnel(cfg);
            socks_reauth_swap(&sockfd, nfd, cfg);
            if (nfd >= 0)
                continue;
            if (!cfg->reauth) {
                cfg->session_lost = true;
                g_stop = 1;
                break;
            }
            /* A-5: hard recv error (receive_vpn set session_lost on its
             * abnormal path) and the re-auth FAILED (callback exists):
             * without clearing it the next round's session_lost branch
             * would immediately re-auth once more before the reauth_at
             * backoff takes effect. Clear it so the retry runs on the
             * reauth_at schedule (mirrors the session_lost branch
             * above, :1062-1063). */
            cfg->session_lost = false;
        }
        service_local_inputs(g_flows);
        handle_dns_results();
        /* consume the rxq BEFORE ns_tick advertises the window: an
         * unconsumed rxq would make conn_win() report 0 and the peer
         * would stop echoing (advertised-window stall) */
        service_local_outputs();
        int tick_ms = ns_tick(&g_ns, now_ms());
        /* flush freshly enqueued segments (same-round, pointers valid) */
        sock_drain_tx(sockfd, cfg);
        /* the queue drained: retry lwIP output it held on ERR_MEM */
        ns_tx_kick(&g_ns);
        update_tcp_states();
        reap_flows();

        /* event-driven wait: sleep until the earliest real deadline
         * (retransmit/idle, keepalive, connect timeout) instead of a fixed
         * 10ms tick; DNS completions wake us via the eventfd.
         * poll() stays: with <= 259 polled fds the scan is sub-microsecond
         * and the measured ~8.8us is syscall/wakeup latency, so epoll
         * adds nothing; an io_uring loop would replace this wait but
         * measured slower on both TX and RX (see receive_vpn /
         * socks_send_batch2 comments). */
        int64_t d = tick_ms;
        int64_t kad = (int64_t)last_ka + SOCKS_KEEPALIVE_MS - (int64_t)now_ms();
        int64_t ctd = next_conn_timeout_ms();
        if (kad < d)
            d = kad;
        if (ctd < d)
            d = ctd;
        if (d < 1)
            d = 1;      /* never busy-poll: an expired RTO would otherwise
                         * make ns_tick return 0 and burn a core */
        if (d > POLL_CEIL_MS)
            d = POLL_CEIL_MS;   /* safety ceiling, not a polling tick */
        wait_events(listener, sockfd, g_dns_evfd, (int)d);
        if (g_dns_evfd >= 0)
            (void)port_evfd_drain(g_dns_evfd);   /* nonblocking: consume
                                                  * any pending wakeups */
    }

    /* stop tunnel DNS: bump the session generation so in-flight workers
     * stop sending. Worker sends are serialized with this call via
     * g_dns_wait_mu, so closing the session socket below (and the
     * eventfd further down) can never race a worker's send or wakeup. */
    dns_stop();
    g_sockfd = -1;
    /* L-4: the global config pointer still refers to the caller's stack
     * cfg after we return — NULL it so nothing can dereference a dangling
     * pointer on a later re-entry or from another thread. */
    g_socks_cfg = NULL;

    for (int i = 0; i < MAX_FLOWS; i++) {
        if (g_flows[i].active)
            ns_abort(&g_ns, g_flows[i].ns_idx);
    }
    ns_tick(&g_ns, now_ms());
    sock_drain_tx(sockfd, cfg);
    {
        buf_t p;
        buf_init(&p);
        ctrl_hdr(&p, PT_CLOSE, cfg->encryption, cfg->sid, cfg->token);
        (void)port_send(sockfd, p.data, p.len, 0);
        buf_free(&p);
    }

    /* A-1 ownership contract: run_socks owns sockfd and MUST close the
     * CURRENT value on exit (the original fd, or the new fd swapped in
     * by a re-auth — the old one was already closed inside
     * socks_reauth_swap, so this is a single close either way; without
     * reauth it is the original fd). Callers must NOT close it
     * themselves: with a re-auth the caller-held old fd number may have
     * been reused, so a caller-side close would be a double-close of an
     * unrelated descriptor. The PT_CLOSE goodbye was sent above on this
     * same socket. */
    port_close(sockfd);
    port_close(listener);
    if (g_dns_evfd >= 0) {
        port_evfd_close(g_dns_evfd);
        atomic_store_explicit(&g_dns_evfd, -1,
                              memory_order_relaxed);
    }
    for (int i = 0; i < MAX_FLOWS; i++)
        if (g_flows[i].active)
            flow_free(&g_flows[i]);
    free(g_flows);
    g_flows = NULL;
#ifndef _WIN32
    /* restore the previous signal dispositions (single-call users see
     * no difference; a second run_socks in the same process must not
     * inherit stale handlers). Windows has no per-session restore: the
     * ctrl handler installed above stays for the process lifetime. */
    sigaction(SIGINT, &old_int, NULL);
    sigaction(SIGTERM, &old_term, NULL);
    sigaction(SIGPIPE, &old_pipe, NULL);
#endif
    log_info("SOCKS5 stopped");
    return cfg->session_lost ? 1 : 0;
}
