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

/* shared stop flag (util.h): written from the signal handler with a
 * relaxed atomic store (lock-free on every supported target) */
void on_sig(int sig) {
    (void)sig;
    atomic_store_explicit(&g_stop, true, memory_order_relaxed);
    atomic_store_explicit(&g_user_stop, true, memory_order_relaxed);
}

int g_dns_evfd = -1;      /* DNS workers write here to wake the loop */
int g_sockfd = -1;        /* session UDP socket; set by run_socks, used by tunnel DNS */
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
    cached = (unsigned)env_ms_range("IWAN_RX_STALE_MS",
                                    SOCKS_RX_STALE_MS_DEFAULT, 10000,
                                    86400000, 1);
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
        fds[n].fd = f->fd;
        /* rx_paused (netstack ring full): do NOT register POLLIN — the
         * socket stays readable, so polling it would return instantly
         * and busy-spin the loop; the next netstack tick (<=100ms)
         * retries the reserve and clears the pause when room frees */
        fds[n].events = f->rx_paused ? 0 : POLLIN;
        if (f->output.len > 0)
            fds[n].events |= POLLOUT;
        n++;
    }
    if (port_poll(fds, (nfds_t)n, timeout_ms) < 0 && errno != EINTR)
        log_err("poll: %s", strerror(errno));
}

void accept_connections(int listener) {
    for (;;) {
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof peer;
        int cfd = port_accept(listener, (struct sockaddr *)&peer, &peerlen);
        if (cfd < 0) {
            /* the wrapper maps WSAEWOULDBLOCK -> EAGAIN, so this stays
             * valid on Windows */
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            log_err("accept SOCKS5 client: %s", strerror(errno));
            return;
        }
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
        port_set_nonblock(cfd, true);
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
            /* gso_ok == -1 caches the disabled state: once setsockopt
             * failed it will not succeed later, so stop re-probing it
             * on every drain round */
            int m = (int)mss;
            if (port_setsockopt(sockfd, SOL_UDP, UDP_SEGMENT, &m,
                                sizeof m) != 0)
                cfg->gso_ok = -1;
            else
                cfg->gso_mss = mss;
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
    if (port_send(sockfd, p.data, (int)p.len, 0) < 0) {
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
 * until lwIP frees the pbuf), 0 when the caller must release it. */
static int vpn_handle_data(SocksConfig *cfg, uint8_t *b, size_t n)
{
    uint8_t t = b[0];
    size_t plen = n - 8;
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
        log_debug("DATA decrypted (%zuB): %s...", plen, hex);
    }
    uint32_t saddr, daddr;
    if (plen < 20 || plen > (size_t)cfg->mtu)
        return 0;
    if ((b[8] >> 4) == 6) {
        /* inner IPv6 (SOCKS targets over IPv6): structural check only —
         * spoof protection is the server's job (its H1 gate binds the
         * source to the session's derived ULA) */
        uint8_t s6[16], d6[16];
        if (plen < 40 || ip6_pkt_ok(b + 8, plen, s6, d6) != 0)
            return 0;
    } else if (ipv4_pkt_ok(b + 8, plen, &saddr, &daddr) != 0) {
        return 0;
    }
    /* M1: inner UDP packets whose dst port belongs to a pending
     * tunnel DNS query are responses — consume them here, never
     * hand them to the TCP stack */
    if (dns_try_handle_response(b + 8, plen))
        return 0;
    ns_rx_packet_ref(&g_ns, b, n);
    return 1;
}

/* one received VPN datagram: outer-header validation (type/sid/token),
 * control frames (CLOSE / ECHO_REQ), and inner-packet dispatch.
 * Returns -1 when the session must stop (server CLOSE), 0 when the
 * caller must release the RX buffer, 1 when the buffer was handed to
 * lwIP (RX pool owns it). */
static int vpn_handle_datagram(int sockfd, SocksConfig *cfg, uint8_t *b,
                               size_t n)
{
    uint8_t t = b[0];
    uint16_t psid = (uint16_t)((b[2] << 8) | b[3]);
    uint32_t ptok = ((uint32_t)b[4] << 24) | ((uint32_t)b[5] << 16) |
                    ((uint32_t)b[6] << 8) | b[7];
    if (dbg_env("IWAN_RXDBG"))
        fprintf(stderr, "VRX: n=%llu t=%u\n", (unsigned long long)n, t);
    if (debug_enabled())
        log_debug("VPN RX type=%u n=%zu sid=%u tok=****%04x "
                  "(cfg sid=%u tok=****%04x)",
                  t, n, psid, ptok & 0xFFFFu, cfg->sid,
                  cfg->token & 0xFFFFu);
    if (psid != cfg->sid || ptok != cfg->token)
        return 0;
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
        if (port_send(sockfd, p.data, (int)p.len, 0) < 0)
            log_err("SOCKS ECHO_RES send failed: %s", strerror(errno));
        buf_free(&p);
        return 0;
    }
    if (t != PT_DATA && t != PT_DATA_ENC)
        return 0;
    return vpn_handle_data(cfg, b, n);
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
    enum { RX_VLEN = 64, RX_SLOT = 2048 };
    static struct iovec rx_iov[RX_VLEN];
    static struct mmsghdr rx_msgs[RX_VLEN];
    void *rx_bufs[RX_VLEN];
    static int rx_init;

    if (!rx_init) {
        /* static: zero once; the iov bases are re-pointed at the pool
         * buffers on every drain below */
        memset(rx_msgs, 0, sizeof rx_msgs);
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
        if (got == 0)
            return 0;   /* pool exhausted: lwIP still holds buffers */
        for (int i = 0; i < got; i++) {
            rx_iov[i].iov_base = rx_bufs[i];
            rx_iov[i].iov_len = RX_SLOT;
            rx_msgs[i].msg_hdr.msg_iov = &rx_iov[i];
            rx_msgs[i].msg_hdr.msg_iovlen = 1;
        }
        int v = port_recvmmsg(sockfd, rx_msgs, (unsigned)got,
                              MSG_DONTWAIT, NULL);
        if (v > 0)
            cfg->last_rx = now_ms();   /* downlink resets the stale clock */
        if (v < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
            errno != ECONNREFUSED) {
            for (int i = 0; i < got; i++)
                ns_rx_buf_release(rx_bufs[i]);
            log_err("receive_vpn: recvmmsg: %s", strerror(errno));
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
            int r = vpn_handle_datagram(sockfd, cfg, rx_bufs[i], (size_t)n);
            if (r < 0) {
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
            f->ns_idx = -1;
            queue_socks_error(f, 4);
            set_flow_state(f, ST_CLOSING);
            continue;
        }
        if (f->ns_idx < 0)
            continue;   /* handshake states: nothing to re-establish */
        if (f->state != ST_CONNECTING && f->state != ST_ESTABLISHED) {
            f->ns_idx = -1;   /* stale index into the rebuilt stack */
            continue;
        }
        uint16_t port = f->tgt_port;
        uint8_t af = f->tgt_af;
        f->ns_idx = -1;
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
    dns_set_server(cfg->dns);
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
        ns_set_outer(&g_ns, oh, cfg->xor_key);
        while (ns_tx_peek(&g_ns))
            ns_tx_pop(&g_ns);
        log_info("SOCKS: inner connections kept (same inner IP)");
    } else {
        /* the server re-assigned our inner IP: rebuild the stack and
         * re-establish every active flow on the new tunnel */
        ns_init(&g_ns, cfg->inner_ip, cfg->gateway, (uint16_t)cfg->mtu);
        ns_set_outer(&g_ns, oh, cfg->xor_key);
        socks_reauth_flows();
        log_info("SOCKS: inner IP changed; flows re-established");
    }
    return newfd;
}

/* re-auth succeeded: swap the tunnel socket in place */
static void socks_reauth_swap(int *sockfd, int nfd)
{
    if (nfd < 0)
        return;
    port_close(*sockfd);
    *sockfd = nfd;
    g_sockfd = nfd;
}

int run_socks(int sockfd, SocksConfig *cfg) {
    int listener;

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
        return 0;
    }
    int one = 1;
    port_setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (port_bind(listener, (struct sockaddr *)&laddr, sizeof laddr) < 0) {
        log_err("bind SOCKS5 listener: %s", strerror(errno));
        port_close(listener);
        return 0;
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
            return 0;
        }
    }
    if (port_listen(listener, LISTEN_BACKLOG) < 0) {
        log_err("listen SOCKS5: %s", strerror(errno));
        port_close(listener);
        return 0;
    }
    port_set_nonblock(listener, true);
    port_set_nonblock(sockfd, true);
    {
        /* high-BDP tunnel: default UDP buffers (~212KB) overflow once
         * the TCP window keeps >~150 segments in flight, silently
         * dropping packets at full rate */
        int rbuf = SOCK_BUF_BYTES;
        port_setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rbuf, sizeof rbuf);
        port_setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &rbuf, sizeof rbuf);
    }

    /* M1: tunnel DNS shares the session socket and the server-assigned
     * resolver (fallback 114.114.114.114 when the server sent none).
     * Both are fixed before any DNS worker can spawn (workers are only
     * created inside the event loop below). */
    g_sockfd = sockfd;
    dns_set_server(cfg->dns);

    /* Rust prints the configured address (config.listen), not the bound one */
    const char *listen_s = cfg->listen_str ? cfg->listen_str : "?";

    ns_init(&g_ns, cfg->inner_ip, cfg->gateway, (uint16_t)cfg->mtu);
    {
        uint8_t oh[8];
        pkt_hdr(cfg->encryption ? PT_DATA_ENC : PT_DATA, cfg->encryption,
                cfg->sid, cfg->token, oh);
        ns_set_outer(&g_ns, oh, cfg->xor_key);
    }

    g_flows = calloc(MAX_FLOWS, sizeof *g_flows);
    if (!g_flows) {
        port_close(listener);
        return 0;
    }
    g_next_id = 1;
    /* clear any DNS state a previous session left behind (result ring,
     * wait table) so stale entries can never match a fresh session's
     * flows or queries; also retires workers that outlived it */
    dns_reset();
    g_dns_evfd = port_evfd_create();

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

    while (!g_stop) {
        /* downlink-silence watchdog: re-auth the tunnel in place (the
         * listener, flows and inner TCP survive); the old behavior —
         * declaring the session lost and exiting — only applies when no
         * re-auth callback was provided. stale_ms == 0 disables it. */
        if (stale_ms != 0 && now_ms() - cfg->last_rx > stale_ms) {
            log_err("SOCKS: no downlink for %llu ms; re-authing tunnel",
                    (unsigned long long)(now_ms() - cfg->last_rx));
            int nfd = socks_reauth_tunnel(cfg);
            socks_reauth_swap(&sockfd, nfd);
            if (nfd < 0 && !cfg->reauth) {
                cfg->session_lost = true;
                g_stop = 1;
                break;
            }
        }
        /* a failed re-auth retries on this schedule */
        if (cfg->reauth_at != 0 && now_ms() >= cfg->reauth_at) {
            int nfd = socks_reauth_tunnel(cfg);
            socks_reauth_swap(&sockfd, nfd);
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
            socks_reauth_swap(&sockfd, nfd);
            if (nfd < 0 && !cfg->reauth) {
                break;
            } else if (nfd < 0) {
                cfg->session_lost = false;
            }
        }
        /* the queue drained: let lwIP retry output it held on ERR_MEM */
        ns_tx_kick(&g_ns);
        send_vpn_keepalive(sockfd, cfg, &last_ka);
        if (cfg->ka_fail >= SOCKS_KA_FAIL_MAX) {
            log_err("SOCKS: %d consecutive keepalive send failures; "
                    "re-authing tunnel", cfg->ka_fail);
            int nfd = socks_reauth_tunnel(cfg);
            socks_reauth_swap(&sockfd, nfd);
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
            socks_reauth_swap(&sockfd, nfd);
            if (nfd >= 0)
                continue;
            if (!cfg->reauth) {
                cfg->session_lost = true;
                g_stop = 1;
                break;
            }
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
        (void)port_send(sockfd, p.data, (int)p.len, 0);
        buf_free(&p);
    }

    port_close(listener);
    if (g_dns_evfd >= 0) {
        port_evfd_close(g_dns_evfd);
        g_dns_evfd = -1;
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
