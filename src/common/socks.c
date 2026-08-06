#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "crypto.h"
#include "netstack.h"


#include "protocol.h"
#include "socks.h"
#include "socks_internal.h"
#include "tun.h"
#include "util.h"

Netstack g_ns;
volatile sig_atomic_t g_stop;

void on_sig(int sig) {
    (void)sig;
    g_stop = 1;
}

int g_dns_evfd = -1;      /* DNS workers write here to wake the loop */
Flow *g_flows;          /* NULL-terminated? no: MAX_FLOWS array */

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
        fds[n].events = POLLIN;
        if (f->output.len > 0)
            fds[n].events |= POLLOUT;
        n++;
    }
    if (poll(fds, (nfds_t)n, timeout_ms) < 0 && errno != EINTR)
        log_err("poll: %s", strerror(errno));
}

void accept_connections(int listener) {
    for (;;) {
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof peer;
        int cfd = accept(listener, (struct sockaddr *)&peer, &peerlen);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            log_err("accept SOCKS5 client: %s", strerror(errno));
            return;
        }
        int nodelay = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof nodelay);
        set_nonblock(cfd);
        Flow *f = flow_alloc(&peer);
        if (!f) {
            close(cfd);
            continue;
        }
        f->fd = cfd;
    }
}

/* ---- VPN framing (mirrors netstack/tunnel.rs) ---- */

#define SOCKS_TX_MAX 65543   /* one GSO unit (65507) + one 8B header */
#define SOCKS_MAX_PK 128     /* drain the whole tx queue: 48 segments +
                              * control ACKs must not accumulate (a 48-item
                              * cap left 1 item/round and drop-oldest
                              * evicted ACKs under load) */

/* Send one accumulated batch: uniform batches (>=2 packets, total <= 65507)
 * go out as a single GSO sendmsg with a multi-iovec message (the kernel
 * treats the iovecs as one continuous stream and segments it; wire output
 * is identical to per-packet sends). Everything else goes via sendmmsg.
 * EAGAIN/ENOBUFS block on POLLOUT instead of dropping; only fatal errors
 * stop the proxy.
 *
 * Kernel-feature review (Linux 7.0, source-verified, measured on
 * loopback): io_uring SENDMSG (46 SQEs/enter) measured ~6% SLOWER than
 * this path (617-635 vs 664-688 MB/s) and has no sendmmsg equivalent for
 * mixed-length batches; SENDMSG_ZC / SO_ZEROCOPY are blocked structurally:
 * seg_compact() memmoves the retransmit slots and retransmit re-seals
 * them in place, both illegal while a zerocopy notification is
 * outstanding. This GSO+sendmmsg shape is the local optimum. */
static void socks_send_batch2(int sockfd, SocksConfig *cfg,
                              struct iovec *iovs, struct mmsghdr *msgs,
                              int npk, size_t total, size_t mss)
{
    if (npk >= 2 && total <= 65507) {
        if (cfg->gso_ok == 0) {
            int m = (int)mss;
            cfg->gso_ok = setsockopt(sockfd, SOL_UDP, UDP_SEGMENT,
                                     &m, sizeof m) == 0 ? 1 : -1;
            if (cfg->gso_ok < 0)
                log_err("SOCKS UDP_SEGMENT unsupported, using sendmmsg");
            else
                cfg->gso_mss = mss;
        } else if (cfg->gso_mss != mss) {
            int m = (int)mss;
            if (setsockopt(sockfd, SOL_UDP, UDP_SEGMENT, &m, sizeof m) != 0)
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
                ssize_t r = sendmsg(sockfd, &mh, 0);
                if (r == (ssize_t)total)
                    return;
                if (r < 0 &&
                    (errno == EAGAIN || errno == EWOULDBLOCK ||
                     errno == ENOBUFS || errno == EINTR)) {
                    if (errno != EINTR) {
                        struct pollfd pfd = { .fd = sockfd,
                                              .events = POLLOUT };
                        if (poll(&pfd, 1, 100) > 0)
                            usleep(1000);
                    }
                    continue;
                }
                log_err("SOCKS GSO send failed: %s", strerror(errno));
                g_stop = 1;
                return;
            }
            return;
        }
    }

    /* per-message path: a lingering UDP_SEGMENT would silently split any
     * datagram longer than the mss, so clear it first */
    if (cfg->gso_mss != 0) {
        int z = 0;
        setsockopt(sockfd, SOL_UDP, UDP_SEGMENT, &z, sizeof z);
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
            ssize_t sm = sendmmsg(sockfd, msgs + sent,
                                  (unsigned)npk - sent, 0);
            if (sm > 0) {
                sent += (unsigned)sm;
                continue;
            }
            if (sm == 0)
                return;
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                struct pollfd pfd = { .fd = sockfd, .events = POLLOUT };
                if (poll(&pfd, 1, 100) > 0)
                    usleep(1000);
                continue;
            }
            log_err("SOCKS sendmmsg: %s", strerror(errno));
            g_stop = 1;
            return;
        }
    }
}

/* drain the netstack device queue: ready packets are referenced by
 * pointer (zero-copy segment slots / inline control), batched, and sent
 * via GSO (uniform lengths) or sendmmsg. Framing + XOR were done at seal
 * time inside the stack. */
static void sock_drain_tx(int sockfd, SocksConfig *cfg)
{
    struct iovec iovs[SOCKS_MAX_PK];
    struct mmsghdr msgs[SOCKS_MAX_PK];
    const TxItem *items[SOCKS_MAX_PK];
    size_t lens[SOCKS_MAX_PK];
    int npk = 0;
    size_t total = 0;
    const TxItem *it;
    (void)cfg;

    while (npk < SOCKS_MAX_PK && (it = ns_tx_peek(&g_ns)) != NULL) {
        size_t l = ns_tx_item_len(it);
        items[npk] = it;
        lens[npk] = l;
        total += l;
        npk++;
        ns_tx_pop(&g_ns);
    }
    if (npk == 0)
        return;
    for (int k = 0; k < npk; k++) {
        iovs[k].iov_base = (void *)ns_tx_item_buf(items[k]);
        iovs[k].iov_len = lens[k];
    }
    /* drain the whole queue in uniform runs: a GSO cap of 65507 must not
     * leave items behind, because their segment pointers go stale once
     * receive_vpn/ns_tick drop+compact the retransmit table */
    for (int k = 0; k < npk;) {
        size_t run_total = lens[k];
        int j = k;
        while (j + 1 < npk && lens[j + 1] == lens[k]) {
            if (run_total + lens[k] > 65507)
                break;                 /* split oversized uniform run */
            run_total += lens[k];
            j++;
        }
        socks_send_batch2(sockfd, cfg, iovs + k, msgs + k, j - k + 1,
                          run_total, lens[k]);
        k = j + 1;
    }
}

void send_vpn_keepalive(int sockfd, const SocksConfig *cfg,
                               uint64_t *last_ka) {
    if (now_mono() - *last_ka < 10000)
        return;
    buf_t p;
    buf_init(&p);
    ctrl_hdr(&p, PT_ECHO_REQ, cfg->encryption, cfg->sid, cfg->token);
    (void)send(sockfd, p.data, (int)p.len, 0);
    buf_free(&p);
    *last_ka = now_mono();
}

int receive_vpn(int sockfd, SocksConfig *cfg) {
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
    enum { RX_VLEN = 64, RX_SLOT = 2048 };
    static _Alignas(8) uint8_t rx_buf[RX_VLEN][RX_SLOT];
    static struct iovec rx_iov[RX_VLEN];
    static struct mmsghdr rx_msgs[RX_VLEN];
    static int rx_init;

    if (!rx_init) {
        /* static: zero once, then set the iovecs; recvmmsg only writes
         * msg_len/msg_flags, so the array must NOT be re-zeroed per call
         * (that would clear msg_iov and truncate every datagram) */
        memset(rx_msgs, 0, sizeof rx_msgs);
        for (int i = 0; i < RX_VLEN; i++) {
            rx_iov[i].iov_base = rx_buf[i];
            rx_iov[i].iov_len = RX_SLOT;
            rx_msgs[i].msg_hdr.msg_iov = &rx_iov[i];
            rx_msgs[i].msg_hdr.msg_iovlen = 1;
        }
        rx_init = 1;
    }

    int budget = 256;
    for (;;) {
        /* yield to the other phases once 256 packets have been handled:
         * with a fast peer the socket never drains, and an unbounded
         * loop starves local reads and TX (echo-mode livelock) */
        if (budget <= 0)
            return 0;
        int v = recvmmsg(sockfd, rx_msgs, RX_VLEN, MSG_DONTWAIT, NULL);
        if (v <= 0) {
            if (v == 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            log_err("receive_vpn: recvmmsg: %s", strerror(errno));
            return -1;
        }
        budget -= v;
        for (int i = 0; i < v; i++) {
            ssize_t n = rx_msgs[i].msg_len;
            if (n < 8 || (rx_msgs[i].msg_hdr.msg_flags & MSG_TRUNC))
                continue;
            uint8_t *b = rx_buf[i];
            uint8_t t = b[0];
            uint16_t psid = (uint16_t)((b[2] << 8) | b[3]);
            uint32_t ptok = ((uint32_t)b[4] << 24) | ((uint32_t)b[5] << 16) |
                            ((uint32_t)b[6] << 8) | b[7];
            if (debug_enabled())
                log_debug("VPN RX type=%u n=%zu sid=%u tok=%u (cfg sid=%u tok=%u)",
                          t, n, psid, ptok, cfg->sid, cfg->token);
            if (psid != cfg->sid || ptok != cfg->token)
                continue;
            if (t == PT_CLOSE) {
                log_err("VPN server closed the session (CLOSE)");
                return -1;
            }
            if (t == PT_ECHO_REQ) {
                buf_t p;
                buf_init(&p);
                ctrl_hdr(&p, PT_ECHO_RES, cfg->encryption, cfg->sid,
                         cfg->token);
                (void)send(sockfd, p.data, (int)p.len, 0);
                buf_free(&p);
                continue;
            }
            if (t != PT_DATA && t != PT_DATA_ENC)
                continue;
            size_t plen = (size_t)(n - 8);
            if (t == PT_DATA_ENC)
                xor_crypt(b + 8, plen, cfg->xor_key, 8);
            if (debug_enabled() && t == PT_DATA_ENC) {
                char hex[100] = "";
                int hn = (int)plen < 32 ? (int)plen : 32;
                for (int i = 0; i < hn; i++)
                    sprintf(hex + i * 3, "%02x ", b[8 + i]);
                log_debug("DATA decrypted (%zuB): %s...", plen, hex);
            }
            if (!(plen != 0 && plen <= (size_t)cfg->mtu && (b[8] >> 4) == 4 &&
                  plen >= 20))
                continue;
            ns_rx_packet(&g_ns, b + 8, plen);
        }
    }
}

void run_socks(int sockfd, SocksConfig *cfg) {
    int listener;
    struct sockaddr_in laddr = cfg->listen_addr;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        log_err("socket SOCKS5 listener: %s", strerror(errno));
        return;
    }
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(listener, (struct sockaddr *)&laddr, sizeof laddr) < 0) {
        log_err("bind SOCKS5 listener: %s", strerror(errno));
        close(listener);
        return;
    }
    if (listen(listener, 64) < 0) {
        log_err("listen SOCKS5: %s", strerror(errno));
        close(listener);
        return;
    }
    set_nonblock(listener);
    set_nonblock(sockfd);
    {
        /* high-BDP tunnel: default UDP buffers (~212KB) overflow once
         * the TCP window keeps >~150 segments in flight, silently
         * dropping packets at full rate */
        int rbuf = 4 * 1024 * 1024;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rbuf, sizeof rbuf);
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &rbuf, sizeof rbuf);
    }

    /* Rust prints the configured address (config.listen), not the bound one */
    const char *listen_s = cfg->listen_str ? cfg->listen_str : "?";

    ns_init(&g_ns, cfg->inner_ip, cfg->gateway, (uint16_t)cfg->mtu,
            (uint32_t)((uint64_t)now_mono() ^ (uint32_t)getpid()));
    {
        uint8_t oh[8];
        pkhdr(cfg->encryption ? PT_DATA_ENC : PT_DATA, cfg->encryption,
              cfg->sid, cfg->token, oh);
        ns_set_outer(&g_ns, oh, cfg->xor_key);
    }

    g_flows = calloc(MAX_FLOWS, sizeof *g_flows);
    if (!g_flows) {
        close(listener);
        return;
    }
    g_next_id = 1;
    g_dns_evfd = eventfd(0, EFD_NONBLOCK);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    log_info("SOCKS5 listening on %s", listen_s);
    if (debug_enabled())
        log_debug("SOCKS5 network: IP %d.%d.%d.%d, gateway %d.%d.%d.%d, MTU %d",
                  (cfg->inner_ip >> 24) & 0xff, (cfg->inner_ip >> 16) & 0xff,
                  (cfg->inner_ip >> 8) & 0xff, cfg->inner_ip & 0xff,
                  (cfg->gateway >> 24) & 0xff, (cfg->gateway >> 16) & 0xff,
                  (cfg->gateway >> 8) & 0xff, cfg->gateway & 0xff, cfg->mtu);

    uint64_t last_ka = now_mono() - 10000;

    while (!g_stop) {
        /* flush leftover tx items first: their segment pointers stay
         * valid only until receive_vpn's handle_rx drop/compact moves
         * the retransmit table */
        sock_drain_tx(sockfd, cfg);
        send_vpn_keepalive(sockfd, cfg, &last_ka);
        accept_connections(listener);
        if (receive_vpn(sockfd, cfg) < 0)
            break;
        service_local_inputs(g_flows);
        handle_dns_results();
        /* consume the rxq BEFORE ns_tick advertises the window: an
         * unconsumed rxq would make conn_win() report 0 and the peer
         * would stop echoing (advertised-window stall) */
        service_local_outputs();
        int tick_ms = ns_tick(&g_ns, now_mono());
        /* flush freshly enqueued segments (same-round, pointers valid) */
        sock_drain_tx(sockfd, cfg);
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
        int64_t kad = (int64_t)last_ka + 10000 - (int64_t)now_ms();
        int64_t ctd = next_conn_timeout_ms();
        if (kad < d)
            d = kad;
        if (ctd < d)
            d = ctd;
        if (d < 1)
            d = 1;      /* never busy-poll: an expired RTO would otherwise
                         * make ns_tick return 0 and burn a core */
        if (d > 1000)
            d = 1000;   /* safety ceiling, not a polling tick */
        wait_events(listener, sockfd, g_dns_evfd, (int)d);
        if (g_dns_evfd >= 0) {
            uint64_t ev;
            ssize_t r = read(g_dns_evfd, &ev, sizeof ev);
            (void)r;   /* EFD_NONBLOCK: drain the counter */
        }
    }

    for (int i = 0; i < MAX_FLOWS; i++) {
        if (g_flows[i].active)
            ns_abort(&g_ns, g_flows[i].ns_idx);
    }
    ns_tick(&g_ns, now_mono());
    sock_drain_tx(sockfd, cfg);
    {
        buf_t p;
        buf_init(&p);
        ctrl_hdr(&p, PT_CLOSE, cfg->encryption, cfg->sid, cfg->token);
        (void)send(sockfd, p.data, (int)p.len, 0);
        buf_free(&p);
    }

    close(listener);
    if (g_dns_evfd >= 0) {
        close(g_dns_evfd);
        g_dns_evfd = -1;
    }
    for (int i = 0; i < MAX_FLOWS; i++)
        flow_free(&g_flows[i]);
    free(g_flows);
    g_flows = NULL;
    log_info("SOCKS5 stopped");
}
