#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

Flow *g_flows;          /* NULL-terminated? no: MAX_FLOWS array */

/* event-driven wait: listener, VPN socket, and client flows; wakes on any
 * readable fd or the next netstack tick. Replaces fixed sleep polling. */
void wait_events(int listener, int sockfd, int timeout_ms)
{
    struct pollfd fds[2 + MAX_FLOWS];
    int n = 0;
    fds[n].fd = listener;
    fds[n].events = POLLIN;
    n++;
    fds[n].fd = sockfd;
    fds[n].events = POLLIN;
    n++;
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
#define SOCKS_MAX_PK 48

/* Send one accumulated batch: uniform batches (>=2 packets, total <= 65507)
 * go out as a single GSO sendmsg (kernel segments; wire-identical to
 * per-packet sends, same invariant the TUN pump relies on), everything
 * else via sendmmsg. EAGAIN/ENOBUFS block on POLLOUT instead of dropping;
 * only fatal errors stop the proxy. */
static void socks_send_batch(int sockfd, SocksConfig *cfg, const uint8_t *tx,
                             size_t blen, int npk, const size_t *offs,
                             const size_t *lens, int uniform, size_t mss)
{
    struct mmsghdr msgs[SOCKS_MAX_PK];
    struct iovec iovs[SOCKS_MAX_PK];

    if (npk >= 2 && uniform && blen <= 65507) {
        struct iovec iov = { .iov_base = (void *)tx, .iov_len = blen };
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
            mh.msg_iov = &iov;
            mh.msg_iovlen = 1;
            while (!g_stop) {
                ssize_t r = sendmsg(sockfd, &mh, 0);
                if (r == (ssize_t)blen)
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
    for (int k = 0; k < npk; k++) {
        iovs[k].iov_base = (void *)(tx + offs[k]);
        iovs[k].iov_len = 8 + lens[k];
    }
    memset(msgs, 0, sizeof msgs);   /* garbage msg_name would EFAULT */
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

/* Drain the netstack output queue into one batch and send it: packets are
 * appended to a contiguous buffer as [8B header][inner packet]; the whole
 * batch then goes out via GSO (uniform lengths) or sendmmsg. A packet that
 * would overflow the batch is carried over to the next flush (pend). */
static void sock_drain_tx(int sockfd, SocksConfig *cfg)
{
    static _Alignas(8) uint8_t tx[SOCKS_TX_MAX];
    static uint8_t pend[2048];
    static size_t pend_n;
    static uint8_t scratch[2048];
    size_t offs[SOCKS_MAX_PK], lens[SOCKS_MAX_PK];
    size_t blen = 0;
    int npk = 0, uniform = 1;
    size_t mss = 0;
    uint8_t typ = cfg->encryption ? PT_DATA_ENC : PT_DATA;

    for (;;) {
        size_t n;
        if (pend_n) {
            n = pend_n;
            memcpy(scratch, pend, n);
            pend_n = 0;
        } else {
            n = ns_device_pop(&g_ns, scratch, sizeof scratch);
            if (n == 0)
                break;
        }
        if (blen > 0 &&
            (blen + 8 + n > SOCKS_TX_MAX || npk == SOCKS_MAX_PK)) {
            /* batch full: carry this packet into the next flush */
            memcpy(pend, scratch, n);
            pend_n = n;
            break;
        }
        if (npk == 0)
            mss = 8 + n;
        else if (8 + n != mss)
            uniform = 0;
        pkhdr(typ, cfg->encryption, cfg->sid, cfg->token, tx + blen);
        memcpy(tx + blen + 8, scratch, n);
        offs[npk] = blen;
        lens[npk] = n;
        blen += 8 + n;
        npk++;
    }
    if (npk > 0) {
        if (cfg->encryption)
            for (int k = 0; k < npk; k++)
                xor_crypt(tx + offs[k] + 8, lens[k], cfg->xor_key, 8);
        socks_send_batch(sockfd, cfg, tx, blen, npk, offs, lens, uniform,
                         mss);
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
     * truncated and skipped via MSG_TRUNC. */
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

    for (;;) {
        int v = recvmmsg(sockfd, rx_msgs, RX_VLEN, MSG_DONTWAIT, NULL);
        if (v <= 0) {
            if (v == 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            log_err("receive_vpn: recvmmsg: %s", strerror(errno));
            return -1;
        }
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

    /* Rust prints the configured address (config.listen), not the bound one */
    const char *listen_s = cfg->listen_str ? cfg->listen_str : "?";

    ns_init(&g_ns, cfg->inner_ip, cfg->gateway, (uint16_t)cfg->mtu,
            (uint32_t)((uint64_t)now_mono() ^ (uint32_t)getpid()));

    g_flows = calloc(MAX_FLOWS, sizeof *g_flows);
    if (!g_flows) {
        close(listener);
        return;
    }
    g_next_id = 1;

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
        send_vpn_keepalive(sockfd, cfg, &last_ka);
        accept_connections(listener);
        if (receive_vpn(sockfd, cfg) < 0)
            break;
        service_local_inputs(g_flows);
        handle_dns_results();

        int tick_ms = ns_tick(&g_ns, now_mono());
        sock_drain_tx(sockfd, cfg);

        update_tcp_states();
        service_local_outputs();
        reap_flows();

        int d = tick_ms;
        if (d < 0)
            d = 0;
        if (d > 10)
            d = 10;   /* cap: DNS-thread results are noticed via timeout */
        wait_events(listener, sockfd, d);
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
    for (int i = 0; i < MAX_FLOWS; i++)
        flow_free(&g_flows[i]);
    free(g_flows);
    g_flows = NULL;
    log_info("SOCKS5 stopped");
}
