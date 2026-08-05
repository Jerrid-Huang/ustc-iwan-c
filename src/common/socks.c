#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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

void send_vpn_packet(int sockfd, const uint8_t *pkt, size_t n,
                            const SocksConfig *cfg) {
    if (cfg->encryption == 0) {
        uint8_t hdr[8];
        pkhdr(PT_DATA, 0, cfg->sid, cfg->token, hdr);
        uint8_t *out = malloc(8 + n);
        if (!out)
            return;
        memcpy(out, hdr, 8);
        memcpy(out + 8, pkt, n);
        (void)send(sockfd, out, (int)(8 + n), 0);
        free(out);
    } else {
        uint8_t hdr[8];
        pkhdr(PT_DATA_ENC, cfg->encryption, cfg->sid, cfg->token, hdr);
        uint8_t *out = malloc(8 + n);
        if (!out)
            return;
        memcpy(out, hdr, 8);
        memcpy(out + 8, pkt, n);
        xor_crypt(out + 8, n, cfg->xor_key, 8);
        (void)send(sockfd, out, (int)(8 + n), 0);
        free(out);
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

int receive_vpn(int sockfd, const SocksConfig *cfg) {
    /* aligned so xor_crypt can use 64-bit loads on the payload */
    union {
        uint8_t  b[65535];
        uint64_t q;
    } u;
    for (;;) {
        ssize_t n = recv(sockfd, u.b, sizeof u.b, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            log_err("receive_vpn: recv error: %s", strerror(errno));
            return -1;
        }
        if (n < 8)
            continue;
        uint8_t t = u.b[0];
        uint16_t psid = (uint16_t)((u.b[2] << 8) | u.b[3]);
        uint32_t ptok = ((uint32_t)u.b[4] << 24) | ((uint32_t)u.b[5] << 16) |
                        ((uint32_t)u.b[6] << 8) | u.b[7];
        if (debug_enabled())
            log_debug("VPN RX type=%u n=%zu sid=%u tok=%u (cfg sid=%u tok=%u)", t, n, psid, ptok, cfg->sid, cfg->token);
        if (psid != cfg->sid || ptok != cfg->token)
            continue;
        if (t == PT_CLOSE) {
            log_err("VPN server closed the session (CLOSE)");
            return -1;
        }
        if (t == PT_ECHO_REQ) {
            buf_t p;
            buf_init(&p);
            ctrl_hdr(&p, PT_ECHO_RES, cfg->encryption, cfg->sid, cfg->token);
            (void)send(sockfd, p.data, (int)p.len, 0);
            buf_free(&p);
            continue;
        }
        if (t != PT_DATA && t != PT_DATA_ENC)
            continue;
        size_t plen = (size_t)(n - 8);
        if (t == PT_DATA_ENC)
            xor_crypt(u.b + 8, plen, cfg->xor_key, 8);
        if (debug_enabled() && t == PT_DATA_ENC) {
            char hex[100] = "";
            int hn = (int)plen < 32 ? (int)plen : 32;
            for (int i = 0; i < hn; i++)
                sprintf(hex + i * 3, "%02x ", u.b[8 + i]);
            log_debug("DATA decrypted (%zuB): %s...", plen, hex);
        }
        if (!(plen != 0 && plen <= (size_t)cfg->mtu && (u.b[8] >> 4) == 4 &&
              plen >= 20))
            continue;
        ns_rx_packet(&g_ns, u.b + 8, plen);
    }
}

void run_socks(int sockfd, const SocksConfig *cfg) {
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
        {
            uint8_t tx[65535];
            size_t n;
            while ((n = ns_device_pop(&g_ns, tx, sizeof tx)) > 0)
                send_vpn_packet(sockfd, tx, n, cfg);
        }

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
    {
        uint8_t tx[65535];
        size_t n;
        ns_tick(&g_ns, now_mono());
        while ((n = ns_device_pop(&g_ns, tx, sizeof tx)) > 0)
            send_vpn_packet(sockfd, tx, n, cfg);
    }
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
