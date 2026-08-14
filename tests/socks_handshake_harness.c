/*
 * SOCKS5 handshake test harness (root-free).
 *
 * Drives the REAL production SOCKS5 code paths — accept_connections(),
 * the RFC1929 + CONNECT flow handshake (socks_flow.c), and the userspace
 * netstack — against a loopback TCP listener instead of a VPN socket.
 * tests/socks_handshake.py speaks the SOCKS5 wire protocol byte-for-byte
 * and asserts the observable handshake contract.
 *
 * This binary exists ONLY for tests: it must never be shipped or used as
 * a proxy. The auth-failure lockout and connect-timeout knobs
 * (IWAN_AUTH_FAIL_MAX, IWAN_AUTH_FAIL_WINDOW_MS,
 * IWAN_NS_CONNECT_TIMEOUT_MS) are read from the process environment by
 * the production code; the harness does not parse them itself.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "socks_internal.h"
#include "tcpstack.h"

int main(int argc, char **argv)
{
    const char *token = NULL;
    int timeout_s = 120;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            token = argv[++i];
        } else if (strcmp(argv[i], "--timeout-s") == 0 && i + 1 < argc) {
            timeout_s = atoi(argv[++i]);
            if (timeout_s < 1)
                timeout_s = 1;
        } else {
            fprintf(stderr, "usage: %s [--token STR] [--timeout-s N]\n",
                    argv[0]);
            return 2;
        }
    }

    port_socket_init();   /* WSAStartup on Windows; no-op on Linux */

    /* session config: mirror run_socks() minus the VPN socket */
    static SocksConfig cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.auth_token = token;        /* NULL = no RFC1929 auth */
    cfg.inner_ip = 0xC6120002u;    /* 198.18.0.2, host order */
    cfg.gateway = 0xC6120001u;     /* 198.18.0.1, host order */
    cfg.mtu = 1500;
    cfg.listen_str = "harness";

    g_socks_cfg = &cfg;
    g_flows = calloc(MAX_FLOWS, sizeof *g_flows);
    if (!g_flows) {
        fprintf(stderr, "harness: calloc(MAX_FLOWS) failed\n");
        return 1;
    }
    g_dns_evfd = -1;   /* no tunnel DNS in the harness */
    g_sockfd = -1;
    g_next_id = 1;

    ns_init(&g_ns, cfg.inner_ip, cfg.gateway, 1500);
    {
        uint8_t oh[8] = {0};
        ns_set_outer(&g_ns, oh, (const uint8_t[8]){0});
    }

    /* loopback listener on an ephemeral port */
    int listener = port_socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        fprintf(stderr, "harness: listener socket: %s\n", strerror(errno));
        free(g_flows);
        return 1;
    }
    int one = 1;
    port_setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in laddr;
    memset(&laddr, 0, sizeof laddr);
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    laddr.sin_port = 0;   /* kernel picks the port */
    if (port_bind(listener, (struct sockaddr *)&laddr, sizeof laddr) < 0) {
        fprintf(stderr, "harness: bind listener: %s\n", strerror(errno));
        port_close(listener);
        free(g_flows);
        return 1;
    }
    if (port_listen(listener, 64) < 0) {
        fprintf(stderr, "harness: listen: %s\n", strerror(errno));
        port_close(listener);
        free(g_flows);
        return 1;
    }
    port_set_nonblock(listener, true);

    struct sockaddr_in bound;
    socklen_t blen = sizeof bound;
    if (getsockname(listener, (struct sockaddr *)&bound, &blen) < 0) {
        fprintf(stderr, "harness: getsockname: %s\n", strerror(errno));
        port_close(listener);
        free(g_flows);
        return 1;
    }
    printf("LISTEN 127.0.0.1:%u\n", (unsigned)ntohs(bound.sin_port));
    fflush(stdout);

    /* dummy UDP socket: wait_events() polls the session fd unconditionally */
    int udpfd = port_socket(AF_INET, SOCK_DGRAM, 0);
    if (udpfd < 0) {
        fprintf(stderr, "harness: UDP socket: %s\n", strerror(errno));
        port_close(listener);
        free(g_flows);
        return 1;
    }

    uint64_t start = now_ms();
    uint64_t deadline = start + (uint64_t)timeout_s * 1000u;
    while (now_ms() < deadline) {
        accept_connections(listener);
        service_local_inputs(g_flows);
        handle_dns_results();
        service_local_outputs();
        int tick = ns_tick(&g_ns, now_ms());
        update_tcp_states();
        reap_flows();
        int64_t d = tick;
        int64_t ctd = next_conn_timeout_ms();
        if (ctd < d)
            d = ctd;
        if (d > 1000)
            d = 1000;
        if (d < 1)
            d = 1;
        wait_events(listener, udpfd, -1, (int)d);
    }

    port_close(udpfd);
    port_close(listener);
    free(g_flows);
    return 0;
}
