#ifndef IWAN_SOCKS_H
#define IWAN_SOCKS_H

#include <stdbool.h>
#include <stdint.h>
#ifdef _WIN32
#  include <winsock2.h>
#else
#  include <netinet/in.h>
#endif

#include "util.h"

typedef struct SocksConfig SocksConfig;

/* In-place tunnel re-auth, called by run_socks when the session must be
 * re-established (downlink-silence watchdog, keepalive failures, server
 * CLOSE). The callback authenticates a NEW session and refreshes every
 * session-derived field of cfg (sid/token/inner_ip/gateway/mtu/dns; the
 * xor_key usually stays identical — it derives from the same
 * credentials). On success it returns 0 with *out_fd = the new UDP
 * socket (run_socks closes the old one). Returns -1 on failure:
 * run_socks keeps the old socket and retries later.
 *
 * The SOCKS listener, the accepted client flows and the userspace inner
 * TCP state (lwIP) are NOT touched by the re-auth: the tunnel is only
 * the carrier, and the USTC server keeps the inner IP across re-OPENs,
 * so established inner connections resume seamlessly. Only the tx queue
 * is flushed (queued frames carry the old sid/token; lwIP's RTO
 * retransmits them with the new outer header). */
typedef int (*socks_reauth_fn)(void *ud, SocksConfig *cfg, int *out_fd);

typedef struct SocksConfig {
    struct sockaddr_in listen_addr;
    const char *listen_str;  /* configured address text, printed like Rust */
    const char *auth_token;  /* RFC1929 password; NULL = no auth (as before) */
    bool     allow_remote;   /* allow non-loopback bind (--allow-remote) */
    bool     open_proxy;     /* explicit --socks-no-token: serve remote
                              * peers WITHOUT auth (open proxy) */
    bool     ipv6;           /* assume the server relays IPv6 (opt-in via
                              * --socks-ipv6): off by default, in which
                              * case domains resolve IPv4 only and ATYP=4
                              * CONNECTs are rejected rep=8; when on, v6
                              * is preferred for dual-stack domains */
    uint32_t inner_ip;     /* host-order IPv4 (from auth.tun) */
    uint32_t gateway;      /* host-order IPv4 (from auth.gw) */
    int      mtu;
    uint8_t  xor_key[8];
    uint16_t sid;
    uint32_t token;
    uint8_t  encryption;
    char     dns[16];      /* server-assigned DNS resolver (AuthResult.dns) */
    int      gso_ok;       /* 0 untried, 1 usable, -1 failed */
    size_t   gso_mss;      /* last UDP_SEGMENT mss set, 0 = none */
    pace_bucket pace;      /* aggregate send pacing (util.h); 0 = off */
    /* in-place tunnel re-auth (NULL = legacy: return 1 -> caller loop) */
    void          *reauth_ud;
    socks_reauth_fn reauth;
    /* runtime session-health state (not configuration): */
    uint64_t last_rx;      /* last downlink datagram (stale-session clock) */
    uint64_t reauth_at;    /* next in-place re-auth retry (0 = none) */
    int      ka_fail;      /* consecutive keepalive send failures */
    bool     session_lost; /* tunnel died (keepalive / no downlink) */
} SocksConfig;

/* Run SOCKS5 server (blocks). sockfd = authenticated UDP socket. */
int run_socks(int sockfd, SocksConfig *cfg);   /* 0 stopped, 1 session lost */

#endif
