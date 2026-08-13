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

typedef struct {
    struct sockaddr_in listen_addr;
    const char *listen_str;  /* configured address text, printed like Rust */
    const char *auth_token;  /* RFC1929 password; NULL = no auth (as before) */
    bool     allow_remote;   /* allow non-loopback bind (--allow-remote) */
    bool     open_proxy;     /* explicit --socks-no-token: serve remote
                              * peers WITHOUT auth (open proxy) */
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
    /* runtime session-health state (not configuration): */
    uint64_t last_rx;      /* last downlink datagram (stale-session clock) */
    int      ka_fail;      /* consecutive keepalive send failures */
    bool     session_lost; /* tunnel died (keepalive / no downlink) */
} SocksConfig;

/* Run SOCKS5 server (blocks). sockfd = authenticated UDP socket. */
int run_socks(int sockfd, SocksConfig *cfg);   /* 0 stopped, 1 session lost */

#endif
