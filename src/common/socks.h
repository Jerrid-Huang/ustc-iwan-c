#ifndef IWAN_SOCKS_H
#define IWAN_SOCKS_H

#include <stdint.h>
#include <netinet/in.h>

typedef struct {
    struct sockaddr_in listen_addr;
    const char *listen_str;  /* configured address text, printed like Rust */
    uint32_t inner_ip;     /* host-order IPv4 (from auth.tun) */
    uint32_t gateway;      /* host-order IPv4 (from auth.gw) */
    int      mtu;
    uint8_t  xor_key[8];
    uint16_t sid;
    uint32_t token;
    uint8_t  encryption;
    int      gso_ok;       /* 0 untried, 1 usable, -1 failed */
    size_t   gso_mss;      /* last UDP_SEGMENT mss set, 0 = none */
} SocksConfig;

/* Run SOCKS5 server (blocks). sockfd = authenticated UDP socket. */
void run_socks(int sockfd, SocksConfig *cfg);

#endif
