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
} SocksConfig;

/* Run SOCKS5 server (blocks). sockfd = authenticated UDP socket. */
void run_socks(int sockfd, const SocksConfig *cfg);

#endif
