#ifndef IWAN_PROXY_H
#define IWAN_PROXY_H

#include <stdint.h>
#include "common.h"

/* TUN <-> UDP pump. Blocks until Ctrl-C/error. sockfd already authenticated.
 * route_targets: list of CIDR/"default"/IPv4/domain strings (may be empty). */
int run_pump(int tun_fd, const char *tun_name, int sockfd,
             const uint8_t xor_key[8], uint16_t sid, uint32_t tok, uint8_t enc,
             const char *server, const slist_t *route_targets,
             const char *auth_tun_ip, uint16_t auth_mtu);

#endif
