#ifndef IWAN_SERVER_MIRROR_H
#define IWAN_SERVER_MIRROR_H

#include <stddef.h>
#include <stdint.h>
#include "server.h"

/* --no-tun echo mode: mirror an inner TCP packet (IPv4 or IPv6) back to its
 * sender by swapping addresses/ports and seq/ack. */
int echo_mirror(struct server_ctx *ctx, uint8_t *p, size_t len, int sockfd);

#endif /* IWAN_SERVER_MIRROR_H */
