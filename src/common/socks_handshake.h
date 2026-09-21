#ifndef IWAN_SOCKS_HANDSHAKE_H
#define IWAN_SOCKS_HANDSHAKE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "proto_parse.h"

/* Forward declaration of Flow */
struct Flow_s;
typedef struct Flow_s Flow;

/* SOCKS5 / HTTP reply helpers */
void socks_reply(Flow *f, uint8_t rep, uint32_t bnd_ip, uint16_t bnd_port);
void socks_reply6(Flow *f, uint8_t rep, const uint8_t bnd_ip6[16], uint16_t bnd_port);

/* Handshake dispatch and target start */
bool flow_open_gated(Flow *f, int af, uint32_t rip,
                     const uint8_t rip6[16], uint16_t port);
void flow_start_target(Flow *f, const pp_target *t);

/* Process incoming handshake data on a flow in ST_GREETING or ST_REQUEST. */
void process_socks_handshake(Flow *f);

#endif /* IWAN_SOCKS_HANDSHAKE_H */
