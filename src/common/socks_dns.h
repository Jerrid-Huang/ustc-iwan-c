#ifndef IWAN_SOCKS_DNS_H
#define IWAN_SOCKS_DNS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "socks_internal.h"

/* Initialize / reset / stop tunnel DNS */
void dns_set_server(const char *ip);
const char *dns_server_name(void);
void dns_reset(void);
void dns_stop(void);

/* Session lock for DNS snapshot reads */
void dns_session_lock(void);
void dns_session_unlock(void);

/* Queue management */
void dns_push_g(unsigned gen, int flow_id, bool ok, uint8_t af,
                uint32_t ip, const uint8_t ip6[16], uint16_t port);
int  dns_drain(DnsResult *out, int max);

/* Spawn async lookup workers */
void spawn_dns(int flow_id, const char *domain, uint16_t port);

/* Consume inner DNS response packets (returns true if packet was consumed) */
bool dns_try_handle_response(const uint8_t *pkt, size_t n);

#endif /* IWAN_SOCKS_DNS_H */
