#ifndef IWAN_SERVER_RATE_H
#define IWAN_SERVER_RATE_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

/* IWAN_RATE_* limits are read once at startup (server_rate_limits_init) */
void server_rate_limits_init(void);

/* Return g_up_throttle_ms */
unsigned server_rate_get_throttle_ms(void);

/* Check rate allowance for unauthenticated control packets (PT_OPEN, PT_PING_REQ, PT_ECHO_REQ).
 * Returns true if allowed, false if dropped (drops increment g_rate_drops). */
bool server_rate_allow_control(const struct sockaddr_in *peer, uint8_t typ);

/* Check rate allowance for unknown-sid misses (DATA / PT_DATA_ENC / CLOSE).
 * Returns true if within miss allowance, false if over budget. */
bool server_rate_allow_sid_miss(uint32_t ip, uint64_t now);

/* Check rate allowance for bound-class wrong-token DATA frames.
 * Returns true if within tokbad budget, false if over budget. */
bool server_rate_allow_tokbad(const struct sockaddr_in *peer, uint64_t now);

/* Check rate allowance for known-sid wrong-token CLOSE frames.
 * Returns true if within close budget, false if over budget. */
bool server_rate_allow_close(const struct sockaddr_in *peer, uint64_t now);

/* Account one drop in g_rate_drops */
void server_rate_drop_inc(void);

/* Print rate drop stats once per second if changed */
void server_rate_drops_maybe_print(void);

/* Read g_rate_drops total (used in stats printing) */
uint64_t server_rate_drops_total(void);

/* Mark current g_rate_drops as reported (called when uplink stats line prints) */
void server_rate_drops_mark_reported(void);

#endif /* IWAN_SERVER_RATE_H */
