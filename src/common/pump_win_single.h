#ifndef IWAN_PUMP_WIN_SINGLE_H
#define IWAN_PUMP_WIN_SINGLE_H

#include "proxy_internal.h"

#ifdef _WIN32
/* Single-thread Windows TUN uplink: one thread reads the wintun ring and
 * immediately WSASends each packet — no SPSC producer/consumer handoff,
 * no semaphores, no separate sender thread, and no copy (the payload is
 * XORed in place inside the ring buffer and sent as header+payload
 * iovecs). Selected with IWAN_WIN_PUMP_SINGLE=1. The downlink recv
 * thread (udp2tun_thread) is unchanged. */

int  pump_win_single_start(pump_ctx_t *ctx);   /* no-op: no thread */
void pump_win_single_stop(pump_ctx_t *ctx);    /* no-op */
void pump_win_single_free(pump_ctx_t *ctx);    /* no-op */
void pump_win_single_pkt(void *ud, uint8_t *pkt, size_t len, bool last);
#endif

#endif /* IWAN_PUMP_WIN_SINGLE_H */
