#ifndef IWAN_UDP_SEND_H
#define IWAN_UDP_SEND_H

#include <stddef.h>
#include <stdint.h>

/* Shared UDP GSO/backpressure helpers for the SOCKS and TUN pump send
 * paths. The batch drivers (proxy.c send_batch/send_gso, socks.c
 * socks_send_batch2) keep their own retry/error contracts; these
 * helpers own only the platform-independent socket state transitions
 * that were previously duplicated (with "keep in sync" comments). */

/* UDP_SEGMENT (Linux) / SIO_UDP_NETSEGMENT (Windows) state on one
 * socket: ok = -1 unknown (probe on first use), 1 armed, 0 disabled
 * (probe failed or a hard error). gso_mss remembers the armed segment
 * size (0 = none). */
void udp_gso_clear(int fd, int *ok, size_t *gso_mss);

/* Prepare UDP_SEGMENT for a uniform batch of mss-sized datagrams.
 * Returns 1 when armed/usable, 0 when GSO is unavailable (the caller
 * falls back to per-datagram sendmmsg). Probing is cached in *ok; a
 * hard failure disables GSO permanently so re-probing stops. */
int udp_gso_prepare(int fd, size_t mss, int *ok, size_t *gso_mss);

/* One bounded EAGAIN/ENOBUFS/EPERM wait: poll POLLOUT for the remaining
 * retry budget (retry_t0 = drain start, budget_ms = total budget).
 * Returns 1 to retry, 0 when the budget is exhausted (caller yields to
 * its receive path). */
int udp_send_stall_wait(int fd, uint64_t retry_t0, unsigned budget_ms);

#endif /* IWAN_UDP_SEND_H */
