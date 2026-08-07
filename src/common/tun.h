#ifndef IWAN_TUN_H
#define IWAN_TUN_H

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* All tun devices are created with IFF_MULTI_QUEUE: a single queue fd is
 * indistinguishable from the old single-queue mode, and extra queue fds
 * (tun_attach) enable parallel user-space readers. */
int  open_tun(const char *name);     /* device owner fd or -1 */
int  tun_attach(const char *name);   /* extra queue fd or -1 */
void tun_detach(int fd);             /* TUNSETQUEUE detach; extra queues only */
void tun_close(int fd);
void set_nonblock(int fd);
ptrdiff_t tun_read(int fd, void *buf, size_t len);
ptrdiff_t tun_write(int fd, const void *buf, size_t len);

/* Attach the embedded flow-hash steering program (TUNSETSTEERINGEBPF).
 * Replaces the tun driver's automq, whose flow hash degenerates to a
 * per-device constant here. 0 on success, -1 if unavailable. */
int tun_steering_attach(int tun_fd);

/* Write with EAGAIN poll-retry instead of dropping; max_ms == 0 waits
 * indefinitely. Returns 0 when fully written, -1 on persistent EAGAIN
 * (max_ms elapsed) or fatal error (errno preserved). */
int tun_write_retry(int fd, const uint8_t *pkt, size_t len, int max_ms,
                    volatile sig_atomic_t *stop);

/* Generic IFF_MULTI_QUEUE reader pool, shared by iwan-server (downlink
 * readers) and the client TUN pump (uplink readers): one thread per
 * queue fd, AIMD grow/shrink driven by tun_pool_tick (~500ms cadence)
 * on the poll-timeout busy signal.
 * cb(ud, pkt, len, last): last=true is a flush signal emitted once the
 * queue drains (EAGAIN), so batch-oriented callbacks can flush their
 * partial batch. fd0 ownership stays with the caller; tun_pool_destroy
 * detaches and closes the extra queues only. abort is a shared stop
 * flag checked by the reader threads (may be NULL). */
struct tun_pool;
typedef void (*tun_pkt_fn)(void *ud, const uint8_t *pkt, size_t len,
                           bool last);

/* tun_pool_tick must be called at (at most) this cadence for the AIMD
 * busy-signal accounting to stay consistent. */
#define TUN_POOL_TICK_MS 500
/* hard ceiling for the queue count (tun_pool_create clamps maxq) */
#define TUN_POOL_MAX 8

struct tun_pool *tun_pool_create(const char *name, int fd0, int maxq,
                                 int initq, tun_pkt_fn cb, void *ud,
                                 volatile sig_atomic_t *abort);
void tun_pool_tick(struct tun_pool *p);
void tun_pool_destroy(struct tun_pool *p);

#endif
