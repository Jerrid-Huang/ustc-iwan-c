#ifndef IWAN_TUN_H
#define IWAN_TUN_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* IFNAMSIZ is a Linux/BSD constant (16) with no Windows counterpart; the
 * tun_name_valid length check needs it on both platforms. Linux headers
 * define the identical value, so this is a no-op there. */
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

/* All tun devices are created with IFF_MULTI_QUEUE: a single queue fd is
 * indistinguishable from the old single-queue mode, and extra queue fds
 * (tun_attach) enable parallel user-space readers. */
int  open_tun(const char *name);     /* device owner fd or -1 */
int  tun_attach(const char *name);   /* extra queue fd or -1 */

/* Validate a TUN device name before it is handed to open_tun or fed to
 * `ip link del` as root: non-empty, at most IFNAMSIZ-1 chars, lowercase
 * alnum/'-'/'_' with a leading letter, and not a typical physical/system
 * interface name (eth*, enp*, lo, docker*, ...) this VPN must never own.
 * Shared by both backends (tun.c on Linux, tun_win.c on Windows): the
 * rule set is platform-independent and the two must agree on it. */
static inline bool tun_name_reserved(const char *name)
{
    static const char *const reserved[] = {
        "eth", "enp", "eno", "ens", "wlp", "wlo", "wwan", "docker",
        "br-", "veth", "tailscale",
        "br0", "virbr", "vmbr", "bond", "team", "ovs", "tap", "tun",
        "vxlan", "vlan", "dummy", "wg", "ppp", "gre", "sit",
    };
    if (strcmp(name, "lo") == 0)
        return true;
    for (size_t i = 0; i < sizeof reserved / sizeof reserved[0]; i++) {
        const char *r = reserved[i];
        if (strncmp(name, r, strlen(r)) == 0)
            return true;
    }
    return false;
}

static inline bool tun_name_valid(const char *name)
{
    size_t n = strlen(name);
    if (n == 0 || n > IFNAMSIZ - 1)
        return false;
    if (!(name[0] >= 'a' && name[0] <= 'z'))
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '-' || c == '_'))
            return false;
    }
    return !tun_name_reserved(name);
}

void tun_detach(int fd);             /* TUNSETQUEUE detach; extra queues only */
void tun_close(int fd);
void set_nonblock(int fd);
ptrdiff_t tun_write(int fd, const void *buf, size_t len);

/* Attach the embedded flow-hash steering program (TUNSETSTEERINGEBPF).
 * Replaces the tun driver's automq, whose flow hash degenerates to a
 * per-device constant here. 0 on success, -1 if unavailable. */
int tun_steering_attach(int tun_fd);

/* Write with EAGAIN poll-retry instead of dropping; max_ms == 0 waits
 * indefinitely. Returns 0 when fully written, -1 on persistent EAGAIN
 * (max_ms elapsed) or fatal error (errno preserved). stop is the shared
 * process stop flag (util.h g_stop); may be NULL to wait unbounded. */
int tun_write_retry(int fd, const uint8_t *pkt, size_t len, int max_ms,
                    atomic_bool *stop);

/* Generic IFF_MULTI_QUEUE reader pool, shared by iwan-server (downlink
 * readers) and the client TUN pump (uplink readers): one thread per
 * queue fd, AIMD grow/shrink driven by tun_pool_tick (~500ms cadence)
 * on the poll-timeout busy signal.
 * cb(ud, pkt, len, last): last=true is a flush signal emitted once the
 * queue drains (EAGAIN), so batch-oriented callbacks can flush their
 * partial batch. fd0 ownership stays with the caller; tun_pool_destroy
 * detaches and closes the extra queues only. abort is the shared stop
 * flag checked by the reader threads (util.h g_stop; may be NULL).
 * tun_pool_set_exit_cb registers an optional per-thread callback that
 * each reader thread runs once, on its own thread, just before exiting
 * (after the final flush signal) — used to free thread-local batch
 * buffers (client pump's g_tx). */
struct tun_pool;
typedef void (*tun_pkt_fn)(void *ud, const uint8_t *pkt, size_t len,
                           bool last);
typedef void (*tun_exit_fn)(void);

/* tun_pool_tick must be called at (at most) this cadence for the AIMD
 * busy-signal accounting to stay consistent. */
#define TUN_POOL_TICK_MS 500
/* hard ceiling for the queue count (tun_pool_create clamps maxq) */
#define TUN_POOL_MAX 8

struct tun_pool *tun_pool_create(const char *name, int fd0, int maxq,
                                 int initq, tun_pkt_fn cb, void *ud,
                                 atomic_bool *abort);
/* actual number of reader threads currently running: adapts (AIMD
 * grow/shrink) on Linux, always 1 on Windows (wintun is single-queue) */
int tun_pool_queues(const struct tun_pool *p);
void tun_pool_set_exit_cb(struct tun_pool *p, tun_exit_fn cb);
void tun_pool_tick(struct tun_pool *p);
void tun_pool_destroy(struct tun_pool *p);

#endif
