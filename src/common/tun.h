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
 * (tun_attach) enable parallel user-space readers.
 * open_tun is the MAIN-device creation and uses IFF_TUN_EXCL (fails EBUSY
 * if the name is already taken); tun_attach deliberately does NOT use
 * EXCL because it re-opens the device we already own to add a queue. */
int  open_tun(const char *name);     /* device owner fd or -1 */
int  tun_attach(const char *name);   /* extra queue fd or -1 */

/* Pre-open up to `maxn` extra queue fds (tun_attach each; stop at first
 * failure). The server calls this while still root so the de-privileged
 * child can pass the fds to tun_pool_create_pre and keep a real
 * multi-queue fan-out. Returns the number actually opened (0 on non-Linux
 * where tun_attach is unavailable).
 * R37 R1E-2: Linux/macOS only — the Windows backend (tun_win.c) is a
 * single-queue wintun pool and implements none of the multi-queue API
 * (tun_attach_many, tun_pool_create_pre, tun_reader_qid); declaring them
 * there promised symbols that do not exist (link-time undefined reference).
 * The only callers live in the Linux-only iwan-server target. */
#ifndef _WIN32
int  tun_attach_many(const char *name, int *fds, int maxn);
#endif

/* The interface name to hand to ifconfig/route etc. Linux/Windows:
 * the requested name IS the interface. macOS: utun devices are named
 * by the kernel (utunN), so open_tun maps the requested name to the
 * actual device and this returns that mapping (or the name unchanged
 * when no mapping exists). */
const char *tun_ifname(const char *name);

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
/* per-packet callback: pkt is a per-reader scratch buffer, owned by the
 * caller only until the callback returns (a batch-oriented callback may
 * copy it; in-place modification is allowed — the server XORs in place) */
typedef void (*tun_pkt_fn)(void *ud, uint8_t *pkt, size_t len, bool last);
typedef void (*tun_exit_fn)(void);

/* tun_pool_tick must be called at (at most) this cadence for the AIMD
 * busy-signal accounting to stay consistent. */
#define TUN_POOL_TICK_MS 500
/* hard ceiling for the queue count (tun_pool_create clamps maxq) */
#define TUN_POOL_MAX 8

struct tun_pool *tun_pool_create(const char *name, int fd0, int maxq,
                                 int initq, tun_pkt_fn cb, void *ud,
                                 atomic_bool *abort);
/* tun_pool_create_pre: same as tun_pool_create, but the eager fill first
 * consumes up to `npre` queue fds from `prefds` (pre-opened by the caller
 * while it still had the privilege), then falls back to tun_attach for any
 * shortfall. Ownership of all `prefds` transfers to the pool — they become
 * ordinary extra queues (closed by tun_pool_destroy), and any the pool
 * does not need are closed during create. Pass prefds=NULL/npre=0 for the
 * plain behavior. The server uses this to keep a real multi-queue fan-out
 * after fork+setuid (see tun_attach_many). Linux/macOS only (R37 R1E-2). */
#ifndef _WIN32
struct tun_pool *tun_pool_create_pre(const char *name, int fd0, int maxq,
                                     int initq, const int *prefds, int npre,
                                     tun_pkt_fn cb, void *ud,
                                     atomic_bool *abort);
#endif
/* actual number of reader threads currently running: adapts (AIMD
 * grow/shrink) on Linux, always 1 on Windows (wintun is single-queue) */
int tun_pool_queues(const struct tun_pool *p);
/* queue fd for uplink writer `tid` (spread writes across queue fds so
 * the device write lock is not a single serialization point); -1 when
 * the pool is empty. Safe to call concurrently with tun_pool_tick.
 * R54-WG3-3: returns a RAW fd — the caller's own write is NOT protected
 * against a concurrent tun_pool_del closing-and-recycling the number.
 * The server therefore writes through tun_pool_write below, which holds
 * the pool lock across the write and closes that window; use this only
 * when the documented "EBADF = transient drop" contract is acceptable. */
int tun_pool_write_fd(const struct tun_pool *p, unsigned tid);
/* R54-WG3-3: lock-protected uplink write — select the queue fd for
 * writer `tid`, and perform the whole tun_write_retry (budget max_ms;
 * mirrors the raw path's EAGAIN-retry "still full after the bound:
 * dropped" contract) under the pool's read lock. tun_pool_del /
 * tun_pool_destroy close queue fds under the write lock, so the close can
 * never race an in-flight write: a stale write can never land on a
 * closed-and-recycled fd number. Returns 0 fully written, -1 dropped
 * (errno preserved on fatal; persistent EAGAIN / EBADF are transient
 * drops, the same contract as before). Linux/macOS only — the Windows
 * wintun backend is single-queue and writes through its own fd. */
#ifndef _WIN32
int tun_pool_write(struct tun_pool *p, unsigned tid, const uint8_t *pkt,
                   size_t len, int max_ms);
/* R54-WG3-1: number of pool queues whose reader exited unexpectedly
 * (device deleted externally without a pool stop). >0 even while the
 * same-named device still exists (a racing grow re-created it); normal
 * del/destroy reads never raise it. The server's dead-tunnel probe
 * treats >0 as fatal. Linux/macOS only (tun_win.c has no such signal). */
int tun_pool_readers_lost(const struct tun_pool *p);
#endif
/* uplink write hit the device queue: prevents the AIMD shrink for the
 * next tick (write fan-out must not collapse under upload congestion) */
void tun_pool_note_stall(struct tun_pool *p);
/* queue index of the calling reader thread (0-based, set at thread
 * start): lets a per-queue consumer (server downlink fd + batch state)
 * pick its own state inside the packet callback without changing the
 * callback signature. Linux/macOS only (R37 R1E-2: the Windows wintun
 * backend is single-queue and has no such thread-local, so the previous
 * "Always 0 on Windows" promise described a function that did not exist
 * there). */
#ifndef _WIN32
int tun_reader_qid(void);
#endif
void tun_pool_set_exit_cb(struct tun_pool *p, tun_exit_fn cb);
void tun_pool_tick(struct tun_pool *p);
void tun_pool_destroy(struct tun_pool *p);

#endif
