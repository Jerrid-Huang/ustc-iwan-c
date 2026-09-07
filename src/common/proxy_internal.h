#ifndef IWAN_PROXY_INTERNAL_H
#define IWAN_PROXY_INTERNAL_H

/* Internal pump context shared between proxy.c (the generic TUN pump)
 * and the Windows-specific pump variants (proxy.c's two-thread SPSC
 * sender, or pump_win_single.c's single-thread zero-copy path). The
 * variant is selected at build time; only one is compiled into
 * iwan_core. */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#include "common.h"   /* port.h: winsock2/windows.h on Windows, iovec */
#include "util.h"     /* pace_bucket */

#ifndef _WIN32
#include <sys/socket.h>   /* struct mmsghdr (with _GNU_SOURCE) */
#include <sys/uio.h>
#endif

struct tun_pool;   /* fwd: tun.h is the owner of the pool internals */

/* ---------------- pump constants ---------------- */
#define PUMP_BATCH 32
#define PUMP_SLOT  2048

#ifndef PUMP_MAX_LAT_US
#define PUMP_MAX_LAT_US 20
#endif

#define PUMP_SEND_RETRY_MS 5   /* EAGAIN/ENOBUFS retry budget per flush:
                                * beyond it, yield to the receive path */

/* ---------------- profiler ---------------- */
#define PUMP_PROF_N 11
enum {
    PP_COPY_XOR = 0,  /* uplink: per-packet copy + XOR into batch */
    PP_ENQ,           /* uplink: per-batch SPSC enqueue */
    PP_SEND,          /* uplink: per-batch UDP send (incl. lock/GSO) */
    PP_RECV,          /* downlink: recvmmsg batch drain */
    PP_TUNWRITE,      /* downlink: per-packet wintun write */
    PP_SEND_SYS,      /* send sub: time inside port_sendmmsg/port_sendmsg */
    PP_SEND_RETRY,    /* send sub: time inside pump_send_retry (EAGAIN wait) */
    PP_SEND_PACE,     /* send sub: time inside pace_take */
    PP_SENDWAIT,      /* sender sub: blocked on ready_sem (idle/starve) */
    PP_POLLWAIT,      /* recv sub: parked in port_poll (no downlink) */
    PP_DLPKT,         /* downlink: whole per-packet loop (incl tun_write) */
};
/* M3-10: per-slot profiler counters — RMW'd by up to TUN_POOL_MAX reader
 * threads and read live by run_pump's tick, so they must be atomic
 * (plain uint64_t was a data race whenever IWAN_PUMP_PROF=1). */
typedef struct { atomic_uint_fast64_t us; atomic_uint_fast64_t n; } pump_prof_t;

/* C4: profiler collection is gated on IWAN_PUMP_PROF (parsed once, like
 * profile.h's g_prof_on) — the per-packet timer/atomic work is pure
 * waste when nobody reads the printout. The single-thread pump variant
 * shares this flag through these externs. */
extern atomic_int g_pump_prof_on;      /* collection gate (relaxed) */
int pump_prof_gate_init(void);         /* parse env once, set the gate */
static inline bool pump_prof_on(void)
{
    return atomic_load_explicit(&g_pump_prof_on, memory_order_relaxed);
}
static inline void pump_prof_add(pump_prof_t *p, uint64_t us)
{
    if (!pump_prof_on())
        return;
    p->us += us;
    p->n++;
}
/* definitions live in proxy.c; the single-thread variant reads/writes
 * the same counters through these externs */
extern atomic_uint_fast64_t g_prof_send_dgrams;
extern atomic_uint_fast64_t g_prof_send_syscalls;
extern atomic_uint_fast64_t g_prof_send_eagain;
extern atomic_uint_fast64_t g_prof_recv_dgrams;
extern atomic_uint_fast64_t g_prof_recv_empty;
extern atomic_uint_fast64_t g_prof_recv_badtok;
extern atomic_uint_fast64_t g_prof_tun_rbig;
extern atomic_uint_fast64_t g_prof_tun_rdrop;
extern _Atomic uint32_t g_prof_tun_rmax;
extern atomic_uint_fast64_t g_prof_pump_tx;
extern atomic_uint_fast64_t g_prof_pump_rx;

#ifdef _WIN32
extern atomic_uint_fast64_t g_tun_wait_us, g_tun_timeouts, g_tun_wakeups,
                            g_tun_pkts, g_tun_drain_us, g_tun_allocfail;
#endif

/* ---------------- TX batch ---------------- */
typedef struct {
    uint8_t *batch;
    struct iovec iov[PUMP_BATCH];
    struct mmsghdr msgs[PUMP_BATCH];
    uint8_t hdr[8];
    unsigned n;
    uint64_t t0;
} pump_tx_t;

/* ---------------- pump context ---------------- */
typedef struct {
    int      tun_fd;   /* downlink write fd (queue 0, device owner) */
    int      sockfd;
    uint8_t  xor_key[8];
    uint16_t sid;
    uint32_t tok;
    uint32_t inner_ip; /* session IP, host order: downlink addr filter */
    uint8_t  enc;
    size_t   gso_mss;   /* last UDP_SEGMENT value set, 0 = none */
    int      gso_ok;    /* 1 = UDP_SEGMENT usable, 0 = failed, -1 = untried */
    size_t   gso_pending_mss; /* C1 hysteresis: mss seen in recent batches */
    unsigned gso_streak;     /* C1 hysteresis: consecutive batches whose
                              * uniform mss == gso_pending_mss while the
                              * armed mss differs; re-arm after
                              * IWAN_GSO_HYST batches so a mixed-MTU
                              * (A/B alternating) stream stops flipping
                              * the socket option on every batch */
    pthread_mutex_t send_lock; /* serializes GSO/sendmmsg on the shared socket */
    struct tun_pool *pool;
    pace_bucket pace;   /* aggregate send pacing (util.h); serialized by
                         * send_lock — the bucket is not thread-safe */
    /* M3-1: written by udp2tun_thread and read by run_pump's tick loop
     * while the thread is alive — must be atomic (plain bool was a
     * C11 data race; M14 only initialized it) */
    _Atomic bool session_lost; /* set by udp2tun_thread when the tunnel
                          * is considered dead (keepalive failures / no
                          * downlink); distinguishes failure from the
                          * user's Ctrl-C so run_pump can report it */
    pump_prof_t prof[PUMP_PROF_N];   /* [prof] stage timers (whole-run) */
} pump_ctx_t;

#endif /* IWAN_PROXY_INTERNAL_H */
