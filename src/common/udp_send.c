#include "udp_send.h"

#include <errno.h>
#include <string.h>

#ifndef _WIN32
#include <netinet/udp.h>   /* SOL_UDP / UDP_SEGMENT */
#endif

#include "common.h"   /* port_poll / port_setsockopt via port.h */
#include "util.h"     /* now_ms */

void udp_gso_clear(int fd, int *ok, size_t *gso_mss)
{
    (void)ok;   /* the caller keeps ok for its own cache */
    if (*gso_mss != 0) {
        int z = 0;
        port_setsockopt(fd, SOL_UDP, UDP_SEGMENT, &z, sizeof z);
        *gso_mss = 0;
    }
}

int udp_gso_prepare(int fd, size_t mss, int *ok, size_t *gso_mss,
                    size_t *pending_mss, unsigned *streak)
{
    if (*ok == -1) {
        /* first use: probe; port_setsockopt translates UDP_SEGMENT to
         * WSAIoctl(SIO_UDP_NETSEGMENT) on Windows and fails with
         * EOPNOTSUPP on older systems, so the sendmmsg fallback works
         * unchanged on both platforms */
        int m = (int)mss;
        *ok = port_setsockopt(fd, SOL_UDP, UDP_SEGMENT, &m, sizeof m) == 0;
        if (!*ok) {
            *gso_mss = 0;
            return 0;
        }
        *gso_mss = mss;
        *pending_mss = mss;
        *streak = 0;
        return 1;
    }
    if (*ok == 0) {
        /* M11: a hard failure (probe or re-arm setsockopt) is cached,
         * but its cause can be transient (temporary resource
         * exhaustion, a restored offload setting). Re-probe at most
         * once per second — shared across all callers so the hot send
         * path never hammers setsockopt: success re-enables GSO for
         * the whole process, failure keeps the sendmmsg fallback.
         * Previously one failure disabled GSO for the process
         * lifetime (SUMMARY-2 M11). */
        static atomic_uint_fast64_t last_probe_ms;
        uint64_t now = now_ms();
        uint64_t last = atomic_load_explicit(&last_probe_ms,
                                             memory_order_relaxed);
        if (now - last < 1000)
            return 0;
        if (!atomic_compare_exchange_strong_explicit(&last_probe_ms,
                                                     &last, now,
                                                     memory_order_relaxed,
                                                     memory_order_relaxed))
            return 0;   /* another caller is probing this second */
        int m = (int)mss;
        if (port_setsockopt(fd, SOL_UDP, UDP_SEGMENT, &m, sizeof m) != 0)
            return 0;
        *ok = 1;
        *gso_mss = mss;
        *pending_mss = mss;
        *streak = 0;
        return 1;
    }
    if (*ok && *gso_mss != mss) {
        /* C1 hysteresis: a different uniform mss does NOT re-arm the
         * socket option immediately — mixed-MTU (A/B alternating) traffic
         * would flip setsockopt on every batch. This batch falls back to
         * sendmmsg; the new mss is armed only after it is seen
         * IWAN_GSO_HYST consecutive batches. send_ctrl's clear/re-arm
         * path bypasses this (it restores the armed mss itself). */
        if (*pending_mss == mss)
            (*streak)++;
        else {
            *pending_mss = mss;
            *streak = 1;
        }
        /* M3-5: a gso_mss == 0 armed state (ok still 1) is a dead state —
         * udp_gso_clear (called on any fallback batch) and send_ctrl's
         * failed re-arm both zero gso_mss without touching ok, and the
         * `*gso_mss != 0` guard below would then never re-arm, so GSO
         * stayed disabled for the whole session and the M11 *ok==0
         * re-probe was unreachable. When gso_mss is 0 there is no armed
         * value to be conservative about: re-arm immediately. A genuine
         * setsockopt failure lands in the *ok==0 M11 path. */
        if ((*gso_mss == 0 || *streak >= IWAN_GSO_HYST)) {
            int m = (int)mss;
            if (port_setsockopt(fd, SOL_UDP, UDP_SEGMENT, &m, sizeof m) != 0) {
                *ok = 0;
                *gso_mss = 0;
                return 0;
            }
            *gso_mss = mss;
            *streak = 0;
        }
        return 0;   /* this batch goes out via sendmmsg */
    }
    if (*ok) {
        /* armed mss matches: reset the hysteresis tracker */
        *pending_mss = mss;
        *streak = 0;
    }
    return *ok ? 1 : 0;
}

int udp_send_stall_wait(int fd, uint64_t retry_t0, unsigned budget_ms)
{
    uint64_t el = now_ms() - retry_t0;
    if (el >= budget_ms)
        return 0;
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    port_poll(&pfd, 1, (int)(budget_ms - el));
    return 1;
}
