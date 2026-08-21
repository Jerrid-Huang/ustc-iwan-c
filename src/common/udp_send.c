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

int udp_gso_prepare(int fd, size_t mss, int *ok, size_t *gso_mss)
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
        return 1;
    }
    if (*ok && *gso_mss != mss) {
        /* re-arm a WORKING GSO socket for a new mss; once GSO is known
         * unavailable (e.g. SIO_UDP_NETSEGMENT rejected on Windows)
         * re-probing on every distinct batch size would just spam
         * WSAEOPNOTSUPP — stay on the sendmmsg fallback */
        int m = (int)mss;
        if (port_setsockopt(fd, SOL_UDP, UDP_SEGMENT, &m, sizeof m) != 0) {
            *ok = 0;
            *gso_mss = 0;
            return 0;
        }
        *gso_mss = mss;
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
