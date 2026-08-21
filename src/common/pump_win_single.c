#include "pump_win_single.h"

#ifdef _WIN32

#include <errno.h>
#include <string.h>

#include "crypto.h"      /* xor_crypt */
#include "profile.h"     /* PROF_ADD */
#include "protocol.h"    /* PT_DATA(_ENC), pkt_hdr */
#include "udp_send.h"    /* udp_send_stall_wait */

/* One highly-optimized uplink thread. For each wintun packet:
 *   - XOR the payload in place inside the ring buffer (zero copy),
 *   - send the 8-byte iWAN header + payload as one WSASend (two iovecs),
 *   - release the ring slot (done by tun_pool after the callback).
 * No batch accumulation, no SPSC rings, no semaphores, no sender thread.
 * The 4-buffer backpressure disappears: the socket's own send buffer is
 * the only backpressure, with the same bounded EAGAIN budget as the
 * two-thread path. */

int pump_win_single_start(pump_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

void pump_win_single_stop(pump_ctx_t *ctx)
{
    (void)ctx;
}

void pump_win_single_free(pump_ctx_t *ctx)
{
    (void)ctx;
}

void pump_win_single_pkt(void *ud, uint8_t *pkt, size_t len, bool last)
{
    pump_ctx_t *ctx = ud;

    if (last)
        return;   /* every packet was handled inline; nothing pending */
    if (len > (uint32_t)g_prof_tun_rmax)
        g_prof_tun_rmax = (uint32_t)len;   /* single reader thread */
    if (len > 1508)
        atomic_fetch_add(&g_prof_tun_rbig, 1);
    if (len == 0 || len > PUMP_SLOT) {
        if (len > PUMP_SLOT)
            atomic_fetch_add(&g_prof_tun_rdrop, 1);
        log_debug("pump: drop packet, len %zu out of [1, %d]", len,
                  PUMP_SLOT);
        return;
    }
    if (g_stop)
        return;

    uint8_t hdr[8];
    pkt_hdr(ctx->enc ? PT_DATA_ENC : PT_DATA, ctx->enc, ctx->sid,
            ctx->tok, hdr);

    uint64_t t0 = now_us();
    xor_crypt(pkt, len, ctx->xor_key, 8);   /* in place in the ring */
    pump_prof_add(&ctx->prof[PP_COPY_XOR], now_us() - t0);
    PROF_ADD(g_prof_pump_tx, len);
    atomic_fetch_add(&g_prof_send_dgrams, 1);

    struct iovec iov[2] = {
        { .iov_base = hdr, .iov_len = 8 },
        { .iov_base = pkt, .iov_len = len },
    };
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = iov;
    mh.msg_iovlen = 2;

    uint64_t s0 = now_us();
    uint64_t retry_t0 = now_ms();
    for (;;) {
        if (g_stop)
            break;
        atomic_fetch_add(&g_prof_send_syscalls, 1);
        ssize_t r = port_sendmsg(ctx->sockfd, &mh, 0);
        if (r == (ssize_t)(8 + len))
            break;
        if (r >= 0)
            break;   /* partial datagram (unexpected): drop the rest */
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ENOBUFS || errno == EPERM) {
            atomic_fetch_add(&g_prof_send_eagain, 1);
            if (!udp_send_stall_wait(ctx->sockfd, retry_t0,
                                     PUMP_SEND_RETRY_MS))
                break;   /* bounded: drop back to reading the ring */
            continue;
        }
        err_printf("[TUN->UDP] send: %s\n", strerror(errno));
        g_stop = 1;
        break;
    }
    pump_prof_add(&ctx->prof[PP_SEND_SYS], now_us() - s0);
    pump_prof_add(&ctx->prof[PP_SEND], now_us() - t0);
}

#endif /* _WIN32 */
