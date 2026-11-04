#include "echo.h"

#include <string.h>

#include "protocol.h"

void iwan_echo_stats_init(struct iwan_echo_stats *st)
{
    if (st == NULL)
        return;
    st->have = false;
    st->cur = 0;
    st->min = IWAN_ECHO_MIN_INIT;
    st->max = 0;
    st->tick = 0;
}

void iwan_echo_build(buf_t *out, uint8_t typ, uint8_t enc, uint16_t sid,
                     uint32_t tok, struct iwan_echo_stats *st, uint64_t now_us)
{
    struct iwan_echo e;

    memset(&e, 0, sizeof e);
    e.tick = now_us;
    if (st != NULL) {
        /* Before a sample is obtained, send the client's initial value min=5s (si_mindelay's initial value),
         * not 0 -- the official client fills it in exactly this way (spec section 16) */
        e.cur = st->have ? st->cur : 0;
        e.min = st->have ? st->min : IWAN_ECHO_MIN_INIT;
        e.max = st->have ? st->max : 0;
        st->tick = now_us;
    }
    /* ECHOREQ is a control frame carrying a 16-byte signature; the peer generates ECHORES with the same signature rules */
    ctrl_hdr(out, typ, enc, sid, tok);
    echo_put(out, &e);
}

bool iwan_echo_observe(struct iwan_echo_stats *st, const uint8_t *payload,
                       size_t len, uint64_t now_us)
{
    struct iwan_echo e;
    uint32_t d;

    if (st == NULL || !echo_parse(payload, len, &e))
        return false;
    /* Subtract only the low 32 bits: the official client's os_curusec() is gettimeofday microseconds,
     * wrapping period about 71.6 min (spec section 16). A tick clearly in the future means it is not our response */
    d = (uint32_t)now_us - (uint32_t)e.tick;
    if ((int32_t)d < 0)
        return false;
    st->cur = d;
    if (!st->have) {
        st->have = true;
        st->min = d;
        st->max = d;
    } else {
        if (d < st->min)
            st->min = d;
        if (d > st->max)
            st->max = d;
    }
    return true;
}
