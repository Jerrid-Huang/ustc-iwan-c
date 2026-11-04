#ifndef IWAN_ECHO_H
#define IWAN_ECHO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"

/* ============================================================================
 * Panabit 60-byte keepalive: ECHOREQ/ECHORES payload helpers
 *
 * The official client sends ECHOREQ as 8B header + 16B signature + the 36-byte
 * payload described in protocol.h, and the responder echoes that payload back
 * verbatim (docs/sdwan-protocol.md section 5). The tick therefore measures a
 * round trip the client can turn into a one-way-ish delay sample
 * (delay = now_us - tick, with the responder's turnaround included).
 *
 * This module keeps the sender-side delay statistics (cur/min/max) the official
 * client maintains in si_curdelay/si_mindelay/si_maxdelay, and builds/observes
 * the frames so every sender path (socks proxy, TCP proxy, relay) behaves
 * identically.
 * ========================================================================== */

#define IWAN_ECHO_MIN_INIT 5000000u   /* client's initial si_mindelay (us) */

struct iwan_echo_stats {
    bool     have;       /* at least one observation */
    uint32_t cur;        /* last measured delay, us */
    uint32_t min;        /* min delay, us (IWAN_ECHO_MIN_INIT until first) */
    uint32_t max;        /* max delay, us */
    uint64_t tick;       /* tick of the last frame we built, us */
};

void iwan_echo_stats_init(struct iwan_echo_stats *st);

/* Append a complete control frame (header + signature + 36-byte payload) to
 * `out`. `st` may be NULL, in which case cur/min/max are sent as zero. */
void iwan_echo_build(buf_t *out, uint8_t typ, uint8_t enc, uint16_t sid,
                     uint32_t tok, struct iwan_echo_stats *st, uint64_t now_us);

/* Fold an ECHORESP payload into `st`. Returns false when the payload is short
 * or was not built by us (tick in the future beyond a sane clock skew), in
 * which case nothing is updated. */
bool iwan_echo_observe(struct iwan_echo_stats *st, const uint8_t *payload,
                       size_t len, uint64_t now_us);

#endif
