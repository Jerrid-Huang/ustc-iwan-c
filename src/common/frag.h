#ifndef IWAN_FRAG_H
#define IWAN_FRAG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * SD-WAN inner-packet fragmentation (frame types 0x22 / 0x24)
 *
 * Wire layout of one fragment datagram, after the 8-byte iwan header (the
 * fragment header is 8 bytes, not 16: the official client's `sdwan_ethpkt`
 * is 8 bytes of iwan header + 8 bytes of fragment header. All fragment fields
 * are HOST order, unlike the rest of the protocol -- the client memcpy()s the
 * two u32 words verbatim):
 *
 *   +0   u32 id        fragment-group id; 0 marks an empty reassembly slot
 *   +4   u32 w         bit field, little-endian packed:
 *                        bit 0      eop       1 = this is the last fragment
 *                        bit 1      fromin    never read by the client
 *                        bits 2-14  fragoff  byte offset inside the group
 *                        bits 15-25 fraglen  payload bytes carried here
 *                        bits 26-31 reserved never validated
 *   +8   u8  data[fraglen]
 *
 * The datagram must be exactly 16 + fraglen bytes long; anything else is
 * dropped as malformed. Frame types 0x22 and 0x24 are handled identically by
 * the official client (both dispatch to the same function).
 * ========================================================================== */

#define IWAN_FRAG_HDR_LEN   8    /* id + meta, AFTER the 8-byte iwan header */
#define IWAN_FRAG_BUF_MAX   4096   /* reassembled packet ceiling */
#define IWAN_FRAG_OFF_MAX   8191   /* 13-bit fragoff field */
#define IWAN_FRAG_LEN_MAX   2047   /* 11-bit fraglen field */
#define IWAN_FRAG_SLOTS     16     /* in-flight groups per endpoint */
#define IWAN_FRAG_TIMEOUT_MS 10000 /* fragTimeOut in the official client */

struct iwan_frag_hdr {
    uint32_t id;
    bool     eop;
    bool     fromin;
    uint16_t fragoff;
    uint16_t fraglen;
};

/* Pack/unpack the 16-byte fragment header. frag_hdr_get() additionally
 * enforces len == IWAN_FRAG_HDR_LEN + fraglen (the official client's only
 * validation) and rejects an empty or oversized fragment. */
void frag_hdr_put(uint8_t out[IWAN_FRAG_HDR_LEN], const struct iwan_frag_hdr *h);
bool frag_hdr_get(const uint8_t *buf, size_t len, struct iwan_frag_hdr *h);

/* One reassembly slot. `buf` holds the partially reassembled packet; `seg`
 * records the covered byte ranges as merged intervals so out-of-order
 * delivery is accepted and completeness is exact at byte granularity (a
 * 64-byte-block bitmap would mark a block covered as soon as the first
 * fragment touched it). The official client only ever sends two in-order
 * fragments and matching on `id` alone; being stricter here (full interval
 * tracking) is still wire-compatible. */
struct iwan_frag_slot {
    bool     used;
    uint16_t sid;
    uint32_t tok;
    uint32_t id;
    uint64_t last_ms;
    bool     total_known;   /* eop seen */
    size_t   total;         /* complete packet length once eop is known */
    int      nseg;          /* merged, sorted, non-adjacent intervals */
    struct {
        uint16_t off;
        uint16_t len;
    } seg[8];
    uint8_t  buf[IWAN_FRAG_BUF_MAX];
};

struct iwan_frag_pool {
    struct iwan_frag_slot slot[IWAN_FRAG_SLOTS];
};

enum {
    IWAN_FRAG_DROP  = -1,   /* malformed / no slot: drop the datagram */
    IWAN_FRAG_MORE  = 0,    /* stored, waiting for the rest */
    IWAN_FRAG_DONE  = 1,     /* complete: *out / *outlen are valid until the
                             * next call on the same pool */
};

void iwan_frag_pool_reset(struct iwan_frag_pool *p);
void iwan_frag_expire(struct iwan_frag_pool *p, uint64_t now_ms);

/* Feed one fragment (pkt points at the fragment header, len is the datagram
 * length after the 8-byte iwan header). Groups are matched on
 * (sid, tok, id) -- the official client matches on id alone, but a shared
 * server must not let two sessions collide. */
int iwan_frag_in(struct iwan_frag_pool *p, uint16_t sid, uint32_t tok,
                 const uint8_t *pkt, size_t len, uint64_t now_ms,
                 const uint8_t **out, size_t *outlen);

/* Split one inner packet into up to 2 datagrams of at most `mtu` payload
 * bytes each (8-byte iwan header excluded). The caller builds the outer
 * header; this fills `frag` (16 bytes) + data at `dst` and returns the number
 * of bytes to send after the outer header, or 0 when `pkt` is too large to
 * fit into two fragments (the caller must then drop). `off` selects which of
 * the two fragments to emit (0 or 1); `*last` reports whether that was the
 * final one so the caller knows when to stop. */
size_t iwan_frag_emit(const uint8_t *pkt, size_t len, size_t mtu, uint32_t id,
                      unsigned frag_idx, uint8_t *dst, size_t dstcap,
                      bool *last);

#endif
