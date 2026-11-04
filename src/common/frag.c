#include "frag.h"

#include <string.h>

/* All fragment-header fields are host order on the wire (the official client
 * memcpy()s the two u32 words straight in/out), so these helpers are
 * little-endian byte shuffles rather than protocol big-endian ones. */
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void frag_hdr_put(uint8_t out[IWAN_FRAG_HDR_LEN], const struct iwan_frag_hdr *h)
{
    uint32_t w = (h->eop ? 1u : 0u) | (h->fromin ? 2u : 0u) |
                 (((uint32_t)h->fragoff & 0x1fffu) << 2) |
                 (((uint32_t)h->fraglen & 0x7ffu) << 15);
    wr32(out, h->id);
    wr32(out + 4, w);
}

bool frag_hdr_get(const uint8_t *buf, size_t len, struct iwan_frag_hdr *h)
{
    uint32_t w;

    if (len < IWAN_FRAG_HDR_LEN)
        return false;
    w = rd32(buf + 4);
    h->id = rd32(buf);
    h->eop = (w & 1u) != 0;
    h->fromin = (w & 2u) != 0;
    h->fragoff = (uint16_t)((w >> 2) & 0x1fffu);
    h->fraglen = (uint16_t)((w >> 15) & 0x7ffu);
    /* the datagram must carry exactly the declared payload; the official
     * client enforces `len == fraglen + 16` and so do we */
    if (h->fraglen == 0)
        return false;
    if ((size_t)h->fraglen + IWAN_FRAG_HDR_LEN != len)
        return false;
    if ((size_t)h->fragoff + h->fraglen > IWAN_FRAG_BUF_MAX)
        return false;
    return true;
}

void iwan_frag_pool_reset(struct iwan_frag_pool *p)
{
    memset(p, 0, sizeof *p);
}

void iwan_frag_expire(struct iwan_frag_pool *p, uint64_t now_ms)
{
    int i;

    for (i = 0; i < IWAN_FRAG_SLOTS; i++) {
        struct iwan_frag_slot *s = &p->slot[i];
        if (!s->used)
            continue;
        /* unsigned wrap of now - last is intentional: a slot is only
         * expired when at least IWAN_FRAG_TIMEOUT_MS has elapsed */
        if (now_ms - s->last_ms >= IWAN_FRAG_TIMEOUT_MS)
            s->used = false;
    }
}

/* Insert [off, off+len) into the merged interval list. Returns false when the
 * list is full or the fragment would need a 9th disjoint interval: both mean
 * the peer is fragmenting pathologically and the group is dropped. */
static bool seg_add(struct iwan_frag_slot *s, uint16_t off, uint16_t len)
{
    int i, j;

    if (s->nseg >= (int)(sizeof s->seg / sizeof s->seg[0]))
        return false;
    for (i = 0; i < s->nseg; i++) {
        if (s->seg[i].off > off)
            break;
    }
    for (j = s->nseg; j > i; j--)
        s->seg[j] = s->seg[j - 1];
    s->seg[i].off = off;
    s->seg[i].len = len;
    s->nseg++;

    /* merge forward: adjacent or overlapping intervals coalesce */
    for (i = 0; i + 1 < s->nseg;) {
        unsigned end = (unsigned)s->seg[i].off + s->seg[i].len;
        unsigned nend = (unsigned)s->seg[i + 1].off + s->seg[i + 1].len;
        if ((unsigned)s->seg[i + 1].off <= end) {
            s->seg[i].len = (uint16_t)((nend > end ? nend : end) -
                                       s->seg[i].off);
            for (j = i + 1; j + 1 < s->nseg; j++)
                s->seg[j] = s->seg[j + 1];
            s->nseg--;
        } else {
            i++;
        }
    }
    return true;
}

int iwan_frag_in(struct iwan_frag_pool *p, uint16_t sid, uint32_t tok,
                 const uint8_t *pkt, size_t len, uint64_t now_ms,
                 const uint8_t **out, size_t *outlen)
{
    struct iwan_frag_hdr h;
    struct iwan_frag_slot *s = NULL;
    int i, free_idx = -1;

    if (!frag_hdr_get(pkt, len, &h))
        return IWAN_FRAG_DROP;
    /* id 0 marks an empty slot in the official client and is never sent */
    if (h.id == 0)
        return IWAN_FRAG_DROP;

    iwan_frag_expire(p, now_ms);

    for (i = 0; i < IWAN_FRAG_SLOTS; i++) {
        struct iwan_frag_slot *c = &p->slot[i];
        if (!c->used) {
            if (free_idx < 0)
                free_idx = i;
            continue;
        }
        if (c->id == h.id && c->sid == sid && c->tok == tok) {
            s = c;
            break;
        }
    }
    if (s == NULL) {
        if (free_idx < 0)
            return IWAN_FRAG_DROP;   /* pool full: never grow unbounded */
        s = &p->slot[free_idx];
        s->used = true;
        s->sid = sid;
        s->tok = tok;
        s->id = h.id;
        s->total_known = false;
        s->total = 0;
        s->nseg = 0;
    }
    s->last_ms = now_ms;

    memcpy(s->buf + h.fragoff, pkt + IWAN_FRAG_HDR_LEN, h.fraglen);
    if (!seg_add(s, h.fragoff, h.fraglen)) {
        s->used = false;
        return IWAN_FRAG_DROP;
    }

    if (h.eop) {
        size_t end = (size_t)h.fragoff + h.fraglen;
        if (s->total_known && s->total != end) {
            s->used = false;   /* conflicting end offsets: corrupt group */
            return IWAN_FRAG_DROP;
        }
        s->total = end;
        s->total_known = true;
    }

    if (s->total_known && s->nseg == 1 && s->seg[0].off == 0 &&
        s->seg[0].len == s->total) {
        *out = s->buf;
        *outlen = s->total;
        s->used = false;
        return IWAN_FRAG_DONE;
    }
    /* coverage beyond the declared end means the peer lied about eop */
    if (s->total_known && s->nseg >= 1) {
        unsigned last = (unsigned)s->seg[s->nseg - 1].off +
                        s->seg[s->nseg - 1].len;
        if (last > s->total) {
            s->used = false;
            return IWAN_FRAG_DROP;
        }
    }
    return IWAN_FRAG_MORE;
}

size_t iwan_frag_emit(const uint8_t *pkt, size_t len, size_t mtu,
                      uint32_t id, unsigned frag_idx, uint8_t *dst,
                      size_t dstcap, bool *last)
{
    struct iwan_frag_hdr h;
    size_t chunk, off;

    *last = false;
    if (len == 0 || mtu == 0 || mtu > IWAN_FRAG_LEN_MAX)
        return 0;
    if (len <= mtu) {
        /* fits in one datagram: a single fragment with eop set */
        if (frag_idx != 0)
            return 0;
        off = 0;
        chunk = len;
        h.eop = true;
    } else {
        /* two fragments at most, exactly like the official client */
        if (len > 2 * mtu || frag_idx > 1)
            return 0;
        off = (size_t)frag_idx * mtu;
        chunk = frag_idx == 0 ? mtu : len - mtu;
        h.eop = frag_idx == 1;
    }
    if (dstcap < IWAN_FRAG_HDR_LEN + chunk)
        return 0;
    h.id = id;
    h.fromin = false;
    h.fragoff = (uint16_t)off;
    h.fraglen = (uint16_t)chunk;
    frag_hdr_put(dst, &h);
    memcpy(dst + IWAN_FRAG_HDR_LEN, pkt + off, chunk);
    *last = h.eop;
    return IWAN_FRAG_HDR_LEN + chunk;
}
