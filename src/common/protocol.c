#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "protocol.h"

void pkt_hdr(uint8_t typ, uint8_t enc, uint16_t sid, uint32_t tok, uint8_t out[8])
{
    out[0] = typ;
    out[1] = enc;
    out[2] = (uint8_t)(sid >> 8);
    out[3] = (uint8_t)sid;
    out[4] = (uint8_t)(tok >> 24);
    out[5] = (uint8_t)(tok >> 16);
    out[6] = (uint8_t)(tok >> 8);
    out[7] = (uint8_t)tok;
}

void pkt_sig(const uint8_t h8[8], uint8_t out[16])
{
    uint8_t x[10];
    memcpy(x, h8, 8);
    memcpy(x + 8, IWAN_MW, 2);
    md5(x, sizeof x, out);
}

void ctrl_hdr(buf_t *out, uint8_t typ, uint8_t enc, uint16_t sid, uint32_t tok)
{
    uint8_t h[8], s[16];
    pkt_hdr(typ, enc, sid, tok, h);
    pkt_sig(h, s);
    buf_put(out, h, sizeof h);
    buf_put(out, s, sizeof s);
}

void tlv_put(buf_t *out, uint8_t typ, const void *val, uint8_t vlen)
{
    buf_put_u8(out, typ);
    buf_put_u8(out, (uint8_t)(vlen + 2));
    if (vlen > 0)
        buf_put(out, val, vlen);
}

int parse_tlvs(const uint8_t *data, size_t len,
               bool (*cb)(uint8_t typ, const uint8_t *val, uint8_t vlen, void *ud),
               void *ud)
{
    size_t i = 0;
    while (i + 2 <= len) {
        uint8_t t = data[i];
        uint8_t l = data[i + 1];
        if (l < 2 || i + l > len)
            return -1; /* malformed length or frame truncated mid-TLV */
        if (cb && !cb(t, data + i + 2, l - 2, ud))
            break; /* callback requested stop: not an error */
        i += l;
    }
    /* trailing bytes (< a full TLV header) are truncation, not a clean end */
    return i == len ? 0 : -1;
}

bool verify_sig(const uint8_t *buf, size_t len)
{
    uint8_t s[16];
    if (len < 24)
        return false;
    pkt_sig(buf, s);
    return memcmp(s, buf + 8, 16) == 0;
}

void ip_to_string(const uint8_t b[4], char out[16])
{
    snprintf(out, 16, "%d.%d.%d.%d", b[0], b[1], b[2], b[3]);
}

bool s2ip4(const char *s, uint8_t out[4])
{
    for (int i = 0; i < 4; i++) {
        if (*s < '0' || *s > '9')
            return false;
        char *end;
        long v = strtol(s, &end, 10);
        if (end == s || v < 0 || v > 255)
            return false;
        out[i] = (uint8_t)v;
        if (i < 3) {
            if (*end != '.')
                return false;
            s = end + 1;
        } else if (*end != '\0') {
            return false;
        }
    }
    return true;
}

uint32_t ip4_u32(const uint8_t b[4])
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

void u32_ip4(uint32_t v, uint8_t out[4])
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}
