#include "sr.h"

#include <openssl/evp.h>
#include <string.h>

/* big-endian field helpers: the SR header and its link list are the only
 * part of the Panabit extension surface that stays network byte order */
static uint32_t rd_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void wr_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/*
 * The official client's hash, ported from ipe_jhash.h. It looks like Jenkins
 * lookup3 but is not: the initial state is a = b = 0x9e3779b9 with c =
 * initval, the 12-byte block loop accumulates k[0..3] into a, k[4..7] into b
 * and k[8..11] into c before the standard subtract/xor mix, and the length is
 * folded into c before the tail bytes are added. The SR key depends on the
 * exact output, so this must not be "cleaned up".
 */
uint32_t iwan_jhash(const void *key, size_t len, uint32_t initval)
{
    const uint8_t *k = key;
    uint32_t a = 0x9e3779b9u, b = 0x9e3779b9u, c = initval;
    uint32_t length = (uint32_t)len;

    while (len > 11) {
        a += (uint32_t)k[0] | ((uint32_t)k[1] << 8) |
             ((uint32_t)k[2] << 16) | ((uint32_t)k[3] << 24);
        b += (uint32_t)k[4] | ((uint32_t)k[5] << 8) |
             ((uint32_t)k[6] << 16) | ((uint32_t)k[7] << 24);
        c += (uint32_t)k[8] | ((uint32_t)k[9] << 8) |
             ((uint32_t)k[10] << 16) | ((uint32_t)k[11] << 24);
        a -= b;
        a -= c;
        a ^= c >> 13;
        b -= c;
        b -= a;
        b ^= a << 8;
        c -= a;
        c -= b;
        c ^= b >> 13;
        a -= b;
        a -= c;
        a ^= c >> 12;
        b -= c;
        b -= a;
        b ^= a << 16;
        c -= a;
        c -= b;
        c ^= b >> 5;
        a -= b;
        a -= c;
        a ^= c >> 3;
        b -= c;
        b -= a;
        b ^= a << 10;
        c -= a;
        c -= b;
        c ^= b >> 15;
        k += 12;
        len -= 12;
    }

    c += length;
    switch (len) {
    case 11:
        c += (uint32_t)k[10] << 24;
        /* fall through */
    case 10:
        c += (uint32_t)k[9] << 16;
        /* fall through */
    case 9:
        c += (uint32_t)k[8] << 8;
        /* fall through */
    case 8:
        b += (uint32_t)k[7] << 24;
        /* fall through */
    case 7:
        b += (uint32_t)k[6] << 16;
        /* fall through */
    case 6:
        b += (uint32_t)k[5] << 8;
        /* fall through */
    case 5:
        b += (uint32_t)k[4];
        /* fall through */
    case 4:
        a += (uint32_t)k[3] << 24;
        /* fall through */
    case 3:
        a += (uint32_t)k[2] << 16;
        /* fall through */
    case 2:
        a += (uint32_t)k[1] << 8;
        /* fall through */
    case 1:
        a += (uint32_t)k[0];
        break;
    default:
        break;
    }
    a -= b;
    a -= c;
    a ^= c >> 13;
    b -= c;
    b -= a;
    b ^= a << 8;
    c -= a;
    c -= b;
    c ^= b >> 13;
    a -= b;
    a -= c;
    a ^= c >> 12;
    b -= c;
    b -= a;
    b ^= a << 16;
    c -= a;
    c -= b;
    c ^= b >> 5;
    a -= b;
    a -= c;
    a ^= c >> 3;
    b -= c;
    b -= a;
    b ^= a << 10;
    c -= a;
    c -= b;
    c ^= b >> 15;
    return c;
}

size_t iwan_sr_hdr_len(const struct iwan_sr_hdr *h)
{
    return 4 + (size_t)h->linkcnt * 4;
}

bool iwan_sr_parse(const uint8_t *buf, size_t len, struct iwan_sr_hdr *out,
                   size_t *hdrlen)
{
    size_t i, need;

    if (len < 4)
        return false;
    out->type = buf[0];
    out->nextid = buf[1];
    out->linkcnt = buf[2];
    out->algo = buf[3] & 0x07;
    out->padlen = (uint8_t)(buf[3] >> 3);
    /* the official client trusts linkcnt and computes srhlen from it, which
     * lets a hostile linkcnt walk off the datagram; a server must bound it */
    if (out->linkcnt > IWAN_SR_MAX_LINKS)
        return false;
    need = 4 + (size_t)out->linkcnt * 4;
    if (len < need)
        return false;
    for (i = 0; i < out->linkcnt; i++)
        out->links[i] = rd_be32(buf + 4 + i * 4);
    *hdrlen = need;
    return true;
}

size_t iwan_sr_build(uint8_t *out, size_t cap, const struct iwan_sr_hdr *h)
{
    size_t need, i;

    if (h->linkcnt > IWAN_SR_MAX_LINKS || h->padlen > 31 || h->algo > 7)
        return 0;
    need = iwan_sr_hdr_len(h);
    if (cap < need)
        return 0;
    out[0] = h->type;
    out[1] = h->nextid;
    out[2] = h->linkcnt;
    out[3] = (uint8_t)((h->algo & 0x07) | (uint8_t)(h->padlen << 3));
    for (i = 0; i < h->linkcnt; i++)
        wr_be32(out + 4 + i * 4, h->links[i]);
    return need;
}

size_t iwan_sr_key(const char *password, const uint32_t *links, size_t nlinks,
                   unsigned algo, uint8_t key[32])
{
    uint8_t buf[32], fwd[IWAN_SR_MAX_LINKS * 4], rev[IWAN_SR_MAX_LINKS * 4];
    size_t n, len, i;
    uint32_t hash = 0, h;

    if (nlinks > IWAN_SR_MAX_LINKS)
        nlinks = IWAN_SR_MAX_LINKS;
    if (nlinks > 0) {
        for (i = 0; i < nlinks; i++) {
            wr_be32(fwd + i * 4, links[i]);
            wr_be32(rev + (nlinks - 1 - i) * 4, links[i]);
        }
        hash = iwan_jhash(fwd, nlinks * 4, 0) +
               iwan_jhash(rev, nlinks * 4, 0);
    }

    n = password != NULL ? strlen(password) : 0;
    if (n > sizeof buf)
        n = sizeof buf;
    memset(buf, 0, sizeof buf);
    if (n > 0)
        memcpy(buf, password, n);

    /* pad to 32 bytes with the hash bytes, 4 at a time then 1 at a time */
    len = n;
    h = hash;
    while (len + 4 <= sizeof buf) {
        buf[len] = (uint8_t)h;
        buf[len + 1] = (uint8_t)(h >> 8);
        buf[len + 2] = (uint8_t)(h >> 16);
        buf[len + 3] = (uint8_t)(h >> 24);
        len += 4;
    }
    while (len < sizeof buf) {
        buf[len++] = (uint8_t)h;
        h >>= 8;
    }

    len = algo == 1 ? 16 : 32;
    memcpy(key, buf, len);
    return len;
}

static bool aes_ecb(uint8_t *buf, size_t len, const uint8_t *key, unsigned bits,
                    bool encrypt)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    int outl = 0, fin = 0;
    bool ok = false;

    if (len == 0 || len % 16 != 0)
        return false;
    cipher = bits == 128 ? EVP_aes_128_ecb() : EVP_aes_256_ecb();
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return false;
    if ((encrypt ? EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL)
                 : EVP_DecryptInit_ex(ctx, cipher, NULL, key, NULL)) != 1)
        goto out;
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
        goto out;
    if ((encrypt ? EVP_EncryptUpdate(ctx, buf, &outl, buf, (int)len)
                 : EVP_DecryptUpdate(ctx, buf, &outl, buf, (int)len)) != 1)
        goto out;
    if ((encrypt ? EVP_EncryptFinal_ex(ctx, buf + outl, &fin)
                 : EVP_DecryptFinal_ex(ctx, buf + outl, &fin)) != 1)
        goto out;
    ok = (size_t)(outl + fin) == len;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool iwan_sr_crypt(uint8_t *buf, size_t len, const uint8_t *key, unsigned bits,
                   bool encrypt)
{
    /* the official client steps by 32 bytes in AES-256 mode and only
     * transforms the first 16 of each step; that cannot round-trip its own
     * ciphertext, so this implementation encrypts/decrypts every block and
     * treats mode != 1 as plain AES-256 (see docs/sdwan-protocol.md section 8.4) */
    return aes_ecb(buf, len, key, bits, encrypt);
}
