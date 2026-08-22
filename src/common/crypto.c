#include "crypto.h"
#include "protocol.h"
#include "util.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* 64-bit word usable on uint8_t storage without strict-aliasing UB */
typedef uint64_t u64_may_alias __attribute__((may_alias));

/* shared EVP one-shot digest with fatal-on-failure semantics (all hashing
 * here is fail-closed: a failed digest would silently corrupt auth, so
 * aborting is correct). `name` only feeds the error message. Callers
 * whose output buffer is smaller than EVP_MAX_MD_SIZE go through a
 * local full-size staging buffer: gcc -Wstringop-overflow (a warning on
 * this cross-build configuration) cannot prove the EVP call writes only
 * the algorithm's digest length. */
static void digest(const EVP_MD *md, const char *name, const void *data,
                   size_t len, uint8_t out[EVP_MAX_MD_SIZE])
{
    unsigned int n = 0;
    if (EVP_Digest(data, len, out, &n, md, NULL) != 1) {
        log_err("%s: EVP_Digest failed", name);
        abort();
    }
}

void md5(const void *data, size_t len, uint8_t out[16])
{
    uint8_t tmp[EVP_MAX_MD_SIZE];
    digest(EVP_md5(), "md5", data, len, tmp);
    memcpy(out, tmp, 16);
}

void sha256(const void *data, size_t len, uint8_t out[32])
{
    uint8_t tmp[EVP_MAX_MD_SIZE];
    digest(EVP_sha256(), "sha256", data, len, tmp);
    memcpy(out, tmp, 32);
}

void hmac_sha256(const uint8_t *key, size_t klen,
                 const uint8_t *msg, size_t mlen, uint8_t out[32])
{
    unsigned int n = 0;
    if (HMAC(EVP_sha256(), key, (int)klen, msg, mlen, out, &n) == NULL) {
        log_err("hmac_sha256: HMAC failed");
        abort();
    }
}

int encrypt_password(const char *plain, const char *username, uint8_t out[16])
{
    size_t ulen = strlen(username);
    uint8_t *keymat = malloc(2 + ulen);
    uint8_t key[16];
    uint8_t pt[16];
    EVP_CIPHER_CTX *ctx = NULL;
    int ok = -1;
    int outl = 0;
    int finl = 0;

    if (!keymat)
        return -1;
    memcpy(keymat, IWAN_MW, 2);
    memcpy(keymat + 2, username, ulen);
    md5(keymat, 2 + ulen, key);
    /* scrub the derivation input: OPENSSL_cleanse is the one scrubber
     * the compiler cannot optimize away */
    OPENSSL_cleanse(keymat, 2 + ulen);
    free(keymat);

    /* Passwords longer than the 16-byte block are silently truncated to
     * the first 16 bytes: zero-padded truncation, matching the reference
     * implementation. Client and server share this same function, so the
     * truncation is consistent on both ends. */
    memset(pt, 0, sizeof(pt));
    size_t plen = strlen(plain);
    if (plen > sizeof(pt))
        plen = sizeof(pt);
    memcpy(pt, plain, plen);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto done;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) != 1 ||
        EVP_EncryptUpdate(ctx, out, &outl, pt, (int)sizeof(pt)) != 1 ||
        EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1)
        goto done;
    ok = 0;

done:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    /* key is derived from the username and pt holds the zero-padded
     * plaintext password: both must not survive the return */
    OPENSSL_cleanse(key, sizeof key);
    OPENSSL_cleanse(pt, sizeof pt);
    if (ok != 0)
        memset(out, 0, 16); /* deterministic output on failure */
    return ok;
}

void session_key(const char *username, const char *password, uint8_t out[16])
{
    size_t ulen = strlen(username);
    size_t plen = strlen(password);
    uint8_t *mat = malloc(ulen + plen);
    if (!mat) {
        /* fail-closed like every other crypto path here: a silently
         * all-zero XOR key would disable the tunnel's confidentiality
         * without any error surfacing */
        oom_abort();
    }
    memcpy(mat, username, ulen);
    memcpy(mat + ulen, password, plen);
    md5(mat, ulen + plen, out);
    /* mat concatenates the plaintext password: scrub before free */
    OPENSSL_cleanse(mat, ulen + plen);
    free(mat);
}

void xor_crypt(uint8_t *data, size_t len, const uint8_t *key, size_t klen)
{
    size_t i;

    if (klen == 0)
        return;
    if (klen == 8 && len >= 8) {
        /* 8-byte session key: XOR in 64-bit words, tail byte-wise */
        uint64_t k64;
        size_t n8 = len & ~(size_t)7;
        memcpy(&k64, key, 8);
        if (((uintptr_t)data & 7) == 0) {
            /* aligned: direct 64-bit loads/stores (may_alias: the buffer
             * is uint8_t storage, e.g. the TUN batch or recv area) */
            u64_may_alias *p = (u64_may_alias *)data;
            for (i = 0; i < n8; i += 8)
                p[i / 8] ^= k64;
        } else {
            /* unaligned (e.g. +8 into a buffer): keep memcpy moves */
            for (i = 0; i < n8; i += 8) {
                uint64_t v;
                memcpy(&v, data + i, 8);
                v ^= k64;
                memcpy(data + i, &v, 8);
            }
        }
        for (; i < len; i++)
            data[i] ^= key[i & 7];
        return;
    }
    for (i = 0; i < len; i++)
        data[i] ^= key[i % klen];
}

/* constant-time equality: both buffers are exactly n bytes (the caller
 * rejects length mismatches first), so the loop hides the comparison
 * shape from timing */
int ct_eq(const void *a, const void *b, size_t n)
{
    const uint8_t *pa = a;
    const uint8_t *pb = b;
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= pa[i] ^ pb[i];
    return d == 0;
}

/* best-effort scrub of secrets, immune to optimizer elision (volatile
 * store loop, same strength as the per-module wipes it replaces) */
void wipe(void *p, size_t n)
{
    volatile unsigned char *v = p;
    while (n--)
        *v++ = 0;
}

static const char HEX_DIGITS[] = "0123456789abcdef";

void hex_encode(const uint8_t *bytes, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = HEX_DIGITS[bytes[i] >> 4];
        out[2 * i + 1] = HEX_DIGITS[bytes[i] & 0x0F];
    }
    out[2 * n] = '\0';
}

/* hex digit parsing: shared static inline hex_nibble from util.h */
int hex_decode(const char *hex, size_t hexlen, uint8_t *out, size_t outcap)
{
    size_t n;
    if (hexlen % 2 != 0)
        return -1;
    n = hexlen / 2;
    if (n > outcap)
        return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble((unsigned char)hex[2 * i]);
        int lo = hex_nibble((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)n;
}

static int b64_char_val(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+' || c == '-')
        return 62;
    if (c == '/' || c == '_')
        return 63;
    return -1;
}

static uint8_t *b64_decode_raw(const char *s, size_t n, size_t *out_len)
{
    while (n > 0 && s[n - 1] == '=')
        n--;
    if (n == 0)
        return NULL;
    size_t rem = n % 4;
    if (rem == 1)
        return NULL;
    size_t full = n / 4;
    size_t nbytes = full * 3;
    if (rem == 2)
        nbytes += 1;
    else if (rem == 3)
        nbytes += 2;
    uint8_t *out = malloc(nbytes + 1);
    if (!out)
        oom_abort();
    size_t o = 0;
    for (size_t i = 0; i < full; i++) {
        int a = b64_char_val((unsigned char)s[i * 4]);
        int b = b64_char_val((unsigned char)s[i * 4 + 1]);
        int c = b64_char_val((unsigned char)s[i * 4 + 2]);
        int d = b64_char_val((unsigned char)s[i * 4 + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) {
            free(out);
            return NULL;
        }
        out[o++] = (uint8_t)((a << 2) | (b >> 4));
        out[o++] = (uint8_t)(((b & 0x0F) << 4) | (c >> 2));
        out[o++] = (uint8_t)(((c & 0x03) << 6) | d);
    }
    if (rem >= 2) {
        size_t i = full * 4;
        int a = b64_char_val((unsigned char)s[i]);
        int b = b64_char_val((unsigned char)s[i + 1]);
        if (a < 0 || b < 0) {
            free(out);
            return NULL;
        }
        out[o++] = (uint8_t)((a << 2) | (b >> 4));
        if (rem == 3) {
            int c = b64_char_val((unsigned char)s[i + 2]);
            if (c < 0) {
                free(out);
                return NULL;
            }
            out[o++] = (uint8_t)(((b & 0x0F) << 4) | (c >> 2));
        }
    }
    *out_len = o;
    return out;
}

uint8_t *b64url_decode(const char *s, size_t *out_len)
{
    *out_len = 0;
    size_t n = strlen(s);
    if (n == 0)
        return NULL;
    /* b64_char_val already accepts '-'/'_' as aliases of '+'/'/', so the
     * old tmp translation was a no-op and its fallback could never
     * succeed where the first pass failed: decode once, directly */
    return b64_decode_raw(s, n, out_len);
}

char *b64url_no_pad(const uint8_t *data, size_t len)
{
    size_t cap = ((len + 2) / 3) * 4 + 1;
    char *out = malloc(cap);
    int n = EVP_EncodeBlock((unsigned char *)out, data, (int)len);
    if (n < 0) {
        free(out);
        return NULL;
    }
    for (int i = 0; i < n; i++) {
        if (out[i] == '+')
            out[i] = '-';
        else if (out[i] == '/')
            out[i] = '_';
    }
    while (n > 0 && out[n - 1] == '=')
        n--;
    out[n] = '\0';
    return out;
}
