#include "crypto.h"

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* 64-bit word usable on uint8_t storage without strict-aliasing UB */
typedef uint64_t u64_may_alias __attribute__((may_alias));

void md5(const void *data, size_t len, uint8_t out[16])
{
    unsigned int n = 0;
    EVP_Digest(data, len, out, &n, EVP_md5(), NULL);
}

void sha256(const void *data, size_t len, uint8_t out[32])
{
    unsigned int n = 0;
    EVP_Digest(data, len, out, &n, EVP_sha256(), NULL);
}

void hmac_sha256(const uint8_t *key, size_t klen,
                 const uint8_t *msg, size_t mlen, uint8_t out[32])
{
    unsigned int n = 0;
    HMAC(EVP_sha256(), key, (int)klen, msg, mlen, out, &n);
}

void encrypt_password(const char *plain, const char *username, uint8_t out[16])
{
    size_t ulen = strlen(username);
    uint8_t *keymat = malloc(2 + ulen);
    keymat[0] = 'm';
    keymat[1] = 'w';
    memcpy(keymat + 2, username, ulen);
    uint8_t key[16];
    md5(keymat, 2 + ulen, key);
    free(keymat);

    uint8_t pt[16];
    memset(pt, 0, sizeof(pt));
    size_t plen = strlen(plain);
    if (plen > sizeof(pt))
        plen = sizeof(pt);
    memcpy(pt, plain, plen);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int outl = 0;
    int finl = 0;
    EVP_EncryptUpdate(ctx, out, &outl, pt, (int)sizeof(pt));
    EVP_EncryptFinal_ex(ctx, out + outl, &finl);
    EVP_CIPHER_CTX_free(ctx);
}

void session_key(const char *username, const char *password, uint8_t out[16])
{
    size_t ulen = strlen(username);
    size_t plen = strlen(password);
    uint8_t *mat = malloc(ulen + plen);
    memcpy(mat, username, ulen);
    memcpy(mat + ulen, password, plen);
    md5(mat, ulen + plen, out);
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

static const char HEX_DIGITS[] = "0123456789abcdef";

void hex_encode(const uint8_t *bytes, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = HEX_DIGITS[bytes[i] >> 4];
        out[2 * i + 1] = HEX_DIGITS[bytes[i] & 0x0F];
    }
    out[2 * n] = '\0';
}

void buf_put_hex(buf_t *out, const uint8_t *bytes, size_t n)
{
    buf_ensure(out, 2 * n);
    for (size_t i = 0; i < n; i++) {
        out->data[out->len++] = HEX_DIGITS[bytes[i] >> 4];
        out->data[out->len++] = HEX_DIGITS[bytes[i] & 0x0F];
    }
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
    char *tmp = malloc(n + 1);
    memcpy(tmp, s, n + 1);
    for (size_t i = 0; i < n; i++) {
        if (tmp[i] == '-')
            tmp[i] = '+';
        else if (tmp[i] == '_')
            tmp[i] = '/';
    }
    uint8_t *out = b64_decode_raw(tmp, n, out_len);
    free(tmp);
    if (out)
        return out;
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
