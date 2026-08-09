#ifndef IWAN_CRYPTO_H
#define IWAN_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"

void md5(const void *data, size_t len, uint8_t out[16]);
void sha256(const void *data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t klen,
                 const uint8_t *msg, size_t mlen, uint8_t out[32]);

/* AES-128-ECB(md5("mw"+username))[zero-padded password].
   Returns 0 on success, -1 on failure (out zeroed). */
int encrypt_password(const char *plain, const char *username, uint8_t out[16]);
/* md5(username + password) */
void session_key(const char *username, const char *password, uint8_t out[16]);

void xor_crypt(uint8_t *data, size_t len, const uint8_t *key, size_t klen);

/* hex encode (lowercase) into out (>= 2*n+1), NUL-terminated */
void hex_encode(const uint8_t *bytes, size_t n, char *out);
void buf_put_hex(buf_t *out, const uint8_t *bytes, size_t n);

/* hex decode (no 0x prefix) into out (outcap bytes max). Returns the
 * number of bytes written, or -1 on malformed input (odd length,
 * non-hex digit, or out too small). */
int hex_decode(const char *hex, size_t hexlen, uint8_t *out, size_t outcap);

/* base64url decode (accepts padded/unpadded, '-'/'_' and standard). */
uint8_t *b64url_decode(const char *s, size_t *out_len);
/* base64url encode, no padding. Caller frees. */
char *b64url_no_pad(const uint8_t *data, size_t len);

#endif
