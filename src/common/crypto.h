#ifndef IWAN_CRYPTO_H
#define IWAN_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"

/* Pre-warm libcrypto on the calling (main) thread, at process start.
 *
 * libcrypto initialises itself lazily inside the first EVP_Digest(); if that
 * internal allocation fails, the library's once/lock state is left broken and
 * the process blocks forever in futex() with no output at all. Calling this
 * early keeps the initialisation on a controlled path where the failure is
 * reported (and turned into the project's visible OOM fatal) instead of an
 * undiagnosable hang. Returns 0 on success, -1 if libcrypto could not be
 * initialised; callers are expected to treat -1 as fatal (oom_abort()). */
int crypto_init(void);

void md5(const void *data, size_t len, uint8_t out[16]);
void sha256(const void *data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t klen,
                 const uint8_t *msg, size_t mlen, uint8_t out[32]);

/* AES-128-ECB(md5("mw"+username))[zero-padded password].
   Returns 0 on success, -1 on failure. out is ALWAYS zeroed on failure
   (including the OOM path), so a caller that skips the return-code check
   can never leak uninitialized stack bytes (M-2). */
int encrypt_password(const char *plain, const char *username, uint8_t out[16]);
/* md5(username + password) */
void session_key(const char *username, const char *password, uint8_t out[16]);

void xor_crypt(uint8_t *data, size_t len, const uint8_t *key, size_t klen);

/* constant-time equality: timing-safe byte compare of n bytes (callers
 * must reject length mismatches before calling). Returns nonzero when
 * the buffers are equal. */
int ct_eq(const void *a, const void *b, size_t n);
/* best-effort scrub of secrets (volatile store loop), immune to
 * optimizer elision; wipe() is the shared replacement for the per-module
 * wipes. */
void wipe(void *p, size_t n);

/* hex encode (lowercase) into out (>= 2*n+1), NUL-terminated */
void hex_encode(const uint8_t *bytes, size_t n, char *out);

/* hex decode (no 0x prefix) into out (outcap bytes max). Returns the
 * number of bytes written, or -1 on malformed input (odd length,
 * non-hex digit, or out too small). */
int hex_decode(const char *hex, size_t hexlen, uint8_t *out, size_t outcap);

/* base64url decode (accepts padded/unpadded, '-'/'_' and standard). */
uint8_t *b64url_decode(const char *s, size_t *out_len);
/* base64url encode, no padding. Caller frees. */
char *b64url_no_pad(const uint8_t *data, size_t len);

#endif
