#ifndef IWAN_CRYPTO_H
#define IWAN_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"

/* Install the never-NULL libcrypto allocator (CRYPTO_set_mem_functions) and
 * then force libcrypto initialisation on the calling thread.
 *
 * This MUST be the first libcrypto call in the process: the setter only
 * works before the library initialises itself (it returns 0 afterwards, and
 * that is treated as fatal). Without it, one failed internal allocation
 * leaves libcrypto's pthread_once state finished-but-incomplete, so
 * initialisation never returns and the process blocks forever in futex()
 * with no output — exactly the R38 symptom. 9fef151's pre-warm did NOT fix
 * that: the hang happens *inside* the pre-warm, so the oom_abort() after it
 * is never reached. With the wrapper installed libcrypto cannot observe an
 * allocation failure at all, and a genuine OOM turns into the project's
 * visible allocation fatal. Returns 0 on success, -1 if libcrypto could not
 * be initialised; callers are expected to treat -1 as fatal (oom_abort()).
 * Call it only on paths that really use libcrypto: pure-CLI paths (--help,
 * version, argument errors) must stay libcrypto-free. */
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
