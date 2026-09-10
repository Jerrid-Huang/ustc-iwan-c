#ifndef IWAN_GCM_H
#define IWAN_GCM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN   16


/* decrypt the iWAN passWord field. Returns malloc'd UTF-8 password, or NULL. */
char *decrypt_password(const char *encrypted_b64, const char *app_secret,
                       const char *domain, const char *username);

/* AES-256-GCM decrypt. ct_tag holds ciphertext followed by the 16-byte tag;
 * on success plain_out receives `*plain_len` bytes and true is returned.
 * On failure false is returned (plain_out contents undefined). */
bool gcm_decrypt(const uint8_t key[32], const uint8_t nonce[GCM_NONCE_LEN],
                 const uint8_t *ct_tag, size_t ct_tag_len,
                 const uint8_t *aad, size_t aad_len,
                 uint8_t *plain_out, size_t *plain_len);

#endif
