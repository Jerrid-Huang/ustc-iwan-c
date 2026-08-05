#ifndef IWAN_GCM_H
#define IWAN_GCM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* AES-256-GCM. ct_tag = ciphertext || 16-byte tag. Returns false on bad tag. */
bool gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                 const uint8_t *ct_tag, size_t ct_tag_len,
                 const uint8_t *aad, size_t aad_len,
                 uint8_t *plain_out, size_t *plain_len);

/* decrypt the iWAN passWord field. Returns malloc'd UTF-8 password, or NULL. */
char *decrypt_password(const char *encrypted_b64, const char *app_secret,
                       const char *domain, const char *username);

#endif
