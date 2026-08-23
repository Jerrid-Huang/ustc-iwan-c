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

#endif
