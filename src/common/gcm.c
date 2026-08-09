#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "crypto.h"
#include "gcm.h"

bool gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                 const uint8_t *ct_tag, size_t ct_tag_len,
                 const uint8_t *aad, size_t aad_len,
                 uint8_t *plain_out, size_t *plain_len) {
    bool ok = false;
    int outl = 0, outl2 = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    size_t ct_len;

    if (ct_tag_len < 16)
        return false;
    ct_len = ct_tag_len - 16;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
        goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;
    if (aad_len > 0 && EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1)
        goto done;
    if (ct_len > 0 && EVP_DecryptUpdate(ctx, plain_out, &outl, ct_tag, (int)ct_len) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)(ct_tag + ct_len)) != 1)
        goto done;
    if (EVP_DecryptFinal_ex(ctx, outl > 0 ? plain_out + outl : plain_out, &outl2) != 1)
        goto done;
    *plain_len = (size_t)outl + (size_t)outl2;
    ok = true;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

char *decrypt_password(const char *encrypted_b64, const char *app_secret,
                       const char *domain, const char *username) {
    size_t aad_len = strlen(domain) + 1 + strlen(username);
    size_t label_len = strlen(app_secret) + 1 + aad_len;
    char *aad, *label;
    uint8_t key[32];
    uint8_t *data = NULL, *plain = NULL;
    size_t data_len = 0, plain_len = 0;
    char *result = NULL;

    aad = malloc(aad_len + 1);
    if (!aad)
        return NULL;
    snprintf(aad, aad_len + 1, "%s|%s", domain, username);

    label = malloc(label_len + 1);
    if (!label) {
        free(aad);
        return NULL;
    }
    snprintf(label, label_len + 1, "%s|%s", app_secret, aad);

    sha256(label, label_len, key);
    free(label);

    data = b64url_decode(encrypted_b64, &data_len);
    if (!data || data_len < 28)
        goto out;

    plain = malloc(data_len - 12);
    if (!plain)
        goto out;

    if (!gcm_decrypt(key, data, data + 12, data_len - 12,
                     (const uint8_t *)aad, aad_len, plain, &plain_len))
        goto out;

    result = malloc(plain_len + 1);
    if (!result)
        goto out;
    memcpy(result, plain, plain_len);
    result[plain_len] = '\0';

out:
    /* wipe the derived key and the decrypted plaintext buffer before
     * releasing them (OPENSSL_cleanse is the one scrubber the compiler
     * cannot optimize away) */
    OPENSSL_cleanse(key, sizeof key);
    if (plain)
        OPENSSL_cleanse(plain, data_len - 12);
    free(plain);
    free(data);
    free(aad);
    return result;
}
