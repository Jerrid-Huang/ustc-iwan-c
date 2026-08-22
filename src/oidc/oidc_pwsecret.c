#include "oidc_pwsecret.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h" /* hex_encode */
#include "oidc.h"
#include "util.h"   /* hex_nibble */
#include "common.h"  /* xstrdup */

#ifdef _WIN32
#include <dpapi.h>

/* "WDP1:" + DPAPI-bytes-as-hex. Entropy = the app secret so only this
 * build can unseal under the same user. */
char *oidc_wrap_password(const char *blob, const char *domain,
                         const char *user)
{
    DATA_BLOB in, out;
    char *hex, *res;
    size_t hl;

    (void)user;
    in.pbData = (BYTE *)(uintptr_t)blob;
    in.cbData = (DWORD)strlen(blob) + 1;
    out.pbData = NULL;
    out.cbData = 0;
    if (!CryptProtectData(&in, L"ustc-iwan-c-pwsecret", NULL, NULL, NULL,
                          CRYPTPROTECT_UI_FORBIDDEN, &out))
        return NULL;
    (void)domain;
    hl = (size_t)out.cbData * 2 + 1;
    hex = malloc(hl);
    if (!hex) {
        LocalFree(out.pbData);
        return NULL;
    }
    hex_encode(out.pbData, out.cbData, hex);
    LocalFree(out.pbData);
    res = malloc(strlen("WDP1:") + hl);
    if (!res) {
        free(hex);
        return NULL;
    }
    sprintf(res, "WDP1:%s", hex);
    free(hex);
    return res;
}

static int pw_hex_decode(const char *hex, size_t n, uint8_t *out, size_t cap)
{
    size_t i;
    if (n % 2 != 0 || cap < n / 2)
        return -1;
    for (i = 0; i < n / 2; i++) {
        int a = hex_nibble(hex[i * 2]);
        int b = hex_nibble(hex[i * 2 + 1]);
        if (a < 0 || b < 0)
            return -1;
        out[i] = (uint8_t)((a << 4) | b);
    }
    return (int)(n / 2);
}

static char *pw_hex_decode_wdp(const char *hex)
{
    size_t n = strlen(hex);
    size_t blen = n / 2;
    BYTE *raw = malloc(blen ? blen : 1);
    char *out;
    if (!raw)
        return NULL;
    if (pw_hex_decode(hex, n, raw, blen) < 0) {
        free(raw);
        return NULL;
    }
    DATA_BLOB in, outblob;
    in.pbData = raw;
    in.cbData = (DWORD)blen;
    outblob.pbData = NULL;
    outblob.cbData = 0;
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL,
                            CRYPTPROTECT_UI_FORBIDDEN, &outblob)) {
        free(raw);
        return NULL;
    }
    out = malloc(outblob.cbData + 1);
    if (out) {
        memcpy(out, outblob.pbData, outblob.cbData);
        out[outblob.cbData] = '\0';
    }
    LocalFree(outblob.pbData);
    free(raw);
    return out;
}

char *oidc_unwrap_password(const char *stored, const char *domain,
                           const char *user)
{
    (void)domain;
    (void)user;
    if (strncmp(stored, "WDP1:", 5) == 0)
        return pw_hex_decode_wdp(stored + 5);
    return xstrdup(stored);
}
#elif defined(__APPLE__)
#include <Security/Security.h>

/* "WKC1" marker: the real blob lives in the login Keychain under
 * service "ustc-iwan-c" / account "domain|user". */
static CFStringRef pw_acc(const char *domain, const char *user)
{
    char acc[512];
    snprintf(acc, sizeof acc, "%s|%s", domain ? domain : "",
             user ? user : "");
    return CFStringCreateWithCString(kCFAllocatorDefault, acc,
                                     kCFStringEncodingUTF8);
}

char *oidc_wrap_password(const char *blob, const char *domain,
                         const char *user)
{
    CFStringRef acc = pw_acc(domain, user);
    CFDataRef data = CFDataCreate(kCFAllocatorDefault,
                                  (const UInt8 *)blob,
                                  (CFIndex)strlen(blob) + 1);
    if (!data) {
        CFRelease(acc);
        return NULL;
    }
    const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount,
                           kSecValueData };
    const void *vals[] = { kSecClassGenericPassword,
                           CFSTR("ustc-iwan-c-pwsecret"), acc, data };
    CFDictionaryRef d = CFDictionaryCreate(
        kCFAllocatorDefault, keys, vals, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    SecItemDelete(d);   /* idempotent save */
    OSStatus st = SecItemAdd(d, NULL);
    CFRelease(d);
    CFRelease(data);
    CFRelease(acc);
    return st == errSecSuccess ? xstrdup("WKC1") : NULL;
}

char *oidc_unwrap_password(const char *stored, const char *domain,
                           const char *user)
{
    if (strncmp(stored, "WKC1", 4) != 0)
        return xstrdup(stored);
    CFStringRef acc = pw_acc(domain, user);
    const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount,
                           kSecReturnData, kSecMatchLimit };
    const void *vals[] = { kSecClassGenericPassword,
                           CFSTR("ustc-iwan-c-pwsecret"), acc,
                           kCFBooleanTrue, kSecMatchLimitOne };
    CFDictionaryRef d = CFDictionaryCreate(
        kCFAllocatorDefault, keys, vals, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching(d, &out);
    CFRelease(d);
    CFRelease(acc);
    if (st != errSecSuccess || !out)
        return NULL;
    CFDataRef data = (CFDataRef)out;
    const UInt8 *p = CFDataGetBytePtr(data);
    CFIndex n = CFDataGetLength(data);
    char *res = malloc((size_t)n + 1);
    if (res) {
        memcpy(res, p, (size_t)n);
        res[n] = '\0';
    }
    CFRelease(out);
    return res;
}
#else
/* No per-user OS protection available: keep the legacy app-secret blob
 * (obfuscation-level only; see oidc_pwsecret.h). */
char *oidc_wrap_password(const char *blob, const char *domain,
                         const char *user)
{
    (void)domain;
    (void)user;
    return xstrdup(blob);
}

char *oidc_unwrap_password(const char *stored, const char *domain,
                           const char *user)
{
    (void)domain;
    (void)user;
    return xstrdup(stored);
}
#endif
