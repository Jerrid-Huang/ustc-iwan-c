/* wintun_pin.c — SHA-256 pin verification (Windows only; see .h) */
#include "crypto.h"   /* -> common.h -> winsock2 before windows.h */
#include "wintun_pin.h"

#ifdef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

bool wintun_pin_ok(const wchar_t *path)
{
    const char *want = IWAN_WINTUN_SHA256;

    if (!want)
        return true;   /* no pin for this arch: keep legacy behaviour */

    HANDLE f = CreateFileW(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return false;

    /* wintun.dll is a few hundred KB — read it in one shot */
    uint8_t *buf = (uint8_t *)malloc(512 * 1024);
    if (!buf) {
        CloseHandle(f);
        return false;
    }
    DWORD got = 0, total = 0;
    while (ReadFile(f, buf + total, 512 * 1024 - total, &got, NULL) &&
           got > 0) {
        total += got;
        if (total >= 512 * 1024)
            break;
    }
    CloseHandle(f);

    uint8_t hash[32];
    sha256(buf, total, hash);
    free(buf);

    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", hash[i]);

    /* constant-time-ish compare against the pin */
    if (strlen(want) != 64)
        return false;
    unsigned diff = 0;
    for (int i = 0; i < 32; i++) {
        unsigned a, b;
        if (sscanf(want + i * 2, "%02x", &a) != 1)
            a = 0;
        b = hash[i];
        diff |= a ^ b;
    }
    return diff == 0;
}

/* narrow (ANSI) wrapper for wintun_fetch.c, which works in char paths */
bool wintun_pin_ok_a(const char *path)
{
    int n = MultiByteToWideChar(CP_ACP, 0, path, -1, NULL, 0);
    if (n <= 0)
        return false;
    wchar_t *w = (wchar_t *)malloc((size_t)n * sizeof *w);
    if (!w)
        return false;
    MultiByteToWideChar(CP_ACP, 0, path, -1, w, n);
    bool ok = wintun_pin_ok(w);
    free(w);
    return ok;
}

#endif /* _WIN32 */
