/* wintun_pin.c — SHA-256 pin verification (Windows only; see .h) */
#include "crypto.h"   /* -> common.h -> winsock2 before windows.h */
#include "wintun_pin.h"

/* R37 WG6 #3: pin comparison, moved out of the _WIN32 body so the host
 * test TU can drive the real code. Constant-time-ish: no early exit, the
 * result is a single OR-accumulated difference. A non-hex pin digit yields
 * the out-of-range value 0x100 instead of the old sscanf()-failure "0", so
 * a malformed pin can never match a real digest byte (fail-closed) — the
 * old code made every non-hex nibble compare equal to a 0x0 hash nibble.
 * static inline: unused on non-Windows builds without -Wunused-function. */
static inline int pin_hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static inline bool pin_matches(const char *want, const uint8_t hash[32])
{
    if (!want || strlen(want) != 64)
        return false;   /* no/unset/odd-length pin: never a match */
    unsigned diff = 0;
    for (int i = 0; i < 32; i++) {
        int hi = pin_hexval(want[i * 2]);
        int lo = pin_hexval(want[i * 2 + 1]);
        unsigned a = (hi < 0 || lo < 0) ? 0x100u : (unsigned)(hi * 16 + lo);
        diff |= a ^ hash[i];
    }
    return diff == 0;
}

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

    /* constant-time-ish compare against the pin; malformed pins fail
     * closed (see pin_matches) */
    return pin_matches(want, hash);
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

/* ------------------------------------------------------------------ */
/* M3: secure loading of the (already verified) wintun.dll            */
/*                                                                   */
/* wintun.dll itself is loaded by absolute path (exe dir / System32)  */
/* in tun_win.c, so the module never comes from CWD/PATH. But its own */
/* import dependencies would still resolve through the standard DLL   */
/* search order — which includes the current directory and PATH —     */
/* unless the loader is told to restrict them. A hostile same-named   */
/* dependency DLL dropped into the CWD would otherwise be loaded into */
/* this process at the same privilege as the pinned, Authenticode-    */
/* verified module (audit M3 / PIN-F2).                               */
/*                                                                   */
/* Win7 floor: the LOAD_LIBRARY_SEARCH_* flags for LoadLibraryExW     */
/* need Win8+, or Win7 with KB2533623 (the same update that adds      */
/* AddDllDirectory/SetDefaultDllDirectories to kernel32). Probe at    */
/* runtime so plain Win7/XP still work; there we fall back to         */
/* SetDllDirectoryW(L"") around a plain LoadLibraryW, which removes   */
/* the current directory from the DLL search order for the duration   */
/* of the load (CWD vector closed; PATH — an env value the same user  */
/* already controls — remains, documented trade-off).                 */
/* ------------------------------------------------------------------ */

/* These loader flags are not defined by the MinGW headers this project
 * builds with at _WIN32_WINNT=0x0601 (they come from the Win8 SDK). The
 * numeric values are a stable public ABI; define them locally so the file
 * compiles on the old toolchain too. */
#ifndef LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
#define LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR 0x00000100
#endif
#ifndef LOAD_LIBRARY_SEARCH_APPLICATION_DIR
#define LOAD_LIBRARY_SEARCH_APPLICATION_DIR 0x00000200
#endif
#ifndef LOAD_LIBRARY_SEARCH_USER_DIRS
#define LOAD_LIBRARY_SEARCH_USER_DIRS 0x00000400
#endif
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif

/* Dependency search is limited to: the directory of the module being
 * loaded (DLL_LOAD_DIR → where wintun.dll lives), System32, the
 * application directory and any AddDllDirectory-registered dirs. CWD and
 * PATH are deliberately NOT in this set. */
#define IWAN_WINTUN_LOAD_FLAGS                                         \
    (LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32 | \
     LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_USER_DIRS)

/* Runtime capability probe, cached (wintun is loaded once at startup).
 * Presence of AddDllDirectory / SetDefaultDllDirectories means the
 * KB2533623 loader update that enables LOAD_LIBRARY_SEARCH_* is present,
 * so LoadLibraryExW with those flags is usable. */
static int wintun_search_flags_supported(void)
{
    static int ok = -1;   /* -1 unknown, 0 no, 1 yes */
    if (ok < 0) {
        HMODULE k = GetModuleHandleW(L"kernel32.dll");
        ok = (k != NULL &&
              (GetProcAddress(k, "AddDllDirectory") != NULL ||
               GetProcAddress(k, "SetDefaultDllDirectories") != NULL))
             ? 1 : 0;
    }
    return ok;
}

HMODULE wintun_load_secure(const wchar_t *path)
{
    /* Preferred path: per-call LoadLibraryExW with loader flags — CWD and
     * PATH are excluded from the target's dependency resolution. */
    if (wintun_search_flags_supported())
        return LoadLibraryExW(path, NULL, IWAN_WINTUN_LOAD_FLAGS);

    /* Legacy path (Win7 without KB2533623 / XP): temporarily drop the
     * current directory from the DLL search order, load, then restore the
     * standard order (SetDllDirectoryW(NULL)). Marks M3 as mitigated for
     * the CWD vector even on systems too old for the loader flags. */
    SetDllDirectoryW(L"");
    HMODULE h = LoadLibraryW(path);
    SetDllDirectoryW(NULL);
    return h;
}

#endif /* _WIN32 */
