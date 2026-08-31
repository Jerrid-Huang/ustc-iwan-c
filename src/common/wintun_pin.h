/* wintun_pin.h — SHA-256 pin for the bundled wintun.dll (Windows only)
 *
 * Both the loader (tun_win.c) and the auto-fetcher (wintun_fetch.c)
 * must only accept the exact official wintun build we ship. Generic
 * Authenticode alone trusts ANY signer the OS trusts; pinning the
 * release hash closes that gap. bump deliberately with the driver. */
#ifndef IWAN_WINTUN_PIN_H
#define IWAN_WINTUN_PIN_H

#ifdef _WIN32

#include <windows.h> /* wchar_t */
#include <stdbool.h>
#include <stdint.h>

/* Official wintun.dll 0.14.1 SHA-256, per target architecture. */
#if defined(__x86_64__) || defined(_M_X64)
#define IWAN_WINTUN_SHA256 \
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
#elif defined(__i386__) || defined(_M_IX86)
#define IWAN_WINTUN_SHA256 \
    "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931"
#elif defined(__aarch64__) || defined(_M_ARM64)
#define IWAN_WINTUN_SHA256 \
    "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80"
#else
#define IWAN_WINTUN_SHA256 NULL
#endif

/* returns true when the file's SHA-256 matches the pinned build.
 * When this architecture has no pin compiled in, returns true (pin is
 * vacuous) so an unsupported host keeps the legacy Authenticode-only
 * behaviour. */
bool wintun_pin_ok(const wchar_t *path);
bool wintun_pin_ok_a(const char *path);

#endif /* _WIN32 */

#endif /* IWAN_WINTUN_PIN_H */
