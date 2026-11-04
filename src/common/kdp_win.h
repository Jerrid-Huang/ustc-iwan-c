/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdp_win.h -- Windows kernel data plane supervisor (counterpart of kdp.c on Linux).
 *
 * Semantics align item by item with kdp.h; only the platform primitives differ:
 *   - the session is handed to the kernel: IOCTL_IWAN_SESSION_OPEN (on Linux it is genetlink SESSION_UP);
 *   - liveness criterion: last_rx_ms in the driver's read-only shared memory page (on Linux it is /dev/iwan mmap),
 *     with a field-by-field identical layout, so the criterion "zero = peer CLOSE, exceeding IWAN_RX_STALE_MS = silent link loss"
 *     is exactly the same on both sides;
 *   - keepalive is all in userspace: the PT_ECHO_REQ every 10s goes over the **client's own UDP
 *     socket** (same as Linux -- control frames do not enter the tunnel, the driver only swallows data frames),
 *     the failure budget and silent death detection are also all here;
 *   - addresses/routes are still configured by userspace: the inner IP is attached to the carrier adapter (KM-TEST loopback),
 *     and routes for proxied prefixes point at it -- reusing route.c's cross-platform implementation, the same set as the TUN plane.
 *
 * Return values match kdp_run / run_pump:
 *   0 = user stopped (Ctrl-C etc.), 1 = session lost (should reconnect), -1 = startup failed.
 * On -1, *ns_busy distinguishes: true = a live session already exists locally (the caller **must not** fall back to the TUN plane,
 * falling back would use the same account to kick that session out), false = driver unavailable (auto may fall back).
 */
#ifndef IWAN_KDP_WIN_H
#define IWAN_KDP_WIN_H

#if defined(_WIN32)

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"   /* slist_t */
#include "iwan_win_abi.h"   /* IWAN_WIN_USER_PATH_MP: device names of the two kernel planes */

/* Default carrier adapter name: the system's built-in KM-TEST loopback adapter, renamed to iWAN after installation
 * (see win-driver/README.md). */
#define IWAN_WIN_DEF_DEV "iWAN"

/* Alias and driver description of the NDIS plane (--data-plane kernel-mp) inner adapter. The alias is
 * the agreed connection name; the description is the DeviceDesc in iwanmp.inf, used to match the
 * system-chosen connection name ("Local Area Connection", possibly with a number after reinstall) against the alias. */
#define IWAN_WIN_DEF_DEV_MP "iwanmp"
#define IWAN_WIN_MP_ADAPTER_DESC "iWAN Tunnel Adapter"

/* Startup precheck before the handshake (**called before authenticate()**, same contract as
 * kdp_plane_precheck()): the driver is present, the ABI version matches, and no live session exists locally.
 * device_path selects the device (NULL = WFP plane \\.\iwan; see iwan_win_abi.h's
 * IWAN_WIN_USER_PATH_MP); both kernel planes share this one supervisor.
 * Returns true = may continue; false = the reason is written into err (Chinese, printable directly).
 * *busy = true means the failure is "a live session already exists locally": the caller must not fall back to the TUN plane. */
bool kdp_win_plane_precheck(const wchar_t *device_path, char *err, size_t errsz,
                            bool *busy);

/* See the file header. dev may be NULL (use IWAN_WIN_DEF_DEV); device_path may be NULL
 * (use the WFP plane device \\.\iwan). */
int kdp_win_run(int sockfd, const uint8_t xor_key[8], uint16_t sid, uint32_t tok,
                uint8_t enc, const char *server, const char *dev,
                const wchar_t *device_path,
                const slist_t *route_targets, const slist_t *route_targets6,
                const char *auth_tun_ip, uint16_t auth_mtu, bool *ns_busy);

#endif /* _WIN32 */
#endif /* IWAN_KDP_WIN_H */
