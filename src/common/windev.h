/* SPDX-License-Identifier: GPL-2.0 */
/*
 * windev.h -- device-layer wrapper for the Windows kernel data plane (WFP callout driver iwan.sys).
 *
 * Isomorphic to the "device half" of kdp.c on the Linux side: open the device, create the session, map the liveness shared-memory page,
 * query stats, and tear down the session. Only the channel form differs: Linux uses genetlink + /dev/iwan mmap,
 * Windows uses a set of IOCTLs + one read-only mapping page.
 *
 * This layer is deliberately thin and dumb: it touches no sockets and no routes/addresses (those are still handled by userspace per platform
 * separately); it only turns the ABI into functions. Therefore it can be compile-checked on a machine without the driver, or even without Windows
 * (tests/windev_probe.c has been run locally with mingw + wine).
 */
#ifndef IWAN_WINDEV_H
#define IWAN_WINDEV_H

#if defined(_WIN32)

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "iwan_win_abi.h"

/* Device-layer error classification: the caller uses it to decide "fall back or report an error"
 *   WINDEV_ENODEV = driver not installed / device absent -- auto should fall back to the TUN path;
 *   WINDEV_EABI   = device present but ABI version mismatch -- report an error, do not fall back (falling back would hide the version problem);
 *   WINDEV_EACCES = insufficient privileges (administrator required);
 *   WINDEV_EIO    = other device/IOCTL errors.
 */
#define WINDEV_OK      0
#define WINDEV_ENODEV  (-1)
#define WINDEV_EACCES  (-2)
#define WINDEV_EABI    (-3)
#define WINDEV_EIO     (-4)

typedef struct windev windev_t;

/* Probe whether the driver is present: creates no session, no side effects. err may be NULL. */
bool windev_present(char *err, size_t errsz);

/* Open the device. 0 on success; on failure, one of the negative codes above. */
int windev_open(windev_t **out, char *err, size_t errsz);

/* Open the given device path (IWAN_WIN_USER_PATH when path is NULL). On Windows there are two
 * kernel data plane devices (iwan for WFP and iwanmp for NDIS); the supervisor selects with --data-plane. */
int windev_open_named(windev_t **out, const wchar_t *path, char *err,
		      size_t errsz);
void windev_close(windev_t *d);

/*
 * Create a session. targets are appended after the request structure (variable-length layout, see iwan_win_abi.h).
 * info is filled with session info (including effective MTU, carrier NIC, liveness timestamp).
 */
int windev_session_open(windev_t *d, const IWAN_WIN_SESSION_OPEN *req,
			const IWAN_WIN_TARGET *targets, size_t ntargets,
			IWAN_WIN_SESSION_INFO *info, char *err, size_t errsz);

/* Tear down the session (the driver actively unmaps the shared memory and releases session state). */
int windev_session_close(windev_t *d, char *err, size_t errsz);

/* Query session info and stats (the stats in info is a snapshot and may lag one packet). */
int windev_session_get(windev_t *d, IWAN_WIN_SESSION_INFO *info,
		       char *err, size_t errsz);

/*
 * Map the read-only shared-memory page and return a pointer (repeated calls on the same session return the same address).
 * The page layout is exactly the same as the /dev/iwan page on Linux, so the liveness-check code is shared by both sides.
 */
int windev_shm_map(windev_t *d, const IWAN_WIN_SHM **out,
		   char *err, size_t errsz);

/* Read the timestamp once (0 = never received / disconnected; same semantics as Linux). */
static inline uint64_t windev_shm_last_rx_ms(const IWAN_WIN_SHM *shm)
{
	return shm != NULL ? (uint64_t)shm->last_rx_ms : 0;
}

/* Driver-reported version string (diagnostic use; buf should be >= 64 bytes). */
int windev_version(windev_t *d, char *buf, size_t bufsz);

#endif /* _WIN32 */
#endif /* IWAN_WINDEV_H */
