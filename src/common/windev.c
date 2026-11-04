/* SPDX-License-Identifier: GPL-2.0 */
/*
 * windev.c -- see windev.h. Thin wrapper: turns IOCTLs into functions, makes no policy judgement.
 *
 * Corresponds item by item to the device part of kdp.c on the Linux side:
 *   open(/dev/iwan)              -> CreateFileW(\\.\iwan)
 *   genl_iwan_session_up(...)    -> IOCTL_IWAN_SESSION_OPEN
 *   genl_iwan_session_down(...)  -> IOCTL_IWAN_SESSION_CLOSE
 *   genl GET_STATS               -> IOCTL_IWAN_SESSION_GET
 *   mmap(/dev/iwan)              -> IOCTL_IWAN_SHM_QUERY (driver supplies a read-only mapping address)
 */
#if defined(_WIN32)

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windev.h"

struct windev {
	HANDLE h;
	/* Device path used when opening (each kernel plane has its own device name); only for error messages */
	const wchar_t *path;
};

/* ---- error formatting ------------------------------------------------- */

static void set_err(char *err, size_t errsz, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (err != NULL && errsz > 0)
		vsnprintf(err, errsz, fmt, ap);
	va_end(ap);
}

static int classify_dword(DWORD e, const wchar_t *path, const char *what,
			  char *err, size_t errsz)
{
	switch (e) {
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
	case ERROR_NO_SUCH_DEVICE:
		set_err(err, errsz,
			"%s: kernel data plane device %ls not found (driver not installed or not loaded; "
			"once installed, use --data-plane kernel (WFP plane iwan.sys) or "
			"--data-plane kernel-mp (NDIS plane iwanmp.sys), "
			"or use --data-plane tun first)",
			what, path);
		return WINDEV_ENODEV;
	case ERROR_ACCESS_DENIED:
		set_err(err, errsz, "%s: opening %ls denied (administrator privileges required, "
				    "consistent with root required on the Linux side)", what, path);
		return WINDEV_EACCES;
	default:
		set_err(err, errsz, "%s: Win32 error %lu", what, (unsigned long)e);
		return WINDEV_EIO;
	}
}

static int ioctl_raw(windev_t *d, DWORD code, void *in, DWORD in_len,
		     void *out, DWORD out_len, DWORD *ret, char *err, size_t errsz)
{
	DWORD got = 0;

	if (!DeviceIoControl(d->h, code, in, in_len, out, out_len, &got, NULL)) {
		DWORD e = GetLastError();

		if (e == ERROR_INVALID_PARAMETER || e == ERROR_BAD_LENGTH) {
			set_err(err, errsz, "IOCTL 0x%08lx arguments rejected by the driver (%lu): "
					    "most likely an ABI version mismatch or an invalid target set",
				(unsigned long)code, (unsigned long)e);
			return WINDEV_EABI;
		}
		return classify_dword(e, d->path, "IOCTL", err, errsz);
	}
	if (ret != NULL)
		*ret = got;
	return WINDEV_OK;
}

/* ---- device open/close ------------------------------------------------ */

bool windev_present(char *err, size_t errsz)
{
	windev_t *d = NULL;
	int rc = windev_open(&d, err, errsz);

	if (rc == WINDEV_OK) {
		windev_close(d);
		return true;
	}
	return false;
}

int windev_open(windev_t **out, char *err, size_t errsz)
{
	return windev_open_named(out, IWAN_WIN_USER_PATH, err, errsz);
}

int windev_open_named(windev_t **out, const wchar_t *path, char *err,
		      size_t errsz)
{
	windev_t *d;

	if (path == NULL)
		path = IWAN_WIN_USER_PATH;
	*out = NULL;
	d = (windev_t *)calloc(1, sizeof(*d));
	if (d == NULL) {
		set_err(err, errsz, "out of memory");
		return WINDEV_EIO;
	}
	d->path = path;

	d->h = CreateFileW(path,
			   GENERIC_READ | GENERIC_WRITE,
			   FILE_SHARE_READ | FILE_SHARE_WRITE,
			   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (d->h == INVALID_HANDLE_VALUE) {
		int rc = classify_dword(GetLastError(), path, "open device", err,
					errsz);

		free(d);
		return rc;
	}

	*out = d;
	return WINDEV_OK;
}

void windev_close(windev_t *d)
{
	if (d == NULL)
		return;
	if (d->h != NULL && d->h != INVALID_HANDLE_VALUE)
		CloseHandle(d->h);
	free(d);
}

/* ---- session ---------------------------------------------------------- */

int windev_session_open(windev_t *d, const IWAN_WIN_SESSION_OPEN *req,
			const IWAN_WIN_TARGET *targets, size_t ntargets,
			IWAN_WIN_SESSION_INFO *info, char *err, size_t errsz)
{
	unsigned char *buf;
	size_t need, req_len;
	IWAN_WIN_SESSION_OPEN hdr;
	DWORD got = 0;
	int rc;

	if (ntargets > IWAN_WIN_MAX_TARGETS) {
		set_err(err, errsz, "too many entries in target set (%llu > %u)",
			(unsigned long long)ntargets,
			(unsigned)IWAN_WIN_MAX_TARGETS);
		return WINDEV_EIO;
	}

	req_len = sizeof(IWAN_WIN_SESSION_OPEN) + ntargets * sizeof(IWAN_WIN_TARGET);
	/* The reply is SESSION_INFO, longer than a request with only the structure header. Under METHOD_BUFFERED, input
	 * and output share one system buffer, so the output length must be sized for the reply: if the driver sees
	 * out_len < sizeof(SESSION_INFO), it immediately returns STATUS_BUFFER_TOO_SMALL, so opening a session with
	 * fewer than 3 targets (including 0 for "do not hijack routes") necessarily fails, and the reason reported back
	 * is "buffer too small", which looks entirely unrelated to the real cause. */
	need = req_len < sizeof(*info) ? sizeof(*info) : req_len;
	buf = (unsigned char *)calloc(1, need);
	if (buf == NULL) {
		set_err(err, errsz, "out of memory");
		return WINDEV_EIO;
	}

	/* Variable-length layout: structure + target set immediately after it */
	hdr = *req;
	hdr.abi_version = IWAN_WIN_ABI_VERSION;
	hdr.size = sizeof(IWAN_WIN_SESSION_OPEN);
	hdr.target_offset = ntargets > 0 ? (uint32_t)sizeof(IWAN_WIN_SESSION_OPEN) : 0;
	hdr.target_count = (uint32_t)ntargets;
	hdr.reserved0 = 0;
	memcpy(buf, &hdr, sizeof(hdr));
	if (ntargets > 0)
		memcpy(buf + sizeof(hdr), targets, ntargets * sizeof(IWAN_WIN_TARGET));

	if (!DeviceIoControl(d->h, IOCTL_IWAN_SESSION_OPEN, buf, (DWORD)req_len,
			     buf, (DWORD)need, &got, NULL)) {
		rc = classify_dword(GetLastError(), d->path, "create session", err,
				    errsz);
		free(buf);
		return rc;
	}
	if (got < sizeof(*info)) {
		free(buf);
		set_err(err, errsz, "driver reply too short (%lu < %llu)",
			(unsigned long)got, (unsigned long long)sizeof(*info));
		return WINDEV_EABI;
	}
	/* Under METHOD_BUFFERED, request and reply share the same system buffer: the driver first reads the request,
	 * then after creating the session writes SESSION_INFO over it, so it is used directly as the reply here. */
	memcpy(info, buf, sizeof(*info));
	free(buf);

	if (info->abi_version != IWAN_WIN_ABI_VERSION) {
		set_err(err, errsz,
			"driver ABI version %u does not match client %u: upgrade driver and client together",
			(unsigned)info->abi_version, (unsigned)IWAN_WIN_ABI_VERSION);
		return WINDEV_EABI;
	}
	return WINDEV_OK;
}

int windev_session_close(windev_t *d, char *err, size_t errsz)
{
	return ioctl_raw(d, IOCTL_IWAN_SESSION_CLOSE, NULL, 0, NULL, 0, NULL,
			 err, errsz);
}

int windev_session_get(windev_t *d, IWAN_WIN_SESSION_INFO *info,
		       char *err, size_t errsz)
{
	DWORD got = 0;
	int rc;

	memset(info, 0, sizeof(*info));
	rc = ioctl_raw(d, IOCTL_IWAN_SESSION_GET, NULL, 0,
		       info, (DWORD)sizeof(*info), &got, err, errsz);
	if (rc != WINDEV_OK)
		return rc;
	if (got < sizeof(*info)) {
		set_err(err, errsz, "session info reply too short (%lu < %llu)",
			(unsigned long)got, (unsigned long long)sizeof(*info));
		return WINDEV_EABI;
	}
	if (info->abi_version != IWAN_WIN_ABI_VERSION) {
		set_err(err, errsz,
			"driver ABI version %u does not match client %u: upgrade driver and client together",
			(unsigned)info->abi_version, (unsigned)IWAN_WIN_ABI_VERSION);
		return WINDEV_EABI;
	}
	return WINDEV_OK;
}

int windev_shm_map(windev_t *d, const IWAN_WIN_SHM **out, char *err, size_t errsz)
{
	IWAN_WIN_SESSION_INFO info;
	int rc;

	*out = NULL;
	rc = ioctl_raw(d, IOCTL_IWAN_SHM_QUERY, NULL, 0,
		       &info, (DWORD)sizeof(info), NULL, err, errsz);
	if (rc != WINDEV_OK)
		return rc;
	if (info.shm_user_va == 0) {
		set_err(err, errsz, "driver did not return a shared-memory mapping address");
		return WINDEV_EIO;
	}
	if (info.shm_section_size < sizeof(IWAN_WIN_SHM)) {
		set_err(err, errsz, "shared memory page too small (%llu < %llu)",
			(unsigned long long)info.shm_section_size,
			(unsigned long long)sizeof(IWAN_WIN_SHM));
		return WINDEV_EABI;
	}

	*out = (const IWAN_WIN_SHM *)(uintptr_t)info.shm_user_va;
	if ((*out)->version != IWAN_WIN_SHM_VERSION) {
		set_err(err, errsz,
			"shared memory layout version %u does not match client %u: upgrade driver and client together",
			(unsigned)(*out)->version, (unsigned)IWAN_WIN_SHM_VERSION);
		*out = NULL;
		return WINDEV_EABI;
	}
	return WINDEV_OK;
}

int windev_version(windev_t *d, char *buf, size_t bufsz)
{
	IWAN_WIN_SESSION_INFO info;
	int rc = windev_session_get(d, &info, buf, bufsz);

	if (rc != WINDEV_OK)
		return rc;
	snprintf(buf, bufsz, "iwan.sys abi=%u mtu=%u carrier=%u",
		 (unsigned)info.abi_version, (unsigned)info.effective_mtu,
		 (unsigned)info.carrier_index);
	return WINDEV_OK;
}

#endif /* _WIN32 */
