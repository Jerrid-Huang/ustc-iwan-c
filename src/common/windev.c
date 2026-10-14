/* SPDX-License-Identifier: GPL-2.0 */
/*
 * windev.c — 见 windev.h。薄封装：把 IOCTL 翻成函数，不做策略判断。
 *
 * 与 Linux 侧 kdp.c 的设备部分逐项对应：
 *   open(/dev/iwan)              -> CreateFileW(\\.\iwan)
 *   genl_iwan_session_up(...)    -> IOCTL_IWAN_SESSION_OPEN
 *   genl_iwan_session_down(...)  -> IOCTL_IWAN_SESSION_CLOSE
 *   genl GET_STATS               -> IOCTL_IWAN_SESSION_GET
 *   mmap(/dev/iwan)              -> IOCTL_IWAN_SHM_QUERY（驱动给只读映射地址）
 */
#if defined(_WIN32)

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windev.h"

struct windev {
	HANDLE h;
	/* 打开时用的设备路径（两个内核平面各有自己的设备名），只用于错误信息 */
	const wchar_t *path;
};

/* ---- 错误格式化 ------------------------------------------------------- */

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
			"%s：找不到内核数据面设备 %ls（驱动未安装或未加载；"
			"装好后用 --data-plane kernel（WFP 面 iwan.sys）或 "
			"--data-plane kernel-mp（NDIS 面 iwanmp.sys），"
			"或先用 --data-plane tun）",
			what, path);
		return WINDEV_ENODEV;
	case ERROR_ACCESS_DENIED:
		set_err(err, errsz, "%s：打开 %ls 被拒绝（需要管理员权限，"
				    "与 Linux 侧需要 root 一致）", what, path);
		return WINDEV_EACCES;
	default:
		set_err(err, errsz, "%s：Win32 错误 %lu", what, (unsigned long)e);
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
			set_err(err, errsz, "IOCTL 0x%08lx 参数被驱动拒绝（%lu）："
					    "多半是 ABI 版本不符或目标集合非法",
				(unsigned long)code, (unsigned long)e);
			return WINDEV_EABI;
		}
		return classify_dword(e, d->path, "IOCTL", err, errsz);
	}
	if (ret != NULL)
		*ret = got;
	return WINDEV_OK;
}

/* ---- 设备开关 --------------------------------------------------------- */

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
		set_err(err, errsz, "内存不足");
		return WINDEV_EIO;
	}
	d->path = path;

	d->h = CreateFileW(path,
			   GENERIC_READ | GENERIC_WRITE,
			   FILE_SHARE_READ | FILE_SHARE_WRITE,
			   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (d->h == INVALID_HANDLE_VALUE) {
		int rc = classify_dword(GetLastError(), path, "打开设备", err,
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

/* ---- 会话 ------------------------------------------------------------- */

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
		set_err(err, errsz, "目标集合条目过多（%zu > %u）",
			ntargets, (unsigned)IWAN_WIN_MAX_TARGETS);
		return WINDEV_EIO;
	}

	req_len = sizeof(IWAN_WIN_SESSION_OPEN) + ntargets * sizeof(IWAN_WIN_TARGET);
	/* 回复是 SESSION_INFO，比只有结构体头的请求长。METHOD_BUFFERED 下输入
	 * 输出共用一块系统缓冲，出参长度必须按回复算：驱动拿
	 * out_len < sizeof(SESSION_INFO) 直接判 STATUS_BUFFER_TOO_SMALL，所以
	 * 目标少于 3 个（含"不劫持路由"的 0 个）时建会话必然失败，而且报回来
	 * 的原因是"缓冲区太小"，与真实原因看着毫不相干。 */
	need = req_len < sizeof(*info) ? sizeof(*info) : req_len;
	buf = (unsigned char *)calloc(1, need);
	if (buf == NULL) {
		set_err(err, errsz, "内存不足");
		return WINDEV_EIO;
	}

	/* 变长布局：结构体 + 紧随其后的目标集合 */
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
		rc = classify_dword(GetLastError(), d->path, "建立会话", err,
				    errsz);
		free(buf);
		return rc;
	}
	if (got < sizeof(*info)) {
		free(buf);
		set_err(err, errsz, "驱动回复过短（%lu < %zu）", (unsigned long)got,
			sizeof(*info));
		return WINDEV_EABI;
	}
	/* METHOD_BUFFERED 下请求与回复共用同一块系统缓冲：驱动先按请求读、
	 * 建好会话后把 SESSION_INFO 覆盖写回，所以这里直接当回复取用。 */
	memcpy(info, buf, sizeof(*info));
	free(buf);

	if (info->abi_version != IWAN_WIN_ABI_VERSION) {
		set_err(err, errsz,
			"驱动 ABI 版本 %u 与客户端 %u 不符：请同步升级驱动与客户端",
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
		set_err(err, errsz, "会话信息回复过短（%lu < %zu）",
			(unsigned long)got, sizeof(*info));
		return WINDEV_EABI;
	}
	if (info->abi_version != IWAN_WIN_ABI_VERSION) {
		set_err(err, errsz,
			"驱动 ABI 版本 %u 与客户端 %u 不符：请同步升级驱动与客户端",
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
		set_err(err, errsz, "驱动没有返回共享内存映射地址");
		return WINDEV_EIO;
	}
	if (info.shm_section_size < sizeof(IWAN_WIN_SHM)) {
		set_err(err, errsz, "共享内存页过小（%llu < %zu）",
			(unsigned long long)info.shm_section_size,
			sizeof(IWAN_WIN_SHM));
		return WINDEV_EABI;
	}

	*out = (const IWAN_WIN_SHM *)(uintptr_t)info.shm_user_va;
	if ((*out)->version != IWAN_WIN_SHM_VERSION) {
		set_err(err, errsz,
			"共享内存布局版本 %u 与客户端 %u 不符：请同步升级驱动与客户端",
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
