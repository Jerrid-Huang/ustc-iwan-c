/* SPDX-License-Identifier: GPL-2.0 */
/*
 * windev.h — Windows 内核数据面（WFP callout 驱动 iwan.sys）的设备层包装。
 *
 * 与 Linux 侧 kdp.c 里"设备那一半"同构：开设备、建会话、映射存活共享内存页、
 * 查统计、撤会话。区别只在通道形态：Linux 是 genetlink + /dev/iwan mmap，
 * Windows 是一组 IOCTL + 一页只读映射。
 *
 * 这一层刻意做得很薄、很哑：不碰套接字、不碰路由/地址（那些仍由用户态按平台
 * 各自处理），只把 ABI 翻成函数。因此它可以在没有驱动、甚至没有 Windows 的
 * 机器上编译检查（tests/windev_probe.c 在本机用 mingw + wine 跑过）。
 */
#ifndef IWAN_WINDEV_H
#define IWAN_WINDEV_H

#if defined(_WIN32)

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "iwan_win_abi.h"

/* 设备层错误分类：调用者据此决定"回退还是报错"
 *   WINDEV_ENODEV = 驱动没装/设备不存在 —— auto 应当回退到 TUN 面；
 *   WINDEV_EABI   = 设备在但 ABI 版本不符 —— 报错，不回退（回退会掩盖版本问题）；
 *   WINDEV_EACCES = 权限不足（需要管理员）；
 *   WINDEV_EIO    = 其它设备/IOCTL 错误。
 */
#define WINDEV_OK      0
#define WINDEV_ENODEV  (-1)
#define WINDEV_EACCES  (-2)
#define WINDEV_EABI    (-3)
#define WINDEV_EIO     (-4)

typedef struct windev windev_t;

/* 探测驱动是否在位：不建立会话、无副作用。err 可传 NULL。 */
bool windev_present(char *err, size_t errsz);

/* 打开设备。成功 0，失败为上面的负值码。 */
int windev_open(windev_t **out, char *err, size_t errsz);

/* 打开指定设备路径（path 为 NULL 时用 IWAN_WIN_USER_PATH）。Windows 上有两个
 * 内核数据面设备（WFP 的 iwan 与 NDIS 的 iwanmp），监督器按 --data-plane 选。 */
int windev_open_named(windev_t **out, const wchar_t *path, char *err,
		      size_t errsz);
void windev_close(windev_t *d);

/*
 * 建立会话。targets 会被拼在请求结构体之后（变长布局见 iwan_win_abi.h）。
 * info 回填会话信息（含生效 MTU、承载网卡、存活时间戳）。
 */
int windev_session_open(windev_t *d, const IWAN_WIN_SESSION_OPEN *req,
			const IWAN_WIN_TARGET *targets, size_t ntargets,
			IWAN_WIN_SESSION_INFO *info, char *err, size_t errsz);

/* 撤销会话（驱动会主动撤销共享内存映射并释放会话状态）。 */
int windev_session_close(windev_t *d, char *err, size_t errsz);

/* 查会话信息与统计（info 里的 stats 是快照，可能落后一个报文）。 */
int windev_session_get(windev_t *d, IWAN_WIN_SESSION_INFO *info,
		       char *err, size_t errsz);

/*
 * 映射只读共享内存页并返回指针（同一会话重复调用返回同一地址）。
 * 页面布局与 Linux 的 /dev/iwan 那一页完全相同，所以判活代码两边共用。
 */
int windev_shm_map(windev_t *d, const IWAN_WIN_SHM **out,
		   char *err, size_t errsz);

/* 读一次时间戳（0 = 从未收到 / 已断开，与 Linux 同语义）。 */
static inline uint64_t windev_shm_last_rx_ms(const IWAN_WIN_SHM *shm)
{
	return shm != NULL ? (uint64_t)shm->last_rx_ms : 0;
}

/* 驱动自报的版本串（诊断用；buf 建议 >= 64 字节）。 */
int windev_version(windev_t *d, char *buf, size_t bufsz);

#endif /* _WIN32 */
#endif /* IWAN_WINDEV_H */
