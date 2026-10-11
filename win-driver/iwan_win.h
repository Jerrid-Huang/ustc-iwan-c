/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win.h — Windows 内核数据面的驱动内部头。
 *
 * 与 Linux 模块的对应关系（docs/win-wfp-data-plane.md）：
 *   struct iwan_session   ↔  IWAN_WIN_SESSION
 *   /dev/iwan 的那一页     ↔  IWAN_WIN_SESSION.shm（非分页池一页，只读映射给用户态）
 *   genetlink 会话属性     ↔  IOCTL_IWAN_SESSION_OPEN/CLOSE/GET 的缓冲
 *   nf_hook_ops + ndo_start_xmit  ↔  WFP callout（见 iwan_win_wfp.c）
 *
 * 硬约束（与 Linux 一致）：
 *   · 驱动里没有任何定时器、DPC、工作项、线程 —— 判活由用户态轮询共享内存页；
 *   · 驱动只写共享内存页里的时间戳与计数，用户态只读；
 *   · last_rx_ms 的时基是"自开机以来的单调毫秒"（对应 ktime_get_mono_fast_ns），
 *     0 表示从未收到或已断开。
 *
 * 并发模型（Windows 侧必须显式写清，Linux 那边靠 rtnl/netns 生命周期兜住）：
 *   · 控制面（本文件的 open/close/query）在 PASSIVE_LEVEL，用 ctrl_mutex 串行化，
 *     因此可以分配池内存、映射/解映射用户地址、等待；
 *   · 数据面（WFP classify）在 DISPATCH_LEVEL，先 ExAcquireRundownProtection，
 *     拿到保护后只读会话状态、只写共享内存页与统计计数器；
 *   · 控制面要改会话状态时先 ExWaitForRundownProtectionRelease 把数据面排空，
 *     改完再 ExReInitializeRundownProtection 放行 —— 这样数据面永远不会看到
 *     正在被替换的 targets 指针，也不会有 use-after-free。
 */
#ifndef IWAN_WIN_H
#define IWAN_WIN_H

#include <ntddk.h>
#include <wdm.h>
#include <wdmsec.h>		/* IoCreateDeviceSecure */
#include <ndis.h>		/* NdisGetDataBuffer 与 NET_BUFFER_* 宏 */
#include <fwpsk.h>		/* WFP 内核 API */
#include <fwpmk.h>		/* WFP 管理 API */

#include "iwan_win_abi.h"
#include "iwan_win_frame.h"	/* 线上格式、XOR、校验和、目标匹配（纯逻辑，可对拍） */

/* 池标签：'I','W','A','N' 的四种排列，便于 !poolused 归因 */
#define IWAN_TAG_SESS   'sneI'
#define IWAN_TAG_TARGET 'tgeI'
#define IWAN_TAG_PKT    'kpeI'
#define IWAN_TAG_SHM    'mheI'

/*
 * 非分页池分配：ExAllocatePool2 从 Win10 2004 起可用且默认清零，老目标回落到
 * ExAllocatePoolWithTag。两条路径都显式清零，调用者不必再管。
 */
#if defined(NTDDI_WIN10_VB) && (NTDDI_VERSION >= NTDDI_WIN10_VB)
#  define IWAN_ALLOC(size, tag) ExAllocatePool2(POOL_FLAG_NON_PAGED, (size), (tag))
#else
#  define IWAN_ALLOC(size, tag) ExAllocatePoolWithTag(NonPagedPool, (size), (tag))
#endif

#define IWAN_WIN_DRV_VERSION_STR L"iwan-win 0.1 (WFP callout, ABI 1)"


/* ---- 会话 ------------------------------------------------------------- */

typedef struct _IWAN_WIN_SESSION {
	volatile LONG		valid;		/* 所有字段就绪后才置 1 */

	/* 控制面参数（对应 IWAN_A_SID/TOK/ENC/KEY） */
	UINT16			sid;
	UINT32			tok;
	UINT8			enc;
	UINT8			key[8];

	/* 外层端点（地址/端口为网络序） */
	UINT32			outer_src;
	UINT32			outer_dst;
	UINT16			sport;
	UINT16			dport;
	UINT8			outer_src6[16];
	UINT8			outer_dst6[16];

	/* 绑定（对应 IWAN_A_OIF/IP/IP6/CARRIER） */
	UINT32			flags;
	UINT32			oif_index;
	UINT32			bind_ip;
	UINT8			bind_ip6[16];
	UINT32			carrier_index;	/* 只读回执：当前实际承载网卡 */
	UINT32			carrier_mtu;

	/* 内层 */
	UINT32			inner_ip;
	UINT8			inner_ip6[16];
	UINT32			inner_mtu;
	UINT32			effective_mtu;	/* 会话建立时按承载网卡 MTU 校验后的值 */

	/* 目标集合（最长前缀匹配） */
	UINT32			target_count;
	IWAN_WIN_TARGET		*targets;

	/* 存活状态：与共享内存页同一份存储（对应 IWAN_A_LAST_KEEPALIVE_MS）。
	 * shm 页由驱动独占写；用户态只读映射（见 iwan_win_shm_map_user）。 */
	IWAN_WIN_SHM		*shm;
	PMDL			shm_mdl;	/* NULL 表示当前没有用户态映射 */
	PVOID			shm_user_va;
	PEPROCESS		shm_owner;	/* 持引用的属主进程；映射只对它有效 */

	/* 统计（计数器名称/顺序对应 enum iwan_stats_attr） */
	IWAN_WIN_STATS		stats;
} IWAN_WIN_SESSION;

/* ---- 设备扩展 --------------------------------------------------------- */

typedef struct _IWAN_WIN_DEVICE_EXTENSION {
	IWAN_WIN_SESSION	sess;

	KMUTEX			ctrl_mutex;	/* 控制面串行化（PASSIVE_LEVEL） */
	EX_RUNDOWN_REF		rundown;	/* 数据面读者保护 */

	/* NBL 池：注入用（NdisAllocateNetBufferListPool 建，wfp_fini 释放；
	 * 释放前必须注销 callout 并排空在途注入） */
	NDIS_HANDLE		nbl_pool;
	volatile LONG		inject_outstanding;

	/* WFP：引擎句柄、callout id、注入句柄 */
	HANDLE			engine;
	UINT32			callout_id_out4;	/* FWPS_LAYER_OUTBOUND_IPPACKET_V4 */
	UINT32			callout_id_out6;	/* FWPS_LAYER_OUTBOUND_IPPACKET_V6 */
	UINT32			callout_id_in4;		/* FWPS_LAYER_INBOUND_IPPACKET_V4  */
	UINT32			callout_id_in6;		/* FWPS_LAYER_INBOUND_IPPACKET_V6  */
	HANDLE			inj_send4;
	HANDLE			inj_send6;
	HANDLE			inj_recv4;
	HANDLE			inj_recv6;
	BOOLEAN			wfp_ready;
} IWAN_WIN_DEVICE_EXTENSION;

#define IWAN_DEVEXT(devobj) \
	((IWAN_WIN_DEVICE_EXTENSION *)(devobj)->DeviceExtension)

/* ---- 单调毫秒（对应 iwan_now_ms） ------------------------------------- */

/*
 * KeQueryInterruptTime() 返回自开机以来的 100ns 中断时间，不受系统时间调整
 * 影响 —— 与 Linux 的 ktime_get_mono_fast_ns() 同一语义。驱动内不缓存，
 * 每次直接取，避免引入任何"定时"概念。
 */
static __inline UINT64 iwan_win_now_ms(VOID)
{
	return (UINT64)(KeQueryInterruptTime() / 10000ULL);
}

/* ---- 会话与控制面（iwan_win_session.c） ------------------------------- */

/* 控制面基础设施：初始化/拆除互斥量与 rundown 保护 */
VOID iwan_win_ctrl_init(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
VOID iwan_win_ctrl_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

NTSTATUS iwan_win_session_open(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			       _In_reads_bytes_(in_len) const IWAN_WIN_SESSION_OPEN *req,
			       _In_ ULONG in_len);
NTSTATUS iwan_win_session_close(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
NTSTATUS iwan_win_session_query_shm(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
				    _Out_ IWAN_WIN_SESSION_INFO *info);
VOID iwan_win_session_info(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			   _Out_ IWAN_WIN_SESSION_INFO *info);
VOID iwan_win_session_teardown(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* 外层是否走 v6：outer_dst6 非全零即按 v6 处理（与会话属性同一判据） */
BOOLEAN iwan_win_session_is_v6(_In_ const IWAN_WIN_SESSION *s);

/* 只在收到"过了外层过滤与凭据闸门"的帧时调用（数据面，DISPATCH_LEVEL）：
 * 写时间戳、置 UP、累加计数。要求调用者已持有 rundown 保护。 */
VOID iwan_win_session_mark_rx(_Inout_ IWAN_WIN_SESSION *s, _In_ UINT32 is_ctrl);
/* 对端 PT_CLOSE：时间戳归零 + peer_state 置已关闭（用户态据此判断开） */
VOID iwan_win_session_mark_close(_Inout_ IWAN_WIN_SESSION *s);

/* ---- WFP 数据面（iwan_win_wfp.c） ------------------------------------- */

NTSTATUS iwan_win_wfp_init(_In_ PDEVICE_OBJECT devobj,
			   _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
VOID iwan_win_wfp_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

#endif /* IWAN_WIN_H */
