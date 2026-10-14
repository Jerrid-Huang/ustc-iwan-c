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
 *   · 会话建立之前数据面根本不存在：callout 与过滤器由 IOCTL_OPEN 装上、
 *     IOCTL_CLOSE 摘掉（iwan_win_wfp_start/stop）。所以 sc start 只验证
 *     “驱动能加载、设备能打开”，接管流量是后面单独一步 —— 与 Linux 侧
 *     “路由指向 iwan0 才碰得到出向报文”同一形式。
 */
#ifndef IWAN_WIN_H
#define IWAN_WIN_H

/* ntifs.h 而不是 ntddk.h：KeStackAttachProcess / KAPC_STATE 只在那里声明
 * （解除用户态共享内存映射时必须切到属主进程的地址空间）。ntifs.h 是
 * ntddk/wdm 的超集，WDK 文档也要求"需要这些 API 时用它替代 ntddk.h"。 */
#include <ntifs.h>
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
 * ExAllocatePoolWithTag —— 那条路径**不清零**（旧注释写"两条路径都显式清零"，
 * 与实现不符）。两条路径语义不一致，所以调用者必须自己初始化"失败路径上会被
 * 读到的字段"，例如 IWAN_INJECT_CTX.mdl，不能依赖清零。
 * 本工程未显式指定 NTDDI_VERSION（vcxproj 只给 TargetVersion=Windows10），
 * 实际走哪条分支取决于 WDK 头里的默认值，两种都可能。
 */
#if defined(NTDDI_WIN10_VB) && (NTDDI_VERSION >= NTDDI_WIN10_VB)
#  define IWAN_ALLOC(size, tag) ExAllocatePool2(POOL_FLAG_NON_PAGED, (size), (tag))
#else
#  define IWAN_ALLOC(size, tag) ExAllocatePoolWithTag(NonPagedPool, (size), (tag))
#endif

#define IWAN_WIN_DRV_VERSION_STR L"iwan-win 0.1 (WFP callout, ABI 2)"
#define IWAN_WIN_DRV_VERSION_STR_MP L"iwan-win 0.1 (miniport + protocol, ABI 2)"


/* ---- 会话 ------------------------------------------------------------- */

typedef struct _IWAN_WIN_SESSION {
	volatile LONG		valid;		/* 所有字段就绪后才置 1 */

	/* 控制面参数（对应 IWAN_A_SID/TOK/ENC/KEY） */
	UINT16			sid;
	UINT32			tok;
	UINT8			enc;
	UINT8			key[8];

	/* 外层端点（地址/端口为网络序） */
	UINT32			outer_src;	/* v4 外层地址，大端整数 */
	UINT32			outer_dst;
	UINT32			outer_hop;	/* 外层下一跳（控制面查路由后传入；
						 * 0 = 未提供，按对端在链路上处理） */
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

/* ---- 第二个平面：小型端口 + 协议驱动 ---------------------------------- */

/*
 * 与 WFP 平面的关系：会话控制面（IWAN_WIN_SESSION 与 iwan_win_session.c）与
 * 线上逻辑（iwan_win_frame.c）完全共用，换掉的只是"报文怎么进出"：
 *
 *   WFP 平面（iwan.sys）              本平面（iwanmp.sys，--data-plane ndis）
 *   出向 OUTBOUND_IPPACKET 处拦截      小型端口收到协议栈交下来的内层数据报
 *   出向 FwpsInjectNetworkSendAsync    协议驱动把外层 UDP 直接交给承载网卡
 *   入向 INBOUND_TRANSPORT 处拦截      协议驱动从承载网卡收外层 UDP
 *   入向 FwpsInjectNetworkReceiveAsync 小型端口把内层数据报指示向上
 *
 * 三处实质差别：① 收发都在自己该在的位置，不需要注入 API，因而没有"在途
 * NBL 占着非分页池、必须限流"的问题，发送是同步的（完成回调只负责归还）；
 * ② 入向不再重新入栈，而是像 Linux 的 netif_rx 那样直接指示向上，少一次
 * 全载荷拷贝；③ 出向只处理"路由指向本适配器"的报文（内层选路由路由表决定），
 * 不再需要目标集合匹配。
 *
 * 承载选择沿用 Linux 侧定下的语义：显式绑定就绑那一张，未绑定则按外层目的
 * 地址查 FIB 决定；选定后这条会话的收发都只走那一张网卡。
 */
struct _IWAN_MP_BINDING;

/* 出向 NBL 的 context 区大小：够放 IWAN_MP_TX_CTX（缓冲地址 + MDL 两个
 * 指针）。池按这个尺寸建，两侧（协议边发送、小型端口指示）共用同一个数，
 * IWAN_MP_TX_CTX 的实际大小在 iwan_win_proto.c 里用 C_ASSERT 对齐。 */
#define IWAN_MP_NBL_CTX_SIZE	16u

/* 承载侧的链路层常量（小型端口那侧是 NdisMediumIP，裸 IP，没有以太头） */
#define IWAN_MP_ETH_HDR_LEN	14u
#define IWAN_MP_ETH_TYPE_IP4	0x0800u
#define IWAN_MP_ETH_TYPE_ARP	0x0806u
#define IWAN_MP_ETH_TYPE_IP6	0x86DDu

typedef struct _IWAN_MP_PLANE {
	/* 小型端口侧 */
	NDIS_HANDLE		mp_handle;	/* MiniportAdapterHandle */
	/* NBL 池：两侧共用。出向要挂一个 IWAN_MP_TX_CTX（缓冲与 MDL 的
	 * 地址，完成回调据此归还），所以建池时就把 context 区留够；
	 * 入向指示用的 NBL 不关心里程碑里的内容，白拿这 16 字节。 */
	NDIS_HANDLE		nbl_pool;
	volatile LONG		mp_running;	/* Pause/Restart 闸门（1=可收可发） */

	/* 协议边。绑定表本身是驱动级的（见 iwan_win_proto.c 的 g_bindings），
	 * 不放在这里：协议驱动在 DriverEntry 就注册，比小型端口（PnP）先出现、
	 * 后消失，把表挂在设备扩展上会有生命周期错配。 */
	NDIS_HANDLE		proto_handle;	/* NdisRegisterProtocolDriver 句柄 */
	KSPIN_LOCK		lock;		/* 保护 active/下一跳/MAC/时间戳 */
	struct _IWAN_MP_BINDING	*active;	/* 会话选定的承载；NULL=未选定 */
	UINT32			active_ifindex;
	UINT32			next_hop_be;	/* 外层下一跳（v4，网络序） */
	UINT8			local_mac[6];	/* 选定承载的本地 MAC（发帧时填源地址） */
	UINT8			peer_mac[6];	/* 下一跳的 MAC */
	volatile LONG		peer_mac_valid;
	volatile LONG		peer_mac_pending;	/* 已发 ARP 请求、等回复 */
	UINT64			arp_ts_ms;	/* 解析出 peer_mac 的时刻（老化用） */
	UINT64			arp_last_ms;	/* 上次发 ARP 的时刻（限速，防请求风暴） */

	/* 承载发送的进度：外层 NBL 已交给 NDIS 但还没完成的数量。
	 * 统计一律写在 sess.stats 里（与 WFP 平面同名同义），装具与用户态不用改。 */
	volatile LONG		outer_outstanding;
} IWAN_MP_PLANE;

/* 统计走 sess.stats，与 WFP 平面的 IWAN_STAT_INC/ADD 同名同义 —— 用户态的
 * 解析器、共享页布局、装具的 STATS 行都不需要为新平面改一个字。 */
#define IWAN_MP_STAT_INC(ext, f) \
	InterlockedIncrement64((volatile LONG64 *)&(ext)->sess.stats.f)
#define IWAN_MP_STAT_ADD(ext, f, v) \
	InterlockedExchangeAdd64((volatile LONG64 *)&(ext)->sess.stats.f, (LONG64)(v))

/* ---- 设备扩展 --------------------------------------------------------- */

typedef struct _IWAN_WIN_DEVICE_EXTENSION {
	IWAN_WIN_SESSION	sess;

	/* 设备对象：callout 注册推迟到会话建立时做，那时手上只有 ext，
	 * 所以入口把它存下来（FwpsCalloutRegister 需要它）。 */
	PDEVICE_OBJECT		devobj;

	KMUTEX			ctrl_mutex;	/* 控制面串行化（PASSIVE_LEVEL） */
	EX_RUNDOWN_REF		rundown;	/* 数据面读者保护 */

	/* NBL 池：注入用（NdisAllocateNetBufferListPool 建，wfp_fini 释放；
	 * 释放前必须注销 callout 并排空在途注入） */
	NDIS_HANDLE		nbl_pool;
	volatile LONG		inject_outstanding;

	/* 第二个平面（iwanmp.sys）的数据面状态。WFP 平面用不到它，但摆在同一个
	 * 设备扩展里：两个平面共用会话控制面，扩展结构共用能省掉一层指针。 */
	IWAN_MP_PLANE		mp;

	/* WFP：引擎句柄、callout id、注入句柄 */
	HANDLE			engine;
	UINT32			callout_id_out4;	/* FWPS_LAYER_OUTBOUND_IPPACKET_V4 */
	UINT32			callout_id_out6;	/* FWPS_LAYER_OUTBOUND_IPPACKET_V6 */
	UINT32			callout_id_in4;		/* FWPS_LAYER_INBOUND_TRANSPORT_V4 */
	UINT32			callout_id_in6;		/* FWPS_LAYER_INBOUND_TRANSPORT_V6 */
	HANDLE			inj_send4;
	HANDLE			inj_send6;
	HANDLE			inj_recv4;
	HANDLE			inj_recv6;
	/* 数据面是否已装上：0=未注册，1=正在装/正在摘，2=已注册。
	 * 注册推迟到会话建立时，多个 OPEN 并发也只能注册一次，所以用
	 * LONG + InterlockedCompareExchange 做闸门。数据面不看这个字段，
	 * 它只看 sess.valid。 */
	volatile LONG		wfp_started;

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

/* 控制设备分发（iwan_win_drv.c）：两个平面共用。NDIS 平面还要在上面套一层
 * "看到 NDIS 自己的设备对象就原样转交"的外壳（见 iwan_win_mp.c）。 */
NTSTATUS iwan_win_dispatch_create(_In_ PDEVICE_OBJECT devobj, _Inout_ PIRP irp);
NTSTATUS iwan_win_dispatch_ioctl(_In_ PDEVICE_OBJECT devobj, _Inout_ PIRP irp);

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

/* 出向拒绝样本：把"为什么拒"写进共享页诊断区（实现 iwan_win_session.c，
 * 两个数据面共用；只在拒绝路径调用，可在 DISPATCH_LEVEL） */
VOID iwan_win_diag_tx(_Inout_ IWAN_WIN_SESSION *s, _In_ UINT32 reason,
		      _In_ ULONG len, _In_ ULONG tot, _In_ ULONG pkt0,
		      _In_reads_bytes_opt_(len) const UINT8 *pkt);

/* ---- WFP 数据面（iwan_win_wfp.c） ------------------------------------- */

/* 准备工具：打开 BFE 引擎、建 NBL 池与四个注入句柄。这一步不拦截任何报文。 */
NTSTATUS iwan_win_wfp_init(_In_ PDEVICE_OBJECT devobj,
			   _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
/* 装上/摘掉数据面：四个层的 callout 与过滤器。start 幂等；由 IOCTL_OPEN
 * 与 IOCTL_CLOSE 驱动，所以“加载驱动”与“接管流量”是两件可分开验证的事。 */
NTSTATUS iwan_win_wfp_start(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
VOID iwan_win_wfp_stop(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
VOID iwan_win_wfp_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* ---- 小型端口 + 协议驱动平面（iwan_win_mp.c / iwan_win_proto.c） -------
 *
 * 这个平面由 iwanmp.vcxproj 定义 IWAN_WIN_PLANE_MP 编出来，与 WFP 平面不共存
 * 于一个二进制：两边都要接管全部收发，装在一个驱动里既没有意义，也会让
 * PnP/非 PnP 两套生命周期纠缠在一起。用户态按设备名选平面。
 */

/* 注册小型端口与协议驱动（iwan_win_mp.c）。DriverEntry 调用一次。 */
NTSTATUS iwan_win_mp_init(_In_ PDRIVER_OBJECT driver,
			  _In_ PDEVICE_OBJECT devobj,
			  _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			  _In_ PUNICODE_STRING registry_path);

/* 协议边（iwan_win_proto.c）：注册/注销 NdisRegisterProtocolDriver。
 * init 由 iwan_win_mp_init 调用，fini 由 iwan_win_mp_fini 调用（两者都不在
 * 数据面，PASSIVE_LEVEL）。 */
NTSTATUS iwan_win_proto_init(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
VOID iwan_win_proto_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* 注销（iwan_win_unload 调用）。会先停适配器再解绑协议边。 */
VOID iwan_win_mp_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* 会话选定承载：由 IOCTL_OPEN 在会话建立之后调用，选定失败即整个 OPEN 失败
 * （fail-closed：宁可建不成会话，也不能把明文放到承载网上）。
 * 判据依次为 显式 oif_index → bind_ip 所在网卡 → 外层目的地址的 FIB 路由。 */
NTSTATUS iwan_win_mp_select_carrier(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
/* IOCTL_CLOSE 调用：清掉 active 与下一跳 MAC 缓存，会话间不残留状态。 */
VOID iwan_win_mp_release_carrier(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* ---- 引擎（iwan_win_mpdata.c）：内层 ↔ 外层，只碰字节与统计 ---------- */

/* 出向：把一个内层 IP 数据报封装成外层帧交给承载。缓冲由本函数分配，
 * 成功时所有权转给承载（由发送完成回调释放），失败时本函数自己释放并按
 * 原因计数（tx_bad_state / tx_bad_inner / tx_err，细节写进共享页诊断区）。 */
BOOLEAN iwan_win_mp_encap_send(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			       _In_reads_bytes_(len) const UINT8 *inner,
			       _In_ ULONG len, _In_ BOOLEAN l4_offloaded);
/* 入向：从承载收到的一个外层 IP 数据报（从 IP 头开始）→ 解封 → 指示向上。
 * 缓冲由本函数分配，成功指示后归小型端口（NBL 归还时释放）。 */
VOID iwan_win_mp_outer_recv(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			    _In_reads_bytes_(len) const UINT8 *ip,
			    _In_ ULONG len);

/* ---- 协议边与小型端口提供给引擎的出口（实现分别在 proto/ mp.c） ------- */

/* 填以太头（源 = 选定承载的 MAC，目的 = 下一跳 MAC）。
 * TRUE = 已填好；FALSE = 邻居还没解析出来（本函数已按限速发过 ARP 请求），
 * 这一个包该丢。缓冲所有权不动：调用者（引擎）在 FALSE 时自己释放。 */
BOOLEAN iwan_win_proto_fill_eth4(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
				 _Inout_ UINT8 *buf);

/* 把整帧外层数据报（含以太头，buf 由 IWAN_ALLOC 分配）交给承载网卡。
 * TRUE = 已交给 NDIS，所有权转移（完成回调里释放）；FALSE = 未发出，
 * 缓冲已被本函数释放（调用者不得再引用）。下一跳 MAC 未知时会发 ARP 并
 * 返回 FALSE。
 * 只有 v4：外层 v6 的邻居发现（NS/NA）留到第二阶段，现在会话是 v6 时引擎
 * 直接拒绝并计 tx_bad_state，不做任何降级。 */
BOOLEAN iwan_win_proto_send_outer4(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
				   _In_reads_bytes_(len) UINT8 *eth,
				   _In_ ULONG len);

/* 把解封出来的内层数据报指示向上（buf 由 IWAN_ALLOC 分配）。
 * TRUE = 已指示，所有权转移（NBL 归还时释放）；FALSE = 失败，且缓冲已被
 * 本函数释放（调用者不得再引用，也不要再释放一次）。 */
BOOLEAN iwan_win_mp_indicate_inner(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
				   _In_reads_bytes_(len) UINT8 *inner,
				   _In_ ULONG len);

#endif /* IWAN_WIN_H */
