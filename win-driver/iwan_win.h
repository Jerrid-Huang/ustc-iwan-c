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
	UINT8			outer_if_guid[16];	/* 承载网卡接口 GUID（全 0 = 未提供） */
	UINT8			peer_mac_fixed[6];	/* 测试旋钮：下一跳 MAC 固化 */
	UINT32			peer_mac_fixed_valid;	/* 0 = 照常发 ARP 解析 */
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

/* NBL context 的布局：出向（协议边）与入向指示（小型端口）共用同一条池、
 * 同一块 context，所以结构必须只有一份定义 —— 两边各写一份 layout 迟早会分叉。
 * 归还时从它取缓冲与 MDL，不从 MDL 反推地址（上层协议驱动可以 advance 过 NB
 * 再还回来，那时 MDL 里的地址是缓冲内部地址，ExFreePoolWithTag 会踩坏池）。 */
typedef struct _IWAN_MP_TX_CTX {
	UINT8			*buf;		/* IWAN_ALLOC 的整帧（含以太头） */
	PMDL			mdl;
} IWAN_MP_TX_CTX;

/* 承载侧的链路层常量（小型端口那侧是 NdisMediumIP，裸 IP，没有以太头） */
#define IWAN_MP_ETH_HDR_LEN	14u
#define IWAN_MP_ETH_TYPE_IP4	0x0800u
#define IWAN_MP_ETH_TYPE_ARP	0x0806u
#define IWAN_MP_ETH_TYPE_IP6	0x86DDu

/* 在途外层 NBL 的上限，两个文件都要用同一个数：
 *   · iwan_win_mpdata.c（引擎）在封装前把关，超限即丢并计 tx_bad_state；
 *   · iwan_win_proto.c（协议边）在交给 NDIS 前再兜一次。
 * 每个在途 NBL 占着非分页池（缓冲 + MDL + NBL）直到发送完成回调，内层可能
 * 远比承载快，没有上限就会以 GB/s 量级净增长、秒级耗尽非分页池 —— WFP 平面
 * 的硬挂就是这个机制，同一个坑不踩第二次。 */
#define IWAN_MP_MAX_OUTER_INFLIGHT 4096u

/* 外层分片重组的过期时间：一个数据报的分片必须在这个窗口内到齐，否则新片
 * 从头开始（对端重发时不会带着旧状态）。Linux 侧 ip_defrag 也是同量级的
 * 30 秒级超时，但这里的槽少、单报文上限小，短一点更安全。 */
#define IWAN_WIN_FRAG_TTL_MS	2000u

/* 在途内层指示的上限。出向有闸门而入向原先没有，这是全数据面唯一的无界非
 * 分页池分配：每个指示上去的包固定占内层缓冲（IWAN_ALLOC）+ IoAllocateMdl +
 * 池 NBL，约 1.6–2 KB，不带 NDIS_RECEIVE_FLAGS_RESOURCES，所以归还只能等上层
 * 协议栈回调 MiniportReturnNetBufferLists。发送路径长期占满 DISPATCH 时归还侧
 * 被饿住，池按入向速率线性净增长，几分钟内耗尽非分页池 —— 表现是整机冻结、
 * 来不及写 BugCheck（Kernel-Power 41 + 6008），与 WFP 平面的硬挂同族。
 * 4096 × 2 KB ≈ 8 MB，是"允许排队但不许吃穿内存"的量级；超限丢包并计
 * rx_nomem（与分配失败同一条外报通道，读侧不必区分）。 */
#define IWAN_MP_MAX_INNER_INFLIGHT 4096u

typedef struct _IWAN_MP_PLANE {
	/* 小型端口侧。这两个句柄的**生命周期完全不同**，绝不能共用一个字段：
	 *   mp_driver_handle：NdisMRegisterMiniportDriver 的输出，从 DriverEntry
	 *     活到 UnloadHandler，注销与 NdisRegisterDeviceEx 都用它；
	 *   adapter_handle：MiniportInitializeEx 的入参（MiniportAdapterHandle），
	 *     只在 InitializeEx 与 Halt 之间有效，指示/完成都用它。
	 * 曾经共用一个字段，结果是 MiniportInitializeEx 里的"只服务一个适配器"
	 * 判据在第一次启动时就为真（注册早就把字段填上了），适配器直接 Code 10。 */
	NDIS_HANDLE		mp_driver_handle;
	NDIS_HANDLE		adapter_handle;	/* MiniportAdapterHandle */
	/* NBL 池有两条，生命周期必须分开。曾经共用一条，MiniportHaltEx 一销毁
	 * 就把协议边还在途的外层 NBL 连池一起废掉 —— NDIS 的硬规则是
	 * "释放池之前必须先释放池里所有 NBL"，违反它就是 0x1E 引用计数失衡
	 * 与 0xD1（迟到的归还走进已释放的池）：
	 *   nbl_pool：入向指示用，小型端口所有，InitializeEx 建、Halt 排空后销毁；
	 *   tx_pool ：出向发外层用，协议边所有，proto_init 建、proto_fini 排空后销毁。
	 * 两条池都要留 16 字节 context（IWAN_MP_TX_CTX = 缓冲 + MDL）。 */
	NDIS_HANDLE		nbl_pool;
	NDIS_HANDLE		tx_pool;
	/* 已指示向上、尚未归还的入向 NBL 数：Halt 靠它判断池里还有没有在途
	 * NBL，等不到就不放池（泄漏一条池远好过让归还没进已释放的池）。 */
	volatile LONG		rx_inflight;
	volatile LONG		mp_running;	/* Pause/Restart 闸门（1=可收可发） */
	volatile LONG		proto_registered;	/* 协议边注册成功过 */

	/* 控制设备（\Device\iwanmp）：由 NdisRegisterDeviceEx 建，所以它是
	 * NDIS 的设备、共享 NDIS 的 DriverObject；注销要用同一个句柄。 */
	PDEVICE_OBJECT		ctrl_devobj;
	NDIS_HANDLE		ctrl_handle;

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
	/* ARP 诊断：出向发不出包时，必须先分清"请求没发出去""请求发了没回""
	 * "回了但 spa 对不上"。这三个计数只在 IOCTL_GET（PASSIVE）时落到
	 * T93/T94/T95，数据面里只做原子加。 */
	/* 外层分片重组槽：Linux 侧在外层走 ip_defrag()，WFP 平面靠 tcpip 的
	 * INBOUND_TRANSPORT（重组之后）—— 只有本平面要自己拼。槽数与单报文
	 * 上限都是写死的（见 iwan_win_frame.h），平时根本用不到这条路径。 */
	IWAN_WIN_FRAG_SLOT	frag[IWAN_WIN_FRAG_SLOTS];

	volatile LONG		arp_sent;
	volatile LONG		arp_rx;
	volatile LONG		arp_learn;

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
	IO_REMOVE_LOCK		ctrl_remove_lock;	/* 在途控制 IRP 的排空 */
	volatile LONG		ctrl_remove_init;	/* 1 = 已初始化 */
	volatile LONG		ctrl_remove_waited;	/* 1 = 卸载路径已进入移除态 */

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

/*
 * 控制面从设备对象取扩展。
 *
 * WFP 平面：设备是 DriverEntry 用 IoCreateDeviceSecure 建的，扩展就是
 * 设备扩展。
 *
 * NDIS 平面：控制设备由 NdisRegisterDeviceEx 建（注册小型端口时
 * DriverObject 必须干净，见 iwan_win_mp_init），它不带设备扩展 ——
 * 扩展是我们自己分配的那一份，全驱动唯一，所以这里返回单例。
 * 单例在 iwan_win_mp_init 里挂上、UnloadHandler 里撤销；控制设备的
 * IRP 只可能在两者之间到达。
 */
#ifdef IWAN_WIN_PLANE_MP
IWAN_WIN_DEVICE_EXTENSION *iwan_win_mp_device_ext(VOID);
#define IWAN_DEVEXT(devobj)	iwan_win_mp_device_ext()
#else
#define IWAN_DEVEXT(devobj) \
	((IWAN_WIN_DEVICE_EXTENSION *)(devobj)->DeviceExtension)
#endif

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
/* 两个平面共用同一个设备类 GUID（只在设备对象里做标记用）：WFP 平面递给
 * IoCreateDeviceSecure，NDIS 平面递给 NdisRegisterDeviceEx。定义在 iwan_win_drv.c。 */
extern const GUID iwan_win_devclass_guid;

/* 原型与定义必须带同一个函数类：静态分析要求“声明与实现一致”
 * （C28252/C28253），而 DRIVER_DISPATCH 也是它判断“这个函数可以填进
 * MajorFunction[]”的唯一依据（C28023）。两处都写，不要只写一处。 */
_Function_class_(DRIVER_DISPATCH)
NTSTATUS iwan_win_dispatch_create(_In_ PDEVICE_OBJECT devobj, _Inout_ PIRP irp);
_Function_class_(DRIVER_DISPATCH)
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

/* 注册小型端口与协议驱动（iwan_win_mp.c）。DriverEntry 调用一次。
 *
 * 顺序上有一条硬约束（客体实测：否则 NdisMRegisterMiniportDriver 当场回
 * NDIS_STATUS_BAD_CHARACTERISTICS = 0xC0010005）：调用它时 DriverObject 必须
 * 还是"干净"的 —— 既没有自己的设备对象，也没有被换过的 MajorFunction。
 * 所以控制设备不由 DriverEntry 用 IoCreateDevice 建，而是注册之后交给 NDIS
 * 的 NdisRegisterDeviceEx（见 iwan_win_mp_open_control）。 */
NTSTATUS iwan_win_mp_init(_In_ PDRIVER_OBJECT driver,
			  _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			  _In_ PUNICODE_STRING registry_path);

/* 建控制设备 \Device\iwanmp（+ \DosDevices\iwanmp）。必须在 iwan_win_mp_init
 * 之后调用：NdisRegisterDeviceEx 要有小型端口句柄，而且它建出来的设备共享
 * NDIS 的 DriverObject，所以这里才把四个 MajorFunction 换成我们的分发
 * （自己的设备走控制面，NDIS 的设备原样转交）。 */
NTSTATUS iwan_win_mp_open_control(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* 加载期失败诊断（实现在 iwan_win_session.c，只在 IWAN_WIN_PLANE_MP 下编入）：
 * 把阶段号与状态码写进服务键的 Parameters 子键。驱动加载失败时没有别的通道
 * 可看 —— 控制设备还没建、客体上没有内核调试器。stage 约定：
 *   3-5   DriverEntry（3 数据面注册、4 完成、5 控制设备）
 *   10-12 iwan_win_mp_init（10 小型端口注册失败、11 协议边注册失败、12 完成）
 *   20-22 MiniportInitializeEx（20 进入、21 失败、22 完成）
 *   30    环境：T30 = NdisGetVersion() */
VOID iwan_win_mp_trace(_In_ ULONG stage, _In_ LONG status);

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
VOID iwan_win_mp_trace_arp(_In_ IWAN_WIN_DEVICE_EXTENSION *ext);
/* IOCTL_CLOSE 调用：清掉 active 与下一跳 MAC 缓存，会话间不残留状态。 */
VOID iwan_win_mp_release_carrier(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* ---- 引擎（iwan_win_mpdata.c）：内层 ↔ 外层，只碰字节与统计 ---------- */

/* 出向封装的三态：丢包不是失败。
 *
 * 背压与超限必须"假装成功"（IWAN_MP_TX_DROP）。理由不是审美：小型端口把
 * NDIS_STATUS_FAILURE 写回 NBL，内层协议栈会把它翻成 sendto() 的
 * WSAEINVAL(10022) —— 实测 4 线程不限速打流时 77% 的 sendto 被这样顶回来，
 * 应用看到的是"参数非法"，而真实原因只是承载来不及取：丢包在 UDP 上本来
 * 就是正常结局，不该伪装成编程错误。
 *
 * 只有"这个包本身不合法"（不是 IPv4）才回 IWAN_MP_TX_FAIL，
 * 其余一律 DROP 并计数（tx_bad_state / ev_dropped / tx_err）。 */
#define IWAN_MP_TX_OK   0u	/* 已交给承载 */
#define IWAN_MP_TX_DROP 1u	/* 主动丢弃，对协议栈报成功 */
#define IWAN_MP_TX_FAIL 2u	/* 报文不合法，对协议栈报失败 */

/* 分片入口：超长 v4 报文按声明的内层 MTU 切片后逐片封装（Linux 侧由协议栈
 * 分片，这里由驱动代劳）。返回值语义与 iwan_win_mp_encap_send 相同。 */
UINT32 iwan_win_mp_encap_send_pkt(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
				  _In_reads_bytes_(len) const UINT8 *inner,
				  _In_ ULONG len, _In_ BOOLEAN l4_offloaded);

UINT32 iwan_win_mp_encap_send(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
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
/* 两种结局都会让调用者失去 eth：TRUE 时所有权随 NBL 交给 NDIS（完成回调
 * 释放），FALSE 时本函数自己已经释放。用 __drv_freesMem 把这条"交出去就
 * 撒手"的约定写成注解 —— 只有写成注解，静态分析才不会再判调用者泄漏。 */
BOOLEAN iwan_win_proto_send_outer4(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
				   __drv_freesMem(_Out_) UINT8 *eth,
				   _In_ ULONG len);

/* 把解封出来的内层数据报指示向上（buf 由 IWAN_ALLOC 分配）。
 * TRUE = 已指示，所有权转移（NBL 归还时释放）；FALSE = 失败，且缓冲已被
 * 本函数释放（调用者不得再引用，也不要再释放一次）。 */
BOOLEAN iwan_win_mp_indicate_inner(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
				   __drv_freesMem(_Out_) UINT8 *inner,
				   _In_ ULONG len);

#endif /* IWAN_WIN_H */
