/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_proto.c — NDIS 协议边：把外层 UDP 放到承载网卡上收发。
 *
 * 这一半负责"外层怎么出去、怎么进来"：
 *
 *   发送：iwan_win_proto_send_outer4() 把引擎装好的整帧（含以太头）交给
 *         该会话选定的那张承载网卡，走 NdisSendNetBufferLists；完成回调
 *         只负责归还缓冲、递减在途计数。
 *   接收：注册的 ReceiveNetBufferLists 在每个绑定的网卡上收到**全部**帧，
 *         逐帧过滤 —— 只有"目的 IP = 会话外层源地址、目的端口 = 会话源
 *         端口、UDP"的才交给引擎，其余只读一眼就归还给 NDIS。
 *
 * 三条与 WFP 平面不同的地方，都是"位置不同"带来的，不是设计取舍：
 *
 * ① 下一跳地址由控制面给（sess.outer_hop），不是驱动自己查路由：Windows
 *    没有给协议驱动用的内核态路由查询接口（netioapi.h 那族只对用户态导出
 *    GetBestRoute2；内核态只导出 Convert* 转换函数）。控制面建会话时本来
 *    就要为 carrier_mtu 查一次路由（src/common/kdp_win.c），顺手把接口索引
 *    与下一跳填进 SESSION_OPEN 即可。查不到就退回"对端在链路上"（下一跳
 *    等于外层目的地址），这是隧道的默认拓扑。
 * ② 邻居（ARP）自己做：本平面不走主机 IP 栈，协议驱动也不会替我们解析。
 *    请求按 IWAN_MP_ARP_RETRY_MS 限速、缓存按 IWAN_MP_ARP_HOLD_MS 老化，
 *    全部用时间戳判断，不引入定时器/DPC/工作项（与整个驱动同一约定）。
 * ③ 控制帧刻意不吸收：承载网卡的常规 TCP/IP 绑定是**另一个**协议驱动，
 *    它照样会把同一批外层 UDP 交给用户态套接字，所以 PT_OPEN_ACK、ECHO、
 *    CLOSE 的控制面在用户态原样可用。本边只记账（rx_ctrl_frame、mark_rx/
 *    mark_close），不截断、不向上指示任何东西 —— 协议驱动也没有"向上指示"
 *    这一说，帧要么自己用掉、要么还给 NDIS。
 *
 * 并发：回调可能在 DISPATCH_LEVEL（ReceiveNetBufferLists 带
 * NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL、发送完成回调亦然）。本文件不等待、
 * 不加互斥、不碰可分页内存；绑定表由 g_bind_lock 保护，会话相关的
 * active/下一跳/邻居缓存由 mp.lock 保护，临界区都只有几条赋值。
 */
#include "iwan_win.h"

/* ARP 请求的最小间隔与缓存有效期 */
#define IWAN_MP_ARP_RETRY_MS	1000u
#define IWAN_MP_ARP_HOLD_MS	60000u

/* 收到的 NBL 允许的最大单包长度：外层数据报 = 承载 MTU 上限 + 余量。
 * 超过这个长度的帧不可能是本会话的。 */
#define IWAN_MP_RECV_MAX	2048u

/* 一个承载绑定（一张以太网卡）。生命周期：BindAdapter → UnbindAdapter。 */
typedef struct _IWAN_MP_BINDING {
	LIST_ENTRY		link;
	IWAN_WIN_DEVICE_EXTENSION *ext;	/* 控制设备扩展（协议驱动上下文） */
	NDIS_HANDLE		binding;	/* NdisBindingHandle */
	NDIS_HANDLE		bind_context;	/* BindAdapterEx 的完成句柄 */
	NDIS_HANDLE		unbind_context;	/* UnbindAdapterEx 的完成句柄 */
	/* 两种完成句柄必须分开存：bind 返回 PENDING 之后设备被拔掉时 NDIS 会先
	 * 调 unbind，一个字段被覆写后 open_complete 就会把 unbind 的句柄交给
	 * NdisCompleteBindAdapterEx（绑定状态机/引用计数错乱）。 */
	UINT32			ifindex;
	UINT8			mac[6];
	ULONG			mac_len;
	volatile LONG		opened;		/* 1=打开成功，可收发 */
	volatile LONG		closed;		/* 1=已关闭，不可再选作出向承载 */
	volatile LONG		outstanding;	/* 已发出、未完成的 NBL 数 */
} IWAN_MP_BINDING;

/* 绑定表是驱动级的：协议驱动在 DriverEntry 注册，早于小型端口（PnP）出现，
 * 也晚于它消失，所以不能挂在设备扩展里。 */
static LIST_ENTRY	g_bindings;
static KSPIN_LOCK	g_bind_lock;
static volatile LONG	g_proto_started;	/* g_bindings/g_bind_lock 已初始化 */
static volatile LONG	g_bind_table_broken;	/* 表头读到 NULL（只诊断用） */

/* 发送在途上下文（IWAN_MP_TX_CTX）定义在 iwan_win.h：入向指示也用它。 */
/* 池的 context 区必须放得下它（池在 iwan_win_mp.c 里按 IWAN_MP_NBL_CTX_SIZE
 * 建；这个断言是两侧唯一的耦合点）。 */
C_ASSERT(sizeof(IWAN_MP_TX_CTX) <= IWAN_MP_NBL_CTX_SIZE);

/* 链上节点数（含已关闭的），只给诊断用。自己取锁：绑定可以被 bind/unbind
 * 随时插拔，不持锁遍历读到半个指针就是自己制造的那类崩溃。 */
static LONG
iwan_win_proto_binding_count(VOID)
{
	PLIST_ENTRY e;
	LONG n = 0;
	KIRQL old;

	KeAcquireSpinLock(&g_bind_lock, &old);
	if (g_bindings.Flink != NULL) {
		for (e = g_bindings.Flink;
		     e != NULL && e != &g_bindings; e = e->Flink)
			n++;
	} else {
		n = -1;
	}
	KeReleaseSpinLock(&g_bind_lock, old);
	return n;
}

/* 绑定表查找：按接口索引找一张已打开的承载。调用者需持有 g_bind_lock。 */
static IWAN_MP_BINDING *
iwan_win_proto_lookup_locked(_In_ UINT32 ifindex)
{
	PLIST_ENTRY e;

	/* 旗子先查，再碰链表：两者在同一把锁内读到，才叫"表可用"。 */
	if (InterlockedCompareExchange(&g_proto_started, 1, 1) == 0)
		return NULL;

	/* 表头必须指向自己（空表）或某个真节点。Flink 为 NULL 说明这张表
	 * 从来没被 InitializeListHead 初始化过 —— 客体上真实发生过：0xD1，
	 * 出错指令正是这里内联出来的 `cmpl %ecx,0x30(%r14)`，r14=0 而 0x30
	 * 是 IWAN_MP_BINDING.ifindex，访问地址恰好 0x30，IRQL=DISPATCH。
	 * 查表是最不该崩的一步：找不到就返回 NULL，调用者回
	 * STATUS_DEVICE_NOT_READY，数据面 fail-closed。 */
	if (g_bindings.Flink == NULL || g_bindings.Blink == NULL) {
		DbgPrint("iwanmp: 绑定表未初始化（Flink=%p），拒绝查表\n",
			 (void *)g_bindings.Flink);
		/* 只置一个内存旗子：本函数在自旋锁内被调用，而写注册表要在
		 * PASSIVE_LEVEL。调用者放锁之后再落 T70。 */
		InterlockedExchange(&g_bind_table_broken, 1);
		return NULL;
	}
	for (e = g_bindings.Flink; e != NULL && e != &g_bindings; e = e->Flink) {
		IWAN_MP_BINDING *b = CONTAINING_RECORD(e, IWAN_MP_BINDING, link);

		if (b->ifindex == ifindex && b->opened && !b->closed)
			return b;
	}
	return NULL;
}

/* 关闭一条绑定：只打标记 + 撤掉"会话正选着它"的引用，**绝不释放**。
 *
 * 绑定对象同时被三条异步路径引用：bind 的完成（open_complete）、unbind 的
 * 完成（close_complete）、以及已经交给 NDIS、还没回调的发送（send_complete
 * 要减在途数）。早期版本在 bind/unbind 返回 NDIS_STATUS_PENDING 时就
 * ExFreePoolWithTag，完成回调再来就是释放后使用 —— 蓝屏的经典形状。
 * 现在 g_bindings 挂着"曾经分配过的全部绑定"，关闭只是打 closed 标记，
 * 真正的释放推迟到 iwan_win_proto_fini：那时 NdisDeregisterProtocolDriver
 * 已经返回，NDIS 保证不会再有任何回调进来。 */
static VOID
iwan_win_proto_binding_close(_Inout_ IWAN_MP_BINDING *b)
{
	IWAN_MP_PLANE *mp = &b->ext->mp;
	KIRQL old;

	InterlockedExchange(&b->opened, 0);
	InterlockedExchange(&b->closed, 1);

	/* 会话若正选着这张卡，立刻放掉：否则出向会继续往一个已经关闭的
	 * 绑定上发（NdisSendNetBufferLists 拿一个关掉的句柄没有好下场）。 */
	KeAcquireSpinLock(&mp->lock, &old);
	if (mp->active == b) {
		mp->active = NULL;
		mp->active_ifindex = 0;
		mp->next_hop_be = 0;
		InterlockedExchange(&mp->peer_mac_valid, 0);
		InterlockedExchange(&mp->peer_mac_pending, 0);
		mp->arp_ts_ms = 0;
		mp->arp_last_ms = 0;
	}
	KeReleaseSpinLock(&mp->lock, old);
}

/* ---- 邻居（ARP） ------------------------------------------------------- */

/* ARP 报文净长（不带以太头）：硬件类型 2 + 协议类型 2 + 长度 2 + 操作 2
 * + 发送方 MAC 6 + 发送方 IP 4 + 目标 MAC 6 + 目标 IP 4。 */
#define IWAN_MP_ARP_LEN 28u

/* 组一个 ARP 请求：who-has next_hop tell local_mac。返回帧长（以太+ARP）。 */
/* bufsz 先判后写：以太头 14 + ARP 28 全在下面逐字节写。注解里的
 * _Out_writes_bytes_(bufsz) 是这条约定的书面形式（原来只写 _Out_，
 * 分析器就只能按 1 字节算，报的是注解缺口不是越界）。 */
_Success_(return != 0)
static ULONG
iwan_win_proto_build_arp4(_In_ IWAN_WIN_DEVICE_EXTENSION *ext,
			  _Out_writes_bytes_(bufsz) UINT8 *eth,
			  _In_ ULONG bufsz)
{
	IWAN_MP_PLANE *mp = &ext->mp;
	UINT8 *a;
	ULONG i;

	if (bufsz < IWAN_MP_ETH_HDR_LEN + IWAN_MP_ARP_LEN)
		return 0;
	/* 下面两个下标的静态上界：eth 的写入落在 [0,14)、a 的写入落在
	 * [14, 14+28)。两者相加正好是上面这条闸门，分析器需要这一句才
	 * 知道 a[27] 不是越界写（C6386）。 */
	__analysis_assume(bufsz >= IWAN_MP_ETH_HDR_LEN + IWAN_MP_ARP_LEN);

	/* 以太头：广播 */
	for (i = 0; i < 6; i++)
		eth[i] = 0xFFu;
	RtlCopyMemory(eth + 6, mp->local_mac, 6);
	eth[12] = (UINT8)(IWAN_MP_ETH_TYPE_ARP >> 8);
	eth[13] = (UINT8)(IWAN_MP_ETH_TYPE_ARP & 0xFFu);

	a = eth + IWAN_MP_ETH_HDR_LEN;
	a[0] = 0x00; a[1] = 0x01;	/* 以太网 */
	a[2] = 0x08; a[3] = 0x00;	/* IPv4 */
	a[4] = 6;			/* 硬件地址长度 */
	a[5] = 4;			/* 协议地址长度 */
	a[6] = 0x00; a[7] = 0x01;	/* 请求 */
	RtlCopyMemory(a + 8, mp->local_mac, 6);
	/* 发送方协议地址留 0：本平面在承载网上没有 IP 身份，填 0 不会让对端
	 * 记错（对端只从以太头学源 MAC）。 */
	a[14] = a[15] = a[16] = a[17] = 0;
	/* 目标硬件地址未知：填 0（与以太头广播一致） */
	a[18] = a[19] = a[20] = a[21] = a[22] = a[23] = 0;
	a[24] = (UINT8)(mp->next_hop_be >> 24);
	a[25] = (UINT8)(mp->next_hop_be >> 16);
	a[26] = (UINT8)(mp->next_hop_be >> 8);
	a[27] = (UINT8)(mp->next_hop_be);

	return IWAN_MP_ETH_HDR_LEN + IWAN_MP_ARP_LEN;
}

/* 收到 ARP：把"发送方协议地址 = 下一跳"的回复记下来。 */
static BOOLEAN
iwan_win_proto_learn_arp4(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			  _In_reads_bytes_(len) const UINT8 *a, _In_ ULONG len)
{
	IWAN_MP_PLANE *mp = &ext->mp;
	UINT32 spa;
	BOOLEAN ok = FALSE;
	KIRQL old;

	if (len < 28u || a[0] != 0x00 || a[1] != 0x01 || a[2] != 0x08 ||
	    a[3] != 0x00 || a[4] != 6 || a[5] != 4)
		return FALSE;
	if (a[6] != 0x00)		/* 以太网/IPv4 */
		return FALSE;
	if (a[7] != 0x02)		/* 只从回复学：请求的 spa 谁都能伪造 */
		return FALSE;

	spa = ((UINT32)a[14] << 24) | ((UINT32)a[15] << 16) |
	      ((UINT32)a[16] << 8) | (UINT32)a[17];
	if (spa == 0)			/* 发方地址为 0 的探测包不作数 */
		return FALSE;

	KeAcquireSpinLock(&mp->lock, &old);
	if (spa == mp->next_hop_be) {
		RtlCopyMemory(mp->peer_mac, a + 8, 6);
		InterlockedExchange(&mp->peer_mac_valid, 1);
		InterlockedExchange(&mp->peer_mac_pending, 0);
		mp->arp_ts_ms = iwan_win_now_ms();
		ok = TRUE;
	}
	KeReleaseSpinLock(&mp->lock, old);
	return ok;
}

/* 发 ARP 请求。调用者不得持有 mp.lock。 */
static VOID
iwan_win_proto_send_arp4(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	UINT8 *buf;
	ULONG len;

	buf = (UINT8 *)IWAN_ALLOC(IWAN_MP_ETH_HDR_LEN + 28u, IWAN_TAG_PKT);
	if (buf == NULL) {
		IWAN_MP_STAT_INC(ext, tx_err);
		return;
	}
	len = iwan_win_proto_build_arp4(ext, buf, IWAN_MP_ETH_HDR_LEN + 28u);
	if (len == 0) {
		ExFreePoolWithTag(buf, IWAN_TAG_PKT);
		return;
	}
	/* 走同一条发送路径：send_outer4 只管把帧交给网卡，不看以太类型。
	 * 它 TRUE 时所有权已随 NBL 转移（完成回调释放）、FALSE 时已经自己
	 * 释放 —— 两种结局都不该在这里再动 buf，所以这里没有 else 释放。 */
	if (!iwan_win_proto_send_outer4(ext, buf, len))
		IWAN_MP_STAT_INC(ext, tx_err);
}

/* ---- 引擎的出口 ------------------------------------------------------- */

/* 填以太头。TRUE = 已填好；FALSE = 邻居未解析（已按限速发过 ARP），本包该丢。
 * 缓冲所有权不动：调用者（引擎）在 FALSE 时自己释放。 */
BOOLEAN
iwan_win_proto_fill_eth4(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext, _Inout_ UINT8 *buf)
{
	IWAN_MP_PLANE *mp = &ext->mp;
	BOOLEAN valid, fire = FALSE;
	UINT64 now;
	KIRQL old;

	now = iwan_win_now_ms();
	KeAcquireSpinLock(&mp->lock, &old);
	valid = mp->peer_mac_valid != 0;
	if (valid && mp->arp_ts_ms != 0 &&
	    now - mp->arp_ts_ms > IWAN_MP_ARP_HOLD_MS) {
		InterlockedExchange(&mp->peer_mac_valid, 0);	/* 老化 */
		valid = FALSE;
	}
	/* pending 只表示"已发过一次、还没学到"，不是"永不再发"：应答丢了、
	 * 或对方的 spa 与本会话下一跳不一致（代理 ARP、下一跳选错）时，必须能
	 * 重发，否则出向每个包都在这里被丢、会话永久不通，重试逻辑成了死代码。
	 * 限速仍由 arp_last_ms 负责。 */
	if (!valid && mp->active != NULL &&
	    (mp->peer_mac_pending == 0 ||
	     (mp->arp_last_ms != 0 &&
	      now - mp->arp_last_ms >= IWAN_MP_ARP_RETRY_MS))) {
		InterlockedExchange(&mp->peer_mac_pending, 1);
		mp->arp_last_ms = now;
		fire = TRUE;
	}
	if (valid) {
		RtlCopyMemory(buf, mp->peer_mac, 6);
		RtlCopyMemory(buf + 6, mp->local_mac, 6);
		buf[12] = (UINT8)(IWAN_MP_ETH_TYPE_IP4 >> 8);
		buf[13] = (UINT8)(IWAN_MP_ETH_TYPE_IP4 & 0xFFu);
	}
	KeReleaseSpinLock(&mp->lock, old);

	if (!valid && fire)
		iwan_win_proto_send_arp4(ext);
	return valid;
}

/* 把整帧交给选定的承载网卡。TRUE = 所有权已转移（完成回调释放）；
 * FALSE = 未发出且缓冲已被本函数释放。 */
BOOLEAN
iwan_win_proto_send_outer4(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			   __drv_freesMem(_Out_) UINT8 *eth, _In_ ULONG len)
{
	IWAN_MP_PLANE *mp = &ext->mp;
	IWAN_MP_BINDING *b;
	IWAN_MP_TX_CTX *ctx;
	NET_BUFFER_LIST *nbl;
	PMDL mdl;
	KIRQL old;

	if (mp->mp_running == 0 || len == 0) {
		ExFreePoolWithTag(eth, IWAN_TAG_PKT);
		return FALSE;
	}
	/* 在途上限由引擎把关（IWAN_MP_MAX_OUTER_INFLIGHT），这里只记账与兜底 */
	if ((ULONG)InterlockedIncrement(&mp->outer_outstanding) >
	    IWAN_MP_MAX_OUTER_INFLIGHT) {
		InterlockedDecrement(&mp->outer_outstanding);
		ExFreePoolWithTag(eth, IWAN_TAG_PKT);
		return FALSE;
	}

	KeAcquireSpinLock(&mp->lock, &old);
	b = mp->active;
	if (b != NULL && b->opened)
		InterlockedIncrement(&b->outstanding);
	else
		b = NULL;
	KeReleaseSpinLock(&mp->lock, old);
	if (b == NULL) {
		InterlockedDecrement(&mp->outer_outstanding);
		ExFreePoolWithTag(eth, IWAN_TAG_PKT);
		return FALSE;
	}

	mdl = IoAllocateMdl(eth, len, FALSE, FALSE, NULL);
	if (mdl != NULL)
		MmBuildMdlForNonPagedPool(mdl);
	nbl = mdl != NULL ?
		NdisAllocateNetBufferAndNetBufferList(mp->tx_pool,
						      sizeof(IWAN_MP_TX_CTX), 0,
						      mdl, 0, len) : NULL;
	if (nbl == NULL) {
		if (mdl != NULL)
			IoFreeMdl(mdl);
		InterlockedDecrement(&b->outstanding);
		InterlockedDecrement(&mp->outer_outstanding);
		ExFreePoolWithTag(eth, IWAN_TAG_PKT);
		return FALSE;
	}
	ctx = (IWAN_MP_TX_CTX *)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
	ctx->buf = eth;
	ctx->mdl = mdl;

	NdisSendNetBufferLists(b->binding, nbl, NDIS_DEFAULT_PORT_NUMBER,
			       (KeGetCurrentIrql() == DISPATCH_LEVEL) ?
				NDIS_SEND_FLAGS_DISPATCH_LEVEL : 0);
	return TRUE;
}

/* 发送完成：归还缓冲、清在途。可能在 DISPATCH_LEVEL。 */
static
_Function_class_(PROTOCOL_SEND_NET_BUFFER_LISTS_COMPLETE)
VOID
iwan_win_proto_send_complete(_In_ NDIS_HANDLE ProtocolBindingContext,
			     _In_ PNET_BUFFER_LIST NetBufferLists,
			     _In_ ULONG SendCompleteFlags)
{
	IWAN_MP_BINDING *b = (IWAN_MP_BINDING *)ProtocolBindingContext;
	IWAN_WIN_DEVICE_EXTENSION *ext = b->ext;
	PNET_BUFFER_LIST nbl = NetBufferLists;
	PNET_BUFFER_LIST next;

	UNREFERENCED_PARAMETER(SendCompleteFlags);

	while (nbl != NULL) {
		IWAN_MP_TX_CTX *ctx =
			(IWAN_MP_TX_CTX *)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);

		next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;

		if (ctx->mdl != NULL)
			IoFreeMdl(ctx->mdl);
		if (ctx->buf != NULL)
			ExFreePoolWithTag(ctx->buf, IWAN_TAG_PKT);
		NdisFreeNetBufferList(nbl);

		InterlockedDecrement(&ext->mp.outer_outstanding);
		InterlockedDecrement(&b->outstanding);
		nbl = next;
	}
}

/* ---- 接收 ------------------------------------------------------------- */

/* 取一个 NB 的连续视图。need 字节；stor/stor_sz 非空时优先用调用者的缓冲
 * （NDIS 会按需拷进去）。返回 NULL = 取不到或超长。调用期间数据有效。 */
_Success_(return != NULL)
static const UINT8 *
iwan_win_proto_view(_In_ NET_BUFFER *nb, _In_ ULONG need,
		    _Inout_opt_ UINT8 *stor, _In_ ULONG stor_sz)
{
	/* 与 NB 的实际长度比一次：NdisGetDataBuffer 对超长请求的行为不写进
	 * 契约，ARP 分支按 42 字节取、帧却可能只有 34..41 字节（下限由调用者
	 * 保证），靠"它会返回 NULL"是运气而不是设计。 */
	if (need == 0 || need > IWAN_MP_RECV_MAX ||
	    need > NET_BUFFER_DATA_LENGTH(nb))
		return NULL;
	if (stor != NULL && stor_sz >= need)
		return (const UINT8 *)NdisGetDataBuffer(nb, need, stor, 1, 0);
	return (const UINT8 *)NdisGetDataBuffer(nb, need, NULL, 1, 0);
}

/* 命中判定：帧内 IPv4 目的地址 = 会话外层源地址、UDP 目的端口 = 会话源端口。
 * 与 WFP 平面入向闸门同一口径（那边地址取自固定字段，这边从帧里读）。 */
_Success_(return != FALSE)
static BOOLEAN
iwan_win_proto_is_ours(_In_ const IWAN_WIN_SESSION *s,
		       _In_reads_bytes_(len) const UINT8 *ip, _In_ ULONG len,
		       _Out_ ULONG *iplen)
{
	ULONG ihl;

	if (len < 20u || (ip[0] >> 4) != 4)
		return FALSE;
	ihl = (ULONG)(ip[0] & 0x0Fu) * 4u;
	if (ihl < 20u || len < ihl + 8u)
		return FALSE;
	*iplen = iwan_win_rd16(ip + 2);
	if (*iplen < ihl + 8u || *iplen > len)
		return FALSE;
	if (iwan_win_rd32(ip + 16) != s->outer_src)
		return FALSE;
	if (ip[9] != IWAN_IPPROTO_UDP)
		return FALSE;
	return iwan_win_rd16(ip + ihl + 2) == s->sport;
}

/* 一个 NB 就是一帧（NdisMedium802_3）。返回 TRUE 表示是本会话的外层帧、
 * 已交给引擎（这就是"读走了"）。 */
static BOOLEAN
iwan_win_proto_recv_one(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			_In_ NET_BUFFER *nb)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	UINT8 hdr[IWAN_MP_ETH_HDR_LEN + 60u + 8u];
	const UINT8 *p;
	ULONG len, iplen, need;
	UINT16 eth_type;

	/* hdr 只在“NdisGetDataBuffer 把数据拷进来”之后才被读（iwan_win_proto_view
	 * 的契约）。清零是给静态分析的确定值，也让任何契约破坏读到零而不是栈残留。 */
	RtlZeroMemory(hdr, sizeof(hdr));
	len = NET_BUFFER_DATA_LENGTH(nb);
	if (len < IWAN_MP_ETH_HDR_LEN + 20u)
		return FALSE;
	p = iwan_win_proto_view(nb, IWAN_MP_ETH_HDR_LEN + 20u, hdr, sizeof(hdr));
	if (p == NULL)
		return FALSE;

	eth_type = (UINT16)(((UINT16)p[12] << 8) | p[13]);
	if (eth_type == IWAN_MP_ETH_TYPE_ARP) {
		p = iwan_win_proto_view(nb, IWAN_MP_ETH_HDR_LEN + 28u, hdr,
					sizeof(hdr));
		if (p == NULL)
			return FALSE;
		iwan_win_proto_learn_arp4(ext, p + IWAN_MP_ETH_HDR_LEN,
					  len - IWAN_MP_ETH_HDR_LEN);
		return FALSE;	/* ARP 不是"本会话的数据帧"，但也不留给谁 */
	}
	if (eth_type != IWAN_MP_ETH_TYPE_IP4)
		return FALSE;
	if (s->valid == 0 || s->outer_src == 0 || ext->mp.active == NULL)
		return FALSE;

	/* IPv4 首部可能带选项（IHL 最大 60），取到"以太头 + 最大首部 + UDP
	 * 首部"为止再判定，免得读越过栈缓冲；帧短于这么多就按实际长度取。 */
	need = len < sizeof(hdr) ? len : (ULONG)sizeof(hdr);
	p = iwan_win_proto_view(nb, need, hdr, sizeof(hdr));
	if (p == NULL)
		return FALSE;
	if (!iwan_win_proto_is_ours(s, p + IWAN_MP_ETH_HDR_LEN,
				    len - IWAN_MP_ETH_HDR_LEN, &iplen))
		return FALSE;

	/* 命中：整包交给引擎。短包直接用栈缓冲；长的先试零拷贝（同一块内存
	 * 时 NdisGetDataBuffer 直接给指针），取不到就让 NDIS 拷进临时缓冲。 */
	if (iplen <= sizeof(hdr) - IWAN_MP_ETH_HDR_LEN) {
		p = iwan_win_proto_view(nb, IWAN_MP_ETH_HDR_LEN + iplen, hdr,
					sizeof(hdr));
		if (p == NULL) {
			/* 已判为本会话的帧却取不到连续首部：吃掉，但必须计数
			 * —— 数据面不许有静默的丢弃通道。 */
			IWAN_MP_STAT_INC(ext, rx_bad_hdr);
			return TRUE;
		}
		iwan_win_mp_outer_recv(ext, p + IWAN_MP_ETH_HDR_LEN, iplen);
		return TRUE;
	}
	{
		ULONG pktlen = IWAN_MP_ETH_HDR_LEN + iplen;
		UINT8 *tmp = (UINT8 *)IWAN_ALLOC(pktlen, IWAN_TAG_PKT);

		if (tmp == NULL) {
			IWAN_MP_STAT_INC(ext, rx_nomem);
			return TRUE;	/* 命中但放不下：吃掉，不重复投递 */
		}
		p = iwan_win_proto_view(nb, pktlen, tmp, pktlen);
		if (p != NULL)
			iwan_win_mp_outer_recv(ext, p + IWAN_MP_ETH_HDR_LEN, iplen);
		else
			IWAN_MP_STAT_INC(ext, rx_bad_hdr);
		ExFreePoolWithTag(tmp, IWAN_TAG_PKT);
		return TRUE;
	}
}

/* 收到一批 NBL。本边一枚都不向上指示：同一条链路上的常规 TCP/IP 绑定是
 * 另一个协议驱动，它自己会收；我们只挑走本会话的外层帧，其余原样归还。 */
static
_Function_class_(PROTOCOL_RECEIVE_NET_BUFFER_LISTS)
VOID
iwan_win_proto_recv_nbls(_In_ NDIS_HANDLE ProtocolBindingContext,
			 _In_ PNET_BUFFER_LIST NetBufferLists,
			 _In_ NDIS_PORT_NUMBER PortNumber,
			 _In_ ULONG NumberOfNetBufferLists,
			 _In_ ULONG ReceiveFlags)
{
	IWAN_MP_BINDING *b = (IWAN_MP_BINDING *)ProtocolBindingContext;
	IWAN_WIN_DEVICE_EXTENSION *ext = b->ext;
	PNET_BUFFER_LIST nbl;

	UNREFERENCED_PARAMETER(PortNumber);
	UNREFERENCED_PARAMETER(NumberOfNetBufferLists);

	for (nbl = NetBufferLists; nbl != NULL;
	     nbl = NET_BUFFER_LIST_NEXT_NBL(nbl)) {
		PNET_BUFFER nb;

		for (nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb != NULL;
		     nb = NET_BUFFER_NEXT_NB(nb)) {
			if (ext->mp.mp_running == 0 || ext->sess.valid == 0)
				break;
			iwan_win_proto_recv_one(ext, nb);
		}
	}
	/* 带 RESOURCES 时这批 NBL 只是**借用**，所有权还在下层：既不能保留，
	 * 更不能归还（归还一个不属于自己的 NBL 是蓝屏的经典入口）。本边本来
	 * 就不留 NBL，所以这里只是跳过归还。 */
	if ((ReceiveFlags & NDIS_RECEIVE_FLAGS_RESOURCES) == 0) {
		NdisReturnNetBufferLists(b->binding, NetBufferLists,
					 (KeGetCurrentIrql() == DISPATCH_LEVEL) ?
						NDIS_RETURN_FLAGS_DISPATCH_LEVEL : 0);
	}
}

/* ---- 接收过滤器 ------------------------------------------------------- */

/* 协议驱动收帧之前必须先把 OID_GEN_CURRENT_PACKET_FILTER 设到绑定上 ——
 * 不设就是 0（一个包都不收）。这是"外层帧到底有没有进来"的分水岭：同一张
 * 承载网卡上的常规 TCP/IP 绑定是**另一个**协议驱动，它自己会设自己的；
 * 我们这一份必须自己设，否则用户态 socket 能完成 OPEN/OPEN_ACK（那是它自己
 * 的绑定收的包），而驱动侧 rx_* 恒为零、每包死在 DIAG_TX_NO_NEIGHBOR。
 *
 * 请求必须活到 NDIS 回调为止（可能回 PENDING），所以请求与 4 字节信息缓冲
 * 一起从非分页池分配，缓冲紧跟结构体后面。done 字段让两条路径（同步返回、
 * 完成回调）恰好释放一次 —— 两种结束方式都要能安全落地，才不用去赌
 * "非 PENDING 时回调到底来不来"。 */
#define IWAN_MP_FILTER_FLAGS						\
	(NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_MULTICAST |	\
	 NDIS_PACKET_TYPE_ALL_MULTICAST | NDIS_PACKET_TYPE_BROADCAST)

/* 26100 的 ntddndis.h 里只剩 deprecated 的 NDIS_OBJECT_TYPE_REQUEST_EX(0x96)，
 * 而 ndis/oidrequest.h 的示例注释用的仍是 NDIS_OBJECT_TYPE_OID_REQUEST ——
 * 同一个值，NDIS 5 以来没变。带上兜底，免得为一个整数常量白跑一轮 CI。 */
#ifndef NDIS_OBJECT_TYPE_OID_REQUEST
#define NDIS_OBJECT_TYPE_OID_REQUEST 0x96
#endif

typedef struct _IWAN_MP_OID_SET {
	NDIS_OID_REQUEST	req;
	ULONG			value;		/* 过滤器位图（请求的信息缓冲） */
	volatile LONG		done;		/* 1=已释放，防两条路径二次释放 */
} IWAN_MP_OID_SET;

static volatile LONG	g_oid_pending;	/* 已交给 NDIS、未收尾的请求数 */

/* 完成回调：只记账 + 归还那块池内存。 */
static
_Function_class_(PROTOCOL_OID_REQUEST_COMPLETE)
VOID
iwan_win_proto_oid_complete(_In_ NDIS_HANDLE ProtocolBindingContext,
			    _In_ PNDIS_OID_REQUEST OidRequest,
			    _In_ NDIS_STATUS Status)
{
	UNREFERENCED_PARAMETER(ProtocolBindingContext);
	UNREFERENCED_PARAMETER(Status);
	if (OidRequest == NULL)
		return;
	{
		IWAN_MP_OID_SET *o =
			CONTAINING_RECORD(OidRequest, IWAN_MP_OID_SET, req);

		InterlockedDecrement(&g_oid_pending);
		if (InterlockedExchange(&o->done, 1) == 0)
			ExFreePoolWithTag(o, IWAN_TAG_PKT);
	}
}

/* 设接收过滤器。失败只记账不致命：收不到外层帧时会话只能发不能收，
 * 症状可辨（rx_outer 恒 0）；承载重启后 open_complete 会再设一次。 */
static VOID
iwan_win_proto_set_packet_filter(_Inout_ IWAN_MP_BINDING *b)
{
	IWAN_MP_OID_SET *o;
	NDIS_STATUS st;

	/* 两条结束路径各释放一次：同步返回（下面 if 的另一半）与 NDIS 的
	 * OidRequestCompleteHandler 回调（PENDING 时才会来）。分析器看不到
	 * NdisOidRequest 会持有指针、更看不到回调，按"分配后没有在本函数里
	 * 每条路径都释放"报 C6014 —— 与 WFP 注入的 ctx/buf 同一类误报。 */
#pragma warning(suppress: 6014)
	o = (IWAN_MP_OID_SET *)IWAN_ALLOC(sizeof(*o), IWAN_TAG_PKT);
	if (o == NULL) {
		DbgPrint("iwanmp: 过滤器请求分配失败（if%u）\n",
			 (unsigned)b->ifindex);
		return;
	}
	RtlZeroMemory(o, sizeof(*o));
	o->value = IWAN_MP_FILTER_FLAGS;

	o->req.Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
	o->req.Header.Revision = NDIS_OID_REQUEST_REVISION_1;
	o->req.Header.Size = (USHORT)NDIS_SIZEOF_OID_REQUEST_REVISION_1;
	o->req.RequestType = NdisRequestSetInformation;
	o->req.Timeout = NDIS_OID_REQUEST_TIMEOUT_INFINITE;
	o->req.DATA.SET_INFORMATION.Oid = OID_GEN_CURRENT_PACKET_FILTER;
	o->req.DATA.SET_INFORMATION.InformationBuffer = &o->value;
	o->req.DATA.SET_INFORMATION.InformationBufferLength = sizeof(o->value);

	InterlockedIncrement(&g_oid_pending);
	st = NdisOidRequest(b->binding, &o->req);
	if (st != NDIS_STATUS_PENDING) {
		/* 同步结束：请求没被 NDIS 接管，自己收尾 */
		InterlockedDecrement(&g_oid_pending);
		if (InterlockedExchange(&o->done, 1) == 0)
			ExFreePoolWithTag(o, IWAN_TAG_PKT);
		DbgPrint("iwanmp: 绑定 if%u 接收过滤器 0x%08x -> 0x%08lx\n",
			 (unsigned)b->ifindex, (unsigned)IWAN_MP_FILTER_FLAGS,
			 (unsigned long)st);
	} else {
		DbgPrint("iwanmp: 绑定 if%u 接收过滤器 0x%08x（PENDING）\n",
			 (unsigned)b->ifindex, (unsigned)IWAN_MP_FILTER_FLAGS);
	}
}

/* ---- 绑定生命周期 ----------------------------------------------------- */

static
_Function_class_(PROTOCOL_OPEN_ADAPTER_COMPLETE_EX)
VOID
iwan_win_proto_open_complete(_In_ NDIS_HANDLE ProtocolBindingContext,
			     _In_ NDIS_STATUS Status)
{
	IWAN_MP_BINDING *b = (IWAN_MP_BINDING *)ProtocolBindingContext;

	if (Status == NDIS_STATUS_SUCCESS) {
		InterlockedExchange(&b->opened, 1);
		/* 先把过滤器设上再算"可用"：opened 只表示句柄打开成功，
		 * 收不收得到帧由过滤器决定。这一句放这里是因为 open_complete
		 * 是唯一保证 b->binding 已经可用的时刻。 */
		iwan_win_proto_set_packet_filter(b);
	} else {
		/* 打开失败：这条绑定不能用，打关闭标记（不释放 —— bind 的
		 * 返回路径可能还在用它，而且 NDIS 可能已经在往上指示/发送）。 */
		iwan_win_proto_binding_close(b);
	}
	/* bind 的完成回执：BindAdapterEx 返回 PENDING 时由这里收尾 */
	NdisCompleteBindAdapterEx(b->bind_context, Status);
}

static
_Function_class_(PROTOCOL_CLOSE_ADAPTER_COMPLETE_EX)
VOID
iwan_win_proto_close_complete(_In_ NDIS_HANDLE ProtocolBindingContext)
{
	IWAN_MP_BINDING *b = (IWAN_MP_BINDING *)ProtocolBindingContext;

	iwan_win_proto_binding_close(b);
	NdisCompleteUnbindAdapterEx(b->unbind_context);
}

static
_Function_class_(PROTOCOL_BIND_ADAPTER_EX)
NDIS_STATUS
iwan_win_proto_bind(_In_ NDIS_HANDLE ProtocolDriverContext,
		    _In_ NDIS_HANDLE BindContext,
		    _In_ PNDIS_BIND_PARAMETERS BindParameters)
{
	IWAN_WIN_DEVICE_EXTENSION *ext =
		(IWAN_WIN_DEVICE_EXTENSION *)ProtocolDriverContext;
	IWAN_MP_BINDING *b;
	NDIS_OPEN_PARAMETERS op;
	NDIS_MEDIUM medium = NdisMedium802_3;
	UINT sel_medium = 0;
	NDIS_STATUS st;
	KIRQL old;

	/* 只关心以太承载。别的介质（回环、隧道伪接口等）本平面不管。 */
	if (BindParameters->MediaType != NdisMedium802_3)
		return NDIS_STATUS_NOT_SUPPORTED;
	if (BindParameters->MacAddressLength != 6)
		return NDIS_STATUS_NOT_SUPPORTED;

	b = (IWAN_MP_BINDING *)IWAN_ALLOC(sizeof(*b), IWAN_TAG_PKT);
	if (b == NULL)
		return NDIS_STATUS_RESOURCES;
	RtlZeroMemory(b, sizeof(*b));
	b->ext = ext;
	b->bind_context = BindContext;
	b->ifindex = BindParameters->BoundIfIndex;
	b->mac_len = 6;
	RtlCopyMemory(b->mac, BindParameters->CurrentMacAddress, 6);

	RtlZeroMemory(&op, sizeof(op));
	op.Header.Type = NDIS_OBJECT_TYPE_OPEN_PARAMETERS;
	op.Header.Revision = NDIS_OPEN_PARAMETERS_REVISION_1;
	op.Header.Size = NDIS_SIZEOF_OPEN_PARAMETERS_REVISION_1;
	op.AdapterName = BindParameters->AdapterName;
	op.MediumArray = &medium;
	op.MediumArraySize = 1;
	/* SelectedMediumIndex 的类型是 PUINT（出参指针），不是索引值本身。
	 * 原来写 0 等于给 NULL：只有 MediumArraySize == 1 时 NDIS 才容忍省略，
	 * 一旦将来数组里多一种介质就会解引用空指针。这里给一个真实变量。 */
	op.SelectedMediumIndex = &sel_medium;
	op.FrameTypeArray = NULL;
	op.FrameTypeArraySize = 0;

	KeAcquireSpinLock(&g_bind_lock, &old);
	InsertTailList(&g_bindings, &b->link);
	KeReleaseSpinLock(&g_bind_lock, old);

	st = NdisOpenAdapterEx(ext->mp.proto_handle, b, &op, BindContext,
			       &b->binding);
	if (st == NDIS_STATUS_SUCCESS) {
		InterlockedExchange(&b->opened, 1);
		/* 同步打开成功 ⇒ bind 不返回 PENDING ⇒ 不需要
		 * NdisCompleteBindAdapterEx，直接回 SUCCESS 即完成绑定。 */
		return NDIS_STATUS_SUCCESS;
	}
	if (st == NDIS_STATUS_PENDING) {
		/* 异步打开：完成由 open_complete 收尾。这里**不能**动这条绑定
		 * （曾经在这里释放，等 open_complete 回来就是释放后使用）。 */
		return NDIS_STATUS_PENDING;
	}
	/* 硬失败：打关闭标记即可，内存留到 fini 统一释放 */
	iwan_win_proto_binding_close(b);
	return st;
}

static
_Function_class_(PROTOCOL_UNBIND_ADAPTER_EX)
NDIS_STATUS
iwan_win_proto_unbind(_In_ NDIS_HANDLE UnbindContext,
		      _In_ NDIS_HANDLE ProtocolBindingContext)
{
	IWAN_MP_BINDING *b = (IWAN_MP_BINDING *)ProtocolBindingContext;
	NDIS_STATUS st;
	ULONG i;

	b->unbind_context = UnbindContext;
	/* 顺序是"摘绑定 → 等在途归零 → 关句柄"，三步都不能换：
	 * ① 先摘：binding_close 在 mp->lock 里置 closed、清 mp->active，新的发送
	 *    从此拿不到它（出向在锁内复核 opened/closed）；
	 * ② 再等：已经拿到引用的发送在锁外分配 MDL/池之后才调
	 *    NdisSendNetBufferLists，只有等 b->outstanding 归零，才能保证没人还
	 *    攥着这个绑定句柄（窗口里有两次分配，不是几条指令）；
	 * ③ 最后关：NdisCloseAdapterEx 返回后句柄即失效，此时已无人可用它。
	 * 反过来（先关再等）会在关闭期间允许对失效句柄发送 —— DISPATCH 上的
	 * 0xD1，或绑定引用计数失衡。 */
	iwan_win_proto_binding_close(b);
	for (i = 0; i < 1000 && b->outstanding > 0; i++)
		KeStallExecutionProcessor(1000);
	if (b->outstanding > 0)
		DbgPrint("iwanmp: unbind 时仍有 %ld 条发送未完成，仍继续关闭\n",
			 (long)b->outstanding);
	st = NdisCloseAdapterEx(b->binding);
	if (st == NDIS_STATUS_PENDING) {
		/* 异步关闭：close_complete 收尾（同步路径不能替它完成 unbind） */
		return NDIS_STATUS_PENDING;
	}
	/* 同步关闭（成功或失败）：unbind 不返回 PENDING，NDIS 认为它已经完成，
	 * **不得**再调 NdisCompleteUnbindAdapterEx —— 那个 API 只用于给返回过
	 * PENDING 的 unbind 收尾，多调一次就是 unbind 记账失衡。 */
	return NDIS_STATUS_SUCCESS;
}

static
_Function_class_(SET_OPTIONS)
NDIS_STATUS
iwan_win_proto_set_options(_In_ NDIS_HANDLE NdisDriverHandle,
			   _In_ NDIS_HANDLE DriverContext)
{
	UNREFERENCED_PARAMETER(NdisDriverHandle);
	UNREFERENCED_PARAMETER(DriverContext);
	return NDIS_STATUS_SUCCESS;
}

static
_Function_class_(PROTOCOL_STATUS_EX)
VOID
iwan_win_proto_status(_In_ NDIS_HANDLE ProtocolBindingContext,
		      _In_ PNDIS_STATUS_INDICATION StatusIndication)
{
	UNREFERENCED_PARAMETER(ProtocolBindingContext);
	UNREFERENCED_PARAMETER(StatusIndication);
}

static
_Function_class_(PROTOCOL_NET_PNP_EVENT)
NDIS_STATUS
iwan_win_proto_pnp_event(_In_ NDIS_HANDLE ProtocolBindingContext,
			 _In_ PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification)
{
	UNREFERENCED_PARAMETER(ProtocolBindingContext);
	UNREFERENCED_PARAMETER(NetPnPEventNotification);
	return NDIS_STATUS_SUCCESS;
}

/* ---- 承载选择（会话 ↔ 网卡） ----------------------------------------- */

/* 由 IOCTL_OPEN 在会话建立后调用。判据：会话里的 oif_index 必须命中一张
 * 已打开的以太承载；下一跳取会话里的 outer_hop，为 0 就是"对端在链路上"。 */
NTSTATUS
iwan_win_mp_select_carrier(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	IWAN_MP_PLANE *mp = &ext->mp;
	IWAN_MP_BINDING *b;
	KIRQL old;

	if (s->oif_index == 0) {
		DbgPrint("iwanmp: 会话没有指定承载接口（oif_index=0），拒绝建立\n");
		return STATUS_INVALID_PARAMETER;
	}

	/* 旗子（g_proto_started）只在"表与锁都已初始化"之后才立起来，所以
	 * 它为 0 就等价于"这张表不可读"。NoProto=1、协议边注册全败、或者
	 * 卸载后再开会话，都会走到这里 —— 必须在这里拒绝，而不是让查表去
	 * 解引用一张全零的表。 */
	if (InterlockedCompareExchange(&g_proto_started, 1, 1) == 0) {
		DbgPrint("iwanmp: 协议边未启动（g_proto_started=0），拒绝建立\n");
		return STATUS_DEVICE_NOT_READY;
	}

	KeAcquireSpinLock(&g_bind_lock, &old);
	b = iwan_win_proto_lookup_locked(s->oif_index);
	KeReleaseSpinLock(&g_bind_lock, old);
	/* 放锁之后才落诊断：T70=1 ⇒ 表从来没被 InitializeListHead 过；
	 * T71=链上节点数，T70 不出现而 T71=0 ⇒ 表是好的但 NDIS 一条绑定都没
	 * 给过（协议边绑不上承载）。两种病因的处置完全不同。 */
	iwan_win_mp_trace(70,
			  InterlockedCompareExchange(&g_bind_table_broken, 1, 1));
	iwan_win_mp_trace(71, (LONG)iwan_win_proto_binding_count());
	if (b == NULL) {
		DbgPrint("iwanmp: 接口 %lu 上没有可用的以太承载，拒绝建立\n",
			 (unsigned long)s->oif_index);
		return STATUS_DEVICE_NOT_READY;
	}

	KeAcquireSpinLock(&mp->lock, &old);
	/* 查表（g_bind_lock）与这里赋值之间有窗口：若该绑定正好被 unbind，
	 * binding_close 的清理判据 `mp->active == b` 当时还不成立，于是 active
	 * 会停在一条已关闭的绑定上 —— 发包虽然会被 opened 复核挡住，但会话看
	 * 起来建立成功却一个字节都出不去。这里在同一个锁内复核一次。 */
	if (b->opened == 0 || b->closed != 0) {
		KeReleaseSpinLock(&mp->lock, old);
		DbgPrint("iwanmp: 承载接口 %lu 在选中瞬间被解绑，拒绝建立会话\n",
			 (unsigned long)s->oif_index);
		return STATUS_DEVICE_NOT_READY;
	}
	mp->active = b;
	mp->active_ifindex = b->ifindex;
	mp->next_hop_be = s->outer_hop != 0 ? s->outer_hop : s->outer_dst;
	RtlCopyMemory(mp->local_mac, b->mac, 6);
	InterlockedExchange(&mp->peer_mac_valid, 0);
	InterlockedExchange(&mp->peer_mac_pending, 0);
	mp->arp_ts_ms = 0;
	mp->arp_last_ms = 0;
	KeReleaseSpinLock(&mp->lock, old);

	DbgPrint("iwanmp: 承载 = 接口 %lu（%02x-%02x-%02x-%02x-%02x-%02x），"
		 "下一跳 %lu.%lu.%lu.%lu\n", (unsigned long)b->ifindex,
		 b->mac[0], b->mac[1], b->mac[2], b->mac[3], b->mac[4], b->mac[5],
		 (unsigned long)((mp->next_hop_be >> 24) & 0xFFu),
		 (unsigned long)((mp->next_hop_be >> 16) & 0xFFu),
		 (unsigned long)((mp->next_hop_be >> 8) & 0xFFu),
		 (unsigned long)(mp->next_hop_be & 0xFFu));
	return STATUS_SUCCESS;
}

VOID
iwan_win_mp_release_carrier(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	IWAN_MP_PLANE *mp = &ext->mp;
	KIRQL old;

	KeAcquireSpinLock(&mp->lock, &old);
	mp->active = NULL;
	mp->active_ifindex = 0;
	mp->next_hop_be = 0;
	InterlockedExchange(&mp->peer_mac_valid, 0);
	InterlockedExchange(&mp->peer_mac_pending, 0);
	mp->arp_ts_ms = 0;
	mp->arp_last_ms = 0;
	KeReleaseSpinLock(&mp->lock, old);
}

/* ---- 注册与注销 ------------------------------------------------------- */

NTSTATUS
iwan_win_proto_init(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	/* 单次注册被客体实测拒绝（小型端口侧 0xC0010005 = NDIS_STATUS_BAD_
	 * CHARACTERISTICS，见 mp.c 的说明），而且旧实验里"版本第一档就命中"是读到了
	 * 陈旧键。这里因此恢复候选表：每档落 T60+i，命中落 T69（值是声明
	 * 的次版本），全部失败落 T58 = 尝试次数。第一档没成功就继续试的前提是
	 * "没成功就不留句柄"：只有成功那一档会写 proto_handle。 */
	NDIS_PROTOCOL_DRIVER_CHARACTERISTICS ch;
	NDIS_STATUS last = NDIS_STATUS_BAD_CHARACTERISTICS;
	UCHAR runtime = (UCHAR)(NdisGetVersion() & 0xFFu);
	/* 0xFF = 用运行时次版本；后面几档是保守声明 */
	static const UCHAR cand_minor[] = { 0xFF, 0xFF, 0, 0, 80, 60, 30 };
	static const UCHAR cand_rev[] = {
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1,
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2,
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1,
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2,
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1,
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1,
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1
	};
	ULONG ci;

	/* 旗子 = "绑定表可读、出向池可用"，所以它必须最后由成功路径立起来。
	 * 反过来（先立旗、后初始化）就是客体上那次 0xD1：任何看到旗子的读者
	 * 都可能读到一张全零的表 —— BSS 里的 LIST_ENTRY 是 16 个零字节，不是
	 * 指向自己的空表，遍历到它就是把 0x30 当 ifindex 读。 */
	if (InterlockedCompareExchange(&g_proto_started, 0, 0) != 0)
		return STATUS_SUCCESS;

	InterlockedExchange(&g_bind_table_broken, 0);
	InitializeListHead(&g_bindings);
	KeInitializeSpinLock(&g_bind_lock);

	for (ci = 0; ci < RTL_NUMBER_OF(cand_minor); ci++) {
		UCHAR minor = cand_minor[ci] == 0xFF ? runtime : cand_minor[ci];
		NDIS_STATUS st;

		RtlZeroMemory(&ch, sizeof(ch));
		ch.Header.Type = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;
		ch.Header.Revision = cand_rev[ci];
		ch.Header.Size = (cand_rev[ci] ==
				  NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2) ?
			NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2 :
			NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1;
		ch.MajorNdisVersion = 6;
		ch.MinorNdisVersion = minor;
		ch.MajorDriverVersion = 1;
		ch.MinorDriverVersion = 0;
		ch.Flags = 0;
		NdisInitUnicodeString(&ch.Name, L"IWANMP");
		ch.SetOptionsHandler = iwan_win_proto_set_options;
		ch.BindAdapterHandlerEx = iwan_win_proto_bind;
		ch.UnbindAdapterHandlerEx = iwan_win_proto_unbind;
		ch.OpenAdapterCompleteHandlerEx = iwan_win_proto_open_complete;
		ch.CloseAdapterCompleteHandlerEx = iwan_win_proto_close_complete;
		ch.NetPnPEventHandler = iwan_win_proto_pnp_event;
		ch.OidRequestCompleteHandler = iwan_win_proto_oid_complete;
		ch.StatusHandlerEx = iwan_win_proto_status;
		ch.ReceiveNetBufferListsHandler = iwan_win_proto_recv_nbls;
		ch.SendNetBufferListsCompleteHandler = iwan_win_proto_send_complete;

		st = NdisRegisterProtocolDriver(ext, &ch,
						&ext->mp.proto_handle);
		iwan_win_mp_trace(60 + ci, (LONG)st);
		last = st;
		if (st == NDIS_STATUS_SUCCESS) {
			iwan_win_mp_trace(69, (LONG)minor);
			DbgPrint("iwanmp: 协议边已注册（NDIS 6.%u, rev %u）\n",
				 (unsigned)minor, (unsigned)cand_rev[ci]);
			/* 出向 NBL 池归协议边所有：生命周期必须包住所有在途外层
			 * 发送（完成回调里 NdisFreeNetBufferList），所以不能建在小型
			 * 端口里 —— 那条池会被 MiniportHaltEx 在设备重启时销毁。 */
			{
				NET_BUFFER_LIST_POOL_PARAMETERS pp;

				RtlZeroMemory(&pp, sizeof(pp));
				pp.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
				pp.Header.Revision =
					NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
				pp.Header.Size =
					NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
				pp.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
				pp.fAllocateNetBuffer = TRUE;
				pp.ContextSize = IWAN_MP_NBL_CTX_SIZE;
				pp.PoolTag = IWAN_TAG_PKT;
				ext->mp.tx_pool = NdisAllocateNetBufferListPool(
					ext->mp.proto_handle, &pp);
			}
			if (ext->mp.tx_pool == NULL) {
				/* 池建不出来就地注销：小型端口还没注册，失败是干净的。 */
				iwan_win_mp_trace(57, NDIS_STATUS_RESOURCES);
				NdisDeregisterProtocolDriver(ext->mp.proto_handle);
				ext->mp.proto_handle = NULL;
				InterlockedExchange(&g_proto_started, 0);
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			/* 到这里"表可读、池可用"才同时成立，旗子此刻立起来。
			 * 在此之前到达的会话请求都会被 select_carrier 挡掉。 */
			InterlockedExchange(&g_proto_started, 1);
			return STATUS_SUCCESS;
		}
	}
	/* 一档都没成功：不留半个句柄 */
	ext->mp.proto_handle = NULL;
	InterlockedExchange(&g_proto_started, 0);
	iwan_win_mp_trace(58, (LONG)RTL_NUMBER_OF(cand_minor));
	DbgPrint("iwanmp: NdisRegisterProtocolDriver 全部候选失败 0x%08lx\n",
		 (unsigned long)last);
	return last;
}

VOID
iwan_win_proto_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	PLIST_ENTRY e, n;
	ULONG i;
	KIRQL old;

	if (ext->mp.proto_handle == NULL)
		return;
	/* NdisDeregisterProtocolDriver 是 VOID（ndis.h:7975-7978），没有返回值
	 * 可查。真正兜住"回调已停"的是下面的在途计数排空：排不空就不放内存。
	 * 它会等所有回调返回，之后绑定表不再变化 —— 这是唯一安全的释放点。 */
	NdisDeregisterProtocolDriver(ext->mp.proto_handle);
	ext->mp.proto_handle = NULL;
	InterlockedExchange(&g_proto_started, 0);
	iwan_win_mp_release_carrier(ext);
	/* 在途外层发送归零之后才动内存：完成回调会解引用 b->ext/b->outstanding
	 * 并 NdisFreeNetBufferList。排不空就整体泄漏（驱动马上卸载）。 */
	for (i = 0; i < 1000 &&
	     (ext->mp.outer_outstanding > 0 || g_oid_pending > 0); i++)
		KeStallExecutionProcessor(1000);
	if (ext->mp.outer_outstanding > 0 || g_oid_pending > 0) {
		DbgPrint("iwanmp: 注销时仍有 %ld 条外层发送、%ld 个 OID 未完成，"
			 "绑定与池都不释放\n",
			 (long)ext->mp.outer_outstanding, (long)g_oid_pending);
		return;
	}
	if (ext->mp.tx_pool != NULL) {
		NdisFreeNetBufferListPool(ext->mp.tx_pool);
		ext->mp.tx_pool = NULL;
	}

	/* 只摘链，不释放：节点一旦 ExFreePoolWithTag，任何还在用 b 的路径
	 * （select_carrier 取到 b 之后放掉 g_bind_lock、再在 mp->lock 里复核
	 * b->opened/b->closed）就变成读已释放内存。驱动正在卸载，几个几十字节
	 * 的绑定泄漏远便宜于一次 bugcheck；而节点留着，链表指针永远指向有效
	 * 内存，即便有人拿着过期指针也只会走到表头自然终止。
	 * 曾经这里先置 b->link.Flink=NULL 再释放 —— 那正是 0xD1 的另一个触发
	 * 形态：遍历读到 Flink=NULL，随后 cmpl 0x30(%r14) 打在 0x30 上。 */
	KeAcquireSpinLock(&g_bind_lock, &old);
	/* 表头也要当不可信数据：卸载路径上这张表的值可能来自一次没走完的
	 * 初始化（Flink=NULL）。摘链前先确认它指向自己或一个真节点。 */
	if (g_bindings.Flink == NULL)
		InitializeListHead(&g_bindings);
	for (e = g_bindings.Flink; e != NULL && e != &g_bindings; e = n) {
		IWAN_MP_BINDING *b = CONTAINING_RECORD(e, IWAN_MP_BINDING, link);

		n = e->Flink;
		RemoveEntryList(e);
		b->opened = 0;
		b->closed = 1;
	}
	InitializeListHead(&g_bindings);
	KeReleaseSpinLock(&g_bind_lock, old);
}
