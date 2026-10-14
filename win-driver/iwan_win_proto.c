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
	NDIS_HANDLE		bind_context;	/* 完成 bind/unbind 时要回传的句柄 */
	UINT32			ifindex;
	UINT8			mac[6];
	ULONG			mac_len;
	volatile LONG		opened;		/* 1=打开成功，可收发 */
	volatile LONG		outstanding;	/* 已发出、未完成的 NBL 数 */
} IWAN_MP_BINDING;

/* 绑定表是驱动级的：协议驱动在 DriverEntry 注册，早于小型端口（PnP）出现，
 * 也晚于它消失，所以不能挂在设备扩展里。 */
static LIST_ENTRY	g_bindings;
static KSPIN_LOCK	g_bind_lock;
static volatile LONG	g_proto_started;	/* g_bindings/g_bind_lock 已初始化 */

/* 发送在途上下文：挂在 NBL 的 context 区，完成回调据此归还缓冲与 MDL */
typedef struct _IWAN_MP_TX_CTX {
	UINT8			*buf;		/* IWAN_ALLOC 的整帧（含以太头） */
	PMDL			mdl;
} IWAN_MP_TX_CTX;

/* 池的 context 区必须放得下它（池在 iwan_win_mp.c 里按 IWAN_MP_NBL_CTX_SIZE
 * 建；这个断言是两侧唯一的耦合点）。 */
C_ASSERT(sizeof(IWAN_MP_TX_CTX) <= IWAN_MP_NBL_CTX_SIZE);

/* 绑定表查找：按接口索引找一张已打开的承载。调用者需持有 g_bind_lock。 */
static IWAN_MP_BINDING *
iwan_win_proto_lookup_locked(_In_ UINT32 ifindex)
{
	PLIST_ENTRY e;

	for (e = g_bindings.Flink; e != &g_bindings; e = e->Flink) {
		IWAN_MP_BINDING *b = CONTAINING_RECORD(e, IWAN_MP_BINDING, link);

		if (b->ifindex == ifindex && b->opened)
			return b;
	}
	return NULL;
}

/* 从绑定表摘除并释放。调用者不得持有 g_bind_lock。 */
static VOID
iwan_win_proto_binding_unlink(_Inout_ IWAN_MP_BINDING *b)
{
	KIRQL old;

	KeAcquireSpinLock(&g_bind_lock, &old);
	if (b->link.Flink != NULL) {
		RemoveEntryList(&b->link);
		b->link.Flink = NULL;
		b->link.Blink = NULL;
	}
	KeReleaseSpinLock(&g_bind_lock, old);
	ExFreePoolWithTag(b, IWAN_TAG_PKT);
}

/* ---- 邻居（ARP） ------------------------------------------------------- */

/* 组一个 ARP 请求：who-has next_hop tell local_mac。返回帧长（以太+ARP）。 */
static ULONG
iwan_win_proto_build_arp4(_In_ IWAN_WIN_DEVICE_EXTENSION *ext, _Out_ UINT8 *eth,
			  _In_ ULONG bufsz)
{
	IWAN_MP_PLANE *mp = &ext->mp;
	UINT8 *a;
	ULONG i;

	if (bufsz < IWAN_MP_ETH_HDR_LEN + 28u)
		return 0;

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

	return IWAN_MP_ETH_HDR_LEN + 28u;
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
	if (a[7] != 0x01 && a[7] != 0x02)	/* 只认请求与回复 */
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
	/* 走同一条发送路径：send_outer4 只管把帧交给网卡，不看以太类型 */
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
	if (!valid && mp->active != NULL && mp->peer_mac_pending == 0 &&
	    (mp->arp_last_ms == 0 || now - mp->arp_last_ms >= IWAN_MP_ARP_RETRY_MS)) {
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
			   _In_reads_bytes_(len) UINT8 *eth, _In_ ULONG len)
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
		NdisAllocateNetBufferAndNetBufferList(mp->nbl_pool,
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

	NdisSendNetBufferLists(b->binding, nbl, NDIS_DEFAULT_PORT_NUMBER, 0);
	return TRUE;
}

/* 发送完成：归还缓冲、清在途。可能在 DISPATCH_LEVEL。 */
static VOID
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
static const UINT8 *
iwan_win_proto_view(_In_ NET_BUFFER *nb, _In_ ULONG need,
		    _Inout_opt_ UINT8 *stor, _In_ ULONG stor_sz)
{
	if (need == 0 || need > IWAN_MP_RECV_MAX)
		return NULL;
	if (stor != NULL && stor_sz >= need)
		return (const UINT8 *)NdisGetDataBuffer(nb, need, stor, 1, 0);
	return (const UINT8 *)NdisGetDataBuffer(nb, need, NULL, 1, 0);
}

/* 命中判定：帧内 IPv4 目的地址 = 会话外层源地址、UDP 目的端口 = 会话源端口。
 * 与 WFP 平面入向闸门同一口径（那边地址取自固定字段，这边从帧里读）。 */
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
		if (p == NULL)
			return TRUE;
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
		ExFreePoolWithTag(tmp, IWAN_TAG_PKT);
		return TRUE;
	}
}

/* 收到一批 NBL。本边一枚都不向上指示：同一条链路上的常规 TCP/IP 绑定是
 * 另一个协议驱动，它自己会收；我们只挑走本会话的外层帧，其余原样归还。 */
static VOID
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
	/* 带 RESOURCES 表示数据只在本次调用期间有效，不带时我们同样立刻归还
	 * （本边不留 NBL）。两种情况都不需要看 DISPATCH_LEVEL 位 —— 本文件
	 * 全部代码都能在 DISPATCH_LEVEL 跑。 */
	UNREFERENCED_PARAMETER(ReceiveFlags);

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
	NdisReturnNetBufferLists(b->binding, NetBufferLists, 0);
}

/* ---- 绑定生命周期 ----------------------------------------------------- */

static VOID
iwan_win_proto_open_complete(_In_ NDIS_HANDLE ProtocolBindingContext,
			     _In_ NDIS_STATUS Status)
{
	IWAN_MP_BINDING *b = (IWAN_MP_BINDING *)ProtocolBindingContext;

	if (Status == NDIS_STATUS_SUCCESS)
		InterlockedExchange(&b->opened, 1);
	/* bind 的完成回执：BindAdapterEx 返回 PENDING 时由这里收尾 */
	NdisCompleteBindAdapterEx(b->bind_context, Status);
}

static VOID
iwan_win_proto_close_complete(_In_ NDIS_HANDLE ProtocolBindingContext)
{
	IWAN_MP_BINDING *b = (IWAN_MP_BINDING *)ProtocolBindingContext;

	InterlockedExchange(&b->opened, 0);
	NdisCompleteUnbindAdapterEx(b->bind_context);
	iwan_win_proto_binding_unlink(b);
}

static NDIS_STATUS
iwan_win_proto_bind(_In_ NDIS_HANDLE ProtocolDriverContext,
		    _In_ NDIS_HANDLE BindContext,
		    _In_ PNDIS_BIND_PARAMETERS BindParameters)
{
	IWAN_WIN_DEVICE_EXTENSION *ext =
		(IWAN_WIN_DEVICE_EXTENSION *)ProtocolDriverContext;
	IWAN_MP_BINDING *b;
	NDIS_OPEN_PARAMETERS op;
	NDIS_MEDIUM medium = NdisMedium802_3;
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
	op.SelectedMediumIndex = 0;
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
	iwan_win_proto_binding_unlink(b);
	return st;
}

static NDIS_STATUS
iwan_win_proto_unbind(_In_ NDIS_HANDLE UnbindContext,
		      _In_ NDIS_HANDLE ProtocolBindingContext)
{
	IWAN_MP_BINDING *b = (IWAN_MP_BINDING *)ProtocolBindingContext;
	NDIS_STATUS st;

	b->bind_context = UnbindContext;
	InterlockedExchange(&b->opened, 0);
	st = NdisCloseAdapterEx(b->binding);
	if (st == NDIS_STATUS_SUCCESS) {
		/* close 同步完成：CloseAdapterComplete 不会再来，自己收尾 */
		NdisCompleteUnbindAdapterEx(UnbindContext);
		iwan_win_proto_binding_unlink(b);
		return NDIS_STATUS_SUCCESS;
	}
	if (st != NDIS_STATUS_PENDING)
		iwan_win_proto_binding_unlink(b);	/* 关不掉也得把表清干净 */
	return st;
}

static NDIS_STATUS
iwan_win_proto_set_options(_In_ NDIS_HANDLE NdisDriverHandle,
			   _In_ NDIS_HANDLE DriverContext)
{
	UNREFERENCED_PARAMETER(NdisDriverHandle);
	UNREFERENCED_PARAMETER(DriverContext);
	return NDIS_STATUS_SUCCESS;
}

static VOID
iwan_win_proto_status(_In_ NDIS_HANDLE ProtocolBindingContext,
		      _In_ PNDIS_STATUS_INDICATION StatusIndication)
{
	UNREFERENCED_PARAMETER(ProtocolBindingContext);
	UNREFERENCED_PARAMETER(StatusIndication);
}

static NDIS_STATUS
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

	KeAcquireSpinLock(&g_bind_lock, &old);
	b = iwan_win_proto_lookup_locked(s->oif_index);
	KeReleaseSpinLock(&g_bind_lock, old);
	if (b == NULL) {
		DbgPrint("iwanmp: 接口 %lu 上没有可用的以太承载，拒绝建立\n",
			 (unsigned long)s->oif_index);
		return STATUS_DEVICE_NOT_READY;
	}

	KeAcquireSpinLock(&mp->lock, &old);
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
	/* 声明的 NDIS 次版本必须被这台机器的 NDIS 接受：客体实测小型端口侧
	 * 声明 6.30 被拒（0xC0010005），改成运行时版本才通过，协议侧很可能
	 * 是同一条规矩（0 = 运行时版本）。逐个候选试，每个候选的结果各落一个
	 * 键（阶段 60 起），一次装机就能看清是哪一档被接受。 */
	static const UCHAR minors[] = { 0u, 85u, 80u, 60u, 30u };
	NDIS_PROTOCOL_DRIVER_CHARACTERISTICS ch;
	NDIS_STATUS st = NDIS_STATUS_NOT_SUPPORTED;
	UCHAR runtime = (UCHAR)(NdisGetVersion() & 0xFFu);
	ULONG mi;

	if (InterlockedExchange(&g_proto_started, 1) != 0)
		return STATUS_SUCCESS;

	InitializeListHead(&g_bindings);
	KeInitializeSpinLock(&g_bind_lock);

	for (mi = 0; mi < RTL_NUMBER_OF(minors); mi++) {
		UCHAR minor = (mi == 0) ? runtime : minors[mi];

	RtlZeroMemory(&ch, sizeof(ch));
	ch.Header.Type = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;
	ch.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1;
	ch.Header.Size = NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1;
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
	ch.StatusHandlerEx = iwan_win_proto_status;
	ch.ReceiveNetBufferListsHandler = iwan_win_proto_recv_nbls;
	ch.SendNetBufferListsCompleteHandler = iwan_win_proto_send_complete;
	/* 不发 OID：MAC 与接口索引都从 BindParameters 里取（协议驱动特有），
	 * 所以不需要 OidRequestCompleteHandler / DirectOidRequestCompleteHandler */

	st = NdisRegisterProtocolDriver(ext, &ch, &ext->mp.proto_handle);
	iwan_win_mp_trace(60u + mi, (LONG)st);
	if (st == NDIS_STATUS_SUCCESS) {
		/* 69 = 命中：低 8 位是声明的次版本 */
		iwan_win_mp_trace(69, (LONG)minor);
		DbgPrint("iwanmp: 协议边已注册（NDIS 6.%u）\n",
			 (unsigned)minor);
		return STATUS_SUCCESS;
	}
	DbgPrint("iwanmp: NdisRegisterProtocolDriver 6.%u 失败 0x%08lx\n",
		 (unsigned)minor, (unsigned long)st);
	}	/* for (mi) */

	InterlockedExchange(&g_proto_started, 0);
	return st;
}

VOID
iwan_win_proto_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	PLIST_ENTRY e, n;

	if (ext->mp.proto_handle == NULL)
		return;
	/* NdisDeregisterProtocolDriver 会等所有回调返回，之后绑定表不再变化 */
	NdisDeregisterProtocolDriver(ext->mp.proto_handle);
	ext->mp.proto_handle = NULL;
	InterlockedExchange(&g_proto_started, 0);

	/* 正常情况下 unbind 回调已经清空了表；这里只兜底（例如注册后立刻
	 * 注销、NDIS 还没走完 unbind）。 */
	for (e = g_bindings.Flink; e != &g_bindings; e = n) {
		IWAN_MP_BINDING *b = CONTAINING_RECORD(e, IWAN_MP_BINDING, link);

		n = e->Flink;
		iwan_win_proto_binding_unlink(b);
	}
}
