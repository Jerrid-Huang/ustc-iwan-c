/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_wfp.c — WFP callout 数据面：出向封装 +（M2）入向解封。
 *
 * 对应 Linux 侧 kernel/iwan_tx.c 的 iwan_xmit（出向）与 kernel/iwan_rx.c 的
 * 钩子（入向）。线上格式与 Linux 模块**逐字节一致**，这是互通的硬前提：
 *
 *   外层 IPv4(20) | 外层 UDP(8) | iWAN 帧头(8) | [XOR 后的内层 IP 包]
 *   iWAN 帧头：fh[0] = PT_DATA(0x14) 或 PT_DATA_ENC(0x18)
 *              fh[1] = enc 标志（1/0）
 *              fh[2..3] = sid（大端）
 *              fh[4..7] = tok（大端）
 *   XOR：内层包（含它自己的 IP 头）从偏移 0 起按 key[i & 7] 逐字节异或；
 *        内层校验和必须在 XOR **之前**是明文校验和（Linux 侧同一注释：
 *        "此刻校验和已是明文校验和，XOR 后仍自洽"）。
 *
 * 与 Linux 侧的关键差别（都是平台差异，不是语义差异）：
 *   · Linux 靠"路由到 iwan0"决定哪些包进隧道；这里靠会话下发的目标集合做
 *     最长前缀匹配（WFP 出向在路由之后，拿不到用户意图）；
 *   · 必须显式排除外层服务器地址（对应 Linux 侧"服务器 /32 钉在物理网卡"），
 *     否则目标集合里的宽前缀会把隧道自己的外层包也吸进来；
 *   · 内层报文可能带着"校验和卸载"标记到达（Linux 侧此刻校验和已就绪，
 *     Windows 侧不一定），所以这里在 XOR 之前按需用软件补齐内层校验和。
 *
 * M1 边界（明确不做的事，全部 fail-closed 并计数，绝不把明文放出去）：
 *   · 分段卸载的大段（内层长度 > 内层 MTU）暂不封装：计数后**丢弃**；
 *     不实现"透传"，避免明文泄漏；软件分段见 README 的 M1.1；
 *   · 非线性（数据跨多个 MDL）的报文暂不处理：计数后放行（不吸收）；
 *   · 入向解封在 M2，当前只匹配并计数。
 */
#include "iwan_win.h"

/* 每个 callout 用固定 GUID；用静态对象而不是 DEFINE_GUID，避免 initguid.h
 * 的实例化规则在驱动里引发重复定义。 */
static const GUID IWAN_CALLOUT_OUT4 = {
	0x7f3c1a10, 0x2b41, 0x4c8e, { 0x9a, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x01 }
};
static const GUID IWAN_CALLOUT_OUT6 = {
	0x7f3c1a10, 0x2b41, 0x4c8e, { 0x9a, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x02 }
};
static const GUID IWAN_CALLOUT_IN4 = {
	0x7f3c1a10, 0x2b41, 0x4c8e, { 0x9a, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x03 }
};
static const GUID IWAN_CALLOUT_IN6 = {
	0x7f3c1a10, 0x2b41, 0x4c8e, { 0x9a, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x04 }
};

#define IWAN_STAT_INC(ext, field) \
	InterlockedIncrement64((volatile LONG64 *)&(ext)->sess.stats.field)

/* 字节数累加：与 IWAN_STAT_INC 同一套约定（数据面只做互锁加法，
 * 用户态只读；统计不参与任何判定，允许读到略旧的值）。 */
#define IWAN_STAT_ADD(ext, field, v) \
	InterlockedAdd64((volatile LONG64 *)&(ext)->sess.stats.field, (LONG64)(v))

/* ---- 出向封装 --------------------------------------------------------- */

typedef struct _IWAN_INJECT_CTX {
	PVOID	buf;		/* 数据缓冲（注入完成后释放） */
	PMDL	mdl;		/* 数据缓冲的 MDL */
	IWAN_WIN_DEVICE_EXTENSION	*ext;	/* 用于在途注入计数 */
} IWAN_INJECT_CTX;

static VOID NTAPI
iwan_win_inject_complete(_In_ VOID *context, _Inout_ NET_BUFFER_LIST *nbl,
			 _In_ ULONG flags)
{
	IWAN_INJECT_CTX *ctx = (IWAN_INJECT_CTX *)context;

	UNREFERENCED_PARAMETER(flags);
	if (nbl != NULL)
		FwpsFreeNetBufferList(nbl);
	if (ctx != NULL) {
		if (ctx->mdl != NULL)
			IoFreeMdl(ctx->mdl);
		if (ctx->buf != NULL)
			ExFreePoolWithTag(ctx->buf, IWAN_TAG_PKT);
		if (ctx->ext != NULL)
			InterlockedDecrement(&ctx->ext->inject_outstanding);
		ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
	}
}

/*
 * 给一块非分页缓冲套上 NBL（数据不算在 NBL 池里，由 ctx 负责释放）。
 * 出向封装与入向解封注入共用：两条路都是"自己的缓冲 + 自己的 MDL"。
 */
static NTSTATUS
iwan_win_nbl_wrap(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		  _Inout_ IWAN_INJECT_CTX *ctx, _Out_ NET_BUFFER_LIST **out_nbl,
		  _In_ ULONG len)
{
	NET_BUFFER_LIST *nbl = NULL;
	NET_BUFFER *nb;
	NTSTATUS st;

	ctx->mdl = IoAllocateMdl(ctx->buf, len, FALSE, FALSE, NULL);
	if (ctx->mdl == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	MmBuildMdlForNonPagedPool(ctx->mdl);

	/* 池句柄由 iwan_win_wfp_init 预建：FwpsAllocateNetBufferAndNetBufferList0
	 * 要的是池句柄，不是在栈上摆一份池参数 */
	st = FwpsAllocateNetBufferAndNetBufferList(ext->nbl_pool, 0, 0, NULL, 0, 0,
						   &nbl);
	if (!NT_SUCCESS(st))
		return st;

	nb = NET_BUFFER_LIST_FIRST_NB(nbl);
	NET_BUFFER_FIRST_MDL(nb) = ctx->mdl;
	NET_BUFFER_DATA_OFFSET(nb) = 0;
	NET_BUFFER_DATA_LENGTH(nb) = len;
	NET_BUFFER_CURRENT_MDL(nb) = ctx->mdl;
	NET_BUFFER_CURRENT_MDL_OFFSET(nb) = 0;
	*out_nbl = nbl;
	return STATUS_SUCCESS;
}

/*
 * 把内层 IPv4 包封装成外层 UDP 并注入协议栈。
 * inner 指向**只读**的内层报文；本函数自己复制一份再变换，
 * 绝不改动协议栈正在用的缓冲（Linux 侧是独占 skb 才原地改）。
 */
/*
 * 出向封装 + 注入。外层用 v4 还是 v6 由**会话**决定（outer_v6），与内层版本
 * 无关 —— 这一点照 Linux 侧：内层版本由 iwan_inner_hdr_check() 判，外层版本
 * 由承载网卡决定，所以 v6-in-v4 与 v4-in-v6 都成立。
 *
 * 失败一律自己回收，绝不让"半封装"的缓冲流出去。
 */
static NTSTATUS
iwan_win_encap_inject(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		      _In_reads_bytes_(inner_len) const UINT8 *inner,
		      _In_ ULONG inner_len, _In_ BOOLEAN l4_offloaded,
		      _In_ UINT16 compartment, _In_ BOOLEAN outer_v6)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	IWAN_INJECT_CTX *ctx = NULL;
	NET_BUFFER_LIST *nbl = NULL;
	UINT8 *buf, *fh;
	ULONG overhead = outer_v6 ? IWAN_OUTER6_TOTAL : IWAN_OUTER4_TOTAL;
	ULONG total = overhead + inner_len;
	ULONG flen = IWAN_FRAME_HDR_LEN + inner_len;
	NTSTATUS st;

	if (inner_len == 0 || total > 0xFFFF)
		return STATUS_INVALID_BUFFER_SIZE;

	ctx = (IWAN_INJECT_CTX *)IWAN_ALLOC(sizeof(*ctx), IWAN_TAG_PKT);
	if (ctx == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	buf = (UINT8 *)IWAN_ALLOC(total, IWAN_TAG_PKT);
	if (buf == NULL) {
		ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	ctx->buf = buf;
	ctx->ext = ext;

	/* 帧紧跟在 IP + UDP 之后：overhead 是"封装总开销"，比帧的起始偏移多出
	 * 一个帧头长度。先摆帧，再让 portable 层去写外层头（两个校验和都在那里）。 */
	fh = buf + overhead - IWAN_FRAME_HDR_LEN;
	iwan_win_build_frame_hdr(fh, s->enc ? PT_DATA_ENC : PT_DATA, s->enc,
				 s->sid, s->tok);
	RtlCopyMemory(fh + IWAN_FRAME_HDR_LEN, inner, inner_len);
	/* 明文校验和 -> XOR（顺序不能颠倒：接收侧解出明文时校验和必须已经正确） */
	iwan_win_inner_fix_csum(fh + IWAN_FRAME_HDR_LEN, inner_len, l4_offloaded);
	if (s->enc)
		iwan_win_xor(fh + IWAN_FRAME_HDR_LEN, inner_len, s->key, 0);

	if (outer_v6) {
		if (iwan_win_outer_hdr6(buf, total, flen, s->outer_src6,
					s->outer_dst6, s->sport,
					s->dport) != total)
			goto fail;
	} else {
		if (iwan_win_outer_hdr4(buf, total, flen, s->outer_src,
					s->outer_dst, s->sport,
					s->dport) != total)
			goto fail;
	}

	st = iwan_win_nbl_wrap(ext, ctx, &nbl, total);
	if (!NT_SUCCESS(st))
		goto fail;

	/* 在途注入计数：注销/卸载时必须等它归零，才谈得上销毁注入句柄与池 */
	InterlockedIncrement(&ext->inject_outstanding);
	st = FwpsInjectNetworkSendAsync(outer_v6 ? ext->inj_send6 : ext->inj_send4,
					NULL, 0, compartment, nbl,
					iwan_win_inject_complete, ctx);
	if (!NT_SUCCESS(st)) {
		/* 注入失败：注入所有权没有转移，自己收回 */
		InterlockedDecrement(&ext->inject_outstanding);
		FwpsFreeNetBufferList(nbl);
		goto fail;
	}
	return STATUS_SUCCESS;

fail:
	if (nbl != NULL)
		FwpsFreeNetBufferList(nbl);
	if (ctx->mdl != NULL)
		IoFreeMdl(ctx->mdl);
	ExFreePoolWithTag(buf, IWAN_TAG_PKT);
	ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
	return STATUS_INSUFFICIENT_RESOURCES;
}

static VOID NTAPI
iwan_win_classify_out4(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
		       _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
		       _Inout_opt_ void *layerData,
		       _In_opt_ const void *classifyContext,
		       _In_ const FWPS_FILTER *filter,
		       _In_ UINT64 flowContext,
		       _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
	IWAN_WIN_DEVICE_EXTENSION *ext =
		(IWAN_WIN_DEVICE_EXTENSION *)(ULONG_PTR)filter->context;
	IWAN_WIN_SESSION *s;
	NET_BUFFER_LIST *nbl = (NET_BUFFER_LIST *)layerData;
	NET_BUFFER_LIST *cur;
	UINT16 compartment = 0;
	BOOLEAN all_hit = TRUE;
	NTSTATUS st;

	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);

	if (classifyOut->rights == 0 ||
	    (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
		return;
	classifyOut->actionType = FWP_ACTION_CONTINUE;

	if (ext == NULL || nbl == NULL)
		return;
	/* 快速路径：没有会话时一个 volatile 读就返回（Linux 侧同样先看开关） */
	s = &ext->sess;
	if (s->valid == 0 || s->inner_ip == 0)
		return;

	if (!ExAcquireRundownProtection(&ext->rundown))
		return;

	if (s->valid == 0)			/* 取得保护后再确认一次 */
		goto done;

	if (inMetaValues != NULL &&
	    FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
					   FWPS_METADATA_FIELD_COMPARTMENT_ID))
		compartment = (UINT16)inMetaValues->compartmentId;

	/* 先整块判定：只要有一个报文不该进隧道，就整块放行，
	 * 绝不做"吸收一半"（半个 NBL 被吃掉会让协议栈状态错乱）。 */
	for (cur = nbl; cur != NULL; cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
		NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
		UINT8 *pkt;
		ULONG len, ihl, tot;

		if (nb == NULL) {
			all_hit = FALSE;
			break;
		}
		len = NET_BUFFER_DATA_LENGTH(nb);
		/* 需要一个连续的头部才能解析；非线性报文不处理 */
		pkt = (UINT8 *)NdisGetDataBuffer(nb, len < IWAN_OUTER_IP4_LEN ?
						      len : IWAN_OUTER_IP4_LEN,
						 NULL, 1, 0);
		if (pkt == NULL || len < IWAN_OUTER_IP4_LEN || (pkt[0] >> 4) != 4) {
			IWAN_STAT_INC(ext, tx_bad_inner);
			all_hit = FALSE;
			break;
		}
		ihl = (ULONG)(pkt[0] & 0x0F) * 4;
		tot = iwan_win_rd16(pkt + 2);
		if (ihl < IWAN_OUTER_IP4_LEN || tot < ihl || tot > len) {
			IWAN_STAT_INC(ext, tx_bad_inner);
			all_hit = FALSE;
			break;
		}
		if (!iwan_win_should_tunnel4(s->targets, s->target_count,
						  (const UINT8 *)&s->outer_dst, pkt + 16)) {
			all_hit = FALSE;
			break;
		}
		/* 装不下就丢（fail-closed）：绝不透传明文。
		 * M1.1 在这里做软件分段（对应 Linux 侧 GSO 分支）。 */
		if (tot + IWAN_OUTER4_TOTAL > s->carrier_mtu) {
			IWAN_STAT_INC(ext, tx_bad_inner);
			classifyOut->actionType = FWP_ACTION_BLOCK;
			classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
			goto done;
		}
	}

	if (!all_hit)
		goto done;

	for (cur = nbl; cur != NULL; cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
		NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
		NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO ci;
		BOOLEAN l4_offloaded = FALSE;
		UINT8 *pkt;
		ULONG tot;

		pkt = (UINT8 *)NdisGetDataBuffer(nb, NET_BUFFER_DATA_LENGTH(nb),
						 NULL, 1, 0);
		if (pkt == NULL) {		/* 判定时连续、这里不连续：不可能，保险 */
			IWAN_STAT_INC(ext, tx_bad_inner);
			goto done;
		}
		tot = iwan_win_rd16(pkt + 2);
		/* 出向 IP 包层拿到的报文可能仍带"校验和由网卡补"的标记：
		 * 内层一旦被 XOR，网卡就再也补不了，所以必须先自己算。 */
		ci.Value = NET_BUFFER_LIST_INFO(cur, TcpIpChecksumNetBufferListInfo);
		if (ci.Transmit.TcpChecksum || ci.Transmit.UdpChecksum)
			l4_offloaded = TRUE;

		st = iwan_win_encap_inject(ext, pkt, tot, l4_offloaded, compartment,
					   iwan_win_session_is_v6(s));
		if (!NT_SUCCESS(st)) {
			IWAN_STAT_INC(ext, tx_err);
			goto done;
		}
		IWAN_STAT_INC(ext, tx_pkts);
		/* tx_bytes 记的是送出承载网卡的外层字节（含封装开销），
		 * 便于与网卡计数直接对照 —— 与 Linux 侧口径注释一致。 */
		InterlockedAdd64((volatile LONG64 *)&s->stats.tx_bytes,
				 (LONG64)(tot + IWAN_OUTER4_TOTAL));
	}

	/* 全部封装完成：吸收原报文，让它不再走正常出向路径 */
	classifyOut->actionType = FWP_ACTION_BLOCK;
	classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

done:
	ExReleaseRundownProtection(&ext->rundown);
}

/* ---- callout：入向（M2 才解封，M1 只匹配并计数） ---------------------- */

/*
 * 入向判定：这个包是不是"本隧道的、我们能处理的数据帧"。
 * 五元组命中（源=外层服务器、外层端口成对）才算我们的包；命中之后，
 * 处理不了的一律吞掉（绝不放给本机协议栈，否则残缺/伪造的隧道内容会被
 * 当成正常入站流量）；只有校验通过的控制帧才原样放行给用户态套接字 ——
 * 与 kernel/iwan_rx.c 同一策略：数据帧内核收，控制帧转用户态。
 */
/* 一个 NBL 链上最多按这么多报文做判定：WFP 通常一个链一个报文，批量是
 * 可能出现的形态。超出上限时整块吞掉（隧道流量宁可丢弃，也不漏给本机
 * 协议栈），并计入 ev_dropped。 */
#define IWAN_WIN_MAX_BATCH	64u

#define IWAN_WIN_IN_NONE	0u	/* 不是我们的包：放行 */
#define IWAN_WIN_IN_CTRL	1u	/* 控制帧：记账后放行给用户态 */
#define IWAN_WIN_IN_DATA	2u	/* 数据帧：解封后注入本机协议栈 */
#define IWAN_WIN_IN_DROP	3u	/* 是我们的包但处理不了：吞掉 */

static UINT32
iwan_win_inbound_kind(_In_ const IWAN_WIN_SESSION *s,
		      _In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		      _Out_ IWAN_WIN_OUTER *o)
{
	/* 五元组：源地址必须是外层服务器，源端口 = 服务端端口，
	 * 目的端口 = 本会话端口（客户端套接字就绑在它上面）。 */
	if (len < IWAN_OUTER_IP4_LEN + IWAN_OUTER_UDP_LEN ||
	    pkt[9] != IWAN_IPPROTO_UDP)
		return IWAN_WIN_IN_NONE;
	if (RtlCompareMemory(pkt + 12, &s->outer_dst, 4) != 4)
		return IWAN_WIN_IN_NONE;
	if (iwan_win_rd16(pkt + IWAN_OUTER_IP4_LEN + 0) != s->dport ||
	    iwan_win_rd16(pkt + IWAN_OUTER_IP4_LEN + 2) != s->sport)
		return IWAN_WIN_IN_NONE;

	/* 到这里这条包就是我们的：解析不了（分片、截断、长度撒谎）就吞掉 */
	if (!iwan_win_outer_parse4(pkt, len, o))
		return IWAN_WIN_IN_DROP;

	switch (iwan_win_frame_classify(o, s->sid, s->tok, s->enc != 0, TRUE)) {
	case IWAN_WIN_FRAME_DATA:
		return IWAN_WIN_IN_DATA;
	case IWAN_WIN_FRAME_CTRL:
		return IWAN_WIN_IN_CTRL;
	default:
		return IWAN_WIN_IN_DROP;
	}
}

/* 解封后的内层包重新交给网络层（v4/v6 各一个句柄） */
static NTSTATUS
iwan_win_inject_net_recv(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			 _In_reads_bytes_(len) const UINT8 *inner, _In_ ULONG len,
			 _In_ UINT32 family, _In_ UINT32 ifindex,
			 _In_ UINT16 compartment)
{
	IWAN_INJECT_CTX *ctx;
	NET_BUFFER_LIST *nbl = NULL;
	HANDLE handle;
	NTSTATUS st;

	handle = (family == 6) ? ext->inj_recv6 : ext->inj_recv4;

	ctx = (IWAN_INJECT_CTX *)IWAN_ALLOC(sizeof(*ctx), IWAN_TAG_PKT);
	if (ctx == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	ctx->buf = IWAN_ALLOC(len, IWAN_TAG_PKT);
	ctx->ext = ext;
	if (ctx->buf == NULL) {
		ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlCopyMemory(ctx->buf, inner, len);

	st = iwan_win_nbl_wrap(ext, ctx, &nbl, len);
	if (!NT_SUCCESS(st)) {
		if (ctx->mdl != NULL)
			IoFreeMdl(ctx->mdl);
		ExFreePoolWithTag(ctx->buf, IWAN_TAG_PKT);
		ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
		return st;
	}

	InterlockedIncrement(&ext->inject_outstanding);
	/* 参数表（10 个）：handle, context, flags, addressFamily, compartment,
	 * interfaceIndex, subInterfaceIndex, nbl, complete, completeContext —— 少写
	 * addressFamily 会让后面全部错位，而且错得"能编译过但行为诡异"的地方在
	 * 于 IF_INDEX 与 COMPARTMENT_ID 同为整数。 */
	st = FwpsInjectNetworkReceiveAsync(handle, NULL, 0,
					   family == 6 ? AF_INET6 : AF_INET,
					   compartment, (IF_INDEX)ifindex, 0, nbl,
					   iwan_win_inject_complete, ctx);
	if (!NT_SUCCESS(st)) {
		InterlockedDecrement(&ext->inject_outstanding);
		FwpsFreeNetBufferList(nbl);
		IoFreeMdl(ctx->mdl);
		ExFreePoolWithTag(ctx->buf, IWAN_TAG_PKT);
		ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
	}
	return st;
}

/* 入向 v6 的判定：与外层 v4 同一套闸门，只是地址/端口字段换成 v6。
 * 外层 v6 由 iwan_tx_outer6 构造：nexthdr 直接是 UDP，没有扩展头。 */
static UINT32
iwan_win_inbound_kind6(_In_ const IWAN_WIN_SESSION *s,
		       _In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		       _Out_ IWAN_WIN_OUTER *o)
{
	if (len < IWAN_OUTER6_TOTAL || pkt[6] != IWAN_IPPROTO_UDP)
		return IWAN_WIN_IN_NONE;
	if (RtlCompareMemory(pkt + 8, s->outer_dst6, 16) != 16)
		return IWAN_WIN_IN_NONE;
	if (iwan_win_rd16(pkt + IWAN_OUTER_IP6_LEN + 0) != s->dport ||
	    iwan_win_rd16(pkt + IWAN_OUTER_IP6_LEN + 2) != s->sport)
		return IWAN_WIN_IN_NONE;
	if (!iwan_win_outer_parse6(pkt, len, o))
		return IWAN_WIN_IN_DROP;
	switch (iwan_win_frame_classify(o, s->sid, s->tok, s->enc != 0, TRUE)) {
	case IWAN_WIN_FRAME_DATA:
		return IWAN_WIN_IN_DATA;
	case IWAN_WIN_FRAME_CTRL:
		return IWAN_WIN_IN_CTRL;
	default:
		return IWAN_WIN_IN_DROP;
	}
}

static VOID NTAPI
iwan_win_classify_in4(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
		      _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
		      _Inout_opt_ void *layerData,
		      _In_opt_ const void *classifyContext,
		      _In_ const FWPS_FILTER *filter,
		      _In_ UINT64 flowContext,
		      _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
	iwan_win_inbound_worker(inFixedValues, inMetaValues, layerData,
				classifyContext, filter, flowContext,
				classifyOut, FALSE);
}

static VOID NTAPI
iwan_win_classify_in6(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
		      _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
		      _Inout_opt_ void *layerData,
		      _In_opt_ const void *classifyContext,
		      _In_ const FWPS_FILTER *filter,
		      _In_ UINT64 flowContext,
		      _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
	iwan_win_inbound_worker(inFixedValues, inMetaValues, layerData,
				classifyContext, filter, flowContext,
				classifyOut, TRUE);
}

static VOID NTAPI
iwan_win_inbound_worker(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
		      _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
		      _Inout_opt_ void *layerData,
		      _In_opt_ const void *classifyContext,
		      _In_ const FWPS_FILTER *filter,
		      _In_ UINT64 flowContext,
		      _Inout_ FWPS_CLASSIFY_OUT *classifyOut,
		      _In_ BOOLEAN outer_v6)
{
	IWAN_WIN_DEVICE_EXTENSION *ext =
		(IWAN_WIN_DEVICE_EXTENSION *)(ULONG_PTR)filter->context;
	IWAN_WIN_SESSION *s;
	NET_BUFFER_LIST *nbl = (NET_BUFFER_LIST *)layerData;
	NET_BUFFER_LIST *cur;
	UINT16 compartment = 0;
	UINT32 ifindex = 0;
	BOOLEAN all_ours = TRUE, overflow = FALSE;
	UINT32 kinds[IWAN_WIN_MAX_BATCH];
	ULONG lens[IWAN_WIN_MAX_BATCH];
	ULONG n = 0;			/* 本批报文数 */
	ULONG i;

	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);

	if (classifyOut->rights == 0 ||
	    (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
		return;
	classifyOut->actionType = FWP_ACTION_CONTINUE;
	if (ext == NULL || nbl == NULL)
		return;

	s = &ext->sess;
	if (s->valid == 0 || iwan_win_session_is_v6(s) != outer_v6)
		return;
	if (!ExAcquireRundownProtection(&ext->rundown))
		return;
	if (s->valid == 0)
		goto done;

	if (inMetaValues != NULL) {
		if (FWPS_IS_METADATA_FIELD_PRESENT(
			    inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID))
			compartment = (UINT16)inMetaValues->compartmentId;
		if (inMetaValues->interfaceIndex != 0)
			ifindex = (UINT32)inMetaValues->interfaceIndex;
	}

	/* 第一遍：整块判定。只要有一个包不是我们的（或超出批缓冲），
	 * 就整块放行 —— 绝不做"吸收一半"。 */
	for (cur = nbl; cur != NULL; cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
		NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
		UINT8 *pkt;
		ULONG len;
		IWAN_WIN_OUTER o;
		UINT32 kind;

		if (nb == NULL || n >= IWAN_WIN_MAX_BATCH) {
			/* 结构异常（空 NB）或批过大：整块吞掉 */
			overflow = TRUE;
			break;
		}
		len = NET_BUFFER_DATA_LENGTH(nb);
		pkt = (UINT8 *)NdisGetDataBuffer(nb, len, NULL, 1, 0);
		if (pkt == NULL) {
			/* 非线性：不处理也不吸收 */
			all_ours = FALSE;
			break;
		}
		kind = (outer_v6 ? iwan_win_inbound_kind6 : iwan_win_inbound_kind)(s, pkt, len, &o);
		if (kind == IWAN_WIN_IN_NONE) {
			all_ours = FALSE;
			break;
		}
		kinds[n] = kind;
		lens[n] = len;
		n++;
	}

	if (overflow) {
		IWAN_STAT_INC(ext, ev_dropped);
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		goto done;
	}
	if (!all_ours || n == 0)
		goto done;

	/* 第二遍：逐包处理。控制帧放行（不吸收），其余吞掉。 */
	{
		BOOLEAN absorb = FALSE;

		i = 0;
		for (cur = nbl; cur != NULL;
		     cur = NET_BUFFER_LIST_NEXT_NBL(cur), i++) {
			NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
			UINT8 *pkt = (UINT8 *)NdisGetDataBuffer(nb, lens[i], NULL, 1, 0);
			IWAN_WIN_OUTER o;

			if (pkt == NULL || !(outer_v6 ? iwan_win_outer_parse6 : iwan_win_outer_parse4)(pkt, lens[i], &o)) {
				IWAN_STAT_INC(ext, rx_bad_hdr);
				absorb = TRUE;
				continue;
			}

			switch (kinds[i]) {
			case IWAN_WIN_IN_CTRL:
				/* 有效控制帧 ⇒ 对端活着；PT_CLOSE 再把时间戳归零
				 * （用户态见到 0 即判断开，与 Linux 同语义）。
				 * 帧本身不吸收：用户态套接字要收到它。 */
				iwan_win_session_mark_rx(s, 1);
				if (o.type == PT_CLOSE)
					iwan_win_session_mark_close(s);
				IWAN_STAT_INC(ext, rx_ctrl_frame);
				break;
			case IWAN_WIN_IN_DATA: {
				UINT8 *inner;
				ULONG ilen;

				iwan_win_session_mark_rx(s, 0);
				IWAN_STAT_INC(ext, rx_outer);
				IWAN_STAT_INC(ext, rx_frames);
				IWAN_STAT_INC(ext, rx_pkts);

				inner = (UINT8 *)IWAN_ALLOC(o.inner_len, IWAN_TAG_PKT);
				if (inner == NULL) {
					IWAN_STAT_INC(ext, rx_nomem);
					absorb = TRUE;
					break;
				}
				UINT32 fam;

				ilen = iwan_win_decap(pkt, lens[i], &o, s->key,
						      inner, o.inner_len);
				fam = ilen != 0 ? iwan_win_inner_family(inner, ilen)
						: 0;
				if (ilen == 0 || fam == 0 ||
				    !iwan_win_inner_sane(inner, ilen)) {
					/* 结构不合法就不注入：宁可丢这一个内层包，
					 * 也不让畸形包进入本机协议栈 */
					IWAN_STAT_INC(ext, rx_bad_inner);
					ExFreePoolWithTag(inner, IWAN_TAG_PKT);
					absorb = TRUE;
					break;
				}
				if (!NT_SUCCESS(iwan_win_inject_net_recv(
						ext, inner, ilen, fam, ifindex,
						compartment))) {
					IWAN_STAT_INC(ext, rx_nomem);
				} else {
					IWAN_STAT_INC(ext, rx_delivered);
				}
				ExFreePoolWithTag(inner, IWAN_TAG_PKT);
				absorb = TRUE;	/* 内层已交付，外层不再上栈 */
				break;
			}
			default:
				IWAN_STAT_INC(ext, rx_bad_hdr);
				absorb = TRUE;
				break;
			}
		}

		if (absorb) {
			classifyOut->actionType = FWP_ACTION_BLOCK;
			classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		}
	}

done:
	ExReleaseRundownProtection(&ext->rundown);
}

/* v6 的两层：M3。当前只放行，绝不改动报文。 */
/*
 * 出向 v6：判定完全用 v6 目标集合（最长前缀 + 服务器外层地址除外），封装时
 * 外层族由会话决定 —— 所以 v6-in-v4（外层 v4 会话承载内层 v6）与 v6-in-v6
 * 都走这里，正如 Linux 侧 iwan_tx_outer4/6 与内层版本无关。
 *
 * 大小闸门：内层 + 外层封装开销不得越过 65535（外层 v6 不分片，超了只能丢）。
 */
static VOID NTAPI
iwan_win_classify_out6(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
		       _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
		       _Inout_opt_ void *layerData,
		       _In_opt_ const void *classifyContext,
		       _In_ const FWPS_FILTER *filter,
		       _In_ UINT64 flowContext,
		       _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
	IWAN_WIN_DEVICE_EXTENSION *ext =
		(IWAN_WIN_DEVICE_EXTENSION *)(ULONG_PTR)filter->context;
	IWAN_WIN_SESSION *s;
	NET_BUFFER_LIST *nbl = (NET_BUFFER_LIST *)layerData;
	ULONG overhead;
	BOOLEAN all_ours = TRUE, overflow = FALSE;
	UINT32 kinds[IWAN_WIN_MAX_BATCH];
	ULONG lens[IWAN_WIN_MAX_BATCH];
	ULONG n = 0;

	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);

	if (classifyOut->rights == 0 ||
	    (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
		return;
	classifyOut->actionType = FWP_ACTION_CONTINUE;
	if (ext == NULL || nbl == NULL)
		return;

	s = &ext->sess;
	if (s->valid == 0)
		return;
	overhead = iwan_win_session_is_v6(s) ? IWAN_OUTER6_TOTAL
					     : IWAN_OUTER4_TOTAL;

	{
		NET_BUFFER_LIST *cur;

		for (cur = nbl; cur != NULL;
		     cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
			NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
			UINT8 *pkt;
			ULONG len;

			if (nb == NULL || n >= IWAN_WIN_MAX_BATCH) {
				overflow = TRUE;
				break;
			}
			len = NET_BUFFER_DATA_LENGTH(nb);
			pkt = (UINT8 *)NdisGetDataBuffer(nb, len, NULL, 1, 0);
			if (pkt == NULL || len < 40 ||
			    iwan_win_inner_family(pkt, len) != 6 ||
			    !iwan_win_inner_sane(pkt, len)) {
				all_ours = FALSE;
				break;
			}
			if (!iwan_win_should_tunnel6(s->targets, s->target_count,
						     s->outer_dst6, pkt + 24)) {
				all_ours = FALSE;
				break;
			}
			if ((ULONG)(overhead + len) > 0xFFFF) {
				all_ours = FALSE;
				break;
			}
			kinds[n] = IWAN_WIN_IN_DATA;
			n++;
		}
	}

	if (overflow) {
		IWAN_STAT_INC(ext, ev_dropped);
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		return;
	}
	if (!all_ours || n == 0)
		return;
	if (!ExAcquireRundownProtection(&ext->rundown))
		return;
	if (s->valid == 0)
		goto done;

	{
		NET_BUFFER_LIST *cur;
		UINT16 compartment = 0;

		if (inMetaValues != NULL &&
		    FWPS_IS_METADATA_FIELD_PRESENT(
			    inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID))
			compartment = (UINT16)inMetaValues->compartmentId;

		for (cur = nbl; cur != NULL;
		     cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
			NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
			ULONG len = NET_BUFFER_DATA_LENGTH(nb);
			UINT8 *pkt = (UINT8 *)NdisGetDataBuffer(nb, len, NULL, 1, 0);
			NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO ci;
			BOOLEAN l4_offloaded = FALSE;

			if (pkt == NULL) {
				IWAN_STAT_INC(ext, tx_bad_inner);
				all_ours = FALSE;
				continue;
			}
			ci.Value = NET_BUFFER_LIST_INFO(cur,
							TcpIpChecksumNetBufferListInfo);
			if (ci.Transmit.TcpChecksum || ci.Transmit.UdpChecksum)
				l4_offloaded = TRUE;
			if (l4_offloaded) {
				/* 分段/校验和卸载的大段：M1.1 尚未做软件切分，
				 * 保持 fail-closed（计数并吞掉，不发明文） */
				IWAN_STAT_INC(ext, tx_bad_state);
				continue;
			}
			if (!NT_SUCCESS(iwan_win_encap_inject(
					ext, pkt, len, l4_offloaded, compartment,
					iwan_win_session_is_v6(s)))) {
				IWAN_STAT_INC(ext, tx_err);
				continue;
			}
			IWAN_STAT_INC(ext, tx_pkts);
			IWAN_STAT_ADD(ext, tx_bytes, len + overhead);
		}
	}

done:
	ExReleaseRundownProtection(&ext->rundown);
	/* 能走到这里说明整批都命中目标集合：一律吸收（已经封装并注入外层包）。
	 * 单包注入失败也在上面计了 tx_err —— 宁可丢这一个包，也绝不放明文出去。 */
	classifyOut->actionType = FWP_ACTION_BLOCK;
	classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
}

static NTSTATUS NTAPI
iwan_win_notify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
		_In_ const GUID *filterKey, _Inout_ FWPS_FILTER *filter)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);
	return STATUS_SUCCESS;
}

/* ---- 注册/注销 -------------------------------------------------------- */

static NTSTATUS
iwan_win_add_callout(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		     _In_ PDEVICE_OBJECT devobj, _In_ const GUID *key,
		     _In_ FWPS_CALLOUT_CLASSIFY_FN classify,
		     _In_ FWP_ACTION_TYPE action,
		     _In_ const GUID *layer, _In_ PCWSTR name,
		     _Out_ UINT32 *callout_id)
{
	FWPS_CALLOUT callout;
	FWPM_CALLOUT mcallout;
	FWPM_FILTER filter;
	NTSTATUS st;

	RtlZeroMemory(&callout, sizeof(callout));
	callout.calloutKey = *key;
	callout.flags = 0;
	callout.classifyFn = classify;
	callout.notifyFn = iwan_win_notify;
	callout.flowDeleteFn = NULL;

	st = FwpsCalloutRegister(devobj, &callout, callout_id);
	if (!NT_SUCCESS(st))
		return st;

	RtlZeroMemory(&mcallout, sizeof(mcallout));
	mcallout.calloutKey = *key;
	mcallout.displayData.name = (PWSTR)name;
	mcallout.flags = 0;		/* 动态会话下不持久化：句柄一关即清 */
	mcallout.applicableLayer = *layer;
	st = FwpmCalloutAdd(ext->engine, &mcallout, NULL, NULL);
	if (!NT_SUCCESS(st))
		return st;

	RtlZeroMemory(&filter, sizeof(filter));
	filter.layerKey = *layer;
	filter.displayData.name = (PWSTR)name;
	filter.action.type = action;
	filter.action.calloutKey = *key;
	filter.weight.type = FWP_EMPTY;		/* 由 BFE 自动分配权重 */
	filter.numFilterConditions = 0;		/* 全部报文进 callout，由我们判断 */
	filter.filterCondition = NULL;
	filter.context = (UINT64)(ULONG_PTR)ext;
	return FwpmFilterAdd(ext->engine, &filter, NULL, NULL);
}

NTSTATUS
iwan_win_wfp_init(_In_ PDEVICE_OBJECT devobj,
		  _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	FWPM_SESSION session;
	NTSTATUS st;

	RtlZeroMemory(&session, sizeof(session));
	/* 动态会话：引擎句柄一关，本驱动加进去的 callout 与过滤器全部消失
	 * （即使驱动崩溃也不会留下半套规则），与 Linux 侧模块卸载即摘钩子等价。 */
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	st = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &ext->engine);
	if (!NT_SUCCESS(st))
		return st;

	/* 注入用的 NBL 池：整驱动一个，报文缓冲另行分配 */
	{
		NET_BUFFER_LIST_POOL_PARAMETERS pp;

		RtlZeroMemory(&pp, sizeof(pp));
		pp.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
		pp.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
		pp.Header.Size =
			NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
		pp.fAllocateNetBuffer = TRUE;
		pp.PoolTag = IWAN_TAG_PKT;
		st = NdisAllocateNetBufferListPool(NULL, &pp, &ext->nbl_pool);
		if (!NT_SUCCESS(st))
			return st;
	}

	st = FwpsInjectionHandleCreate(AF_INET, FWPS_INJECTION_TYPE_NETWORK,
				       &ext->inj_send4);
	if (!NT_SUCCESS(st))
		return st;
	st = FwpsInjectionHandleCreate(AF_INET6, FWPS_INJECTION_TYPE_NETWORK,
				       &ext->inj_send6);
	if (!NT_SUCCESS(st))
		return st;
	/* 入向解封后要把内层 IP 包重新交给网络层（FwpsInjectNetworkReceiveAsync0），
	 * 所以这里同样是 NETWORK 类型，而不是 TRANSPORT —— 传输层注入拿到的是
	 * "传输载荷"，而我们要交回去的是完整的内层 IP 包。 */
	st = FwpsInjectionHandleCreate(AF_INET, FWPS_INJECTION_TYPE_NETWORK,
				       &ext->inj_recv4);
	if (!NT_SUCCESS(st))
		return st;
	st = FwpsInjectionHandleCreate(AF_INET6, FWPS_INJECTION_TYPE_NETWORK,
				       &ext->inj_recv6);
	if (!NT_SUCCESS(st))
		return st;

	st = iwan_win_add_callout(ext, devobj, &IWAN_CALLOUT_OUT4,
				  iwan_win_classify_out4,
				  FWP_ACTION_CALLOUT_TERMINATING,
				  &FWPM_LAYER_OUTBOUND_IPPACKET_V4,
				  L"iwan out4", &ext->callout_id_out4);
	if (!NT_SUCCESS(st))
		return st;
	st = iwan_win_add_callout(ext, devobj, &IWAN_CALLOUT_IN4,
				  iwan_win_classify_in4,
				  FWP_ACTION_CALLOUT_TERMINATING,
				  &FWPM_LAYER_INBOUND_IPPACKET_V4,
				  L"iwan in4", &ext->callout_id_in4);
	if (!NT_SUCCESS(st))
		return st;
	st = iwan_win_add_callout(ext, devobj, &IWAN_CALLOUT_OUT6,
				  iwan_win_classify_out6,
				  FWP_ACTION_CALLOUT_TERMINATING,
				  &FWPM_LAYER_OUTBOUND_IPPACKET_V6,
				  L"iwan out6", &ext->callout_id_out6);
	if (!NT_SUCCESS(st))
		return st;
	st = iwan_win_add_callout(ext, devobj, &IWAN_CALLOUT_IN6,
				  iwan_win_classify_in6,
				  FWP_ACTION_CALLOUT_TERMINATING,
				  &FWPM_LAYER_INBOUND_IPPACKET_V6,
				  L"iwan in6", &ext->callout_id_in6);
	if (!NT_SUCCESS(st))
		return st;

	ext->wfp_ready = TRUE;
	return STATUS_SUCCESS;
}

VOID
iwan_win_wfp_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	ULONG spin;
	if (ext->callout_id_out4 != 0)
		FwpsCalloutUnregisterById(ext->callout_id_out4);
	if (ext->callout_id_in4 != 0)
		FwpsCalloutUnregisterById(ext->callout_id_in4);
	if (ext->callout_id_out6 != 0)
		FwpsCalloutUnregisterById(ext->callout_id_out6);
	if (ext->callout_id_in6 != 0)
		FwpsCalloutUnregisterById(ext->callout_id_in6);
	ext->callout_id_out4 = ext->callout_id_in4 = 0;
	ext->callout_id_out6 = ext->callout_id_in6 = 0;

	/* 排空在途注入：完成回调要归还 NBL 到池、释放报文缓冲。注销 callout
	 * 已保证不再有新的注入进来，这里只等已发出的那批回完。有界等待后仍
	 * 不归零，说明有注入卡在协议栈里；此时宁可留下句柄与池不释放
	 * （内存泄漏），也不冒释放后仍被引用的风险 —— 卸载路径上，泄漏比
	 * 蓝屏可接受。 */
	for (spin = 0; spin < 20000; spin++) {
		if (ext->inject_outstanding == 0)
			break;
		KeStallExecutionProcessor(100);
	}
	if (ext->inject_outstanding != 0) {
		DbgPrint("iwan-win: 仍有过期注入 %ld 个，保留注入句柄与 NBL 池不释放\n",
			 ext->inject_outstanding);
		ext->engine = NULL;
		ext->wfp_ready = FALSE;
		return;
	}

	if (ext->inj_send4 != NULL)
		FwpsInjectionHandleDestroy(ext->inj_send4);
	if (ext->inj_send6 != NULL)
		FwpsInjectionHandleDestroy(ext->inj_send6);
	if (ext->inj_recv4 != NULL)
		FwpsInjectionHandleDestroy(ext->inj_recv4);
	if (ext->inj_recv6 != NULL)
		FwpsInjectionHandleDestroy(ext->inj_recv6);
	ext->inj_send4 = ext->inj_send6 = ext->inj_recv4 = ext->inj_recv6 = NULL;

	if (ext->nbl_pool != NULL) {
		NdisFreeNetBufferListPool(ext->nbl_pool);
		ext->nbl_pool = NULL;
	}

	if (ext->engine != NULL) {
		FwpmEngineClose(ext->engine);
		ext->engine = NULL;
	}
	ext->wfp_ready = FALSE;
}
