/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_wfp.c — WFP callout 数据面：出向封装 +（M2）入向解封。
 *
 * 两层的位置（入向这一层是特意选的）：
 *   · 出向：FWPS_LAYER_OUTBOUND_IPPACKET_V4/V6 —— IP 头已组好、还没分片；
 *   · 入向：FWPS_LAYER_INBOUND_TRANSPORT_V4/V6 —— **协议栈重组之后**：外层分片
 *     已经拼好、IP 头已被摘掉，layerData 从 UDP 头开始，地址由 WFP 固定字段给。
 *     Linux 侧是站在"两次重组之间"自己补一次 ip_defrag（见 kernel/iwan_rx.c 的
 *     注释），Windows 侧把这一步交给协议栈，换来的是不必自己处理分片。
 *   · 注入仍然回到**重组之前**（网络层 FwpsInjectNetworkReceiveAsync）：内层包
 *     照常走完整的 IP 解析、重组与分流 —— 与 Linux 侧解封后 NF_ACCEPT/netif_rx
 *     回到 ip_defrag 之前同一语义。
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
 *   · 非线性（数据跨多个 MDL）的报文暂不处理：计数后放行（不吸收）。
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

/*
 * 关于静态分析里的 C6014（"Leaking memory 'ctx' / 'buf' / 'nbl' / 'stor'"）：
 * 本文件里这类告警全部是误报，判读依据写在这里，免得下一轮有人照着告警
 * 去"修"一处本来就正确的所有权转移。
 *
 *   · ctx / ctx->buf：分配之后交给 FwpsInject*Async 的完成回调
 *     iwan_win_inject_complete 释放（同一文件 :96-101）。WFP 的注入接口
 *     没有 SAL 注解说明这条转移，分析器只看见"分配了、函数返回前没释放"。
 *     真实现上两条失败路径（同步失败 goto fail、异步失败回调）都各释放
 *     一次，成功路径恰好一次 —— 已在客体上按逐包对账验证过（1,375,401 帧
 *     100% 投递、无泄漏性硬挂）。
 *   · nbl（iwan_win_mp.c 的 indicate_inner）：交给
 *     NdisMIndicateReceiveNetBufferLists 之后归 NDIS，归还时由
 *     MiniportReturnNetBufferLists 释放，这是 NDIS 的池所有权约定。
 *   · stor（classify_out6）：循环体内的临时拼接缓冲，本文件内三处
 *     ExFreePoolWithTag + 置空，每条 continue 前都已归还。
 *   · ext / devobj（DriverEntry）：驱动生命周期资产，随设备对象与卸载路径
 *     释放，不随函数返回释放。
 *
 * 判据：只要"分配点"与"释放点"在同一个函数的两条互斥路径上，且每条路径
 * 恰好释放一次，这条告警就是误报。上面四类都逐条核对过。
 *
 * 处置：分析与构建都带 /FI shared\warning.h，但 C6014 是分析器对"所有权
 * 转移不在它能读懂的契约里"的判断，不随头部告警一起消失，因此在每个分配点
 * 上方放一行 `#pragma warning(suppress: 6014)`，并就地写明判据。这么做不是
 * 为了把日志刷干净 —— 只有把已知误报逐个压掉，下一次新出现的 C6014 才有
 * 可能被看见。改这些抑制时请先读对应注释，再读那段代码。
 */

typedef struct _IWAN_INJECT_CTX {
	PVOID	buf;		/* 数据缓冲（注入完成后释放） */
	PMDL	mdl;		/* 数据缓冲的 MDL */
	IWAN_WIN_DEVICE_EXTENSION	*ext;	/* 用于在途注入计数 */
} IWAN_INJECT_CTX;

static VOID NTAPI
iwan_win_inject_complete(_In_ VOID *context, _Inout_ NET_BUFFER_LIST *nbl,
			 _In_ BOOLEAN dispatch_level)
{
	IWAN_INJECT_CTX *ctx = (IWAN_INJECT_CTX *)context;

	UNREFERENCED_PARAMETER(dispatch_level);
	/* 临时诊断：入向注入"排队成功"不等于"上栈成功"，完成回调里的
	 * NET_BUFFER_LIST_STATUS 才是 WFP 的最终裁决。成功/失败各占一个
	 * 空闲计数器，失败时把状态码原值累加进 rx_reasm（同码多次 -> 可除）。 */
	if (ctx != NULL && ctx->ext != NULL) {
		ULONG ist = nbl != NULL ? NET_BUFFER_LIST_STATUS(nbl)
					: (ULONG)0xC0000001L;

		if (ist == STATUS_SUCCESS)
			IWAN_STAT_INC(ctx->ext, rx_batch_skip);
		else {
			IWAN_STAT_INC(ctx->ext, rx_batch);
			IWAN_STAT_ADD(ctx->ext, rx_reasm, (LONG64)ist);
		}
	}
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
	NTSTATUS st;

	ctx->mdl = IoAllocateMdl(ctx->buf, len, FALSE, FALSE, NULL);
	if (ctx->mdl == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	MmBuildMdlForNonPagedPool(ctx->mdl);

	/* MDL 直接交给分配器，而不是事后再往 NET_BUFFER_FIRST_MDL 上塞：
	 * NBL 从出生那一刻就是完整形态，不依赖“分配完再改内部字段”这种
	 * 未文档化的用法。MDL 的所有权仍在调用者（ctx->mdl 由完成回调或
	 * 失败路径 IoFreeMdl 释放），这里只是借给 NBL 描述数据。
	 * 池句柄由 iwan_win_wfp_init 预建：FwpsAllocateNetBufferAndNetBufferList0
	 * 要的是池句柄，不是在栈上摆一份池参数。 */
	st = FwpsAllocateNetBufferAndNetBufferList(ext->nbl_pool, 0, 0, ctx->mdl,
						   0, len, &nbl);
	if (!NT_SUCCESS(st))
		return st;

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
/* 在途注入上限（每个在途包约占 2 KB 非分页池：缓冲 + MDL + NBL，要等完成
 * 回调才归还）。没有上限的现场是：洪泛速率远高于承载通道（实测 21k pps），
 * 出向吸收又同时取消了发送端的反压 —— 池以 GB/s 量级净增长，秒级耗尽非分页
 * 池，整机硬挂且来不及写 BugCheck（对应 Kernel-Power 41 + 6008）。
 * 超限就丢当前包并计 tx_bad_state，把背压还给协议栈。 */
#define IWAN_WIN_MAX_INFLIGHT 1024u

/* 出向被拒/被丢的原因记录：实现在 iwan_win_session.c（两个数据面共用），
 * 这里只剩调用点。 */

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

	if (inner_len == 0 || total > 0xFFFF) {
		return STATUS_INVALID_BUFFER_SIZE;
	}

	if (ext->inject_outstanding >= IWAN_WIN_MAX_INFLIGHT) {
		/* 在途窗口满 = 主动限流，不是封装失败。诊断区必须分开记，
		 * 否则现场会把"背压丢包"读成"报文畸形"。 */
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_INFLIGHT, inner_len,
				 total, inner_len > 0 ? (ULONG)inner[0] : 0xFFFFu,
				 inner);
		IWAN_STAT_INC(ext, tx_bad_state);
		return STATUS_DEVICE_BUSY;
	}

	/* C6014 误报：ctx 与 buf 的所有权随 NBL 一起交给
	 * FwpsInjectNetworkSendAsync0，由完成回调 iwan_win_inject_complete
	 * 释放。WFP 的注入接口没有"所有权转移"的 SAL 注解，分析器只看得见
	 * "分配了、返回前没释放"，此处的抑制是判读结论而非免责。 */
#pragma warning(suppress: 6014)
	ctx = (IWAN_INJECT_CTX *)IWAN_ALLOC(sizeof(*ctx), IWAN_TAG_PKT);
	if (ctx == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	/* 同上：buf 由完成回调释放。 */
#pragma warning(suppress: 6014)
	buf = (UINT8 *)IWAN_ALLOC(total, IWAN_TAG_PKT);
	if (buf == NULL) {
		ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	ctx->buf = buf;
	ctx->ext = ext;
	/* 池分配不保证清零（见 iwan_win.h 的 IWAN_ALLOC 注释）：外层首部构造失败
	 * 时也会走 fail，那时 mdl 还没被 nbl_wrap 赋值，不初始化就会读到野指针
	 * 并把它交给 IoFreeMdl。 */
	ctx->mdl = NULL;

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
					s->dport) != total) {
			goto fail;
		}
	} else {
		if (iwan_win_outer_hdr4(buf, total, flen, s->outer_src,
					s->outer_dst, s->sport,
					s->dport) != total) {
			goto fail;
		}
	}

	st = iwan_win_nbl_wrap(ext, ctx, &nbl, total);
	if (!NT_SUCCESS(st)) {
		goto fail;
	}

	/* 在途注入计数：注销/卸载时必须等它归零，才谈得上销毁注入句柄与池 */
	InterlockedIncrement(&ext->inject_outstanding);
	/* 注入句柄可能同步失败，也可能异步失败（完成回调里报 NTSTATUS）。
	 * 两种失败都由完成回调统一释放 ctx->buf / ctx->mdl / ctx，
	 * 也就是"交出去之后本函数不再拥有它们"。 */
	st = FwpsInjectNetworkSendAsync(outer_v6 ? ext->inj_send6 : ext->inj_send4,
					NULL, 0, compartment, nbl,
					iwan_win_inject_complete, ctx);
	if (!NT_SUCCESS(st)) {
		/* 注入失败：注入所有权没有转移，自己收回 */
		InterlockedDecrement(&ext->inject_outstanding);
		FwpsFreeNetBufferList(nbl);
		/* 必须置空：fail 分支还会判一次 nbl，不置空就是同一个 NBL 被释放
		 * 两次 —— 空闲链同一节点挂两遍，两个分配者拿到同一块内存，属于
		 * 静默的池损坏/随机硬挂（未开 Verifier 不会当场抓）。 */
		nbl = NULL;
		goto fail;
	}
	/* 注入成功：ctx 与 buf 的所有权已随 NBL 交给 WFP，完成回调
	 * （iwan_win_inject_complete）里释放。两个局部指针就地作废 —— 这是
	 * "所有权已转移"的唯一记号，也免得静态分析把它读成泄漏（C6014）。 */
	ctx = NULL;
	buf = NULL;
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

/*
 * 这个 NBL 是不是我们自己注入进去的？
 *
 * 注入不是“绕过协议栈”：注进去的包会重新走一遍同一层，于是又进我们的
 * classify。认不出来就会二次封装（外层套外层），所以出向必须放行自己注入
 * 的外层包、入向必须放行自己注入的内层包。用 WFP 自己的记账
 * （FwpsQueryPacketInjectionState0）判断，而不是靠“目的地址不在目标集合里”
 * 这种巧合。
 */
static BOOLEAN
iwan_win_nbl_from_self(_In_ HANDLE handle, _In_ const NET_BUFFER_LIST *nbl)
{
	FWPS_PACKET_INJECTION_STATE st;

	if (handle == NULL || nbl == NULL)
		return FALSE;
	/* 第三个参数是 [out, optional]，这里传 NULL，只取返回值 —— 返回值本身
	 * 就是注入状态。原因：WDK 10.0.26100 的 fwpsk.h 把它声明成 HANDLE *
	 * （文档写的是 FWPS_PACKET_INJECTION_STATE *），/WX 下 C4022 直接当错误。
	 * 传 NULL 后两种声明都能编过，语义也不依赖那个出参。
	 *
	 * 另外说明：即使这个判断因为声明差异失灵，也不会造成外层套外层 ——
	 * 目标集合判定时我们显式把对端地址（s->outer_dst）排除在外，自己注入
	 * 的外层包本来就不会命中目标。这里是第二道保险，不是唯一防线。 */
	st = FwpsQueryPacketInjectionState0(handle, nbl, NULL);
	return st == FWPS_PACKET_INJECTED_BY_SELF ||
	       st == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF;
}

/*
 * 出向入口：超长内层报文先按声明的内层 MTU 分片，再逐片封装。
 *
 * 口径与 Linux 对齐：Linux 侧是协议栈在 ndo_start_xmit 之前按外层设备 MTU 分好
 * 片、驱动只逐片封装；我们在 OUTBOUND_IPPACKET 拦截（那时还没分片），所以要
 * 自己补这一步。分片阈值取声明的内层 MTU（= min(服务器协商值, 承载 MTU - 开销)），
 * 因此每一片必然装得进承载，外层仍然 DF=1、永不分片。
 *
 * frames/bytes 回填"真正注入了几个外层帧、多少外层字节"：计数器必须按帧记，
 * 按原始报文记会让 tx_pkts 在分片场景下与网卡计数对不上。
 */
static NTSTATUS
iwan_win_encap_send_pkt(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			_In_reads_bytes_(len) const UINT8 *inner,
			_In_ ULONG len, _In_ BOOLEAN l4_offloaded,
			_In_ UINT16 compartment, _In_ BOOLEAN outer_v6,
			_Out_ ULONG *frames, _Out_ ULONG *bytes)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	UINT8 *copy = NULL, *frag = NULL;
	ULONG mtu = s->inner_mtu;
	ULONG n, i, flen = 0;
	NTSTATUS st;

	*frames = 1;
	*bytes = len + (outer_v6 ? IWAN_OUTER6_TOTAL : IWAN_OUTER4_TOTAL);
	if (outer_v6)
		return iwan_win_encap_inject(ext, inner, len, l4_offloaded,
					     compartment, TRUE);

	n = (mtu > IWAN_WIN_MTU_MIN) ? iwan_win_frag4_count(inner, len, mtu) : 0;
	if (n == 0)
		return iwan_win_encap_inject(ext, inner, len, l4_offloaded,
					     compartment, FALSE);

	copy = (UINT8 *)IWAN_ALLOC(len, IWAN_TAG_PKT);
	frag = (UINT8 *)IWAN_ALLOC(mtu, IWAN_TAG_PKT);
	if (copy == NULL || frag == NULL) {
		if (copy != NULL)
			ExFreePoolWithTag(copy, IWAN_TAG_PKT);
		if (frag != NULL)
			ExFreePoolWithTag(frag, IWAN_TAG_PKT);
		*frames = 0;
		*bytes = 0;
		IWAN_STAT_INC(ext, tx_bad_state);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlCopyMemory(copy, inner, len);
	/* L4 校验和必须在切之前修好：只有首片带 L4 头，切完再逐片修是不可能的。
	 * 修好之后每片都按"校验和已正确"封装（l4_offloaded = FALSE）。 */
	iwan_win_inner_fix_csum(copy, len, l4_offloaded);

	st = STATUS_SUCCESS;
	*frames = 0;
	*bytes = 0;
	for (i = 0; i < n; i++) {
		if (!iwan_win_frag4_build(frag, mtu, copy, len, mtu, i, &flen)) {
			IWAN_STAT_INC(ext, tx_bad_state);
			st = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		st = iwan_win_encap_inject(ext, frag, flen, FALSE, compartment,
					   FALSE);
		if (!NT_SUCCESS(st))
			break;
		(*frames)++;
		*bytes += flen + IWAN_OUTER4_TOTAL;
	}
	ExFreePoolWithTag(frag, IWAN_TAG_PKT);
	ExFreePoolWithTag(copy, IWAN_TAG_PKT);
	return st;
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
	UINT8 od[4];

	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);

	/* 先把"放行"写进结论，再谈别的。
	 *
	 * 本层挂的是**终止型**过滤器：终止型没有"下一条"可继续，结论只能是 PERMIT
	 * 或 BLOCK。写 CONTINUE（"不表态"）的现场是：会话一建立、全机流量两个方向
	 * 立刻中断 —— 出向 callout 明明被调用了 233 次、每次都返回放行，包却一个都
	 * 没出去；客体本身活得好好的，CLOSE 一返回立刻恢复。
	 * 写权限（FWPS_RIGHT_ACTION_WRITE）管的是"能不能收紧成 BLOCK"，不是"能不能
	 * 放行"：拿不到就只放行、不再收紧。 */
	classifyOut->actionType = FWP_ACTION_PERMIT;

	if (ext == NULL || nbl == NULL)
		return;

	/* 放行本身不是失败，但**必须留痕**：否则"会话在、包却一个没进隧道"会
	 * 表现为 17 个计数器全零，和"callout 压根没被调用"完全无法区分。 */
	if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
		IWAN_STAT_INC(ext, tx_bad_state);
		return;
	}

	/* 快速路径：没有会话时一个 volatile 读就返回（Linux 侧同样先看开关） */
	s = &ext->sess;
	if (s->valid == 0 || s->inner_ip == 0) {
		/* inner_ip 由客户端填。真实客户端曾经长期不填它 —— 这一支会放行
		 * 全部出向流量、一个包都不封装，而计数器全零（kdp_win.c:350 有
		 * 同样的记录）。所以这里必须计数。 */
		IWAN_STAT_INC(ext, tx_bad_state);
		return;
	}

	/* 自己注入的外层包：放行，绝不再封装一层 */
	if (iwan_win_nbl_from_self(ext->inj_send4, nbl) ||
	    iwan_win_nbl_from_self(ext->inj_send6, nbl))
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
		UINT8 hdr[IWAN_OUTER_IP4_LEN];
		UINT8 *pkt;
		ULONG len, ihl, tot;

		if (nb == NULL) {
			iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_NB_NULL, 0, 0, 0xFFFFu, NULL);
			all_hit = FALSE;
			break;
		}
		len = NET_BUFFER_DATA_LENGTH(nb);
		/* 头部可能跨 MDL（UDP 走校验和卸载时就是这样：首部与载荷分属
		 * 不同的内存块）。给一块 20 字节的栈缓冲让 NDIS 把头部拼进来，
		 * 不能像以前那样"取不到连续指针就判 HDR_BAD"——那样凡是不连续的
		 * 出向报文都被放行到承载网，现场表现就是隧道没有吞吐。
		 * 缓冲只有 20 字节且在栈上，不跨调用、不涉及非分页池。 */
		pkt = (UINT8 *)NdisGetDataBuffer(nb, IWAN_OUTER_IP4_LEN, hdr, 1, 0);
		if (pkt == NULL || (pkt[0] >> 4) != 4) {
			/* pkt == NULL 只可能是报文短于 20 字节（拼不出来） */
			iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_HDR_BAD, len, 0,
					 pkt != NULL ? (ULONG)pkt[0] : 0xFFFFu, pkt);
			IWAN_STAT_INC(ext, tx_bad_inner);
			all_hit = FALSE;
			break;
		}
		ihl = (ULONG)(pkt[0] & 0x0F) * 4;
		tot = iwan_win_rd16(pkt + 2);
		if (ihl < IWAN_OUTER_IP4_LEN || tot < ihl || tot > len) {
			iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_LEN_BAD, len, tot, pkt[0], pkt);
			IWAN_STAT_INC(ext, tx_bad_inner);
			all_hit = FALSE;
			break;
		}
		iwan_win_wr32(od, s->outer_dst);	/* 会话里是大端整数，这里要字节 */
		if (!iwan_win_should_tunnel4(s->targets, s->target_count,
						  od, pkt + 16)) {
			all_hit = FALSE;
			break;
		}
		/* 超长不再直接丢：v4 交给分片层（与 Linux 协议栈在 ndo_start_xmit
		 * 之前按设备 MTU 分片同口径）。只有在"连 8 字节片载荷都放不下"
		 * 的畸形阈值下才 fail-closed —— 绝不透传明文，也不让网卡去分。 */
		if (tot + IWAN_OUTER4_TOTAL > s->carrier_mtu &&
		    iwan_win_frag4_count(pkt, tot, s->inner_mtu) == 0) {
			iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_MTU, len, tot, pkt[0], pkt);
			IWAN_STAT_INC(ext, tx_bad_state);
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
		UINT8 hdr[IWAN_OUTER_IP4_LEN];
		UINT8 *stor = NULL;
		UINT8 *pkt;
		ULONG nblen, tot, frames, fbytes;

		nblen = NET_BUFFER_DATA_LENGTH(nb);
		/* 判定只需要前 20 字节连续，封装却需要**整包**连续：大包一跨 MDL，
		 * NdisGetDataBuffer(tot, NULL) 就返回 NULL —— 现场表现是"805 B ICMP
		 * 进得了隧道、1228 B UDP 一个都进不去"，也就是隧道没有吞吐。
		 * 这里给一块 tot 大小的非分页缓冲让 NDIS 把散块拼进来；拼好的内容紧
		 * 接着被封装层整块拷走，所以即用即还，不跨迭代持有。
		 * tot 上限由上面"装不下就丢"的分支保证（<= carrier_mtu），不会出现
		 * 巨帧级别的分配。*/
		pkt = (UINT8 *)NdisGetDataBuffer(nb, IWAN_OUTER_IP4_LEN, hdr, 1, 0);
		if (pkt == NULL || nblen < IWAN_OUTER_IP4_LEN) {
			iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_COALESCE, nblen, 0,
					 pkt != NULL ? (ULONG)pkt[0] : 0xFFFFu, pkt);
			IWAN_STAT_INC(ext, tx_bad_inner);
			goto done;
		}
		tot = iwan_win_rd16(pkt + 2);
		if (tot < IWAN_OUTER_IP4_LEN || tot > nblen) {
			IWAN_STAT_INC(ext, tx_bad_inner);
			goto done;
		}
		pkt = (UINT8 *)NdisGetDataBuffer(nb, tot, NULL, 1, 0);
		if (pkt == NULL) {
			stor = (UINT8 *)IWAN_ALLOC(tot, IWAN_TAG_PKT);
			if (stor == NULL) {
				/* 池压力下不能默默放明文出去 */
				IWAN_STAT_INC(ext, tx_err);
				classifyOut->actionType = FWP_ACTION_BLOCK;
				classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
				goto done;
			}
			pkt = (UINT8 *)NdisGetDataBuffer(nb, tot, stor, 1, 0);
			if (pkt == NULL) {
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_COALESCE,
						 nblen, tot, 0xFFFFu, NULL);
				ExFreePoolWithTag(stor, IWAN_TAG_PKT);
				IWAN_STAT_INC(ext, tx_bad_inner);
				goto done;
			}
		}
		/* 出向 IP 包层拿到的报文可能仍带"校验和由网卡补"的标记：
		 * 内层一旦被 XOR，网卡就再也补不了，所以必须先自己算。 */
		ci.Value = NET_BUFFER_LIST_INFO(cur, TcpIpChecksumNetBufferListInfo);
		if (ci.Transmit.TcpChecksum || ci.Transmit.UdpChecksum)
			l4_offloaded = TRUE;

		st = iwan_win_encap_send_pkt(ext, pkt, tot, l4_offloaded, compartment,
					     iwan_win_session_is_v6(s),
					     &frames, &fbytes);
		if (stor != NULL) {
			/* 封装层已整块拷走，这里即用即还 */
			ExFreePoolWithTag(stor, IWAN_TAG_PKT);
			/* 必须置空：下一轮若走零拷贝分支不再分配 stor，而循环末尾
			 * 还会判一次 stor —— 不置空就是同一块缓冲释放两次。 */
			stor = NULL;
		}
		if (!NT_SUCCESS(st)) {
			/* 命中目标集合的包没能进隧道 = 明文会漏到承载网。与"装不下
			 * 就丢"、以及 v6 侧 done: 的无条件吸收同一条规矩：宁可丢，
			 * 绝不透传。v4 这里原来只 goto done，动作还是 PERMIT。
			 * 在途窗口满（DEVICE_BUSY）已在 encap_inject 里记过
			 * INFLIGHT，这里不能再覆盖成 ENCAP_FAIL。 */
			if (st != STATUS_DEVICE_BUSY)
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_ENCAP_FAIL,
						 nblen, tot, pkt[0], pkt);
			IWAN_STAT_INC(ext, tx_err);
			classifyOut->actionType = FWP_ACTION_BLOCK;
			classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
			goto done;
		}
		/* 按帧记账：一个内层报文被分成 N 片时，网卡上看到的是 N 个外层
		 * 帧，tx_pkts/tx_bytes 必须与它逐帧对得上。 */
		IWAN_STAT_ADD(ext, tx_pkts, (LONG64)frames);
		/* tx_bytes 记的是送出承载网卡的外层字节（含封装开销），
		 * 便于与网卡计数直接对照 —— 与 Linux 侧口径注释一致。 */
		IWAN_STAT_ADD(ext, tx_bytes, (LONG64)fbytes);
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
 * 五元组里的地址那一半（协议必须是 UDP、源地址必须是外层服务器）由 worker 用
 * WFP 固定字段判 —— 传输层 IP 头已被摘掉，包上没得比；端口这一半在这里判，
 * 取自 UDP 头本身（iwan_win_dgram_parse 顺手填进 IWAN_WIN_OUTER）。
 * 命中之后，
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
	/* 端口成对：源端口 = 服务端端口，目的端口 = 本会话端口（客户端套接字
	 * 绑在它上面）。地址那一半已经在 worker 的固定字段闸门里过了。 */
	if (!iwan_win_dgram_parse(pkt, len, o))
		return IWAN_WIN_IN_DROP;	/* 是本会话的包但结构不合法：吞 */
	if (o->sport != s->dport || o->dport != s->sport)
		return IWAN_WIN_IN_NONE;

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
			 _In_ UINT32 sub_ifindex, _In_ UINT16 compartment)
{
	IWAN_INJECT_CTX *ctx;
	NET_BUFFER_LIST *nbl = NULL;
	HANDLE handle;
	NTSTATUS st;

	handle = (family == 6) ? ext->inj_recv6 : ext->inj_recv4;

	/* C6014 误报：ctx/ctx->buf 交给 FwpsInjectNetworkReceiveAsync0，
	 * 由同一个完成回调释放。 */
#pragma warning(suppress: 6014)
	ctx = (IWAN_INJECT_CTX *)IWAN_ALLOC(sizeof(*ctx), IWAN_TAG_PKT);
	if (ctx == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	/* 同上。 */
#pragma warning(suppress: 6014)
	ctx->buf = IWAN_ALLOC(len, IWAN_TAG_PKT);
	ctx->ext = ext;
	ctx->mdl = NULL;		/* 池分配不清零，见 encap 侧同样处理 */
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
	/* 参数表就是 9 个：handle, context, flags, compartment, interfaceIndex,
	 * subInterfaceIndex, nbl, complete, completeContext。
	 * 上一次我"照文档补了个 addressFamily"其实是错的 —— 编译器把真原型
	 * 打了出来（C2197），按它改回来才是对的：这个 API 没有地址族参数，
	 * 地址族由注入句柄自己带（inj_recv4 / inj_recv6 分开注册）。 */
	st = FwpsInjectNetworkReceiveAsync(handle, NULL, 0, compartment,
					   (IF_INDEX)ifindex,
					   (IF_INDEX)sub_ifindex, nbl,
					   iwan_win_inject_complete, ctx);
	if (!NT_SUCCESS(st)) {
		InterlockedDecrement(&ext->inject_outstanding);
		FwpsFreeNetBufferList(nbl);
		IoFreeMdl(ctx->mdl);
		ExFreePoolWithTag(ctx->buf, IWAN_TAG_PKT);
		ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
		return st;
	}
	/* 注入成功：ctx（连 buf/mdl）由 iwan_win_inject_complete 释放，
	 * 本函数一个都不再持有。 */
	ctx = NULL;
	return st;
}

/* 前向声明：in4/in6 是薄封装，worker 的实体在它们后面（第一次真编译在这里
 * 报"undefined; assuming extern returning int" + 重定义） */
static VOID NTAPI
iwan_win_inbound_worker(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
			_In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
			_Inout_opt_ void *layerData,
			_In_opt_ const void *classifyContext,
			_In_ const FWPS_FILTER *filter,
			_In_ UINT64 flowContext,
			_Inout_ FWPS_CLASSIFY_OUT *classifyOut,
			_In_ BOOLEAN outer_v6);

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
	UINT32 sub_ifindex = 0;
	BOOLEAN all_ours = TRUE, overflow = FALSE;
	UINT32 kinds[IWAN_WIN_MAX_BATCH];
	ULONG lens[IWAN_WIN_MAX_BATCH];
	ULONG n = 0;			/* 本批报文数 */
	ULONG i;
	UINT32 fidx;

	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);

	/* 先把"放行"写进结论，再谈别的。
	 *
	 * 本层挂的是**终止型**过滤器：终止型没有"下一条"可继续，结论只能是 PERMIT
	 * 或 BLOCK。写 CONTINUE（"不表态"）的现场是：会话一建立、全机流量两个方向
	 * 立刻中断 —— 出向 callout 明明被调用了 233 次、每次都返回放行，包却一个都
	 * 没出去；客体本身活得好好的，CLOSE 一返回立刻恢复。
	 * 写权限（FWPS_RIGHT_ACTION_WRITE）管的是"能不能收紧成 BLOCK"，不是"能不能
	 * 放行"：拿不到就只放行、不再收紧。 */
	classifyOut->actionType = FWP_ACTION_PERMIT;
	if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
		return;
	if (ext == NULL || nbl == NULL)
		return;
	s = &ext->sess;
	if (s->valid == 0 || iwan_win_session_is_v6(s) != outer_v6)
		return;
	/* 传输层没有 IP 头可看：协议与外层对端地址只能问 WFP 固定字段。
	 * 取值前先断言类型（类型不符读到的是垃圾），拿不到就放行 —— 判不了
	 * 归属就不该动这个包。索引先卡上界：固定字段数组是按层实际字段数
	 * 分配的，越界读就是读别人的内存。 */
	if (inFixedValues == NULL)
		return;
	fidx = outer_v6 ? FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL
			: FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL;
	if (fidx >= inFixedValues->valueCount)
		return;
	if (inFixedValues->incomingValue[fidx].value.type != FWP_UINT8 ||
	    inFixedValues->incomingValue[fidx].value.uint8 != IWAN_IPPROTO_UDP)
		return;
	fidx = outer_v6 ? FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS
			: FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS;
	if (fidx >= inFixedValues->valueCount)
		return;
	if (outer_v6) {
		if (inFixedValues->incomingValue[fidx].value.type !=
			    FWP_BYTE_ARRAY16_TYPE ||
		    RtlCompareMemory(inFixedValues->incomingValue[fidx]
					     .value.byteArray16->byteArray16,
				     s->outer_dst6, 16) != 16)
			return;
	} else {
		if (inFixedValues->incomingValue[fidx].value.type != FWP_UINT32 ||
		    inFixedValues->incomingValue[fidx].value.uint32 != s->outer_dst)
			return;
	}

	/* 自己注入的内层包：放行，让它正常往上交付 */
	if (iwan_win_nbl_from_self(ext->inj_recv4, nbl) ||
	    iwan_win_nbl_from_self(ext->inj_recv6, nbl))
		return;
	if (!ExAcquireRundownProtection(&ext->rundown))
		return;
	if (s->valid == 0)
		goto done;

	/* 入向注入必须告诉 WFP"这个包是从哪张网卡、哪个子接口收到的"，而入向
	 * 的权威来源是**固定字段**（值本身随层而定，见 fwpsk.h 的
	 * FWPS_FIELDS_INBOUND_TRANSPORT_V4：INTERFACE_INDEX / SUB_INTERFACE_INDEX）。
	 * 之前只从元数据取 sourceInterfaceIndex，在 INBOUND_TRANSPORT 上拿不到
	 * 真值，等于给注入 API 传 interfaceIndex = 0 —— 报文能排进队列（调用返回
	 * 成功、rx_delivered 照涨），随后被 WFP 异步退回：完成回调里
	 * NET_BUFFER_LIST_STATUS 全是 0xC000000D（STATUS_INVALID_PARAMETER），
	 * 33 个包 33 次失败、一次都没上栈。出向注入不需要网卡索引，所以出向
	 * 一直是通的 —— 这条不对称就是当时的线索。
	 * 取值前照例卡上界与类型：固定字段按层分配，越界就是读别人的内存。 */
	fidx = outer_v6 ? FWPS_FIELD_INBOUND_TRANSPORT_V6_INTERFACE_INDEX
			: FWPS_FIELD_INBOUND_TRANSPORT_V4_INTERFACE_INDEX;
	if (inFixedValues != NULL && fidx < inFixedValues->valueCount &&
	    inFixedValues->incomingValue[fidx].value.type == FWP_UINT32)
		ifindex = inFixedValues->incomingValue[fidx].value.uint32;
	fidx = outer_v6 ? FWPS_FIELD_INBOUND_TRANSPORT_V6_SUB_INTERFACE_INDEX
			: FWPS_FIELD_INBOUND_TRANSPORT_V4_SUB_INTERFACE_INDEX;
	if (inFixedValues != NULL && fidx < inFixedValues->valueCount &&
	    inFixedValues->incomingValue[fidx].value.type == FWP_UINT32)
		sub_ifindex = inFixedValues->incomingValue[fidx].value.uint32;

	if (inMetaValues != NULL) {
		if (FWPS_IS_METADATA_FIELD_PRESENT(
			    inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID))
			compartment = (UINT16)inMetaValues->compartmentId;
		/* 兜底：元数据里的 sourceInterfaceIndex。注意它在头文件里紧挨着
		 * destinationInterfaceIndex，是**出向语义**的成员，入向上通常取不到
		 * 真值 —— 权威来源是下面那段固定字段。 */
		if (FWPS_IS_METADATA_FIELD_PRESENT(
			    inMetaValues,
			    FWPS_METADATA_FIELD_SOURCE_INTERFACE_INDEX) &&
		    inMetaValues->sourceInterfaceIndex != 0)
			ifindex = (UINT32)inMetaValues->sourceInterfaceIndex;
	}

	/* 这里曾经临时把 ifindex / compartment / 元数据掩码累加进
	 * tx_bad_state / tx_bad_inner / tx_err，用来定位"每个包都被退
	 * STATUS_INVALID_PARAMETER"。线测实测结论（诊断值 = 原值 × 注入次数）：
	 *   tx_bad_state/12 = 7   —— 网卡索引取自固定字段 INTERFACE_INDEX，是
	 *                            NDIS 索引（7），与会话里那个 MIB 索引（6）
	 *                            不是同一套编号；拿错了 WFP 就整批退包；
	 *   tx_bad_inner/12 = 1   —— 隔离舱 1；
	 *   tx_err/12       = 15  —— 元数据四项俱全（1|2|4|8）。
	 * 改对之后 12 个包 12 次注入全部成功（rx_batch_skip=12、rx_batch=0）。
	 * 这三个计数器已归还给原语义，别再借用 —— 借来的计数器会污染后续测量。 */

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
		kind = iwan_win_inbound_kind(s, pkt, len, &o);
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

			if (pkt == NULL || !iwan_win_dgram_parse(pkt, lens[i], &o)) {
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
						sub_ifindex, compartment))) {
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
	BOOLEAN all_ours = TRUE, overflow = FALSE, fail_closed = FALSE;
	UINT32 kinds[IWAN_WIN_MAX_BATCH];
	ULONG n = 0;

	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);

	/* 先把"放行"写进结论，再谈别的。
	 *
	 * 本层挂的是**终止型**过滤器：终止型没有"下一条"可继续，结论只能是 PERMIT
	 * 或 BLOCK。写 CONTINUE（"不表态"）的现场是：会话一建立、全机流量两个方向
	 * 立刻中断 —— 出向 callout 明明被调用了 233 次、每次都返回放行，包却一个都
	 * 没出去；客体本身活得好好的，CLOSE 一返回立刻恢复。
	 * 写权限（FWPS_RIGHT_ACTION_WRITE）管的是"能不能收紧成 BLOCK"，不是"能不能
	 * 放行"：拿不到就只放行、不再收紧。 */
	classifyOut->actionType = FWP_ACTION_PERMIT;
	if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
		return;
	if (ext == NULL || nbl == NULL)
		return;

	s = &ext->sess;
	if (s->valid == 0)
		return;

	/* 自己注入的外层包：放行，绝不再封装一层 */
	if (iwan_win_nbl_from_self(ext->inj_send4, nbl) ||
	    iwan_win_nbl_from_self(ext->inj_send6, nbl))
		return;
	overhead = iwan_win_session_is_v6(s) ? IWAN_OUTER6_TOTAL
					     : IWAN_OUTER4_TOTAL;

	{
		NET_BUFFER_LIST *cur;

		for (cur = nbl; cur != NULL;
		     cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
			NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
			UINT8 hdr6[IWAN_INNER_IP6_LEN];
			UINT8 *pkt;
			ULONG len;

			if (nb == NULL || n >= IWAN_WIN_MAX_BATCH) {
				overflow = TRUE;
				break;
			}
			len = NET_BUFFER_DATA_LENGTH(nb);
			/* 判定只需要内层 v6 首部那 40 字节：给一块栈缓冲让 NDIS
			 * 跨 MDL 拼出来。原先这里要求**整包**连续
			 * （NdisGetDataBuffer(nb, len, NULL, ...)），而校验和卸载
			 * 下的常规报文首部与载荷分属不同 MDL，于是这些包被判成
			 * “不是我们的”、明文走上承载网 —— 与出向 v4 修掉的是同一
			 * 个错，v6 侧一直漏着。 */
			pkt = (UINT8 *)NdisGetDataBuffer(nb, IWAN_INNER_IP6_LEN,
							 hdr6, 1, 0);
			if (pkt == NULL || len < IWAN_INNER_IP6_LEN ||
			    iwan_win_inner_family(pkt, len) != 6) {
				/* 短于首部或不是 v6：不是本会话的包，放行 */
				all_ours = FALSE;
				break;
			}
			if (!iwan_win_inner_sane(pkt, len)) {
				/* 是我们的包但声明长度与整帧矛盾：丢，绝不放明文 */
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_LEN_BAD, len,
						 (ULONG)IWAN_INNER_IP6_LEN +
						 iwan_win_rd16(pkt + 4), pkt[0], pkt);
				IWAN_STAT_INC(ext, tx_bad_inner);
				fail_closed = TRUE;
				break;
			}
			if (!iwan_win_should_tunnel6(s->targets, s->target_count,
						     s->outer_dst6, pkt + 24)) {
				all_ours = FALSE;
				break;
			}
			if ((ULONG)(overhead + len) > 0xFFFF) {
				/* 外层总长越过 16 位：装不下就丢（与 v4 的 MTU
				 * 闸门同一规矩），不透传 */
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_MTU, len,
						 (ULONG)IWAN_INNER_IP6_LEN +
						 iwan_win_rd16(pkt + 4), pkt[0], pkt);
				IWAN_STAT_INC(ext, tx_bad_state);
				fail_closed = TRUE;
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
	if (fail_closed) {
		/* 是我们的包、但封装不了：丢。计数器在判定处已经计过，
		 * 这里只落结论，避免同一原因被记两次。 */
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
			NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO ci;
			BOOLEAN l4_offloaded = FALSE;
			UINT8 hdr6[IWAN_INNER_IP6_LEN];
			UINT8 *stor = NULL;
			UINT8 *pkt;
			ULONG nblen, tot;
			NTSTATUS st;

			nblen = NET_BUFFER_DATA_LENGTH(nb);
			/* 与出向 v4 同一口径：判定只用首部那 40 字节，给栈缓冲让
			 * NDIS 跨 MDL 拼；整包连续性单独探一次，不连续就拼进临时
			 * 缓冲。原来这里一次取整包，取不到就丢，等于把校验和
			 * 卸载下的常规 v6 报文全挡在隧道外。 */
			pkt = (UINT8 *)NdisGetDataBuffer(nb, IWAN_INNER_IP6_LEN,
							 hdr6, 1, 0);
			if (pkt == NULL || nblen < IWAN_INNER_IP6_LEN) {
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_COALESCE,
						 nblen, 0,
						 pkt != NULL ? (ULONG)pkt[0] : 0xFFFFu,
						 pkt);
				IWAN_STAT_INC(ext, tx_bad_inner);
				continue;
			}
			tot = (ULONG)IWAN_INNER_IP6_LEN + iwan_win_rd16(pkt + 4);
			if (tot > nblen) {
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_LEN_BAD,
						 nblen, tot, pkt[0], pkt);
				IWAN_STAT_INC(ext, tx_bad_inner);
				continue;
			}
			pkt = (UINT8 *)NdisGetDataBuffer(nb, tot, NULL, 1, 0);
			if (pkt == NULL) {
			/* C6014 误报：stor 是本轮拼接缓冲，下面每条出口
			 * （取缓冲失败、MTU 装不下、封装后即用即还）都已释放并
			 * 置空；分析器按循环回边把已释放路径也算进去。 */
#pragma warning(suppress: 6014)
				stor = (UINT8 *)IWAN_ALLOC(tot, IWAN_TAG_PKT);
				if (stor == NULL) {
					/* 池压力下不能默默放明文出去 */
					IWAN_STAT_INC(ext, tx_err);
					continue;
				}
				pkt = (UINT8 *)NdisGetDataBuffer(nb, tot, stor, 1, 0);
				if (pkt == NULL) {
					iwan_win_diag_tx(s,
							 IWAN_WIN_DIAG_TX_COALESCE,
							 nblen, tot, 0xFFFFu, NULL);
					ExFreePoolWithTag(stor, IWAN_TAG_PKT);
					/* 必须置空：stor 声明在循环体内，不置空就是
					 * 下一轮仍持有已释放指针 —— 那条路径若走零
					 * 拷贝成功，末尾的 `if (stor != NULL)`
					 * 会把同一块缓冲再释放一次（池损坏）。 */
					stor = NULL;
					IWAN_STAT_INC(ext, tx_bad_inner);
					continue;
				}
			}
			ci.Value = NET_BUFFER_LIST_INFO(cur,
							TcpIpChecksumNetBufferListInfo);
			if (ci.Transmit.TcpChecksum || ci.Transmit.UdpChecksum)
				l4_offloaded = TRUE;
			/* 校验和卸载不等于大段：多数 TCP/UDP 都带这个标记，而网卡
			 * 补不了已经被 XOR 过的内层，只能自己算。这里与出向 v4 走
			 * 同一条路 —— l4_offloaded 交给封装层，由
			 * iwan_win_inner_fix_csum() 补算 L4 校验和。曾经把这一类
			 * 整批丢弃，等于把绝大多数 v6 流量挡在隧道外。
			 *
			 * 真正装不下的大段（LSO/巨帧）仍然 fail-closed：外层 v6
			 * 不参与分片，内层加封装开销越过承载 MTU 就丢，绝不让网卡
			 * 再去分。Linux 参考实现遇到 GSO 同样是丢（记
			 * tx_bad_state），并不做软件分段 —— 所以这里不是缺陷，
			 * 是两侧一致的选择。 */
			if (tot + IWAN_OUTER6_TOTAL > s->carrier_mtu) {
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_MTU, nblen,
						 tot, pkt[0], pkt);
				IWAN_STAT_INC(ext, tx_bad_state);
				if (stor != NULL) {
					ExFreePoolWithTag(stor, IWAN_TAG_PKT);
					/* 必须置空：stor 声明在循环体内，但分析器
					 * 按"循环回边仍持有已释放指针"报 C6014；更
					 * 要紧的是真语义 —— 置空是"本轮这块缓冲已
					 * 归还"的唯一记号，下一轮重新分配。 */
					stor = NULL;
				}
				continue;
			}

			st = iwan_win_encap_inject(ext, pkt, tot, l4_offloaded,
						   compartment,
						   iwan_win_session_is_v6(s));
			if (stor != NULL) {
				/* 封装层已整块拷走，即用即还 */
				ExFreePoolWithTag(stor, IWAN_TAG_PKT);
				stor = NULL;
			}
			if (!NT_SUCCESS(st)) {
				/* 在途窗口满已在 encap_inject 里记过 INFLIGHT，
				 * 这里不能再覆盖成 ENCAP_FAIL */
				if (st != STATUS_DEVICE_BUSY)
					iwan_win_diag_tx(s,
							 IWAN_WIN_DIAG_TX_ENCAP_FAIL,
							 nblen, tot, pkt[0], pkt);
				IWAN_STAT_INC(ext, tx_err);
				continue;
			}
			IWAN_STAT_INC(ext, tx_pkts);
			IWAN_STAT_ADD(ext, tx_bytes, tot + overhead);
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
	/* 过滤器也用 callout 的 GUID 做键：注销时按 key 删即可（filterKey 与
	 * calloutKey 是两个独立命名空间，同一 GUID 不冲突），省掉保存
	 * FwpmFilterAdd 回填 id 的那套状态。 */
	filter.filterKey = *key;
	filter.layerKey = *layer;
	filter.displayData.name = (PWSTR)name;
	filter.action.type = action;
	filter.action.calloutKey = *key;
	filter.weight.type = FWP_EMPTY;		/* 由 BFE 自动分配权重 */
	filter.numFilterConditions = 0;		/* 全部报文进 callout，由我们判断 */
	filter.filterCondition = NULL;
	/* FWPM_FILTER0 里放用户上下文用的成员叫 rawContext；classify 回调
	 * 通过 FWPS_FILTER0.context 读到的就是它（名字不一样，别想当然）。 */
	filter.rawContext = (UINT64)(ULONG_PTR)ext;
	return FwpmFilterAdd(ext->engine, &filter, NULL, NULL);
}

/*
 * 四个内建层的层键（layerKey）—— 写死的公开常量。
 *
 * 数值来源：WDK 用户态的 fwpuclnt.lib（用户态能链到这些符号）。内核态的
 * fwpkclnt.lib / fwpuclnt.lib / netio.lib 都不导出它们，链接期直接报
 * unresolved external，所以只能把数值抄进来。
 *
 * 曾经的做法是运行时用 FwpmLayerGetById0(engine, FWPS_LAYER_* 枚举值) 反查，
 * 那个 id 空间与 FWPM 的层 ID 不是一回事：查出来的层键指向别处（很可能落在
 * ALE 授权层），过滤器装上去之后 callout 的判定根本无法解析 —— 表现为
 * "会话一开，全机流量立刻中断，两个方向都断，而客体本身活得好好的；callout
 * 一次都没被调用（所有计数器全 0）；CLOSE 一返回网络立刻恢复"。层键是稳定
 * 常量，抄数值比隔着 id 空间猜要可靠。
 */
static const GUID IWAN_LAYER_OUT4 = {
	0x1E5C9FAE, 0x8A84, 0x4135,
	{ 0xA3, 0x31, 0x95, 0x0B, 0x54, 0x22, 0x9E, 0xCD }
};					/* FWPM_LAYER_OUTBOUND_IPPACKET_V4 */
static const GUID IWAN_LAYER_IN4 = {
	0x5926DFC8, 0xE3CF, 0x4426,
	{ 0xA2, 0x83, 0xDC, 0x39, 0x3F, 0x5D, 0x0F, 0x9D }
};					/* FWPM_LAYER_INBOUND_TRANSPORT_V4 */
static const GUID IWAN_LAYER_OUT6 = {
	0xA3B3AB6B, 0x3564, 0x488C,
	{ 0x91, 0x17, 0xF3, 0x4E, 0x82, 0x14, 0x27, 0x63 }
};					/* FWPM_LAYER_OUTBOUND_IPPACKET_V6 */
static const GUID IWAN_LAYER_IN6 = {
	0x634A869F, 0xFC23, 0x4B90,
	{ 0xB0, 0xC1, 0xBF, 0x62, 0x0A, 0x36, 0xAE, 0x6F }
};					/* FWPM_LAYER_INBOUND_TRANSPORT_V6 */

NTSTATUS
iwan_win_wfp_init(_In_ PDEVICE_OBJECT devobj,
		  _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	FWPM_SESSION session;
	NTSTATUS st;

	ext->devobj = devobj;	/* callout 注册推迟到会话建立，那时要用它 */

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
		/* 池句柄是**返回值**，不是出参：NdisAllocateNetBufferListPool(
		 * NDIS_HANDLE, const NET_BUFFER_LIST_POOL_PARAMETERS *) -> NDIS_HANDLE。
		 * 非 NDIS 驱动第一个参数传 NULL。 */
		ext->nbl_pool = NdisAllocateNetBufferListPool(NULL, &pp);
		if (ext->nbl_pool == NULL)
			return STATUS_INSUFFICIENT_RESOURCES;
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

	/* 到这里只是“工具就绪”：引擎、NBL 池、四个注入句柄都不会拦截任何
	 * 报文。四个 callout 与过滤器由 iwan_win_wfp_start 在会话建立时装上
	 * —— 于是 sc start 只验证“驱动能加载、设备能打开”。 */
	InterlockedExchange(&ext->wfp_started, 0);
	return STATUS_SUCCESS;
}

/*
 * 装上数据面：向 BFE 取四个层的层键，然后逐层注册 callout + 过滤器。
 * 出向两层在 IP 包层；入向两层在**传输层**（协议栈重组之后，见文件头说明）。
 *
 * 为什么不在 DriverEntry 里做：一注册就等于全机每一个出向/入向 IP 包都要
 * 先过我们的 classify，而“能不能加载驱动”和“接管流量”应该分开验证。放到
 * 这里之后，加载失败的排查范围只剩 DriverEntry 与控制面。
 *
 * 幂等：wfp_started 做一次性闸门，并发 OPEN 只有一个真正注册。
 */
NTSTATUS
iwan_win_wfp_start(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	NTSTATUS st;

	if (InterlockedCompareExchange(&ext->wfp_started, 1, 0) != 0)
		return STATUS_SUCCESS;		/* 已装好，或有人正在装 */
	if (ext->engine == NULL || ext->devobj == NULL) {
		InterlockedExchange(&ext->wfp_started, 0);
		return STATUS_INVALID_DEVICE_STATE;
	}

	/* 层键是写死的公开常量（见上面四个 GUID 的说明）：不再运行时向 BFE 反查 */
	st = iwan_win_add_callout(ext, ext->devobj, &IWAN_CALLOUT_OUT4,
				  iwan_win_classify_out4,
				  FWP_ACTION_CALLOUT_TERMINATING,
				  &IWAN_LAYER_OUT4, L"iwan out4",
				  &ext->callout_id_out4);
	if (NT_SUCCESS(st)) {
		st = iwan_win_add_callout(ext, ext->devobj, &IWAN_CALLOUT_IN4,
					  iwan_win_classify_in4,
					  FWP_ACTION_CALLOUT_TERMINATING,
					  &IWAN_LAYER_IN4, L"iwan in4",
					  &ext->callout_id_in4);
	}
	if (NT_SUCCESS(st)) {
		st = iwan_win_add_callout(ext, ext->devobj, &IWAN_CALLOUT_OUT6,
					  iwan_win_classify_out6,
					  FWP_ACTION_CALLOUT_TERMINATING,
					  &IWAN_LAYER_OUT6, L"iwan out6",
					  &ext->callout_id_out6);
	}
	if (NT_SUCCESS(st)) {
		st = iwan_win_add_callout(ext, ext->devobj, &IWAN_CALLOUT_IN6,
					  iwan_win_classify_in6,
					  FWP_ACTION_CALLOUT_TERMINATING,
					  &IWAN_LAYER_IN6, L"iwan in6",
					  &ext->callout_id_in6);
	}
	if (!NT_SUCCESS(st)) {
		iwan_win_wfp_stop(ext);		/* 半个数据面比不装更危险 */
		return st;
	}

	InterlockedExchange(&ext->wfp_started, 2);
	return STATUS_SUCCESS;
}

/*
 * 摘掉数据面。顺序不能颠倒：先删过滤器，再注销 callout —— 反过来会留下
 * 引用“已注销 callout”的终止型过滤器，那是全机流量的黑洞（动作无法解析
 * 时协议栈只能丢包），比根本不装还危险。
 *
 * 按 key 删而不是按 id 删：filterKey 在 iwan_win_add_callout 里显式设成了
 * 每个 callout 自己的 GUID，因此不必再保存 FwpmFilterAdd 回填的 id。
 * 调用方都在控制面串行路径上（IOCTL 或卸载），这里的闸门只防重复与重入。
 */
VOID
iwan_win_wfp_stop(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	if (InterlockedCompareExchange(&ext->wfp_started, 1, 2) != 2)
		return;				/* 本来就没装，或有人正在装/摘 */

	if (ext->engine != NULL) {
		FwpmFilterDeleteByKey0(ext->engine, &IWAN_CALLOUT_OUT4);
		FwpmFilterDeleteByKey0(ext->engine, &IWAN_CALLOUT_IN4);
		FwpmFilterDeleteByKey0(ext->engine, &IWAN_CALLOUT_OUT6);
		FwpmFilterDeleteByKey0(ext->engine, &IWAN_CALLOUT_IN6);
	}

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

	if (ext->engine != NULL) {
		FwpmCalloutDeleteByKey0(ext->engine, &IWAN_CALLOUT_OUT4);
		FwpmCalloutDeleteByKey0(ext->engine, &IWAN_CALLOUT_IN4);
		FwpmCalloutDeleteByKey0(ext->engine, &IWAN_CALLOUT_OUT6);
		FwpmCalloutDeleteByKey0(ext->engine, &IWAN_CALLOUT_IN6);
	}

	InterlockedExchange(&ext->wfp_started, 0);
}


VOID
iwan_win_wfp_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	ULONG spin;

	iwan_win_wfp_stop(ext);		/* 先停数据面（幂等） */

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
		InterlockedExchange(&ext->wfp_started, 0);
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
	InterlockedExchange(&ext->wfp_started, 0);
}
