/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_mpdata.c — NDIS 小型端口 + 协议驱动平面的隧道引擎。
 *
 * 与 WFP 平面（iwan_win_wfp.c）的关系：线上字节必须逐字节一致 —— 帧头、
 * 异或、内层校验和、外层首部全部走同一套 iwan_win_frame.c；会话参数与统计
 * 口径也同一套（同名同义的 sess.stats）。差别只在"报文怎么进出"：
 *
 *   出向（内层 → 外层）
 *     WFP 平面：OUTBOUND_IPPACKET 处截获 → 封装 → FwpsInjectNetworkSendAsync
 *     本平面　：小型端口收到协议栈交下来的内层数据报 → 封装 →
 *               NdisSendNetBufferLists（协议边，绑在承载网卡上）
 *   入向（外层 → 内层）
 *     WFP 平面：INBOUND_TRANSPORT 处截获 → 解封 → FwpsInjectNetworkReceiveAsync
 *     本平面　：协议边从承载网卡收外层 UDP → 解封 →
 *               NdisMIndicateReceiveNetBufferLists（小型端口指示向上）
 *
 * 因此三处更简单：① 出向只处理"路由指向本适配器"的报文，不需要目标集合
 * 匹配；② 入向直接指示向上，不像注入那样再走一遍协议栈入口；③ 不需要注入
 * 完成前的"缓冲必须存活"约束，但要保留在途上限（见下）。
 *
 * 控制帧（OPEN/ECHO/CLOSE）本平面只记账、不指示向上：承载网卡的常规
 * TCP/IP 绑定本来就会把这些 UDP 交给用户态套接字（原客户端进程收到
 * PT_OPEN_ACK 比驱动更早），所以控制面天然继续可用。数据帧则不同 —— 它们
 * 到了用户态套接字只是噪声，必须由引擎吸收（外层不进主机栈）。
 *
 * 并发：本文件全部在 <= DISPATCH_LEVEL 被调用（小型端口发送、协议边接收），
 * 不等待、不加锁、不碰可分页内存。会话参数按 WFP 平面的同一约定用 rundown
 * 保护读取。
 */
#include "iwan_win.h"

/* 外层在途上限：每个在途外层 NBL 都占着非分页池，要等 NDIS 发送完成回调
 * 才归还。内层可能远比承载快（10 Gbps 的内层灌一条 100 Mbps 的承载），
 * 没有上限就会以 GB/s 量级净增长、秒级耗尽非分页池 —— 这正是 WFP 平面
 * 硬挂的机制（Kernel-Power 41 + 6008），同一个坑不能踩第二次。
 * 超限丢当前包并计 ev_dropped（队列溢出丢弃），但**对协议栈报成功**：
 * 报失败会被翻成 sendto() 的 WSAEINVAL，把"承载来不及取"伪装成"应用参数
 * 非法"。丢包是 UDP 的正常结局，计数才是唯一的诊断通道。 */

/* "这帧是本会话的什么"，与 WFP 平面 iwan_win_inbound_kind 同义 */
#define IWAN_MP_IN_NONE		0u	/* 不是本会话的帧（端口不成对） */
#define IWAN_MP_IN_DROP		1u	/* 是本会话的帧但结构或凭据不合法 */
#define IWAN_MP_IN_DATA		2u
#define IWAN_MP_IN_CTRL		3u

/* 端口成对 + 凭据 + 类型三分：判据必须与 WFP 平面逐条一致，否则同一个包
 * 在两个平面上会得到不同结论。地址那一半由协议边在调用前卡（外层目的地址
 * 必须等于 outer_src），这里只管传输层与隧道层。 */
static UINT32
iwan_win_mp_outer_kind(_In_ const IWAN_WIN_SESSION *s,
		       _In_ const IWAN_WIN_OUTER *o)
{
	if (o->sport != s->dport || o->dport != s->sport)
		return IWAN_MP_IN_NONE;

	switch (iwan_win_frame_classify(o, s->sid, s->tok, s->enc != 0, TRUE)) {
	case IWAN_WIN_FRAME_DATA:
		return IWAN_MP_IN_DATA;
	case IWAN_WIN_FRAME_CTRL:
		return IWAN_MP_IN_CTRL;
	default:
		return IWAN_MP_IN_DROP;
	}
}

/* ---- 出向：内层数据报 → 外层帧 ---------------------------------------- */

UINT32
iwan_win_mp_encap_send(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		       _In_reads_bytes_(len) const UINT8 *inner,
		       _In_ ULONG len, _In_ BOOLEAN l4_offloaded)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	UINT8 *buf, *ip, *fh;
	ULONG overhead = IWAN_OUTER4_TOTAL;
	ULONG total, flen;
	BOOLEAN sent;

	if (!ExAcquireRundownProtection(&ext->rundown))
		return IWAN_MP_TX_DROP;	/* 会话正在拆除：本包丢弃，不报错 */

	if (s->valid == 0) {
		/* 没有会话：本适配器唯一的存在理由就是隧道，报文到此为止。
		 * 明确失败（小型端口把状态回给协议栈）并计数 —— 静默丢弃是
		 * WFP 平面吃过亏的地方。
		 *
		 * 这里**刻意不看** s->inner_ip：WFP 平面用它做"哪些报文该进
		 * 隧道"的判据，本平面的判据是路由（报文能到本适配器就说明
		 * 该进隧道），内层身份由控制面用 netsh 设在适配器上。真实的
		 * 控制面（kdp_win.c）从不填 SESSION_OPEN 里的 inner_ip，若在这里
		 * 也要求它非零，结果会是"会话建立了、一个字节都出不去"。 */
		IWAN_MP_STAT_INC(ext, tx_bad_state);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_DROP;
	}
	/* 外层 v6 的邻居发现（NS/NA）留到第二阶段：现在直接拒绝，绝不降级成
	 * 明文或"猜一个网关 MAC"。 */
	if (iwan_win_session_is_v6(s)) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_V6_NOT_IMPL, len, len,
				 len > 0 ? (ULONG)inner[0] : 0xFFFFu, inner);
		IWAN_MP_STAT_INC(ext, tx_bad_state);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_DROP;
	}
	/* 内层自洽：调用者（小型端口）已经从首部读出总长，这里独立复核一次 */
	if (len < IWAN_INNER_IP4_LEN || (inner[0] >> 4) != 4 ||
	    iwan_win_rd16(inner + 2) > len) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_LEN_BAD, len, len,
				 len > 0 ? (ULONG)inner[0] : 0xFFFFu, inner);
		IWAN_MP_STAT_INC(ext, tx_bad_inner);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_FAIL;
	}

	/* 先判再加：无符号回绕会让超长 len（如 0xFFFFFFF0）算出的 total 变小，
	 * 0xFFFF、承载 MTU、在途上限三道理就全部放行，而拷贝仍按 len 抄。
	 * 调用者今天给不出这种长度（NET_BUFFER_DATA_LENGTH 到不了 4G），
	 * 但数据面的长度闸门不该建立在调用者的善意上。 */
	if (overhead > 0xFFFFu || len > 0xFFFFu - overhead) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_LEN_BAD, len, len,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, tx_bad_inner);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_FAIL;
	}
	total = overhead + len;
	flen = IWAN_FRAME_HDR_LEN + len;
	if (total > 0xFFFFu) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_LEN_BAD, len, total,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, tx_bad_inner);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_FAIL;
	}
	/* 承载网卡 MTU：外层 IP 数据报不能超过它（外层不分片，装不下就是丢）。
	 * 与 WFP 平面同一判据、同一计数器。 */
	if (total > s->carrier_mtu) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_MTU, len, total,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, tx_bad_state);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_DROP;
	}
	/* 在途上限就是"发送队列溢出"：语义上属于 ev_dropped（队列溢出丢弃），
	 * 不是 tx_bad_state（状态坏了）。两者混用会让"驱动坏了"和"承载跟不上"
	 * 在计数里长得一样。 */
	if ((ULONG)ext->mp.outer_outstanding >= IWAN_MP_MAX_OUTER_INFLIGHT) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_INFLIGHT, len, total,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, ev_dropped);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_DROP;
	}

	/* 缓冲一次分配到位：以太头(14) + 外层 IP+UDP(28) + 帧头(8) + 载荷 */
	buf = (UINT8 *)IWAN_ALLOC(IWAN_MP_ETH_HDR_LEN + total, IWAN_TAG_PKT);
	if (buf == NULL) {
		IWAN_MP_STAT_INC(ext, tx_err);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_DROP;
	}
	ip = buf + IWAN_MP_ETH_HDR_LEN;
	fh = ip + overhead - IWAN_FRAME_HDR_LEN;

	/* 会话参数在这一段内被读走；写完帧头与载荷后即可放行 rundown */
	iwan_win_build_frame_hdr(fh, s->enc ? PT_DATA_ENC : PT_DATA, s->enc,
				 s->sid, s->tok);
	RtlCopyMemory(fh + IWAN_FRAME_HDR_LEN, inner, len);
	/* 内层校验和必须在异或之前补算（网卡再也补不了被 XOR 过的内层） */
	iwan_win_inner_fix_csum(fh + IWAN_FRAME_HDR_LEN, len, l4_offloaded);
	if (s->enc)
		iwan_win_xor(fh + IWAN_FRAME_HDR_LEN, len, s->key, 0);
	if (iwan_win_outer_hdr4(ip, total, flen, s->outer_src, s->outer_dst,
				s->sport, s->dport) != total) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_ENCAP_FAIL, len, total,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, tx_bad_state);
		ExReleaseRundownProtection(&ext->rundown);
		ExFreePoolWithTag(buf, IWAN_TAG_PKT);
		return IWAN_MP_TX_DROP;
	}
	/* rundown 一直持到本函数结束：诊断（iwan_win_diag_tx 会解引用 s->shm
	 * 并写 40 字节）必须落在 rundown 内。否则并发的 IOCTL_CLOSE 走
	 * session_reset → shm_destroy → ExFreePoolWithTag 之后，数据面还在
	 * DISPATCH_LEVEL 往已释放的非分页池里写。WFP 平面同一口径：取 rundown
	 * 之后所有 diag 都在释放之前。 */

	/* 以太头：源 = 选定承载的 MAC，目的 = 下一跳 MAC。下一跳还没解析出来
	 * 时本函数发 ARP 并返回 FALSE（本包丢，计 tx_bad_state + 诊断）。 */
	if (!iwan_win_proto_fill_eth4(ext, buf)) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_NO_NEIGHBOR, len, total,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, tx_bad_state);
		ExReleaseRundownProtection(&ext->rundown);
		ExFreePoolWithTag(buf, IWAN_TAG_PKT);
		return IWAN_MP_TX_DROP;
	}

	/* send_outer4 的两种结局都不留 buf 给我们：TRUE = 所有权随 NBL 转移
	 * （完成回调 ExFreePoolWithTag），FALSE = 它已经在内部释放。这里是
	 * 唯一一处“交出即撒手”的缓冲，所以显式置空，别让后面的人以为还能用。 */
	sent = iwan_win_proto_send_outer4(ext, buf, IWAN_MP_ETH_HDR_LEN + total);
	buf = NULL;
	if (sent) {
		/* 与 WFP 平面同一口径：tx_bytes 记外层字节（含外层 IP+UDP），
		 * 不含以太头 —— 那是承载的链路层开销，不属隧道开销。 */
		IWAN_MP_STAT_INC(ext, tx_pkts);
		IWAN_MP_STAT_ADD(ext, tx_bytes, total);
	} else {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_SEND_FAIL, len, total,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, tx_bad_state);
	}
	ExReleaseRundownProtection(&ext->rundown);
	return sent ? IWAN_MP_TX_OK : IWAN_MP_TX_DROP;
}

/* ---- 入向：外层帧 → 内层数据报 ---------------------------------------- */

VOID
iwan_win_mp_outer_recv(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		       _In_reads_bytes_(len) const UINT8 *ip, _In_ ULONG len)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	IWAN_WIN_OUTER o;
	UINT8 *inner;
	ULONG ilen;
	UINT32 kind, fam;

	if (!ExAcquireRundownProtection(&ext->rundown))
		return;
	if (s->valid == 0) {
		ExReleaseRundownProtection(&ext->rundown);
		return;
	}

	/* 地址闸门（外层目的地址 == outer_src）由协议边在调用前卡掉；这里
	 * 解析隧道层并分类。解析失败说明是本会话五元组的包但结构不合法。 */
	if (!iwan_win_dgram_parse(ip, len, &o)) {
		IWAN_MP_STAT_INC(ext, rx_bad_hdr);
		ExReleaseRundownProtection(&ext->rundown);
		return;
	}
	kind = iwan_win_mp_outer_kind(s, &o);
	if (kind == IWAN_MP_IN_NONE || kind == IWAN_MP_IN_DROP) {
		/* IN_NONE 说明协议边的端口判据与本函数不一致（不该发生）；
		 * IN_DROP 是本会话的帧但凭据/类型不合法。两者都吞掉并计数。 */
		if (kind == IWAN_MP_IN_DROP)
			IWAN_MP_STAT_INC(ext, rx_bad_hdr);
		ExReleaseRundownProtection(&ext->rundown);
		return;
	}

	if (kind == IWAN_MP_IN_CTRL) {
		/* 控制帧：只记账，不指示向上（承载网卡的常规绑定已把同一份
		 * UDP 交给用户态套接字，控制面在那里）。 */
		iwan_win_session_mark_rx(s, 1);
		if (o.type == PT_CLOSE)
			iwan_win_session_mark_close(s);
		IWAN_MP_STAT_INC(ext, rx_ctrl_frame);
		ExReleaseRundownProtection(&ext->rundown);
		return;
	}

	/* 数据帧 */
	iwan_win_session_mark_rx(s, 0);
	IWAN_MP_STAT_INC(ext, rx_outer);
	IWAN_MP_STAT_INC(ext, rx_frames);
	IWAN_MP_STAT_INC(ext, rx_pkts);

	inner = (UINT8 *)IWAN_ALLOC(o.inner_len, IWAN_TAG_PKT);
	if (inner == NULL) {
		IWAN_MP_STAT_INC(ext, rx_nomem);
		ExReleaseRundownProtection(&ext->rundown);
		return;
	}
	ilen = iwan_win_decap(ip, len, &o, s->key, inner, o.inner_len);
	fam = ilen != 0 ? iwan_win_inner_family(inner, ilen) : 0;
	if (ilen == 0 || fam == 0 || !iwan_win_inner_sane(inner, ilen)) {
		/* 结构不合法就不指示向上：宁可丢这一个内层包，也不让畸形包
		 * 进入本机协议栈。判据与 WFP 平面逐条一致。 */
		IWAN_MP_STAT_INC(ext, rx_bad_inner);
		ExFreePoolWithTag(inner, IWAN_TAG_PKT);
		ExReleaseRundownProtection(&ext->rundown);
		return;
	}

	/* 与出向同一约定：indicate_inner 要么把内层缓冲连 NBL 一起交给 NDIS
	 * （TRUE），要么自己释放后回 FALSE。两种结局这里都不再持有。 */
	if (iwan_win_mp_indicate_inner(ext, inner, ilen))
		IWAN_MP_STAT_INC(ext, rx_delivered);
	else
		IWAN_MP_STAT_INC(ext, rx_nomem);

	ExReleaseRundownProtection(&ext->rundown);
}
