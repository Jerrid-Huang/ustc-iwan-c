/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_frame.c — 见 iwan_win_frame.h。纯函数，无锁、无分配、无 WDK 依赖。
 */
#include "iwan_win_frame.h"

VOID
iwan_win_build_frame_hdr(_Out_writes_bytes_(IWAN_FRAME_HDR_LEN) UINT8 *out,
			 _In_ UINT8 typ, _In_ UINT8 enc,
			 _In_ UINT16 sid, _In_ UINT32 tok)
{
	out[0] = typ;
	out[1] = enc;
	out[2] = (UINT8)(sid >> 8);
	out[3] = (UINT8)sid;
	out[4] = (UINT8)(tok >> 24);
	out[5] = (UINT8)(tok >> 16);
	out[6] = (UINT8)(tok >> 8);
	out[7] = (UINT8)tok;
}

/*
 * 把 8 字节密钥旋转到"从 off 开始"的相位，得到一个 64 位掩码字。
 * 逐字节写法是 p[i] ^= key[(off + i) & 7]；按 8 字节分组时组内第 j 字节
 * 对应的密钥下标是 (off + j) & 7（组起始下标是 8 的倍数），与掩码字的
 * 第 j 个字节一致，所以两种写法逐位等价，与主机字节序无关。
 */
static UINT64
iwan_win_xor_mask(_In_reads_bytes_(IWAN_KEY_LEN) const UINT8 *key, _In_ ULONG off)
{
	UINT64 k = 0;
	ULONG j;

	for (j = 0; j < IWAN_KEY_LEN; j++)
		k |= (UINT64)key[(off + j) & (IWAN_KEY_LEN - 1)] << (8 * j);
	return k;
}

VOID
iwan_win_xor(_Inout_updates_bytes_(len) UINT8 *p, _In_ ULONG len,
	     _In_reads_bytes_(IWAN_KEY_LEN) const UINT8 *key, _In_ ULONG off)
{
	UINT64 k = iwan_win_xor_mask(key, off);
	ULONG i = 0;

	/* 每轮一个 64 位字；用 RtlCopyMemory 取值与回写，未对齐也安全 */
	while (i + IWAN_KEY_LEN <= len) {
		UINT64 v;

		RtlCopyMemory(&v, p + i, sizeof(v));
		v ^= k;
		RtlCopyMemory(p + i, &v, sizeof(v));
		i += IWAN_KEY_LEN;
	}
	for (; i < len; i++)
		p[i] ^= key[(off + i) & (IWAN_KEY_LEN - 1)];
}

/*
 * 拷贝与解密一遍完成，等价于"先逐字节拷贝、再 iwan_win_xor(out, len, key, 0)"。
 * 调用方保证 out 与 in 不重叠：驱动里 out 是新分配的解封缓冲。
 */
static VOID
iwan_win_copy_dec(_Out_writes_bytes_(len) UINT8 *out,
		  _In_reads_bytes_(len) const UINT8 *in, _In_ ULONG len,
		  _In_reads_bytes_(IWAN_KEY_LEN) const UINT8 *key)
{
	UINT64 k = iwan_win_xor_mask(key, 0);
	ULONG i = 0;

	while (i + IWAN_KEY_LEN <= len) {
		UINT64 v;

		RtlCopyMemory(&v, in + i, sizeof(v));
		v ^= k;
		RtlCopyMemory(out + i, &v, sizeof(v));
		i += IWAN_KEY_LEN;
	}
	for (; i < len; i++)
		out[i] = in[i] ^ key[i & (IWAN_KEY_LEN - 1)];
}

USHORT
iwan_win_rd16(_In_reads_bytes_(2) const UINT8 *p)
{
	return (USHORT)((p[0] << 8) | p[1]);
}

VOID
iwan_win_wr32(_Out_writes_bytes_(4) UINT8 *p, _In_ UINT32 v)
{
	p[0] = (UINT8)(v >> 24);
	p[1] = (UINT8)(v >> 16);
	p[2] = (UINT8)(v >> 8);
	p[3] = (UINT8)v;
}

UINT32
iwan_win_rd32(_In_reads_bytes_(4) const UINT8 *p)
{
	return ((UINT32)p[0] << 24) | ((UINT32)p[1] << 16) |
	       ((UINT32)p[2] << 8) | (UINT32)p[3];
}

VOID
iwan_win_wr16(_Out_writes_bytes_(2) UINT8 *p, _In_ USHORT v)
{
	p[0] = (UINT8)(v >> 8);
	p[1] = (UINT8)v;
}

static USHORT
iwan_win_csum_finish(_In_ ULONG sum)
{
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return (USHORT)~sum;
}

static ULONG
iwan_win_csum_add(_In_ ULONG sum, _In_reads_bytes_(len) const UINT8 *p,
		  _In_ ULONG len, _In_ ULONG odd_parity)
{
	ULONG i;

	for (i = 0; i + 1 < len; i += 2)
		sum += ((ULONG)p[i] << 8) | p[i + 1];
	if (i < len)
		sum += ((ULONG)p[i] << 8) | odd_parity;
	return sum;
}

VOID
iwan_win_inner_fix_csum(_Inout_updates_bytes_(len) UINT8 *pkt, _In_ ULONG len,
			_In_ BOOLEAN l4_offloaded)
{
	ULONG ihl, tot, sum, l4len, csum;
	UINT8 proto;

	if (len < IWAN_OUTER_IP4_LEN)
		return;
	if ((pkt[0] >> 4) != 4)
		return;

	ihl = (ULONG)(pkt[0] & 0x0F) * 4;
	if (ihl < IWAN_OUTER_IP4_LEN || ihl > len)
		return;

	proto = pkt[9];
	tot = iwan_win_rd16(pkt + 2);
	if (tot == 0 || tot > len)
		tot = len;
	/* 下面所有写入都限制在 [ihl, tot) 内，而 tot <= len 刚刚钉死过。
	 * 显式夹一次是给静态分析看的：iwan_win_csum_add() 用 ULONG 做下标，
	 * PREfast 推不出 l4len 与 tot 的关系，会把 L4 头的写当成越界（C6386）。 */
	__analysis_assume(tot <= len);
	__analysis_assume(ihl <= tot);

	/* IPv4 头校验和：清零后重算。
	 * 偏移是 10，不是 12 —— 12 是**源地址**的头两个字节。写错了两件事同时发生：
	 * 内层源地址被校验和盖掉（现场表现为 122.x.0.2 这种随包递减的值，因为
	 * IP ID 每包 +2、校验和就每包 -2），回包永远回不来；下面算 L4 伪首部时
	 * 读的又是同一段被污染的地址，TCP/UDP 校验和跟着一起错。
	 * 金标用例抓不到它：那边用"含校验和字段时总和为 0xFFFF"自证，而校验和
	 * 正是对"12/13 清零后的头"算的、又写回同一位置，自洽。
	 * tests/win_frame_test.c 的 test_inner_fix_csum_keeps_addrs() 以
	 * "地址必须原样"为锚，专门守这一处。 */
	pkt[10] = 0;
	pkt[11] = 0;
	sum = iwan_win_csum_add(0, pkt, ihl, 0);
	iwan_win_wr16(pkt + 10, iwan_win_csum_finish(sum));

	if (!l4_offloaded)
		return;
	if (proto != IWAN_IPPROTO_TCP && proto != IWAN_IPPROTO_UDP)
		return;
	if (tot <= ihl)
		return;

	/* 伪首部：源/目的地址 + 协议号 + L4 长度 */
	l4len = tot - ihl;
	if (l4len > len - ihl)
		l4len = len - ihl;	/* tot <= len 已保证，这行让上界对分析器可见 */
	sum = iwan_win_csum_add(0, pkt + 12, 8, 0);
	sum += (ULONG)proto;
	sum += l4len;

	if (proto == IWAN_IPPROTO_TCP) {
		/* 两条都要判：l4len 够长（数据报里有完整的 TCP 首部），以及
		 * pkt 本身够长（写 ihl + 16 不越界）。第二条由第一条与
		 * l4len <= len - ihl 推出，但静态分析不会替我们做这条推导，
		 * 于是显式写出来 —— 一次比较换掉一条“可能越界写”的告警，
		 * 而且真值上也更稳（万一 l4len 的夹取逻辑将来被改坏）。 */
		if (l4len < IWAN_INNER_TCP_HDR_LEN ||
		    ihl + IWAN_INNER_TCP_HDR_LEN > len)
			return;
		pkt[ihl + 16] = 0;
		pkt[ihl + 17] = 0;
		sum = iwan_win_csum_add(sum, pkt + ihl, l4len, 0);
		iwan_win_wr16(pkt + ihl + 16, iwan_win_csum_finish(sum));
	} else {
		if (l4len < IWAN_INNER_UDP_HDR_LEN ||
		    ihl + IWAN_INNER_UDP_HDR_LEN > len)
			return;
		pkt[ihl + 6] = 0;
		pkt[ihl + 7] = 0;
		sum = iwan_win_csum_add(sum, pkt + ihl, l4len, 0);
		csum = iwan_win_csum_finish(sum);
		if (csum == 0)
			csum = 0xFFFF;	/* UDP：0 表示"无校验和"，用全 1 代替 */
		iwan_win_wr16(pkt + ihl + 6, (USHORT)csum);
	}
}

BOOLEAN
iwan_win_target_match(_In_reads_(count) const IWAN_WIN_TARGET *targets,
		      _In_ UINT32 count, _In_ UINT32 family,
		      _In_reads_bytes_((family == IWAN_WIN_AF_V4) ? 4 : 16)
		      const UINT8 *addr)
{
	ULONG best = 0;
	BOOLEAN hit = FALSE;
	ULONG i;

	for (i = 0; i < count; i++) {
		const IWAN_WIN_TARGET *t = &targets[i];
		ULONG bits, bytes, rem, b;

		if (t->family != family)
			continue;
		bits = t->prefix_len;
		if (family == IWAN_WIN_AF_V4 && bits > 32)
			continue;
		if (family == IWAN_WIN_AF_V6 && bits > 128)
			continue;
		if (bits < best)
			continue;

		bytes = bits / 8;
		rem = bits % 8;
		for (b = 0; b < bytes; b++)
			if (t->addr[b] != addr[b])
				break;
		if (b != bytes)
			continue;
		if (rem != 0) {
			UINT8 mask = (UINT8)(0xFFu << (8 - rem));

			if ((t->addr[bytes] & mask) != (addr[bytes] & mask))
				continue;
		}
		best = bits;
		hit = TRUE;
	}
	return hit;
}

_Success_(return != FALSE)
BOOLEAN
iwan_win_should_tunnel4(_In_reads_(count) const IWAN_WIN_TARGET *targets,
			_In_ UINT32 count,
			_In_reads_bytes_(4) const UINT8 *outer_dst_be,
			_In_reads_bytes_(4) const UINT8 *daddr)
{
	UINT32 i;

	for (i = 0; i < 4; i++)
		if (daddr[i] != outer_dst_be[i])
			break;
	if (i == 4)
		return FALSE;		/* 外层服务器自己：绝不进隧道 */
	return iwan_win_target_match(targets, count, IWAN_WIN_AF_V4, daddr);
}

/* ---- 入向（M2）：外层解析、帧分类、解封 ------------------------------- */

/* 从帧头取 type/enc/sid/tok：三种外层形态共用一份，改一处不会漏两处 */
/* 只写 out 的 type/enc/sid/tok 四个字段（frame_off 必须已被调用者填好），
 * 所以这里用 _Inout_ 而不是 _Out_：_Out_ 会让分析器认为 out 被整体重写，
 * 而它先前填的 frame_off/frame_len 恰恰是这里要读的。 */
static VOID
iwan_win_frame_hdr_read(_In_ const UINT8 *pkt, _Inout_ IWAN_WIN_OUTER *out)
{
	out->type = pkt[out->frame_off + 0];
	out->enc = pkt[out->frame_off + 1];
	out->sid = iwan_win_rd16(pkt + out->frame_off + 2);
	out->tok = ((UINT32)pkt[out->frame_off + 4] << 24) |
		   ((UINT32)pkt[out->frame_off + 5] << 16) |
		   ((UINT32)pkt[out->frame_off + 6] << 8) |
		   (UINT32)pkt[out->frame_off + 7];
}

_Success_(return != FALSE)
BOOLEAN
iwan_win_outer_parse4(_In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		      _Out_ IWAN_WIN_OUTER *out)
{
	ULONG ihl, ulen, need, avail;
	UINT8 proto;

	/* 失败路径不填 out 是契约，但“不填”与“未初始化”在静态分析眼里
	 * 没法区分（C6101）。先清零再填：失败时调用者顶多读到全零，不会
	 * 从栈上捡到上一个包留下的偏移量。 */
	RtlZeroMemory(out, sizeof(*out));
	if (len < IWAN_OUTER_IP4_LEN || (pkt[0] >> 4) != 4)
		return FALSE;
	ihl = (ULONG)(pkt[0] & 0x0F) * 4;
	if (ihl < IWAN_OUTER_IP4_LEN || ihl > len)
		return FALSE;
	proto = pkt[9];
	if (proto != IWAN_IPPROTO_UDP)
		return FALSE;
	/* 外层分片一律不处理（MF 位与偏移都要为 0 才是完整数据报）：首片虽然
	 * 带 UDP 与帧头，但内层是残的，解封出来会注入一个残缺内层包。Linux 侧
	 * 在外层走 ip_defrag() 重组，Windows 侧 M2 不做重组 —— 实践中两端的外层
	 * 包都按协商 MTU 发送（客户端 DF=1），所以这里是异常路径：调用者按
	 * "命中五元组但处理不了" 计数并吞掉，绝不把残缺包放给本机协议栈。 */
	if ((iwan_win_rd16(pkt + 6) & 0x3FFF) != 0)
		return FALSE;
	/* 外层 UDP 长度：按它取帧长，并用包实际长度兜底 */
	if (len < ihl + IWAN_OUTER_UDP_LEN)
		return FALSE;
	ulen = iwan_win_rd16(pkt + ihl + 4);
	if (ulen < IWAN_OUTER_UDP_LEN)
		return FALSE;
	avail = len - ihl;
	if (ulen > avail)
		ulen = avail;

	need = ihl + IWAN_OUTER_UDP_LEN + IWAN_FRAME_HDR_LEN;
	if (len < need)
		return FALSE;

	out->sport = iwan_win_rd16(pkt + ihl + 0);
	out->dport = iwan_win_rd16(pkt + ihl + 2);
	out->frame_off = ihl + IWAN_OUTER_UDP_LEN;
	out->frame_len = ulen - IWAN_OUTER_UDP_LEN;
	if (out->frame_len < IWAN_FRAME_HDR_LEN)
		return FALSE;
	out->inner_off = out->frame_off + IWAN_FRAME_HDR_LEN;
	out->inner_len = out->frame_len - IWAN_FRAME_HDR_LEN;
	if (out->inner_len == 0)
		return FALSE;

	iwan_win_frame_hdr_read(pkt, out);
	return TRUE;
}

UINT32
iwan_win_frame_classify(_In_ const IWAN_WIN_OUTER *o, _In_ UINT16 sess_sid,
			_In_ UINT32 sess_tok, _In_ BOOLEAN sess_enc,
			_In_ BOOLEAN session_established)
{
	BOOLEAN cred_ok = (o->sid == sess_sid && o->tok == sess_tok);

	switch (o->type) {
	case PT_DATA:
		if (sess_enc)
			return IWAN_WIN_FRAME_BAD;
		break;
	case PT_DATA_ENC:
		if (!sess_enc)
			return IWAN_WIN_FRAME_BAD;
		break;
	case PT_OPEN:
	case PT_OPEN_ACK:
	case PT_OPEN_REJECT:
	case PT_ECHO_REQ:
	case PT_ECHO_RES:
	case PT_CLOSE:
	case PT_PING_REQ:
	case PT_PING_RSP:
		if (!session_established)
			return IWAN_WIN_FRAME_BAD;
		if (o->type == PT_OPEN || o->type == PT_OPEN_ACK ||
		    o->type == PT_OPEN_REJECT)
			return IWAN_WIN_FRAME_CTRL;	/* 凭据留给用户态校验 */
		if (o->type == PT_PING_REQ || o->type == PT_PING_RSP)
			return (cred_ok || (o->sid == IWAN_PING_SID &&
					    o->tok == IWAN_PING_TOK))
				       ? IWAN_WIN_FRAME_CTRL
				       : IWAN_WIN_FRAME_BAD;
		return cred_ok ? IWAN_WIN_FRAME_CTRL : IWAN_WIN_FRAME_BAD;
	default:
		return IWAN_WIN_FRAME_BAD;
	}
	/* 走得到这里的只有 PT_DATA / PT_DATA_ENC。两者都必须与帧头的 enc 字节
	 * 一致：解封是按帧里的 o->enc 决定要不要解密的（iwan_win_decap），
	 * 只看类型就能被降级 —— 会话是加密的，攻击者发 type=PT_DATA_ENC 但
	 * enc=0（sid/tok 在帧头明文，照抄即可），decap 走明文分支，任意内层包
	 * 直通。判据必须与解密那一侧同源。 */
	if (o->enc != (sess_enc ? 1u : 0u))
		return IWAN_WIN_FRAME_BAD;
	return cred_ok ? IWAN_WIN_FRAME_DATA : IWAN_WIN_FRAME_BAD;
}

_Success_(return != 0)
ULONG
iwan_win_decap(_In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
	       _In_ const IWAN_WIN_OUTER *o,
	       _In_reads_bytes_(IWAN_KEY_LEN) const UINT8 *key,
	       _Out_writes_bytes_(outsz) UINT8 *out, _In_ ULONG outsz)
{
	if (o->inner_len == 0 || o->inner_len > outsz)
		return 0;
	if (o->inner_off + o->inner_len > len)
		return 0;

	if (o->enc)
		iwan_win_copy_dec(out, pkt + o->inner_off, o->inner_len, key);
	else
		RtlCopyMemory(out, pkt + o->inner_off, o->inner_len);
	return o->inner_len;
}

UINT32
iwan_win_inner_family(_In_reads_bytes_(len) const UINT8 *inner, _In_ ULONG len)
{
	if (len < 1)
		return 0;
	if ((inner[0] >> 4) == 4)
		return 4;
	if ((inner[0] >> 4) == 6)
		return 6;
	return 0;
}

BOOLEAN
iwan_win_inner_sane(_In_reads_bytes_(len) const UINT8 *inner, _In_ ULONG len)
{
	ULONG hlen, total;

	if (len < 1)
		return FALSE;
	switch (inner[0] >> 4) {
	case 4:
		if (len < 20)
			return FALSE;
		hlen = (ULONG)(inner[0] & 0x0F) * 4;
		if (hlen < 20 || hlen > len)
			return FALSE;
		total = iwan_win_rd16(inner + 2);
		break;
	case 6:
		if (len < 40)
			return FALSE;
		hlen = 40;			/* 扩展头不在这里展开 */
		total = hlen + iwan_win_rd16(inner + 4);
		break;
	default:
		return FALSE;
	}
	/* 头部声明的长度盖不住整帧才拒（多余尾字节不拒，与内核侧同口径） */
	return total >= hlen && total <= len;
}

/* ---- 出向：外层头构造 ------------------------------------------------- */

ULONG
iwan_win_outer_build4(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
		      _In_reads_bytes_(flen) const UINT8 *frame, _In_ ULONG flen,
		      _In_ UINT32 src_be, _In_ UINT32 dst_be, _In_ USHORT sport,
		      _In_ USHORT dport)
{
	if (flen == 0 || IWAN_OUTER4_TOTAL + flen > bufsz)
		return 0;
	/* 帧紧跟在 IP + UDP 之后：IWAN_OUTER4_TOTAL 是"封装总开销"，它比帧的
	 * 起始偏移多出一个帧头长度。写错这里会得到一个"总长对、内容错位"的包。 */
	RtlCopyMemory(buf + IWAN_OUTER4_TOTAL - IWAN_FRAME_HDR_LEN, frame, flen);
	return iwan_win_outer_hdr4(buf, bufsz, flen, src_be, dst_be, sport, dport);
}

ULONG
iwan_win_outer_hdr4(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
		    _In_ ULONG flen, _In_ UINT32 src_be, _In_ UINT32 dst_be,
		    _In_ USHORT sport, _In_ USHORT dport)
{
	/* flen 是整帧长度（含 8 字节帧头），而 IWAN_OUTER4_TOTAL 已经把帧头
	 * 算进“封装总开销”里了：真实包长 = 帧起始偏移 + flen，也就是
	 * IWAN_OUTER4_TOTAL - IWAN_FRAME_HDR_LEN + flen。不减这一个帧头长度，外层 IP
	 * 就会声称比实际多 8 字节，接收侧照声明长度取到的尾部是垃圾。 */
	ULONG total = IWAN_OUTER4_TOTAL - IWAN_FRAME_HDR_LEN + flen;
	ULONG ulen = IWAN_OUTER_UDP_LEN + flen;
	ULONG sum;

	if (flen < IWAN_FRAME_HDR_LEN || total > bufsz || total > 0xFFFF ||
	    ulen > 0xFFFF)
		return 0;
	/* 外层 UDP（校验和先清零再算） */
	iwan_win_wr16(buf + IWAN_OUTER_IP4_LEN + 0, sport);
	iwan_win_wr16(buf + IWAN_OUTER_IP4_LEN + 2, dport);
	iwan_win_wr16(buf + IWAN_OUTER_IP4_LEN + 4, (USHORT)ulen);
	iwan_win_wr16(buf + IWAN_OUTER_IP4_LEN + 6, 0);

	/* 外层 IPv4：ttl 64、DF=1（外层不再分片，MTU 由会话的内层 MTU 保证） */
	RtlZeroMemory(buf, IWAN_OUTER_IP4_LEN);
	buf[0] = 0x45;
	iwan_win_wr16(buf + 2, (USHORT)total);
	iwan_win_wr16(buf + 6, IWAN_IP4_DF);
	buf[8] = 64;
	buf[9] = IWAN_IPPROTO_UDP;
	iwan_win_wr32(buf + 12, src_be);
	iwan_win_wr32(buf + 16, dst_be);
	sum = iwan_win_csum_add(0, buf, IWAN_OUTER_IP4_LEN, 0);
	iwan_win_wr16(buf + 10, iwan_win_csum_finish(sum));

	/* UDP 校验和：伪头（src/dst/zero/proto/len）+ UDP 头 + 载荷 */
	{
		/* 伪头的 zero + protocol 两字节 */
		UINT8 zp[2] = { 0, IWAN_IPPROTO_UDP };

		sum = iwan_win_csum_add(0, buf + 12, 8, 0);
		sum = iwan_win_csum_add(sum, zp, 2, 0);
	}
	sum = iwan_win_csum_add(sum, buf + IWAN_OUTER_IP4_LEN + 4, 2, 0);
	sum = iwan_win_csum_add(sum, buf + IWAN_OUTER_IP4_LEN, ulen, 0);
	sum = iwan_win_csum_finish(sum);
	if (sum == 0)
		sum = 0xFFFF;	/* 0 表示"无校验和"，用全 1 代替 */
	iwan_win_wr16(buf + IWAN_OUTER_IP4_LEN + 6, (USHORT)sum);
	return total;
}

ULONG
iwan_win_outer_build6(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
		      _In_reads_bytes_(flen) const UINT8 *frame, _In_ ULONG flen,
		      _In_reads_bytes_(16) const UINT8 *src6,
		      _In_reads_bytes_(16) const UINT8 *dst6, _In_ USHORT sport,
		      _In_ USHORT dport)
{
	if (flen == 0 || IWAN_OUTER6_TOTAL + flen > bufsz)
		return 0;
	RtlCopyMemory(buf + IWAN_OUTER6_TOTAL - IWAN_FRAME_HDR_LEN, frame, flen);
	return iwan_win_outer_hdr6(buf, bufsz, flen, src6, dst6, sport, dport);
}

ULONG
iwan_win_outer_hdr6(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
		    _In_ ULONG flen, _In_reads_bytes_(16) const UINT8 *src6,
		    _In_reads_bytes_(16) const UINT8 *dst6, _In_ USHORT sport,
		    _In_ USHORT dport)
{
	/* flen 是整帧长度（含 8 字节帧头），而 IWAN_OUTER6_TOTAL 已经把帧头
	 * 算进“封装总开销”里了：真实包长 = 帧起始偏移 + flen，也就是
	 * IWAN_OUTER6_TOTAL - IWAN_FRAME_HDR_LEN + flen。不减这一个帧头长度，外层 IP
	 * 就会声称比实际多 8 字节，接收侧照声明长度取到的尾部是垃圾。 */
	ULONG total = IWAN_OUTER6_TOTAL - IWAN_FRAME_HDR_LEN + flen;
	ULONG ulen = IWAN_OUTER_UDP_LEN + flen;
	ULONG sum;

	if (flen < IWAN_FRAME_HDR_LEN || total > bufsz || ulen > 0xFFFF)
		return 0;
	iwan_win_wr16(buf + IWAN_OUTER_IP6_LEN + 0, sport);
	iwan_win_wr16(buf + IWAN_OUTER_IP6_LEN + 2, dport);
	iwan_win_wr16(buf + IWAN_OUTER_IP6_LEN + 4, (USHORT)ulen);
	iwan_win_wr16(buf + IWAN_OUTER_IP6_LEN + 6, 0);

	/* 外层 IPv6：traffic class 与 flow label 全 0（与 iwan_tx_outer6 的
	 * memset 后只填 version/nexthdr/hop_limit/payload_len/地址一致） */
	RtlZeroMemory(buf, IWAN_OUTER_IP6_LEN);
	buf[0] = 0x60;			/* version 6, tc 0, flow label 0 */
	iwan_win_wr16(buf + 4, (USHORT)ulen);	/* payload_len = UDP 头 + 载荷 */
	buf[6] = IWAN_IPPROTO_UDP;
	buf[7] = 64;
	RtlCopyMemory(buf + 8, src6, 16);
	RtlCopyMemory(buf + 24, dst6, 16);

	/* UDP 校验和：v6 伪头是 16B 源 + 16B 目的 + 4B 长度 + 3B 零 + 1B 下一头 */
	{
		/* 伪头尾部：3 字节零 + 下一头；长度字段只有低 16 位可能非零 */
		UINT8 zp[4] = { 0, 0, 0, IWAN_IPPROTO_UDP };

		sum = iwan_win_csum_add(0, src6, 16, 0);
		sum = iwan_win_csum_add(sum, dst6, 16, 0);
		sum = iwan_win_csum_add(sum, zp, 4, 0);
	}
	sum = iwan_win_csum_add(sum, buf + IWAN_OUTER_IP6_LEN + 4, 2, 0);
	sum = iwan_win_csum_add(sum, buf + IWAN_OUTER_IP6_LEN, ulen, 0);
	sum = iwan_win_csum_finish(sum);
	if (sum == 0)
		sum = 0xFFFF;
	iwan_win_wr16(buf + IWAN_OUTER_IP6_LEN + 6, (USHORT)sum);
	return total;
}

_Success_(return != FALSE)
BOOLEAN
iwan_win_outer_parse6(_In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		      _Out_ IWAN_WIN_OUTER *out)
{
	ULONG ulen, avail, need;

	RtlZeroMemory(out, sizeof(*out));
	if (len < IWAN_OUTER6_TOTAL || (pkt[0] >> 4) != 6)
		return FALSE;
	/* 外层 v6 由 iwan_tx_outer6 构造：nexthdr 直接是 UDP，不带扩展头；
	 * 出现扩展头说明不是本隧道的格式，交回协议栈。 */
	if (pkt[6] != IWAN_IPPROTO_UDP)
		return FALSE;
	ulen = iwan_win_rd16(pkt + IWAN_OUTER_IP6_LEN + 4);
	if (ulen < IWAN_OUTER_UDP_LEN)
		return FALSE;
	avail = len - IWAN_OUTER_IP6_LEN;
	if (ulen > avail)
		ulen = avail;

	need = IWAN_OUTER6_TOTAL + IWAN_FRAME_HDR_LEN;
	if (len < need)
		return FALSE;

	out->sport = iwan_win_rd16(pkt + IWAN_OUTER_IP6_LEN + 0);
	out->dport = iwan_win_rd16(pkt + IWAN_OUTER_IP6_LEN + 2);
	out->frame_off = IWAN_OUTER6_TOTAL - IWAN_FRAME_HDR_LEN;
	out->frame_len = ulen - IWAN_OUTER_UDP_LEN;
	if (out->frame_len < IWAN_FRAME_HDR_LEN)
		return FALSE;
	out->inner_off = out->frame_off + IWAN_FRAME_HDR_LEN;
	out->inner_len = out->frame_len - IWAN_FRAME_HDR_LEN;
	if (out->inner_len == 0)
		return FALSE;

	iwan_win_frame_hdr_read(pkt, out);
	return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
iwan_win_dgram_parse(_In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		     _Out_ IWAN_WIN_OUTER *out)
{
	ULONG off = 0, ulen, avail;

	RtlZeroMemory(out, sizeof(*out));
	if (len < IWAN_OUTER_UDP_LEN)
		return FALSE;

	/* 先判"是不是仍带 IP 头"：四项自洽才认，否则一律当裸数据报 */
	if ((pkt[0] >> 4) == 4 && len >= IWAN_OUTER_IP4_LEN) {
		ULONG ihl = (ULONG)(pkt[0] & 0x0F) * 4;

		if (ihl >= IWAN_OUTER_IP4_LEN && ihl <= len &&
		    pkt[9] == IWAN_IPPROTO_UDP &&
		    (iwan_win_rd16(pkt + 6) & 0x3FFF) == 0)
			off = ihl;
	} else if ((pkt[0] >> 4) == 6 && len >= IWAN_OUTER_IP6_LEN) {
		if (pkt[6] == IWAN_IPPROTO_UDP)
			off = IWAN_OUTER_IP6_LEN;
	}

	if (len < off + IWAN_OUTER_UDP_LEN + IWAN_FRAME_HDR_LEN)
		return FALSE;
	ulen = iwan_win_rd16(pkt + off + 4);
	if (ulen < IWAN_OUTER_UDP_LEN)
		return FALSE;
	avail = len - off;
	if (ulen > avail)
		ulen = avail;		/* UDP 长度撒谎时按实际长度兜底 */

	out->sport = iwan_win_rd16(pkt + off + 0);
	out->dport = iwan_win_rd16(pkt + off + 2);
	out->frame_off = off + IWAN_OUTER_UDP_LEN;
	out->frame_len = ulen - IWAN_OUTER_UDP_LEN;
	if (out->frame_len < IWAN_FRAME_HDR_LEN)
		return FALSE;
	out->inner_off = out->frame_off + IWAN_FRAME_HDR_LEN;
	out->inner_len = out->frame_len - IWAN_FRAME_HDR_LEN;
	if (out->inner_len == 0)
		return FALSE;

	iwan_win_frame_hdr_read(pkt, out);
	return TRUE;
}

BOOLEAN
iwan_win_should_tunnel6(_In_reads_(count) const IWAN_WIN_TARGET *targets,
			_In_ UINT32 count, _In_reads_bytes_(16) const UINT8 *outer_dst6,
			_In_reads_bytes_(16) const UINT8 *daddr6)
{
	if (targets == NULL || outer_dst6 == NULL || daddr6 == NULL)
		return FALSE;
	/* 外层服务器自己：绝不进隧道（否则封装包会再被自己匹配一次，打成环） */
	if (RtlCompareMemory(daddr6, outer_dst6, 16) == 16)
		return FALSE;
	return iwan_win_target_match(targets, count, IWAN_WIN_AF_V6, daddr6);
}
