/* SPDX-License-Identifier: GPL-2.0 */
/*
 * win_frame_test.c — Windows 数据面纯逻辑的对拍与自检（可在 Linux 上跑）。
 *
 * 为什么要有这个测试：封装格式是 Windows 驱动与 Linux 模块、用户态客户端三者
 * 互通的硬前提，而它偏偏是最容易写错、又最难在 Windows 上调的部分（写错只会
 * 表现为"对端全丢包"）。所以把纯逻辑抽到 win-driver/iwan_win_frame.c，在本机
 * 用主机编译器与仓库里已有的**独立实现**对拍：
 *
 *   · 帧头：与 src/common/protocol.c 的 pkt_hdr() 逐字节比对；
 *   · XOR ：与 src/common/crypto.c 的 xor_crypt(key, 8) 逐字节比对；
 *   · 校验和：用独立验证器复算（包含校验和字段时总和必须为 0xFFFF）；
 *   · 目标匹配：最长前缀语义 + "外层服务器地址绝不进隧道"。
 *
 * 构建（本机验证过）：
 *   gcc -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
 *       -DIWAN_WIN_ABI_BARE -Isrc/common -Iwin-driver \
 *       tests/win_frame_test.c win-driver/iwan_win_frame.c \
 *       src/common/protocol.c src/common/crypto.c src/common/util.c \
 *       -Wl,--gc-sections -lcrypto -o /tmp/win_frame_test
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "iwan_win_frame.h"

/* 仓库里已有的用户态实现（独立于驱动的那一份），用于对拍 */
void pkt_hdr(uint8_t typ, uint8_t enc, uint16_t sid, uint32_t tok,
	     uint8_t out[8]);
void xor_crypt(uint8_t *data, size_t len, const uint8_t *key, size_t klen);

static int g_fail;
static int g_pass;

#define CHECK(cond, ...) do {						\
	if (cond) {							\
		g_pass++;						\
	} else {							\
		g_fail++;						\
		printf("FAIL %s:%d: ", __FILE__, __LINE__);		\
		printf(__VA_ARGS__);					\
		printf("\n");						\
	}								\
} while (0)

/* ---- 1. 帧头：与用户态 pkt_hdr() 对拍 --------------------------------- */

static void
test_frame_hdr(void)
{
	static const struct {
		uint8_t typ, enc;
		uint16_t sid;
		uint32_t tok;
	} cases[] = {
		{ IWAN_PT_DATA,     0, 0x0000, 0x00000000 },
		{ IWAN_PT_DATA_ENC, 1, 0x1234, 0xdeadbeef },
		{ IWAN_PT_DATA_ENC, 1, 0x030c, 0x00000001 },
		{ IWAN_PT_DATA,     0, 0xffff, 0xffffffff },
		{ IWAN_PT_DATA_ENC, 1, 0x00ff, 0x01000000 },
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		uint8_t mine[8], theirs[8];

		iwan_win_build_frame_hdr(mine, cases[i].typ, cases[i].enc,
					 cases[i].sid, cases[i].tok);
		pkt_hdr(cases[i].typ, cases[i].enc, cases[i].sid, cases[i].tok,
			theirs);
		CHECK(memcmp(mine, theirs, 8) == 0,
		      "帧头与用户态 pkt_hdr 不一致（sid=%04x tok=%08x）",
		      cases[i].sid, cases[i].tok);
	}

	/* 字段顺序按 kernel/iwan_tx.c 的 fh[] 钉死：类型、enc、
	 * sid 大端 16 位、tok 大端 32 位 */
	{
		uint8_t h[8];

		iwan_win_build_frame_hdr(h, IWAN_PT_DATA_ENC, 1, 0x030c,
					 0x01020304);
		CHECK(h[0] == 0x18 && h[1] == 0x01 && h[2] == 0x03 &&
		      h[3] == 0x0c && h[4] == 0x01 && h[5] == 0x02 &&
		      h[6] == 0x03 && h[7] == 0x04,
		      "帧头字节序不符：%02x %02x %02x %02x %02x %02x %02x %02x",
		      h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
	}
}

/* ---- 2. XOR：与用户态 xor_crypt() 对拍 + 往返自检 ---------------------- */

static void
test_xor(void)
{
	uint8_t key[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
	uint8_t a[1024], b[1024];
	size_t lens[] = { 0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 1000, 1024 };
	uint32_t offs[] = { 0, 1, 3, 8 };
	size_t i, j;

	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		for (j = 0; j < sizeof(offs) / sizeof(offs[0]); j++) {
			size_t n = lens[i];
			uint8_t ref[1024];
			size_t k;

			for (k = 0; k < n; k++)
				a[k] = b[k] = (uint8_t)(k * 31 + 7);
			/* 逐字节参考：分块（每轮 64 位字）写法必须与它逐位一致。
			 * 只做往返自检对"相位算错"是盲的——错相位照样能还原。 */
			for (k = 0; k < n; k++)
				ref[k] = (uint8_t)((uint8_t)(k * 31 + 7) ^
						   key[(offs[j] + k) & 7]);

			/* 驱动的实现只在 off 为 0 时对整包使用，但函数本身
			 * 支持 off（与内核 iwan_xor 的语义一致），这里一并验 */
			iwan_win_xor(a, (ULONG)n, key, (ULONG)offs[j]);
			CHECK(memcmp(a, ref, n) == 0,
			      "XOR 与逐字节参考不一致（len=%zu off=%u）",
			      n, offs[j]);
			if (offs[j] == 0) {
				xor_crypt(b, n, key, sizeof(key));
				CHECK(memcmp(a, b, n) == 0,
				      "XOR 与用户态 xor_crypt 不一致（len=%zu）", n);
			}

			/* 往返：再 XOR 一次必须还原 */
			iwan_win_xor(a, (ULONG)n, key, (ULONG)offs[j]);
			for (k = 0; k < n; k++)
				if (a[k] != (uint8_t)(k * 31 + 7))
					break;
			CHECK(k == n, "XOR 往返不还原（len=%zu off=%u）",
			      n, offs[j]);
		}
	}
}

/* ---- 3. 校验和：独立验证器复算 ---------------------------------------- */

/* 标准的"包含校验和字段一起求和 == 0xFFFF"验证 */
static uint32_t
sum16(const uint8_t *p, size_t len)
{
	uint32_t s = 0;
	size_t i;

	for (i = 0; i + 1 < len; i += 2)
		s += ((uint32_t)p[i] << 8) | p[i + 1];
	if (i < len)
		s += ((uint32_t)p[i] << 8);
	while (s >> 16)
		s = (s & 0xFFFF) + (s >> 16);
	return s;
}

static void
test_csum(void)
{
	uint8_t pkt[64];
	uint32_t l4;

	/* 造一个 IPv4 + UDP 报文（20 + 8 + 16 字节载荷），校验和字段先留 0 */
	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x45;
	pkt[8] = 64;
	pkt[9] = 17;			/* UDP */
	pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1;
	pkt[16] = 10; pkt[17] = 0; pkt[18] = 0; pkt[19] = 2;
	pkt[20] = 0x04; pkt[21] = 0xd2;	/* 1234 */
	pkt[22] = 0x16; pkt[23] = 0x2e;	/* 5678 */
	pkt[24] = 0x00; pkt[25] = 0x18;	/* 24 = 8 + 16 */
	{
		uint16_t tot = 44;
		uint8_t t[24];
		size_t k;

		for (k = 0; k < 16; k++)
			pkt[28 + k] = (uint8_t)(k * 7 + 1);
		t[0] = (uint8_t)(tot >> 8);
		t[1] = (uint8_t)tot;
		pkt[2] = t[0];
		pkt[3] = t[1];
	}

	/* 带"校验和卸载"标记：两张都要补齐 */
	iwan_win_inner_fix_csum(pkt, 44, TRUE);

	CHECK(sum16(pkt, 20) == 0xFFFF, "IPv4 头校验和验证失败（sum=%04x）",
	      sum16(pkt, 20));

	/* UDP 校验和验证要带伪首部 */
	l4 = 44 - 20;
	{
		uint32_t s = 0;
		uint8_t pseudo[12];
		uint32_t i;

		memcpy(pseudo, pkt + 12, 8);
		pseudo[8] = 0;
		pseudo[9] = 17;
		pseudo[10] = (uint8_t)(l4 >> 8);
		pseudo[11] = (uint8_t)l4;
		s = sum16(pseudo, sizeof(pseudo));
		for (i = 20; i < 44; i += 2)
			s += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
		while (s >> 16)
			s = (s & 0xFFFF) + (s >> 16);
		CHECK(s == 0xFFFF, "UDP 校验和验证失败（sum=%04x）", s);
	}

	/* 不带卸载标记时只重算 IP 头，不动 L4 */
	{
		uint8_t before[64];

		memset(pkt + 20, 0, 24);
		pkt[20] = 0x04; pkt[21] = 0xd2;
		pkt[22] = 0x16; pkt[23] = 0x2e;
		pkt[24] = 0x00; pkt[25] = 0x18;
		memcpy(before, pkt, 44);
		iwan_win_inner_fix_csum(pkt, 44, FALSE);
		CHECK(memcmp(before + 20, pkt + 20, 24) == 0,
		      "未标记卸载却改动了 L4 区域");
		CHECK(sum16(pkt, 20) == 0xFFFF, "IP 头校验和未重算");
	}

	/* 非 IPv4 或不合法长度：必须原样返回，不能越界写 */
	{
		uint8_t junk[8] = { 0x60, 0, 0, 0, 0, 0, 0, 0 };

		iwan_win_inner_fix_csum(junk, sizeof(junk), TRUE);
		CHECK(junk[0] == 0x60, "非 IPv4 报文被改动");
	}
}


/*
 * 内层校验和修复必须"地址原样"。
 *
 * 这个用例存在的唯一理由：iwan_win_inner_fix_csum() 曾经把 IPv4 头校验和写
 * 到偏移 12（正确是 10）—— 正好盖住内层源地址的高半字。既有用例抓不到它：
 * 两处校验都用"含校验和字段时总和为 0xFFFF"自证，而校验和正是对"12/13 清零
 * 后的头"算出来、又写回同一位置的，于是自洽；UDP 伪首部读的又是同一段被污染
 * 的地址，两个检查一起被骗过去。
 * 现场症状：帧格式、sid/tok、长度全对，对端能解出帧，但内层源地址变成
 * 122.x.0.2 这种随包递减的值（IP ID 每包 +2，校验和就每包 -2），回包永远
 * 回不来 —— ping 100% 丢、UDP 没有应答。
 */
static void
test_inner_fix_csum_keeps_addrs(void)
{
	uint8_t pkt[44];
	const uint8_t src[4] = { 10, 99, 0, 2 };
	const uint8_t dst[4] = { 10, 0, 2, 15 };
	uint32_t s, i;

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x45;
	pkt[2] = 0; pkt[3] = 44;
	pkt[8] = 64;
	pkt[9] = 17;			/* UDP */
	memcpy(pkt + 12, src, 4);
	memcpy(pkt + 16, dst, 4);
	pkt[20] = 0x9c; pkt[21] = 0x41;	/* 源端口 40001 */
	pkt[22] = 0x27; pkt[23] = 0x0f;	/* 目的端口 9999 */
	pkt[24] = 0x00; pkt[25] = 0x18;	/* UDP 长度 24 = 8 + 16 */
	for (i = 0; i < 16; i++)
		pkt[28 + i] = 0xAB;

	iwan_win_inner_fix_csum(pkt, sizeof(pkt), TRUE);

	CHECK(memcmp(pkt + 12, src, 4) == 0,
	      "内层源地址被改写了（IPv4 头校验和在偏移 10/11，不是 12/13）");
	CHECK(memcmp(pkt + 16, dst, 4) == 0, "内层目的地址被改写了");
	CHECK(!(pkt[10] == 0 && pkt[11] == 0),
	      "IPv4 头校验和没有写进偏移 10/11");
	CHECK(sum16(pkt, 20) == 0xFFFF, "IPv4 头校验和自洽性检查失败");

	/* UDP 校验和必须按"真实源地址"的伪首部成立。这里**故意不读 pkt 的
	 * 12..19 字节**，而是用已知的 src/dst 常数算伪首部 —— 读报文自己的地址
	 * 会和实现犯同一个错（实现也是拿被污染的地址算的），等于自己证明自己。 */
	s = 0;
	for (i = 0; i < 4; i += 2)
		s += ((uint32_t)src[i] << 8) | src[i + 1];
	for (i = 0; i < 4; i += 2)
		s += ((uint32_t)dst[i] << 8) | dst[i + 1];
	s += 17 + 24;
	for (i = 20; i < 44; i += 2)
		s += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
	while (s >> 16)
		s = (s & 0xFFFF) + (s >> 16);
	CHECK(s == 0xFFFF, "UDP 校验和未按真实源地址成立（sum=%04x）", s);
}

/* ---- 4. 目标匹配 + 外层服务器排除 ------------------------------------- */

static void
put_v4(IWAN_WIN_TARGET *t, const uint8_t *a, uint32_t plen)
{
	t->family = IWAN_WIN_AF_V4;
	t->prefix_len = plen;
	memset(t->addr, 0, sizeof(t->addr));
	memcpy(t->addr, a, 4);
}

static void
test_targets(void)
{
	IWAN_WIN_TARGET t[4];
	uint8_t server[4] = { 202, 38, 64, 106 };
	uint8_t wide[4] = { 202, 38, 0, 0 };
	uint8_t campus[4] = { 202, 38, 95, 0 };
	uint8_t other[4] = { 8, 8, 8, 8 };
	uint8_t in_campus[4] = { 202, 38, 95, 110 };
	uint8_t in_other[4] = { 202, 38, 100, 1 };

	put_v4(&t[0], wide, 16);		/* 202.38.0.0/16 */
	put_v4(&t[1], campus, 24);	/* 202.38.95.0/24 */
	put_v4(&t[2], server, 32);	/* 服务器 /32 也在集合里 */
	put_v4(&t[3], other, 32);	/* 8.8.8.8/32 */

	CHECK(iwan_win_target_match(t, 4, IWAN_WIN_AF_V4, in_campus),
	      "202.38.95.110 应命中集合");
	CHECK(iwan_win_target_match(t, 4, IWAN_WIN_AF_V4, in_other),
	      "202.38.100.1 应由 /16 命中");
	CHECK(iwan_win_target_match(t, 4, IWAN_WIN_AF_V4, other),
	      "8.8.8.8 命中 /32 自身");
	/* 服务器地址只被 /16 覆盖；只留校园 /24 时它就不该命中 */
	CHECK(!iwan_win_target_match(t + 1, 1, IWAN_WIN_AF_V4, server),
	      "服务器地址不应被校园 /24 命中");

	/* 关键：即使集合里有覆盖服务器的宽前缀，服务器地址也绝不进隧道 */
	CHECK(!iwan_win_should_tunnel4(t, 4, server, server),
	      "外层服务器地址被错误地判为进隧道");
	CHECK(iwan_win_should_tunnel4(t, 4, server, in_campus),
	      "校园地址应进隧道");
	CHECK(iwan_win_should_tunnel4(t, 4, server, other),
	      "8.8.8.8/32 在集合内应进隧道");

	/* v6：/128 与 /64 */
	{
		IWAN_WIN_TARGET v6;
		uint8_t net[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
				    0, 0, 0, 0, 0, 0, 0, 0 };
		uint8_t a1[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
				   0, 0, 0, 0, 0, 0, 0, 1 };
		uint8_t a2[16] = { 0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0,
				   0, 0, 0, 0, 0, 0, 0, 1 };
		uint8_t a3[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x80, 0, 0, 0,
				   0, 0, 0, 0, 0, 0, 0, 1 };

		v6.family = IWAN_WIN_AF_V6;
		v6.prefix_len = 33;
		memcpy(v6.addr, net, 16);
		v6.addr[4] = 0x80;	/* 2001:db8:8000::/33 */
		CHECK(iwan_win_target_match(&v6, 1, IWAN_WIN_AF_V6, a3),
		      "v6 /33 非整字节前缀匹配失败");
		CHECK(!iwan_win_target_match(&v6, 1, IWAN_WIN_AF_V6, a1),
		      "v6 越界地址被误判命中");
		CHECK(!iwan_win_target_match(&v6, 1, IWAN_WIN_AF_V6, a2),
		      "v6 另一前缀被误判命中");
	}
}


/* ---- 5. 入向 M2：外层解析 / 帧分类 / 解封 ----------------------------- */

/* 线上常量必须与 kernel/iwan.h、src/common/protocol.h 一致。数值本身是冻结的
 * 线上契约；下面第 6 组用用户态的 pkt_hdr() 造帧再喂给驱动侧解析，等价于
 * 对这份数值表再做一次交叉验证。 */
static void
test_wire_constants(void)
{
	CHECK(PT_OPEN_REJECT == 0x11 && PT_OPEN_ACK == 0x12 && PT_OPEN == 0x13,
	      "握手帧类型与线上不符");
	CHECK(PT_DATA == 0x14 && PT_ECHO_REQ == 0x15 && PT_ECHO_RES == 0x16 &&
	      PT_CLOSE == 0x17 && PT_DATA_ENC == 0x18,
	      "数据/回声/关闭帧类型与线上不符");
	CHECK(PT_PING_REQ == 0x29 && PT_PING_RSP == 0x2A,
	      "ping 帧类型与线上不符");
	CHECK(IWAN_PING_SID == 0xFFFF && IWAN_PING_TOK == 0xFFFFFFFFu,
	      "ping 固定凭据与线上不符");
	CHECK(IWAN_OUTER4_TOTAL == 36, "外层 IPv4 封装开销应为 36 字节");
}

/* 造一个外层 IPv4 + UDP + 帧头 + 载荷的包（载荷由调用者填） */
static size_t
build_outer(uint8_t *buf, size_t inner_len, uint16_t sport, uint16_t dport,
	    uint8_t type, uint8_t enc, uint16_t sid, uint32_t tok,
	    uint16_t frag_off)
{
	uint8_t *ip = buf, *udp = buf + 20;
	size_t total = 20 + 8 + 8 + inner_len;
	uint32_t sum;

	memset(buf, 0, total);
	ip[0] = 0x45;
	ip[2] = (uint8_t)(total >> 8);
	ip[3] = (uint8_t)total;
	frag_off = (uint16_t)(frag_off | 0x4000u);   /* DF */
	ip[6] = (uint8_t)(frag_off >> 8);
	ip[7] = (uint8_t)frag_off;
	ip[8] = 64;
	ip[9] = 17;
	ip[12] = 202; ip[13] = 38; ip[14] = 64; ip[15] = 106;  /* 服务器 */
	ip[16] = 10; ip[17] = 0; ip[18] = 0; ip[19] = 2;
	udp[0] = (uint8_t)(sport >> 8); udp[1] = (uint8_t)sport;
	udp[2] = (uint8_t)(dport >> 8); udp[3] = (uint8_t)dport;
	{
		uint16_t ul = (uint16_t)(8 + 8 + inner_len);

		udp[4] = (uint8_t)(ul >> 8);
		udp[5] = (uint8_t)ul;
	}
	iwan_win_build_frame_hdr(buf + 28, type, enc, sid, tok);
	sum = 0;
	for (size_t i = 0; i + 1 < 20; i += 2)
		sum += ((uint32_t)ip[i] << 8) | ip[i + 1];
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	sum = ~sum & 0xFFFF;
	ip[10] = (uint8_t)(sum >> 8);
	ip[11] = (uint8_t)sum;
	return total;
}

static void
test_inbound(void)
{
	const uint8_t key[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t inner[64], outer[256], out[128];
	IWAN_WIN_OUTER o;
	size_t total, n;
	uint16_t sid = 0x030c;
	uint32_t tok = 0xdeadbeef;

	/* 内层 IPv4 包（20 字节头 + 8 字节 UDP 头 + 4 字节载荷） */
	memset(inner, 0, sizeof(inner));
	inner[0] = 0x45;
	inner[2] = 0; inner[3] = 32;
	inner[8] = 64;
	inner[9] = 17;
	inner[12] = 10; inner[13] = 0; inner[14] = 0; inner[15] = 2;
	inner[16] = 8; inner[17] = 8; inner[18] = 8; inner[19] = 8;
	inner[20] = 0x04; inner[21] = 0xd2;
	inner[22] = 0x16; inner[23] = 0x2e;
	inner[24] = 0; inner[25] = 12;
	inner[28] = 'i'; inner[29] = 'w'; inner[30] = 'a'; inner[31] = 'n';

	/* --- 加密帧：解析 + 分类 + 解封，还原出内层原样 --- */
	{
		uint8_t enc_inner[64];

		memcpy(enc_inner, inner, 32);
		xor_crypt(enc_inner, 32, key, 8);
		total = build_outer(outer, 32, 40000, 6001, PT_DATA_ENC, 1, sid, tok, 0);
		memcpy(outer + 36, enc_inner, 32);

		CHECK(iwan_win_outer_parse4(outer, total, &o), "合法外层包解析失败");
		CHECK(o.type == PT_DATA_ENC && o.enc == 1 && o.sid == sid &&
		      o.tok == tok, "帧头字段解析错位");
		CHECK(o.inner_off == 36 && o.inner_len == 32, "内层偏移/长度算错");
		CHECK(iwan_win_inner_family(outer + 36, 32) == 4,
		      "加密内层不该直接判协议族（应为 v4 首字节）");
		CHECK(iwan_win_frame_classify(&o, sid, tok, TRUE, TRUE) ==
		      IWAN_WIN_FRAME_DATA, "合法加密数据帧应判为 DATA");
		n = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
		CHECK(n == 32, "解封长度错误");
		CHECK(memcmp(out, inner, 32) == 0, "解封结果与内层原文不符");
		CHECK(iwan_win_inner_family(out, n) == 4, "解封后应识别为内层 v4");
	}

	/* --- 明文帧 --- */
	{
		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0);
		memcpy(outer + 36, inner, 32);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "明文外层包解析失败");
		CHECK(iwan_win_frame_classify(&o, sid, tok, FALSE, TRUE) ==
		      IWAN_WIN_FRAME_DATA, "合法明文数据帧应判为 DATA");
		n = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
		CHECK(n == 32 && memcmp(out, inner, 32) == 0, "明文解封应原样返回");
	}

	/* --- 内层 v6（外层仍是 v4）：注入时要用 v6 句柄 --- */
	{
		uint8_t in6[48];

		memset(in6, 0, sizeof(in6));
		in6[0] = 0x60;
		in6[4] = 0; in6[5] = 8;          /* payload len */
		in6[6] = 17;                     /* next header = UDP */
		in6[7] = 64;
		in6[8] = 0x20; in6[9] = 0x01;
		total = build_outer(outer, 48, 40000, 6001, PT_DATA, 0, sid, tok, 0);
		memcpy(outer + 36, in6, 48);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "v6-in-v4 解析失败");
		n = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
		CHECK(n == 48 && iwan_win_inner_family(out, n) == 6,
		      "内层 v6 应识别为协议族 6");
	}

	/* --- 凭据与类型闸门 --- */
	{
		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0);
		memcpy(outer + 36, inner, 32);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "解析失败");
		CHECK(iwan_win_frame_classify(&o, sid, tok + 1, FALSE, TRUE) ==
		      IWAN_WIN_FRAME_BAD, "sid/tok 不符的数据帧必须丢弃");
		CHECK(iwan_win_frame_classify(&o, sid, tok, TRUE, TRUE) ==
		      IWAN_WIN_FRAME_BAD, "enc 模式不符的数据帧必须丢弃");
		/* 数据帧不看会话闸门（kernel/iwan_rx.c 的 iwan_frame_check 只对
		 * 控制帧查 dp->session）；"有没有会话"由调用点先判 —— 驱动里就是
		 * 先看 s->valid，没有会话时整个 callout 直接放行不碰。 */
		CHECK(iwan_win_frame_classify(&o, sid, tok, FALSE, FALSE) ==
		      IWAN_WIN_FRAME_DATA, "数据帧分类不应受会话闸门影响");
	}

	/* --- 类型与帧头 enc 必须自洽：否则加密会话可被降级成明文直通 ---
	 * 解封那一侧（iwan_win_decap）是按帧里的 o->enc 决定要不要解密的，
	 * 分类只看类型就留下了缺口：会话是加密的，攻击者发 type=PT_DATA_ENC
	 * 但 enc=0（sid/tok 在帧头明文，照抄即可），decap 走明文分支，
	 * 任意内层包直通。下面两组是"闸门必须拦住、而 decap 本身拦不住"的证据。 */
	{
		total = build_outer(outer, 32, 40000, 6001, PT_DATA_ENC, 0, sid, tok, 0);
		memcpy(outer + 36, inner, 32);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "解析失败");
		CHECK(o.type == PT_DATA_ENC && o.enc == 0, "帧头字段解析错位");
		CHECK(iwan_win_frame_classify(&o, sid, tok, TRUE, TRUE) ==
		      IWAN_WIN_FRAME_BAD, "加密会话里 enc=0 的数据帧必须丢弃");
		CHECK(iwan_win_decap(outer, total, &o, key, out, sizeof(out)) == 32 &&
		      memcmp(out, inner, 32) == 0,
		      "对照：decap 确实按帧里的 enc 走明文分支，闸门只能在分类处");

		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 1, sid, tok, 0);
		memcpy(outer + 36, inner, 32);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "解析失败");
		CHECK(o.enc == 1, "帧头 enc 解析错位");
		CHECK(iwan_win_frame_classify(&o, sid, tok, FALSE, TRUE) ==
		      IWAN_WIN_FRAME_BAD, "明文会话里 enc=1 的数据帧必须丢弃");
	}

	/* --- 控制帧：ECHO/CLOSE 要凭据，握手帧一律转交；ping 接受固定凭据 --- */
	{
		static const struct { uint8_t type; uint16_t sid; uint32_t tok;
				      uint32_t want; } c[] = {
			{ PT_ECHO_REQ, 0x030c, 0xdeadbeef, IWAN_WIN_FRAME_CTRL },
			{ PT_ECHO_RES, 0x030c, 0xdeadbeef, IWAN_WIN_FRAME_CTRL },
			{ PT_CLOSE,    0x030c, 0xdeadbeef, IWAN_WIN_FRAME_CTRL },
			{ PT_ECHO_REQ, 0x0001, 0xdeadbeef, IWAN_WIN_FRAME_BAD },
			{ PT_OPEN,     0x0000, 0x00000000, IWAN_WIN_FRAME_CTRL },
			{ PT_OPEN_ACK, 0x1234, 0xabcdef01, IWAN_WIN_FRAME_CTRL },
			{ PT_OPEN_REJECT, 0x0000, 0x00000000, IWAN_WIN_FRAME_CTRL },
			{ PT_PING_REQ, IWAN_PING_SID, IWAN_PING_TOK,
			  IWAN_WIN_FRAME_CTRL },
			{ PT_PING_RSP, 0x030c, 0xdeadbeef, IWAN_WIN_FRAME_CTRL },
			{ PT_PING_REQ, 0x030c, 0x11111111, IWAN_WIN_FRAME_BAD },
		};
		size_t i;

		for (i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
			total = build_outer(outer, 8, 40000, 6001, c[i].type, 0,
					    c[i].sid, c[i].tok, 0);
			CHECK(iwan_win_outer_parse4(outer, total, &o),
			      "控制帧解析失败（type=%02x）", c[i].type);
			CHECK(iwan_win_frame_classify(&o, 0x030c, 0xdeadbeef,
						      FALSE, TRUE) == c[i].want,
			      "控制帧分类不符（type=%02x sid=%04x）",
			      c[i].type, c[i].sid);
		}
		/* 未建会话时连握手帧都要丢（与内核侧 session 闸门一致） */
		total = build_outer(outer, 8, 40000, 6001, PT_OPEN_ACK, 0, 1, 2, 0);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "解析失败");
		CHECK(iwan_win_frame_classify(&o, 0x030c, 0xdeadbeef, FALSE, FALSE) ==
		      IWAN_WIN_FRAME_BAD, "未建会话时握手帧也要丢弃");
	}

	/* --- 结构不合法：分片、截断、非 UDP、长度撒谎，都必须安全拒绝 --- */
	{
		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok,
				    0x2000);      /* MF 置位 */
		CHECK(!iwan_win_outer_parse4(outer, total, &o), "分片不应被解析");
		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok,
				    100);         /* 非首片偏移 */
		CHECK(!iwan_win_outer_parse4(outer, total, &o), "非首片不应被解析");
		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0);
		outer[9] = 6;                          /* TCP */
		CHECK(!iwan_win_outer_parse4(outer, total, &o), "非 UDP 不应被解析");
		outer[9] = 17;
		CHECK(!iwan_win_outer_parse4(outer, 30, &o), "截断包不应被解析");
		CHECK(!iwan_win_outer_parse4(outer, 0, &o), "空包不应被解析");
		/* UDP 长度大于实际：按实际长度兜底，仍能解析（与内核侧宽松口径一致） */
		outer[24] = 0xff; outer[25] = 0xff;
		CHECK(iwan_win_outer_parse4(outer, total, &o), "UDP 长度撒谎应兜底解析");
		CHECK(o.inner_len == total - 36, "兜底后的内层长度不对");
		/* 内层为 0 长度：拒绝 */
		total = build_outer(outer, 0, 40000, 6001, PT_DATA, 0, sid, tok, 0);
		CHECK(!iwan_win_outer_parse4(outer, total, &o), "零长内层应拒绝");
	}

	/* --- 解封输出缓冲不够：必须拒绝而不是溢出 --- */
	{
		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0);
		memcpy(outer + 36, inner, 32);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "解析失败");
		CHECK(iwan_win_decap(outer, total, &o, key, out, 16) == 0,
		      "输出缓冲不足时必须拒绝");
	}

	/* --- 内层头自洽性（注入前的最后一道闸）--- */
	{
		CHECK(iwan_win_inner_sane(inner, 32), "合法内层 v4 包应通过");
		CHECK(!iwan_win_inner_sane(inner, 12), "内层 v4 头不全应拒绝");
		{
			uint8_t bad[32];

			memcpy(bad, inner, 32);
			bad[3] = 200;           /* 声明的总长超过实际 */
			CHECK(!iwan_win_inner_sane(bad, 32),
			      "内层声明长度超过整帧应拒绝");
			memcpy(bad, inner, 32);
			bad[0] = 0x35;          /* ihl=5 => 20，合法；改成 0x4f 试 */
			bad[0] = 0x4f;          /* ihl=15 => 60 > len */
			CHECK(!iwan_win_inner_sane(bad, 32), "内层 ihl 越界应拒绝");
			memcpy(bad, inner, 32);
			bad[0] = 0x70;          /* 版本 7 */
			CHECK(!iwan_win_inner_sane(bad, 32), "未知内层版本应拒绝");
		}
		{
			uint8_t in6[48];

			memset(in6, 0, sizeof(in6));
			in6[0] = 0x60;
			in6[4] = 0; in6[5] = 8;         /* payload len = 8 */
			in6[6] = 17;
			CHECK(iwan_win_inner_sane(in6, 48), "合法内层 v6 包应通过");
			in6[5] = 200;                   /* 声明长度超过整帧 */
			CHECK(!iwan_win_inner_sane(in6, 48),
			      "内层 v6 声明长度超过整帧应拒绝");
			CHECK(!iwan_win_inner_sane(in6, 20), "内层 v6 头不全应拒绝");
		}
	}
}

/* ---- 5b. 解封按长度分块：每个长度都要与"逐字节拷贝再异或"等价 ------- */

static void
test_decap_lengths(void)
{
	const uint8_t key[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				 0x88 };
	size_t lens[] = { 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
			  127, 128, 129, 1000 };
	uint8_t plain[1200], enc[1200], outer[1400], out[1200];
	uint16_t sid = 0x030c;
	uint32_t tok = 0xdeadbeef;
	size_t i, k;

	for (k = 0; k < sizeof(plain); k++)
		plain[k] = (uint8_t)(k * 7 + 3);

	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		size_t n = lens[i];
		IWAN_WIN_OUTER o;
		size_t total, got;

		/* 加密帧：解封必须还原出明文 */
		memcpy(enc, plain, n);
		xor_crypt(enc, n, key, sizeof(key));
		total = build_outer(outer, n, 40000, 6001, PT_DATA_ENC, 1, sid,
				    tok, 0);
		memcpy(outer + 36, enc, n);
		CHECK(iwan_win_outer_parse4(outer, total, &o),
		      "加密帧解析失败（len=%zu）", n);
		got = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
		CHECK(got == n, "解封长度错误（len=%zu got=%zu）", n, got);
		CHECK(memcmp(out, plain, n) == 0, "解封结果不符（len=%zu）", n);

		/* 明文帧：解封必须原样拷贝 */
		total = build_outer(outer, n, 40000, 6001, PT_DATA, 0, sid, tok,
				    0);
		memcpy(outer + 36, plain, n);
		CHECK(iwan_win_outer_parse4(outer, total, &o),
		      "明文帧解析失败（len=%zu）", n);
		memset(out, 0xA5, sizeof(out));
		got = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
		CHECK(got == n, "明文解封长度错误（len=%zu got=%zu）", n, got);
		CHECK(memcmp(out, plain, n) == 0, "明文解封结果不符（len=%zu）",
		      n);

		/* 输出缓冲不足：必须拒绝而不是截断写入 */
		CHECK(iwan_win_decap(outer, total, &o, key, out,
				     (ULONG)(n - 1)) == 0,
		      "输出缓冲不足应拒绝（len=%zu）", n);
	}
}

/* ---- 5c. 失败路径的 out 参数必须被写成确定值 -------------------------
 *
 * 四个解析函数（outer_parse4 / outer_parse6 / dgram_parse / decap）在返回
 * 失败时都不承诺填 out —— 调用者本不该读它。但“不承诺”与“栈上残留”在
 * 静态分析里无法区分，而真实的隐患是：调用者若在失败后仍然读了 out 的
 * 某个字段（比如拿 inner_len 去算长度），就会用到上一个包的数据。
 * 这里把 out 预先填成 0xCD，再喂各种坏包，要求函数**要么返回失败且
 * 不动 out 的语义字段，要么返回失败并把它们清成 0** —— 现在是后者。
 */
static void
test_parse_failure_clears_out(void)
{
	uint8_t shortpkt[8];
	uint8_t badver[60];
	IWAN_WIN_OUTER o;
	uint8_t out[64];
	const uint8_t key[8] = { 0 };

	memset(shortpkt, 0x00, sizeof(shortpkt));
	memset(badver, 0x00, sizeof(badver));
	badver[0] = 0x65;	/* 版本 6 的包喂给 v4 解析器 */

	/* v4 解析：长度不足 / 版本不符 */
	memset(&o, 0xCD, sizeof(o));
	CHECK(!iwan_win_outer_parse4(shortpkt, sizeof(shortpkt), &o),
	      "8 字节包不应被当成合法外层 v4");
	CHECK(o.inner_len == 0 && o.inner_off == 0 && o.frame_len == 0,
	      "失败后 out 的偏移字段应清零（inner_len=%u frame_len=%u）",
	      o.inner_len, o.frame_len);

	memset(&o, 0xCD, sizeof(o));
	CHECK(!iwan_win_outer_parse4(badver, sizeof(badver), &o),
	      "版本号 6 的包不应被 v4 解析器接受");
	CHECK(o.inner_len == 0 && o.type == 0 && o.enc == 0,
	      "失败后 out 的类型字段应清零");

	/* 裸数据报解析：过短 */
	memset(&o, 0xCD, sizeof(o));
	CHECK(!iwan_win_dgram_parse(shortpkt, sizeof(shortpkt), &o),
	      "8 字节裸包不应被接受");
	CHECK(o.inner_len == 0 && o.frame_off == 0,
	      "失败后裸包解析的偏移字段应清零");

	/* 解封：输出缓冲不足 / 上下文非法 */
	memset(out, 0xCD, sizeof(out));
	o.inner_len = 4;
	o.inner_off = 0;
	o.enc = 0;
	CHECK(iwan_win_decap(shortpkt, sizeof(shortpkt), &o, key, out, 3) == 0,
	      "outsz 小于 inner_len 必须拒绝");
	CHECK(out[0] == 0xCD, "被拒绝的解封不应写输出缓冲");

	memset(&o, 0, sizeof(o));
	CHECK(iwan_win_decap(shortpkt, sizeof(shortpkt), &o, key, out,
			     sizeof(out)) == 0,
	      "inner_len 为 0 必须拒绝");
}

/* ---- 5d. 两个解析器对同一条流必须给出一致的字段 ----------------------- */

static void
test_parse4_vs_dgram_agree(void)
{
	uint8_t outer[600];
	uint8_t payload[100];
	IWAN_WIN_OUTER a, b;
	size_t total, i;

	for (i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)(i ^ 0x5A);

	/* build_outer 造的是完整的 IPv4+UDP 外层；dgram_parse 对"仍带 IP 头"
	 * 的输入应当解析出与 outer_parse4 完全相同的字段。两条入向路径
	 * （协议边 / WFP 平面）各用一个，字段必须逐项相等，否则同一份报文
	 * 在两条路径上会解出不同的内层边界。 */
	total = build_outer(outer, sizeof(payload), 40000, 6001, PT_DATA, 0,
			    0x1234, 0x12345678, 0);
	memcpy(outer + 36, payload, sizeof(payload));

	CHECK(iwan_win_outer_parse4(outer, total, &a), "v4 解析失败");
	CHECK(iwan_win_dgram_parse(outer, total, &b), "dgram 解析失败");
	CHECK(a.frame_off == b.frame_off && a.frame_len == b.frame_len &&
	      a.inner_off == b.inner_off && a.inner_len == b.inner_len,
	      "两个解析器的偏移不一致（%u/%u/%u/%u vs %u/%u/%u/%u）",
	      a.frame_off, a.frame_len, a.inner_off, a.inner_len,
	      b.frame_off, b.frame_len, b.inner_off, b.inner_len);
	CHECK(a.type == b.type && a.enc == b.enc && a.sid == b.sid &&
	      a.tok == b.tok,
	      "两个解析器的帧头字段不一致");
	CHECK(a.inner_len == sizeof(payload), "内层长度应为 %zu（实得 %u）",
	      sizeof(payload), a.inner_len);
}

/* ---- 6. 与用户态发送侧对拍：拿 pkt_hdr()/xor_crypt() 造的帧喂驱动解析 --- */

static void
test_inbound_crosscheck(void)
{
	const uint8_t key[8] = { 0x9a, 0x77, 0x01, 0xff, 0x40, 0x22, 0xbe, 0xef };
	uint16_t sid = 0x4a1b;
	uint32_t tok = 0x0badc0de;
	uint8_t inner[48], outer[256], out[128], enc[48];
	IWAN_WIN_OUTER o;
	uint8_t hdr[8];
	size_t total, n;

	memset(inner, 0, sizeof(inner));
	inner[0] = 0x45;
	inner[3] = (uint8_t)sizeof(inner);
	inner[9] = 17;
	inner[13] = 1; inner[15] = 9;
	inner[17] = 2; inner[19] = 9;
	for (size_t i = 20; i < sizeof(inner); i++)
		inner[i] = (uint8_t)(i * 13 + 5);

	/* 用户态发送侧就是这么干的：pkt_hdr() 造帧头、xor_crypt() 加密载荷 */
	pkt_hdr(PT_DATA_ENC, 1, sid, tok, hdr);
	memcpy(enc, inner, sizeof(inner));
	xor_crypt(enc, sizeof(enc), key, 8);

	total = build_outer(outer, sizeof(inner), 40000, 6001, PT_DATA_ENC, 1,
			    sid, tok, 0);
	memcpy(outer + 28, hdr, 8);          /* 用用户态的帧头覆盖 */
	memcpy(outer + 36, enc, sizeof(enc));

	CHECK(memcmp(outer + 28, hdr, 8) == 0, "帧头写回失败");
	CHECK(iwan_win_outer_parse4(outer, total, &o), "用户态造的帧解析失败");
	CHECK(iwan_win_frame_classify(&o, sid, tok, TRUE, TRUE) ==
	      IWAN_WIN_FRAME_DATA, "用户态造的数据帧应判为 DATA");
	n = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
	CHECK(n == sizeof(inner), "解封长度与用户态发送长度不符");
	CHECK(memcmp(out, inner, sizeof(inner)) == 0,
	      "解封结果与用户态加密前的明文不符");
}


/* ---- 7. 出向外层头构造（v4/v6）与 v6 目标判定 ------------------------- */

/* 独立的一份校验和实现（不复用被测代码），用来交叉验证外层头里的校验和 */
static uint32_t
t_sum(const uint8_t *p, size_t n, uint32_t sum)
{
	for (size_t i = 0; i + 1 < n; i += 2)
		sum += ((uint32_t)p[i] << 8) | p[i + 1];
	if (n & 1)
		sum += (uint32_t)p[n - 1] << 8;
	return sum;
}

static uint16_t
t_fin(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return (uint16_t)(~sum & 0xFFFF);
}

static void
test_outer_build4(void)
{
	const uint8_t key[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
	uint8_t frame[8 + 40], outer[256], out[128];
	uint32_t src = 0x0a000002, dst = 0xca26406a;   /* 10.0.0.2 -> 202.38.64.106 */
	IWAN_WIN_OUTER o;
	uint16_t sport = 0x9c40, dport = 0x1771;       /* 40000 -> 6001 */
	size_t flen = 8 + 40, total, n;

	for (size_t i = 0; i < 40; i++)
		frame[8 + i] = (uint8_t)(i * 7 + 1);
	iwan_win_build_frame_hdr(frame, PT_DATA, 0, 0x030c, 0xdeadbeef);

	total = iwan_win_outer_build4(outer, sizeof(outer), frame, flen, src, dst,
				      sport, dport);
	CHECK(total == 36 - 8 + flen, "v4 外层总长不对");
	CHECK(outer[0] == 0x45, "v4 版本/头长不对");
	CHECK(outer[8] == 64, "v4 ttl 应为 64");
	CHECK(outer[9] == 17, "v4 协议应为 UDP");
	CHECK((outer[6] << 8 | outer[7]) == 0x4000, "v4 应置 DF");
	CHECK(memcmp(outer + 12, "\x0a\x00\x00\x02", 4) == 0, "v4 源地址不对");
	CHECK(memcmp(outer + 16, "\xca\x26\x40\x6a", 4) == 0, "v4 目的地址不对");
	CHECK(memcmp(outer + 20, "\x9c\x40\x17\x71", 4) == 0, "v4 UDP 端口不对");
	CHECK((size_t)((outer[24] << 8) | outer[25]) == 8 + flen,
	      "v4 UDP 长度不对");

	/* 独立验证 IP 头校验和 */
	{
		uint32_t sum = 0;

		for (size_t i = 0; i < 20; i += 2)
			sum += ((uint32_t)outer[i] << 8) | outer[i + 1];
		CHECK(t_fin(sum) == 0, "v4 头校验和自校验应为 0");
	}

	/* 独立验证 UDP 校验和（伪头 + UDP 头 + 载荷） */
	{
		uint32_t sum = 0;

		sum = t_sum(outer + 12, 8, sum);
		sum = t_sum((const uint8_t *)"\x00\x11", 2, sum);
		sum = t_sum(outer + 24, 2, sum);
		sum = t_sum(outer + 20, 8 + flen, sum);
		CHECK(t_fin(sum) == 0, "v4 UDP 校验和（含伪头）应为 0");
		CHECK(((outer[26] << 8) | outer[27]) != 0 ||
		      ((outer[26] << 8) | outer[27]) == 0xFFFF,
		      "v4 UDP 校验和不应为 0（0 表示无校验和）");
	}

	/* 与入向解析对拍：构造 → 解析 → 解封 */
	CHECK(iwan_win_outer_parse4(outer, total, &o), "构造出的 v4 外层解析失败");
	CHECK(o.inner_off == 36 && o.inner_len == 40, "v4 内层偏移/长度不对");
	CHECK(iwan_win_frame_classify(&o, 0x030c, 0xdeadbeef, FALSE, TRUE) ==
	      IWAN_WIN_FRAME_DATA, "构造出的明文帧应判为 DATA");
	n = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
	CHECK(n == 40 && memcmp(out, frame + 8, 40) == 0, "v4 解封与载荷不符");
}

static void
test_outer_build6(void)
{
	uint8_t frame[8 + 40], outer[256], out[128];
	static const uint8_t src6[16] = { 0x20, 0x01, 0xda, 0x08, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 2 };
	static const uint8_t dst6[16] = { 0x20, 0x01, 0xda, 0x08, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 9 };
	uint16_t sport = 0x9c40, dport = 0x1771;
	size_t flen = 8 + 40, total, n;
	IWAN_WIN_OUTER o;

	for (size_t i = 0; i < 40; i++)
		frame[8 + i] = (uint8_t)(0xa0 - i);
	iwan_win_build_frame_hdr(frame, PT_DATA, 0, 0x030c, 0xdeadbeef);

	total = iwan_win_outer_build6(outer, sizeof(outer), frame, flen, src6, dst6,
				      sport, dport);
	CHECK(total == 56 - 8 + flen, "v6 外层总长不对");
	CHECK((outer[0] >> 4) == 6, "v6 版本不对");
	CHECK((outer[0] & 0x0F) == 0 && outer[1] == 0 && outer[2] == 0 &&
	      outer[3] == 0, "v6 traffic class / flow label 应为 0");
	CHECK(outer[6] == 17, "v6 nexthdr 应为 UDP（不带扩展头）");
	CHECK(outer[7] == 64, "v6 hop limit 应为 64");
	CHECK((size_t)((outer[4] << 8) | outer[5]) == 8 + flen,
	      "v6 payload_len 不对");
	CHECK(memcmp(outer + 8, src6, 16) == 0 && memcmp(outer + 24, dst6, 16) == 0,
	      "v6 地址不对");
	CHECK(memcmp(outer + 40, "\x9c\x40\x17\x71", 4) == 0, "v6 UDP 端口不对");
	CHECK((size_t)((outer[44] << 8) | outer[45]) == 8 + flen,
	      "v6 UDP 长度不对");

	/* 独立验证 UDP 校验和：v6 伪头 = 16B 源 + 16B 目的 + 4B 长度 + 3B 零 +
	 * 1B 下一头。RFC 8200 强制非零。 */
	{
		uint32_t sum = 0;
		uint8_t tail[4] = { 0, 0, 0, 17 };
		uint8_t ulen[4] = { 0, 0, 0, 0 };
		uint16_t ul = (uint16_t)(8 + flen);

		ulen[2] = (uint8_t)(ul >> 8);
		ulen[3] = (uint8_t)ul;
		sum = t_sum(src6, 16, sum);
		sum = t_sum(dst6, 16, sum);
		sum = t_sum(ulen, 4, sum);
		sum = t_sum(tail, 4, sum);
		sum = t_sum(outer + 40, 8 + flen, sum);
		CHECK(t_fin(sum) == 0, "v6 UDP 校验和（含 v6 伪头）应为 0");
		CHECK(((outer[46] << 8) | outer[47]) != 0,
		      "v6 UDP 校验和不得为 0（RFC 8200 强制）");
	}

	/* 构造 → 解析 → 解封（v6 外层包 v6 内层） */
	CHECK(iwan_win_outer_parse6(outer, total, &o), "构造出的 v6 外层解析失败");
	CHECK(o.inner_off == 56 && o.inner_len == 40, "v6 内层偏移/长度不对");
	CHECK(iwan_win_frame_classify(&o, 0x030c, 0xdeadbeef, FALSE, TRUE) ==
	      IWAN_WIN_FRAME_DATA, "v6 外层的明文帧应判为 DATA");
	n = iwan_win_decap(outer, total, &o, NULL, out, sizeof(out));
	CHECK(n == 40 && memcmp(out, frame + 8, 40) == 0, "v6 解封与载荷不符");

	/* 结构不合法：截断 / 扩展头 / 非 UDP */
	CHECK(!iwan_win_outer_parse6(outer, 40, &o), "截断的 v6 包不应被解析");
	{
		uint8_t save = outer[6];

		outer[6] = 0;                  /* 逐跳扩展头 */
		CHECK(!iwan_win_outer_parse6(outer, total, &o),
		      "带扩展头的 v6 外层不应被解析");
		outer[6] = 6;                  /* TCP */
		CHECK(!iwan_win_outer_parse6(outer, total, &o),
		      "非 UDP 的 v6 外层不应被解析");
		outer[6] = save;
	}
}

static void
test_should_tunnel6(void)
{
	static const uint8_t outer6[16] = { 0x20, 0x01, 0xda, 0x08, 0, 0, 0, 0,
					    0, 0, 0, 0, 0, 0, 0, 9 };
	IWAN_WIN_TARGET t[3];
	static const uint8_t campus[16] = { 0x20, 0x01, 0xda, 0x08, 0x02, 0x00, 0, 0,
					    0, 0, 0, 0, 0, 0, 0, 0 };

	memset(t, 0, sizeof(t));
	t[0].family = IWAN_WIN_AF_V6;
	t[0].prefix_len = 32;                  /* 2001:da8::/32 */
	memcpy(t[0].addr, campus, 16);
	t[1].family = IWAN_WIN_AF_V6;
	t[1].prefix_len = 48;                  /* 2001:da8:2::/48 */
	t[1].addr[0] = 0x20; t[1].addr[1] = 0x01; t[1].addr[2] = 0xda;
	t[1].addr[3] = 0x08; t[1].addr[4] = 0x02;
	t[2].family = IWAN_WIN_AF_V4;          /* v4 条目对 v6 判定无影响 */
	t[2].prefix_len = 0;

	{
		static const uint8_t in6[16] = { 0x20, 0x01, 0xda, 0x08, 0x02, 0x00,
						 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
		static const uint8_t other[16] = { 0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0,
						   0, 0, 0, 0, 0, 0, 0, 1 };

		CHECK(iwan_win_should_tunnel6(t, 3, outer6, in6),
		      "校园 v6 地址应入隧道");
		CHECK(!iwan_win_should_tunnel6(t, 3, outer6, other),
		      "集合外的 v6 地址不应入隧道");
		CHECK(!iwan_win_should_tunnel6(t, 3, outer6, outer6),
		      "外层服务器地址永不入隧道");
	}
	CHECK(!iwan_win_should_tunnel6(NULL, 0, outer6, outer6),
	      "空目标集合不应入隧道");
}

/*
 * 重组后的数据报形态（入向 callout 在 INBOUND_TRANSPORT_V4/V6）：
 * UDP 头在包首、IP 头已被协议栈摘掉。同一份字节按"裸数据报"与"仍带 IP 头"
 * 两种形态都必须解析出同样的结果。
 */
static void
test_dgram_parse(void)
{
	const uint8_t key[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t inner[64], outer[256], out[128];
	IWAN_WIN_OUTER o;
	size_t total, n;
	uint16_t sid = 0x030c;
	uint32_t tok = 0xdeadbeef;

	memset(inner, 0, sizeof(inner));
	inner[0] = 0x45;
	inner[2] = 0; inner[3] = 32;
	inner[8] = 64;
	inner[9] = 17;
	inner[12] = 10; inner[13] = 0; inner[14] = 0; inner[15] = 1;
	inner[16] = 10; inner[17] = 0; inner[18] = 0; inner[19] = 2;
	inner[20] = 0x9c; inner[21] = 0x41;
	inner[22] = 0x27; inner[23] = 0x0f;
	inner[24] = 0; inner[25] = 12;
	inner[28] = 'i'; inner[29] = 'w'; inner[30] = 'a'; inner[31] = 'n';

	/* 裸数据报：这就是协议栈重组后交上来的形态。加密帧的载荷要先 XOR
	 * 再放进去（线上是密文，decap 解出来才是明文）。 */
	{
		uint8_t enc_inner[64];

		memcpy(enc_inner, inner, 32);
		xor_crypt(enc_inner, 32, key, 8);
		total = build_outer(outer, 32, 40000, 6001, PT_DATA_ENC, 1, sid, tok, 0);
		memcpy(outer + 36, enc_inner, 32);
	}
	CHECK(iwan_win_dgram_parse(outer + 20, total - 20, &o),
	      "裸数据报形态解析失败");
	CHECK(o.sport == 40000 && o.dport == 6001, "外层端口解析错");
	CHECK(o.frame_off == 8 && o.inner_off == 16 && o.inner_len == 32,
	      "裸数据报的偏移/长度算错");
	CHECK(o.type == PT_DATA_ENC && o.enc == 1 && o.sid == sid && o.tok == tok,
	      "裸数据报的帧头字段错位");
	n = iwan_win_decap(outer + 20, total - 20, &o, key, out, sizeof(out));
	CHECK(n == 32 && memcmp(out, inner, 32) == 0, "裸数据报解封结果不符");
	CHECK(iwan_win_frame_classify(&o, sid, tok, TRUE, TRUE) ==
	      IWAN_WIN_FRAME_DATA, "裸数据报应判为 DATA");

	/* 仍带 IP 头：偏移整体后移 20，其余结论必须一致 */
	total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0);
	memcpy(outer + 36, inner, 32);
	CHECK(iwan_win_dgram_parse(outer, total, &o), "带 IP 头形态解析失败");
	CHECK(o.sport == 40000 && o.dport == 6001 && o.frame_off == 28 &&
	      o.inner_off == 36 && o.inner_len == 32 && o.enc == 0,
	      "带 IP 头的偏移/端口算错");

	/* 带 IP 头但分片位非 0：形态不对，拒绝（这一层永远只该见到重组完的包）*/
	total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0x2000);
	CHECK(!iwan_win_dgram_parse(outer, total, &o),
	      "带分片位的包不该按完整数据报解析");

	/* 裸数据报 + 源端口高半字节像版本号：必须回落到裸解析 */
	total = build_outer(outer, 32, 0x4a12, 6001, PT_DATA, 0, sid, tok, 0);
	memcpy(outer + 36, inner, 32);
	CHECK(iwan_win_dgram_parse(outer + 20, total - 20, &o),
	      "源端口高半字节像版本号时回落失败");
	CHECK(o.sport == 0x4a12 && o.frame_off == 8 && o.inner_len == 32,
	      "回落后的偏移/长度错");

	/* UDP 长度撒谎（比实际大）：按实际长度兜底 */
	total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0);
	memcpy(outer + 36, inner, 32);
	outer[20 + 4] = 0xff; outer[20 + 5] = 0xff;
	CHECK(iwan_win_dgram_parse(outer + 20, total - 20, &o),
	      "UDP 长度撒谎应兜底解析");
	CHECK(o.inner_len == 32, "兜底后的内层长度不对");

	/* 拒绝路径 */
	CHECK(!iwan_win_dgram_parse(outer + 20, 8, &o), "只有 UDP 头不该解析");
	CHECK(!iwan_win_dgram_parse(outer + 20, 0, &o), "空包不该解析");
	{
		uint8_t only_hdr[16];

		memset(only_hdr, 0, sizeof(only_hdr));
		only_hdr[0] = 0x9c; only_hdr[1] = 0x40;	/* sport = 40000 */
		only_hdr[4] = 0; only_hdr[5] = 16;	/* ulen = 16 = UDP 头 + 帧头 */
		CHECK(!iwan_win_dgram_parse(only_hdr, sizeof(only_hdr), &o),
		      "内层零长不该解析");
	}
}

/*
 * 线测脚手架的金标向量：tests/win_wire_peer.py 造出来的 57 字节外层数据报
 * （8 字节 UDP 头 + 8 字节帧头 + 41 字节内层包），原样喂给驱动侧的解析、
 * 判定、解封。宿主对端脚本是"验证的另一半"，它一旦与驱动对不上，现场表现
 * 只是客体侧计数不动、很难查；把它的输出固化成金标，脚本改坏线上格式时
 * 本机编译就能发现（不需要客体在场）。
 *
 * 41 字节内层 = IPv4(20) + UDP(8) + "IWAN-INNER-OK"(13)，
 * 端口对 40001 -> 9999，内层目的 10.0.2.15。
 */
static void
test_wire_harness_golden(void)
{
	const uint8_t key[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	const uint8_t good[57] = {
		0xb2, 0x6e, 0x9e, 0xd4, 0x00, 0x39, 0x00, 0x00,
		0x18, 0x01, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
		0x44, 0x02, 0x03, 0x2d, 0x05, 0x06, 0x07, 0x08,
		0x41, 0x13, 0x67, 0x56, 0x0f, 0x65, 0x07, 0x09,
		0x0b, 0x02, 0x01, 0x0b, 0x99, 0x47, 0x20, 0x07,
		0x01, 0x17, 0x03, 0x04, 0x4c, 0x51, 0x46, 0x46,
		0x2c, 0x4b, 0x4d, 0x4a, 0x40, 0x54, 0x2a, 0x47,
		0x4a,
	};
	const uint8_t bad[57] = {
		0xb2, 0x6e, 0x9e, 0xd4, 0x00, 0x39, 0x00, 0x00,
		0x18, 0x01, 0x12, 0x34, 0x12, 0x34, 0x56, 0x79,
		0x44, 0x02, 0x03, 0x2d, 0x05, 0x06, 0x07, 0x08,
		0x41, 0x13, 0x67, 0x56, 0x0f, 0x65, 0x07, 0x09,
		0x0b, 0x02, 0x01, 0x0b, 0x99, 0x47, 0x20, 0x07,
		0x01, 0x17, 0x03, 0x04, 0x4c, 0x51, 0x46, 0x46,
		0x2c, 0x4b, 0x4d, 0x4a, 0x40, 0x54, 0x2a, 0x47,
		0x4a,
	};
	IWAN_WIN_OUTER o;
	uint8_t out[64];
	ULONG n;

	CHECK(iwan_win_dgram_parse(good, sizeof(good), &o), "线测正常帧解析失败");
	CHECK(o.sport == 45678 && o.dport == 40660,
	      "外层端口对不上（脚本按大端字节写，驱动按大端整数比）");
	CHECK(o.frame_off == 8 && o.inner_off == 16 && o.inner_len == 41,
	      "帧/内层偏移或长度不符");
	CHECK(o.type == PT_DATA_ENC && o.enc == 1 && o.sid == 0x1234 &&
	      o.tok == 0x12345678, "帧头字段与脚本不一致");
	CHECK(iwan_win_frame_classify(&o, 0x1234, 0x12345678, TRUE, TRUE) ==
	      IWAN_WIN_FRAME_DATA, "线测正常帧应判为数据帧");

	n = iwan_win_decap(good, sizeof(good), &o, key, out, sizeof(out));
	CHECK(n == 41, "解封长度应为 41（实得 %lu）", (unsigned long)n);
	CHECK(out[0] == 0x45 && out[9] == 17, "解封出的内层不是 IPv4/UDP");
	CHECK(out[16] == 10 && out[17] == 0 && out[18] == 2 && out[19] == 15,
	      "解封出的内层目的地址不是 10.0.2.15");
	CHECK(out[22] == 0x27 && out[23] == 0x0f, "解封出的内层目的端口不是 9999");
	CHECK(memcmp(out + 28, "IWAN-INNER-OK", 13) == 0,
	      "解封出的载荷不是 IWAN-INNER-OK");
	CHECK(sum16(out, 20) == 0xFFFF, "解封出的内层 IP 校验和无效（脚本算错）");

	CHECK(iwan_win_dgram_parse(bad, sizeof(bad), &o),
	      "坏凭据样本结构合法，应当能解析");
	CHECK(iwan_win_frame_classify(&o, 0x1234, 0x12345678, TRUE, TRUE) ==
	      IWAN_WIN_FRAME_BAD, "令牌不匹配的帧必须判为 BAD");
}

int
main(void)
{
	test_frame_hdr();
	test_xor();
	test_csum();
	test_inner_fix_csum_keeps_addrs();
	test_targets();
	test_wire_constants();
	test_inbound();
	test_decap_lengths();
	test_dgram_parse();
	test_inbound_crosscheck();
	test_outer_build4();
	test_outer_build6();
	test_should_tunnel6();
	test_wire_harness_golden();
	test_parse_failure_clears_out();
	test_parse4_vs_dgram_agree();

	printf("win_frame_test: 通过 %d 项，失败 %d 项\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
