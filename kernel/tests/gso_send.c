/* SPDX-License-Identifier: GPL-2.0 */
/*
 * gso_send.c —— iWAN GSO 批处理验收的**发送侧**（纯 libc + _GNU_SOURCE）。
 *
 * 目的：把 N 个**等长**加密数据帧用一次 sendmsg(UDP_SEGMENT) 发成一个 UDP
 * 超级报文。veth 的 features 含 NETIF_F_GSO_SOFTWARE（含 GSO_UDP_L4），
 * validate_xmit_skb() 不会提前分段，接收侧因此在 netfilter 钩子里看到
 * skb_is_gso() 的 skb，进入 kernel/iwan_rx.c 的 iwan_rx_batch()。
 *
 * 帧构造与 kernel/tests/interop_c.c 的 encap 路径逐字节一致（冻结线格式，
 * 见 src/common/protocol.h）：
 *   [外层 IPv4 20B][外层 UDP 8B]              ← 由内核按 UDP_SEGMENT 生成
 *   [8B 帧头: type=0x18, enc, sid(u16 BE), tok(u32 BE)]
 *   [XOR(内层 IPv4 包整体，含内层 IP 头)]      ← 8 字节会话密钥按字节偏移循环
 * 注意：**数据帧没有签名** —— IWAN_CTRL_LEN=24 的 MD5 签名只用于控制帧
 * （src/common/protocol.h 的 ctrl_hdr/pkt_sig），本工具只发数据帧，所以这里
 * 只有帧头 + XOR，与 interop_c 的 encap 完全一致。
 *
 * 为什么不直接链接 src/common：本工具刻意只依赖 libc，让 gso_test.sh 不需要
 * libcrypto；与生产实现的一致性由 interop_test.sh 的逐字节对拍负责，本工具
 * 端到端正确性由两件事保证：
 *   · 启动时对第 0 帧做一次 XOR 往返 + 帧头逐字节自检（SELFCHECK=ok）；
 *   · 内核解封后按**明文**校验内层 UDP 校验和，N 个包必须全部投递到 socket。
 *
 * 编译（gso_test.sh 用的就是这一行）：
 *   cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o gso_send gso_send.c
 *
 * 用法：
 *   gso_send --outer-src IP --outer-dst IP [--sport N] --dport N \
 *            --inner-src IP --inner-dst IP [--inner-sport N] [--inner-dport N] \
 *            [--sid N] [--tok N] [--enc 0|1] [--key HEX16] \
 *            [--count N] [--inner-len N] [--ttl N] [--ip-id N] \
 *            [--dump-frame FILE] [--quiet]
 *
 * stdout 是稳定的 KEY=value（给脚本解析），stderr 是人看的诊断；
 * 退出码：0 成功；1 运行时错误（socket/sendmsg/自检失败）；2 用法错误。
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/udp.h>	/* SOL_UDP / UDP_SEGMENT */
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* PROTOCOL.md / src/common/protocol.h 的冻结值（镜像，不 include src/） */
#define IWAN_HDR_LEN	8
#define IWAN_KEY_BYTES	8
#define PT_DATA		0x14
#define PT_DATA_ENC	0x18

#define IP_HDR_LEN	20
#define UDP_HDR_LEN	8
#define MIN_INNER	(IP_HDR_LEN + UDP_HDR_LEN)	/* 28 */
#define MARK_LEN	14				/* "IWAN-GSO-%04u" + NUL */
/* 一个 UDP 数据报的载荷上限（PROTOCOL.md §10；留 8B 给外层 UDP 头） */
#define MAX_PAYLOAD	65507

#define DEF_KEY		"0011223344556677"
#define DEF_SID		4660
#define DEF_TOK		3405691582u
#define DEF_ENC		1
#define DEF_COUNT	32
#define DEF_INNER_LEN	200
#define DEF_TTL		64
#define DEF_IP_ID	0x4700
#define DEF_ISPORT	40000
#define DEF_IDPORT	9999

/* 老 linux/udp.h 没有这个常量时给一份：UAPI 冻结值 103 */
#ifndef UDP_SEGMENT
#define UDP_SEGMENT	103
#endif

static const char *progname = "gso_send";

/* ---------------------------------------------------------------- 基础工具 */

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));

static void die(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: 错误: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static void info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void info(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void usage(FILE *fd)
{
	fprintf(fd,
"用法:\n"
"  %s --outer-src IP --outer-dst IP [--sport N] --dport N \\\n"
"      --inner-src IP --inner-dst IP [--inner-sport N] [--inner-dport N] \\\n"
"      [--sid N] [--tok N] [--enc 0|1] [--key HEX16] [--count N] \\\n"
"      [--inner-len N] [--ttl N] [--ip-id N] [--dump-frame FILE] [--quiet]\n"
"\n"
"说明:\n"
"  · 一次 sendmsg 用 UDP_SEGMENT 发出 --count 个等长加密帧（帧头 + XOR，\n"
"    与 interop_c 的 encap 同格式）；外层源端口 --sport 省略 = --dport，\n"
"    与模块 TX 的口径一致\n"
"  · --inner-len 是**内层 IPv4 包总长**（含 IP/UDP 头），默认 %d；\n"
"    每个帧的内层 UDP 载荷以 \"IWAN-GSO-<4位序号>\" 开头，接收侧据此清点\n"
"  · --dump-frame FILE 把第 0 帧（8B 帧头 + XOR 后的内层包）写到文件，\n"
"    便于与 interop_c 的输出做逐字节对拍\n"
"  · stdout: KEY=value（含 FRAME0_HEX / SELFCHECK / SENDMSG_BYTES）\n"
"  · 退出码: 0 成功, 1 运行时错误, 2 用法错误\n",
		progname, DEF_INNER_LEN);
}

/* ---------------------------------------------------------------- 参数解析 */

struct args {
	uint32_t	osrc, odst;	/* be32 */
	uint32_t	isrc, idst;	/* be32 */
	uint16_t	dport, sport;
	uint16_t	isport, idport;
	uint16_t	sid;
	uint32_t	tok;
	uint8_t		enc;
	unsigned	count;
	unsigned	inner_len;
	unsigned	ttl;
	uint16_t	ip_id;
	uint8_t		key[IWAN_KEY_BYTES];
	char		key_hex[2 * IWAN_KEY_BYTES + 1];
	const char	*dump_frame;
	bool		quiet;
	bool		osrc_given, odst_given, isrc_given, idst_given;
	bool		dport_given, sport_given;
};

static unsigned long parse_ul(const char *s, const char *what)
{
	char *end;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &end, 0);
	if (errno || end == s || *end)
		die("%s 不是合法整数: \"%s\"", what, s);
	return v;
}

static uint32_t parse_ip(const char *s, const char *what)
{
	struct in_addr a;

	if (inet_pton(AF_INET, s, &a) != 1)
		die("%s 不是合法 IPv4 地址: \"%s\"", what, s);
	return a.s_addr;
}

/* inet_ntoa() 用静态缓冲区，一次 printf 里调多次会互相覆盖，必须各用各的 buf */
static void ip_str(uint32_t be, char *out, size_t len)
{
	struct in_addr a = { .s_addr = be };

	if (!inet_ntop(AF_INET, &a, out, len))
		snprintf(out, len, "?");
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static void parse_key(const char *s, struct args *a)
{
	size_t i;

	if (strlen(s) != IWAN_KEY_BYTES * 2)
		die("--key 需要 %d 个十六进制字符（%d 字节），实际 %zu 个",
		    IWAN_KEY_BYTES * 2, IWAN_KEY_BYTES, strlen(s));
	for (i = 0; i < IWAN_KEY_BYTES; i++) {
		int hi = hexval(s[2 * i]);
		int lo = hexval(s[2 * i + 1]);

		if (hi < 0 || lo < 0)
			die("--key 含非十六进制字符: \"%s\"", s);
		a->key[i] = (uint8_t)((hi << 4) | lo);
	}
	snprintf(a->key_hex, sizeof(a->key_hex), "%s", s);
}

static void parse_args(int argc, char **argv, struct args *a)
{
	int c;
	static const struct option long_opts[] = {
		{ "outer-src",	required_argument,	NULL, 'a' },
		{ "outer-dst",	required_argument,	NULL, 'b' },
		{ "sport",	required_argument,	NULL, 'c' },
		{ "dport",	required_argument,	NULL, 'd' },
		{ "inner-src",	required_argument,	NULL, 'e' },
		{ "inner-dst",	required_argument,	NULL, 'f' },
		{ "inner-sport", required_argument,	NULL, 'g' },
		{ "inner-dport", required_argument,	NULL, 'i' },
		{ "sid",	required_argument,	NULL, 'j' },
		{ "tok",	required_argument,	NULL, 'k' },
		{ "enc",	required_argument,	NULL, 'l' },
		{ "key",	required_argument,	NULL, 'm' },
		{ "count",	required_argument,	NULL, 'n' },
		{ "inner-len",	required_argument,	NULL, 'o' },
		{ "ttl",	required_argument,	NULL, 'p' },
		{ "ip-id",	required_argument,	NULL, 'q' },
		{ "dump-frame",	required_argument,	NULL, 'r' },
		{ "quiet",	no_argument,		NULL, 's' },
		{ "help",	no_argument,		NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	memset(a, 0, sizeof(*a));
	snprintf(a->key_hex, sizeof(a->key_hex), "%s", DEF_KEY);
	parse_key(DEF_KEY, a);
	a->sid = DEF_SID;
	a->tok = DEF_TOK;
	a->enc = DEF_ENC;
	a->count = DEF_COUNT;
	a->inner_len = DEF_INNER_LEN;
	a->ttl = DEF_TTL;
	a->ip_id = DEF_IP_ID;
	a->isport = DEF_ISPORT;
	a->idport = DEF_IDPORT;

	while ((c = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
		switch (c) {
		case 'a':
			a->osrc = parse_ip(optarg, "--outer-src");
			a->osrc_given = true;
			break;
		case 'b':
			a->odst = parse_ip(optarg, "--outer-dst");
			a->odst_given = true;
			break;
		case 'c':
			a->sport = (uint16_t)parse_ul(optarg, "--sport");
			a->sport_given = true;
			break;
		case 'd':
			a->dport = (uint16_t)parse_ul(optarg, "--dport");
			a->dport_given = true;
			break;
		case 'e':
			a->isrc = parse_ip(optarg, "--inner-src");
			a->isrc_given = true;
			break;
		case 'f':
			a->idst = parse_ip(optarg, "--inner-dst");
			a->idst_given = true;
			break;
		case 'g':
			a->isport = (uint16_t)parse_ul(optarg, "--inner-sport");
			break;
		case 'i':
			a->idport = (uint16_t)parse_ul(optarg, "--inner-dport");
			break;
		case 'j':
			a->sid = (uint16_t)parse_ul(optarg, "--sid");
			break;
		case 'k':
			a->tok = (uint32_t)parse_ul(optarg, "--tok");
			break;
		case 'l':
			a->enc = (uint8_t)parse_ul(optarg, "--enc");
			break;
		case 'm':
			parse_key(optarg, a);
			break;
		case 'n':
			a->count = (unsigned)parse_ul(optarg, "--count");
			break;
		case 'o':
			a->inner_len = (unsigned)parse_ul(optarg, "--inner-len");
			break;
		case 'p':
			a->ttl = (unsigned)parse_ul(optarg, "--ttl");
			break;
		case 'q':
			a->ip_id = (uint16_t)parse_ul(optarg, "--ip-id");
			break;
		case 'r':
			a->dump_frame = optarg;
			break;
		case 's':
			a->quiet = true;
			break;
		case 'h':
			usage(stdout);
			exit(0);
		default:
			usage(stderr);
			exit(2);
		}
	}
	if (optind != argc) {
		usage(stderr);
		die("多余参数: %s", argv[optind]);
	}
	if (!a->osrc_given || !a->odst_given)
		die("需要 --outer-src 与 --outer-dst（外层 veth 上的地址）");
	if (!a->isrc_given || !a->idst_given)
		die("需要 --inner-src 与 --inner-dst（内层隧道地址）");
	if (!a->dport_given)
		die("需要 --dport（外层隧道目的端口，与 SESSION_UP 的 dport 一致）");
	if (!a->sport_given)
		a->sport = a->dport;	/* 与模块 TX 的口径一致：省略 = 用 dport */
	if (!a->dport || !a->sport)
		die("--dport/--sport 不能为 0");
	if (a->enc > 1)
		die("--enc 只能是 0 或 1，实际 %u", a->enc);
	if (a->count == 0 || a->count > 4096)
		die("--count 必须在 1..4096 之间，实际 %u", a->count);
	if (a->inner_len < MIN_INNER + MARK_LEN || a->inner_len > 1400)
		die("--inner-len 必须在 %d..1400 之间（内层包总长），实际 %u",
		    MIN_INNER + MARK_LEN, a->inner_len);
	if (a->ttl == 0 || a->ttl > 255)
		die("--ttl 必须在 1..255 之间");
	if ((unsigned long)a->count * (IWAN_HDR_LEN + a->inner_len) > MAX_PAYLOAD)
		die("--count × 帧长超过一个 UDP 数据报上限 %d 字节", MAX_PAYLOAD);
}

/* ---------------------------------------------------------------- 校验和 */

static uint32_t csum_add(const void *data, size_t len, uint32_t sum)
{
	const uint8_t *p = data;
	size_t i;

	for (i = 0; i + 1 < len; i += 2)
		sum += (uint32_t)((p[i] << 8) | p[i + 1]);
	if (i < len)
		sum += (uint32_t)(p[i] << 8);
	return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

static uint16_t ip_checksum(const uint8_t *pkt, size_t hdr_len)
{
	return csum_fold(csum_add(pkt, hdr_len, 0));
}

/* UDP 校验和（含 12 字节伪首部）；结果为 0 时按 RFC 768 写成 0xFFFF */
static uint16_t udp_checksum(const uint8_t *pkt, size_t inner_len)
{
	uint32_t sum = 0;
	uint8_t pseudo[12];
	uint16_t udp_len = (uint16_t)(inner_len - IP_HDR_LEN);

	memset(pseudo, 0, sizeof(pseudo));
	memcpy(pseudo + 0, pkt + 12, 4);	/* 源地址 */
	memcpy(pseudo + 4, pkt + 16, 4);	/* 目的地址 */
	pseudo[9] = IPPROTO_UDP;
	pseudo[10] = (uint8_t)(udp_len >> 8);
	pseudo[11] = (uint8_t)udp_len;
	sum = csum_add(pseudo, sizeof(pseudo), sum);
	sum = csum_add(pkt + IP_HDR_LEN, inner_len - IP_HDR_LEN, sum);
	sum = csum_fold(sum);

	return sum ? sum : 0xffff;
}

/* ---------------------------------------------------------------- 帧构造 */

static void put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

/*
 * 与 kernel/iwan_core.c 的 iwan_xor() / src/common 的 xor_crypt() 逐字节等价：
 * 8 字节循环密钥、按字节偏移取 key[off & 7]。内核那份用 64 位字加速，结果
 * 完全一致（kernel/tests/xor_equiv_test.sh 用 20 万组随机用例钉住了这一点）。
 */
static void xor_crypt(uint8_t *p, size_t len, const uint8_t *key)
{
	size_t i;

	for (i = 0; i < len; i++)
		p[i] ^= key[i & 7];
}

/* 按冻结格式生成第 idx 个内层 IPv4+UDP 包（明文，校验和正确） */
static void build_inner(uint8_t *pkt, const struct args *a, unsigned idx)
{
	uint8_t *udp = pkt + IP_HDR_LEN;
	size_t plen = a->inner_len - MIN_INNER;
	size_t i;

	memset(pkt, 0, a->inner_len);

	/* ---- IPv4 头 ---- */
	pkt[0] = 0x45;				/* version 4, ihl 5 */
	pkt[1] = 0;				/* tos */
	put_be16(pkt + 2, (uint16_t)a->inner_len);
	put_be16(pkt + 4, (uint16_t)(a->ip_id + idx));
	put_be16(pkt + 6, 0);			/* 片内偏移 0，不分片 */
	pkt[8] = (uint8_t)a->ttl;
	pkt[9] = IPPROTO_UDP;
	/* isrc/idst 由 inet_pton 写入，内存里已经是网络序字节，直接拷 4 字节；
	 * 再走一次 put_be32 会把地址字节序翻转（10.9.0.2 变成 2.0.9.10）。 */
	memcpy(pkt + 12, &a->isrc, 4);
	memcpy(pkt + 16, &a->idst, 4);
	put_be16(pkt + 10, ip_checksum(pkt, IP_HDR_LEN));

	/* ---- UDP 头 ---- */
	put_be16(udp + 0, a->isport);
	put_be16(udp + 2, a->idport);
	put_be16(udp + 4, (uint16_t)(a->inner_len - IP_HDR_LEN));

	/* ---- 载荷：可读序号 + 确定性填充（等长，逐帧不同） ---- */
	snprintf((char *)(udp + UDP_HDR_LEN), plen, "IWAN-GSO-%04u", idx);
	for (i = 0; i < plen; i++)
		if (udp[UDP_HDR_LEN + i] == '\0')
			udp[UDP_HDR_LEN + i] = (uint8_t)('a' + (idx + i) % 26);
	put_be16(udp + 6, udp_checksum(pkt, a->inner_len));
}

/* 生成第 idx 个完整帧：8B 帧头 + XOR(内层包) */
static void build_frame(uint8_t *frame, const struct args *a, unsigned idx)
{
	uint8_t *inner = frame + IWAN_HDR_LEN;

	frame[0] = a->enc ? PT_DATA_ENC : PT_DATA;
	frame[1] = a->enc;
	put_be16(frame + 2, a->sid);
	put_be32(frame + 4, a->tok);
	build_inner(inner, a, idx);
	if (a->enc)
		xor_crypt(inner, a->inner_len, a->key);
}

/*
 * 自检：把第 0 帧按内核/RX 侧的口径解回来（校验帧头 → XOR → 校验内层头和
 * UDP 校验和），确认构造路径没有偏移/长度错误。这是纯用户态检查，不依赖
 * 模块是否加载。
 */
static bool selfcheck(const uint8_t *frame, const struct args *a)
{
	uint8_t inner[1400];
	uint16_t chk;

	if (frame[0] != (a->enc ? PT_DATA_ENC : PT_DATA) || frame[1] != a->enc)
		return false;
	if (((uint16_t)frame[2] << 8 | frame[3]) != a->sid)
		return false;
	if (((uint32_t)frame[4] << 24 | (uint32_t)frame[5] << 16 |
	     (uint32_t)frame[6] << 8 | frame[7]) != a->tok)
		return false;

	memcpy(inner, frame + IWAN_HDR_LEN, a->inner_len);
	if (a->enc)
		xor_crypt(inner, a->inner_len, a->key);
	if (inner[0] != 0x45 || inner[9] != IPPROTO_UDP)
		return false;
	if (((uint16_t)inner[2] << 8 | inner[3]) != (uint16_t)a->inner_len)
		return false;
	if (memcmp(inner + 12, &a->isrc, 4) || memcmp(inner + 16, &a->idst, 4))
		return false;
	chk = ip_checksum(inner, IP_HDR_LEN);
	if (chk != 0)				/* 含校验和的头再算一遍应为 0 */
		return false;
	chk = csum_fold(csum_add(inner + IP_HDR_LEN,
				 a->inner_len - IP_HDR_LEN,
				 csum_add(inner + 12, 8, 0) + IPPROTO_UDP +
				 (uint32_t)(a->inner_len - IP_HDR_LEN)));
	return chk == 0;
}

static void dump_hex(const char *key, const uint8_t *p, size_t len)
{
	size_t i;

	printf("%s=", key);
	for (i = 0; i < len; i++)
		printf("%02x", p[i]);
	putchar('\n');
}

/* ---------------------------------------------------------------- main */

int main(int argc, char **argv)
{
	struct args a;
	struct sockaddr_in src, dst;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(sizeof(uint16_t))];
	uint16_t gso;
	uint8_t *payload, *frame0;
	char s_osrc[INET_ADDRSTRLEN], s_odst[INET_ADDRSTRLEN];
	char s_isrc[INET_ADDRSTRLEN], s_idst[INET_ADDRSTRLEN];
	unsigned frame_len;
	size_t total;
	ssize_t n;
	int fd, opt_rc, opt_errno, send_errno;
	bool sc;

	parse_args(argc, argv, &a);
	frame_len = IWAN_HDR_LEN + a.inner_len;
	total = (size_t)a.count * frame_len;
	ip_str(a.osrc, s_osrc, sizeof(s_osrc));
	ip_str(a.odst, s_odst, sizeof(s_odst));
	ip_str(a.isrc, s_isrc, sizeof(s_isrc));
	ip_str(a.idst, s_idst, sizeof(s_idst));

	if (!a.quiet)
		info("发送 %u 帧 × %u 字节 = %zu 字节，GSO 段长 %u，"
		     "外层 %s:%u -> %s:%u", a.count, frame_len, total, frame_len,
		     s_osrc, (unsigned)a.sport, s_odst, (unsigned)a.dport);

	payload = malloc(total);
	if (!payload)
		die("malloc(%zu) 失败", total);
	for (unsigned i = 0; i < a.count; i++)
		build_frame(payload + (size_t)i * frame_len, &a, i);

	frame0 = payload;

	/* 构造自检：不过就根本不发，避免把"工具写错了"报成"模块有问题" */
	sc = selfcheck(frame0, &a);
	if (a.dump_frame) {
		FILE *f = fopen(a.dump_frame, "wb");

		if (!f)
			die("写 %s 失败: %s", a.dump_frame, strerror(errno));
		if (fwrite(frame0, 1, frame_len, f) != frame_len) {
			fclose(f);
			die("写 %s 失败: %s", a.dump_frame, strerror(errno));
		}
		fclose(f);
	}
	if (!sc) {
		fprintf(stderr, "%s: 构造自检失败（帧头/XOR/内层校验和不自洽）\n",
			progname);
		free(payload);
		return 1;
	}

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("socket(AF_INET, SOCK_DGRAM): %s", strerror(errno));

	memset(&src, 0, sizeof(src));
	src.sin_family = AF_INET;
	src.sin_addr.s_addr = a.osrc;
	src.sin_port = htons(a.sport);
	if (bind(fd, (struct sockaddr *)&src, sizeof(src)) < 0)
		die("bind(%s:%u): %s", s_osrc,
		    (unsigned)a.sport, strerror(errno));

	/*
	 * UDP_SEGMENT 的正规用法是 sendmsg 的 cmsg（udp_cmsg_send() 只认
	 * cmsg）。这里仍按验收要求先试一次 setsockopt：老/新内核若支持就顺带
	 * 打开，返回 ENOPROTOOPT 属正常，不当作失败。真正生效的是下面的 cmsg。
	 */
	gso = (uint16_t)frame_len;
	opt_rc = setsockopt(fd, SOL_UDP, UDP_SEGMENT, &gso, sizeof(gso));
	opt_errno = opt_rc == 0 ? 0 : errno;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = a.odst;
	dst.sin_port = htons(a.dport);

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = payload;
	iov.iov_len = total;
	msg.msg_name = &dst;
	msg.msg_namelen = sizeof(dst);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(cbuf, 0, sizeof(cbuf));
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_UDP;
	cmsg->cmsg_type = UDP_SEGMENT;
	cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
	memcpy(CMSG_DATA(cmsg), &gso, sizeof(gso));
	msg.msg_controllen = CMSG_SPACE(sizeof(uint16_t));

	n = sendmsg(fd, &msg, 0);
	send_errno = n < 0 ? errno : 0;

	/* 稳定顺序的 KEY=value；脚本只 grep 需要的键 */
	printf("MODE=gso-send\n");
	printf("COUNT=%u\n", a.count);
	printf("INNER_LEN=%u\n", a.inner_len);
	printf("FRAME_BYTES=%u\n", frame_len);
	printf("GSO_SIZE=%u\n", frame_len);
	printf("TOTAL_BYTES=%zu\n", total);
	printf("OUTER_SRC=%s\n", s_osrc);
	printf("OUTER_DST=%s\n", s_odst);
	printf("SPORT=%u\n", (unsigned)a.sport);
	printf("DPORT=%u\n", (unsigned)a.dport);
	printf("INNER_SRC=%s\n", s_isrc);
	printf("INNER_DST=%s\n", s_idst);
	printf("INNER_SPORT=%u\n", (unsigned)a.isport);
	printf("INNER_DPORT=%u\n", (unsigned)a.idport);
	printf("SID=%u\n", (unsigned)a.sid);
	printf("TOK=%u\n", a.tok);
	printf("ENC=%u\n", (unsigned)a.enc);
	printf("KEY=%s\n", a.key_hex);
	printf("SELFCHECK=%s\n", sc ? "ok" : "failed");
	printf("SEGMENT_SETSOCKOPT=%s\n",
	       opt_rc == 0 ? "ok" : strerror(opt_errno));
	printf("SENDMSG_BYTES=%lld\n", (long long)(n < 0 ? -1 : n));
	printf("SENDMSG_ERROR=%s\n", n < 0 ? strerror(send_errno) : "");
	dump_hex("FRAME0_HDR_HEX", frame0, IWAN_HDR_LEN);
	dump_hex("FRAME0_HEX", frame0, frame_len);
	printf("RESULT=%s\n", n == (ssize_t)total ? "ok" : "short");

	close(fd);
	free(payload);

	if (n < 0) {
		fprintf(stderr, "%s: sendmsg(UDP_SEGMENT) 失败: %s\n",
			progname, strerror(send_errno));
		return 1;
	}
	if (n != (ssize_t)total) {
		fprintf(stderr, "%s: sendmsg 只发出 %lld/%zu 字节\n",
			progname, (long long)n, total);
		return 1;
	}
	return 0;
}
