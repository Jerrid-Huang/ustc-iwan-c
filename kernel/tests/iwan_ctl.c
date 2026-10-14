/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_ctl —— iWAN 控制面（genetlink）命令行工具，纯 C + libc。
 *
 * ABI: kernel/iwan_genl.h（冻结，直接 include，不重复定义这里的常量）；
 *      设计说明: kernel/CONTROL-PLANE.md。
 *
 * 家族 id 与多播组 id 一律用 CTRL_CMD_GETFAMILY 查 "iwan" 得到
 * （等价于 libnl 的 genl_ctrl_resolve / genl_ctrl_resolve_grp），不硬编码
 * 家族号；netlink 消息自己拼，不依赖 libmnl/libnl。
 *
 * 字节序（按 iwan_genl.h 的逐字段注释）：
 *   · IWAN_A_SID(u16) / TOK(u32) / ENC(u8) / MTU(u32) / ENABLED(u8) / FLAGS(u32)
 *     用主机序；
 *   · IWAN_A_OUTER_SRC/DST(be32) 与 SPORT/DPORT(be16) 用网络序
 *     （它们对应内核里的 __be32/__be16 字段）。
 *
 * 事件里控制帧的 PT_* 类型常量来自 PROTOCOL.md 第 3 节（冻结值，与
 * src/common/protocol.h 一致），只用于把 FRAME_TYPE 标注成人可读的名字。
 *
 * 退出码：0 成功；1 参数/内核错误；2 用法错误；3 get-stats 内核报错
 *         （此时仍把 error= 与会话空值打到 stdout，便于脚本判定"会话不存在"）；
 *         4 events 在超时前没收到 --count 条事件。
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE	/* 本仓库约定（命令行通常也会 -D_GNU_SOURCE） */
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../iwan_genl.h"

#define BUF_SZ		8192

/*
 * iwan_genl.h 说明了 KEY 是"8 字节 MD5(user||pass)[0..8)"，但没有给长度
 * 常量；这里按注释定义局部常量（建议上游在 ABI 头补一个 IWAN_KEY_LEN）。
 */
#define IWAN_KEY_BYTES	8

/* PROTOCOL.md 第 3 节：帧类型（冻结；0x19-0x28 未分配） */
enum iwan_pt {
	PT_OPEN_REJECT	= 0x11,
	PT_OPEN_ACK	= 0x12,
	PT_OPEN		= 0x13,
	PT_DATA		= 0x14,
	PT_ECHO_REQ	= 0x15,
	PT_ECHO_RES	= 0x16,
	PT_CLOSE	= 0x17,
	PT_DATA_ENC	= 0x18,
	PT_PING_REQ	= 0x29,
	PT_PING_RSP	= 0x2A,
};

static const char *progname = "iwan_ctl";
static uint32_t nl_seq;

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

static void usage(FILE *fd)
{
	fprintf(fd,
"用法:\n"
"  iwan_ctl session-up --sid N --tok N --enc 0|1 --key HEX16 \\\n"
"                    --outer-src IP --outer-dst IP --dport N \\\n"
"                    [--outer-src6 IP6 --outer-dst6 IP6] [--ip6 IP6] \\\n"
"                    [--sport N] [--mtu N] [--oif N] [--no-create-dev]\n"
"                    [--reserved-flag-bit1]  置位保留的 FLAGS bit1（代答未实现），\n"
"                                            用来验证内核拒绝保留位（期望 -EINVAL）\n"
"  iwan_ctl session-down\n"
"  iwan_ctl set-peer --outer-dst IP [--sport N] [--dport N]\n"
"  iwan_ctl set-enabled 0|1\n"
"  iwan_ctl get-stats\n"
"  iwan_ctl events [--count N] [--timeout SEC]\n"
"\n"
"说明:\n"
"  · 家族 \"%s\" 与多播组 \"%s\" 用 CTRL_CMD_GETFAMILY 解析，不硬编码家族号\n"
"  · --outer-src = 本端外层地址，--outer-dst = 对端外层地址（见 iwan_genl.h）\n\
  · --outer-src6/--outer-dst6 = 外层 v6 端点（外层版本由“给了哪一对”决定；\n\
    两对同时给是 -EINVAL，本工具照发，用来测那条判据）\n\
  · --ip6 = 绑定的出口 v6 地址（必须等于 --outer-src6 且属于本机接口）\n\
  · --oif = 显式绑定的承载网卡 ifindex（IWAN_A_OIF；绑定路径不容忍解析错误）\n"
"  · get-stats 把配置快照/计数器按 KEY=value 打到 stdout；回执里缺的属性\n"
"    打印成空值（KEY=），内核报错时额外打印 error=<原因> 并以 3 退出\n"
"  · events 每条事件打印 EVENT=<事件名> 加属性；控制帧附 FRAME_HEX 与\n"
"    FRAME_TYPE_NAME，--timeout 0 表示一直等，--count 0 表示不限条数\n"
"  · 退出码: 0 成功, 1 参数/内核错误, 2 用法错误, 3 get-stats 内核报错,\n"
"            4 events 超时未收满 --count 条\n",
		IWAN_GENL_NAME, IWAN_GENL_MCGRP_EVENTS);
}

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ---------------------------------------------------------------- 消息构造 */

struct iwan_req {
	char		buf[BUF_SZ];
	struct nlmsghdr	*nlh;
};

static void req_init(struct iwan_req *r, uint16_t type, uint16_t flags,
		     uint8_t cmd, uint8_t version)
{
	struct genlmsghdr *gh;

	memset(r, 0, sizeof(*r));
	r->nlh = (struct nlmsghdr *)r->buf;
	r->nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	r->nlh->nlmsg_type = type;
	r->nlh->nlmsg_flags = flags;
	r->nlh->nlmsg_seq = ++nl_seq;
	gh = (struct genlmsghdr *)NLMSG_DATA(r->nlh);
	gh->cmd = cmd;
	gh->version = version;
	gh->reserved = 0;
}

static struct nlattr *nla_put(struct iwan_req *r, uint16_t type,
			      const void *data, size_t len)
{
	size_t off = NLA_ALIGN(r->nlh->nlmsg_len);
	struct nlattr *nla;

	if (off + NLA_HDRLEN + len > sizeof(r->buf))
		die("netlink 消息超出 %d 字节缓冲区", BUF_SZ);
	nla = (struct nlattr *)(r->buf + off);
	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + len;
	if (len)
		memcpy((char *)nla + NLA_HDRLEN, data, len);
	r->nlh->nlmsg_len = off + NLA_HDRLEN + len;
	return nla;
}

static void nla_put_u8(struct iwan_req *r, uint16_t t, uint8_t v)
{
	nla_put(r, t, &v, sizeof(v));
}

static void nla_put_u16(struct iwan_req *r, uint16_t t, uint16_t v)
{
	nla_put(r, t, &v, sizeof(v));
}

static void nla_put_u32(struct iwan_req *r, uint16_t t, uint32_t v)
{
	nla_put(r, t, &v, sizeof(v));
}

/* be32：地址已经是 inet_pton 给出的网络序字节，直接放 */
static void nla_put_be32(struct iwan_req *r, uint16_t t, uint32_t be)
{
	nla_put(r, t, &be, sizeof(be));
}

/* be16：主机序端口转网络序后放 */
static void nla_put_be16(struct iwan_req *r, uint16_t t, uint16_t host)
{
	uint16_t be = htons(host);

	nla_put(r, t, &be, sizeof(be));
}

static void nla_put_str(struct iwan_req *r, uint16_t t, const char *s)
{
	nla_put(r, t, s, strlen(s) + 1);
}

/* ---------------------------------------------------------------- 属性解析 */

/*
 * NLA_OK/NLA_NEXT 是内核内部宏（include/net/netlink.h），UAPI 头里没有，
 * 这里按同样的语义自己写一份，避免依赖内核源码树。
 */
static bool nla_ok(const struct nlattr *nla, int rem)
{
	return rem >= (int)sizeof(*nla) && nla->nla_len >= sizeof(*nla) &&
	       nla->nla_len <= rem;
}

static struct nlattr *nla_next(const struct nlattr *nla, int *rem)
{
	int step = NLA_ALIGN(nla->nla_len);

	*rem -= step;
	return (struct nlattr *)((char *)nla + step);
}

static void parse_attrs(const void *data, int len, struct nlattr **tb, int max)
{
	struct nlattr *nla;
	int rem = len;

	memset(tb, 0, sizeof(*tb) * (size_t)max);
	for (nla = (struct nlattr *)data; nla_ok(nla, rem);
	     nla = nla_next(nla, &rem)) {
		int t = (int)(nla->nla_type & NLA_TYPE_MASK);

		if (t > 0 && t < max)
			tb[t] = nla;
	}
}

static int nla_payload_len(const struct nlattr *nla)
{
	return (int)nla->nla_len - NLA_HDRLEN;
}

static bool attr_u8(struct nlattr **tb, int t, uint8_t *out)
{
	if (!tb[t] || nla_payload_len(tb[t]) < (int)sizeof(*out))
		return false;
	memcpy(out, (char *)tb[t] + NLA_HDRLEN, sizeof(*out));
	return true;
}

static bool attr_u16(struct nlattr **tb, int t, uint16_t *out)
{
	if (!tb[t] || nla_payload_len(tb[t]) < (int)sizeof(*out))
		return false;
	memcpy(out, (char *)tb[t] + NLA_HDRLEN, sizeof(*out));
	return true;
}

static bool attr_u32(struct nlattr **tb, int t, uint32_t *out)
{
	if (!tb[t] || nla_payload_len(tb[t]) < (int)sizeof(*out))
		return false;
	memcpy(out, (char *)tb[t] + NLA_HDRLEN, sizeof(*out));
	return true;
}

static bool attr_u64(struct nlattr **tb, int t, uint64_t *out)
{
	if (!tb[t] || nla_payload_len(tb[t]) < (int)sizeof(*out))
		return false;
	memcpy(out, (char *)tb[t] + NLA_HDRLEN, sizeof(*out));
	return true;
}

/* 属性里的 be16 -> 主机序端口；不存在返回 -1 */
static int attr_port(struct nlattr **tb, int t)
{
	uint16_t be;

	if (!attr_u16(tb, t, &be))
		return -1;
	return (int)ntohs(be);
}

/* 属性里的 be32 -> 点分十进制；不存在返回 false */
static bool attr_ip(struct nlattr **tb, int t, char *out, size_t outsz)
{
	uint32_t be;
	struct in_addr a;

	if (!attr_u32(tb, t, &be))
		return false;
	a.s_addr = be;
	return inet_ntop(AF_INET, &a, out, (socklen_t)outsz) != NULL;
}

static bool attr_str(struct nlattr **tb, int t, char *out, size_t outsz)
{
	int l;

	if (!tb[t])
		return false;
	l = nla_payload_len(tb[t]);
	if (l <= 0)
		return false;
	if ((size_t)l > outsz)
		l = (int)outsz;
	memcpy(out, (char *)tb[t] + NLA_HDRLEN, (size_t)l);
	out[l - 1] = '\0';
	return true;
}

/* ---------------------------------------------------------------- 连接 */

struct nl_ctx {
	int		fd;
	bool		resolved;
	uint16_t	fam_id;
	int		grp_id;
};

static void nl_open(struct nl_ctx *c)
{
	struct sockaddr_nl sa;
	struct timeval tv;

	memset(c, 0, sizeof(*c));
	c->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (c->fd < 0)
		die("socket(AF_NETLINK, NETLINK_GENERIC): %s", strerror(errno));
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(c->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind(netlink): %s", strerror(errno));
	/* 回执超时：模块没应答时报错而不是挂死 */
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	if (setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		die("setsockopt(SO_RCVTIMEO): %s", strerror(errno));
}

/*
 * 发一条请求并等回执。返回 0 成功、负 errno。
 * reply/replylen 带回第一条数据消息（genlmsghdr + 属性），可为 NULL。
 */
static int nl_talk(struct nl_ctx *c, struct iwan_req *r, char *reply,
		   size_t replysz, size_t *replylen)
{
	struct sockaddr_nl dst;
	char buf[BUF_SZ];
	bool want_ack = (r->nlh->nlmsg_flags & NLM_F_ACK) != 0;

	if (replylen)
		*replylen = 0;
	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	if (sendto(c->fd, r->buf, r->nlh->nlmsg_len, 0,
		   (struct sockaddr *)&dst, sizeof(dst)) < 0)
		return -errno;

	for (;;) {
		ssize_t n = recv(c->fd, buf, sizeof(buf), 0);
		int rem;
		struct nlmsghdr *h;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return (replylen && *replylen) ? 0 : -ETIMEDOUT;
			return -errno;
		}
		rem = (int)n;
		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, rem);
		     h = NLMSG_NEXT(h, rem)) {
			if (h->nlmsg_seq != r->nlh->nlmsg_seq)
				continue;
			if (h->nlmsg_type == NLMSG_ERROR) {
				const struct nlmsgerr *e =
					(const struct nlmsgerr *)NLMSG_DATA(h);

				if (e->error)
					return e->error;	/* 负 errno */
				return 0;			/* ACK */
			}
			if (h->nlmsg_type == NLMSG_DONE)
				return 0;
			if (reply && replysz) {
				size_t l = h->nlmsg_len - NLMSG_HDRLEN;

				if (l > replysz)
					l = replysz;
				memcpy(reply, NLMSG_DATA(h), l);
				if (replylen)
					*replylen = l;
			}
			if (!want_ack)
				return 0;
		}
	}
}

/* 解析家族 id 与多播组 id（只做一次）；失败带清晰原因退出。 */
static void nl_resolve(struct nl_ctx *c)
{
	struct iwan_req r;
	char reply[BUF_SZ];
	size_t rl = 0;
	struct nlattr *tb[CTRL_ATTR_MAX + 1];
	uint16_t fam_id = 0;
	int grp_id = 0;
	int err;

	if (c->resolved)
		return;
	req_init(&r, GENL_ID_CTRL, NLM_F_REQUEST, CTRL_CMD_GETFAMILY,
		 IWAN_GENL_VERSION);
	nla_put_str(&r, CTRL_ATTR_FAMILY_NAME, IWAN_GENL_NAME);
	err = nl_talk(c, &r, reply, sizeof(reply), &rl);
	if (err)
		die("查询 genetlink 家族 \"%s\" 失败: %s（模块没加载？）",
		    IWAN_GENL_NAME, strerror(-err));
	if (rl < GENL_HDRLEN)
		die("家族查询回执过短（%zu 字节）", rl);
	parse_attrs(reply + GENL_HDRLEN, (int)rl - GENL_HDRLEN, tb,
		    CTRL_ATTR_MAX + 1);
	if (!attr_u16(tb, CTRL_ATTR_FAMILY_ID, &fam_id) || !fam_id)
		die("内核回执里没有 CTRL_ATTR_FAMILY_ID");
	if (tb[CTRL_ATTR_MCAST_GROUPS]) {
		struct nlattr *g;
		int glen = nla_payload_len(tb[CTRL_ATTR_MCAST_GROUPS]);

		for (g = (struct nlattr *)((char *)tb[CTRL_ATTR_MCAST_GROUPS] +
					   NLA_HDRLEN);
		     nla_ok(g, glen); g = nla_next(g, &glen)) {
			struct nlattr *gtb[CTRL_ATTR_MCAST_GRP_MAX + 1];
			char name[64] = "";
			uint32_t id = 0;

			parse_attrs((char *)g + NLA_HDRLEN, nla_payload_len(g),
				    gtb, CTRL_ATTR_MCAST_GRP_MAX + 1);
			if (!attr_str(gtb, CTRL_ATTR_MCAST_GRP_NAME, name,
				      sizeof(name)))
				continue;
			if (!attr_u32(gtb, CTRL_ATTR_MCAST_GRP_ID, &id))
				continue;
			if (!strcmp(name, IWAN_GENL_MCGRP_EVENTS))
				grp_id = (int)id;
		}
	}
	if (!grp_id)
		die("家族 \"%s\" 没有多播组 \"%s\"（模块版本不匹配？）",
		    IWAN_GENL_NAME, IWAN_GENL_MCGRP_EVENTS);
	fprintf(stderr, "%s: 家族 \"%s\" id=%u, 多播组 \"%s\" id=%d\n",
		progname, IWAN_GENL_NAME, fam_id, IWAN_GENL_MCGRP_EVENTS,
		grp_id);
	c->fam_id = fam_id;
	c->grp_id = grp_id;
	c->resolved = true;
}

/* ---------------------------------------------------------------- 参数 */

struct args {
	bool	sid_given, tok_given, enc_given, key_given;
	bool	osrc_given, odst_given, dport_given, sport_given, mtu_given;
	bool	osrc6_given, odst6_given, ip6_given, oif_given;
	bool	no_create_dev, reserved_flag_bit1;
	uint16_t sid;
	uint32_t tok;
	uint8_t	enc;
	uint8_t	key[IWAN_KEY_BYTES];
	uint32_t osrc, odst;	/* be32（inet_pton 结果） */
	/* 外层 v6 端点与出口 IP（切片 2）。两对地址"都给"是合法输入形态之一
	 * —— 内核必须 -EINVAL 拒，本工具照发，专门用来测那条判据。 */
	struct in6_addr osrc6, odst6, ip6;
	uint16_t dport, sport;
	uint32_t mtu;
	uint32_t oif;		/* 显式绑定的承载网卡 ifindex（IWAN_A_OIF） */
	int	count, timeout;
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

static uint16_t parse_u16(const char *s, const char *what)
{
	unsigned long v = parse_ul(s, what);

	if (v > 0xffffUL)
		die("%s 超出 u16 范围: %s", what, s);
	return (uint16_t)v;
}

static uint32_t parse_u32(const char *s, const char *what)
{
	unsigned long v = parse_ul(s, what);

	if (v > 0xffffffffUL)
		die("%s 超出 u32 范围: %s", what, s);
	return (uint32_t)v;
}

static int hexval(char ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	return -1;
}

/* --key HEX16 -> 8 字节 */
static void parse_key(const char *s, uint8_t out[IWAN_KEY_BYTES])
{
	size_t i;

	if (strlen(s) != IWAN_KEY_BYTES * 2)
		die("--key 需要 %d 个十六进制字符（%d 字节），实际 %zu 个字符",
		    IWAN_KEY_BYTES * 2, IWAN_KEY_BYTES, strlen(s));
	for (i = 0; i < IWAN_KEY_BYTES; i++) {
		int hi = hexval(s[2 * i]);
		int lo = hexval(s[2 * i + 1]);

		if (hi < 0 || lo < 0)
			die("--key 含非十六进制字符: \"%s\"", s);
		out[i] = (uint8_t)((hi << 4) | lo);
	}
}

/* IP -> be32（网络序，直接塞进属性） */
static uint32_t parse_ip(const char *s, const char *what)
{
	struct in_addr a;

	if (inet_pton(AF_INET, s, &a) != 1)
		die("%s 不是合法 IPv4 地址: \"%s\"", what, s);
	return a.s_addr;
}

/* 外层 v6 字面量：允许裸地址与 [地址] 两种写法（与客户端一致） */
static void parse_ip6(const char *s, const char *what, struct in6_addr *out)
{
	char buf[INET6_ADDRSTRLEN];
	size_t n = strlen(s);

	if (n >= 2 && s[0] == '[' && s[n - 1] == ']') {
		s++;
		n -= 2;
	}
	if (n == 0 || n >= sizeof(buf))
		die("%s 太长/为空: \"%s\"", what, s);
	memcpy(buf, s, n);
	buf[n] = '\0';
	if (inet_pton(AF_INET6, buf, out) != 1)
		die("%s 不是合法 IPv6 地址: \"%s\"", what, buf);
}

/* ---------------------------------------------------------------- 命令 */

static void send_or_die(struct nl_ctx *c, struct iwan_req *r, const char *what,
			char *reply, size_t replysz, size_t *replylen)
{
	int err = nl_talk(c, r, reply, replysz, replylen);

	if (err)
		die("%s 失败: %s", what, strerror(-err));
}

static void put_stats_attrs(struct iwan_req *r, const struct args *a)
{
	nla_put_u16(r, IWAN_A_SID, a->sid);
	nla_put_u32(r, IWAN_A_TOK, a->tok);
	nla_put_u8(r, IWAN_A_ENC, a->enc);
	nla_put(r, IWAN_A_KEY, a->key, IWAN_KEY_BYTES);
	if (a->osrc_given || a->odst_given) {
		nla_put_be32(r, IWAN_A_OUTER_SRC, a->osrc);
		nla_put_be32(r, IWAN_A_OUTER_DST, a->odst);
	}
	if (a->osrc6_given || a->odst6_given) {
		nla_put(r, IWAN_A_OUTER_SRC6, &a->osrc6, sizeof(a->osrc6));
		nla_put(r, IWAN_A_OUTER_DST6, &a->odst6, sizeof(a->odst6));
	}
	if (a->ip6_given)
		nla_put(r, IWAN_A_IP6, &a->ip6, sizeof(a->ip6));
	if (a->oif_given)
		nla_put_u32(r, IWAN_A_OIF, a->oif);
	nla_put_be16(r, IWAN_A_DPORT, a->dport);
	if (a->sport_given)
		nla_put_be16(r, IWAN_A_SPORT, a->sport);
	if (a->mtu_given)
		nla_put_u32(r, IWAN_A_MTU, a->mtu);
}

static int cmd_session_up(struct nl_ctx *c, const struct args *a)
{
	struct iwan_req r;
	char reply[BUF_SZ];
	size_t rl = 0;
	struct nlattr *tb[IWAN_A_MAX + 1];
	char dev[64] = "";
	uint32_t rmtu = 0;
	uint32_t rowned = 0;
	bool has_mtu, has_dev, has_owned;
	uint32_t flags;

	if (!a->sid_given || !a->tok_given || !a->enc_given || !a->key_given ||
	    !a->dport_given ||
	    !((a->osrc_given && a->odst_given) ||
	      (a->osrc6_given && a->odst6_given)))
		die("session-up 需要 --sid --tok --enc --key --dport 与外层地址对"
		    "（--outer-src/--outer-dst 或 --outer-src6/--outer-dst6）"
		    "；--sport/--mtu/--ip6 可选");
	if (a->enc > 1)
		die("--enc 只能是 0 或 1，实际 %u", a->enc);
	if (a->sport_given && !a->sport)
		die("--sport 不能为 0（省略即用 --dport）");

	nl_resolve(c);
	req_init(&r, c->fam_id, NLM_F_REQUEST | NLM_F_ACK, IWAN_CMD_SESSION_UP,
		 IWAN_GENL_VERSION);
	put_stats_attrs(&r, a);
	if (a->no_create_dev || a->reserved_flag_bit1) {
		flags = 0;
		if (!a->no_create_dev)
			flags |= IWAN_A_FLAG_CREATE_DEV;
		if (a->reserved_flag_bit1)
			flags |= IWAN_A_FLAG_ANSWER_PING;   /* 保留位，模块应拒绝 */
		nla_put_u32(&r, IWAN_A_FLAGS, flags);
	}
	send_or_die(c, &r, "SESSION_UP", reply, sizeof(reply), &rl);

	memset(tb, 0, sizeof(tb));
	if (rl > GENL_HDRLEN)
		parse_attrs(reply + GENL_HDRLEN, (int)rl - GENL_HDRLEN, tb,
			    IWAN_A_MAX + 1);
	has_dev = attr_str(tb, IWAN_A_DEVNAME, dev, sizeof(dev));
	has_mtu = attr_u32(tb, IWAN_A_MTU, &rmtu);
	has_owned = attr_u32(tb, IWAN_A_DEV_OWNED, &rowned);
	if (!has_dev) {
		/* 回执缺 DEVNAME 时按设计默认名，让脚本还能继续并给出提示 */
		snprintf(dev, sizeof(dev), "iwan0");
		fprintf(stderr, "%s: 警告: SESSION_UP 回执没有 IWAN_A_DEVNAME，"
			"按 \"iwan0\" 处理\n", progname);
	}
	printf("DEVNAME=%s\n", dev);
	printf("MTU=%u\n", has_mtu ? rmtu :
	       (a->mtu_given ? a->mtu : 1500 - 36));
	printf("MTU_FROM_REPLY=%d\n", has_mtu ? 1 : 0);
	/* DEV_OWNED=1：这张 iwan0 是模块建的（SESSION_DOWN 会删它）；
	 * 0：不是模块建的（例如用户自己 ip link add 的 iwan 设备）；
	 * 老内核没有这个属性时回 -1，脚本据此跳过该项断言。 */
	printf("DEV_OWNED=%d\n", has_owned ? (int)rowned : -1);
	printf("DEV_OWNED_FROM_REPLY=%d\n", has_owned ? 1 : 0);
	return 0;
}

static int cmd_session_down(struct nl_ctx *c)
{
	struct iwan_req r;

	nl_resolve(c);
	req_init(&r, c->fam_id, NLM_F_REQUEST | NLM_F_ACK, IWAN_CMD_SESSION_DOWN,
		 IWAN_GENL_VERSION);
	send_or_die(c, &r, "SESSION_DOWN", NULL, 0, NULL);
	printf("SESSION=down\n");
	return 0;
}

static int cmd_set_peer(struct nl_ctx *c, const struct args *a)
{
	struct iwan_req r;
	char reply[BUF_SZ];
	size_t rl = 0;
	struct nlattr *tb[IWAN_A_MAX + 1];
	char ip[INET_ADDRSTRLEN] = "";
	int sport, dport;

	if (!a->odst_given)
		die("set-peer 需要 --outer-dst IP（--sport/--dport 可选）");

	nl_resolve(c);
	req_init(&r, c->fam_id, NLM_F_REQUEST | NLM_F_ACK, IWAN_CMD_SET_PEER,
		 IWAN_GENL_VERSION);
	nla_put_be32(&r, IWAN_A_OUTER_DST, a->odst);
	if (a->sport_given)
		nla_put_be16(&r, IWAN_A_SPORT, a->sport);
	if (a->dport_given)
		nla_put_be16(&r, IWAN_A_DPORT, a->dport);
	send_or_die(c, &r, "SET_PEER", reply, sizeof(reply), &rl);

	memset(tb, 0, sizeof(tb));
	if (rl > GENL_HDRLEN)
		parse_attrs(reply + GENL_HDRLEN, (int)rl - GENL_HDRLEN, tb,
			    IWAN_A_MAX + 1);
	if (!attr_ip(tb, IWAN_A_OUTER_DST, ip, sizeof(ip))) {
		struct in_addr x;

		x.s_addr = a->odst;
		inet_ntop(AF_INET, &x, ip, sizeof(ip));
	}
	sport = attr_port(tb, IWAN_A_SPORT);
	dport = attr_port(tb, IWAN_A_DPORT);
	printf("OK=1\n");
	printf("outer_dst=%s\n", ip);
	if (sport >= 0)
		printf("sport=%d\n", sport);
	if (dport >= 0)
		printf("dport=%d\n", dport);
	return 0;
}

static int cmd_set_enabled(struct nl_ctx *c, int val)
{
	struct iwan_req r;

	if (val != 0 && val != 1)
		die("set-enabled 只接受 0 或 1，实际 %d", val);
	nl_resolve(c);
	req_init(&r, c->fam_id, NLM_F_REQUEST | NLM_F_ACK, IWAN_CMD_SET_ENABLED,
		 IWAN_GENL_VERSION);
	nla_put_u8(&r, IWAN_A_ENABLED, (uint8_t)val);
	send_or_die(c, &r, "SET_ENABLED", NULL, 0, NULL);
	printf("enabled=%d\n", val);
	return 0;
}

/* 事件里控制帧的类型名（PROTOCOL.md 冻结值） */
static const char *frame_type_name(uint8_t t)
{
	switch (t) {
	case PT_OPEN_REJECT:	return "PT_OPEN_REJECT";
	case PT_OPEN_ACK:	return "PT_OPEN_ACK";
	case PT_OPEN:		return "PT_OPEN";
	case PT_DATA:		return "PT_DATA";
	case PT_ECHO_REQ:	return "PT_ECHO_REQ";
	case PT_ECHO_RES:	return "PT_ECHO_RES";
	case PT_CLOSE:		return "PT_CLOSE";
	case PT_DATA_ENC:	return "PT_DATA_ENC";
	case PT_PING_REQ:	return "PT_PING_REQ";
	case PT_PING_RSP:	return "PT_PING_RSP";
	default:		return "PT_UNKNOWN";
	}
}

static const char *event_name(uint8_t c)
{
	switch (c) {
	case IWAN_EV_CTRL_FRAME:	return "IWAN_EV_CTRL_FRAME";
	case IWAN_EV_PEER_CLOSE:	return "IWAN_EV_PEER_CLOSE";
	case IWAN_EV_PEER_SILENT:	return "IWAN_EV_PEER_SILENT";
	case IWAN_EV_KEEPALIVE:		return "IWAN_EV_KEEPALIVE";
	default:			return "IWAN_EV_UNKNOWN";
	}
}

static const char *peer_state_name(uint8_t s)
{
	switch (s) {
	case IWAN_PEER_UNKNOWN:	return "UNKNOWN";
	case IWAN_PEER_UP:	return "UP";
	case IWAN_PEER_SILENT:	return "SILENT";
	case IWAN_PEER_CLOSED:	return "CLOSED";
	default:		return "INVALID";
	}
}

/* 一条事件：事件名 + 属性；控制帧把帧字节 hex 打印并标注帧类型 */
static void print_event(uint8_t cmd, struct nlattr **tb)
{
	char ip[INET_ADDRSTRLEN];
	uint16_t sid;
	int port;

	printf("\nEVENT=%s\n", event_name(cmd));
	printf("EVENT_ID=%u\n", cmd);
	if (attr_u16(tb, IWAN_EVA_SID, &sid))
		printf("SID=%u\n", sid);
	if (attr_ip(tb, IWAN_EVA_OUTER_SRC, ip, sizeof(ip)))
		printf("OUTER_SRC=%s\n", ip);
	if (attr_ip(tb, IWAN_EVA_OUTER_DST, ip, sizeof(ip)))
		printf("OUTER_DST=%s\n", ip);
	port = attr_port(tb, IWAN_EVA_SPORT);
	if (port >= 0)
		printf("SPORT=%d\n", port);
	port = attr_port(tb, IWAN_EVA_DPORT);
	if (port >= 0)
		printf("DPORT=%d\n", port);
	if (tb[IWAN_EVA_SILENT_MS]) {
		uint64_t v = 0;

		attr_u64(tb, IWAN_EVA_SILENT_MS, &v);
		printf("SILENT_MS=%llu\n", (unsigned long long)v);
	}
	if (tb[IWAN_EVA_TIMESTAMP_MS]) {
		uint64_t v = 0;

		attr_u64(tb, IWAN_EVA_TIMESTAMP_MS, &v);
		printf("TIMESTAMP_MS=%llu\n", (unsigned long long)v);
	}
	if (tb[IWAN_EVA_FRAME]) {
		const uint8_t *f = (const uint8_t *)tb[IWAN_EVA_FRAME] + NLA_HDRLEN;
		int flen = nla_payload_len(tb[IWAN_EVA_FRAME]);
		int i;

		printf("FRAME_LEN=%d\n", flen);
		if (flen >= 4) {
			printf("FRAME_TYPE=0x%02x\n", f[0]);
			printf("FRAME_TYPE_NAME=%s\n", frame_type_name(f[0]));
			printf("FRAME_ENC=%u\n", f[1]);
			printf("FRAME_SID=%u\n", (unsigned)((f[2] << 8) | f[3]));
		}
		if (flen >= 8) {
			uint32_t tok = ((uint32_t)f[4] << 24) |
				       ((uint32_t)f[5] << 16) |
				       ((uint32_t)f[6] << 8) |
				       (uint32_t)f[7];

			printf("FRAME_TOK=%u\n", tok);
		}
		printf("FRAME_HEX=");
		for (i = 0; i < flen; i++)
			printf("%02x", f[i]);
		printf("\n");
	}
	fflush(stdout);
}

/* 嵌套 IWAN_A_STATS 里的计数器；缺属性按 0 */
static long long stat_val(struct nlattr **st, int idx)
{
	uint64_t v = 0;

	attr_u64(st, idx, &v);
	return (long long)v;
}

static int cmd_get_stats(struct nl_ctx *c)
{
	struct iwan_req r;
	char reply[BUF_SZ];
	size_t rl = 0;
	struct nlattr *tb[IWAN_A_MAX + 1];
	struct nlattr *st[IWAN_S_MAX + 1];
	uint16_t sid = 0;
	uint32_t tok = 0;
	uint8_t enc = 0, enabled = 0, pstate = 0;
	uint64_t ka = 0;
	uint32_t mtu = 0, flags = 0;
	uint32_t oif = 0, carrier = 0;
	char dev[64] = "", osrc[INET_ADDRSTRLEN] = "", odst[INET_ADDRSTRLEN] = "";
	char bip[INET_ADDRSTRLEN] = "";
	char keyhex[IWAN_KEY_BYTES * 2 + 1] = "";
	int sport, dport, err, rc = 0;
	bool has_sid, has_tok, has_dev;

	nl_resolve(c);
	req_init(&r, c->fam_id, NLM_F_REQUEST | NLM_F_ACK, IWAN_CMD_GET_STATS,
		 IWAN_GENL_VERSION);
	err = nl_talk(c, &r, reply, sizeof(reply), &rl);

	memset(tb, 0, sizeof(tb));
	memset(st, 0, sizeof(st));
	if (!err) {
		if (rl > GENL_HDRLEN)
			parse_attrs(reply + GENL_HDRLEN,
				    (int)rl - GENL_HDRLEN, tb, IWAN_A_MAX + 1);
		if (tb[IWAN_A_STATS])
			parse_attrs((char *)tb[IWAN_A_STATS] + NLA_HDRLEN,
				    nla_payload_len(tb[IWAN_A_STATS]), st,
				    IWAN_S_MAX + 1);
	} else {
		rc = 3;
	}

	has_sid = attr_u16(tb, IWAN_A_SID, &sid);
	has_tok = attr_u32(tb, IWAN_A_TOK, &tok);
	has_dev = attr_str(tb, IWAN_A_DEVNAME, dev, sizeof(dev));
	attr_u8(tb, IWAN_A_ENC, &enc);
	attr_u8(tb, IWAN_A_ENABLED, &enabled);
	attr_u8(tb, IWAN_A_PEER_STATE, &pstate);
	attr_u64(tb, IWAN_A_LAST_KEEPALIVE_MS, &ka);
	attr_u32(tb, IWAN_A_MTU, &mtu);
	attr_u32(tb, IWAN_A_FLAGS, &flags);
	attr_ip(tb, IWAN_A_OUTER_SRC, osrc, sizeof(osrc));
	attr_ip(tb, IWAN_A_OUTER_DST, odst, sizeof(odst));
	/* 承载网卡绑定：请求值（oif/bind_ip）与**实际生效**的承载网卡
	 * （carrier）一起打印——三者不一致就是排障要找的线索 */
	attr_u32(tb, IWAN_A_OIF, &oif);
	attr_ip(tb, IWAN_A_IP, bip, sizeof(bip));
	attr_u32(tb, IWAN_A_CARRIER, &carrier);
	sport = attr_port(tb, IWAN_A_SPORT);
	dport = attr_port(tb, IWAN_A_DPORT);
	if (tb[IWAN_A_KEY] && nla_payload_len(tb[IWAN_A_KEY]) >= IWAN_KEY_BYTES) {
		const uint8_t *k = (const uint8_t *)tb[IWAN_A_KEY] + NLA_HDRLEN;
		int i;

		for (i = 0; i < IWAN_KEY_BYTES; i++)
			sprintf(keyhex + 2 * i, "%02x", k[i]);
	}

	/* 稳定顺序的 KEY=value；缺的属性是空值，脚本只 grep 需要的键 */
	printf("error=%s\n", err ? strerror(-err) : "");
	printf("session=%d\n", ((has_sid && sid) || (has_tok && tok) ||
				(has_dev && dev[0])) ? 1 : 0);
	printf("sid=%u\n", sid);
	printf("tok=%u\n", tok);
	printf("enc=%u\n", enc);
	printf("key=%s\n", keyhex);
	printf("outer_src=%s\n", osrc);
	printf("outer_dst=%s\n", odst);
	printf("oif=%u\n", oif);
	printf("bind_ip=%s\n", bip);
	printf("carrier=%u\n", carrier);
	printf("sport=%d\n", sport < 0 ? 0 : sport);
	printf("dport=%d\n", dport < 0 ? 0 : dport);
	printf("mtu=%u\n", mtu);
	printf("devname=%s\n", dev);
	printf("enabled=%u\n", enabled);
	printf("flags=%u\n", flags);
	printf("peer_state=%u\n", pstate);
	printf("peer_state_name=%s\n", peer_state_name(pstate));
	printf("last_keepalive_ms=%llu\n", (unsigned long long)ka);
	printf("rx_pkts=%lld\n", stat_val(st, IWAN_S_RX_PKTS));
	printf("rx_outer=%lld\n", stat_val(st, IWAN_S_RX_OUTER));
	printf("rx_reasm=%lld\n", stat_val(st, IWAN_S_RX_REASM));
	printf("rx_frames=%lld\n", stat_val(st, IWAN_S_RX_FRAMES));
	printf("rx_delivered=%lld\n", stat_val(st, IWAN_S_RX_DELIVERED));
	printf("rx_batch=%lld\n", stat_val(st, IWAN_S_RX_BATCH));
	printf("rx_batch_skip=%lld\n", stat_val(st, IWAN_S_RX_BATCH_SKIP));
	printf("rx_bad_hdr=%lld\n", stat_val(st, IWAN_S_RX_BAD_HDR));
	printf("rx_bad_inner=%lld\n", stat_val(st, IWAN_S_RX_BAD_INNER));
	printf("rx_nomem=%lld\n", stat_val(st, IWAN_S_RX_NOMEM));
	printf("rx_ctrl_frame=%lld\n", stat_val(st, IWAN_S_RX_CTRL_FRAME));
	printf("tx_pkts=%lld\n", stat_val(st, IWAN_S_TX_PKTS));
	printf("tx_bytes=%lld\n", stat_val(st, IWAN_S_TX_BYTES));
	printf("tx_bad_state=%lld\n", stat_val(st, IWAN_S_TX_BAD_STATE));
	printf("tx_bad_inner=%lld\n", stat_val(st, IWAN_S_TX_BAD_INNER));
	printf("tx_err=%lld\n", stat_val(st, IWAN_S_TX_ERR));

	if (err)
		fprintf(stderr, "%s: GET_STATS 失败: %s\n", progname,
			strerror(-err));
	return rc;
}

static int cmd_events(struct nl_ctx *c, const struct args *a)
{
	int got = 0, rc = 0, one;
	uint64_t deadline = 0;

	nl_resolve(c);
	one = c->grp_id;
	if (setsockopt(c->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &one,
		       sizeof(one)) < 0)
		die("加入多播组 \"%s\"(id=%d) 失败: %s",
		    IWAN_GENL_MCGRP_EVENTS, c->grp_id, strerror(errno));
	printf("READY=1\n");
	fflush(stdout);

	if (a->timeout > 0)
		deadline = now_ms() + (uint64_t)a->timeout * 1000;
	while (!(a->count > 0 && got >= a->count)) {
		struct pollfd pfd;
		char buf[BUF_SZ];
		ssize_t n;
		int rem, wait = -1, pr;
		struct nlmsghdr *h;

		if (deadline) {
			uint64_t t = now_ms();

			if (t >= deadline)
				break;
			wait = (int)(deadline - t);
		}
		pfd.fd = c->fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		pr = poll(&pfd, 1, wait);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			die("poll: %s", strerror(errno));
		}
		if (pr == 0)
			break;			/* 超时 */
		n = recv(c->fd, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			die("recv: %s", strerror(errno));
		}
		rem = (int)n;
		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, rem);
		     h = NLMSG_NEXT(h, rem)) {
			struct genlmsghdr *gh;
			struct nlattr *tb[IWAN_EVA_MAX + 1];
			int alen;

			if (h->nlmsg_type != c->fam_id)
				continue;
			if (h->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
				continue;
			gh = (struct genlmsghdr *)NLMSG_DATA(h);
			alen = (int)h->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
			parse_attrs((char *)gh + GENL_HDRLEN, alen, tb,
				    IWAN_EVA_MAX + 1);
			print_event(gh->cmd, tb);
			got++;
		}
	}
	if (a->count > 0 && got < a->count) {
		fprintf(stderr, "%s: events 超时：只收到 %d/%d 条（timeout=%ds）\n",
			progname, got, a->count, a->timeout);
		rc = 4;
	}
	return rc;
}

/* ---------------------------------------------------------------- main */

enum {
	OPT_SID = 1, OPT_TOK, OPT_ENC, OPT_KEY, OPT_OUTER_SRC, OPT_OUTER_DST,
	OPT_OUTER_SRC6, OPT_OUTER_DST6, OPT_IP6, OPT_OIF,
	OPT_DPORT, OPT_SPORT, OPT_MTU, OPT_COUNT, OPT_TIMEOUT,
	OPT_NO_CREATE_DEV, OPT_RESERVED_FLAG_BIT1, OPT_HELP,
};

static const struct option long_opts[] = {
	{ "sid",		required_argument,	NULL, OPT_SID },
	{ "tok",		required_argument,	NULL, OPT_TOK },
	{ "enc",		required_argument,	NULL, OPT_ENC },
	{ "key",		required_argument,	NULL, OPT_KEY },
	{ "outer-src",		required_argument,	NULL, OPT_OUTER_SRC },
	{ "outer-dst",		required_argument,	NULL, OPT_OUTER_DST },
	{ "outer-src6",		required_argument,	NULL, OPT_OUTER_SRC6 },
	{ "outer-dst6",		required_argument,	NULL, OPT_OUTER_DST6 },
	{ "ip6",		required_argument,	NULL, OPT_IP6 },
	{ "oif",		required_argument,	NULL, OPT_OIF },
	{ "dport",		required_argument,	NULL, OPT_DPORT },
	{ "sport",		required_argument,	NULL, OPT_SPORT },
	{ "mtu",		required_argument,	NULL, OPT_MTU },
	{ "count",		required_argument,	NULL, OPT_COUNT },
	{ "timeout",		required_argument,	NULL, OPT_TIMEOUT },
	{ "no-create-dev",	no_argument,		NULL, OPT_NO_CREATE_DEV },
	{ "reserved-flag-bit1",	no_argument,		NULL, OPT_RESERVED_FLAG_BIT1 },
	{ "help",		no_argument,		NULL, OPT_HELP },
	{ NULL, 0, NULL, 0 },
};

int main(int argc, char **argv)
{
	struct args a;
	struct nl_ctx ctx;
	const char *cmd;
	int c, rc;

	memset(&a, 0, sizeof(a));
	a.timeout = 5;

	if (argc < 2) {
		usage(stderr);
		return 2;
	}
	cmd = argv[1];
	if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help") || !strcmp(cmd, "help")) {
		usage(stdout);
		return 0;
	}

	optind = 2;	/* 跳过子命令，从它的参数开始解析 */
	while ((c = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
		switch (c) {
		case OPT_SID:
			a.sid = parse_u16(optarg, "--sid");
			a.sid_given = true;
			break;
		case OPT_TOK:
			a.tok = parse_u32(optarg, "--tok");
			a.tok_given = true;
			break;
		case OPT_ENC: {
			uint32_t v = parse_u32(optarg, "--enc");

			if (v > 1)
				die("--enc 只能是 0 或 1，实际 %u", v);
			a.enc = (uint8_t)v;
			a.enc_given = true;
			break;
		}
		case OPT_KEY:
			parse_key(optarg, a.key);
			a.key_given = true;
			break;
		case OPT_OUTER_SRC:
			a.osrc = parse_ip(optarg, "--outer-src");
			a.osrc_given = true;
			break;
		case OPT_OUTER_SRC6:
			parse_ip6(optarg, "--outer-src6", &a.osrc6);
			a.osrc6_given = true;
			break;
		case OPT_OUTER_DST6:
			parse_ip6(optarg, "--outer-dst6", &a.odst6);
			a.odst6_given = true;
			break;
		case OPT_OIF:
			a.oif = (uint32_t)strtoul(optarg, NULL, 10);
			a.oif_given = true;
			break;
		case OPT_IP6:
			parse_ip6(optarg, "--ip6", &a.ip6);
			a.ip6_given = true;
			break;
		case OPT_OUTER_DST:
			a.odst = parse_ip(optarg, "--outer-dst");
			a.odst_given = true;
			break;
		case OPT_DPORT:
			a.dport = parse_u16(optarg, "--dport");
			a.dport_given = true;
			break;
		case OPT_SPORT:
			a.sport = parse_u16(optarg, "--sport");
			a.sport_given = true;
			break;
		case OPT_MTU:
			a.mtu = parse_u32(optarg, "--mtu");
			a.mtu_given = true;
			break;
		case OPT_COUNT:
			a.count = (int)parse_u32(optarg, "--count");
			break;
		case OPT_TIMEOUT:
			a.timeout = (int)parse_u32(optarg, "--timeout");
			break;
		case OPT_NO_CREATE_DEV:
			a.no_create_dev = true;
			break;
		case OPT_RESERVED_FLAG_BIT1:
			a.reserved_flag_bit1 = true;
			break;
		case OPT_HELP:
			usage(stdout);
			return 0;
		default:
			usage(stderr);
			return 2;
		}
	}

	nl_open(&ctx);
	if (!strcmp(cmd, "session-up")) {
		if (optind != argc)
			die("session-up 有多余参数: %s", argv[optind]);
		rc = cmd_session_up(&ctx, &a);
	} else if (!strcmp(cmd, "session-down")) {
		if (optind != argc)
			die("session-down 不接受参数");
		rc = cmd_session_down(&ctx);
	} else if (!strcmp(cmd, "set-peer")) {
		if (optind != argc)
			die("set-peer 有多余参数: %s", argv[optind]);
		rc = cmd_set_peer(&ctx, &a);
	} else if (!strcmp(cmd, "set-enabled")) {
		if (optind != argc - 1)
			die("用法: iwan_ctl set-enabled 0|1");
		rc = cmd_set_enabled(&ctx,
				     (int)parse_ul(argv[optind], "set-enabled"));
	} else if (!strcmp(cmd, "get-stats")) {
		if (optind != argc)
			die("get-stats 不接受参数");
		rc = cmd_get_stats(&ctx);
	} else if (!strcmp(cmd, "events")) {
		if (optind != argc)
			die("events 有多余参数: %s", argv[optind]);
		rc = cmd_events(&ctx, &a);
	} else {
		fprintf(stderr, "%s: 未知子命令 \"%s\"\n", progname, cmd);
		usage(stderr);
		return 2;
	}
	close(ctx.fd);
	return rc;
}
