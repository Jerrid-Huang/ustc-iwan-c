/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_frame.h — Windows 数据面的纯逻辑：线上格式、XOR、校验和、目标匹配。
 *
 * 这里刻意不依赖 WDK（除了类型别名）：同一份代码既编进驱动，也能在本机用
 * 主机编译器编出来跑对拍测试（tests/win_frame_test.c），把"线上格式"这件
 * 最容易出错、又最难在 Windows 上调试的事提前钉死。
 *
 * 线上格式与 Linux 模块逐字节一致，出处：
 *   · kernel/iwan_tx.c 的 fh[] 构造          —— 8 字节 iWAN 帧头
 *   · kernel/iwan_core.c 的 iwan_xor()       —— key[(off + i) & 7]
 *   · kernel/iwan_tx.c 的外层 IPv4/UDP 构造  —— ttl 64、DF、源地址取会话
 *   · src/common/protocol.c 的 pkt_hdr()     —— 用户态同一份帧头，用于对拍
 */
#ifndef IWAN_WIN_FRAME_H
#define IWAN_WIN_FRAME_H

#if defined(_KERNEL_MODE)
#  include <ntddk.h>
#else
#  include <stdint.h>
#  include <stddef.h>
#  include <string.h>
typedef uint8_t  UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uint16_t USHORT;

/* 主机侧（Linux 上做静态检查与对拍）没有 WDK 的 Rtl* 例程：给一份等价实现。
 * 只在非 Windows 宿主上生效：mingw/Windows SDK 的 winnt.h 自带这些名字，
 * 重定义会撞车（驱动真正的构建走 _KERNEL_MODE 分支，与这里无关）。
 *
 * 语义按 WDK 文档：RtlCopyMemory/RtlZeroMemory/RtlFillMemory 与 mem* 同义，
 * RtlCompareMemory 返回从头开始逐字节相同的字节数（首个不同处停下）。 */
#if !defined(_WIN32)
static __inline void iwan_win_host_copy(void *dst, const void *src, size_t n)
{
	memcpy(dst, src, n);
}
static __inline void iwan_win_host_zero(void *dst, size_t n)
{
	memset(dst, 0, n);
}
static __inline size_t iwan_win_host_cmp(const void *a, const void *b, size_t n)
{
	const unsigned char *x = (const unsigned char *)a;
	const unsigned char *y = (const unsigned char *)b;
	size_t i;

	for (i = 0; i < n; i++)
		if (x[i] != y[i])
			break;
	return i;
}
#define RtlCopyMemory(d, s2, n) iwan_win_host_copy((d), (s2), (n))
#define RtlZeroMemory(d, n)     iwan_win_host_zero((d), (n))
#define RtlCompareMemory(a, b, n) iwan_win_host_cmp((a), (b), (n))
#endif /* !_WIN32 */
typedef unsigned long ULONG;
typedef int BOOLEAN;
typedef long NTSTATUS;
#  ifndef TRUE
#    define TRUE 1
#  endif
#  ifndef FALSE
#    define FALSE 0
#  endif

/* 主机侧把 WDK 的 VOID 与 SAL 注解中和掉，同一份源码既进驱动也进对拍测试 */
#  define VOID void
#  define _In_
#  define _In_opt_
#  define _In_z_
#  define _Out_
#  define _Out_opt_
#  define _Inout_
#  define _Inout_opt_
#  define _In_reads_(x)
#  define _In_reads_opt_(x)
#  define _In_reads_bytes_(x)
#  define _Out_writes_(x)
#  define _Out_writes_bytes_(x)
#  define _Out_writes_bytes_opt_(x)
#  define _Inout_updates_bytes_(x)
#  define _Outptr_
#  define _Outptr_opt_
#  define _Inout_updates_(x)
#endif

#include "iwan_win_abi.h"

/* 与 kernel/iwan.h 一致的线上常量 */
#define IWAN_PT_DATA		0x14	/* 明文内层 IP 包 */
#define IWAN_PT_DATA_ENC	0x18	/* XOR 后的内层 IP 包 */
#define IWAN_KEY_LEN		8
#define IWAN_FRAME_HDR_LEN	8
#define IWAN_OUTER_UDP_LEN	8
#define IWAN_OUTER_IP4_LEN	20
#define IWAN_OUTER4_TOTAL \
	(IWAN_OUTER_IP4_LEN + IWAN_OUTER_UDP_LEN + IWAN_FRAME_HDR_LEN)	/* 36 */
#define IWAN_OUTER_IP6_LEN	40
#define IWAN_OUTER6_TOTAL	(IWAN_OUTER_IP6_LEN + IWAN_OUTER_UDP_LEN + IWAN_FRAME_HDR_LEN)
/* 内层 IPv6 首部（不含扩展头）。数值与 IWAN_OUTER_IP6_LEN 相同但含义不同：
 * 前者是内层报文自己的头，后者是封装用外层头，别混用。 */
#define IWAN_INNER_IP6_LEN	40

#define IWAN_IPPROTO_TCP	6
#define IWAN_IPPROTO_UDP	17
#define IWAN_IP4_DF		0x4000

/* 帧类型。数值必须与 kernel/iwan.h、src/common/protocol.h 完全一致：
 * tests/win_frame_test.c 里有一组断言把它们钉在 protocol.h 上，改一处就会
 * 在测试中报错（这是最容易悄悄写错、又只能表现为"对端全丢包"的地方）。 */
#define PT_OPEN_REJECT		0x11
#define PT_OPEN_ACK		0x12
#define PT_OPEN			0x13
#define PT_DATA			0x14
#define PT_ECHO_REQ		0x15
#define PT_ECHO_RES		0x16
#define PT_CLOSE		0x17
#define PT_DATA_ENC		0x18
#define PT_PING_REQ		0x29
#define PT_PING_RSP		0x2A

#define IWAN_PING_SID		0xFFFF
#define IWAN_PING_TOK		0xFFFFFFFFu

/* 帧分类结果，与 kernel/iwan_rx.c 的 enum iwan_frame_kind 一一对应 */
#define IWAN_WIN_FRAME_BAD	0u	/* 丢弃（凭据不符/类型未知/结构不合法） */
#define IWAN_WIN_FRAME_DATA	1u	/* 解封后注入本机协议栈 */
#define IWAN_WIN_FRAME_CTRL	2u	/* 原样放行给用户态套接字 */

/* 外层解析结果 */
typedef struct _IWAN_WIN_OUTER {
	UINT32	frame_off;	/* iWAN 帧头相对包首的偏移 */
	UINT32	frame_len;	/* 帧字节数（含 8 字节帧头） */
	UINT32	inner_off;	/* 内层包相对包首的偏移 */
	UINT32	inner_len;	/* 内层包长度 */
	UINT16	sport;		/* 外层 UDP 源端口（网络序，取自 UDP 头本身） */
	UINT16	dport;		/* 外层 UDP 目的端口 */
	UINT8	type;
	UINT8	enc;
	UINT16	sid;
	UINT32	tok;
} IWAN_WIN_OUTER;

/* ---- 出向（M1/M3）：外层头构造 ---------------------------------------- */

/*
 * 把"已经加密好的帧"（8B 帧头 + 载荷）包成完整的外层数据报。
 *
 * 与 kernel/iwan_tx.c 逐字段对齐：外层 IPv4 ttl 64 / DF=1 / 协议 UDP；
 * 外层 IPv6 traffic class 与 flow label 全 0 / hop limit 64 / nexthdr 直接是
 * UDP（不带扩展头）/ 不分片。
 *
 * UDP 校验和两条路都算真的：Linux 侧 v4 用 udp_set_csum()、v6 用
 * udp6_set_csum()，Windows 照做 —— v6 的 UDP 校验和是 RFC 8200 强制的，v4
 * 有一个正确值也让中间设备和 NAT 省心。返回整个数据报长度，0 = 参数不合法。
 */
/* 只写外层 IP/UDP 头（含两个校验和）：调用者必须已把帧放在
 * IWAN_OUTERx_TOTAL - IWAN_FRAME_HDR_LEN 处。flen 是帧长（8B 帧头 + 载荷）。
 * 返回整个数据报长度，0 = 参数不合法。驱动走这条（帧已在自己的缓冲里），
 * 测试走下面的 build（自带搬运）。 */
ULONG iwan_win_outer_hdr4(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
			  _In_ ULONG flen, _In_ UINT32 src_be, _In_ UINT32 dst_be,
			  _In_ USHORT sport, _In_ USHORT dport);

ULONG iwan_win_outer_hdr6(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
			  _In_ ULONG flen,
			  _In_reads_bytes_(16) const UINT8 *src6,
			  _In_reads_bytes_(16) const UINT8 *dst6,
			  _In_ USHORT sport, _In_ USHORT dport);

ULONG iwan_win_outer_build4(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
			    _In_reads_bytes_(flen) const UINT8 *frame,
			    _In_ ULONG flen, _In_ UINT32 src_be,
			    _In_ UINT32 dst_be, _In_ USHORT sport,
			    _In_ USHORT dport);

ULONG iwan_win_outer_build6(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
			    _In_reads_bytes_(flen) const UINT8 *frame,
			    _In_ ULONG flen,
			    _In_reads_bytes_(16) const UINT8 *src6,
			    _In_reads_bytes_(16) const UINT8 *dst6,
			    _In_ USHORT sport, _In_ USHORT dport);

/* 解析外层 IPv6 + UDP + iWAN 帧头（字段语义同 IWAN_WIN_OUTER）。 */
BOOLEAN iwan_win_outer_parse6(_In_reads_bytes_(len) const UINT8 *pkt,
			      _In_ ULONG len, _Out_ IWAN_WIN_OUTER *out);

/*
 * 出向是否该隧道：在 v6 目标集合里做最长前缀匹配。外层服务器自己的地址
 * 永不入隧道（否则封装出来的包会再被自己匹配一次，直接打成环）。
 */
BOOLEAN iwan_win_should_tunnel6(_In_reads_(count) const IWAN_WIN_TARGET *targets,
				_In_ UINT32 count,
				_In_reads_bytes_(16) const UINT8 *outer_dst6,
				_In_reads_bytes_(16) const UINT8 *daddr6);

/* 解析外层 IPv4 + UDP + iWAN 帧头。FALSE = 结构不合法（版本/协议/长度）。
 * 不做凭据判断（那是 iwan_win_frame_classify 的事）。 */
BOOLEAN iwan_win_outer_parse4(_In_reads_bytes_(len) const UINT8 *pkt,
			      _In_ ULONG len, _Out_ IWAN_WIN_OUTER *out);

/*
 * 解析"协议栈已重组"的数据报形态：入向 callout 装在 INBOUND_TRANSPORT_V4/V6，
 * 那里分片已经由协议栈拼好、IP 头已经被摘掉，layerData 从外层 UDP 头开始。
 * 端口与长度都从 UDP 头本身取，因此这一层不依赖 WFP 固定字段里的端口。
 *
 * 兼容"仍带 IP 头"的形态：只有版本号、IHL、协议(UDP)、无分片位四项全部自洽
 * 时才跳过 IP 头，否则按裸数据报解析 —— 层形态与预期不符时不至于静默失效，
 * 而误判也进不来：裸数据报偏移 9 那个字节是帧头的 enc 字段（只可能是 0/1），
 * 永远不可能等于 17。
 */
BOOLEAN iwan_win_dgram_parse(_In_reads_bytes_(len) const UINT8 *pkt,
			     _In_ ULONG len, _Out_ IWAN_WIN_OUTER *out);

/* 帧分类：与 kernel/iwan_rx.c 的 iwan_frame_check 逐条一致 ——
 *   · PT_DATA / PT_DATA_ENC：类型必须与会话 enc 模式一致，且 sid/tok 相符；
 *   · PT_OPEN/OPEN_ACK/OPEN_REJECT：握手帧，凭据只能由用户态校验，
 *     已建会话时一律转交；
 *   · PT_ECHO_REQ/RES、PT_CLOSE：必须带会话 sid/tok；
 *   · PT_PING_REQ/RSP：接受协议固定凭据或会话凭据；
 *   · 其余：丢弃。 */
UINT32 iwan_win_frame_classify(_In_ const IWAN_WIN_OUTER *o,
			       _In_ UINT16 sess_sid, _In_ UINT32 sess_tok,
			       _In_ BOOLEAN sess_enc,
			       _In_ BOOLEAN session_established);

/* 解封：把内层包复制到 out 并在 enc 时 XOR 还原。返回写出的字节数，
 * 0 = 参数不合法。返回的明文包其校验和是有效的（发送侧在 XOR 之前算好的，
 * 与 kernel/iwan_core.c 的同一约定），所以这里不需要重算校验和。 */
ULONG iwan_win_decap(_In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		     _In_ const IWAN_WIN_OUTER *o,
		     _In_reads_bytes_(IWAN_KEY_LEN) const UINT8 *key,
		     _Out_writes_bytes_(outsz) UINT8 *out, _In_ ULONG outsz);

/* 内层包的协议族（4 或 6）：决定用哪个注入句柄重新入栈。0 = 不认识的版本。 */
UINT32 iwan_win_inner_family(_In_reads_bytes_(len) const UINT8 *inner,
			     _In_ ULONG len);

/* 明文内层包的头部自洽性：版本 + 头长 + 头部声明的总长盖得住整帧。
 * 口径与 kernel/iwan_rx.c 的 RX 判定一致（宽松：多余尾字节不拒）。 */
BOOLEAN iwan_win_inner_sane(_In_reads_bytes_(len) const UINT8 *inner,
			    _In_ ULONG len);

/* 8 字节 iWAN 帧头：与 kernel/iwan_tx.c 的 fh[] 和 src/common/protocol.c 的
 * pkt_hdr() 逐字节相同（typ 由调用者给 PT_DATA/PT_DATA_ENC）。 */
VOID iwan_win_build_frame_hdr(_Out_writes_bytes_(IWAN_FRAME_HDR_LEN) UINT8 *out,
			      _In_ UINT8 typ, _In_ UINT8 enc,
			      _In_ UINT16 sid, _In_ UINT32 tok);

/* 就地 XOR：p[i] ^= key[(off + i) & 7]（对应 kernel/iwan_core.c 的 iwan_xor） */
VOID iwan_win_xor(_Inout_updates_bytes_(len) UINT8 *p, _In_ ULONG len,
		  _In_reads_bytes_(IWAN_KEY_LEN) const UINT8 *key, _In_ ULONG off);

/* 在 XOR **之前**对明文内层 IPv4 包补齐校验和：IP 头校验和总是重算，
 * TCP/UDP 校验和只在报文带着校验和卸载标记时重算（l4_offloaded）。 */
VOID iwan_win_inner_fix_csum(_Inout_updates_bytes_(len) UINT8 *pkt, _In_ ULONG len,
			     _In_ BOOLEAN l4_offloaded);

/* 目标集合最长前缀匹配（纯函数，便于对拍）。family 用 IWAN_WIN_AF_V4/V6，
 * addr 指向 4 或 16 字节网络序地址。 */
BOOLEAN iwan_win_target_match(_In_reads_(count) const IWAN_WIN_TARGET *targets,
			      _In_ UINT32 count, _In_ UINT32 family,
			      _In_reads_bytes_(16) const UINT8 *addr);

/* 该不该进隧道：命中目标集合，且目的地址不是外层服务器自己
 * （对应 Linux 侧"服务器 /32 钉在物理网卡"，避免隧道外层包反过来进隧道）。 */
BOOLEAN iwan_win_should_tunnel4(_In_reads_(count) const IWAN_WIN_TARGET *targets,
				_In_ UINT32 count,
				_In_reads_bytes_(4) const UINT8 *outer_dst_be,
				_In_reads_bytes_(4) const UINT8 *daddr);

/* 小工具（驱动内部与测试都用） */
USHORT iwan_win_rd16(_In_reads_bytes_(2) const UINT8 *p);
VOID iwan_win_wr16(_Out_writes_bytes_(2) UINT8 *p, _In_ USHORT v);
VOID iwan_win_wr32(_Out_writes_bytes_(4) UINT8 *p, _In_ UINT32 v);
UINT32 iwan_win_rd32(_In_reads_bytes_(4) const UINT8 *p);

#endif /* IWAN_WIN_FRAME_H */
