/* 最小 libbpf 垫片 —— 本机没有 libbpf-dev 时用，配合 iproute2 的 legacy
 * 加载器（`ip route ... encap bpf xmit obj x.o sec lwt_xmit` / `tc filter ...
 * bpf da obj x.o`）。iproute2 自己解析 ELF 并重定位，不需要 libbpf。
 *
 * helper 用"常量函数指针"声明：这是 libbpf 之前的标准做法，指针值就是
 * BPF_FUNC_* 编号，加载器会把它重定位成真正的 helper 调用。
 * 若系统装了 libbpf-dev，用 -I/usr/include 让 <bpf/bpf_helpers.h> 命中官方
 * 版本即可（把本目录的 -I 放到最后）。
 */
#ifndef IWAN_BPF_HELPERS_H
#define IWAN_BPF_HELPERS_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#define SEC(x) __attribute__((section(x), used))
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#define __noinline __attribute__((noinline))

/* BTF 式映射定义所需宏（libbpf 1.0+ 已不支持 legacy struct bpf_map_def） */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* 计数器自增。必须内联展开：map 引用要作为常量直接传给 helper，
 * 不能把 map 指针当函数参数（否则 clang 会生成传 map fd 的调用形式）。 */
#define BUMP(map, idx)							\
	do {								\
		__u32 _k = (idx);					\
		__u64 *_v = bpf_map_lookup_elem(&(map), &_k);		\
		if (_v)							\
			*_v = *_v + 1;					\
	} while (0)

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
	(void *) BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *v,
				   __u64 f) = (void *) BPF_FUNC_map_update_elem;
static long (*bpf_skb_store_bytes)(void *skb, __u32 off, const void *from,
				   __u32 len, __u64 f) =
	(void *) BPF_FUNC_skb_store_bytes;
static long (*bpf_l3_csum_replace)(void *skb, __u32 off, __u64 from, __u64 to,
				   __u64 size) = (void *) BPF_FUNC_l3_csum_replace;
static long (*bpf_l4_csum_replace)(void *skb, __u32 off, __u64 from, __u64 to,
				   __u64 f) = (void *) BPF_FUNC_l4_csum_replace;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 off, void *to,
				  __u32 len) = (void *) BPF_FUNC_skb_load_bytes;
static long (*bpf_skb_adjust_room)(void *skb, __s32 len_diff, __u32 mode,
				   __u64 f) = (void *) BPF_FUNC_skb_adjust_room;
static long (*bpf_lwt_push_encap)(void *skb, __u32 type, void *hdr,
				  __u32 len) = (void *) BPF_FUNC_lwt_push_encap;

/* 字节序：x86/arm64 上 BPF 为小端 ⇒ htons/ntohs 就是 bswap */
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)

/* 精简协议头（只用到固定长度字段，避免依赖内核内部头） */
struct ethhdr_min {
	__u8 dst[6];
	__u8 src[6];
	__u16 proto;
};
struct ipv4_hdr {
	__u8 ver_ihl;
	__u8 tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
};
struct udp_hdr {
	__u16 source;
	__u16 dest;
	__u16 len;
	__u16 check;
};
#endif /* IWAN_BPF_HELPERS_H */
