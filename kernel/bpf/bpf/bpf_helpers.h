/* Minimal libbpf shim -- for use when libbpf-dev is not available, together with iproute2's legacy
 * loader (`ip route ... encap bpf xmit obj x.o sec lwt_xmit` / `tc filter ...
 * bpf da obj x.o`). iproute2 parses the ELF and relocates by itself; libbpf is not needed.
 *
 * Helpers are declared as "constant function pointers": the standard practice before libbpf; the pointer value is
 * the BPF_FUNC_* number, and the loader relocates it into a real helper call.
 * If libbpf-dev is installed, use -I/usr/include so <bpf/bpf_helpers.h> resolves to the official
 * version (put this directory's -I last).
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

/* Macros needed for BTF-style map definitions (libbpf 1.0+ no longer supports legacy struct bpf_map_def) */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* Counter increment. Must be inlined: the map reference must be passed to the helper as a constant,
 * not as a function parameter (otherwise clang generates the call form that passes a map fd). */
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

/* Byte order: BPF is little-endian on x86/arm64 => htons/ntohs are just bswap */
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)

/* Minimal protocol headers (only fixed-length fields, to avoid depending on kernel internal headers) */
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
