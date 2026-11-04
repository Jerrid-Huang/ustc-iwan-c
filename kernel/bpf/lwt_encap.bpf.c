/* Comparison path (not for production): eBPF egress encapsulation on LWT_XMIT.
 *
 * Its purpose is to **prove that eBPF egress cannot satisfy the frozen XOR semantics**, not to provide a
 * usable path. The reason is the hook position:
 *
 *   The LWT_XMIT hook runs inside ip_finish_output2() -- after software fragmentation (that part is fine),
 *   but still before validate_xmit_skb(). At this point the skb L4 checksum is usually still
 *   CHECKSUM_PARTIAL ("not computed yet, left to the driver/hardware"). Therefore:
 *     - enc=1 (XOR): XOR covers the checksum field, so what the driver/software computes afterwards is
 *       "the checksum of the ciphertext"; the peer decapsulates to plaintext and validates it as plaintext => InCsumErrors / packet loss for sure.
 *     - enc=0 (no XOR): only header encapsulation is added, the checksum is still computed later => all fine.
 *   The same program passes/fails by flipping one switch, so the failure cause is uniquely pinned to the XOR
 *   conflict with "checksum computation timing" (the kernel module does XOR in ndo_start_xmit, when the
 *   checksum is already computed, so it does not have this problem).
 *
 * Config and counters live in maps, filled by kernel/tests/ab_lwt_test.sh via bpftool.
 */
#include <bpf/bpf_helpers.h>

#define IWAN_HDR_LEN	8
#define PT_DATA		0x14
#define PT_DATA_ENC	0x18
#define MAX_WORDS	192	/* 192*8 = 1536B >= 1500 MTU */

/* Matches the frozen format in PROTOCOL.md: [outer IP][UDP][type,enc,sid(u16 BE),tok(u32 BE)][payload] */
struct lwt_cfg {
	__u32 outer_saddr;	/* network byte order */
	__u32 outer_daddr;	/* network byte order */
	__u16 sport;		/* host byte order */
	__u16 dport;		/* host byte order */
	__u16 sid;
	__u32 tok;
	__u8  key[8];		/* session key = MD5(user||pass)[0..8) */
	__u8  enc;		/* 1 = XOR(PT_DATA_ENC), 0 = plaintext(PT_DATA) */
	__u8  pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct lwt_cfg);
} lwt_cfg_map SEC(".maps");

/* Counter indexes: 1=XOR done 2=plain encaps 3=no config 4=push_encap failed 5=encrypted sent 6=plain sent */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} lwt_cnt SEC(".maps");

struct encap_hdr {
	struct ipv4_hdr ip;
	struct udp_hdr udp;
	__u8 iwan[IWAN_HDR_LEN];
} __attribute__((packed));

SEC("lwt_xmit")
int iwan_lwt_encap(struct __sk_buff *skb)
{
	__u32 zero = 0, i, len = skb->len, wlen, tail;
	struct lwt_cfg *cf = bpf_map_lookup_elem(&lwt_cfg_map, &zero);
	struct encap_hdr h;
	__u64 key;
	__u8 keyb[8];

	if (!cf) {
		BUMP(lwt_cnt, 3);
		return BPF_OK;		/* no config: pass through unchanged */
	}

	if (cf->enc) {
		/* Whole-packet XOR: the word part is unrolled at constant offsets, the tail byte by byte (byte-for-byte
		 * equivalent to the kernel module and to the 8-byte cyclic key of userspace xor_crypt()).
		 * key is fetched with a byte-wise memcpy: the key field in the map is not guaranteed to be 8-byte aligned. */
		__builtin_memcpy(&key, cf->key, 8);
		wlen = len & ~7u;
		tail = len & 7u;
#pragma unroll
		for (i = 0; i < MAX_WORDS; i++) {
			__u32 o = i * 8;
			__u64 w;
			if (o >= wlen)
				break;
			if (bpf_skb_load_bytes(skb, o, &w, 8))
				break;
			w ^= key;
			if (bpf_skb_store_bytes(skb, o, &w, 8, 0))
				break;
		}
		if (tail) {
			__builtin_memcpy(keyb, &key, 8);
#pragma unroll
			for (i = 0; i < 7; i++) {
				__u8 b;
				if (i >= tail)
					break;
				if (bpf_skb_load_bytes(skb, wlen + i, &b, 1))
					break;
				b ^= keyb[i];
				bpf_skb_store_bytes(skb, wlen + i, &b, 1, 0);
			}
		}
		BUMP(lwt_cnt, 1);
	} else {
		BUMP(lwt_cnt, 2);
	}

	__builtin_memset(&h, 0, sizeof(h));
	h.ip.ver_ihl = 0x45;
	h.ip.tot_len = bpf_htons(sizeof(h) + len);
	h.ip.frag_off = bpf_htons(0x4000);	/* DF=1: no further outer fragmentation */
	h.ip.ttl = 64;
	h.ip.protocol = 17;			/* UDP */
	h.ip.saddr = cf->outer_saddr;
	h.ip.daddr = cf->outer_daddr;
	h.udp.source = bpf_htons(cf->sport);
	h.udp.dest = bpf_htons(cf->dport);
	h.udp.len = bpf_htons(IWAN_HDR_LEN + len);
	h.iwan[0] = cf->enc ? PT_DATA_ENC : PT_DATA;
	h.iwan[1] = cf->enc;
	h.iwan[2] = (__u8)(cf->sid >> 8);
	h.iwan[3] = (__u8)cf->sid;
	h.iwan[4] = (__u8)(cf->tok >> 24);
	h.iwan[5] = (__u8)(cf->tok >> 16);
	h.iwan[6] = (__u8)(cf->tok >> 8);
	h.iwan[7] = (__u8)cf->tok;

	if (bpf_lwt_push_encap(skb, BPF_LWT_ENCAP_IP, &h, sizeof(h))) {
		BUMP(lwt_cnt, 4);
		return BPF_DROP;
	}
	/* Make the kernel redo FIB/neighbor lookup for the new outer L3 header; note reroute does not write back iph->saddr,
	 * so the outer source address must come from the map (the default route source address is not used). */
	BUMP(lwt_cnt, cf->enc ? 5 : 6);
	return BPF_LWT_REROUTE;
}

char _license[] SEC("license") = "GPL";
