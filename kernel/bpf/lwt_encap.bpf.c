/* 对照路径（不用于生产）：LWT_XMIT 上的 eBPF 出站封装。
 *
 * 存在的意义是**证明 eBPF 出站满足不了冻结的 XOR 语义**，而不是提供一条
 * 可用路径。原因在位置上：
 *
 *   LWT_XMIT 钩子跑在 ip_finish_output2() 里面 —— 软件分片之后（这一点没问题），
 *   但仍在 validate_xmit_skb() 之前。此刻 skb 的 L4 校验和通常还是
 *   CHECKSUM_PARTIAL（"还没算，交给驱动/硬件算"）。于是：
 *     · enc=1（XOR）：XOR 覆盖了校验和字段，之后驱动/软件再算出来的是
 *       "密文的校验和"；对端解出明文后按明文校验 ⇒ 必然 InCsumErrors / 丢包。
 *     · enc=0（不 XOR）：只是加头封装，校验和照旧由后面算 ⇒ 一切正常。
 *   同一个程序只翻一个开关就能通过/失败，于是失败原因被唯一地锁定在 XOR
 *   与"校验和计算时机"的冲突上（内核模块把 XOR 放在 ndo_start_xmit，那时
 *   校验和已经算完，所以没有这个问题）。
 *
 * 配置/计数都放在 map 里，由 kernel/tests/ab_lwt_test.sh 用 bpftool 填。
 */
#include <bpf/bpf_helpers.h>

#define IWAN_HDR_LEN	8
#define PT_DATA		0x14
#define PT_DATA_ENC	0x18
#define MAX_WORDS	192	/* 192*8 = 1536B ≥ 1500 MTU */

/* 与 PROTOCOL.md 冻结格式一致：[外层IP][UDP][type,enc,sid(u16 BE),tok(u32 BE)][载荷] */
struct lwt_cfg {
	__u32 outer_saddr;	/* 网络序 */
	__u32 outer_daddr;	/* 网络序 */
	__u16 sport;		/* 主机序 */
	__u16 dport;		/* 主机序 */
	__u16 sid;
	__u32 tok;
	__u8  key[8];		/* 会话密钥 = MD5(user||pass)[0..8) */
	__u8  enc;		/* 1 = XOR(PT_DATA_ENC)，0 = 明文(PT_DATA) */
	__u8  pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct lwt_cfg);
} lwt_cfg_map SEC(".maps");

/* 计数下标：1=已XOR 2=明文封装 3=无配置 4=push_encap 失败 5=加密发出 6=明文发出 */
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
		return BPF_OK;		/* 没配置就原样放行 */
	}

	if (cf->enc) {
		/* 整包 XOR：字部分常量偏移展开，尾部逐字节（与内核模块、与用户态
		 * xor_crypt() 的 8 字节循环密钥逐字节等价）。
		 * key 按字节 memcpy 取出：map 里的 key 字段不保证 8 字节对齐。 */
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
	h.ip.frag_off = bpf_htons(0x4000);	/* DF=1：外层不再分片 */
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
	/* 让内核按新的外层 L3 头重走 FIB/邻居；注意重路由不会回写 iph->saddr，
	 * 所以外层源地址必须来自 map（默认路由的源地址不会被采用）。 */
	BUMP(lwt_cnt, cf->enc ? 5 : 6);
	return BPF_LWT_REROUTE;
}

char _license[] SEC("license") = "GPL";
