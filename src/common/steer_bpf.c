/* steer_bpf.c — tun steering classifier (TUNSETSTEERINGEBPF).
 * Returns a flow hash for each inner IP packet; the kernel maps it to a
 * queue via ret % numqueues. Replaces the tun driver's automq flow
 * table, whose flow hash degenerates to a per-device constant here
 * (observed: every flood run pinned all flows onto one queue).
 * The tun ioctl requires BPF_PROG_TYPE_SOCKET_FILTER, which forbids
 * direct packet access, so the 4-tuple is read via bpf_skb_load_bytes.
 * Compiled with clang -target bpf and embedded into the binaries.
 */
#define SEC(NAME) __attribute__((section(NAME), used))

#include <linux/bpf.h>
#include <linux/types.h>

static long (*bpf_skb_load_bytes)(void *ctx, __u32 off, void *to,
                                  __u32 size) = (void *)BPF_FUNC_skb_load_bytes;

SEC("classifier")
int steer(struct __sk_buff *skb)
{
    __u8 proto;
    __u32 saddr, daddr, sport, dport;

    if (bpf_skb_load_bytes(skb, 9, &proto, 1))
        return 0;
    if (proto != 17)   /* UDP only: TCP/ICMP -> queue 0 */
        return 0;
    if (bpf_skb_load_bytes(skb, 12, &saddr, 4) ||
        bpf_skb_load_bytes(skb, 16, &daddr, 4) ||
        bpf_skb_load_bytes(skb, 20, &sport, 2) ||
        bpf_skb_load_bytes(skb, 22, &dport, 2))
        return 0;
    return saddr ^ daddr ^ sport ^ dport;
}

char _license[] SEC("license") = "Dual MIT/GPL";
