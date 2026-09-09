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
    __u8 byte0, proto;
    __u32 saddr, daddr, sport, dport;

    /* Version gate: only IPv4 flows are steered. Parsing the 4-tuple at
     * IPv4 offsets (12/16/20/22) on IPv6 packets would hash them all to
     * ~one queue — the exact degeneration this classifier replaces for
     * our fd00::/96-derived ULA traffic. Non-IPv4 (IPv6 etc.) returns 0
     * and lets the kernel distribute normally; we never drop data, only
     * (mis)balance. */
    if (bpf_skb_load_bytes(skb, 0, &byte0, 1))
        return 0;
    if ((byte0 >> 4) != 4)
        return 0;

    if (bpf_skb_load_bytes(skb, 9, &proto, 1))
        return 0;
    /* TCP/UDP carry the 4-tuple at a fixed offset; ICMP/other go to
     * queue 0. The offset assumes an optionless IPv4 header (IHL=5):
     * true for tun-device traffic (the kernel emits and accepts
     * optionless headers there), and a wrong queue choice on exotic
     * input only misbalances the reader pool — it never drops data.
     * Hash TCP too: the pool's whole point is spreading the dominant
     * inner-TCP load, not just the DNS/QUIC UDP fraction. */
    if (proto != 6 && proto != 17)
        return 0;
    if (bpf_skb_load_bytes(skb, 12, &saddr, 4) ||
        bpf_skb_load_bytes(skb, 16, &daddr, 4) ||
        bpf_skb_load_bytes(skb, 20, &sport, 2) ||
        bpf_skb_load_bytes(skb, 22, &dport, 2))
        return 0;
    /* Mask to 16 bits: the kernel treats a SOCKET_FILTER return as the
     * number of bytes to keep and caps it at 0..0xffff on older kernels,
     * so an unmasked 32-bit hash could be misread as "drop everything".
     * Truncating costs no distribution quality (we only use it via
     * ret % numqueues). */
    return (saddr ^ daddr ^ sport ^ dport) & 0xffff;
}

char _license[] SEC("license") = "Dual MIT/GPL";
