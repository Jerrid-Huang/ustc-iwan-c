// SPDX-License-Identifier: GPL-2.0
/*
 * iwan_rx.c - RX: decapsulation inside the netfilter hook.
 *
 * Why at PRE_ROUTING (default prio=-300):
 *   The kernel's two reassembly points are at -400 (nf_defrag_ipv4, only enabled by conntrack/nft and the
 *   like) and ip_local_deliver (after LOCAL_IN). Tunnel outer fragments must be made whole **before the port
 *   is looked at** (non-first fragments carry no UDP/iWAN header), so at -300 we call the exported ip_defrag()
 *   once ourselves: non-zero = this fragment was queued -> NF_STOLEN (the skb belongs to reassembly, do
 *   not touch it again); zero = the datagram is complete right now, so decapsulation continues in this
 *   same call. This is the same convention as the kernel's nf_ct_ipv4_gather_frags(), not new semantics.
 *
 * Inner fragments: this module does **not** reassemble the inner layer. Once NF_ACCEPTed, the decapsulated
 *   inner packet naturally reaches ip_local_deliver's ip_defrag (local host) or the next hop (forwarding) --
 *   which is exactly why 'whether the inner layer should be reassembled' can only be answered after routing.
 *
 * Inner version (v4/v6): both are accepted, judged by iwan_inner_hdr_check()
 *   (one copy shared with TX, see iwan_core.c). Two delivery modes:
 *     - inner version == outer version (v4 in v4, the old v1 path): NF_ACCEPT,
 *       the current stack path continues, bit-for-bit unchanged;
 *     - inner version != outer version (v6 in v4): must netif_rx to re-inject; NF_ACCEPT means "keep going
 *       down the outer path", but that path came in by the outer version (a v4 hook -> ip_rcv_finish would
 *       parse the inner header as v4), so a version change necessarily misparses. Re-injection sets the
 *       protocol type per the **inner** version (ETH_P_IPV6) and the transport offset likewise (v6 = 40
 *   + ext hdrs); module param reinject=true re-injects regardless of version (old behavior unchanged).
 *
 * Params (after the genetlink control plane): one iwan_dp_get() snapshot per packet -- session params when
 *   the netns has a netlink session, else module params (bit-for-bit equal to the old implementation).
 * Non-data frames (OPEN/OPEN_ACK/ECHO/PING/CLOSE): not delivered as inner packets, but passed as-is to
 *   user space (IWAN_EV_CTRL_FRAME), see iwan_rx_ctrl(). Event multicast is token-bucket rate limited
 *   per netns (over limit -> IWAN_S_EV_DROPPED); the limit only caps how many events are sent, not
 *   shared-memory accounting or PT_CLOSE semantics -- both of those finish before/outside the bucket.
 *
 * Liveness timestamp (v1 shared-memory page, layout in kernel/iwan_shm.h):
 *   every frame that **passes the credential gate** (data or control) writes the current monotonic
 *   ms into that netns's shared-memory page (/dev/iwan, user-space read-only mmap); PT_CLOSE sets
 *   it to 0. Only two write sites: iwan_decap_one() and iwan_rx_ctrl(), both in softirq context:
 *   plain store only (WRITE_ONCE), no lock, no allocation, and no second time base (iwan_now_ms()).
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/ip.h>
#include <net/ipv6.h>		/* ipv6_ext_hdr / ipv6_optlen / ipv6_authlen */
#include <net/gso.h>
#include <net/netns/generic.h>

#include "iwan.h"
#include "iwan_genl.h"	/* IWAN_CTRL_FRAME_MAX / IWAN_PEER_* */

/*
 * Family-agnostic view of the outer header (slice 2).
 *
 * On the RX path, "demux" happens at only the two outermost spots: the kernel picks ip_rcv / ipv6_rcv
 * by skb->protocol, and the netfilter hook tables are per-family as well (hooks_ipv4/hooks_ipv6).
 * We do not take the pre-demux position (netdev_rx_handler / NF_NETDEV_INGRESS hook **per NIC**,
 * while the "bind nothing" mode requires any carrier NIC to receive and lets FIB self-heal a
 * NIC swap at runtime -- per-NIC hooking would cut that semantics away). Instead: one hook per
 * family, shared hook body; the family appears only once, in "how to find the UDP header / how to
 * compare addresses"; after that the port check, decapsulation and delivery are one single path.
 *
 * src/dst point at the address fields inside the skb (v4 4 bytes / v6 16 bytes); match compares them per family.
 */
struct iwan_outer_view {
	const void	*src;
	const void	*dst;
	unsigned int	l3;	/* UDP header offset (includes the IP header and extension headers) */
	bool		v6;
	bool		frag;	/* outer fragment */
};

/* Outer v4 parse: the criterion is bit-for-bit as in slice 1 and before */
static bool iwan_outer_parse4(struct sk_buff *skb, struct iwan_outer_view *o)
{
	const struct iphdr *iph;

	if (skb->protocol != htons(ETH_P_IP))
		return false;
	if (!pskb_may_pull(skb, sizeof(*iph)))
		return false;
	iph = ip_hdr(skb);
	if (iph->version != 4 || iph->ihl < 5 || iph->protocol != IPPROTO_UDP)
		return false;
	o->src = &iph->saddr;
	o->dst = &iph->daddr;
	o->l3 = iph->ihl * 4;
	o->v6 = false;
	o->frag = ip_is_fragment(iph);
	return true;
}

/*
 * Outer v6 parse. Two structural differences from v4:
 *   - the base header is a fixed 40B, so the transport offset can only come from walking the extension header chain (v4 uses ihl);
 *   - of a fragmented packet only the first fragment carries a UDP header; non-first fragments do not even show the port.
 *
 * Fragment policy: **any v6 outer packet carrying a fragment header is never treated as complete**. In this
 * design outer v6 never fragments (v6 has no DF bit; source-side fragmentation only earns a peer rejection, see
 * iwan_tx.c), and sessions whose inner MTU + IWAN_OVERHEAD_V6 does not fit the carrier NIC MTU were already
 * rejected at the control plane with -EMSGSIZE. So a fragment means "the peer config differs from ours": count it
 * (rx_frag6), then hand it to the stack under its own rules (NF_ACCEPT: do not swallow, do not fake completeness).
 * First fragments are refused too: their UDP header is present but the payload is truncated, and the RX inner
 * criterion is lenient, so it would decapsulate a truncated inner header as a valid packet and deliver it.
 */
static bool iwan_outer_parse6(struct sk_buff *skb, struct iwan_outer_view *o)
{
	const struct ipv6hdr *iph;
	unsigned int off;
	u8 nexthdr;

	if (skb->protocol != htons(ETH_P_IPV6))
		return false;
	if (!pskb_may_pull(skb, sizeof(*iph)))
		return false;
	iph = ipv6_hdr(skb);
	if (iph->version != 6)
		return false;
	o->src = &iph->saddr;
	o->dst = &iph->daddr;
	o->v6 = true;
	o->frag = false;
	o->l3 = 0;

	off = sizeof(*iph);
	nexthdr = iph->nexthdr;
	while (ipv6_ext_hdr(nexthdr)) {
		const struct ipv6_opt_hdr *hp;
		unsigned int hlen;

		if (nexthdr == NEXTHDR_FRAGMENT) {
			o->frag = true;
			return true;	/* fragment: the caller applies the policy */
		}
		if (nexthdr == NEXTHDR_NONE)
			return false;
		if (!pskb_may_pull(skb, off + sizeof(*hp)))
			return false;
		hp = (const struct ipv6_opt_hdr *)(skb->data + off);
		/* AH length field semantics differ from other extension headers ((len+2)*4 rather than (len+1)*8) */
		hlen = nexthdr == NEXTHDR_AUTH ? ipv6_authlen(hp) :
						 ipv6_optlen(hp);
		nexthdr = hp->nexthdr;
		off += hlen;
		if (off > skb->len)
			return false;
	}
	if (nexthdr != IPPROTO_UDP)
		return false;
	o->l3 = off;
	return true;
}

static bool iwan_outer_parse(struct sk_buff *skb, struct iwan_outer_view *o)
{
	return skb->protocol == htons(ETH_P_IPV6) ? iwan_outer_parse6(skb, o) :
						    iwan_outer_parse4(skb, o);
}

/* Outer address match (any_dir allows the reverse direction, used for peer/local two-way verification). Compared per family: a v4 session
 * accepts only v4 packets, a v6 session only v6 packets -- without this restriction a v4 packet's 4-byte source address
 * could "equal" the first 4 bytes of some v6 session address (the compared lengths differ anyway, so the family must
 * separate them first). */
static bool iwan_outer_match(const struct iwan_dp *dp,
			     const struct iwan_outer_view *o)
{
	if (dp->outer_v6 != o->v6)
		return false;
	if (o->v6) {
		const struct in6_addr *s = o->src, *d = o->dst;

		if (ipv6_addr_any(&dp->outer_src6) ||
		    ipv6_addr_any(&dp->outer_dst6))
			return false;
		if (ipv6_addr_equal(s, &dp->outer_src6) &&
		    ipv6_addr_equal(d, &dp->outer_dst6))
			return true;
		if (dp->any_dir &&
		    ipv6_addr_equal(s, &dp->outer_dst6) &&
		    ipv6_addr_equal(d, &dp->outer_src6))
			return true;
		return false;
	}
	{
		const struct iphdr *iph = container_of(o->src, struct iphdr,
						       saddr);

		if (!dp->outer_src || !dp->outer_dst)
			return false;
		if (iph->saddr == dp->outer_src &&
		    iph->daddr == dp->outer_dst)
			return true;
		if (dp->any_dir && iph->saddr == dp->outer_dst &&
		    iph->daddr == dp->outer_src)
			return true;
		return false;
	}
}

enum iwan_frame_kind {
	IWAN_FRAME_BAD  = -1,
	IWAN_FRAME_DATA = 0,	/* inner IPv4 packet, handed to the stack after decapsulation */
	IWAN_FRAME_CTRL = 1,	/* non-data frame, forwarded to user space */
};

/*
 * Kernel-side credential rules for control frames (aligned with the on-wire semantics in src/common/protocol.h):
 *
 *   - PT_PING_REQ/RSP: keepalive uses the **protocol-fixed credentials** 0xFFFF/0xFFFFFFFF, not
 *     session credentials -- gating on session sid/tok would never report it; session credentials
 *     are accepted here as well, tolerating implementations that ping with session credentials.
 *   - PT_ECHO_REQ/RES, PT_CLOSE: carry the session sid/tok (user space sends it that way).
 *   - PT_OPEN/PT_OPEN_ACK/PT_OPEN_REJECT: handshake frames. OPEN_ACK carries the server's
 *     **newly allocated** sid/tok, which the receiving kernel cannot know in advance;
 *     OPEN/OPEN_REJECT use 0/0. So these frames can only be credential-checked in user
 *     space (the HMAC signature over IWAN_CTRL_LEN=24, verify_sig), which is exactly why
 *     CONTROL-PLANE.md section 4 requires the kernel to forward non-data frames as-is.
 *
 * All three cases still require the outer 4-tuple + dport to match (already done in the hook), which squeezes the
 * injection surface down to "can forge the peer's outer address and tunnel port"; this also matches the intent
 * of "report only when sid/tok match": every frame type whose session credentials can be checked is checked.
 */
static bool iwan_ctrl_cred_ok(const struct iwan_dp *dp, u8 type, u16 sid, u32 tok)
{
	switch (type) {
	case PT_PING_REQ:
	case PT_PING_RSP:
		return (sid == IWAN_PING_SID && tok == IWAN_PING_TOK) ||
		       (sid == dp->sid && tok == dp->tok);
	case PT_OPEN:
	case PT_OPEN_ACK:
	case PT_OPEN_REJECT:
		return true;
	default:		/* PT_ECHO_REQ/PT_ECHO_RES/PT_CLOSE */
		return sid == dp->sid && tok == dp->tok;
	}
}

/*
 * Frame header check: type + credentials. sid/tok are placed before decryption (a forged frame never
 * even gets XORed), same rule as the old implementation: a data frame's type must match the enc mode.
 *
 * Control frames count as "forwardable" only when a **netlink session is established**: with no session
 * they reach IWAN_FRAME_BAD exactly as before (rx_bad_hdr++ then drop) -- this is the guarantee point for
 * "with no session the behavior is bit-for-bit identical to before the control plane was introduced".
 */
static enum iwan_frame_kind iwan_frame_check(const struct iwan_dp *dp, const u8 *h)
{
	u16 sid = ((u16)h[2] << 8) | h[3];
	u32 tok = ((u32)h[4] << 24) | ((u32)h[5] << 16) |
		  ((u32)h[6] << 8) | h[7];

	switch (h[0]) {
	case PT_DATA:
		if (dp->enc)
			return IWAN_FRAME_BAD;
		break;
	case PT_DATA_ENC:
		if (!dp->enc)
			return IWAN_FRAME_BAD;
		break;
	case PT_OPEN_REJECT:
	case PT_OPEN_ACK:
	case PT_OPEN:
	case PT_ECHO_REQ:
	case PT_ECHO_RES:
	case PT_CLOSE:
	case PT_PING_REQ:
	case PT_PING_RSP:
		if (!dp->session)
			return IWAN_FRAME_BAD;
		return iwan_ctrl_cred_ok(dp, h[0], sid, tok) ?
			IWAN_FRAME_CTRL : IWAN_FRAME_BAD;
	default:
		return IWAN_FRAME_BAD;
	}
	return sid == dp->sid && tok == dp->tok ? IWAN_FRAME_DATA : IWAN_FRAME_BAD;
}

/*
 * Control frame demux: count, update peer state, emit the per-type semantic event, pass the frame through as-is to user space.
 *
 * A separate noinline function: the 512B frame buffer only spends stack on this one
 * cold path, not on the hot path every packet takes (data frames never call it).
 */
static noinline void iwan_rx_ctrl(struct iwan_net *pn, struct sk_buff *skb,
				  unsigned int off, unsigned int len, u8 type,
				  const struct iphdr *iph,
				  const struct udphdr *uh)
{
	struct iwan_outer_tuple t = {
		.src	= iph->saddr,
		.dst	= iph->daddr,
		.sport	= uh->source,
		.dport	= uh->dest,
	};
	u8 buf[IWAN_CTRL_FRAME_MAX];
	const u8 *frame;
	u16 sid = READ_ONCE(pn->sess.sid);
	u64 ts;
	bool delivered;

	atomic64_inc(&pn->st.rx_ctrl_frame);
	iwan_shm_note_ctrl_frame(pn);	/* counter mirror in the shared-memory page (plain store) */

	/* Over the cap: truncate and log (ABI cap: IWAN_CTRL_FRAME_MAX) */
	if (len > (unsigned int)IWAN_CTRL_FRAME_MAX) {
		pr_info_ratelimited("iwan: control frame %u bytes over the limit %d, truncated and forwarded\n",
				    len, IWAN_CTRL_FRAME_MAX);
		len = IWAN_CTRL_FRAME_MAX;
	}
	frame = skb_header_pointer(skb, off, (int)len, buf);
	if (!frame)
		return;		/* already counted in rx_ctrl_frame, no delivery, no further report */

	/*
	 * The raw frame is forwarded first (user space verifies/parses it itself), then the semantic events follow.
	 *
	 * delivered == false only means the **event multicast** was dropped by the token-bucket limiter (see
	 * iwan_ev_ctrl_frame); the shared-memory side effects are unaffected: before entering the bucket
	 * iwan_decap_one() already wrote last_rx_ms/peer_state, and the PT_CLOSE semantics below still run.
	 * Otherwise an attacker could empty the bucket with a flood and turn a real peer's PT_CLOSE into
	 * "invisible to user space, timestamp still non-zero" -- that would switch dead-link detection off.
	 * Rate limiting should only cap "how many events are sent", never change "what the data plane saw".
	 */
	delivered = iwan_ev_ctrl_frame(pn, sid, &t, frame, len);

	if (type == PT_PING_REQ || type == PT_PING_RSP) {
		/* keepalive timestamp was already written into shared memory by the generic path of iwan_decap_one()
		 * (every frame passing the credential gate writes it; PING is not special); only the semantic
		 * event is emitted here, and its payload still uses the same current time base, iwan_now_ms(). */
		ts = iwan_now_ms();
		if (delivered)
			iwan_ev_keepalive(pn, ts);
	} else if (type == PT_CLOSE) {
		/* PT_CLOSE: set the shared-memory page timestamp to 0 (user space sees 0
		 * and declares the link down), and drop peer_state to IWAN_PEER_CLOSED.
		 * Neither depends on rate limiting; both must happen unconditionally. */
		iwan_shm_note_close(pn);
		if (delivered)
			iwan_ev_peer_close(pn, sid);
	}
}

/*
 * Decapsulate an already complete outer datagram into a plaintext inner packet. Returns 0 = plaintext
 * inner packet ready (skb stripped / decrypted); 1 = control frame (already forwarded to user space,
 * skb left as-is, the caller decides to drop); <0 = drop (the counter was already bumped inside).
 *
 * Branch point: after outer reassembly -> 4-tuple -> dport -> frame header type/credentials
 * (iwan_frame_check), i.e. the split happens only **after exactly the same pre-checks as data frames**.
 */
static int iwan_decap_one(struct iwan_net *pn, struct sk_buff *skb,
			  const struct iwan_dp *dp, unsigned int l3)
{
	struct udphdr *uh;
	u8 hdrbuf[IWAN_HDR_LEN];
	const u8 *fh;
	enum iwan_frame_kind kind;
	unsigned int ulen, need;

	/* the outer IP+UDP header must be pulled into the linear area before dereferencing it directly. The skb handed
	 * over by the UDP large-datagram TX path (ip_generic_getfrag -> page frags) may hold only those 28 bytes of
	 * IP+UDP header linearly: once an outer datagram exceeds ~16KB the payload is almost entirely in frags. */
	if (unlikely(!pskb_may_pull(skb, l3 + sizeof(*uh)))) {
		atomic64_inc(&pn->st.rx_nomem);
		return -ENOMEM;
	}
	uh = (struct udphdr *)((u8 *)ip_hdr(skb) + l3);
	ulen = ntohs(uh->len);
	if (ulen < sizeof(*uh) + IWAN_HDR_LEN) {
		atomic64_inc(&pn->st.rx_bad_hdr);
		return -EINVAL;
	}
	need = l3 + sizeof(*uh) + IWAN_HDR_LEN;
	if (skb->len < need) {
		atomic64_inc(&pn->st.rx_bad_hdr);
		return -EINVAL;
	}
	fh = skb_header_pointer(skb, l3 + sizeof(*uh), IWAN_HDR_LEN, hdrbuf);
	if (!fh) {
		atomic64_inc(&pn->st.rx_bad_hdr);
		return -EINVAL;
	}
	kind = iwan_frame_check(dp, fh);
	if (kind == IWAN_FRAME_BAD) {
		atomic64_inc(&pn->st.rx_bad_hdr);
		return -EINVAL;
	}

	/* passed the credential gate => the peer is alive: write the current monotonic ms into
	 * the shared-memory page (data frames and control frames alike). PT_CLOSE overwrites it
	 * with 0 in iwan_rx_ctrl(). Softirq context: plain store only, no lock, no allocation. */
	iwan_shm_note_frame(pn);

	/* valid frame => peer alive (IWAN_PEER_UP = a valid frame was received);
	 * PT_CLOSE overwrites it with IWAN_PEER_CLOSED in iwan_rx_ctrl(). */
	if (dp->session && iwan_shm_peer_state(pn) != IWAN_PEER_CLOSED)
		iwan_shm_set_peer_state(pn, IWAN_PEER_UP);

	if (kind == IWAN_FRAME_CTRL) {
		/* UDP payload = raw frame bytes after the outer IP/UDP header (8B frame
		 * header + payload). Length taken from the UDP header len, with the real skb length as fallback. */
		unsigned int flen = ulen - sizeof(*uh);
		unsigned int avail = skb->len - l3 - sizeof(*uh);

		if (flen > avail)
			flen = avail;
		iwan_rx_ctrl(pn, skb, l3 + sizeof(*uh), flen, fh[0],
			     ip_hdr(skb), uh);
		return 1;
	}

	atomic64_inc(&pn->st.rx_frames);
	iwan_shm_note_data_frame(pn);	/* counter mirror in the shared-memory page */

	/* strip the outer IPv4 + UDP + iWAN frame header -- all need bytes must first be guaranteed
	 * in the linear area: for a large outer datagram (inner > ~16KB => outer > ~16KB) the
	 * payload is in page frags and the linear area may hold fewer than need bytes, so a direct
	 * skb_pull trips __skb_pull's BUG_ON(skb->len < skb->data_len). Crash-lab trace 2026-10-08:
	 * skb_pull+0x40 <- iwan_decap_one <- iwan_rx_hook (softirq panic); inner 20000B + s2c
	 * (large outer packet relayed by the server) always blew up under test; a 1200B probe and
	 * 9000B (outer 9036, still within linear allocation) did not, hence the earlier escape. */
	if (unlikely(!pskb_may_pull(skb, need))) {
		atomic64_inc(&pn->st.rx_nomem);
		return -ENOMEM;
	}
	skb_pull(skb, need);
	skb_reset_network_header(skb);

	/* Decrypt: XOR the whole inner IP packet (inner IP header included) back with the session key */
	if (dp->enc) {
		if (iwan_xor_skb(skb, dp->key)) {
			atomic64_inc(&pn->st.rx_nomem);
			return -ENOMEM;
		}
	}

	/* plaintext inner header check (one criterion shared by v4/v6; RX keeps the existing lenient length rule: reject only
	 * when the length declared by the inner header does not cover the whole frame, extra trailing bytes are accepted).
	 * The transport offset is computed per version -- v6 is 40 + extension headers, the v4 ihl cannot be reused. */
	{
		u32 nhlen;

		if (iwan_inner_hdr_check(skb, false, &nhlen)) {
			atomic64_inc(&pn->st.rx_bad_inner);
			return -EINVAL;
		}
		/* inner_src allowlist is a **module parameter** (the ABI has no session-level counterpart) typed
		 * __be32, so it can only express an inner v4 source address: it applies to v4 only. Inner v6 gets no
		 * equivalent filter -- silently dropping v6 would be another black hole, and the v6 admission filter
		 * (derived ULA: the destination must be this session's ULA, the source must not be) is implemented
		 * in the user-space TUN side; the kernel side does not replicate that policy for now (this module
		 * is the data plane; replicating it would first need an inner address item in the ABI). */
		if (skb->data[0] >> 4 == 4 && dp->inner_src) {
			const struct iphdr *iph = ip_hdr(skb);

			if (iph->saddr != dp->inner_src) {
				atomic64_inc(&pn->st.rx_bad_inner);
				return -EINVAL;
			}
		}
		skb_set_transport_header(skb, nhlen);
	}
	/* the wire carries a ciphertext checksum; XOR already restored it to the plaintext checksum -> let the kernel verify it as plaintext */
	skb->ip_summed = CHECKSUM_NONE;
	/* the outer dst is not set yet in this hook anyway, but guard against upstream leftovers */
	skb_dst_drop(skb);
	return 0;
}

/* LOCAL_IN fallback: after decapsulation send back to ip_rcv, i.e. back to before ip_defrag */
static unsigned int iwan_reinject(struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	/* the inner header was already checked by iwan_decap_one, skb->data is the inner IP header */
	u8 ver = skb->data[0] >> 4;

	skb->dev = state->in;
	/* the protocol type must follow the **inner** version: netif_rx selects the
	 * protocol handler with it, and a wrong choice (a v6 packet tagged ETH_P_IP) is dropped by ip_rcv on version mismatch. */
	skb->protocol = htons(ver == 6 ? ETH_P_IPV6 : ETH_P_IP);
	skb->pkt_type = PACKET_HOST;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	/* the transport offset was already set per version in iwan_decap_one (v4 = ihl*4;
	 * v6 = 40 + extension headers), so do not overwrite it from the v4 ihl here. */
	/*
	 * netif_rx() takes over the skb unconditionally: on success it enters the backlog, on
	 * congestion/stack drop it returns NET_RX_DROP and **has already freed it itself**. Ownership
	 * has moved in both branches, so we may only return NF_STOLEN -- returning NF_DROP would
	 * make nf_hook_slow() free the same skb once more (double free). netfilter.h states the rule
	 * literally: a hook that already kfree_skb'd must return NF_STOLEN and own the consequences.
	 */
	netif_rx(skb);
	return NF_STOLEN;
}

static unsigned int iwan_rx_single(struct iwan_net *pn, struct sk_buff *skb,
				   const struct iwan_cfg *c,
				   const struct iwan_dp *dp, unsigned int l3,
				   const struct nf_hook_state *state)
{
	int ret = iwan_decap_one(pn, skb, dp, l3);

	if (ret < 0) {
		/* 4-tuple + port both matched yet the frame check failed: forged or corrupt, drop */
		return NF_DROP;
	}
	if (ret > 0) {
		/* control frame: already forwarded to user space, never deliver it as an inner
		 * packet. NF_DROP makes the framework free the skb (we do not own it). */
		return NF_DROP;
	}
	atomic64_inc(&pn->st.rx_delivered);
	/* delivery mode: module param reinject=true always sends the packet back to the stack via netif_rx; there
	 * is also one case that **must** re-inject -- inner version != outer version (v6 in v4, supported from this
	 * slice on). NF_ACCEPT means "let the current stack path continue", and that path came in by the outer
	 * version (v4 hook -> ip_rcv_finish parses the inner header as v4, so the addresses/lengths it reads are all
	 * wrong); any version change necessarily misparses, so the skb must be re-injected and let skb->protocol
	 * pick the handler again. Same version keeps the old behavior (NF_ACCEPT), bit-for-bit unchanged. */
	if (READ_ONCE(c->reinject) ||
	    (skb->data[0] >> 4) != (state->pf == NFPROTO_IPV6 ? 6 : 4))
		return iwan_reinject(skb, state);
	return NF_ACCEPT;
}

/*
 * GSO batching: the reference client uses UDP_SEGMENT to send N equal-length frames as a run of UDP datagrams, and
 * GRO on the receiving side may merge them into a single skb (outer header + N equal-length payloads). The protocol
 * document mandates "equal-length frames" precisely so the receiver can do this: split back into single datagrams by
 * gso_size, strip/decrypt each one separately (XOR restarts at offset 0 per frame), and re-inject each into the stack.
 * Splitting consumes the original skb, and a netfilter hook cannot replace the skb pointer it holds => NF_STOLEN, and
 * we hand the decapsulated inner packets to netif_receive_skb ourselves (back to before ip_rcv). Coalesced packets with
 * mixed control frames: control frames are reported as usual (iwan_decap_one returns 1), they are just not delivered.
 */
static unsigned int iwan_rx_batch(struct iwan_net *pn, struct sk_buff *skb,
				  const struct iwan_cfg *c,
				  const struct iwan_dp *dp,
				  const struct nf_hook_state *state)
{
	struct net_device *indev = state->in;
	struct sk_buff *segs, *seg;

	atomic64_inc(&pn->st.rx_batch);
	if (!READ_ONCE(c->batch))
		return NF_ACCEPT;
	if (unlikely(skb_cloned(skb) || skb_shared(skb))) {
		atomic64_inc(&pn->st.rx_batch_skip);
		return NF_ACCEPT;
	}
	segs = skb_gso_segment(skb, 0);	/* features=0: the checksum of each segment is computed in software */
	if (IS_ERR(segs)) {
		/*
		 * skb_gso_segment() does **not consume** the original skb on IS_ERR (upstream fixed ownership
		 * specifically so the original skb still belongs to the caller), so free it here ourselves; and since
		 * we already freed it we must return NF_STOLEN: NF_DROP would make the framework free it a second time.
		 */
		kfree_skb(skb);
		atomic64_inc(&pn->st.rx_bad_hdr);
		return NF_STOLEN;
	}
	if (!segs)
		return NF_ACCEPT;	/* no real segmentation happened, the original skb is still valid */
	consume_skb(skb);

	while ((seg = segs) != NULL) {
		struct iwan_outer_view so;
		unsigned int l3;
		int ret;

		segs = seg->next;
		seg->next = NULL;
		seg->prev = NULL;
		/* a segment's outer header is the same family and shape as the ingress skb (GSO only cuts the
		 * payload; each segment carries its own IP+UDP header), so reuse the family-aware parse of
		 * the single path to get the UDP header offset instead of writing a second v4/v6 decision. */
		if (!iwan_outer_parse(seg, &so) || so.frag)
			goto drop;
		l3 = so.l3;
		/* symmetric with the single path: iwan_decap_one() reads uh->len, so pull the UDP header
		 * into the linear area first. Do not build the contract on the implementation detail
		 * that "the segmenter guarantees every segment has the IP+UDP headers linear". */
		if (!pskb_may_pull(seg, l3 + sizeof(struct udphdr)))
			goto drop;
		ret = iwan_decap_one(pn, seg, dp, l3);
		if (ret)
			goto drop;	/* <0 bad frame; >0 control frame already reported, not delivered */
		atomic64_inc(&pn->st.rx_delivered);
		seg->dev = indev;
		/* pick the protocol by the **inner** version (the batch path always
		 * re-injects through netif_receive_skb): inner v6 tagged ETH_P_IP is dropped by ip_rcv on version mismatch. */
		seg->protocol = htons((seg->data[0] >> 4) == 6 ? ETH_P_IPV6
							       : ETH_P_IP);
		seg->pkt_type = PACKET_HOST;
		skb_reset_mac_header(seg);
		netif_receive_skb(seg);
		continue;
drop:
		kfree_skb(seg);
	}
	return NF_STOLEN;
}

static unsigned int iwan_rx_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct iwan_net *pn = iwan_net_of(state->net);
	struct iwan_cfg *c = iwan_cfg_get();
	struct iwan_dp dp;
	struct iwan_outer_view o;
	struct udphdr *uh;
	u16 lport;

	(void)priv;
	/* diagnostic pass-through: the hook lets the packet go (NF_ACCEPT) as soon as it sees it, no parsing, no decapsulation.
	 * The only difference from the normal path is "entering the hook" itself. */
	if (unlikely(READ_ONCE(c->pass_through) & IWAN_PASS_RX))
		return NF_ACCEPT;
	/* session first, module params as fallback: with no session every field of dp
	 * equals what the old implementation read straight from cfg/pn (including the cfg.enabled && pn->enabled gate). */
	iwan_dp_get(pn, c, false, &dp);
	if (!dp.enabled)
		return NF_ACCEPT;
	/* carrier NIC restriction: one session accepts only one downstream NIC. An explicit binding (dp.oif) wins,
	 * otherwise the already pinned one is used (pn->carrier; 0 = not resolved yet, no restriction then, behavior
	 * identical to before binding was introduced). Locally generated paths with state->in == NULL (hooks
	 * configured at OUTPUT/POST_ROUTING) are not restricted. This layer also tightens the forgery surface:
	 * the outer 4-tuple is forgeable, so without an interface restriction a forged packet on any interface
	 * could enter decapsulation (the credential gate runs later). The cost is one ifindex comparison. */
	if (dp.oif || READ_ONCE(pn->carrier)) {
		u32 want = dp.oif ? dp.oif : READ_ONCE(pn->carrier);

		if (state->in && state->in->ifindex != want)
			return NF_ACCEPT;
	}
	if (!iwan_outer_parse(skb, &o))
		return NF_ACCEPT;
	/* counter semantics (both families combined): rx_pkts = well-formed UDP
	 * outer packets that passed this hook (addresses not yet compared); rx_outer = those whose outer address belongs to this session. */
	atomic64_inc(&pn->st.rx_pkts);
	if (!iwan_outer_match(&dp, &o))
		return NF_ACCEPT;
	atomic64_inc(&pn->st.rx_outer);

	/* 1) outer fragment */
	if (o.frag) {
		if (o.v6) {
			/* outer v6 does not fragment (see iwan_outer_parse6): do not swallow it, do not
			 * treat it as a complete packet; count it and hand it back to the stack. */
			atomic64_inc(&pn->st.rx_frag6);
			pr_info_ratelimited("iwan: outer v6 fragment: outer v6 never fragments here (MTU checked at session setup); not decapsulated by this tunnel\n");
			return NF_ACCEPT;
		}
		/* v4: reassembly is needed only at PRE_ROUTING (at LOCAL_IN the kernel already did it) */
		if (READ_ONCE(c->hooknum) != IWAN_HOOK_PRE_ROUTING)
			return NF_ACCEPT;
		{
			int ret;

			local_bh_disable();
			ret = ip_defrag(state->net, skb, IP_DEFRAG_LOCAL_DELIVER);
			local_bh_enable();
			if (ret) {
				/* queued (or dropped on overflow): the skb was consumed by reassembly */
				atomic64_inc(&pn->st.rx_reasm);
				return NF_STOLEN;
			}
		}
		/* returns 0: the datagram is complete right now, keep decapsulating in this call */
		atomic64_inc(&pn->st.rx_reasm);
		if (!iwan_outer_parse(skb, &o) || o.frag)
			return NF_ACCEPT;
		if (!iwan_outer_match(&dp, &o))
			return NF_ACCEPT;
	}

	/*
	 * 2) ports are only visible on a complete datagram, so this comes after reassembly.
	 *
	 * the local receive port = SPORT when given explicitly; otherwise DPORT is kept, i.e. the old "same port
	 * on both ends" rule, bit-for-bit as before SPORT existed. This distinction is mandatory: TX uses SPORT
	 * as the **source** port, while a real client's local port is ephemeral and differs from the peer's DPORT
	 * -- with DPORT only, a real client's inbound packets would never match and the kernel data plane would
	 * be dead (the earlier tests that used the same port on both ends had exactly hidden this). Deliberately
	 * not written as "accept both ports": that would also swallow packets sent to the peer's port.
	 */
	if (!pskb_may_pull(skb, o.l3 + sizeof(*uh)))
		return NF_ACCEPT;
	uh = (struct udphdr *)(skb_network_header(skb) + o.l3);
	lport = dp.sport ? dp.sport : dp.dport;
	if (uh->dest != htons(lport)) {
		/* the session/params keep host byte order, the packet is network byte order: convert before comparing. A
		 * destination port mismatch also means "the encapsulation header is not ours", so it counts into rx_bad_hdr:
		 * this path used to return silently, leaving nothing visible in the counters when something broke. The
		 * ratelimited print shows the actual values: a port mismatch can only be located by comparing the numbers. */
		pr_info_ratelimited("iwan: destination port mismatch: got %u expected %u\n",
				    ntohs(uh->dest), lport);
		atomic64_inc(&pn->st.rx_bad_hdr);
		return NF_ACCEPT;
	}

	/* 3) per-frame decapsulation (GSO-coalesced packets take the batch path);
	 *    data frames and control frames split inside iwan_decap_one() after the credential check */
	if (skb_is_gso(skb) && skb_shinfo(skb)->gso_size)
		return iwan_rx_batch(pn, skb, c, &dp, state);
	return iwan_rx_single(pn, skb, c, &dp, o.l3, state);
}

int iwan_rx_net_init(struct iwan_net *pn)
{
	struct iwan_cfg *c = iwan_cfg_get();
	int err;

	/* one hook per family, both pointing at the same hook function. netfilter's hook tables are
	 * themselves per-family (nf_hooks_ipv4 / nf_hooks_ipv6) and there is no "family-agnostic
	 * hook" available; hooking per NIC (netdev_rx_handler / NF_NETDEV_INGRESS) would break the
	 * semantics that with "bind nothing" any carrier NIC can receive and the carrier NIC can
	 * self-heal to another card, so we take the "one hook per family + shared hook body" road. */
	pn->rx_ops4.hook = iwan_rx_hook;
	pn->rx_ops4.pf = NFPROTO_IPV4;
	pn->rx_ops6.hook = iwan_rx_hook;
	pn->rx_ops6.pf = NFPROTO_IPV6;
	for (int i = 0; i < 2; i++) {
		struct nf_hook_ops *ops = i ? &pn->rx_ops6 : &pn->rx_ops4;

		ops->hooknum = READ_ONCE(c->hooknum) == IWAN_HOOK_LOCAL_IN ?
			       NF_INET_LOCAL_IN : NF_INET_PRE_ROUTING;
		ops->priority = READ_ONCE(c->hookprio);
		err = nf_register_net_hook(pn->net, ops);
		if (err) {
			pr_err("netns %u: nf_register_net_hook(%s) failed %d\n",
			       pn->net->ns.inum, i ? "v6" : "v4", err);
			if (i)
				nf_unregister_net_hook(pn->net, &pn->rx_ops4);
			return err;
		}
	}
	/* WRITE_ONCE pairs with SESSION_UP's READ_ONCE(pn->rx_hooked): this flag is
	 * the only basis for the 'hook gate' (netns creation and SESSION_UP may run on different CPUs). */
	WRITE_ONCE(pn->rx_hooked, true);
	return 0;
}

void iwan_rx_net_exit(struct iwan_net *pn)
{
	if (pn->rx_hooked) {
		nf_unregister_net_hook(pn->net, &pn->rx_ops4);
		nf_unregister_net_hook(pn->net, &pn->rx_ops6);
		WRITE_ONCE(pn->rx_hooked, false);
		/*
		 * after removing the hook we must wait one more RCU grace period before we may
		 * consider that "no hook is in flight": nf_unregister_net_hook() only unlinks the hook
		 * from the array and hands the old array to call_rcu() for freeing, while a traversal
		 * that has **already started** (NF_HOOK runs entirely under rcu_read_lock()) may still
		 * call this hook, and this hook writes that netns's shared-memory page. The caller is
		 * about to drop the pernet reference to the page (iwan_net_exit -> iwan_shm_net_exit):
		 * without this barrier it is a "hook still running, page already recycled"
		 * use-after-free. pernet exit is process context, so synchronize_rcu() may sleep.
		 */
		synchronize_rcu();
	}
}
