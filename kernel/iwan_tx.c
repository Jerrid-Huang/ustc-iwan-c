// SPDX-License-Identifier: GPL-2.0
/*
 * iwan_tx.c -- egress: kernel virtual NIC + encapsulation in ndo_start_xmit.
 *
 * Why the kernel TX path is required (instead of eBPF on LWT/tc/XDP):
 *   XOR covers **every byte** of the inner IP packet, incl. the TCP/UDP checksum.
 *   On TX the checksum is deferred (CHECKSUM_PARTIAL, driver/hw computes it last)
 *   and GSO super-packets are segmented last. Any eBPF hook (LWT_XMIT / tc egress
 *   / XDP) runs before that point, so a packet XORed there necessarily reaches
 *   the peer with a bad checksum (not even the SYN passes). The reference impl
 *   works because its user-space daemon reads already-checksummed packets from TUN.
 *
 * This device's features declare only SG (scatter-gather); checksum offload and
 * TSO are left unset, so validate_xmit_skb will:
 *   1) segment by GSO (ip_finish_output_gso also pre-splits by route MTU);
 *   2) compute the L4 checksum in software when the device lacks hw checksum
 *      (skb_checksum_help, iterating page frames, linearity not required);
 *   3) no longer force linearization -- paged payload reaches ndo_start_xmit
 *      as-is; iwan_xor_paged() transforms linear area and page frames in place,
 *      segment by segment. By ndo_start_xmit we therefore have "one complete IP
 *      packet + checksum ready", the only safe point for XOR; fragmentation is
 *      already done by the stack => the frozen "per-fragment XOR" holds.
 *
 * Inner version: both v4 and v6 are encapsulated (criterion is iwan_inner_hdr_check(),
 * shared with RX, see iwan_core.c). XOR covers all bytes from skb->data, any version.
 *
 * Outer version (slice 2): v4 and v6 both, family chosen by the session
 *   (iwan_dp.outer_v6). Shared up to the UDP header; only three forks: transport
 *   checksum helper (udp_set_csum / udp6_set_csum), outer IP header (20B/40B),
 *   sending stack entry (ip_local_out / ip6_local_out). Outer v6 **never
 *   fragments**: no DF bit in v6, source fragments are dropped by the peer hook
 *   as "outer v6 fragment", so inner MTU + IWAN_OVERHEAD_V6 must fit the carrier
 *   NIC MTU -- setup check (iwan_carrier_resolve6), egress re-check: drop + tx_err.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/inetdevice.h>	/* __ip_dev_find: egress IP -> owning interface */
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/ipv6.h>		/* struct ipv6hdr: outer v6 header, 40B */
#include <linux/inet.h>		/* INET_ADDRSTRLEN / INET6_ADDRSTRLEN */
#include <net/ip.h>
#include <net/udp.h>
#include <net/ipv6.h>		/* ip6_local_out */
#include <net/ip6_route.h>	/* ip6_route_output (inline) */
#include <net/ip6_checksum.h>	/* udp6_set_csum (v6 pseudo-header checksum) */
#include <net/addrconf.h>	/* ipv6_chk_addr: v6 egress IP -> owning interface */
#include <net/route.h>
#include <net/netns/generic.h>

#include <net/rtnetlink.h>
#include "iwan.h"

static netdev_tx_t iwan_xmit(struct sk_buff *skb, struct net_device *dev);
static netdev_tx_t iwan_tx_outer4(struct iwan_net *pn, struct net *net,
				  struct net_device *dev,
				  const struct iwan_dp *dp,
				  struct sk_buff *skb, unsigned int flen);
static netdev_tx_t iwan_tx_outer6(struct iwan_net *pn, struct net *net,
				  struct net_device *dev,
				  const struct iwan_dp *dp,
				  struct sk_buff *skb, unsigned int flen);

static const struct net_device_ops iwan_netdev_ops = {
	.ndo_start_xmit		= iwan_xmit,
};

static void iwan_dev_setup(struct net_device *dev)
{
	dev->netdev_ops		= &iwan_netdev_ops;
	dev->type		= ARPHRD_TUNNEL;	/* L3, no MAC */
	dev->flags		= IFF_POINTOPOINT | IFF_NOARP;
	dev->hard_header_len	= 0;
	dev->addr_len		= 4;	/* one IPv4 each for dev_addr/broadcast (same as ipip) */
	dev->mtu		= 1500 - IWAN_OVERHEAD;
	dev->min_mtu		= 68;
	dev->max_mtu		= 65535 - IWAN_OVERHEAD;
	/* Preset: only enough for the outer header this module pushes itself. Once the
	 * carrier NIC is pinned (at session setup or on first-packet egress resolve),
	 * iwan_carrier_pin() raises it to IWAN_OVERHEAD + LL_RESERVED_SPACE(carrier),
	 * so the sender reserves enough once -- ip_finish_output2's reallocation (a full copy on a linear skb) never happens. */
	dev->needed_headroom	= IWAN_OVERHEAD;
	/*
	 * Feature set: declare only SG (scatter-gather), leave the rest unset.
	 *
	 * Leaving checksum offload and TSO unset stays a prerequisite for XOR
	 * correctness: the stack finishes the sw checksum (skb_checksum_help, per page
	 * frame, no linearity required) and GSO segmentation before this driver, so
	 * the transform acts on "one packet with frozen checksum". With SG declared,
	 * validate_xmit_skb no longer __skb_linearize()s non-linear skb, paged payload
	 * reaches ndo_start_xmit as-is, iwan_xor_paged() drops the TX full copy (65KB/packet at large MTU).
	 */
	dev->features		= NETIF_F_SG;
	dev->hw_features	= NETIF_F_SG;
	dev->vlan_features	= 0;
	dev->priv_flags		|= IFF_NO_QUEUE;
	/*
	 * Devices created by rtnl_link_ops are freed by the core on unregister
	 * (netdev_run_todo() frees only when needs_free_netdev is set). Omitting this
	 * line leaks one net_device on every `ip link del` / SESSION_DOWN -- the
	 * control plane creates/deletes on demand, so declare ownership here.
	 */
	dev->needs_free_netdev	= true;
}

/*
 * Carrier NIC (downstream NIC) binding.
 *
 * Semantics (set 2026-10-09): **a session always uses one downstream NIC**.
 *   - Explicit binding (IWAN_A_OIF) -> strictly that NIC: outer lookup carries
 *     flowi4_oif, the data plane never drifts. flowi4_oif is a "hard bind":
 *     with the device UP and an IPv4 address, ip_route_output_flow() also
 *     synthesizes a scope link route for it (SO_BINDTODEVICE semantics) even
 *     with no FIB route via it -- so binding to a NIC with no return route
 *     does not fail on the control plane; it sends and the network drops it
 *     (black hole); only a missing device or unresolvable route fails
 *     (SESSION_UP returns -ENETUNREACH);
 *   - Unbound -> resolve once via FIB and pin the result (ifindex) on pn->carrier;
 *     later outer lookups all carry this flowi4_oif, no per-packet change. Pin users: egress lookup (6), ingress filter (iwan_rx.c), needed_headroom (here).
 */

/*
 * Pin the carrier NIC and derive this device's needed_headroom from it.
 *
 * Why derive needed_headroom: the outer header pushes IWAN_OVERHEAD bytes and
 * the carrier then needs LL_RESERVED_SPACE(carrier) for its link header (macro
 * already includes the carrier's hard_header_len, its declared
 * needed_headroom and 16B alignment slack). Senders (UDP ip_append_data,
 * raw/IP_HDRINCL raw_sendmsg, TCP hh_len) reserve via LL_RESERVED_SPACE(iwan0):
 * if enough, slack remains after the push and skb_realloc_headroom in
 * ip_finish_output2 never triggers. That reallocation moves the whole **linear
 * area**: on a linear skb (raw/IP_HDRINCL sender) headlen is the whole packet,
 * ~15us at 65KB measured (20 percent of that TX path); a paged skb has only tens of bytes, no such cost.
 *
 * Only grow, never shrink (take max): shrinking for a less demanding carrier
 * buys nothing, it only makes headroom jitter with session setup/teardown. The
 * cap is clamped by LL_MAX_HEADER so an absurd carrier needed_headroom cannot raise every packet's reservation.
 */
/* overhead = outer encapsulation cost of this session (whole value like v4 36 /
 * v6 56, see iwan.h); bind_desc != NULL means "bound by egress IP", the content
 * being the address already formatted (v4/v6 are pre-formatted with %pI4/%pI6 -- this log cannot fork into two per-family versions). */
static void iwan_carrier_pin(struct iwan_net *pn, const struct net_device *carrier,
			     struct net_device *dev, bool explicit,
			     const char *bind_desc, unsigned int overhead)
{
	unsigned int want = overhead + LL_RESERVED_SPACE(carrier);

	WRITE_ONCE(pn->carrier, carrier->ifindex);
	if (want > overhead + LL_MAX_HEADER)
		want = overhead + LL_MAX_HEADER;
	if (dev && READ_ONCE(dev->needed_headroom) < want)
		WRITE_ONCE(dev->needed_headroom, want);
	if (bind_desc)
		pr_info("netns %u: carrier NIC %s ifindex=%u (resolved by egress IP %s) needed_headroom=%u\n",
			pn->net->ns.inum, carrier->name, carrier->ifindex,
			bind_desc,
			dev ? READ_ONCE(dev->needed_headroom) : 0);
	else
		pr_info("netns %u: carrier NIC %s ifindex=%u (%s) needed_headroom=%u\n",
			pn->net->ns.inum, carrier->name, carrier->ifindex,
			explicit ? "explicit binding" : "pinned after FIB resolve",
			dev ? READ_ONCE(dev->needed_headroom) : 0);
}

/* "which NIC owns a given v6 address": same source of truth as v4's
 * __ip_dev_find (the local address table); v6 just has no exported "one call
 * returns the device" helper, so ask ipv6_chk_addr(..., strict=1) per device
 * (strict excludes tentative addresses whose DAD is unfinished -- an address
 * unusable as source is pointless). Session setup / bond re-resolve only, not per-packet. */
static struct net_device *iwan_bind_ip6_dev(struct net *net,
					    const struct in6_addr *ip6)
{
	struct net_device *d, *found = NULL;

	rcu_read_lock();
	for_each_netdev_rcu(net, d) {
		if (ipv6_chk_addr(net, ip6, d, 1)) {
			dev_hold(d);
			found = d;
			break;
		}
	}
	rcu_read_unlock();
	return found;
}

int iwan_bind_ip_check6(struct net *net, const struct in6_addr *ip6, u32 oif)
{
	struct net_device *ipdev;

	if (ipv6_addr_any(ip6))
		return 0;
	ipdev = iwan_bind_ip6_dev(net, ip6);
	if (!ipdev)
		return -EADDRNOTAVAIL;
	if (oif && ipdev->ifindex != oif) {
		dev_put(ipdev);
		return -EINVAL;
	}
	dev_put(ipdev);
	return 0;
}

int iwan_bind_ip_check(struct net *net, __be32 ip, u32 oif)
{
	const struct net_device *ipdev;

	if (!ip)
		return 0;
	/* __ip_dev_find walks the local address table (RTN_LOCAL): which interface owns
	 * an address is decided by **address config**. devref=false => no ref, ifindex only. */
	ipdev = __ip_dev_find(net, ip, false);
	if (!ipdev)
		return -EADDRNOTAVAIL;
	if (oif && ipdev->ifindex != oif)
		return -EINVAL;
	return 0;
}

/* Resolve and pin the carrier NIC (once at setup; later only the data plane
 * re-resolves, on outer lookup failure with **no** explicit binding (see iwan_xmit 6).
 *
 * Three inputs together decide "which downstream NIC this session uses":
 *   oif      NIC explicitly named by the control plane ("bind NIC");
 *   bind_ip  egress IP explicitly named by the control plane ("bind IP"):
 *            resolve the interface holding it via the address table, equal to
 *            binding that interface; neither -> one FIB resolve ("bind nothing").
 *
 * Failure semantics (returned to the control plane as-is; no "second best" NIC
 * swap here -- binding means no drifting):
 *   -EINVAL         the two binding specs contradict (IP not on the named NIC),
 *                   or the egress IP differs from the outer source address;
 *   -EADDRNOTAVAIL  the IP belongs to no local interface;
 *   -ENETUNREACH    no outer route through that NIC (device absent / not UP);
 *   -ELOOP          the outer endpoint points at the tunnel itself.
 */
int iwan_carrier_resolve(struct net *net, struct iwan_net *pn,
			 struct net_device *dev, __be32 src, __be32 dst,
			 u32 oif, __be32 bind_ip)
{
	struct flowi4 fl4 = {
		.daddr		= dst,
		.saddr		= src,
		.flowi4_proto	= IPPROTO_UDP,
		.flowi4_oif	= oif,
	};
	struct net_device *ipdev = NULL;
	struct rtable *rt;
	int err;

	/* "bind IP" level 1: it is the outer header source (OUTER_SRC already
	 * written there, see oiph->saddr in iwan_xmit). Mismatch = config error:
	 * packet leaves with a source unrelated to the binding, so the peer's 5-tuple filter cannot match. */
	if (bind_ip && bind_ip != src)
		return -EINVAL;

	/* Level 2: address table resolve. "Which NIC owns an IP" is **address
	 * config** (in_device on net_device), not the route table nor the NIC driver;
	 * route reverse lookup would degrade "bind IP" to "FIB decides", the same as "bind nothing". */
	if (bind_ip) {
		ipdev = __ip_dev_find(net, bind_ip, true);
		if (!ipdev)
			return -EADDRNOTAVAIL;
		if (oif && ipdev->ifindex != oif) {
			err = -EINVAL;
			goto out;
		}
		oif = ipdev->ifindex;
		fl4.flowi4_oif = oif;
	}

	rt = ip_route_output_flow(net, &fl4, NULL);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto out;
	}
	/* flowi4_oif is only a "preferred device"; the kernel does not guarantee it
	 * (measured: binding lo still resolves the vethbp1 direct route). Explicit
	 * binding must verify itself, else "bind a NIC" silently becomes "some NIC". */
	if (oif && rt->dst.dev->ifindex != oif) {
		ip_rt_put(rt);
		err = -ENETUNREACH;
		goto out;
	}
	/* Outer endpoint = tunnel itself: pinning is pointless, let iwan_xmit's loopback gate reject it */
	if (rt->dst.dev == dev) {
		ip_rt_put(rt);
		err = -ELOOP;
		goto out;
	}
	{
		char desc[INET_ADDRSTRLEN];

		if (bind_ip)
			snprintf(desc, sizeof(desc), "%pI4", &bind_ip);
		iwan_carrier_pin(pn, rt->dst.dev, dev, oif != 0,
				 bind_ip ? desc : NULL, IWAN_OVERHEAD);
	}
	ip_rt_put(rt);
	err = 0;
out:
	if (ipdev)
		dev_put(ipdev);
	return err;
}

/* Session-level outer v6 resolve: same rules as v4 (two-level "bind IP", no
 * drift when explicit, tunnel endpoint rejected); differs only in family and the **hard precondition** below:
 *
 * Outer v6 does not fragment (see header), so "inner MTU + v6 overhead <=
 * carrier MTU" is the setup criterion: the carrier MTU is the only known path
 * MTU lower bound here (no socket in the data plane, so no ICMPv6 PTB arrives).
 * If violated return -EMSGSIZE so the control plane reports it clearly, rather
 * than the first packet silently fragmented in ip6_finish_output and dropped at the peer as "outer v6 fragment".
 *
 * Failure semantics identical to v4: -EINVAL/-EADDRNOTAVAIL/-ENETUNREACH/-ELOOP,
 * plus -EMSGSIZE (inner MTU does not fit). */
int iwan_carrier_resolve6(struct net *net, struct iwan_net *pn,
			  struct net_device *dev, u32 mtu,
			  const struct in6_addr *src,
			  const struct in6_addr *dst, u32 oif,
			  const struct in6_addr *bind_ip)
{
	struct flowi6 fl6 = {
		.daddr		= *dst,
		.saddr		= *src,
		.flowi6_proto	= IPPROTO_UDP,
		.flowi6_oif	= oif,
	};
	struct net_device *ipdev = NULL;
	struct dst_entry *rt;
	char desc[INET6_ADDRSTRLEN];
	int err;

	if (!ipv6_addr_any(bind_ip) && !ipv6_addr_equal(bind_ip, src))
		return -EINVAL;

	if (!ipv6_addr_any(bind_ip)) {
		ipdev = iwan_bind_ip6_dev(net, bind_ip);
		if (!ipdev)
			return -EADDRNOTAVAIL;
		if (oif && ipdev->ifindex != oif) {
			err = -EINVAL;
			goto out;
		}
		oif = ipdev->ifindex;
		fl6.flowi6_oif = oif;
	}

	rt = ip6_route_output(net, NULL, &fl6);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		pr_info("netns %u: outer v6 resolve failed ip6_route_output=%d (src %pI6c dst %pI6c oif %u bind %pI6c dev %s mtu %u)\n",
			net->ns.inum, err, src, dst, oif, bind_ip,
			dev ? dev->name : "(none)", mtu);
		goto out;
	}
	/* Unreachable destinations return a dst with non-zero error (typically
	 * ip6_null_entry): that is not a "successful resolve" and must be treated as a
	 * failure -- else the carrier pins to lo and the MTU check uses lo's MTU ("it fits"). */
	if (rt->error) {
		err = rt->error;
		pr_info("netns %u: outer v6 resolved only an unusable route %d (src %pI6c dst %pI6c oif %u dev %s)\n",
			net->ns.inum, err, src, dst, oif, rt->dev->name);
		dst_release(rt);
		goto out;
	}
	/* flowi6_oif is a hard bind in v6 (the kernel filters routes by oif), but we
	 * still verify: same reason as v4 -- "bind one NIC" must not silently become "any NIC". */
	if (oif && rt->dev->ifindex != oif) {
		dst_release(rt);
		err = -ENETUNREACH;
		goto out;
	}
	if (rt->dev == dev) {
		dst_release(rt);
		err = -ELOOP;
		goto out;
	}
	if (mtu && mtu + IWAN_OVERHEAD_V6 > READ_ONCE(rt->dev->mtu)) {
		pr_info("netns %u: outer v6 session rejected: inner MTU %u + overhead %u exceeds carrier %s MTU %u\n",
			net->ns.inum, mtu, (unsigned int)IWAN_OVERHEAD_V6,
			rt->dev->name, READ_ONCE(rt->dev->mtu));
		dst_release(rt);
		err = -EMSGSIZE;
		goto out;
	}
	if (!ipv6_addr_any(bind_ip))
		snprintf(desc, sizeof(desc), "%pI6c", bind_ip);
	pr_info("netns %u: outer v6 carrier resolved %s (mtu %u, src %pI6c dst %pI6c, inner MTU %u)\n",
		net->ns.inum, rt->dev->name, READ_ONCE(rt->dev->mtu), src, dst,
		mtu);
	iwan_carrier_pin(pn, rt->dev, dev, oif != 0,
			 ipv6_addr_any(bind_ip) ? NULL : desc, IWAN_OVERHEAD_V6);
	dst_release(rt);
	err = 0;
out:
	if (ipdev)
		dev_put(ipdev);
	return err;
}

static netdev_tx_t iwan_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net *net = dev_net(dev);
	struct iwan_net *pn = iwan_net_of(net);
	struct iwan_cfg *c = iwan_cfg_get();
	struct iwan_dp dp;
	struct udphdr *uh;

	/* Diagnostic pass-through: just account "went through ndo_start_xmit" and drop, no
	 * encapsulation, no injection. Shares dev->stats / tx_pkts with the normal path, so meters read directly. */
	if (unlikely(READ_ONCE(c->pass_through) & IWAN_PASS_TX)) {
		dev->stats.tx_bytes += skb->len;
		atomic64_inc(&pn->st.tx_pkts);
		atomic64_add(skb->len, &pn->st.tx_bytes);
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	u16 sport;
	u8 fh[IWAN_HDR_LEN];
	unsigned int flen;
	u32 tok;
	u16 sid;

	/* Session first, module params as fallback: without a netlink session the outer
	 * endpoints come from /proc pn->tx_src/tx_dst, port/credentials from module
	 * params, switch from cfg.enabled && pn->enabled -- bit-identical to before the control plane. */
	iwan_dp_get(pn, c, true, &dp);
	sport = dp.sport ? dp.sport : dp.dport;

	/* Endpoint criterion per family: v4 sessions test whether the __be32 is 0, v6
	 * sessions test whether the 16 bytes are all zero. The two fields are never
	 * valid together (iwan_dp_get fills only the session's family), so test them separately -- applying the v4 test to a v6 session drops every session. */
	if (unlikely(!dp.enabled))
		goto drop;
	if (dp.outer_v6) {
		if (ipv6_addr_any(&dp.outer_src6) ||
		    ipv6_addr_any(&dp.outer_dst6))
			goto drop;
	} else if (!dp.outer_src || !dp.outer_dst) {
		goto drop;
	}

	/*
	 * Invariant check: by here it must already be "one complete IP packet + checksum
	 * done". If not, drop and count -- better to drop than to emit a dirty packet.
	 */
	if (unlikely(skb_is_gso(skb) || skb->ip_summed == CHECKSUM_PARTIAL ||
		     skb_network_offset(skb) != 0)) {
		atomic64_inc(&pn->st.tx_bad_state);
		goto drop;
	}
	{
		/* Inner v4/v6 share one criterion (iwan_core.c); TX requires the declared length
		 * to equal skb->len exactly -- egress encapsulates only "one complete inner
		 * packet". Exactly one failure reason: not a legal inner header of either
		 * version (i.e. incomplete packets other than inner fragments). */
		u32 nhlen;

		if (unlikely(iwan_inner_hdr_check(skb, true, &nhlen))) {
			atomic64_inc(&pn->st.tx_bad_inner);
			goto drop;
		}
	}
	flen = skb->len;

	/* 1) XOR the inner IP packet (checksum is plaintext by now, XOR keeps it self-consistent) */
	if (dp.enc && unlikely(iwan_xor_skb(skb, dp.key))) {
		atomic64_inc(&pn->st.tx_err);
		goto drop;
	}

	/* 2) 8-byte iWAN frame header */
	if (unlikely(skb_cow_head(skb, IWAN_OVERHEAD)))
		goto drop;
	sid = dp.sid;
	tok = dp.tok;
	fh[0] = dp.enc ? PT_DATA_ENC : PT_DATA;
	fh[1] = dp.enc;
	fh[2] = (u8)(sid >> 8);
	fh[3] = (u8)sid;
	fh[4] = (u8)(tok >> 24);
	fh[5] = (u8)(tok >> 16);
	fh[6] = (u8)(tok >> 8);
	fh[7] = (u8)tok;
	memcpy(skb_push(skb, IWAN_HDR_LEN), fh, IWAN_HDR_LEN);

	/* 3) drop inner-path metadata (inner conntrack ref, dst, trace) */
	skb_scrub_packet(skb, false);

	/* 4) outer UDP */
	uh = skb_push(skb, sizeof(*uh));
	memset(uh, 0, sizeof(*uh));
	/* Ports in cfg/session are host byte order (module_param and netlink inputs are
	 * both converted), the wire wants network byte order, so convert explicitly here
	 * -- same convention as the sid/tok shift serialization above. Skipping this
	 * byte-swaps the wire port: local loopback hides it, but the peer's packets to the configured port are all rejected by RX. */
	uh->source = htons(sport);
	uh->dest = htons(dp.dport);
	uh->len = htons(skb->len);
	skb_reset_transport_header(skb);

	/* 5) outer send forks by family: up to here (frame header, UDP header, length
	 * and ports) all is shared; forks only in checksum helper, IP header, stack entry. */
	if (dp.outer_v6)
		udp6_set_csum(false, skb, &dp.outer_src6, &dp.outer_dst6,
			      skb->len);
	else
		udp_set_csum(false, skb, dp.outer_src, dp.outer_dst,
			     skb->len);	/* left to the driver/hardware */

	return dp.outer_v6 ? iwan_tx_outer6(pn, net, dev, &dp, skb, flen) :
			     iwan_tx_outer4(pn, net, dev, &dp, skb, flen);

drop:
	dev_kfree_skb_any(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

/* Outer v4 send: header build, route cache, carrier pinning and self-heal,
 * counters all kept as-is (slice 2 only moved this out of iwan_xmit, bit-identical). */
static netdev_tx_t iwan_tx_outer4(struct iwan_net *pn, struct net *net,
				  struct net_device *dev,
				  const struct iwan_dp *dp,
				  struct sk_buff *skb, unsigned int flen)
{
	struct iwan_cfg *c = iwan_cfg_get();
	struct iphdr *oiph;
	struct flowi4 fl4;
	struct rtable *rt;
	__be32 src = dp->outer_src, dst = dp->outer_dst;
	u32 oif;
	int err;

	/* 5) outer IPv4 (default DF=1: outer no longer fragments, MTU guaranteed by
	 *    iwan0's mtu; df=0 allows outer fragmentation, to verify inline reassembly in the peer hook) */
	oiph = skb_push(skb, sizeof(*oiph));
	memset(oiph, 0, sizeof(*oiph));
	oiph->version = 4;
	oiph->ihl = 5;
	oiph->ttl = 64;
	oiph->protocol = IPPROTO_UDP;
	oiph->tot_len = htons(skb->len);
	oiph->frag_off = READ_ONCE(c->df) ? htons(IP_DF) : 0;
	oiph->saddr = src;
	oiph->daddr = dst;
	ip_send_check(oiph);
	skb_reset_network_header(skb);
	skb_reset_mac_header(skb);
	skb->protocol = htons(ETH_P_IP);

	/* 6) send via the physical route. Session-level route cache: outer endpoints
	 * stay fixed for the session's life, per-packet FIB lookup is pure duplicate
	 * work (a main per-packet cost at high packet rates). dst_cache dst_checks by
	 * route generation, so route table changes invalidate automatically; outer
	 * endpoint changes (/proc write, new session) are caught by comparing the
	 * address pair remembered here, then dst_cache_reset() invalidates lazily. On
	 * hit and miss alike the rt reference is owned by the cache; the skb's is dst_clone'd.
	 * Note: runs under ndo_start_xmit, dev_queue_xmit holds rcu_read_lock_bh() (BH off, as dst_cache needs). */
	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = dst;
	fl4.saddr = src;
	fl4.flowi4_proto = IPPROTO_UDP;
	/* Carrier NIC: when pinned it joins the lookup (strict bind); when not pinned
	 * but the session named one, look up by it too (the first packet must not
	 * drift). 0 = FIB decides this time, pin right after resolve (see iwan_carrier_pin). */
	oif = READ_ONCE(pn->carrier);
	if (!oif && dp->bind_ip) {
		/* "bind IP" mode but the pin was cleared (SET_PEER and outer endpoint rewrite
		 * both clear it, see iwan_carrier_forget): the egress IP still decides the
		 * carrier, so resolve it from the address table first, never let FIB pick a
		 * different NIC. Not steady-state -- a valid pin skips this, so no address
		 * lookup in steady state. If no local interface holds the address, binding failed (count tx_err). */
		const struct net_device *ipdev =
			__ip_dev_find(net, dp->bind_ip, false);

		if (!ipdev) {
			atomic64_inc(&pn->st.tx_err);
			goto drop;
		}
		oif = ipdev->ifindex;
	}
	if (!oif)
		oif = dp->oif;
	fl4.flowi4_oif = oif;
	rt = NULL;
	if (pn->tx_route_ok) {
		rt = dst_cache_get_ip4(&pn->tx_route, &fl4.saddr);
		if (rt && unlikely(pn->tx_route_dst != dst ||
				   pn->tx_route_src != src ||
				   pn->tx_route_oif != oif)) {
			dst_cache_reset(&pn->tx_route);
			fl4.saddr = src;
			rt = NULL;
		}
	}
	if (!rt) {
		rt = ip_route_output_flow(net, &fl4, NULL);
		if (!IS_ERR(rt) && oif && rt->dst.dev->ifindex != oif) {
			/* flowi4_oif is only a "preferred device", the kernel does not guarantee it
			 * (measured: binding lo still resolves the vethbp1 direct route). Binding must
			 * verify itself, else "bind a NIC" silently degrades into "some NIC". */
			ip_rt_put(rt);
			rt = ERR_PTR(-ENETUNREACH);
		}
		if (IS_ERR(rt) && oif) {
			/* Both cases land here: lookup failed (device deleted / route withdrawn), or
			 * the lookup succeeded but resolved to a NIC other than the bound one. The
			 * auto-pinned case falls back -- clear the pin, re-resolve via FIB once and
			 * re-pin, keeping "only one NIC at a time" instead of failing forever;
			 * explicit binds deliberately do not fall back: binding means no drift, so if
			 * that NIC is unreachable it fails (count tx_err). Explicit binding has two
			 * delivery forms: bind NIC (dp->oif) and bind egress IP (dp->bind_ip, already
			 * resolved to the same NIC at session setup); both mean "no drift". */
			if (iwan_dp_bound(dp))
				pr_info_ratelimited("netns %u: bound carrier ifindex=%u has no route to %pI4 (%ld), dropping\n",
						    net->ns.inum, oif, &dst,
						    PTR_ERR(rt));
			else {
				pr_info("netns %u: carrier ifindex=%u is unreachable (%ld), re-resolving outer route via FIB\n",
					net->ns.inum, oif, PTR_ERR(rt));
				WRITE_ONCE(pn->carrier, 0);
				if (pn->tx_route_ok)
					dst_cache_reset(&pn->tx_route);
				oif = 0;	/* after the re-pin FIB picks it, counted as "non-explicit" below */
				fl4.saddr = src;
				fl4.flowi4_oif = 0;
				rt = ip_route_output_flow(net, &fl4, NULL);
			}
		}
		if (IS_ERR(rt)) {
			atomic64_inc(&pn->st.tx_err);
			goto drop;
		}
		if (pn->tx_route_ok) {
			dst_cache_set_ip4(&pn->tx_route, &rt->dst, src);
			pn->tx_route_dst = dst;
			pn->tx_route_src = src;
			pn->tx_route_oif = rt->dst.dev->ifindex;
		}
	}
	/* Pin the carrier NIC on the first successful resolve (with an explicit bind it
	 * always equals the bound value). Must sit **after** the loopback gate above:
	 * if the outer endpoint points at the tunnel itself that "NIC" is iwan0, pinning it only hurts RX. */
	if (unlikely(rt->dst.dev == dev)) {	/* route loopback: reject */
		if (pn->tx_route_ok)
			dst_cache_reset(&pn->tx_route);
		else
			ip_rt_put(rt);
		atomic64_inc(&pn->st.tx_err);
		goto drop;
	}
	if (unlikely(READ_ONCE(pn->carrier) != rt->dst.dev->ifindex)) {
		char desc[INET_ADDRSTRLEN];

		if (dp->bind_ip)
			snprintf(desc, sizeof(desc), "%pI4", &dp->bind_ip);
		iwan_carrier_pin(pn, rt->dst.dev, dev, oif != 0,
				 dp->bind_ip ? desc : NULL, IWAN_OVERHEAD);
	}
	skb_dst_drop(skb);
	/* the cache owns the reference (on miss dst_cache_set_ip4 took it), take another here */
	skb_dst_set(skb, pn->tx_route_ok ? dst_clone(&rt->dst) : &rt->dst);
	skb->dev = rt->dst.dev;

	dev->stats.tx_packets++;
	dev->stats.tx_bytes += flen;
	atomic64_inc(&pn->st.tx_pkts);
	atomic64_add(flen, &pn->st.tx_bytes);

	/* ip_local_out() consumes the skb on every path */
	err = ip_local_out(net, NULL, skb);
	if (unlikely(err))
		atomic64_inc(&pn->st.tx_err);
	return NETDEV_TX_OK;

drop:
	dev_kfree_skb_any(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

/* Outer v6 send. Corresponds line by line to v4 (header build, loopback gate,
 * bind "self-heal vs no drift", counters); three family-specific spots:
 *   - header is fixed 40B, the length field is **payload length** (no header), hop_limit replaces ttl;
 *   - checksum already set in the shared part by udp6_set_csum() (v6 pseudo-header is a 16B address);
 *   - v6 has no DF bit and **never fragments**: if it does not fit the carrier MTU, drop and count tx_err.
 *     (Session setup already rejected by the same criterion; this catches "carrier MTU shrank mid-session".)
 * Deliberately no v4-style dst_cache: dst_cache_get_ip6() writes back prefsrc, and its
 * interaction with "hard source address binding" needs its own audit; outer v6 is not in
 * the performance baseline yet, so per-packet lookup for now, correctness first (cache deferred to a performance slice, along with v4's dst_cache).
 */
static netdev_tx_t iwan_tx_outer6(struct iwan_net *pn, struct net *net,
				  struct net_device *dev,
				  const struct iwan_dp *dp,
				  struct sk_buff *skb, unsigned int flen)
{
	struct ipv6hdr *oiph;
	struct flowi6 fl6;
	struct dst_entry *dst;
	u32 oif;
	int err;

	/* 5) outer IPv6 */
	oiph = skb_push(skb, sizeof(*oiph));
	memset(oiph, 0, sizeof(*oiph));
	oiph->version = 6;
	oiph->nexthdr = IPPROTO_UDP;
	oiph->hop_limit = 64;
	oiph->payload_len = htons(skb->len - sizeof(*oiph));
	oiph->saddr = dp->outer_src6;
	oiph->daddr = dp->outer_dst6;
	skb_reset_network_header(skb);
	skb_reset_mac_header(skb);
	skb->protocol = htons(ETH_P_IPV6);

	/* 6) per-packet outer lookup: same bind semantics as v4 (an explicit bind uses
	 * that NIC strictly; when unpinned, resolve via FIB then pin; if the pinned one is unreachable, clear and re-resolve once). */
	memset(&fl6, 0, sizeof(fl6));
	fl6.daddr = dp->outer_dst6;
	fl6.saddr = dp->outer_src6;
	fl6.flowi6_proto = IPPROTO_UDP;
	oif = READ_ONCE(pn->carrier);
	if (!oif && !ipv6_addr_any(&dp->bind_ip6)) {
		/* "bind IP" mode but the pin was cleared (SET_PEER and outer endpoint rewrite
		 * both clear it, see iwan_carrier_forget): the egress IP still decides the
		 * carrier, so resolve it from the address table first, never let FIB pick another NIC. Not reached in steady state. */
		struct net_device *ipdev = iwan_bind_ip6_dev(net, &dp->bind_ip6);

		if (!ipdev) {
			atomic64_inc(&pn->st.tx_err);
			goto drop;
		}
		oif = ipdev->ifindex;
		dev_put(ipdev);
	}
	if (!oif)
		oif = dp->oif;
	fl6.flowi6_oif = oif;
	dst = ip6_route_output(net, NULL, &fl6);
	/* v6 lookup failure has two shapes: ERR_PTR, or "a dst carrying an error" (the
	 * null_entry family). Both must count as failure; testing only IS_ERR would send the latter out as a usable route. */
	if (!IS_ERR(dst) && oif && dst->dev->ifindex != oif) {
		dst_release(dst);
		dst = ERR_PTR(-ENETUNREACH);
	}
	if (!IS_ERR(dst) && unlikely(dst->error)) {
		int e2 = dst->error;

		dst_release(dst);
		dst = ERR_PTR(e2);
	}
	if (IS_ERR(dst) && oif) {
		if (iwan_dp_bound(dp)) {
			pr_info_ratelimited("netns %u: bound carrier ifindex=%u has no route to %pI6c (%ld), dropping\n",
					    net->ns.inum, oif,
					    &dp->outer_dst6, PTR_ERR(dst));
		} else {
			pr_info("netns %u: carrier ifindex=%u is unreachable (%ld), re-resolving outer route via FIB\n",
				net->ns.inum, oif, PTR_ERR(dst));
			WRITE_ONCE(pn->carrier, 0);
			oif = 0;
			fl6.flowi6_oif = 0;
			dst = ip6_route_output(net, NULL, &fl6);
		}
	}
	if (IS_ERR(dst)) {
		atomic64_inc(&pn->st.tx_err);
		goto drop;
	}
	if (unlikely(dst->dev == dev)) {	/* route loopback: reject */
		dst_release(dst);
		atomic64_inc(&pn->st.tx_err);
		goto drop;
	}
	if (unlikely(READ_ONCE(dev->mtu) + IWAN_OVERHEAD_V6 >
		     READ_ONCE(dst->dev->mtu))) {
		pr_info_ratelimited("netns %u: outer v6 does not fit: inner MTU %u + overhead %u exceeds carrier %s MTU %u, dropping\n",
				    net->ns.inum, READ_ONCE(dev->mtu),
				    (unsigned int)IWAN_OVERHEAD_V6,
				    dst->dev->name, READ_ONCE(dst->dev->mtu));
		dst_release(dst);
		atomic64_inc(&pn->st.tx_err);
		goto drop;
	}
	if (unlikely(READ_ONCE(pn->carrier) != dst->dev->ifindex)) {
		char desc[INET6_ADDRSTRLEN];

		if (!ipv6_addr_any(&dp->bind_ip6))
			snprintf(desc, sizeof(desc), "%pI6c", &dp->bind_ip6);
		iwan_carrier_pin(pn, dst->dev, dev, oif != 0,
				 ipv6_addr_any(&dp->bind_ip6) ? NULL : desc,
				 IWAN_OVERHEAD_V6);
	}
	skb_dst_drop(skb);
	/* the reference from the lookup goes to the send path with the skb (same convention as v4's &rt->dst) */
	skb_dst_set(skb, dst);
	skb->dev = dst->dev;

	dev->stats.tx_packets++;
	dev->stats.tx_bytes += flen;
	atomic64_inc(&pn->st.tx_pkts);
	atomic64_add(flen, &pn->st.tx_bytes);

	err = ip6_local_out(net, NULL, skb);
	if (unlikely(err))
		atomic64_inc(&pn->st.tx_err);
	return NETDEV_TX_OK;

drop:
	dev_kfree_skb_any(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}


/* The NIC is no longer created by pernet init.
 *
 * Reason (measured): pernet's device-class init runs first in the whole netns
 * init, so register_netdevice() hits the not-yet-built device table and crashes
 * the kernel (module then hangs in "loading" forever, reboot only); the created device also backrefs the module, so rmmod fails.
 * Switched to rtnl_link_ops: the device is created either by `ip link add <name> type iwan`, or
 * by genetlink's SESSION_UP in process context via rtnl_create_link() on demand
 * (iwan_netlink.c); delete, netns destroy and rmmod all take the standard kernel paths.
 */
struct rtnl_link_ops iwan_link_ops = {
	.kind		= "iwan",
	.priv_size	= 0,
	.setup		= iwan_dev_setup,
	.dellink	= unregister_netdevice_queue,
};

int iwan_tx_init(void)
{
	return rtnl_link_register(&iwan_link_ops);
}

void iwan_tx_exit(void)
{
	rtnl_link_unregister(&iwan_link_ops);
}
