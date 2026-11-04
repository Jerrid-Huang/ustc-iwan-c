// SPDX-License-Identifier: GPL-2.0
/*
 * iwan_core.c -- module entry: global config (module parameters), per-netns lifecycle,
 *               /proc/net/iwan (read stats + write the per-netns egress endpoint).
 *
 * The config plane has three layers (since v1, see kernel/CONTROL-PLANE.md):
 *   - global (module parameters): **defaults**, effective only while that netns has no genetlink session;
 *   - per-netns session (genetlink, written by iwan_netlink.c): once the session is established the data plane uses only it
 *     (iwan_dp_get does "session first, parameters as fallback");
 *   - per-netns (/proc/net/iwan is writable): egress outer source/destination address when there is no session. One module
 *     instance serves all netns, and the egress destination differs in the two directions, so it must be configured per netns
 *     -- local bidirectional verification (two netns) relies exactly on this.
 *
 * With no netlink session, every field the data plane reads is bit-for-bit identical to before the control plane was introduced:
 * that is the precondition for the existing 13-item acceptance test (kernel/tests/tcp_echo_test.sh) not regressing.
 *
 * /dev/iwan (shared-memory page, iwan_shm.c): one page per netns, recording the monotonic milliseconds of the
 * "last valid frame received" (plus peer_state/counters), mmap'ed read-only for user-space polling.
 * The page is allocated in pernet init and released in pernet exit (refcount, see iwan_shm.c).
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>	/* kmap_local_page: map page by page for the paged XOR */
#include <linux/capability.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <net/ipv6.h>	/* ipv6_skip_exthdr: transport-layer offset of the inner v6 header */
#include <net/netns/generic.h>

#include "iwan.h"
#include "iwan_genl.h"	/* IWAN_GENL_NAME/VERSION: used only for the boot log */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
#error "iwan requires Linux >= 4.18"
#endif

/* ---- global config (module parameters = defaults when no session is established) ---------------------- */

static struct iwan_cfg cfg = {
	.enabled	= true,
	.any_dir	= false,
	.batch		= true,
	.reinject	= false,
	.verbose	= false,
	.hooknum	= IWAN_HOOK_PRE_ROUTING,
	.hookprio	= -300,
	.enc		= 1,
	.df		= true,
	.max_mtu	= IWAN_MAX_MTU,
};

struct iwan_cfg *iwan_cfg_get(void) { return &cfg; }

/*
 * Data-plane parameter lookup: per-netns session first, module parameters as fallback.
 *
 * With no session (sess.valid == false), every field provided here is bit-for-bit
 * identical to before the genetlink control plane was introduced:
 *   - RX outer filtering/ports/credentials = module parameters, switch = cfg.enabled && pn->enabled;
 *   - TX outer endpoint = pn->tx_src/tx_dst set via /proc, ports/credentials = module parameters.
 * With a session the whole set is replaced by the session parameters (including the session-level enabled switch).
 * Called once per packet, taking one consistent snapshot so a packet never sees two different configs.
 *
 * Locking: none, following the existing convention of struct iwan_cfg (no in-flight traffic while reconfiguring);
 * scalars are read one at a time with READ_ONCE; on the session side the control plane sets valid last and clears it first.
 */
void iwan_dp_get(struct iwan_net *pn, const struct iwan_cfg *c, bool tx,
		 struct iwan_dp *dp)
{
	struct iwan_session *s = &pn->sess;
	bool up = READ_ONCE(s->valid);

	dp->session = up;
	/* inner_src has no session-level counterpart in the ABI, so always take the module parameter */
	dp->inner_src = READ_ONCE(c->inner_src);

	if (up) {
		/* any_dir is always true for a session: the ABI defines OUTER_SRC/DST as the "local/peer"
		 * pair of **identities** (not directions); TX uses (src->dst), while for the same session the
		 * inbound packets are exactly reversed (dst->src), so RX must match as an unordered pair.
		 * The any_dir module parameter matters only for the fallback path below (old semantics unchanged). */
		dp->any_dir = true;
		dp->enabled = READ_ONCE(c->enabled) && READ_ONCE(s->enabled);
		dp->outer_src = READ_ONCE(s->outer_src);
		dp->outer_dst = READ_ONCE(s->outer_dst);
		dp->outer_v6 = READ_ONCE(s->outer_v6);
		dp->outer_src6 = s->outer_src6;
		dp->outer_dst6 = s->outer_dst6;
		dp->bind_ip6 = s->bind_ip6;
		dp->dport = READ_ONCE(s->dport);
		dp->sport = READ_ONCE(s->sport);
		dp->oif = READ_ONCE(s->oif);
		dp->bind_ip = READ_ONCE(s->bind_ip);
		dp->sid = READ_ONCE(s->sid);
		dp->tok = READ_ONCE(s->tok);
		dp->enc = READ_ONCE(s->enc);
		memcpy(dp->key, s->key, IWAN_KEY_LEN);
		return;
	}

	dp->any_dir = READ_ONCE(c->any_dir);
	dp->enabled = READ_ONCE(c->enabled) && READ_ONCE(pn->enabled);
	dp->outer_src = tx ? READ_ONCE(pn->tx_src) : READ_ONCE(c->outer_src);
	dp->outer_dst = tx ? READ_ONCE(pn->tx_dst) : READ_ONCE(c->outer_dst);
	/* Outer v6 is expressed only by a session (netlink); the /proc fallback path has no counterpart: clear explicitly.
	 * The caller's struct iwan_dp is on the stack; omitting this step lets "which version the outer header uses"
	 * be decided by stack garbage (TX would take the v6 branch and send with zero addresses). */
	dp->outer_v6 = false;
	memset(&dp->outer_src6, 0, sizeof(dp->outer_src6));
	memset(&dp->outer_dst6, 0, sizeof(dp->outer_dst6));
	memset(&dp->bind_ip6, 0, sizeof(dp->bind_ip6));
	/* Carrier NIC binding is a device property (direction-independent): the fallback path uniformly takes the /proc-configured
	 * tx_oif; 0 = resolve once via FIB and pin the result. */
	dp->oif = READ_ONCE(pn->tx_oif);
	dp->bind_ip = READ_ONCE(pn->tx_bind_ip);
	dp->dport = READ_ONCE(c->dport);
	dp->sport = READ_ONCE(c->sport);
	dp->sid = READ_ONCE(c->sid);
	dp->tok = READ_ONCE(c->tok);
	dp->enc = READ_ONCE(c->enc);
	memcpy(dp->key, c->key, IWAN_KEY_LEN);
}

unsigned int iwan_net_id __read_mostly;

module_param_named(enabled, cfg.enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "master switch (default 1)");
module_param_named(any_dir, cfg.any_dir, bool, 0644);
MODULE_PARM_DESC(any_dir, "outer (src,dst) may also be reversed, for local bidirectional/peer testing");
module_param_named(batch, cfg.batch, bool, 0644);
MODULE_PARM_DESC(batch, "process GRO-merged GSO skbs (default 1)");
module_param_named(reinject, cfg.reinject, bool, 0644);
MODULE_PARM_DESC(reinject, "after decapsulation, netif_rx back to before ip_defrag (LOCAL_IN fallback)");
module_param_named(verbose, cfg.verbose, bool, 0644);
module_param_named(hooknum, cfg.hooknum, int, 0644);
MODULE_PARM_DESC(hooknum, "0=PRE_ROUTING (default), 1=LOCAL_IN (fallback)");
module_param_named(hookprio, cfg.hookprio, int, 0644);
MODULE_PARM_DESC(hookprio, "hook priority, default -300 (after defrag, before conntrack)");
module_param_named(max_mtu, cfg.max_mtu, uint, 0644);
MODULE_PARM_DESC(max_mtu, "inner MTU upper limit (default 1500; hard spec limit 65499). "
			  "Values above the hard limit are clamped, not applied");
module_param_named(dport, cfg.dport, ushort, 0644);
MODULE_PARM_DESC(dport, "tunnel UDP destination port (matched on RX, used on TX)");
module_param_named(sport, cfg.sport, ushort, 0644);
MODULE_PARM_DESC(sport, "tunnel UDP source port (TX only; 0 = use dport)");
module_param_named(sid, cfg.sid, ushort, 0644);
MODULE_PARM_DESC(sid, "session id (delivered by OPEN_ACK)");
module_param_named(tok, cfg.tok, uint, 0644);
MODULE_PARM_DESC(tok, "session token (u32, delivered by OPEN_ACK)");
module_param_named(enc, cfg.enc, byte, 0644);
MODULE_PARM_DESC(enc, "1 = data-plane XOR (DATA_ENC), 0 = plaintext (DATA)");
module_param_named(pass_through, cfg.pass_through, uint, 0644);
MODULE_PARM_DESC(pass_through, "diagnostic bitmask: 1 = egress pass-through drop (only passes through ndo, no encapsulation); "
			       "2 = ingress pass-through allow (hook returns NF_ACCEPT immediately, no decapsulation). "
			       "default 0 = normal forwarding");
module_param_named(df, cfg.df, bool, 0644);
MODULE_PARM_DESC(df, "set DF=1 in the outer IP header (default 1); set 0 to allow outer fragmentation, for verifying in-hook reassembly");

/* ---- string parameters ---------------------------------------------------- */

static char key_hex[2 * IWAN_KEY_LEN + 1] = "0000000000000000";
static char outer_src_str[16] = "0.0.0.0";
static char outer_dst_str[16] = "0.0.0.0";
static char inner_src_str[16] = "0.0.0.0";

static int iwan_hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int iwan_set_key(const char *val, const struct kernel_param *kp)
{
	u8 tmp[IWAN_KEY_LEN];
	int i;

	(void)kp;
	if (strcspn(val, "\n") != 2 * IWAN_KEY_LEN)
		return -EINVAL;
	for (i = 0; i < IWAN_KEY_LEN; i++) {
		int hi = iwan_hexval(val[2 * i]);
		int lo = iwan_hexval(val[2 * i + 1]);

		if (hi < 0 || lo < 0)
			return -EINVAL;
		tmp[i] = (u8)((hi << 4) | lo);
	}
	memcpy(cfg.key, tmp, IWAN_KEY_LEN);
	strscpy(key_hex, val, sizeof(key_hex));
	return 0;
}

static int iwan_get_key(char *buf, const struct kernel_param *kp)
{
	(void)kp;
	return scnprintf(buf, PAGE_SIZE, "%s\n", key_hex);
}

static const struct kernel_param_ops iwan_key_ops = {
	.set = iwan_set_key,
	.get = iwan_get_key,
};

static int iwan_set_addr(const char *val, const struct kernel_param *kp)
{
	__be32 a;
	char *dst = kp->arg;

	if (!in4_pton(val, strcspn(val, "\n"), (u8 *)&a, -1, NULL))
		return -EINVAL;
	if (dst == (char *)&cfg.outer_src) {
		WRITE_ONCE(cfg.outer_src, a);
		strscpy(outer_src_str, val, sizeof(outer_src_str));
	} else if (dst == (char *)&cfg.outer_dst) {
		WRITE_ONCE(cfg.outer_dst, a);
		strscpy(outer_dst_str, val, sizeof(outer_dst_str));
	} else {
		WRITE_ONCE(cfg.inner_src, a);
		strscpy(inner_src_str, val, sizeof(inner_src_str));
	}
	return 0;
}

static int iwan_get_addr(char *buf, const struct kernel_param *kp)
{
	char *src = kp->arg;

	if (src == (char *)&cfg.outer_src)
		src = outer_src_str;
	else if (src == (char *)&cfg.outer_dst)
		src = outer_dst_str;
	else
		src = inner_src_str;
	return scnprintf(buf, PAGE_SIZE, "%s\n", src);
}

static const struct kernel_param_ops iwan_addr_ops = {
	.set = iwan_set_addr,
	.get = iwan_get_addr,
};

module_param_cb(outer_src, &iwan_addr_ops, &cfg.outer_src, 0644);
MODULE_PARM_DESC(outer_src, "RX filter: outer source address (server IP)");
module_param_cb(outer_dst, &iwan_addr_ops, &cfg.outer_dst, 0644);
MODULE_PARM_DESC(outer_dst, "RX filter: outer destination address (local tunnel address)");
module_param_cb(inner_src, &iwan_addr_ops, &cfg.inner_src, 0644);
MODULE_PARM_DESC(inner_src, "optional: inner source address whitelist, 0.0.0.0 = disabled");
module_param_cb(key, &iwan_key_ops, NULL, 0644);
MODULE_PARM_DESC(key, "16 hex digit data-plane key = MD5(user||pass)[0..8)");

/* ---- XOR ------------------------------------------------------------- */

/*
 * The session key is an 8-byte cyclic key applied to **all bytes** of the inner IPv4 packet (including the inner IP
 * header) -- so inbound must decrypt before reading the inner header, and outbound must XOR after checksums are computed.
 * Byte-for-byte equivalent to the 64-bit-word implementation of user-space xor_crypt(); off carries the offset across regions.
 */
void iwan_xor(u8 *p, size_t len, const u8 *key, size_t off)
{
	u64 k, v;
	size_t i = 0;

	memcpy(&k, key, IWAN_KEY_LEN);
	while (i < len && ((off + i) & 7))
		p[i] ^= key[(off + i) & 7], i++;
	while (i + 8 <= len) {
		memcpy(&v, p + i, 8);
		v ^= k;
		memcpy(p + i, &v, 8);
		i += 8;
	}
	while (i < len) {
		p[i] ^= key[(off + i) & 7];
		i++;
	}
}

/*
 * XOR all skb payload (linear area + page fragments + frag_list) in place with the 8-byte session key;
 * off increases continuously across segments -- strictly equivalent to transforming the "whole logical byte sequence", but without requiring physically
 * contiguous data, thus avoiding whole-packet linearization. Previously, the large-MTU profile (once the payload exceeded the kernel's paged-allocation threshold,
 * TX-side validate_xmit_skb linearization + RX-side skb_ensure_writable linearization) cost
 * two full-packet copies, which were the main part of the 6x gap versus the bare lo baseline. kmap_local_page can be used in softirq
 * context; frag_list child skbs are handled recursively (the shape after outer df=0 fragment reassembly).
 * Precondition: the caller has confirmed the whole packet is writable (see iwan_xor_skb).
 */
static void iwan_xor_paged(struct sk_buff *skb, const u8 *key, u32 off)
{
	struct sk_buff *it;
	skb_frag_t *f;
	u8 *p;
	u32 n, i;

	p = skb->data;
	n = skb_headlen(skb);
	iwan_xor(p, n, key, off);
	off += n;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		void *base;

		f = &skb_shinfo(skb)->frags[i];
		n = skb_frag_size(f);
		if (n) {
			base = kmap_local_page(skb_frag_page(f));
			iwan_xor(base + skb_frag_off(f), n, key, off);
			kunmap_local(base);
		}
		off += n;
	}

	for (it = skb_shinfo(skb)->frag_list; it; it = it->next) {
		iwan_xor_paged(it, key, off);
		off += it->len;
	}
}

/*
 * XOR the entire skb in place (including page fragments).
 *
 * Writability precondition: in-place modification requires exclusive write access to the buffer. skb clones (both sides of a clone share
 * shinfo and page fragments, typically the original skb in the TCP retransmit queue) and user pages pinned by MSG_ZEROCOPY
 * are not writable -- these two cases fall back to the old path: skb_ensure_writable() handles clones
 * (pskb_expand_head when needed) and pulls the data into the linear area, skb_linearize() is the fallback,
 * then the linear area is transformed. The exclusive case goes through iwan_xor_paged(), with no copy.
 */
int iwan_xor_skb(struct sk_buff *skb, const u8 *key)
{
	if (unlikely(skb_cloned(skb) || skb_header_cloned(skb) ||
		     (skb_shinfo(skb)->flags & SKBFL_ALL_ZEROCOPY))) {
		if (unlikely(skb_ensure_writable(skb, skb->len)))
			return -ENOMEM;
		if (unlikely(skb_is_nonlinear(skb)) && skb_linearize(skb))
			return -ENOMEM;
		iwan_xor(skb->data, skb->len, key, 0);
		return 0;
	}
	iwan_xor_paged(skb, key, 0);
	return 0;
}

/*
 * Inner IP header validation -- TX (iwan_tx.c) and RX (iwan_rx.c) share one set of criteria so that
 * version support in the two paths does not drift apart (v6 support is a capability enabled in both places together).
 *
 * Only "header self-consistency" is checked, not policy: the module is the data plane, source/destination address filtering is left to user space
 * (the TUN path has admission filtering on inner_ip and a derived ULA; the kernel side historically had only the module parameter
 * inner_src, a v4 whitelist; see the call site in iwan_rx.c for semantics).
 *
 * exact_len=true (TX): a data frame carries exactly **one** complete inner packet, and the declared length must
 *   equal skb->len -- egress must never wrap a truncated packet or one with extra trailing bytes into the tunnel.
 * exact_len=false (RX): keep the lenient rule that predates v6 -- reject only when the length declared by the inner header
 *   cannot cover the whole frame; extra trailing bytes are not rejected (existing behavior unchanged).
 *
 * v4: version=4, ihl>=5, tot_len in [ihl*4, skb->len] (equality required when exact_len);
 * v6: version=6, payload_len+40 == skb->len (equality required when exact_len),
 *     no support for the payload_len=0 hop-by-hop jumbogram form (the real length sits in hop-by-hop options; this module does no
 *     jumbograms), and the extension header chain must be walkable (ipv6_skip_exthdr must not return a negative value).
 *     Inner fragments, as with v4, are left to the stack for reassembly (this module does not reassemble the inner layer).
 * Out-param *net_hdr_len = inner network header length (v4 = ihl*4; v6 = 40 + extension headers),
 * from which the caller sets the transport-layer offset -- v6 cannot reuse the v4 ihl formula.
 *
 * Returns 0 = valid, -EINVAL = invalid (the caller counts tx_bad_inner / rx_bad_inner).
 */
int iwan_inner_hdr_check(struct sk_buff *skb, bool exact_len, u32 *net_hdr_len)
{
	const struct iphdr *iph;
	const struct ipv6hdr *ip6h;
	u8 ver, nexthdr;
	__be16 frag_off;
	u32 tot, hdrlen;
	int off;

	/* first make sure the version byte is in the linear area (skb->data may lie entirely in page fragments) */
	if (unlikely(!pskb_may_pull(skb, 1)))
		return -EINVAL;
	ver = skb->data[0] >> 4;

	if (ver == 4) {
		if (unlikely(!pskb_may_pull(skb, sizeof(*iph))))
			return -EINVAL;
		iph = ip_hdr(skb);
		if (iph->version != 4 || iph->ihl < 5)
			return -EINVAL;
		hdrlen = (u32)iph->ihl * 4;
		tot = ntohs(iph->tot_len);
		if (tot < hdrlen)
			return -EINVAL;
		if (exact_len ? tot != skb->len : tot > skb->len)
			return -EINVAL;
		*net_hdr_len = hdrlen;
		return 0;
	}

	if (ver == 6) {
		if (unlikely(!pskb_may_pull(skb, sizeof(*ip6h))))
			return -EINVAL;
		ip6h = (const struct ipv6hdr *)skb_network_header(skb);
		if (ip6h->version != 6 || ntohs(ip6h->payload_len) == 0)
			return -EINVAL;
		tot = (u32)ntohs(ip6h->payload_len) + (u32)sizeof(*ip6h);
		if (exact_len ? tot != skb->len : tot > skb->len)
			return -EINVAL;
		/* extension header chain (including the fragment header): obtain the transport-layer offset; reject any bad chain */
		nexthdr = ip6h->nexthdr;
		off = ipv6_skip_exthdr(skb, (int)sizeof(*ip6h), &nexthdr,
				       &frag_off);
		if (off < 0 || (u32)off > skb->len)
			return -EINVAL;
		*net_hdr_len = (u32)off;
		return 0;
	}

	return -EINVAL;
}

/* ---- /proc/net/iwan: read stats, write the per-netns egress endpoint --------------------- */

/*
 * The read path is **frozen**: neither the format nor any field may change (the existing 13-item acceptance test reads counters by name),
 * so what is shown here is always the "module parameters + per-netns switches/endpoints" layer; for netlink session
 * state/counters use IWAN_CMD_GET_STATS (the new rx_ctrl_frame counter exists only there too).
 */
static void iwan_proc_format(struct iwan_net *pn, char *buf, size_t size)
{
	struct iwan_stats *s = &pn->st;

	snprintf(buf, size,
		"enabled %d any_dir %d batch %d reinject %d hooknum %d prio %d\n"
		"outer_src %pI4 outer_dst %pI4 inner_src %pI4 dport %u sport %u\n"
		"sid %u tok %u enc %u df %d key %s\n"
		"netns_enabled %d tx_src %pI4 tx_dst %pI4 dev %s\n"
		"tx_oif %u tx_bind_ip %pI4 carrier %u\n"
		"rx_pkts %lld\nrx_outer %lld\nrx_reasm %lld\nrx_frames %lld\n"
		"rx_delivered %lld\nrx_batch %lld\nrx_batch_skip %lld\n"
		"rx_bad_hdr %lld\nrx_bad_inner %lld\nrx_nomem %lld\n"
		"tx_pkts %lld\ntx_bytes %lld\ntx_bad_state %lld\n"
		"tx_bad_inner %lld\ntx_err %lld\n",
		READ_ONCE(cfg.enabled), READ_ONCE(cfg.any_dir), READ_ONCE(cfg.batch),
		READ_ONCE(cfg.reinject), READ_ONCE(cfg.hooknum),
		READ_ONCE(cfg.hookprio), &cfg.outer_src, &cfg.outer_dst,
		&cfg.inner_src, READ_ONCE(cfg.dport),
		READ_ONCE(cfg.sport) ? READ_ONCE(cfg.sport) : READ_ONCE(cfg.dport),
		READ_ONCE(cfg.sid), READ_ONCE(cfg.tok), READ_ONCE(cfg.enc),
		READ_ONCE(cfg.df), key_hex,
		READ_ONCE(pn->enabled), &pn->tx_src, &pn->tx_dst,
		"-",	/* the NIC is now created by rtnl_link_ops and no longer hangs off the netns state */
		READ_ONCE(pn->tx_oif), &pn->tx_bind_ip, READ_ONCE(pn->carrier),
		(long long)atomic64_read(&s->rx_pkts),
		(long long)atomic64_read(&s->rx_outer),
		(long long)atomic64_read(&s->rx_reasm),
		(long long)atomic64_read(&s->rx_frames),
		(long long)atomic64_read(&s->rx_delivered),
		(long long)atomic64_read(&s->rx_batch),
		(long long)atomic64_read(&s->rx_batch_skip),
		(long long)atomic64_read(&s->rx_bad_hdr),
		(long long)atomic64_read(&s->rx_bad_inner),
		(long long)atomic64_read(&s->rx_nomem),
		(long long)atomic64_read(&s->tx_pkts),
		(long long)atomic64_read(&s->tx_bytes),
		(long long)atomic64_read(&s->tx_bad_state),
		(long long)atomic64_read(&s->tx_bad_inner),
		(long long)atomic64_read(&s->tx_err));
}

static ssize_t iwan_proc_read(struct file *file, char __user *ubuf,
			      size_t count, loff_t *ppos)
{
	struct iwan_net *pn = pde_data(file_inode(file));
	char *buf;
	ssize_t ret;

	buf = kmalloc(1024, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	iwan_proc_format(pn, buf, 1024);
	ret = simple_read_from_buffer(ubuf, count, ppos, buf, strlen(buf));
	kfree(buf);
	return ret;
}

/* write: tx_src=A.B.C.D tx_dst=A.B.C.D enabled=0/1 oif=<ifindex> ip=A.B.C.D
 *
 * oif = ifindex of the explicitly bound carrier NIC (downstream NIC); omitted or 0 means resolve once via FIB and
 * pin it. In both cases the data plane uses only one NIC; see iwan_carrier_pin() in iwan_tx.c.
 *
 * ip = explicitly bound **egress IP** ("bind IP" mode): it sets tx_src as well (the outer header's source
 * address) and decides the carrier NIC from the local address table -- whichever interface holds the address is used; if it conflicts with the NIC
 * given by oif (the address is not on that NIC), the whole write fails (-EINVAL). If the address does not belong to
 * any local interface, it fails too (-EADDRNOTAVAIL): binding a nonexistent address is pointless, and here
 * this deliberately differs from oif, which validates format only. ip=0.0.0.0 clears the IP binding.
 *
 * One write() is **one config transaction**: all tokens are parsed first and validated against the post-commit state,
 * then committed all at once; if any part is invalid the whole line has no effect (no "half a config" is left behind). Hence
 * after a write such as `oif=2 ip=<address not on that NIC>` fails, oif is not changed either.
 *
 * Deprecated: all new features go into the genetlink control plane (iwan_netlink.c).
 * Kept for the existing test scripts and troubleshooting: **with no netlink session** what is configured here is exactly the
 * per-netns egress endpoint/switch the data plane actually uses; once that netns establishes a session, the data plane follows the session
 * parameters (iwan_dp_get), and values written here exist only as fallback defaults.
 */
static ssize_t iwan_proc_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	struct iwan_net *pn = pde_data(file_inode(file));
	char buf[128], *p, *tok;
	/* one write() is a config transaction: parse the whole write locally and validate it against the **post-commit**
	 * state, then commit all at once. Applying token by token as it is parsed leaves "half a config"
	 * -- the first half takes effect and the second half errors; that intermediate state has no matching command line and would make the next
	 * write that should succeed conflict for no reason (observed: after `oif=2 ip=<address of another NIC>` fails,
	 * oif has already become 2). */
	__be32 n_src = READ_ONCE(pn->tx_src);
	__be32 n_dst = READ_ONCE(pn->tx_dst);
	__be32 n_bind = READ_ONCE(pn->tx_bind_ip);
	u32 n_oif = READ_ONCE(pn->tx_oif);
	bool n_enabled = READ_ONCE(pn->enabled);
	bool touch_tx = false;
	bool touch_en = false;
	bool saw_src = false;
	bool saw_ip = false;
	__be32 v_src = 0;
	__be32 v_ip = 0;
	int err;

	(void)ppos;
	if (!ns_capable(pn->net->user_ns, CAP_NET_ADMIN))
		return -EPERM;
	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';

	p = buf;
	while ((tok = strsep(&p, " \t\r\n")) != NULL) {
		char *eq = strchr(tok, '=');
		__be32 a;
		bool b;

		if (!*tok)
			continue;
		if (!eq)
			return -EINVAL;
		*eq++ = '\0';
		if (!strcmp(tok, "tx_src")) {
			if (!in4_pton(eq, -1, (u8 *)&a, -1, NULL))
				return -EINVAL;
			n_src = a;
			v_src = a;
			saw_src = true;
			touch_tx = true;
		} else if (!strcmp(tok, "tx_dst")) {
			if (!in4_pton(eq, -1, (u8 *)&a, -1, NULL))
				return -EINVAL;
			n_dst = a;
			touch_tx = true;
		} else if (!strcmp(tok, "oif")) {
			/* explicitly bind the carrier NIC (ifindex; 0 = resolve via FIB and pin).
			 * Only the format is validated, not existence: /proc is often configured before the NIC/route exists,
			 * the real resolution happens at session setup or first egress packet, and failures count into tx_err. */
			if (kstrtou32(eq, 0, &n_oif))
				return -EINVAL;
			touch_tx = true;
		} else if (!strcmp(tok, "ip")) {
			/* egress IP binding: it is also the outer header's source address (the outer header uses
			 * OUTER_SRC, so n_src is rewritten here as well). */
			if (!in4_pton(eq, -1, (u8 *)&a, -1, NULL))
				return -EINVAL;
			n_bind = a;
			v_ip = a;
			saw_ip = true;
			if (a)
				n_src = a;
			touch_tx = true;
		} else if (!strcmp(tok, "enabled")) {
			if (kstrtobool(eq, &b))
				return -EINVAL;
			n_enabled = b;
			touch_en = true;
		} else {
			return -EINVAL;
		}
	}

	/* transaction-level validation against the post-commit state:
	 *   1) the egress IP must belong to some local interface (address table), and if a NIC is bound too, it
	 *      must be on that NIC (address not local = -EADDRNOTAVAIL, conflict = -EINVAL);
	 *   2) the egress IP must be exactly the outer source address -- the outer header writes OUTER_SRC, and if the two
	 *      differ then "the binding" and "the source address actually sent" are not the same value.
	 * Validate only when this write actually touches the endpoint/binding (tx_src/tx_dst/oif/ip):
	 * otherwise a write that only changes enabled would be dragged down by an existing stale binding -- then not even
	 * "turn the data plane off" could be written, leaving no way out during troubleshooting. */
	if (touch_tx) {
		err = iwan_bind_ip_check(pn->net, n_bind, n_oif);
		if (err)
			return err;
		if (n_bind && n_bind != n_src)
			return -EINVAL;
		/* both tx_src and ip given in the same write but inconsistent: the two tokens set the same
		 * field; taking the later one would become "last one written wins", so reject outright.
		 * ip=0.0.0.0 is "clear the binding" and does not participate in the comparison. */
		if (saw_src && saw_ip && v_ip != 0 && v_src != v_ip)
			return -EINVAL;
	}

	if (touch_tx) {
		WRITE_ONCE(pn->tx_src, n_src);
		WRITE_ONCE(pn->tx_dst, n_dst);
		WRITE_ONCE(pn->tx_oif, n_oif);
		WRITE_ONCE(pn->tx_bind_ip, n_bind);
		/* endpoint or binding spec changed: the pinned NIC no longer represents this config */
		iwan_carrier_forget(pn);
	}
	if (touch_en)
		WRITE_ONCE(pn->enabled, n_enabled);
	return count;
}

static const struct proc_ops iwan_proc_ops = {
	.proc_read	= iwan_proc_read,
	.proc_write	= iwan_proc_write,
};

/* ---- per-netns lifecycle -----------------------------------------------
 *
 * Use only **one device-class** pernet operation, doing two things: register the netfilter hooks and create
 * /proc/net/iwan. The order is a hard constraint; this was hit before (insmod fine, but ip netns add
 * crashed the kernel, after which the module stayed stuck in "loading" forever and only a reboot helped):
 *
 *  - device-class init runs entirely after all subsys-class inits -- measured evidence: when we registered as
 *    subsys, our init ran before loopback_net_init, and register_netdevice()
 *    blew up on a not-yet-initialized netns device table.
 *  - The netfilter netns hook array and the /proc/net directory are created by
 *    the two subsys operations netfilter_net_init and proc_net_ns_init, so these must finish before we
 *    touch anything: otherwise the hooks get wiped by the subsequently initialized array, and /proc/net does not exist yet either.
 *
 * Never create NICs here: pernet init's context is subject to the ordering above, and any device created
 * would also reference the module back, making rmmod fail forever. Use rtnl_link_ops instead, created explicitly by
 * `ip link add <name> type iwan`, with the lifecycle fully owned by the kernel.
 */
static int __net_init iwan_net_init(struct net *net)
{
	struct iwan_net *pn = iwan_net_of(net);
	int err;

	pn->net = net;
	pn->enabled = true;
	/* session state: net_generic memory is already zeroed, initialize explicitly here against future changes.
	 * valid == false => the data plane takes the "module parameter defaults" fallback path, behaving bit-for-bit as before
	 * the genetlink control plane was introduced; a session can only be established by SESSION_UP. */
	memset(&pn->sess, 0, sizeof(pn->sess));
	/* shared-memory page (/dev/iwan): allocated before the RX hook, so "the hook is running"
	 * implies pn->shm is definitely non-NULL (the RX side still treats it as nullable, see iwan.h).
	 * Note that when pernet init fails the kernel does not call the matching exit (setup_net's
	 * out_undo rolls back only the ops that succeeded), so nothing may be allocated before returning an error
	 * -- which is why page allocation comes first. */
	err = iwan_shm_net_init(pn);
	if (err) {
		pr_err("netns %u: shared-memory page allocation failed %d\n", net->ns.inum, err);
		return err;
	}
	/* egress outer route cache: initialized after shm. For the same reason (a failed pernet init does not
	 * call exit), do not return an error on allocation failure here -- just mark it unavailable; the data plane
	 * degrades to a per-packet FIB lookup, with correctness unaffected. */
	if (dst_cache_init(&pn->tx_route, GFP_KERNEL)) {
		pr_warn("netns %u: egress route cache allocation failed, falling back to per-packet FIB lookup\n",
			net->ns.inum);
	} else {
		pn->tx_route_ok = true;
	}
	/*
	 * The return value is deliberately not propagated (the (void) cast makes the "intentional discard" obvious):
	 * failing netns creation is too costly -- it would make the whole netns unusable, and not even the most basic
	 * troubleshooting tools would run. On failure iwan_rx_net_init() has already pr_err'd and left
	 * pn->rx_hooked false, so the data plane is effectively off in this netns; SESSION_UP
	 * checks rx_hooked and returns -EIO (see iwan_netlink.c), so user space sees
	 * a clear failure instead of the illusion of "session succeeded but no packets arrive".
	 */
	(void)iwan_rx_net_init(pn);
	if (!net->proc_net) {
		/* normally unreachable: proc_net is created by the netns framework's subsys init.
		 * If it ever happens it only means no proc file, and a NULL pointer must never be dereferenced here. */
		pr_err("netns %u: proc_net not ready yet, skipping /proc/net/iwan\n",
		       net->ns.inum);
		return 0;
	}
	pn->proc = proc_create_data("iwan", 0644, net->proc_net,
				    &iwan_proc_ops, pn);
	return 0;
}

static void __net_exit iwan_net_exit(struct net *net)
{
	struct iwan_net *pn = iwan_net_of(net);

	/* the NIC of a session: reclaimed by the device framework when the netns is destroyed; do not touch devices here --
	 * device-class pernet exit runs under the rtnl lock, and taking rtnl again would deadlock. */
	if (pn->proc) {
		remove_proc_entry("iwan", net->proc_net);
		pn->proc = NULL;
	}
	/* order is a hard constraint: remove the hooks first (iwan_rx_net_exit's synchronize_rcu guarantees that
	 * no in-flight hook still writes the shared-memory page), then drop the page's pernet reference. The reverse order is
	 * the "hook still running, page already reclaimed" use-after-free. */
	iwan_rx_net_exit(pn);
	iwan_shm_net_exit(pn);
	/* route cache destroyed last: its dst references may point to this netns's outer devices, so wait until all in-flight
	 * references (dst_clone from skb_dst_set) are released and then drop them all. */
	if (pn->tx_route_ok)
		dst_cache_destroy(&pn->tx_route);
}

static struct pernet_operations iwan_net_ops = {
	.init = iwan_net_init,
	.exit = iwan_net_exit,
	.id   = &iwan_net_id,
	.size = sizeof(struct iwan_net),
};

/*
 * Registration order (teardown in reverse): pernet device class -> /dev/iwan (misc) -> netdev's
 * rtnl_link_ops -> genetlink family.
 *   - /dev/iwan's open() must fetch net_generic state for the opener's netns, so it must come
 *     after register_pernet_device() (pernet area first, device node second);
 *   - genetlink goes last: control-plane SESSION_UP needs rtnl_link_ops to create iwan0, so once the family
 *     is visible all dependencies must be in place; unregistering in reverse ensures commands disappear first, then device
 *     types, /dev/iwan, and pernet state are torn down.
 */
static int __init iwan_init(void)
{
	static const u8 zero[IWAN_KEY_LEN];
	int err;

	if (!memcmp(cfg.key, zero, IWAN_KEY_LEN))
		pr_warn("key is still all zeros: only for functional testing; production must use a session key\n");

	err = register_pernet_device(&iwan_net_ops);
	if (err)
		return err;
	err = iwan_shm_init();
	if (err) {
		unregister_pernet_device(&iwan_net_ops);
		return err;
	}
	err = iwan_tx_init();
	if (err) {
		iwan_shm_exit();
		unregister_pernet_device(&iwan_net_ops);
		return err;
	}
	err = iwan_netlink_init();
	if (err) {
		iwan_tx_exit();
		iwan_shm_exit();
		unregister_pernet_device(&iwan_net_ops);
		return err;
	}

	pr_info("loaded: hooknum=%d prio=%d dport=%u sid=%u enc=%d key=%s (module parameters = defaults when no session is established; control plane genetlink \"%s\" v%d; liveness /dev/%s mmap read-only, one page/netns)\n",
		cfg.hooknum, cfg.hookprio, cfg.dport, cfg.sid, cfg.enc, key_hex,
		IWAN_GENL_NAME, IWAN_GENL_VERSION, IWAN_SHM_DEV_NAME);
	return 0;
}

static void __exit iwan_exit(void)
{
	iwan_netlink_exit();
	iwan_tx_exit();
	iwan_shm_exit();
	unregister_pernet_device(&iwan_net_ops);
	pr_info("unloaded\n");
}

module_init(iwan_init);
module_exit(iwan_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("USTC iWAN");
MODULE_DESCRIPTION("iWAN zero-user-space data path: netfilter RX decap + virtual NIC TX encap");
MODULE_VERSION("0.1.0");
