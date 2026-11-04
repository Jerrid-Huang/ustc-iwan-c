// SPDX-License-Identifier: GPL-2.0
/*
 * iwan_netlink.c -- genetlink control plane (kernel side, v1).
 *
 * The ABI is frozen in kernel/iwan_genl.h; design in kernel/CONTROL-PLANE.md. This file handles:
 *   1) Family registration: netnsok = true -- all state comes from the **netns of
 *      the sending socket** (genl_info_net, from sock_net), never guessed from current's netns;
 *   2) Session setup/teardown (SESSION_UP/DOWN): create/delete iwan0 on demand
 *      via rtnl_link_ops (process context, never in pernet init);
 *   3) Session parameter updates and stats reply (SET_PEER/SET_ENABLED/GET_STATS);
 *   4) Event multicast (CTRL_FRAME/PEER_CLOSE/KEEPALIVE, called by iwan_rx.c).
 *      There is no PEER_SILENT: the kernel does no silence detection (no timer);
 *      liveness is judged entirely in user space by polling last_rx_ms in shm.
 *
 * Param convention: session state keeps the module param habit (ports in **host
 * byte order**, addrs be32); on netlink ports are be16, addrs be32, other ints host order -- converted once each way.
 *
 * Single source of truth (v1 shm page): the liveness timestamp and peer state live
 * in exactly one place -- this netns's shm page (pn->shm, see iwan_shm.h). GET_STATS
 * reads IWAN_A_LAST_KEEPALIVE_MS/IWAN_A_PEER_STATE from here; SESSION_UP/DOWN and
 * SET_ENABLED write here; struct iwan_session no longer keeps a second copy.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/timekeeping.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>

#include "iwan.h"
#include "iwan_genl.h"

/*
 * Family object (full definition at the end of the file): the reply/event builders
 * need it, and it references the command handler table -- a forward declaration breaks the cycle.
 */
static struct genl_family iwan_genl_family;

/* ------------------------------------------------------------ nla_policy */

/*
 * One table per command: attributes the command uses get a type, all others are
 * NLA_REJECT -- a wrong attribute never takes effect silently. strict_start_type is
 * deliberately avoided (old kernels lack the field); NLA_REJECT works under both strict and loose validation.
 */
#define IWAN_A_REJECT	{ .type = NLA_REJECT }

static const struct nla_policy iwan_policy_up[IWAN_A_MAX + 1] = {
	/* Required: SID/TOK/ENC/KEY/OUTER_SRC/OUTER_DST/DPORT */
	[IWAN_A_SID]		= { .type = NLA_U16 },
	[IWAN_A_TOK]		= { .type = NLA_U32 },
	[IWAN_A_ENC]		= { .type = NLA_U8 },
	[IWAN_A_KEY]		= { .type = NLA_BINARY, .len = IWAN_KEY_LEN },
	[IWAN_A_OUTER_SRC]	= { .type = NLA_BE32 },
	[IWAN_A_OUTER_DST]	= { .type = NLA_BE32 },
	[IWAN_A_DPORT]		= { .type = NLA_BE16 },
	/* Optional: SPORT omitted = use DPORT; MTU omitted = 1500-IWAN_OVERHEAD;
	 * FLAGS omitted = IWAN_A_FLAG_CREATE_DEV; OIF omitted = resolved by FIB then pinned */
	[IWAN_A_SPORT]		= { .type = NLA_BE16 },
	[IWAN_A_MTU]		= { .type = NLA_U32 },
	[IWAN_A_FLAGS]		= { .type = NLA_U32 },
	[IWAN_A_OIF]		= { .type = NLA_U32 },
	[IWAN_A_IP]		= { .type = NLA_BE32 },
	/* Outer v6 (slice 2): family = **which address pair is given**, no family switch.
	 * Both pairs given, or only half of a pair, are rejected as -EINVAL in the handler
	 * (see there); NLA_BINARY .len is an upper bound, and the handler requires exactly 16. */
	[IWAN_A_OUTER_SRC6]	= { .type = NLA_BINARY, .len = 16 },
	[IWAN_A_OUTER_DST6]	= { .type = NLA_BINARY, .len = 16 },
	[IWAN_A_IP6]		= { .type = NLA_BINARY, .len = 16 },
	[IWAN_A_CARRIER]	= IWAN_A_REJECT,
	[IWAN_A_ENABLED]	= IWAN_A_REJECT,
	[IWAN_A_DEVNAME]	= IWAN_A_REJECT,
	[IWAN_A_LAST_KEEPALIVE_MS] = IWAN_A_REJECT,
	[IWAN_A_PEER_STATE]	= IWAN_A_REJECT,
	[IWAN_A_STATS]		= IWAN_A_REJECT,
	/* Only appears in the SESSION_UP reply, not accepted as input */
	[IWAN_A_DEV_OWNED]	= IWAN_A_REJECT,
};

static const struct nla_policy iwan_policy_down[IWAN_A_MAX + 1] = {
	/* No input attributes needed, idempotent */
	[IWAN_A_SID]		= IWAN_A_REJECT,
	[IWAN_A_TOK]		= IWAN_A_REJECT,
	[IWAN_A_ENC]		= IWAN_A_REJECT,
	[IWAN_A_KEY]		= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_DST]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC6]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_DST6]	= IWAN_A_REJECT,
	[IWAN_A_IP6]		= IWAN_A_REJECT,
	[IWAN_A_DPORT]		= IWAN_A_REJECT,
	[IWAN_A_SPORT]		= IWAN_A_REJECT,
	[IWAN_A_MTU]		= IWAN_A_REJECT,
	[IWAN_A_FLAGS]		= IWAN_A_REJECT,
	[IWAN_A_ENABLED]	= IWAN_A_REJECT,
	[IWAN_A_DEVNAME]	= IWAN_A_REJECT,
	[IWAN_A_LAST_KEEPALIVE_MS] = IWAN_A_REJECT,
	[IWAN_A_PEER_STATE]	= IWAN_A_REJECT,
	[IWAN_A_STATS]		= IWAN_A_REJECT,
	/* Only appears in the SESSION_UP reply, not accepted as input */
	[IWAN_A_DEV_OWNED]	= IWAN_A_REJECT,
};

static const struct nla_policy iwan_policy_peer[IWAN_A_MAX + 1] = {
	/* Only peer address/port hot updates (drift, link change); credentials and local address need a new session */
	[IWAN_A_OUTER_DST]	= { .type = NLA_BE32 },
	/* Peer outer v6 address: changed on drift/link change (family switch = new session, not here) */
	[IWAN_A_OUTER_DST6]	= { .type = NLA_BINARY, .len = 16 },
	[IWAN_A_SPORT]		= { .type = NLA_BE16 },
	[IWAN_A_DPORT]		= { .type = NLA_BE16 },
	[IWAN_A_SID]		= IWAN_A_REJECT,
	[IWAN_A_TOK]		= IWAN_A_REJECT,
	[IWAN_A_ENC]		= IWAN_A_REJECT,
	[IWAN_A_KEY]		= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC6]	= IWAN_A_REJECT,
	[IWAN_A_IP6]		= IWAN_A_REJECT,
	[IWAN_A_MTU]		= IWAN_A_REJECT,
	[IWAN_A_FLAGS]		= IWAN_A_REJECT,
	[IWAN_A_ENABLED]	= IWAN_A_REJECT,
	[IWAN_A_DEVNAME]	= IWAN_A_REJECT,
	[IWAN_A_LAST_KEEPALIVE_MS] = IWAN_A_REJECT,
	[IWAN_A_PEER_STATE]	= IWAN_A_REJECT,
	[IWAN_A_STATS]		= IWAN_A_REJECT,
	/* Only appears in the SESSION_UP reply, not accepted as input */
	[IWAN_A_DEV_OWNED]	= IWAN_A_REJECT,
};

static const struct nla_policy iwan_policy_enabled[IWAN_A_MAX + 1] = {
	[IWAN_A_ENABLED]	= { .type = NLA_U8 },
	[IWAN_A_SID]		= IWAN_A_REJECT,
	[IWAN_A_TOK]		= IWAN_A_REJECT,
	[IWAN_A_ENC]		= IWAN_A_REJECT,
	[IWAN_A_KEY]		= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_DST]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC6]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_DST6]	= IWAN_A_REJECT,
	[IWAN_A_IP6]		= IWAN_A_REJECT,
	[IWAN_A_DPORT]		= IWAN_A_REJECT,
	[IWAN_A_SPORT]		= IWAN_A_REJECT,
	[IWAN_A_MTU]		= IWAN_A_REJECT,
	[IWAN_A_FLAGS]		= IWAN_A_REJECT,
	[IWAN_A_DEVNAME]	= IWAN_A_REJECT,
	[IWAN_A_LAST_KEEPALIVE_MS] = IWAN_A_REJECT,
	[IWAN_A_PEER_STATE]	= IWAN_A_REJECT,
	[IWAN_A_STATS]		= IWAN_A_REJECT,
	/* Only appears in the SESSION_UP reply, not accepted as input */
	[IWAN_A_DEV_OWNED]	= IWAN_A_REJECT,
};

static const struct nla_policy iwan_policy_stats[IWAN_A_MAX + 1] = {
	/* No input: only one snapshot for this netns (per-netns dump: see the TODO in GET_STATS) */
	[IWAN_A_SID]		= IWAN_A_REJECT,
	[IWAN_A_TOK]		= IWAN_A_REJECT,
	[IWAN_A_ENC]		= IWAN_A_REJECT,
	[IWAN_A_KEY]		= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_DST]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC6]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_DST6]	= IWAN_A_REJECT,
	[IWAN_A_IP6]		= IWAN_A_REJECT,
	[IWAN_A_DPORT]		= IWAN_A_REJECT,
	[IWAN_A_SPORT]		= IWAN_A_REJECT,
	[IWAN_A_MTU]		= IWAN_A_REJECT,
	[IWAN_A_FLAGS]		= IWAN_A_REJECT,
	[IWAN_A_ENABLED]	= IWAN_A_REJECT,
	[IWAN_A_DEVNAME]	= IWAN_A_REJECT,
	[IWAN_A_LAST_KEEPALIVE_MS] = IWAN_A_REJECT,
	[IWAN_A_PEER_STATE]	= IWAN_A_REJECT,
	[IWAN_A_STATS]		= IWAN_A_REJECT,
	/* Only appears in the SESSION_UP reply, not accepted as input */
	[IWAN_A_DEV_OWNED]	= IWAN_A_REJECT,
};

/* Index of the multicast group in mcgrps[] (the group argument of genlmsg_multicast_netns) */
enum { IWAN_MCGRP_EVENTS_IDX = 0 };

/* ------------------------------------------------------------ permissions */

/*
 * Consistent with the /proc/net/iwan write path and with rtnetlink's own rule:
 * the sending socket needs CAP_NET_ADMIN in the **target netns user_ns**.
 * GENL_ADMIN_PERM is deliberately unused: it checks init_user_ns, needlessly denying rootless netns config.
 */
static bool iwan_genl_capable(const struct sk_buff *skb, const struct net *net)
{
	return netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN);
}

/* ------------------------------------------------------------ device (iwan0) */

struct iwan_dev_info {
	char	name[IFNAMSIZ];
	u32	mtu;
	int	ifindex;
	bool	ours;	/* is an iwan-kind device (rtnl_link_ops matches) */
	bool	owned;	/* created by the module (incl. by an earlier session); SESSION_DOWN deletes it */
};

/*
 * Create iwan0 in this netns on demand, or reuse the one already there.
 *
 * Called only from the genetlink doit (process context): during pernet init the
 * device table is not ready yet, and creating a device there replays the
 * rtnl_fill_ifinfo oops (see the comment in iwan_core.c). rtnl_create_link()
 * behaviour varies by kernel version (some only allocate, the caller registers);
 * registration is completed here based on reg_state, both paths agree. A device
 * built/reused is set UP as well: SESSION_UP means "data plane ready"; manual config beyond up/addr/route stays user space's (CONTROL-PLANE section 6).
 *
 * Device kind gate (the key constraint here): a same-name device **not** built by
 * this module (dev->rtnl_link_ops != &iwan_link_ops) is always refused, -EBUSY:
 *   - this project's iwan-client builds iwan0 with TUN for a real tunnel, and TUN
 *     and iwan share ARPHRD 65534 (ARPHRD_TUNNEL), so name/type cannot tell them apart;
 *   - the old implementation only pr_warn'd and **kept reusing it**: user space got
 *     a "success" reply while the data plane was dead (ciphertext packets TUN gets
 *     never reach our hooks), and it later even changed that device's MTU, which
 *     cuts off the user's running tunnel; so: no reuse, no UP, no MTU touch, failure stays visible.
 *
 * Ownership is tracked by ifindex (prev_ifindex), not by name: a device can be
 * renamed, and then SESSION_DOWN cannot find it by name, so it "reports success
 * while the device is still there and dev_owned remains". Conversely the kernel
 * reuses ifindexes (a new device often gets the same number), so "it is the same device" requires both prev_owned and ifindex.
 */
static int iwan_dev_ensure(struct net *net, u32 req_mtu, bool create,
			   bool prev_owned, int prev_ifindex,
			   struct iwan_dev_info *out)
{
	struct net_device *dev;
	/*
	 * rtnl_create_link() takes tb as an IFLA_* attribute array; this kernel reads
	 * tb[IFLA_NUM_TX_QUEUES] unconditionally on entry (+0x22, 0xf8(%tb)) and
	 * **does not accept NULL**. Measured consequence of NULL: NULL deref while
	 * holding the rtnl lock -> the task exits with the lock held (log "exited with
	 * irqs disabled") -> the routing/net subsystem and dependent user space hang; the
	 * box looks frozen (ping still works, SSH unresponsive, cannot switch TTY). An all-zero array means "no attributes", num_tx_queues takes the default.
	 */
	struct nlattr *tb[IFLA_MAX + 1] = {};
	bool created = false;
	int err;

	memset(out, 0, sizeof(*out));
	strscpy(out->name, "-", sizeof(out->name));
	out->mtu = req_mtu;

	rtnl_lock();
	dev = __dev_get_by_name(net, IWAN_DEV_NAME);
	if (dev)
		goto have_dev;
	if (!create) {
		rtnl_unlock();
		return 0;	/* no create and not present: only echo the requested MTU */
	}

	dev = rtnl_create_link(net, IWAN_DEV_NAME, NET_NAME_UNKNOWN,
			       &iwan_link_ops, tb, NULL);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		rtnl_unlock();
		pr_err("netns %u: create %s failed: %d\n",
		       net->ns.inum, IWAN_DEV_NAME, err);
		return err;
	}
	if (dev->reg_state != NETREG_REGISTERED) {
		err = register_netdevice(dev);
		if (err) {
			free_netdev(dev);
			rtnl_unlock();
			pr_err("netns %u: register %s failed: %d\n",
			       net->ns.inum, IWAN_DEV_NAME, err);
			return err;
		}
	}
	/* Finish the rtnl link creation: mark RTNL_LINK_INITIALIZED and notify RTNLGRP_LINK,
	 * the step `ip link add` also completes. The return value must be checked (the old
	 * implementation dropped it): failure means the device is not initialized and a
	 * half-built entry stays in the registry -- delete it and return the error rather than let user space think "device ready". */
	err = rtnl_configure_link(dev, NULL, 0, NULL);
	if (err) {
		pr_err("netns %u: configure %s failed: %d\n", net->ns.inum, dev->name, err);
		rtnl_delete_link(dev, 0, NULL);
		rtnl_unlock();
		return err;
	}
	created = true;

have_dev:
	strscpy(out->name, dev->name, sizeof(out->name));
	out->mtu = dev->mtu;
	out->ifindex = dev->ifindex;
	out->ours = (dev->rtnl_link_ops == &iwan_link_ops);
	if (!out->ours) {
		pr_err("netns %u: %s is taken by a non-iwan device (kind=%s ifindex=%d), refusing to reuse\n",
		       net->ns.inum, dev->name,
		       dev->rtnl_link_ops && dev->rtnl_link_ops->kind ?
				dev->rtnl_link_ops->kind : "?",
		       dev->ifindex);
		rtnl_unlock();
		return -EBUSY;
	} else if (created || !(dev->flags & IFF_UP)) {
		/* A freshly created device is necessarily DOWN, and so is an existing one that is
		 * not up yet. Direct assignment matches setup(): dev_set_mtu() is deliberately
		 * not called -- it can emit a NETDEV_CHANGEMTU notification (better observability)
		 * and does MTU range validation, but whether it takes rtnl again internally varies
		 * by kernel version, and rtnl is already held here, so re-entry would deadlock.
		 * Trade-off: one notification is not worth a machine-wide hang; the device is
		 * fresh/not UP, nothing else relies on this MTU change, and the range was already checked at SESSION_UP entry (IWAN_MIN_MTU..IWAN_MAX_MTU). */
		dev->mtu = req_mtu;
		if (!(dev->flags & IFF_UP)) {
			/* SESSION_UP promises "data plane ready": the device must be UP, otherwise user
			 * space still has to run ip link set up itself (acceptance T2b/T2d checks exactly that). */
			err = dev_open(dev, NULL);
			if (err) {
				pr_err("netns %u: open %s failed: %d\n",
				       net->ns.inum, dev->name, err);
				if (created)
					rtnl_delete_link(dev, 0, NULL);
				rtnl_unlock();
				return err;
			}
		}
		out->mtu = dev->mtu;
	} else if (dev->mtu != (int)req_mtu) {
		pr_info("netns %u: %s is up already, ignoring MTU=%u (actual %u; use ip link set mtu to change)\n",
			net->ns.inum, dev->name, req_mtu, dev->mtu);
	}
	/* Ownership: created now, or created by an earlier session with the device
	 * identity (ifindex) unchanged => SESSION_DOWN deletes it. Both details are
	 * deliberate: not claimed by name, so a renamed device can still be deleted;
	 * and not dev_owned alone, because ifindex is reused -- if the user deletes our
	 * device and creates a different one with the same number, the flag alone would
	 * delete the wrong device. Residual window (known, accepted): the user deletes
	 * our device, creates an **iwan-kind** device, and the kernel happens to assign
	 * it the same ifindex, so it is misidentified as "the same one". Triggering it
	 * takes all three at once and the deleted one is still an iwan device we serve (not the user's TUN); by-name claiming has a much larger window (same name = hit). */
	out->owned = created || (prev_owned && prev_ifindex &&
				 prev_ifindex == dev->ifindex);
	rtnl_unlock();
	return 0;
}

/* Delete a module-created NIC: via rtnl_link_ops -> dellink, i.e. the same path as `ip link del`.
 *
 * Locating the device prefers the ifindex (recorded at session claim) and falls
 * back to the name only if missing: after a rename, lookup by name reports "not
 * found -> success" while the device is still there. Both gates must pass: kind
 * must be this module's rtnl_link_ops (never a same-name device of another kind, e.g. the user's own TUN iwan0) and ifindex must match the session record. */
static int iwan_dev_remove(struct net *net, const char *name, int ifindex)
{
	struct net_device *dev;
	int err = 0;

	rtnl_lock();
	dev = ifindex ? __dev_get_by_index(net, ifindex) :
			__dev_get_by_name(net, name);
	if (!dev)
		goto out;			/* already gone: delete is idempotent */
	if (dev->rtnl_link_ops != &iwan_link_ops) {
		pr_warn("netns %u: ifindex %d (%s) is not an iwan device, not deleting\n",
			net->ns.inum, dev->ifindex, dev->name);
		goto out;
	}
	err = rtnl_delete_link(dev, 0, NULL);
out:
	rtnl_unlock();
	return err;
}

/* Device name in the snapshot: with a session use the recorded name; without one,
 * look up the same-name device in this netns to compare with `ip link` (return "-" if not found). */
static void iwan_devname_of(struct net *net, const struct iwan_session *s,
			    char *out, size_t len)
{
	struct net_device *dev;

	if (READ_ONCE(s->valid) && s->devname[0]) {
		strscpy(out, s->devname, len);
		return;
	}
	strscpy(out, "-", len);
	rtnl_lock();
	dev = __dev_get_by_name(net, IWAN_DEV_NAME);
	if (dev)
		strscpy(out, dev->name, len);
	rtnl_unlock();
}

/* ------------------------------------------------------------ reply/snapshot */

#define IWAN_PUT_CTR(skb, pn, attr, field)				\
	do {								\
		u64 __v = (u64)atomic64_read(&(pn)->st.field);		\
									\
		if (nla_put((skb), (attr), (int)sizeof(__v), &__v))	\
			goto nla_put_failure;				\
	} while (0)

/* Counter nest (IWAN_A_STATS). u64 uses a plain attribute: nla_get_u64 on the
 * receive side is a memcpy, so no 8-byte alignment is needed and no pad attribute has to be inserted into the attribute stream. */
static int iwan_genl_put_stats(struct sk_buff *skb, struct iwan_net *pn)
{
	struct nlattr *nest = nla_nest_start(skb, IWAN_A_STATS);

	if (!nest)
		return -EMSGSIZE;
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_PKTS, rx_pkts);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_OUTER, rx_outer);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_REASM, rx_reasm);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_FRAMES, rx_frames);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_DELIVERED, rx_delivered);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_BATCH, rx_batch);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_BATCH_SKIP, rx_batch_skip);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_BAD_HDR, rx_bad_hdr);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_BAD_INNER, rx_bad_inner);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_NOMEM, rx_nomem);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_CTRL_FRAME, rx_ctrl_frame);
	IWAN_PUT_CTR(skb, pn, IWAN_S_TX_PKTS, tx_pkts);
	IWAN_PUT_CTR(skb, pn, IWAN_S_TX_BYTES, tx_bytes);
	IWAN_PUT_CTR(skb, pn, IWAN_S_TX_BAD_STATE, tx_bad_state);
	IWAN_PUT_CTR(skb, pn, IWAN_S_TX_BAD_INNER, tx_bad_inner);
	IWAN_PUT_CTR(skb, pn, IWAN_S_TX_ERR, tx_err);
	IWAN_PUT_CTR(skb, pn, IWAN_S_EV_DROPPED, ev_dropped);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_FRAG6, rx_frag6);
	nla_nest_end(skb, nest);
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

/*
 * Config snapshot (session first, module param fallback, same source as the data
 * plane iwan_dp_get) + keepalive timestamp + peer_state + all counters. Without a
 * session it returns exactly the "module parameter defaults" layer; the /proc/net/iwan read path is unaffected.
 */
static int iwan_genl_put_snapshot(struct sk_buff *skb, struct iwan_net *pn,
				  const char *devname)
{
	struct iwan_session *s = &pn->sess;
	struct iwan_dp dp;
	u64 keepalive;
	u32 flags = 0;
	u32 mtu;
	u16 sport;

	iwan_dp_get(pn, iwan_cfg_get(), false, &dp);
	mtu = READ_ONCE(s->valid) ? READ_ONCE(s->mtu) : (1500 - IWAN_OVERHEAD);
	if (READ_ONCE(s->create_dev))
		flags |= IWAN_A_FLAG_CREATE_DEV;
	/* With SPORT omitted (0) the wire uses DPORT; the reply gives the effective value */
	sport = dp.sport ? dp.sport : dp.dport;
	/* The keepalive timestamp and peer_state both come from this netns's shm page
	 * (/dev/iwan, user-space mmap reads the same copy): single source, no second copy. */
	keepalive = iwan_shm_last_rx_ms(pn);

	if (nla_put_u16(skb, IWAN_A_SID, dp.sid) ||
	    nla_put_u32(skb, IWAN_A_TOK, dp.tok) ||
	    nla_put_u8(skb, IWAN_A_ENC, dp.enc) ||
	    nla_put(skb, IWAN_A_KEY, IWAN_KEY_LEN, dp.key) ||
	    nla_put_be32(skb, IWAN_A_OUTER_SRC, dp.outer_src) ||
	    nla_put_be32(skb, IWAN_A_OUTER_DST, dp.outer_dst) ||
	    /* Only outer-v6 sessions send these three attributes (v4 sends none): family is
	     * expressed by "attribute present or not", same rule as the SESSION_UP input --
	     * judging by "all-zero v6 address" would mix "v6 session without bound IP" and "v4 session". */
	    (dp.outer_v6 && nla_put(skb, IWAN_A_OUTER_SRC6,
				    sizeof(dp.outer_src6), &dp.outer_src6)) ||
	    (dp.outer_v6 && nla_put(skb, IWAN_A_OUTER_DST6,
				    sizeof(dp.outer_dst6), &dp.outer_dst6)) ||
	    (dp.outer_v6 && nla_put(skb, IWAN_A_IP6, sizeof(s->bind_ip6),
				    &s->bind_ip6)) ||
	    nla_put_be16(skb, IWAN_A_DPORT, htons(dp.dport)) ||
	    nla_put_be16(skb, IWAN_A_SPORT, htons(sport)) ||
	    nla_put_u32(skb, IWAN_A_MTU, mtu) ||
	    nla_put_u32(skb, IWAN_A_FLAGS, flags) ||
	    nla_put_u8(skb, IWAN_A_ENABLED, dp.enabled ? 1 : 0) ||
	    /* Binding spec and resolution result: control-plane reconciliation input. carrier is
	     * the one that **actually** took effect (decided at session setup, 0 = unresolved),
	     * and together with the requested oif/ip it shows whether "wanted" and "got" agree. */
	    nla_put_u32(skb, IWAN_A_OIF, READ_ONCE(s->oif)) ||
	    nla_put_be32(skb, IWAN_A_IP, READ_ONCE(s->bind_ip)) ||
	    nla_put_u32(skb, IWAN_A_CARRIER, READ_ONCE(pn->carrier)) ||
	    nla_put_string(skb, IWAN_A_DEVNAME, devname) ||
	    nla_put(skb, IWAN_A_LAST_KEEPALIVE_MS, (int)sizeof(keepalive),
		    &keepalive) ||
	    nla_put_u8(skb, IWAN_A_PEER_STATE,
		       (u8)iwan_shm_peer_state(pn)) ||
	    iwan_genl_put_stats(skb, pn))
		return -EMSGSIZE;
	return 0;
}

static int iwan_genl_reply_snapshot(struct genl_info *info, u8 cmd,
				    const char *devname)
{
	struct sk_buff *rep;
	void *hdr;

	rep = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!rep)
		return -ENOMEM;
	hdr = genlmsg_put_reply(rep, info, &iwan_genl_family, 0, cmd);
	if (!hdr || iwan_genl_put_snapshot(rep, iwan_net_of(genl_info_net(info)),
					   devname)) {
		nlmsg_free(rep);
		return -EMSGSIZE;
	}
	genlmsg_end(rep, hdr);
	return genlmsg_reply(rep, info);
}

/* SESSION_UP reply: device name + actual MTU + device ownership (CONTROL-PLANE section 3) */
static int iwan_genl_reply_up(struct genl_info *info, const char *devname,
			      u32 mtu, bool owned)
{
	struct sk_buff *rep;
	void *hdr;

	rep = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!rep)
		return -ENOMEM;
	hdr = genlmsg_put_reply(rep, info, &iwan_genl_family, 0,
				IWAN_CMD_SESSION_UP);
	if (!hdr ||
	    nla_put_string(rep, IWAN_A_DEVNAME, devname) ||
	    nla_put_u32(rep, IWAN_A_MTU, mtu) ||
	    /* DEV_OWNED: 1 = this device was built/claimed by the module (SESSION_DOWN deletes
	     * it), 0 = not built by us (e.g. an iwan device the user added with ip link add).
	     * Plain host-order u32, consistent with the other scalars in this table; old
	     * clients do not know the attribute and just ignore it per genetlink convention. */
	    nla_put_u32(rep, IWAN_A_DEV_OWNED, owned ? 1 : 0)) {
		nlmsg_free(rep);
		return -EMSGSIZE;
	}
	genlmsg_end(rep, hdr);
	return genlmsg_reply(rep, info);
}

/* ------------------------------------------------------------ commands */

static int iwan_genl_session_up(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct iwan_net *pn = iwan_net_of(net);
	struct iwan_session *s = &pn->sess;
	struct iwan_dev_info dev;
	struct iwan_session req;
	const char *conflict = NULL;
	bool was_valid;
	u32 flags, mtu;
	int err;

	if (!iwan_genl_capable(skb, net))
		return -EPERM;

	/*
	 * RX hook gate: the return value of iwan_rx_net_init() is deliberately not
	 * propagated in iwan_core.c (failing the whole netns would be too costly); on
	 * failure pn->rx_hooked stays false. Such a netns has a dead data plane: no hook
	 * installed, so no inbound packet is ever decapsulated. If we let it through,
	 * user space gets "SESSION_UP ok + iwan0 UP" yet never receives a packet, and troubleshooting would blame the peer; so fail explicitly here.
	 */
	if (!READ_ONCE(pn->rx_hooked)) {
		GENL_SET_ERR_MSG(info, "RX hook not installed in this netns (nf_register_net_hook failed); data plane unavailable");
		pr_err("netns %u: SESSION_UP rejected: RX hook not installed (see iwan_rx_net_init log)\n",
		       net->ns.inum);
		return -EIO;
	}

	/* Required attributes; only SPORT (omitted = use DPORT), MTU (omitted =
	 * 1500-IWAN_OVERHEAD) and FLAGS (omitted = CREATE_DEV) have documented defaults.
	 * The outer address must come as **exactly one pair**: v4's (OUTER_SRC, OUTER_DST)
	 * or v6's (OUTER_SRC6, OUTER_DST6) -- the pair given selects the family, no
	 * separate switch (both families at once is ambiguous: one outer header version only). */
	if (!info->attrs[IWAN_A_SID] || !info->attrs[IWAN_A_TOK] ||
	    !info->attrs[IWAN_A_ENC] || !info->attrs[IWAN_A_KEY] ||
	    !info->attrs[IWAN_A_DPORT]) {
		GENL_SET_ERR_MSG(info, "SESSION_UP needs SID/TOK/ENC/KEY/DPORT and an outer address pair (OUTER_SRC+OUTER_DST or OUTER_SRC6+OUTER_DST6)");
		return -EINVAL;
	}
	if (nla_len(info->attrs[IWAN_A_KEY]) != IWAN_KEY_LEN) {
		GENL_SET_ERR_MSG(info, "KEY must be 8 bytes");
		return -EINVAL;
	}

	memset(&req, 0, sizeof(req));
	req.sid = nla_get_u16(info->attrs[IWAN_A_SID]);
	req.tok = nla_get_u32(info->attrs[IWAN_A_TOK]);
	req.enc = nla_get_u8(info->attrs[IWAN_A_ENC]);
	memcpy(req.key, nla_data(info->attrs[IWAN_A_KEY]), IWAN_KEY_LEN);
	{
		const bool any4 = info->attrs[IWAN_A_OUTER_SRC] ||
				  info->attrs[IWAN_A_OUTER_DST];
		const bool pair4 = info->attrs[IWAN_A_OUTER_SRC] &&
				   info->attrs[IWAN_A_OUTER_DST];
		const bool any6 = info->attrs[IWAN_A_OUTER_SRC6] ||
				  info->attrs[IWAN_A_OUTER_DST6];
		const bool pair6 = info->attrs[IWAN_A_OUTER_SRC6] &&
				   info->attrs[IWAN_A_OUTER_DST6];

		if (!pair4 && !pair6) {
			GENL_SET_ERR_MSG(info, "outer addresses must be paired: OUTER_SRC+OUTER_DST (v4) or OUTER_SRC6+OUTER_DST6 (v6)");
			return -EINVAL;
		}
		if (any4 && any6) {
			GENL_SET_ERR_MSG(info, "outer address family must be unique: the v4 and v6 pairs cannot both be given");
			return -EINVAL;
		}
		if (pair6) {
			if (nla_len(info->attrs[IWAN_A_OUTER_SRC6]) !=
					sizeof(struct in6_addr) ||
			    nla_len(info->attrs[IWAN_A_OUTER_DST6]) !=
					sizeof(struct in6_addr)) {
				GENL_SET_ERR_MSG(info, "OUTER_SRC6/OUTER_DST6 must be 16 bytes");
				return -EINVAL;
			}
			req.outer_v6 = true;
			nla_memcpy(&req.outer_src6,
				   info->attrs[IWAN_A_OUTER_SRC6],
				   sizeof(req.outer_src6));
			nla_memcpy(&req.outer_dst6,
				   info->attrs[IWAN_A_OUTER_DST6],
				   sizeof(req.outer_dst6));
		} else {
			req.outer_src = nla_get_be32(info->attrs[IWAN_A_OUTER_SRC]);
			req.outer_dst = nla_get_be32(info->attrs[IWAN_A_OUTER_DST]);
		}
	}
	req.dport = ntohs(nla_get_be16(info->attrs[IWAN_A_DPORT]));
	if (info->attrs[IWAN_A_SPORT])
		req.sport = ntohs(nla_get_be16(info->attrs[IWAN_A_SPORT]));
	/* The MTU default must count the overhead of **this session's family**: outer v6
	 * costs 20B more than v4, so the v4 default would make the default config violate the MTU check below on a 1500 carrier. */
	mtu = info->attrs[IWAN_A_MTU] ? nla_get_u32(info->attrs[IWAN_A_MTU]) :
		(u32)(1500 - (req.outer_v6 ? IWAN_OVERHEAD_V6 : IWAN_OVERHEAD));
	flags = info->attrs[IWAN_A_FLAGS] ?
		nla_get_u32(info->attrs[IWAN_A_FLAGS]) : IWAN_A_FLAG_CREATE_DEV;
	/* Omitted = 0 = unspecified: resolved once by the FIB and then pinned (see iwan_tx.c) */
	req.oif = info->attrs[IWAN_A_OIF] ?
		nla_get_u32(info->attrs[IWAN_A_OIF]) : 0;
	/* Omitted = 0 = no egress-IP binding; if given it must be a local address and
	 * must be on the same interface as oif (if also given) -- see the explicit checks below. */
	req.bind_ip = info->attrs[IWAN_A_IP] ?
		nla_get_be32(info->attrs[IWAN_A_IP]) : 0;
	/* On outer v6, "IP binding" is IWAN_A_IP6 (same semantics: the egress address must
	 * equal the outer source address and belong to some local interface). One entry
	 * per family; the wrong family is -EINVAL, never converted implicitly. */
	if (info->attrs[IWAN_A_IP6]) {
		if (!req.outer_v6) {
			GENL_SET_ERR_MSG(info, "IWAN_A_IP6 is only for outer-v6 sessions");
			return -EINVAL;
		}
		if (nla_len(info->attrs[IWAN_A_IP6]) != sizeof(struct in6_addr)) {
			GENL_SET_ERR_MSG(info, "IWAN_A_IP6 must be 16 bytes");
			return -EINVAL;
		}
		nla_memcpy(&req.bind_ip6, info->attrs[IWAN_A_IP6],
			   sizeof(req.bind_ip6));
	} else if (info->attrs[IWAN_A_IP] && req.outer_v6) {
		GENL_SET_ERR_MSG(info, "IWAN_A_IP is the v4 egress address; use IWAN_A_IP6 for outer v6");
		return -EINVAL;
	}

	/* Self-consistency check: the data plane filters on exactly this 5-tuple, none may be missing */
	if (!req.dport || req.enc > 1 ||
	    (req.outer_v6 ? (ipv6_addr_any(&req.outer_src6) ||
			     ipv6_addr_any(&req.outer_dst6))
			  : (!req.outer_src || !req.outer_dst)) ||
	    mtu < IWAN_MIN_MTU ||
	    /* Upper bound = module param max_mtu, then clamped once more by the spec hard
	     * limit. The hard limit differs by family: outer v4 total length is only 16 bits
	     * (above 65499 tot_len overflows); outer v6 payload length is 16 bits too, but
	     * the base header is 20 bytes larger, so its hard limit is 20 lower (IWAN_MTU_HARD_MAX_V6). */
	    mtu > min_t(u32, READ_ONCE(iwan_cfg_get()->max_mtu),
			(u32)(req.outer_v6 ? IWAN_MTU_HARD_MAX_V6 :
					     IWAN_MTU_HARD_MAX)) ||
	    (flags & ~IWAN_A_FLAG_CREATE_DEV)) {
		GENL_SET_ERR_MSG(info, "invalid params: outer address/port must not be 0, ENC in {0,1}, "
				      "MTU out of range; FLAGS only defines CREATE_DEV (bit0), "
				      "bit1 is reserved (proxy reply not implemented), setting it is rejected");
		if (req.outer_v6)
			pr_info("netns %u: SESSION_UP invalid params src=%pI6c dst=%pI6c dport=%u enc=%u mtu=%u\n",
				net->ns.inum, &req.outer_src6,
				&req.outer_dst6, req.dport, req.enc, mtu);
		else
			pr_info("netns %u: SESSION_UP invalid params src=%pI4 dst=%pI4 dport=%u enc=%u mtu=%u\n",
				net->ns.inum, &req.outer_src,
				&req.outer_dst, req.dport, req.enc, mtu);
		return -EINVAL;
	}

	/* Conflict with an existing session: sid/tok/key/enc/outer endpoints are session
	 * identity, changing them needs SESSION_DOWN first (peer drift uses SET_PEER).
	 * Identical params = idempotent replay: refresh only device and switches, do not reset keepalive/peer_state. */
	was_valid = READ_ONCE(s->valid);
	if (was_valid) {
		if (req.sid != READ_ONCE(s->sid))
			conflict = "sid";
		else if (req.tok != READ_ONCE(s->tok))
			conflict = "tok";
		else if (memcmp(req.key, s->key, IWAN_KEY_LEN))
			conflict = "key";
		else if (req.enc != READ_ONCE(s->enc))
			conflict = "enc";
		else if (req.outer_v6 != READ_ONCE(s->outer_v6))
			conflict = "outer_family";
		else if (req.outer_v6 &&
			 !ipv6_addr_equal(&req.outer_src6, &s->outer_src6))
			conflict = "outer_src6";
		else if (req.outer_v6 &&
			 !ipv6_addr_equal(&req.outer_dst6, &s->outer_dst6))
			conflict = "outer_dst6";
		else if (!req.outer_v6 &&
			 req.outer_src != READ_ONCE(s->outer_src))
			conflict = "outer_src";
		else if (!req.outer_v6 &&
			 req.outer_dst != READ_ONCE(s->outer_dst))
			conflict = "outer_dst";
		else if (!ipv6_addr_equal(&req.bind_ip6, &s->bind_ip6))
			conflict = "ip6";
		else if (req.dport != READ_ONCE(s->dport))
			conflict = "dport";
		else if (req.sport != READ_ONCE(s->sport))
			conflict = "sport";
		else if (req.oif != READ_ONCE(s->oif))
			conflict = "oif";
		else if (req.bind_ip != READ_ONCE(s->bind_ip))
			conflict = "ip";
		if (conflict) {
			GENL_SET_ERR_MSG(info, "SESSION_UP conflicts with the existing session (field name in dmesg)");
			pr_info("netns %u: SESSION_UP rejected: %s differs from the existing session (SESSION_DOWN first; use SET_PEER for endpoint drift)\n",
				net->ns.inum, conflict);
			return -EINVAL;
		}
	}

	/* Device: create/reuse on demand (this netns only; never during pernet init).
	 * prev_owned/prev_ifindex take **no was_valid condition**: if the previous
	 * SESSION_DOWN failed to delete the device, valid is already cleared while
	 * dev_owned/dev_ifindex remain, and the device that session left behind must be
	 * claimed by the next SESSION_UP -- the old implementation wrote
	 * `was_valid && dev_owned`, so "DOWN failed -> UP again" wiped ownership and nobody could ever delete that device (permanent leak). */
	err = iwan_dev_ensure(net, mtu, flags & IWAN_A_FLAG_CREATE_DEV,
			      READ_ONCE(s->dev_owned),
			      READ_ONCE(s->dev_ifindex), &dev);
	if (err)
		return err;

	/* Write session state: valid is set last so the data plane never reads half a credential set */
	WRITE_ONCE(s->enabled, true);
	WRITE_ONCE(s->create_dev, !!(flags & IWAN_A_FLAG_CREATE_DEV));
	WRITE_ONCE(s->dev_owned, dev.owned);
	WRITE_ONCE(s->dev_ifindex, dev.ifindex);
	WRITE_ONCE(s->enc, req.enc);
	WRITE_ONCE(s->sid, req.sid);
	WRITE_ONCE(s->tok, req.tok);
	memcpy(s->key, req.key, IWAN_KEY_LEN);
	/* Outer family and endpoints: write only the current family and zero the other --
	 * iwan_dp_get() copies both to the data plane, and keeping stale addresses of one
	 * family would force "which family is bound" to be inferred from a flag (iwan_dp_bound() would have to look at both families' bind_ip). */
	WRITE_ONCE(s->outer_v6, req.outer_v6);
	if (req.outer_v6) {
		s->outer_src6 = req.outer_src6;
		s->outer_dst6 = req.outer_dst6;
		WRITE_ONCE(s->outer_src, 0);
		WRITE_ONCE(s->outer_dst, 0);
	} else {
		WRITE_ONCE(s->outer_src, req.outer_src);
		WRITE_ONCE(s->outer_dst, req.outer_dst);
		memset(&s->outer_src6, 0, sizeof(s->outer_src6));
		memset(&s->outer_dst6, 0, sizeof(s->outer_dst6));
	}
	s->bind_ip6 = req.bind_ip6;
	WRITE_ONCE(s->dport, req.dport);
	WRITE_ONCE(s->sport, req.sport);
	WRITE_ONCE(s->oif, req.oif);
	WRITE_ONCE(s->bind_ip, req.bind_ip);
	/*
	 * Store the **effective value** rather than the requested one: when the device
	 * already exists and is UP, iwan_dev_ensure() ignores the requested MTU (see its
	 * 256-258 branch), so recording the requested value would make GET_STATS report an MTU that never took effect, contradicting the ABI's "report the measured value".
	 */
	WRITE_ONCE(s->mtu, dev.mtu);
	strscpy(s->devname, dev.name, sizeof(s->devname));

	/*
	 * Carrier NIC: resolved once at session setup and pinned (an explicit binding
	 * strictly uses the bound NIC). Must complete before valid is set -- the data
	 * plane (including RX NIC filtering) only trusts this published result. Failure
	 * semantics differ by binding mode:
	 *   - explicit binding => reject the session: binding means no drift, so report
	 *     an error at the control plane rather than silently switch to another NIC
	 *     (all we can judge is "the resolved NIC is the bound one"; when bound to a
	 *     NIC with no return route the kernel synthesizes a scope link route, and
	 *     that black hole cannot be judged at the control plane);
	 *   - no explicit binding => log only, resolve again when the first packet
	 *     egresses (routes may be ready by then). Fields are written, valid is not, so rejection exposes no half state; dev_owned/dev_ifindex were recorded above, so the device is not lost.
	 */
	if (req.outer_v6 && !ipv6_addr_any(&req.bind_ip6)) {
		/* v6 "IP binding": mirrors v4 item by item (belongs to a local interface + equals outer source) */
		int aerr = iwan_bind_ip_check6(net, &req.bind_ip6, req.oif);

		if (aerr == -EADDRNOTAVAIL) {
			GENL_SET_ERR_MSG(info, "the bound egress IP does not belong to any local interface");
			pr_info("netns %u: SESSION_UP rejected: egress IP %pI6c is not in the local address table (strict: tentative addresses do not count)\n",
				net->ns.inum, &req.bind_ip6);
			return aerr;
		}
		if (aerr) {
			GENL_SET_ERR_MSG(info, "the bound egress IP is not on the specified carrier NIC");
			pr_info("netns %u: SESSION_UP rejected: egress IP %pI6c is not on the bound NIC ifindex=%u\n",
				net->ns.inum, &req.bind_ip6, req.oif);
			return aerr;
		}
		if (!ipv6_addr_equal(&req.bind_ip6, &req.outer_src6)) {
			GENL_SET_ERR_MSG(info, "the bound egress IP must match OUTER_SRC6");
			pr_info("netns %u: SESSION_UP rejected: egress IP %pI6c does not match outer source %pI6c\n",
				net->ns.inum, &req.bind_ip6, &req.outer_src6);
			return -EINVAL;
		}
	} else if (req.bind_ip) {
		/* The two hard requirements of "IP binding" are checked separately so errors point
		 * at the exact one: - the address must belong to some local interface (the address
		 * table is the only source of truth for "which NIC holds this IP"); - it is also
		 * the outer header source, so it must equal OUTER_SRC. */
		int aerr = iwan_bind_ip_check(net, req.bind_ip, req.oif);

		if (aerr == -EADDRNOTAVAIL) {
			GENL_SET_ERR_MSG(info, "the bound egress IP does not belong to any local interface");
			pr_info("netns %u: SESSION_UP rejected: egress IP %pI4 is not in the local address table\n",
				net->ns.inum, &req.bind_ip);
			return aerr;
		}
		if (aerr) {
			GENL_SET_ERR_MSG(info, "the bound egress IP is not on the specified carrier NIC");
			pr_info("netns %u: SESSION_UP rejected: egress IP %pI4 is not on the bound NIC ifindex=%u\n",
				net->ns.inum, &req.bind_ip, req.oif);
			return aerr;
		}
		if (req.bind_ip != req.outer_src) {
			GENL_SET_ERR_MSG(info, "the bound egress IP must match OUTER_SRC");
			pr_info("netns %u: SESSION_UP rejected: egress IP %pI4 does not match outer source %pI4\n",
				net->ns.inum, &req.bind_ip, &req.outer_src);
			return -EINVAL;
		}
	}
	{
		struct net_device *idev = dev_get_by_index(net, dev.ifindex);
		int cerr;

		if (req.outer_v6)
			cerr = iwan_carrier_resolve6(net, pn, idev, dev.mtu,
						     &req.outer_src6,
						     &req.outer_dst6, req.oif,
						     &req.bind_ip6);
		else
			cerr = iwan_carrier_resolve(net, pn, idev, req.outer_src,
						    req.outer_dst, req.oif,
						    req.bind_ip);
		dev_put(idev);
		/* Outer v6 has one more failure code: inner MTU + encapsulation does not fit the
		 * carrier NIC MTU. This is not "temporarily unresolved" but that this session
		 * **cannot** work correctly at the current MTU (outer v6 does not fragment), so reject with or without a binding. */
		if (cerr == -EMSGSIZE) {
			GENL_SET_ERR_MSG(info, "outer v6 does not fit: inner MTU + encap overhead exceeds the carrier NIC MTU (outer v6 does not fragment)");
			return cerr;
		}
		/* Without a binding, "unresolved" is tolerated by design (device first, route
		 * later), but tolerating it is not the same as ignoring it: log the error code and
		 * cause to dmesg so it does not become a silent hole (the outer v6 MTU check hangs on this resolution). */
		if (cerr && req.outer_v6 && ipv6_addr_any(&req.bind_ip6))
			pr_info("netns %u: outer v6 carrier unresolved (%d), tolerated as \"device first, route later\"; MTU check not evaluated here, handed to the send side\n",
				net->ns.inum, cerr);
		if (cerr && req.outer_v6 && !ipv6_addr_any(&req.bind_ip6)) {
			GENL_SET_ERR_MSG(info, "the bound egress IP is unusable: no outer route resolved through its NIC (device missing/unusable)");
			pr_info("netns %u: SESSION_UP rejected: NIC of egress IP %pI6c has no route to %pI6c (%d)\n",
				net->ns.inum, &req.bind_ip6, &req.outer_dst6,
				cerr);
			return cerr;
		}
		if (cerr && req.outer_v6 && req.oif) {
			GENL_SET_ERR_MSG(info, "the bound carrier NIC is unusable: no outer route resolved through it (device missing/unusable)");
			pr_info("netns %u: SESSION_UP rejected: bound ifindex=%u has no route to %pI6c (%d)\n",
				net->ns.inum, req.oif, &req.outer_dst6, cerr);
			return cerr;
		}
		if (cerr && req.bind_ip) {
			GENL_SET_ERR_MSG(info, "the bound egress IP is unusable: no outer route resolved through its NIC (device missing/unusable)");
			pr_info("netns %u: SESSION_UP rejected: NIC of egress IP %pI4 has no route to %pI4 (%d)\n",
				net->ns.inum, &req.bind_ip, &req.outer_dst, cerr);
			return cerr;
		}
		if (cerr && req.oif) {
			GENL_SET_ERR_MSG(info, "the bound carrier NIC is unusable: no outer route resolved through it (device missing/unusable)");
			pr_info("netns %u: SESSION_UP rejected: bound ifindex=%u has no route to %pI4 (%d)\n",
				net->ns.inum, req.oif, &req.outer_dst, cerr);
			return cerr;
		}
		if (cerr)
			pr_info("netns %u: carrier NIC not resolved yet (%d), will resolve on first egress\n",
				net->ns.inum, cerr);
		/* Without an explicit v6 binding we do not reject here: same convention as v4
		 * (resolve on first egress). The difference is that the v6 egress path re-looks-up
		 * every time and validates MTU the same way, so "route appears later" is still caught. */
	}
	if (!was_valid) {
		/* New session: the shm page starts from zero (timestamp 0 = no frame received yet,
		 * peer_state = UNKNOWN, session counters zeroed). An idempotent replay (was_valid)
		 * deliberately does not reset -- consistent with the existing rule that a replay
		 * with identical params does not disturb keepalive/peer_state. */
		iwan_shm_session_up(pn);
	}
	WRITE_ONCE(s->valid, true);
	/* Only once the session is live is the data plane switch published to the shm page
	 * (user space uses that to tell whether the kernel data plane is open for this session). */
	iwan_shm_set_enabled(pn, true);

	if (req.outer_v6)
		pr_info("netns %u: SESSION_UP(outer v6) sid=%u enc=%u dport=%u sport=%u dev=%s ifindex=%d mtu=%u owned=%d oif=%u src=%pI6c dst=%pI6c ip6=%pI6c carrier=%u\n",
			net->ns.inum, req.sid, req.enc, req.dport,
			req.sport ? req.sport : req.dport, dev.name, dev.ifindex,
			dev.mtu, dev.owned, req.oif, &req.outer_src6,
			&req.outer_dst6, &req.bind_ip6, READ_ONCE(pn->carrier));
	else
		pr_info("netns %u: SESSION_UP sid=%u enc=%u dport=%u sport=%u dev=%s ifindex=%d mtu=%u owned=%d oif=%u ip=%pI4 carrier=%u\n",
			net->ns.inum, req.sid, req.enc, req.dport,
			req.sport ? req.sport : req.dport, dev.name, dev.ifindex,
			dev.mtu, dev.owned, req.oif, &req.bind_ip,
			READ_ONCE(pn->carrier));

	/* The reply can only fail with EMSGSIZE: the session is established, replaying SESSION_UP is idempotent */
	return iwan_genl_reply_up(info, dev.name, dev.mtu, dev.owned);
}

static int iwan_genl_session_down(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct iwan_net *pn = iwan_net_of(net);
	struct iwan_session *s = &pn->sess;
	char devname[IFNAMSIZ];
	int ifindex;
	bool owned;
	int err = 0;

	if (!iwan_genl_capable(skb, net))
		return -EPERM;

	memcpy(devname, s->devname, sizeof(devname));
	devname[sizeof(devname) - 1] = '\0';
	/* Note that valid is **not** checked here: if the previous DOWN failed to delete
	 * the device, valid is already cleared but dev_owned/dev_ifindex/devname remain,
	 * and a repeated SESSION_DOWN must still delete it. The criterion no longer relies on the name: after a rename the name does not match, but ifindex still points at that device. */
	ifindex = READ_ONCE(s->dev_ifindex);
	owned = READ_ONCE(s->dev_owned) && (ifindex || devname[0] != '\0');

	/* 1) Turn the data plane off: clear valid first so no half state is used while deleting */
	WRITE_ONCE(s->valid, false);

	/* 2) Delete only the NIC created by the module (rtnl_link_ops path). On failure
	 *    keep dev_owned/dev_ifindex/devname so a repeated SESSION_DOWN can retry;
	 *    the user can also run `ip link del` directly. */
	if (owned) {
		err = iwan_dev_remove(net, devname, ifindex);
		if (err)
			pr_warn("netns %u: deleting %s(ifindex=%d) failed: %d (keeping ownership for retry)\n",
				net->ns.inum, devname, ifindex, err);
	}

	/* 3) Clear credentials and keepalive: the data plane then falls back to module
	 * parameter defaults. The whole shm page is zeroed (version is kept):
	 * last_rx_ms=0, peer_state=UNKNOWN, enabled=0, session counters zeroed -- the same
	 * storage as GET_STATS's "keepalive/peer_state cleared after SESSION_DOWN". */
	WRITE_ONCE(s->enabled, false);
	WRITE_ONCE(s->create_dev, false);
	WRITE_ONCE(s->enc, 0);
	WRITE_ONCE(s->sid, 0);
	WRITE_ONCE(s->tok, 0);
	memset(s->key, 0, IWAN_KEY_LEN);
	WRITE_ONCE(s->outer_src, 0);
	WRITE_ONCE(s->outer_dst, 0);
	/* The family flag must be cleared as well: keeping outer_v6=true makes the next v4
	 * session look like v6 in iwan_dp_get() (the outer header would be sent with zero addresses). */
	WRITE_ONCE(s->outer_v6, false);
	memset(&s->outer_src6, 0, sizeof(s->outer_src6));
	memset(&s->outer_dst6, 0, sizeof(s->outer_dst6));
	memset(&s->bind_ip6, 0, sizeof(s->bind_ip6));
	WRITE_ONCE(s->dport, 0);
	WRITE_ONCE(s->sport, 0);
	WRITE_ONCE(s->oif, 0);
	WRITE_ONCE(s->bind_ip, 0);
	WRITE_ONCE(s->mtu, 0);
	/* Unpin the carrier NIC: session over, the data plane goes back to "whatever the
	 * FIB decides" (or the explicit binding from /proc). Route cache invalidation is done lazily by the data plane via the tx_route_* records. */
	iwan_carrier_forget(pn);
	iwan_shm_session_down(pn);
	if (!err) {
		WRITE_ONCE(s->dev_owned, false);
		WRITE_ONCE(s->dev_ifindex, 0);
		memset(s->devname, 0, sizeof(s->devname));
	} else {
		return err;	/* let user space see the failure and retry */
	}

	pr_info("netns %u: SESSION_DOWN (dev=%s ifindex=%d deleted, behaviour back to module parameter defaults)\n",
		net->ns.inum, devname[0] ? devname : "-", ifindex);
	return iwan_genl_reply_snapshot(info, IWAN_CMD_SESSION_DOWN,
					devname[0] ? devname : "-");
}

static int iwan_genl_set_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct iwan_net *pn = iwan_net_of(net);
	struct iwan_session *s = &pn->sess;
	char devname[IFNAMSIZ];
	__be32 dst;
	u16 port;

	if (!iwan_genl_capable(skb, net))
		return -EPERM;
	if (!READ_ONCE(s->valid)) {
		GENL_SET_ERR_MSG(info, "no session yet: SESSION_UP first");
		return -ENOENT;
	}
	/* Only OUTER_DST/OUTER_DST6/SPORT/DPORT can be changed hot: credentials and the
	 * local address need a new session (family is part of session identity too: switching family = switching outer header version, use SESSION_UP) */
	if (info->attrs[IWAN_A_SID] || info->attrs[IWAN_A_TOK] ||
	    info->attrs[IWAN_A_ENC] || info->attrs[IWAN_A_KEY] ||
	    info->attrs[IWAN_A_OUTER_SRC] || info->attrs[IWAN_A_OUTER_SRC6]) {
		GENL_SET_ERR_MSG(info, "SET_PEER only accepts OUTER_DST/OUTER_DST6/SPORT/DPORT");
		return -EINVAL;
	}
	if (!info->attrs[IWAN_A_OUTER_DST] &&
	    !info->attrs[IWAN_A_OUTER_DST6] && !info->attrs[IWAN_A_SPORT] &&
	    !info->attrs[IWAN_A_DPORT]) {
		GENL_SET_ERR_MSG(info, "SET_PEER needs at least one of OUTER_DST/OUTER_DST6/SPORT/DPORT");
		return -EINVAL;
	}
	if (info->attrs[IWAN_A_OUTER_DST6] && info->attrs[IWAN_A_OUTER_DST]) {
		GENL_SET_ERR_MSG(info, "only one of OUTER_DST and OUTER_DST6 may be given");
		return -EINVAL;
	}

	if (info->attrs[IWAN_A_OUTER_DST6]) {
		/* Peer drift for a v6 session. The family criterion is the session's own outer_v6:
		 * the wrong family is rejected, never converted implicitly ("a v6 session got
		 * OUTER_DST" can only mean the control plane mixed up the family). */
		struct in6_addr d6;

		if (!READ_ONCE(s->outer_v6)) {
			GENL_SET_ERR_MSG(info, "OUTER_DST6 is only for outer-v6 sessions");
			return -EINVAL;
		}
		if (nla_len(info->attrs[IWAN_A_OUTER_DST6]) !=
		    sizeof(struct in6_addr)) {
			GENL_SET_ERR_MSG(info, "OUTER_DST6 must be 16 bytes");
			return -EINVAL;
		}
		nla_memcpy(&d6, info->attrs[IWAN_A_OUTER_DST6], sizeof(d6));
		if (ipv6_addr_any(&d6)) {
			GENL_SET_ERR_MSG(info, "OUTER_DST6 must not be ::");
			return -EINVAL;
		}
		/* Updating a 16-byte address does not play atomicity games: drift is a low-rate
		 * control-plane event and the worst case is a few packets that fail to match the
		 * old address at the drift instant (dropped), same convention as writing endpoints in SESSION_UP. */
		s->outer_dst6 = d6;
		iwan_carrier_forget(pn);
	} else if (info->attrs[IWAN_A_OUTER_DST]) {
		if (READ_ONCE(s->outer_v6)) {
			GENL_SET_ERR_MSG(info, "OUTER_DST is the v4 peer address; use OUTER_DST6 for outer v6");
			return -EINVAL;
		}
		dst = nla_get_be32(info->attrs[IWAN_A_OUTER_DST]);
		if (!dst) {
			GENL_SET_ERR_MSG(info, "OUTER_DST must not be 0");
			return -EINVAL;
		}
		WRITE_ONCE(s->outer_dst, dst);
		/* Peer drift may land on another carrier NIC: unpin it, and the next packet
		 * re-resolves with the new endpoint (explicit binding still applies; an unreachable NIC counts into tx_err). */
		iwan_carrier_forget(pn);
	}
	if (info->attrs[IWAN_A_DPORT]) {
		port = ntohs(nla_get_be16(info->attrs[IWAN_A_DPORT]));
		if (!port) {
			GENL_SET_ERR_MSG(info, "DPORT must not be 0");
			return -EINVAL;
		}
		WRITE_ONCE(s->dport, port);
	}
	/* SPORT = 0 is a legal value (means "use DPORT") */
	if (info->attrs[IWAN_A_SPORT])
		WRITE_ONCE(s->sport,
			   ntohs(nla_get_be16(info->attrs[IWAN_A_SPORT])));

	if (READ_ONCE(s->outer_v6))
		pr_info("netns %u: SET_PEER(outer v6) dst=%pI6c dport=%u sport=%u\n",
			net->ns.inum, &s->outer_dst6, READ_ONCE(s->dport),
			READ_ONCE(s->sport));
	else
		pr_info("netns %u: SET_PEER dst=%pI4 dport=%u sport=%u\n",
			net->ns.inum, &s->outer_dst, READ_ONCE(s->dport),
			READ_ONCE(s->sport));
	iwan_devname_of(net, s, devname, sizeof(devname));
	return iwan_genl_reply_snapshot(info, IWAN_CMD_SET_PEER, devname);
}

static int iwan_genl_set_enabled(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct iwan_net *pn = iwan_net_of(net);
	struct iwan_session *s = &pn->sess;
	char devname[IFNAMSIZ];
	bool en;

	if (!iwan_genl_capable(skb, net))
		return -EPERM;
	if (!READ_ONCE(s->valid)) {
		GENL_SET_ERR_MSG(info, "no session yet: SESSION_UP first");
		return -ENOENT;
	}
	if (!info->attrs[IWAN_A_ENABLED]) {
		GENL_SET_ERR_MSG(info, "SET_ENABLED requires ENABLED");
		return -EINVAL;
	}
	en = nla_get_u8(info->attrs[IWAN_A_ENABLED]) ? true : false;
	WRITE_ONCE(s->enabled, en);
	/* The shm page's enabled follows too (user space sees the data plane stopped with
	 * zero syscalls); same convention as the data plane's dp.enabled: session switch && module param master switch. */
	iwan_shm_set_enabled(pn, en);
	pr_info("netns %u: SET_ENABLED %d (session state preserved)\n", net->ns.inum, en);
	iwan_devname_of(net, s, devname, sizeof(devname));
	return iwan_genl_reply_snapshot(info, IWAN_CMD_SET_ENABLED, devname);
}

static int iwan_genl_get_stats(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct iwan_net *pn = iwan_net_of(net);
	char devname[IFNAMSIZ];

	if (!iwan_genl_capable(skb, net))
		return -EPERM;

	/* Readable without a session too: returns the "module parameter defaults" layer of
	 * config plus the current counters, same source as the data plane fallback path
	 * (GET_STATS is the troubleshooting entry). TODO(dump): CONTROL-PLANE section 3 allows
	 * NLM_F_DUMP per-netns enumeration later; there is no .dumpit now, so the kernel replies -EOPNOTSUPP. */
	iwan_devname_of(net, &pn->sess, devname, sizeof(devname));
	return iwan_genl_reply_snapshot(info, IWAN_CMD_GET_STATS, devname);
}

/* ------------------------------------------------------------ event multicast */

/*
 * Event token bucket: may one more control-frame event be delivered? Softirq-safe
 * (atomics only: no locks, no sleeping, no allocation); fields and convention in iwan_ev_bucket in iwan.h.
 *
 * Returns false = bucket empty; the caller counts it and skips this multicast.
 *
 * Why rate limit: control frames have **no** usable credential gate --
 * iwan_ctrl_cred_ok() lets PT_OPEN/PT_OPEN_ACK/PT_OPEN_REJECT through
 * unconditionally (during the handshake the kernel has no session, so blocking
 * them would hide handshake packets from user space). Without this layer any source can flood the events multicast with forged PT_OPEN frames (a genlmsg alloc + full-group multicast each).
 *
 * Implementation notes:
 *   - first use (last_ms == 0): fill the bucket and set the time base; CAS makes concurrent callers share one base;
 *   - tokens are refilled only by the CPU that successfully advanced last_ms from
 *     the old value to now, avoiding duplicate refill across CPUs; amount = elapsed
 *     ms x rate -- SCALE=1000 cancels "per second", so the unit is tokens x SCALE, no division;
 *   - tokens are taken with a CAS loop; failure means the bucket is empty. Under
 *     concurrency at most one or two extra tokens slip out, a deliberately accepted error (see iwan.h).
 */
static bool iwan_ev_rate_ok(struct iwan_net *pn)
{
	struct iwan_ev_bucket *b = &pn->ev_bucket;
	const u64 cap = (u64)IWAN_EV_BURST * IWAN_EV_TOK_SCALE;
	u64 now = iwan_now_ms();
	u64 last = (u64)atomic64_read(&b->last_ms);
	u64 tokens;

	if (unlikely(!last)) {
		atomic64_set(&b->tokens, (s64)cap);
		atomic64_cmpxchg(&b->last_ms, 0, (s64)now);
		last = (u64)atomic64_read(&b->last_ms);
	}
	if (now > last &&
	    atomic64_cmpxchg(&b->last_ms, (s64)last, (s64)now) == (s64)last) {
		tokens = (u64)atomic64_read(&b->tokens) +
			 (now - last) * IWAN_EV_RATE_PER_SEC;
		if (tokens > cap)
			tokens = cap;	/* bucket full: no more burst builds up however long the idle */
		atomic64_set(&b->tokens, (s64)tokens);
	}
	for (;;) {
		tokens = (u64)atomic64_read(&b->tokens);
		if (tokens < IWAN_EV_TOK_SCALE)
			return false;
		if (atomic64_cmpxchg(&b->tokens, (s64)tokens,
				     (s64)(tokens - IWAN_EV_TOK_SCALE)) ==
		    (s64)tokens)
			return true;
	}
}

/* Events are delivered only to the netns the session belongs to; the call site may
 * be in softirq (RX hook), so always GFP_ATOMIC. Multicast success does not affect the data plane: failures are only counted, never printed. */
static void iwan_ev_send(struct iwan_net *pn, struct sk_buff *skb, void *hdr)
{
	genlmsg_end(skb, hdr);
	(void)genlmsg_multicast_netns(&iwan_genl_family, pn->net, skb, 0,
				      IWAN_MCGRP_EVENTS_IDX, GFP_ATOMIC);
}

static struct sk_buff *iwan_ev_new(struct iwan_net *pn, u8 cmd, void **hdr)
{
	struct sk_buff *skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_ATOMIC);

	if (!skb) {
		atomic64_inc(&pn->st.rx_nomem);
		return NULL;
	}
	*hdr = genlmsg_put(skb, 0, 0, &iwan_genl_family, 0, cmd);
	if (!*hdr) {
		nlmsg_free(skb);
		atomic64_inc(&pn->st.rx_nomem);
		return NULL;
	}
	return skb;
}

/*
 * IWAN_EV_CTRL_FRAME: non-data frames are handed to user space verbatim.
 * frame is the raw frame bytes **after the outer IP/UDP header** (8B frame header +
 * payload, truncated to IWAN_CTRL_FRAME_MAX); user space verifies the HMAC itself
 * (IWAN_CTRL_LEN=24). SID is the session sid (which session the event belongs to); the frame's own sid is in the raw FRAME bytes.
 *
 * Return value: true = passed rate limiting (later semantic events are still sent);
 * false = dropped by the token bucket and already counted in st.ev_dropped. In both
 * cases **the shm accounting has already happened** (last_rx_ms/peer_state in
 * iwan_decap_one, and the zeroing on PT_CLOSE); rate limiting only affects the multicast, not the "is the peer alive" decision.
 *
 * Note that the rx_ctrl_frame counter and its shm-page mirror are accumulated in the
 * caller (iwan_rx_ctrl) before entering the bucket: it counts "non-data frames that
 * passed the credential gate", independent of how many the rate limiter dropped; the relation is ev_dropped <= rx_ctrl_frame.
 */
bool iwan_ev_ctrl_frame(struct iwan_net *pn, u16 sid,
			const struct iwan_outer_tuple *t,
			const u8 *frame, size_t len)
{
	struct sk_buff *skb;
	void *hdr;

	/* Rate limiting comes first: an over-limit frame does not even allocate a genlmsg --
	 * the point of limiting is to save that GFP_ATOMIC allocation and multicast, not to spend then drop. */
	if (!iwan_ev_rate_ok(pn)) {
		atomic64_inc(&pn->st.ev_dropped);
		return false;
	}

	skb = iwan_ev_new(pn, IWAN_EV_CTRL_FRAME, &hdr);
	if (!skb)
		return true;	/* allocation failure already counted in rx_nomem, not a rate-limit drop */
	if (nla_put_u16(skb, IWAN_EVA_SID, sid) ||
	    nla_put(skb, IWAN_EVA_FRAME, (int)len, frame) ||
	    nla_put_be32(skb, IWAN_EVA_OUTER_SRC, t->src) ||
	    nla_put_be32(skb, IWAN_EVA_OUTER_DST, t->dst) ||
	    nla_put_be16(skb, IWAN_EVA_SPORT, t->sport) ||
	    nla_put_be16(skb, IWAN_EVA_DPORT, t->dport)) {
		nlmsg_free(skb);
		return true;
	}
	iwan_ev_send(pn, skb, hdr);
	return true;
}

void iwan_ev_peer_close(struct iwan_net *pn, u16 sid)
{
	struct sk_buff *skb;
	void *hdr;

	skb = iwan_ev_new(pn, IWAN_EV_PEER_CLOSE, &hdr);
	if (!skb)
		return;
	if (nla_put_u16(skb, IWAN_EVA_SID, sid)) {
		nlmsg_free(skb);
		return;
	}
	iwan_ev_send(pn, skb, hdr);
}

void iwan_ev_keepalive(struct iwan_net *pn, u64 timestamp_ms)
{
	struct sk_buff *skb;
	void *hdr;

	skb = iwan_ev_new(pn, IWAN_EV_KEEPALIVE, &hdr);
	if (!skb)
		return;
	if (nla_put_u16(skb, IWAN_EVA_SID, READ_ONCE(pn->sess.sid)) ||
	    nla_put(skb, IWAN_EVA_TIMESTAMP_MS, (int)sizeof(timestamp_ms),
		    &timestamp_ms)) {
		nlmsg_free(skb);
		return;
	}
	iwan_ev_send(pn, skb, hdr);
}

/* ------------------------------------------------------------ family */

static const struct genl_multicast_group iwan_mcgrps[] = {
	/*
	 * events carries the raw control frame (the 24 bytes user space verifies), the
	 * peer outer address/port and the session SID, so CAP_NET_ADMIN must be required:
	 * genetlink's per-netns socket registers with NL_CFG_F_NONROOT_RECV, and "may this
	 * multicast group be bound" is decided **only** by the group's own flags --
	 * genl_bind() checks ns_capable(net->user_ns, CAP_NET_ADMIN) only when that flag
	 * is set. Not setting it means any local user in the same netns can subscribe: a real permission gap, not an optimization.
	 */
	{ .name = IWAN_GENL_MCGRP_EVENTS, .flags = GENL_MCAST_CAP_NET_ADMIN },
};

static const struct genl_ops iwan_genl_ops[] = {
	{
		.cmd		= IWAN_CMD_SESSION_UP,
		.doit		= iwan_genl_session_up,
		.policy		= iwan_policy_up,
		.maxattr	= IWAN_A_MAX,
	},
	{
		.cmd		= IWAN_CMD_SESSION_DOWN,
		.doit		= iwan_genl_session_down,
		.policy		= iwan_policy_down,
		.maxattr	= IWAN_A_MAX,
	},
	{
		.cmd		= IWAN_CMD_SET_PEER,
		.doit		= iwan_genl_set_peer,
		.policy		= iwan_policy_peer,
		.maxattr	= IWAN_A_MAX,
	},
	{
		.cmd		= IWAN_CMD_SET_ENABLED,
		.doit		= iwan_genl_set_enabled,
		.policy		= iwan_policy_enabled,
		.maxattr	= IWAN_A_MAX,
	},
	{
		.cmd		= IWAN_CMD_GET_STATS,
		.doit		= iwan_genl_get_stats,
		.policy		= iwan_policy_stats,
		.maxattr	= IWAN_A_MAX,
	},
};

static struct genl_family iwan_genl_family = {
	.hdrsize	= 0,
	.name		= IWAN_GENL_NAME,
	.version	= IWAN_GENL_VERSION,
	.maxattr	= IWAN_A_MAX,
	.netnsok	= true,		/* all state comes from the sending socket's netns */
	.module		= THIS_MODULE,
	.ops		= iwan_genl_ops,
	.n_ops		= ARRAY_SIZE(iwan_genl_ops),
	.mcgrps		= iwan_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(iwan_mcgrps),
	/* resv_start_op stays 0: all commands carry a policy, handled as an old family */
};

int iwan_netlink_init(void)
{
	return genl_register_family(&iwan_genl_family);
}

void iwan_netlink_exit(void)
{
	genl_unregister_family(&iwan_genl_family);
}

MODULE_ALIAS_GENL_FAMILY(IWAN_GENL_NAME);
