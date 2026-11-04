/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan - zero user-space data path (kernel side).
 *
 * Inbound (RX, default NF_INET_PRE_ROUTING prio=-300):
 *   outer IP[DF=1] / UDP / 8B iWAN frame header / XOR(inner IPv4 packet)
 *   In the hook, reassemble the outer packet first (non-first fragments carry no UDP/iWAN header, so
 *   the ports are only visible once all fragments are joined), then validate the frame header
 *   (type/enc/sid/tok), strip outer and frame headers, restore by XOR with the session key, set
 *   CHECKSUM_NONE so the kernel verifies the inner checksum on plaintext, then NF_ACCEPT. If the inner
 *   packet is fragmented too, ip_defrag reassembles it in ip_local_deliver (local host) or at the next hop (forwarding); this module does not touch inner reassembly.
 *
 * Outbound (TX, kernel virtual NIC ndo_start_xmit):
 *   Before ndo_start_xmit is reached, the stack has already done GSO segmentation and
 *   L4 checksum computation (this device's features/hw_features are all 0, so
 *   validate_xmit_skb does it for us), so what arrives here is always "a complete single
 *   IP packet with the checksum ready", which is what makes XOR safe. Then add the 8B frame header + UDP + outer IP (DF=1) and hand it to ip_local_out.
 *
 * Config plane (v1, see kernel/CONTROL-PLANE.md):
 *   - Module parameters are downgraded to **defaults**: they only take effect while
 *     that netns has no genetlink session yet (struct iwan_session.valid == false); behavior
 *     is bit-for-bit as before the control plane; the /proc/net/iwan read path is unchanged, the write path is kept but deprecated.
 *   - Per-netns session is written by the genetlink control plane (iwan_netlink.c); the data plane is read-only.
 *
 * Disconnect basis (v1, shared memory page, see kernel/iwan_shm.h and CONTROL-PLANE.md section 5):
 *   keepalive **sending** is in user space; the kernel only "stamps the time on
 *   receive"; every frame (data/control) that passes the credential gate writes
 *   iwan_now_ms() into the shared memory page of that netns (/dev/iwan, mmap'd
 *   read-only to user space). netlink's IWAN_A_LAST_KEEPALIVE_MS and the page's last_rx_ms are **the same storage**, no second copy is kept.
 *
 * Frame constants mirror the frozen values in PROTOCOL.md and src/common/protocol.h; changing them is forbidden;
 * the kernel side defines them by numeric value and does not include headers under src/.
 */
#ifndef IWAN_KERNEL_H
#define IWAN_KERNEL_H

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/timekeeping.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/dst_cache.h>	/* outbound outer route cache (auto-invalidated by route generation) */

#include "iwan_genl.h"	/* enum iwan_peer_state: the page peer_state reuses it */
#include "iwan_shm.h"	/* shared memory page layout (/dev/iwan), frozen ABI */

struct page;		/* iwan_net.shm_page: only a pointer is needed, keeps linux/mm.h out */

#define IWAN_HDR_LEN	8	/* frame header: type, enc, sid(u16 BE), tok(u32 BE) */
#define IWAN_KEY_LEN	8	/* MD5(username||password)[0..8) */

/* Frame types (mirror the frozen values in src/common/protocol.h):
 *   0x11-0x18 data/handshake frames, 0x29/0x2A keepalive. */
#define PT_OPEN_REJECT	0x11
#define PT_OPEN_ACK	0x12
#define PT_OPEN		0x13	/* client OPEN (sid/tok = 0/0) */
#define PT_DATA		0x14	/* plaintext inner IPv4 packet */
#define PT_ECHO_REQ	0x15
#define PT_ECHO_RES	0x16
#define PT_CLOSE	0x17
#define PT_DATA_ENC	0x18	/* XOR result: inner IPv4 packet */
#define PT_PING_REQ	0x29
#define PT_PING_RSP	0x2A

/* PT_PING_REQ/RSP use the protocol's fixed credential, not the session credential (see src/common/protocol.h):
 * so the credential rule for control frames must be split by type; the rules and rationale are in
 * iwan_ctrl_cred_ok():
 *   - PING_REQ/RSP  -> fixed 0xFFFF/0xFFFFFFFF (the session credential is also tolerated);
 *   - ECHO_REQ/RES, CLOSE -> must equal the session sid/tok;
 *   - OPEN/OPEN_ACK/OPEN_REJECT -> the kernel cannot know in advance (the ACK carries the
 *     sid/tok, OPEN is 0/0), so only the outer 4-tuple + dport filter is applied and the frame is passed
 *     to user space as is; the HMAC signature in user space (IWAN_CTRL_LEN=24) does the real credential check. */
#define IWAN_PING_SID	0xFFFF
#define IWAN_PING_TOK	0xFFFFFFFFu

/* outer overhead: 8B frame header + 8B UDP + 20B IPv4 (no options) */
#define IWAN_OVERHEAD	(IWAN_HDR_LEN + 8 + 20)

/* Overhead of outer IPv6: the IPv6 base header is a fixed 40B (20B more than v4) and has no options field.
 * It must be used in two places instead of IWAN_OVERHEAD: needed_headroom (per-packet reservation) and the
 * MTU hard cap for the inner MTU (the outer UDP length field is still 16 bits, the same for v6). */
#define IWAN_OVERHEAD_V6	(IWAN_HDR_LEN + 8 + 40)

/* SESSION_UP creates the NIC name on demand; MTU bounds match iwan_dev_setup() */
#define IWAN_DEV_NAME	"iwan0"
#define IWAN_MIN_MTU	68
/* **Default** of the inner MTU cap, overridable by module parameter max_mtu (default 1500).
 * Why the default is still held back at 1500: the kernel data path has only been validated on inner packets <=1500.
 * 2026-10-07 measurement: after raising the inner MTU to 60000 (CMake -DIWAN_JUMBO_MTU=60000),
 * the kernel build hit a kernel panic -- at that size the TX/RX paths (especially the
 * iwan_rx.c:377 skb_gso_segment batching and the 60KB skb in ndo_start_xmit) have not
 * been audited. The cap is now a module parameter, so the ladder (1600/2048/4096/9000/...)
 * needs no rebuild, and an oversized SESSION_UP is still cleanly rejected by iwan_netlink.c instead of panicking. */
#define IWAN_MAX_MTU	1500

/* Hard cap from the spec: the outer IPv4 total length is a 16-bit field and the 36B encapsulation overhead must fit;
 * exceeding it overflows tot_len at encapsulation time (so max_mtu is clamped by this rule no matter how large). */
#define IWAN_MTU_HARD_MAX	(65535 - IWAN_OVERHEAD)
#define IWAN_MTU_HARD_MAX_V6	(65535 - IWAN_OVERHEAD_V6)

enum iwan_hooknum {
	IWAN_HOOK_PRE_ROUTING = 0,	/* default: between the two reassembly passes */
	IWAN_HOOK_LOCAL_IN    = 1,	/* fallback: the outer packet is already reassembled by the kernel, inner fragments need reinject */
};

/* Global default config (module parameters). Each field is READ_ONCE/WRITE_ONCE: there
 * should be no in-flight traffic while the config changes (test scripts configure first, then send); no atomic snapshot is taken.
 *
 * genetlink control plane introduction: this struct only supplies data path
 * parameters when that netns has no session (see iwan_dp_get), i.e. "module parameter = default value while no session is established". */
struct iwan_cfg {
	bool		enabled;
	bool		any_dir;	/* outer (src,dst) may be reversed (peer/local bidirectional test) */
	bool		batch;		/* handle GSO skbs after GRO merging */
	bool		reinject;	/* after decapsulation, use netif_rx to return before ip_defrag */
	bool		verbose;
	int		hooknum;	/* enum iwan_hooknum */
	int		hookprio;	/* default -300 (after defrag, before conntrack) */
	__be32		outer_src;	/* RX filter: outer source (server) */
	__be32		outer_dst;	/* RX filter: outer destination (local tunnel address) */
	__be32		inner_src;	/* optional: inner source address whitelist, 0 = disabled */
	__be16		dport;		/* RX matching & TX: tunnel destination port */
	__be16		sport;		/* TX outer source port (0 = use dport) */
	u16		sid;		/* session id (the only data path credential) */
	u32		tok;		/* session token */
	u8		key[IWAN_KEY_LEN];
	u8		enc;		/* 1 = data path XOR, 0 = plaintext session */
	bool		df;		/* set DF=1 on the outer header (default); 0 allows outer fragmentation,
					 * used to verify the "outer fragment -> inline reassembly in the hook" path */
	u32		max_mtu;	/* inner MTU cap (module parameter, default IWAN_MAX_MTU) */
	u32		pass_through;	/* diagnostic switch (bitmask): 1 = outbound passes
					 * ndo_start_xmit then is dropped (no encapsulation/injection);
					 * 2 = inbound hook immediately NF_ACCEPT (no parsing,
					 * no decapsulation). Used to measure "the entry cost itself" and
					 * "encapsulation/decapsulation cost" separately */
};

/* pass_through bits */
#define IWAN_PASS_TX	1u
#define IWAN_PASS_RX	2u

struct iwan_stats {
	atomic64_t	rx_pkts;	/* UDP outer packets that passed the hook with a valid encapsulated shape
					 * (v4/v6 combined; addresses are not compared yet -- the same definition as before
					 * v6 was introduced for "IPv4 packets entering the hook", with the
					 * value taken on v4) */
	atomic64_t	rx_outer;	/* outer address pair matched this session */
	atomic64_t	rx_reasm;	/* **v4** outer reassembly completed inside the hook */
	atomic64_t	rx_frag6;	/* outer v6 fragments: by design the outer v6 is never fragmented
					 * (checked against the carrier NIC MTU at session setup); seeing a fragment
					 * means the peer configuration does not match; not swallowed, not
					 * treated as a complete packet, handed back to the stack */
	atomic64_t	rx_frames;	/* **data** frames that passed the frame header check */
	atomic64_t	rx_delivered;	/* inner packets decrypted and handed to the stack */
	atomic64_t	rx_batch;	/* GSO merged skbs seen */
	atomic64_t	rx_batch_skip;	/* merged skb passed through because it cannot be split safely */
	atomic64_t	rx_bad_hdr;	/* frame header/length/sid/tok invalid */
	atomic64_t	rx_bad_inner;	/* inner is not a valid IPv4/IPv6 packet (criteria in
					 * iwan_inner_hdr_check) */
	atomic64_t	rx_nomem;
	atomic64_t	rx_ctrl_frame;	/* **passed the credential gate**: non-data frames (IWAN_S_RX_CTRL_FRAME).
					 * the part dropped by the event rate limit is in ev_dropped:
					 * ev_dropped <= rx_ctrl_frame. */
	atomic64_t	tx_pkts;	/* outbound frames */
	atomic64_t	tx_bytes;
	atomic64_t	tx_bad_state;	/* still GSO or checksum not complete (reject, avoids emitting bad packets) */
	atomic64_t	tx_bad_inner;
	atomic64_t	tx_err;		/* route/memory/send failure */
	/* control frames dropped by the event channel token bucket (IWAN_S_EV_DROPPED).
	 * GET_STATS only: the column order of /proc/net/iwan is frozen, no column is added there. */
	atomic64_t	ev_dropped;
};

/*
 * Per-netns session state (written by the genetlink control plane, read-only for the data plane).
 *
 * Field conventions follow the module parameters: ports are **host order**, addresses
 * are be32; the netlink side converts once on ingress/egress (in the ABI ports are be16, addresses are be32).
 * No lock between writer and reader: the existing convention of struct iwan_cfg is kept (no in-flight
 * traffic while a session is changed), scalars use READ_ONCE/WRITE_ONCE, valid is set last and cleared first, so
 * the data path cannot read a persistent "half credential" state (in the extreme race at most one frame is lost).
 *
 * There is **no** keepalive timestamp or peer_state here: the only storage for these two fields is the per-netns
 * shared memory page (pn->shm, see iwan_shm.h); netlink's IWAN_A_LAST_KEEPALIVE_MS
 * / IWAN_A_PEER_STATE and the user-space mmap read the same copy; storing a second copy is not allowed.
 */
struct iwan_session {
	bool		valid;		/* netlink session established (data path switch) */
	bool		enabled;	/* data path switch (SET_ENABLED, does not lose credentials) */
	/* iwan0 was created by **this session** (or the earlier session that was never deleted) => SESSION_DOWN
	 * is responsible for deleting it. Deliberately not tracked by name: the device can be renamed (ip link set
	 * name), the name then no longer finds the device, so we get "reported success but the device is still
	 * there". The identity criterion is dev_ifindex (see below); dev_owned only means "we claimed it last time". */
	bool		dev_owned;
	bool		create_dev;	/* SESSION_UP IWAN_A_FLAG_CREATE_DEV */
	u8		enc;
	u16		sid;
	u32		tok;
	u32		mtu;		/* requested device MTU */
	/* explicitly bound outer egress NIC ifindex (0 = unspecified, pinned once after FIB resolution).
	 * A session always uses only one downstream NIC, see the iwan_net.carrier comment in iwan.h. */
	u32		oif;
	/* explicitly bound outer egress IP (0 = unspecified). It is both the source address of
	 * the outer header and the **binding spec**: the kernel resolves the interface holding this
	 * address from the local address table and pins the carrier NIC from it; with oif both must point to the same interface (see iwan_carrier_resolve). */
	__be32		bind_ip;
	/* carrier NIC ifindex claimed by the session (0 = not claimed). Deletion goes by ifindex, not by name:
	 * still deletable after a rename, and it will not delete the wrong one ("same name but
	 * already a different device"). ifindex gets reused, so deletion requires both dev_owned && ifindex. */
	int		dev_ifindex;
	u8		key[IWAN_KEY_LEN];
	__be32		outer_src;	/* local outer address */
	__be32		outer_dst;	/* peer outer address */
	u16		dport;		/* host order */
	u16		sport;		/* host order, 0 = use dport */
	char		devname[IFNAMSIZ];
	/* outer IPv6 (slice 2): when outer_v6 is true the __be32 pair above is always 0 and the data
	 * path only reads the pair below; the family is immutable for the lifetime of the session
	 * (changing family requires SESSION_DOWN and re-setup, the same rule as "credentials/local address require a new session"). */
	bool		outer_v6;
	struct in6_addr	outer_src6;	/* local outer v6 address */
	struct in6_addr	outer_dst6;	/* peer outer v6 address */
	struct in6_addr	bind_ip6;	/* explicitly bound outer egress v6 address;
					 * all zero = not bound by IP */
};

/* Data path parameter snapshot: per-netns session first, module parameter fallback (iwan_dp_get).
 * session == false means every field is bit-for-bit as before the control plane:
 *   RX uses cfg.*, TX outer endpoints use the /proc-configured pn->tx_*, the switch uses
 *   cfg.enabled && pn->enabled. */
struct iwan_dp {
	bool	session;	/* whether the session fields above come from the netlink session */
	bool	enabled;
	bool	any_dir;	/* whether the outer (src,dst) may match in reverse.
				 * session path is always true (OUTER_SRC/DST are the "local/peer"
				 * identity pair, so inbound is naturally reversed); the module parameter
				 * any_dir only takes effect on the fallback path. */
	u8	enc;
	u16	sid;
	u32	tok;
	u8	key[IWAN_KEY_LEN];
	__be32	outer_src;
	__be32	outer_dst;
	__be32	inner_src;	/* module parameters only (not in the ABI) */
	u16	dport;		/* host order */
	u16	sport;		/* host order, 0 = use dport */
	u32	oif;		/* explicitly bound carrier NIC ifindex; 0 = resolved by FIB
				 * and pinned afterwards (session takes sess.oif, the fallback path takes
				 * pn->tx_oif). */
	__be32	bind_ip;	/* explicitly bound outer egress IP ("bind IP" mode);
				 * 0 = not bound by IP. It and oif are only the criterion for
				 * "whether the control plane specified a binding": the real carrier NIC is always recorded in
				 * pn->carrier (resolved at session setup). */
	/* outer v6 (slice 2). With outer_v6 = true the three v4 fields above are always 0,
	 * the data path only looks at the three below. */
	bool		outer_v6;
	struct in6_addr	outer_src6;
	struct in6_addr	outer_dst6;
	struct in6_addr	bind_ip6;	/* all zero = not bound by IP */
};

/* Whether the control plane explicitly issued a binding spec (NIC or egress IP). With a binding spec the data path
 * **never** drifts to another NIC after an outer lookup failure (it drops and counts); only without one does it re-resolve
 * via FIB (that is the self-healing path of "bind nothing" mode). */
static inline bool iwan_dp_bound(const struct iwan_dp *dp)
{
	/* the family decides which bind_ip is looked at: for a v4 session bind_ip6 is always zero,
	 * bind_ip is always zero for a v6 session (SESSION_UP/SESSION_DOWN both clear by
	 * family), but the criterion still branches explicitly on family -- so nobody can later clear only one half and silently change the "is bound" semantics. */
	if (dp->outer_v6)
		return dp->oif != 0 || !ipv6_addr_any(&dp->bind_ip6);
	return dp->oif != 0 || dp->bind_ip != 0;
}

/* outer encapsulation overhead of this session (used by needed_headroom and the inner MTU hard cap) */
static inline unsigned int iwan_dp_overhead(const struct iwan_dp *dp)
{
	return dp->outer_v6 ? IWAN_OVERHEAD_V6 : IWAN_OVERHEAD;
}

/* outer 5-tuple (for the event payload; addresses/ports stay in network order, same as on the wire) */
struct iwan_outer_tuple {
	__be32	src;
	__be32	dst;
	__be16	sport;
	__be16	dport;
};

/*
 * Event channel token bucket (one per netns).
 *
 * Why it exists: the control frame path has **no** usable credential gate -- PT_OPEN/PT_OPEN_ACK/
 * PT_OPEN_REJECT appears during the handshake, when the kernel has no session yet (iwan_ctrl_cred_ok
 * lets these three through unconditionally), otherwise user space would never receive handshake packets. So "forged control frames
 * flooding the events multicast" can only be contained by rate limiting. Data frames are unaffected: they go through the credential check in iwan_decap_one and never enter the bucket.
 *
 * Accounting: by **frame**, not by byte -- the event channel cost is genlmsg allocation and
 * multicast, independent of frame length. Default 100 frames/sec, burst 200 frames, i.e. at
 * most 100 events per second steady state, at most 200 tokens accumulated. Excess is dropped and counted in IWAN_S_EV_DROPPED.
 *
 * Implementation constraint: the call site may be in softirq (RX hook), so only atomic operations
 * are used -- no lock, no sleep, no allocation. The rate limit is therefore "approximate" rather
 * than exact (two CPUs may refill tokens at the same time, worst case one or two extra are let
 * through); that is a deliberate trade-off: better to occasionally let one extra through than to
 * make the data path take a lock. The fields are zeroed by kzalloc at netns creation; tokens/last_ms == 0 means "not used yet"; the first received frame fills the bucket and sets the time base in iwan_ev_rate_ok().
 *
 * tokens is a **fixed-point** value: 1 token = IWAN_EV_TOK_SCALE units, so refilling a token
 * needs only one integer multiply-add, no division in softirq.
 */
#define IWAN_EV_RATE_PER_SEC	100u	/* token refill rate (frames/sec) */
#define IWAN_EV_BURST		200u	/* bucket capacity (frames), also the burst cap */
#define IWAN_EV_TOK_SCALE	1000u	/* fixed-point scale: 1 token = 1000 units */

struct iwan_ev_bucket {
	atomic64_t	tokens;		/* available tokens x IWAN_EV_TOK_SCALE */
	atomic64_t	last_ms;	/* monotonic milliseconds of the last token refill (iwan_now_ms) */
};

/* Per-netns state. The TX outer endpoints deliberately live here: one module instance
 * serves all netns, and the outer destination differs between the two directions, so each
 * netns decides via /proc/net/iwan (when there is no netlink session) or via the genetlink session (when there is one).
 *
 * shm/shm_page: the shared memory page of this netns (/dev/iwan mmap'd read-only into user space).
 *   - shm is the page header pointer; the data plane and netlink only read/write page fields
 *     through it, every access takes READ_ONCE(pn->shm) and tolerates NULL (after pernet exit detached it);
 *   - shm_page is only used at open()/mmap()/reference release, lives and dies with shm;
 *   - lifetime and refcount see the header comment of iwan_shm.c. */
struct iwan_net {
	struct net		*net;
	/* receive hooks: one each for v4 and v6 (the netfilter hook tables are per family), both
	 * point to the same iwan_rx_hook; the family difference is only the outer header parsing
	 * layer inside the hook (see iwan_outer_view in iwan_rx.c). */
	struct nf_hook_ops	rx_ops4;
	struct nf_hook_ops	rx_ops6;
	struct proc_dir_entry	*proc;
	struct iwan_stats	st;
	struct iwan_session	sess;	/* genetlink session (written by iwan_netlink.c) */
	struct iwan_shm		*shm;	/* one shared memory page per netns; NULL = detached */
	struct page		*shm_page;	/* the corresponding struct page */
	struct iwan_ev_bucket	ev_bucket;	/* events multicast rate limit (used in softirq) */
	bool			rx_hooked;
	bool			enabled;	/* per-netns switch, default true (effective when there is no session) */
	__be32			tx_src;		/* outbound outer source when there is no session (/proc configured) */
	__be32			tx_dst;		/* outbound outer destination when there is no session (/proc configured) */
	u32			tx_oif;		/* carrier NIC explicitly bound when there is no session
						 * (/proc configured, 0 = resolved by FIB and pinned) */
	__be32			tx_bind_ip;	/* egress IP explicitly bound when there is no session
						 * (/proc configured, 0 = not bound by IP).
						 * Same value as tx_src: it is both the source
						 * address of the outer header and the criterion for "which NIC". */
	u32			carrier;	/* ifindex of the pinned carrier NIC
						 * (0 = not resolved yet). A session always uses
						 * only one downstream NIC: outbound lookup carries
						 * flowi4_oif, inbound filters by ifindex, and
						 * needed_headroom is derived from the
						 * LL_RESERVED_SPACE of the pinned carrier NIC. The
						 * iwan_tx.c file writes it through iwan_carrier_pin();
						 * the control plane clears it to 0 at session setup/end
						 * and on endpoint change so the next use
						 * re-resolves. */
	struct dst_cache	tx_route;	/* outbound outer route cache: the outer endpoint does not
						 * change during the session, so a per-packet FIB lookup is pure
						 * duplicate work; dst_check invalidates automatically by route
						 * generation; endpoint consistency is checked at use time */
	bool			tx_route_ok;	/* tx_route initialized successfully; on failure it falls
						 * back to a per-packet FIB lookup, correctness is unaffected */
	__be32			tx_route_dst;	/* outer dst/src at cache setup: the cache is dropped
						 * when the endpoints change (/proc or a new session) */
	__be32			tx_route_src;
	u32			tx_route_oif;	/* carrier NIC at cache setup: the cache is dropped
						 * when the pinned result changes (new session/new binding).
						 * The control plane does **not** call dst_cache_reset
						 * directly (that requires BH disabled), it only clears
						 * pn->carrier, and the data plane drops the cache lazily
						 * based on these three recorded values. */
	bool			tx_route_v6;	/* outer family at cache setup; checked together with the
						 * endpoints at use time, a family change always mismatches */
	struct in6_addr		tx_route_dst6;
	struct in6_addr		tx_route_src6;
};

extern unsigned int iwan_net_id;

struct rtnl_link_ops;
extern struct rtnl_link_ops iwan_link_ops;	/* iwan_tx.c: NIC create/delete */

static inline struct iwan_net *iwan_net_of(struct net *net)
{
	return net_generic(net, iwan_net_id);
}

/* Release the carrier NIC pin: called when the outer endpoint or binding changes and at session end. Only clears scalars, **no**
 * dst_cache_reset -- the latter requires BH disabled and the control plane does not touch it from process context; the data plane relies on the
 * tx_route_dst/src/oif recorded values to notice "the parameters at cache setup have changed", and drops the cache lazily in an
 * environment with softirqs disabled (see item 6 in iwan_tx.c). */
static inline void iwan_carrier_forget(struct iwan_net *pn)
{
	WRITE_ONCE(pn->carrier, 0);
}

/* Monotonic clock in milliseconds: keepalive/liveness timestamp (the shared memory page, GET_STATS and KEEPALIVE
 * events all use this single time source; jiffies or a second time base is not allowed) */
static inline u64 iwan_now_ms(void)
{
	return div_u64(ktime_get_mono_fast_ns(), NSEC_PER_MSEC);
}

/* ---- shared memory page accessors (/dev/iwan, see iwan_shm.h) ----------------------
 *
 * Page allocation/release and refcounting all live in iwan_shm.c; here only field reads/writes are done, shared by the data plane
 * (iwan_rx.c, softirq context) and the control plane (iwan_netlink.c):
 *   - every accessor takes the pointer with READ_ONCE(pn->shm) and **tolerates NULL** (when pernet exit
 *     has already detached the page, it reads NULL and does nothing, no deref);
 *   - the data plane only does plain stores (WRITE_ONCE only prevents compiler tearing), lockless, no allocation,
 *     no other synchronization primitive; the page is a one-way "kernel writes, user space reads" snapshot;
 *   - last_rx_ms and netlink's IWAN_A_LAST_KEEPALIVE_MS are the same storage.
 */
static inline struct iwan_shm *iwan_shm_of(const struct iwan_net *pn)
{
	return READ_ONCE(pn->shm);
}

/* netlink GET_STATS keepalive snapshot: 0 when there is no page/no session (same as the old definition) */
static inline u64 iwan_shm_last_rx_ms(const struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	return shm ? READ_ONCE(shm->last_rx_ms) : 0;
}

static inline u32 iwan_shm_peer_state(const struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	return shm ? READ_ONCE(shm->peer_state) : IWAN_PEER_UNKNOWN;
}

static inline void iwan_shm_set_peer_state(struct iwan_net *pn, u32 state)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	if (shm)
		WRITE_ONCE(shm->peer_state, state);
}

/*
 * **Every** frame (data or control) that passes the credential gate refreshes the timestamp: this is the only
 * "is the peer still alive" basis in user space. Time base = iwan_now_ms() (exactly the same as GET_STATS).
 * On PT_CLOSE it is overwritten with 0 by iwan_shm_note_close().
 */
static inline void iwan_shm_note_frame(struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	if (shm)
		WRITE_ONCE(shm->last_rx_ms, iwan_now_ms());
}

/*
 * The two counters in the page are **mirror snapshots** of the corresponding atomic64 in pn->st: they must be called after
 * atomic64_inc() has run, so the page value comes from the same source as /proc/net/iwan and GET_STATS
 * (the same authoritative count, no separate copy). Under concurrent RX the mirror may lag briefly,
 * but no count is lost -- user space uses it to confirm "the link is moving", not for accounting.
 */
static inline void iwan_shm_note_data_frame(struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	if (shm)
		WRITE_ONCE(shm->rx_frames,
			   (u64)atomic64_read(&pn->st.rx_frames));
}

static inline void iwan_shm_note_ctrl_frame(struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	if (shm)
		WRITE_ONCE(shm->rx_ctrl_frame,
			   (u64)atomic64_read(&pn->st.rx_ctrl_frame));
}

/* On PT_CLOSE(0x17): timestamp set to 0 (user space treats 0 as link down) + peer_state=CLOSED */
static inline void iwan_shm_note_close(struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	if (!shm)
		return;
	WRITE_ONCE(shm->last_rx_ms, 0);
	WRITE_ONCE(shm->peer_state, IWAN_PEER_CLOSED);
}

/* iwan_core.c */
struct iwan_cfg *iwan_cfg_get(void);
void iwan_dp_get(struct iwan_net *pn, const struct iwan_cfg *c, bool tx,
		 struct iwan_dp *dp);
void iwan_xor(u8 *p, size_t len, const u8 *key, size_t off);
int iwan_xor_skb(struct sk_buff *skb, const u8 *key);
/* Inner IP header check; both v4/v6 inner headers share one set of criteria (called from both TX and RX).
 * exact_len = the declared length must equal skb->len (used by TX);
 * out param *net_hdr_len = inner network header length, used to set the transport offset.
 * Returns 0 = valid, -EINVAL = invalid. See the implementation comment in iwan_core.c. */
int iwan_inner_hdr_check(struct sk_buff *skb, bool exact_len,
			 u32 *net_hdr_len);

/* iwan_shm.c: /dev/iwan device registration + per-netns page allocation/release + session-level fields */
int iwan_shm_init(void);
void iwan_shm_exit(void);
int iwan_shm_net_init(struct iwan_net *pn);
void iwan_shm_net_exit(struct iwan_net *pn);
void iwan_shm_session_up(struct iwan_net *pn);
void iwan_shm_session_down(struct iwan_net *pn);
void iwan_shm_set_enabled(struct iwan_net *pn, bool sess_enabled);

/* iwan_rx.c */
int iwan_rx_net_init(struct iwan_net *pn);
void iwan_rx_net_exit(struct iwan_net *pn);

/* iwan_tx.c: rtnl_link_ops register/unregister (the NIC is created by rtnl_create_link or the
 * `ip link add ... type iwan` command) */
int iwan_tx_init(void);
void iwan_tx_exit(void);

/* iwan_tx.c: resolve and pin the carrier NIC from the outer endpoint (process context; an explicit binding resolution failure returns
 * errno, the caller rejects the session based on it). On success pn->carrier and iwan0's needed_headroom
 * are both in place. */
int iwan_carrier_resolve(struct net *net, struct iwan_net *pn,
			 struct net_device *dev, __be32 src, __be32 dst,
			 u32 oif, __be32 bind_ip);
/* Egress IP binding consistency check (address table only, no route resolution, no NIC pinning):
 * ip == 0 = not bound by IP, pass immediately; if ip belongs to no local interface it returns
 * -EADDRNOTAVAIL; if a NIC oif is also given and the address is not on that NIC, -EINVAL is returned.
 * Both the control plane (genetlink SESSION_UP and the /proc ip=/oif=) use it, so that
 * "two binding specs must point to the same interface" has only one implementation. */
int iwan_bind_ip_check(struct net *net, __be32 ip, u32 oif);
int iwan_bind_ip_check6(struct net *net, const struct in6_addr *ip6, u32 oif);
int iwan_carrier_resolve6(struct net *net, struct iwan_net *pn,
			  struct net_device *dev, u32 mtu,
			  const struct in6_addr *src,
			  const struct in6_addr *dst, u32 oif,
			  const struct in6_addr *bind_ip);

/* iwan_netlink.c: genetlink control plane (register/unregister + event reporting).
 * Events are delivered only to the "events" multicast group of the netns the session belongs to; the call site may be in softirq
 * (RX hook); the implementation is all GFP_ATOMIC, failures only count, no error is reported. */
int iwan_netlink_init(void);
void iwan_netlink_exit(void);

/* Hand control frames over as is + emit the semantic event; returns false = dropped by the event token bucket
 * (already counted in st.ev_dropped); the caller should skip the multicast of subsequent semantic events but **must not**
 * skip the shared-memory side effects (last_rx_ms/peer_state accounting is independent of rate limiting). */
bool iwan_ev_ctrl_frame(struct iwan_net *pn, u16 sid,
			const struct iwan_outer_tuple *t,
			const u8 *frame, size_t len);
void iwan_ev_peer_close(struct iwan_net *pn, u16 sid);
void iwan_ev_keepalive(struct iwan_net *pn, u64 timestamp_ms);

#endif /* IWAN_KERNEL_H */
