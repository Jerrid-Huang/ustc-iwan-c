/* iWAN control-plane ABI (genetlink) v1 -- shared by kernel and user space.
 *
 * Frozen interface; for design notes see kernel/CONTROL-PLANE.md. This file uses only standard integer types,
 * no kernel-only headers, so user space can include it directly; the kernel-side nla_policy must match
 * the type comments in this file, so any change here requires changing the policy too.
 */
#ifndef IWAN_GENL_H
#define IWAN_GENL_H

#define IWAN_GENL_NAME		"iwan"
#define IWAN_GENL_VERSION	1

/* Multicast group name: kernel -> user space */
#define IWAN_GENL_MCGRP_EVENTS	"events"

/* Event payload limit: non-data frames (OPEN/OPEN_ACK/PING/CLOSE etc.) are far smaller than this value */
#define IWAN_CTRL_FRAME_MAX	512

/* Session key length: IWAN_A_KEY must be exactly this many bytes. Same value as IWAN_KEY_LEN
 * in kernel/iwan.h; it is defined again here so user space need not hardcode it. */
#ifndef IWAN_KEY_LEN
#define IWAN_KEY_LEN	8
#endif

/* ------------------------------------------------------------ byte order rules
 *
 * Attributes come in two classes; mixing them yields the defect where "the module talks to itself fine and only a real peer fails":
 *
 *   - plain integers (SID/TOK/ENC/MTU/FLAGS/ENABLED and all counters): **host byte order**;
 *   - addresses and ports (OUTER_SRC/OUTER_DST/SPORT/DPORT): **network byte order**,
 *     user space must htonl/htons before storing them in attributes; the kernel side uses be32/be16.
 *
 * Inside the kernel, dport/sport in struct iwan_cfg / struct iwan_session are kept in **host byte order**
 * (htons when writing the outer header on egress, htons when comparing on ingress). Conversion therefore happens only at the netlink
 * boundary: store after ntohs() on the way in, return after htons() on the way out.
 * Before changing either side, confirm the other still lines up -- this is exactly where it went wrong in the past.
 */

/* ---------------------------------------------------------------- commands */

enum iwan_genl_cmd {
	IWAN_CMD_UNSPEC = 0,
	IWAN_CMD_SESSION_UP,	/* create session, idempotent */
	IWAN_CMD_SESSION_DOWN,	/* tear down session: clear state and delete the NIC created by the module */
	IWAN_CMD_SET_PEER,	/* update peer address/port only (drift, link change) */
	IWAN_CMD_SET_ENABLED,	/* temporarily stop/start the data plane without losing session state */
	IWAN_CMD_GET_STATS,	/* config snapshot + counters + keepalive timestamp */
	__IWAN_CMD_MAX,
};
#define IWAN_CMD_MAX (__IWAN_CMD_MAX - 1)

/* ---------------------------------------------------------------- attributes */

enum iwan_genl_attr {
	IWAN_A_UNSPEC = 0,
	/* --- SESSION_UP / SET_PEER --- */
	IWAN_A_SID,		/* u16 */
	IWAN_A_TOK,		/* u32 */
	IWAN_A_ENC,		/* u8, 1 = PT_DATA_ENC + XOR, 0 = PT_DATA plaintext */
	IWAN_A_KEY,		/* 8 bytes, MD5(user||pass)[0..8) */
	IWAN_A_OUTER_SRC,	/* be32, local outer address */
	IWAN_A_OUTER_DST,	/* be32, peer outer address */
	IWAN_A_DPORT,		/* be16 */
	IWAN_A_SPORT,		/* be16, defaults to DPORT when omitted */
	IWAN_A_MTU,		/* u32, defaults to 1500 - IWAN_OVERHEAD when omitted */
	IWAN_A_FLAGS,		/* u32, see IWAN_A_FLAG_* */
	/* --- SET_ENABLED --- */
	IWAN_A_ENABLED,		/* u8 */
	/* --- SESSION_UP / GET_STATS reply --- */
	IWAN_A_DEVNAME,		/* string, actual device name */
	IWAN_A_LAST_KEEPALIVE_MS,	/* u64, monotonic clock in ms; 0 when there is no keepalive */
	IWAN_A_PEER_STATE,	/* u8, see IWAN_PEER_* */
	IWAN_A_STATS,		/* nested, see iwan_stats_attr */
	/* --- SESSION_UP reply (new attributes, old clients may ignore them) --- */
	IWAN_A_DEV_OWNED,	/* u32, device ownership: 1 = this device was created/claimed by this module,
				 * a later SESSION_DOWN deletes it; 0 = not created by us
				 * (e.g. a device the user created with "ip link add ... type iwan";
				 * we do not delete it). Host byte order, like the other scalars in this table.
				 * Note this attribute expresses "whether the session is responsible for deleting it", not
				 * "whether the netdev kind is iwan": a device with the same name but not from this module
				 * (TUN/veth occupying iwan0) is rejected outright and SESSION_UP
				 * returns -EBUSY, with no reply at all.
				 * Old clients do not know this attribute; per genetlink convention they just ignore it. */
	/* --- SESSION_UP input (new attributes, appended at the end so existing attribute numbers stay unchanged;
	 *     old clients not sending them = pinned after FIB resolution, same behavior as before binding was introduced) --- */
	IWAN_A_OIF,		/* u32, host byte order: explicitly bind the outer egress NIC (ifindex).
				 * 0 or omitted = unspecified: resolve once via FIB and pin the result
				 * -- in both cases "this session uses only one downstream NIC" holds;
				 * the only difference is who chose: explicit binding strictly uses the given NIC (the kernel's
				 * flowi4_oif is a hard bind: when the device is UP and has an IPv4 address, even if
				 * FIB has no route, a scope link route is synthesized for it, i.e.
				 * SO_BINDTODEVICE semantics; binding to a NIC with no return route still sends
				 * and the network side drops it; if the device does not exist or no route resolves, it returns
				 * -ENETUNREACH and never drifts to another NIC); if unspecified, FIB
				 * chooses once and it stays fixed, never changing per packet afterwards. */
	IWAN_A_IP,		/* be32: explicitly bind the outer egress IP ("bind IP" mode).
				 * Semantics have two layers: (1) the address is written into the source address field of the outer IP header
				 * (it must agree with OUTER_SRC when both are set); (2) it is the **binding
				 * spec** -- the kernel resolves it via the local address table to the
				 * interface holding that address, and pins the carrier NIC to that interface, equivalent to "bind NIC".
				 * 0 or omitted = no IP binding. When given together with OIF, it must point to
				 * the same interface, otherwise SESSION_UP returns -EINVAL (when two binding
				 * specs contradict each other, neither may be chosen). If it cannot be resolved (the address belongs to
				 * no local interface), returns -EADDRNOTAVAIL.
				 * Note: resolution uses the **address table** (local addresses attached to interfaces),
				 * not the routing table -- reverse lookup via a route would degrade "bind IP" into "decided by FIB"
				 * and lose the distinction from "bind nothing". */
	IWAN_A_CARRIER,		/* u32, read-only (GET/reply): ifindex of the NIC
				 * actually carrying the traffic, 0 = not resolved yet. For control-plane reconciliation and diagnostics
				 * (which NIC the kernel picked under "bind IP/bind NIC"; besides logs,
				 * this is the only readable source). The write path ignores this attribute. */
	/* --- outer IPv6 additions (appended at the end, no existing attribute number changes) ---------
	 * The outer address family is determined by attributes **appearing in pairs**; there is no separate "family" switch:
	 * OUTER_SRC6 + OUTER_DST6 means an outer v6 session, and the v4 pair means a v4
	 * session; giving both pairs returns -EINVAL (the family must be unique; the data plane must not guess).
	 * The inner layer is unaffected: the inner version is still decided per packet (iwan_inner_hdr_check), and inner v4
	 * can still run inside outer v6. */
	IWAN_A_OUTER_SRC6,	/* 16 bytes, struct in6_addr: local outer IPv6 address.
				 * Must be given together with OUTER_DST6 and must not be all zero. */
	IWAN_A_OUTER_DST6,	/* 16 bytes: peer outer IPv6 address */
	IWAN_A_IP6,		/* 16 bytes: explicitly bind the outer egress IPv6 address
				 * (v6 form of "bind IP" mode). Semantics map
				 * item by item to IWAN_A_IP: (1) it is the source address of the outer IPv6 header, so it must
				 * equal OUTER_SRC6; (2) it is the **binding spec** -- the kernel uses
				 * the local v6 address table to resolve the interface holding that address and pins
				 * the carrier NIC to it; when given together with OIF, it must point to the same
				 * interface (-EINVAL); if it cannot be resolved, returns -EADDRNOTAVAIL.
				 * All zero or omitted = no IP binding. */
	__IWAN_A_MAX,
};
#define IWAN_A_MAX (__IWAN_A_MAX - 1)

/* GET_STATS reply contract (v1 implementation semantics; change this first before changing code):
 *  - Only the view of the **netns where the sending socket lives** is returned; there is no NLM_F_DUMP enumeration, so across netns
 *    query each netns separately.
 *  - **With no netlink session there is no error and no clearing**, it returns the module-parameter layer (fallback path) view,
 *    i.e. the config the data plane really uses when SESSION_UP was never called; user space uses SID/DEVNAME
 *    to tell whether a session exists. After SESSION_DOWN the credentials and LAST_KEEPALIVE_MS are cleared.
 *  - LAST_KEEPALIVE_MS is a read-only snapshot (SESSION_UP/SET_PEER carrying this attribute return -EINVAL);
 *    it is updated by PT_PING_REQ/RSP and cleared on SESSION_DOWN.
 *  - The SESSION_UP reply always carries DEVNAME; MTU returns the **measured value** (it may differ from
 *    the requested value when the device is already UP and cannot be changed); DEV_OWNED returns device ownership (see IWAN_A_DEV_OWNED).
 *  - **KEY is echoed back** (plaintext 8 bytes, byte-for-byte identical to what was set): the implementation treats
 *    "set means readable back", and user space uses this to verify the session was set up by this process. This contradicts
 *    the old comment "KEY is not echoed back"; **the implementation is authoritative**. Because it is echoed back, do not write get-stats
 *    output into logs/tickets/reports (complete session credentials including KEY, SID, TOK).
 */

/* FLAGS bits for SESSION_UP */
#define IWAN_A_FLAG_CREATE_DEV	(1u << 0)	/* create iwan0 on demand (set by default) */
#define IWAN_A_FLAG_ANSWER_PING	(1u << 1)	/* reserved bit: v1 does not implement kernel-side answering of
						 * PT_PING_REQ; setting it returns -EINVAL
						 * (better to reject than to pretend support) */

/* Peer state (IWAN_A_PEER_STATE) */
enum iwan_peer_state {
	IWAN_PEER_UNKNOWN = 0,
	IWAN_PEER_UP,		/* has received a valid frame */
	IWAN_PEER_SILENT,	/* reserved number: v1 never assigns it -- the kernel has no timer,
				 * liveness detection is done by user space polling last_rx_ms */
	IWAN_PEER_CLOSED,	/* received PT_CLOSE */
};

/* GET_STATS counters (IWAN_A_STATS nests one level).
 * The nested table uses iwan_stats_attr; all values are u64 in host byte order; unimplemented counters return 0.
 * Names/semantics match the existing /proc/net/iwan counters so the two paths can be compared. */
enum iwan_stats_attr {
	IWAN_S_UNSPEC = 0,
	IWAN_S_RX_PKTS,
	IWAN_S_RX_OUTER,
	IWAN_S_RX_REASM,
	IWAN_S_RX_FRAMES,
	IWAN_S_RX_DELIVERED,
	IWAN_S_RX_BATCH,
	IWAN_S_RX_BATCH_SKIP,
	IWAN_S_RX_BAD_HDR,
	IWAN_S_RX_BAD_INNER,
	IWAN_S_RX_NOMEM,
	IWAN_S_RX_CTRL_FRAME,	/* non-data frames that passed the credential gate; for those dropped by event rate limiting see
				 * IWAN_S_EV_DROPPED (ev_dropped <= rx_ctrl_frame) */
	IWAN_S_TX_PKTS,
	IWAN_S_TX_BYTES,
	IWAN_S_TX_BAD_STATE,
	IWAN_S_TX_BAD_INNER,
	IWAN_S_TX_ERR,
	/* New counter (appended at the end, earlier numbers unchanged, old clients may ignore it):
	 * number of frames dropped by event-channel rate limiting. The control-frame path has no credentials to check
	 * (PT_OPEN/PT_OPEN_ACK/PT_OPEN_REJECT must be passed through to user space),
	 * so a per-netns token bucket covers the "forged/storm frames saturate the event channel" path.
	 * Relation to IWAN_S_RX_CTRL_FRAME: that item counts the **frames that passed the credential gate**
	 * in total (including those dropped by rate limiting), so ev_dropped <= rx_ctrl_frame always holds;
	 * when rate limiting drops a frame, the shared-memory page timestamp/peer_state accounting still happens (only the multicast
	 * is dropped), so link-loss detection is unaffected by rate limiting.
	 * The /proc/net/iwan column order is frozen; this counter is visible only in GET_STATS. */
	IWAN_S_EV_DROPPED,
	/* New counter (also appended at the end): outer v6 fragments. This design does not fragment outer v6
	 * (v6 has no DF bit, so source fragmentation only buys rejection by the peer; at session setup the "inner MTU +
	 * encapsulation <= MTU" check is done against the carrier NIC MTU), so a non-zero value here means the peer's config
	 * differs from the local one (or the peer runs an outer v6 jumbo profile). These packets are **not** decapsulated
	 * for this tunnel: they are counted and handed back to the stack unchanged (NF_ACCEPT).
	 * The /proc/net/iwan column order is frozen; this item is visible only in GET_STATS. */
	IWAN_S_RX_FRAG6,
	__IWAN_S_MAX,
};
#define IWAN_S_MAX (__IWAN_S_MAX - 1)

/* ---------------------------------------------------------------- events */

enum iwan_genl_event {
	IWAN_EV_UNSPEC = 0,
	IWAN_EV_CTRL_FRAME,	/* non-data frame received, forwarded to user space as-is */
	IWAN_EV_PEER_CLOSE,	/* received PT_CLOSE */
	IWAN_EV_PEER_SILENT,	/* reserved number: v1 never generates it (no kernel timer) */
	IWAN_EV_KEEPALIVE,	/* received PT_PING_REQ/RSP (optional subscription) */
	__IWAN_EV_MAX,
};
#define IWAN_EV_MAX (__IWAN_EV_MAX - 1)

enum iwan_ev_attr {
	IWAN_EVA_UNSPEC = 0,
	IWAN_EVA_SID,		/* u16 */
	IWAN_EVA_FRAME,		/* raw frame bytes (after the outer IP/UDP header), <= IWAN_CTRL_FRAME_MAX */
	IWAN_EVA_OUTER_SRC,	/* be32 */
	IWAN_EVA_OUTER_DST,	/* be32 */
	IWAN_EVA_SPORT,		/* be16 */
	IWAN_EVA_DPORT,		/* be16 */
	IWAN_EVA_SILENT_MS,	/* reserved number: only used by the once-planned PEER_SILENT */
	IWAN_EVA_TIMESTAMP_MS,	/* u64, KEEPALIVE only */
	__IWAN_EVA_MAX,
};
#define IWAN_EVA_MAX (__IWAN_EVA_MAX - 1)

#endif /* IWAN_GENL_H */
