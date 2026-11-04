/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_abi.h -- ABI between the Windows kernel data plane (WFP callout) and the userspace client.
 *
 * Design mapping (see docs/win-wfp-data-plane.md):
 *   - The session model maps item by item onto the Linux genetlink attribute set (kernel/iwan_genl.h):
 *     outer endpoints, inner MTU, encryption flag and key, binding (egress NIC/egress IP),
 *     session id/token, toggle bits, statistics counters;
 *   - Liveness state corresponds to that read-only shared-memory page of /dev/iwan (kernel/iwan_shm.h):
 *     layout version, fixed offsets, 0 = never received/disconnected, semantics fully identical;
 *   - The three extra Windows fields are platform differences, not semantic differences:
 *     inner address (which address to attach to the loopback adapter), proxied target set (WFP outbound matches
 *     against it, replacing Linux's "route to iwan0"), flow-context toggle (WFP's own
 *     connection tracking, replacing Linux's conntrack + fwmark policy routing).
 *
 * Conventions:
 *   - All fields are host order; only outer addresses/ports are interpreted in network order (same as Linux);
 *   - Structs are explicitly padded to a fixed layout only; offsets are pinned by the assertions at the end of this file;
 *   - The version number is bumped by 1 only on field additions/removals, and the driver, client and assertions in this file must be updated together.
 *
 * This file does not depend on WDK-proprietary headers: kernel mode includes ntddk.h/wdm.h, userspace includes
 * windows.h/winioctl.h, so both sides can include it directly.
 */
#ifndef IWAN_WIN_ABI_H
#define IWAN_WIN_ABI_H

#if defined(_KERNEL_MODE)
#  include <ntddk.h>
#  include <wdm.h>          /* CTL_CODE */
/*
 * Kernel mode has no C99 fixed-width types: the WDK kernel include path has no <stdint.h>, and wdm.h only provides
 * the INT8..UINT64 set of WDK names. This file uses the C99 names throughout (the two userspace sides already have
 * <stdint.h>), so a layer of same-width aliases is added here instead of changing hundreds of field types to WDK names
 * and maintaining two sets -- the ABI struct field types must be one single declaration in all three build targets.
 *
 * C11 allows redefining a typedef to the same type (6.7/3), and MSVC accepts it under /std:c11 as well,
 * so if some future WDK provides these names itself, there is no conflict as long as the widths match.
 */
typedef signed char        int8_t;
typedef unsigned char      uint8_t;
typedef short              int16_t;
typedef unsigned short     uint16_t;
typedef int                int32_t;
typedef unsigned int       uint32_t;
typedef long long          int64_t;
typedef unsigned long long uint64_t;

/*
 * Likewise there is no offsetof: it is a <stddef.h> macro and that header is not in the kernel include path.
 * Provide one using the compiler built-in form; C11 allows redefining the same macro to the same expansion,
 * so it will not conflict if some future WDK provides it. size_t is provided by the WDK itself.
 */
#  ifndef offsetof
#    define offsetof(type, member) ((size_t)(ULONG_PTR)&(((type *)0)->member))
#  endif
#elif defined(IWAN_WIN_ABI_BARE)
/* Bare mode: the host-side cross-check test (tests/win_frame_test.c) only needs the structs and constants,
 * without pulling in windows.h, so the same ABI can be compiled and checked on Linux. */
#  include <stdint.h>
#  include <stddef.h>
#else
#  include <windows.h>
#  include <winioctl.h>     /* CTL_CODE */
#  include <stdint.h>
#endif

/* ---- Version ---------------------------------------------------------- */

/* Device and IOCTL ABI version: refuse to open a session when the driver and client disagree.
 * 3: append outer_if_guid (carrier NIC interface GUID, 16 bytes) at the end of SESSION_OPEN.
 *    Cause: the NDIS binding index and the interface index given by userspace GetBestRoute2 are in practice not the same
 *    numbering scheme (same Ethernet NIC: netio reports 7, NDIS binding parameters report 23); selecting the carrier by index inevitably fails,
 *    and the symptom is exactly the same as "the carrier was never bound at all". The GUID exists in both schemes and is the only
 *    stable identity criterion.
 * 2: append outer_hop (outer next hop) at the end of SESSION_OPEN. An old client sending a 136-byte
 *    request is rejected by the size check, and that is intentional -- without the next hop the outer
 *    frame cannot be sent on the carrier network, and silent degradation is worse than an outright refusal. */
#define IWAN_WIN_ABI_VERSION      3u

/* Liveness shared-memory page layout version: kept in sync with Linux's IWAN_SHM_VERSION (the same
 * userspace reader code consumes the pages from both sides, so the version numbers must move together) */
#define IWAN_WIN_SHM_VERSION      1u

/* Encapsulation overhead and inner MTU bounds (client and driver share one set, so the values they compute cannot diverge):
 *   outer IPv4 = 20 + 8(UDP) + 8(frame header) = 36
 *   outer IPv6 = 40 + 8(UDP) + 8(frame header) = 56
 * The declared inner MTU is min(server-negotiated value, carrier NIC MTU - overhead): the carrier MTU is
 * the hard limit given by the NIC, the negotiated value is what the server is willing to receive, and only the smaller one both fits and avoids
 * being dropped by the peer. */
#define IWAN_WIN_OVERHEAD_V4      36u
#define IWAN_WIN_OVERHEAD_V6      56u
#define IWAN_WIN_MTU_MIN          68u
#define IWAN_WIN_MTU_HARD_MAX_V4  65499u
#define IWAN_WIN_MTU_HARD_MAX_V6  65479u

/* ---- Device names (not needed in bare mode) --------------------------- */

#if !defined(IWAN_WIN_ABI_BARE)

#define IWAN_WIN_DEVICE_NAME      L"\\Device\\iwan"
#define IWAN_WIN_DOS_NAME         L"\\DosDevices\\iwan"
#define IWAN_WIN_USER_PATH        L"\\\\.\\iwan"
/* The second plane (miniport + protocol driver, iwanmp.sys) uses a different set of device names: the two planes can
 * be installed on one machine at the same time; userspace picks one to open via --data-plane, for A/B measurement. */
#define IWAN_WIN_DEVICE_NAME_MP   L"\\Device\\iwanmp"
#define IWAN_WIN_DOS_NAME_MP      L"\\DosDevices\\iwanmp"
#define IWAN_WIN_USER_PATH_MP     L"\\\\.\\iwanmp"
/* Named section object mapped read-only into userspace (corresponds to Linux's /dev/iwan mmap).
 * Note that both planes share the same section name: only one session should run at a time, otherwise the timestamp
 * userspace reads cannot be attributed to a writer (the Linux side likewise has a single global copy). */
#define IWAN_WIN_SHM_NAME         L"\\BaseNamedObjects\\iwan_shm"

/* ---- IOCTL ------------------------------------------------------------ */

#define IWAN_WIN_DEVICE_TYPE      0x8331u   /* custom, avoids system device types */

#define IOCTL_IWAN_SESSION_OPEN \
	CTL_CODE(IWAN_WIN_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_IWAN_SESSION_CLOSE \
	CTL_CODE(IWAN_WIN_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_IWAN_SESSION_GET \
	CTL_CODE(IWAN_WIN_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_IWAN_SHM_QUERY \
	CTL_CODE(IWAN_WIN_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA)

#endif /* !IWAN_WIN_ABI_BARE */

/* ---- Session toggle bits (correspond to IWAN_A_FLAG_*) ---------------- */

/* Attach the inner address to the loopback adapter (on Linux this corresponds to "create iwan0"; set by default).
 * When cleared, the driver only forwards and does not touch the local address table. */
#define IWAN_WIN_FLAG_BIND_INNER      0x0001u
/* Establish flow contexts for inbound connections so their replies go back the way they came (on Linux this corresponds to the whole
 * conntrack + fwmark policy routing stack; Windows uses native WFP flow contexts, set by default) */
#define IWAN_WIN_FLAG_REPLY_VIA_TUNNEL 0x0002u
/* Outer egress NIC explicitly bound (oi f_index valid), corresponds to IWAN_A_OIF */
#define IWAN_WIN_FLAG_BIND_OIF        0x0004u
/* Outer egress IP explicitly bound (bind_ip / bind_ip6 valid), corresponds to IWAN_A_IP* */
#define IWAN_WIN_FLAG_BIND_IP         0x0008u

/* ---- Peer state (corresponds to enum iwan_peer_state) ----------------- */

enum iwan_win_peer_state {
	IWAN_WIN_PEER_UNKNOWN = 0,
	IWAN_WIN_PEER_UP,	/* received a valid frame */
	IWAN_WIN_PEER_SILENT,	/* reserved value: the driver has no timer, liveness is polled from userspace */
	IWAN_WIN_PEER_CLOSED,	/* received PT_CLOSE */
};

/* ---- Target set entries (proxied targets; WFP outbound does longest-prefix matching) ---- */

#define IWAN_WIN_AF_V4            4u
#define IWAN_WIN_AF_V6            6u

/* Upper bound on target set entries: client and driver share the same limit; opening a session must fail explicitly when it is exceeded,
 * so userspace cannot exhaust the kernel pool (the equivalent bound on Linux is applied when userspace expands --proxy-cidr). */
#define IWAN_WIN_MAX_TARGETS      4096u

typedef struct _IWAN_WIN_TARGET {
	uint32_t family;	/* IWAN_WIN_AF_V4 / IWAN_WIN_AF_V6 */
	uint32_t prefix_len;	/* v4: 0..32, v6: 0..128 */
	uint8_t  addr[16];	/* network order; v4 uses the first 4 bytes, the rest are 0 */
} IWAN_WIN_TARGET, *PIWAN_WIN_TARGET;

/* ---- Open-session request --------------------------------------------- */

/*
 * Variable length: targets follow immediately after the struct (same IOCTL buffer), target_count items,
 * each an IWAN_WIN_TARGET. target_offset is the offset relative to the start of this struct, normally
 * equal to sizeof(IWAN_WIN_SESSION_OPEN); the field is reserved so that future prepending of fields
 * does not break old clients.
 */
typedef struct _IWAN_WIN_SESSION_OPEN {
	uint32_t abi_version;	/* IWAN_WIN_ABI_VERSION */
	uint32_t size;		/* size of this struct, used for version compatibility checks */

	/* Session identity and control-plane parameters (correspond to SID/TOK/ENC/KEY) */
	uint16_t sid;
	uint16_t reserved0;
	uint32_t tok;
	uint8_t  enc;		/* 1 = PT_DATA_ENC + XOR, 0 = plaintext */
	uint8_t  key[8];	/* MD5(user||pass)[0..8) */

	/* Outer endpoints (host-order fields + network-order addresses/ports, same as Linux) */
	uint32_t outer_src;	/* be32 */
	uint32_t outer_dst;	/* be32 */
	uint16_t sport;		/* be16; 0 means same as dport */
	uint16_t dport;		/* be16 */
	uint8_t  outer_src6[16];/* outer v6 source; treated as v6 only when both this and outer_dst6 are non-zero */
	uint8_t  outer_dst6[16];/* outer v6 destination */

	/* Bindings (correspond to IWAN_A_OIF / IWAN_A_IP / IWAN_A_IP6) */
	uint32_t flags;		/* IWAN_WIN_FLAG_* */
	uint32_t oif_index;	/* carrier NIC ifindex (BIND_OIF) */
	uint32_t bind_ip;	/* be32, local-end outer egress IP (BIND_IP) */
	uint8_t  bind_ip6[16];	/* local-end outer egress v6 */

	/* Inner (Windows-specific: on Linux the module attaches the inner address itself when creating iwan0) */
	uint32_t inner_ip;	/* be32, inner address assigned to this machine */
	uint8_t  inner_ip6[16];	/* inner v6 (ULA), all 0 if none */
	uint32_t inner_mtu;	/* inner MTU; 0 = carrier_mtu - encapsulation overhead */
	uint32_t carrier_mtu;	/* carrier NIC MTU: looked up by the client and reported up; the driver validates with
				 * "inner_mtu + overhead <= carrier_mtu" */

	/* Target set */
	uint32_t target_offset;	/* relative to the start of this struct */
	uint32_t target_count;

	/* Outer next hop: looked up by the control plane and passed down (be32).
	 *
	 * Why not let the driver look it up itself: kernel mode has no usable route-lookup API -- the GetBestRoute2
	 * family lives only in userspace netioapi.h; if the protocol driver guesses the next hop itself, when the peer is not on-link
	 * ARP never answers, which shows up as "the session is up but not a single byte gets out". The control plane already needs
	 * one GetBestRoute2 for the carrier MTU (src/common/kdp_win.c), and taking NextHop along the way
	 * adds no overhead.
	 * 0 = not provided: treated as "peer is on-link" (this is the correct value when the peer is in the same subnet as the carrier NIC). */
	uint32_t outer_hop;
	uint32_t reserved1;	/* keeps 8-byte alignment; must be 0 */

	/* Carrier NIC interface GUID (16 bytes, same byte order as GetAdaptersAddresses' AdapterName /
	 * ConvertInterfaceLuidToGuid). All 0 = not provided; the driver falls back to matching by
	 * oif_index (trying both numbering schemes), for transition-period compatibility only. */
	uint8_t  outer_if_guid[16];
} IWAN_WIN_SESSION_OPEN, *PIWAN_WIN_SESSION_OPEN;

/* ---- Statistics (counter names and order correspond to enum iwan_stats_attr) ---- */

typedef struct _IWAN_WIN_STATS {
	uint64_t rx_pkts;
	uint64_t rx_outer;
	uint64_t rx_reasm;
	uint64_t rx_frames;
	uint64_t rx_delivered;
	uint64_t rx_batch;
	uint64_t rx_batch_skip;
	uint64_t rx_bad_hdr;
	uint64_t rx_bad_inner;
	uint64_t rx_nomem;
	uint64_t rx_ctrl_frame;
	uint64_t tx_pkts;
	uint64_t tx_bytes;
	uint64_t tx_bad_state;
	uint64_t tx_bad_inner;
	uint64_t tx_err;
	uint64_t ev_dropped;
} IWAN_WIN_STATS, *PIWAN_WIN_STATS;

/* ---- Query session (reply to SESSION_GET / SHM_QUERY) ----------------- */

typedef struct _IWAN_WIN_SESSION_INFO {
	uint32_t abi_version;
	uint32_t size;

	uint16_t sid;
	uint16_t reserved0;
	uint32_t peer_state;	/* enum iwan_win_peer_state */
	uint32_t enabled;	/* session-level data plane switch */
	uint32_t effective_mtu;	/* effective inner MTU (validated against the carrier NIC MTU when the session was established) */
	uint32_t carrier_index;	/* actual carrier NIC ifindex (corresponds to IWAN_A_CARRIER) */
	uint32_t dev_owned;	/* 1 = inner address attached by this driver (corresponds to IWAN_A_DEV_OWNED) */
	uint32_t reserved1;

	uint64_t last_rx_ms;	/* same storage as the shared-memory page (corresponds to IWAN_A_LAST_KEEPALIVE_MS) */
	uint64_t shm_section_size;	/* shared-memory page size (for SHM_QUERY) */
	uint64_t shm_user_va;	/* SHM_QUERY: read-only address mapped into the calling process;
				 * valid only in the process that called SHM_QUERY */

	IWAN_WIN_STATS stats;
} IWAN_WIN_SESSION_INFO, *PIWAN_WIN_SESSION_INFO;

/* ---- Liveness shared-memory page (layout matches kernel/iwan_shm.h) --- */

#define IWAN_WIN_SHM_OFF_VERSION        0x00
#define IWAN_WIN_SHM_OFF_PAD            0x04
#define IWAN_WIN_SHM_OFF_LAST_RX_MS     0x08
#define IWAN_WIN_SHM_OFF_PEER_STATE     0x10
#define IWAN_WIN_SHM_OFF_ENABLED        0x14
#define IWAN_WIN_SHM_OFF_RX_FRAMES      0x18
#define IWAN_WIN_SHM_OFF_RX_CTRL_FRAME  0x20
#define IWAN_WIN_SHM_HDR_SIZE           0x28

typedef struct _IWAN_WIN_SHM {
	uint32_t version;	/* IWAN_WIN_SHM_VERSION */
	uint32_t pad;		/* always 0 */
	uint64_t last_rx_ms;	/* monotonic milliseconds; 0 = never received / already disconnected */
	uint32_t peer_state;	/* enum iwan_win_peer_state */
	uint32_t enabled;
	uint64_t rx_frames;
	uint64_t rx_ctrl_frame;
} IWAN_WIN_SHM, *PIWAN_WIN_SHM;

/* ---- Layout assertions (must pass in kernel mode, userspace and cross-compilers) ---- */

#if defined(_KERNEL_MODE)
#  define IWAN_WIN_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#elif defined(__cplusplus)
#  define IWAN_WIN_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
#  define IWAN_WIN_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

/* Shared-memory page: aligned one by one with Linux's IWAN_SHM_OFF_* (same userspace reader code) */
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_VERSION == 0x00, "shm version offset");
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_PAD == 0x04, "shm pad offset");
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_LAST_RX_MS == 0x08, "shm last_rx offset");
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_PEER_STATE == 0x10, "shm peer_state offset");
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_ENABLED == 0x14, "shm enabled offset");
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_RX_FRAMES == 0x18, "shm rx_frames offset");
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_RX_CTRL_FRAME == 0x20, "shm rx_ctrl offset");

IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, version) == IWAN_WIN_SHM_OFF_VERSION,
		       "IWAN_WIN_SHM.version offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, pad) == IWAN_WIN_SHM_OFF_PAD,
		       "IWAN_WIN_SHM.pad offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, last_rx_ms) == IWAN_WIN_SHM_OFF_LAST_RX_MS,
		       "IWAN_WIN_SHM.last_rx_ms offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, peer_state) == IWAN_WIN_SHM_OFF_PEER_STATE,
		       "IWAN_WIN_SHM.peer_state offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, enabled) == IWAN_WIN_SHM_OFF_ENABLED,
		       "IWAN_WIN_SHM.enabled offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, rx_frames) == IWAN_WIN_SHM_OFF_RX_FRAMES,
		       "IWAN_WIN_SHM.rx_frames offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, rx_ctrl_frame) == IWAN_WIN_SHM_OFF_RX_CTRL_FRAME,
		       "IWAN_WIN_SHM.rx_ctrl_frame offset");
IWAN_WIN_STATIC_ASSERT(sizeof(IWAN_WIN_SHM) == IWAN_WIN_SHM_HDR_SIZE,
		       "IWAN_WIN_SHM must be exactly 0x28 bytes");

/* ---- Frozen offsets: measured values; check tests/win_abi_layout.c before changing fields -----
 *
 * The driver is 64-bit and the client may be 32-bit, so the numbers below must be identical under both targets.
 * These were compiled and run once each with x86_64-w64-mingw32-gcc and i686-w64-mingw32-gcc, and compared
 * line by line (see usage in tests/win_abi_layout.c); no differences except sizeof(void*);
 * mingw and MSVC both align __int64 to 8 bytes, so the MSVC target holds as well.
 * If any of these assertions fails, the ABI is broken -- the client and driver would interpret the same
 * buffer using different offsets, and the driver, client and version number in this file must be changed together.
 */
IWAN_WIN_STATIC_ASSERT(sizeof(IWAN_WIN_TARGET) == 24, "IWAN_WIN_TARGET must be 24 bytes");
IWAN_WIN_STATIC_ASSERT(sizeof(IWAN_WIN_STATS) == 17 * 8, "IWAN_WIN_STATS must be 17 u64s");
/* Pinning sizeof and the last field is not enough: swap rx_outer and rx_reasm and
 * these two assertions still pass, while the userspace parser is shifted wholesale. The three boundaries below are each pinned. */
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_STATS, rx_outer) == 8,
		       "IWAN_WIN_STATS.rx_outer offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_STATS, rx_frames) == 24,
		       "IWAN_WIN_STATS.rx_frames offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_STATS, rx_nomem) == 72,
		       "IWAN_WIN_STATS.rx_nomem offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_STATS, tx_pkts) == 88,
		       "IWAN_WIN_STATS.tx_pkts offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_STATS, tx_bad_state) == 104,
		       "IWAN_WIN_STATS.tx_bad_state offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_STATS, tx_err) == 120,
		       "IWAN_WIN_STATS.tx_err offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_STATS, ev_dropped) == 128,
		       "IWAN_WIN_STATS.ev_dropped offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_OPEN, outer_src6) == 40,
		       "SESSION_OPEN.outer_src6 offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_OPEN, inner_ip6) == 104,
		       "SESSION_OPEN.inner_ip6 offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_OPEN, carrier_mtu) == 124,
		       "SESSION_OPEN.carrier_mtu offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_OPEN, target_offset) == 128,
		       "SESSION_OPEN.target_offset offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_OPEN, target_count) == 132,
		       "SESSION_OPEN.target_count offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_OPEN, outer_hop) == 136,
		       "SESSION_OPEN.outer_hop offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_OPEN, outer_if_guid) == 144,
		       "SESSION_OPEN.outer_if_guid offset");
IWAN_WIN_STATIC_ASSERT(sizeof(IWAN_WIN_SESSION_OPEN) == 160,
		       "IWAN_WIN_SESSION_OPEN must be 160 bytes");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_INFO, last_rx_ms) == 40,
		       "SESSION_INFO.last_rx_ms offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_INFO, shm_user_va) == 56,
		       "SESSION_INFO.shm_user_va offset");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_INFO, stats) == 64,
		       "SESSION_INFO.stats offset");
IWAN_WIN_STATIC_ASSERT(sizeof(IWAN_WIN_SESSION_INFO) == 200,
		       "IWAN_WIN_SESSION_INFO must be 200 bytes");

/* ---- Outbound rejection sample (diagnostic area, write-only) ----------
 *
 * Shared page 0x00..0x27 is the cross-platform layout; 0x100 onwards is unused on both sides (the
 * kernel/iwan_shm.h offsets stop at 0x20). Placed here instead of extending STATS: none of SESSION_INFO's
 * size or offsets change, so old userspace parsers keep working.
 *
 * Rationale: counters only say "how many were rejected", not "why". When all UDP is rejected and
 * all ICMP passes, only this one record can distinguish "the buffer does not start with an IPv4 header" from "total
 * length contradicts the NET_BUFFER length".
 */
#define IWAN_WIN_SHM_OFF_DIAG	0x100
#define IWAN_WIN_DIAG_MAGIC	0x49574447u	/* 'IWDG' */

#define IWAN_WIN_DIAG_TX_NB_NULL	1
#define IWAN_WIN_DIAG_TX_HDR_BAD	2	/* header not contiguous / shorter than 20 bytes / not IPv4 */
#define IWAN_WIN_DIAG_TX_LEN_BAD	3	/* ihl or tot contradicts the NB length */
#define IWAN_WIN_DIAG_TX_MTU		4	/* encapsulation overhead exceeds the carrier MTU */
#define IWAN_WIN_DIAG_TX_ENCAP_FAIL	5
#define IWAN_WIN_DIAG_TX_INFLIGHT	6	/* in-flight injection count reached the limit */
#define IWAN_WIN_DIAG_TX_COALESCE	7	/* failed to obtain the whole packet on the second pass */
#define IWAN_WIN_DIAG_TX_NO_NEIGHBOR	8	/* next-hop MAC not resolved (NDIS plane) */
#define IWAN_WIN_DIAG_TX_V6_NOT_IMPL	9	/* outer v6 on the NDIS plane is not implemented yet */
#define IWAN_WIN_DIAG_TX_SEND_FAIL	10	/* handing to the carrier NIC failed (NDIS plane) */

typedef struct _IWAN_WIN_DIAG {
	uint32_t magic;
	uint32_t reason;
	uint32_t len;		/* NET_BUFFER_DATA_LENGTH */
	uint32_t tot;		/* IPv4 total length read; 0 if not obtained */
	uint32_t pkt0;		/* first byte of the rejected buffer; 0xFFFF if not obtained */
	uint32_t seq;		/* incremented on every write; readers use it to tell the record was updated */
	uint8_t  first[16];	/* first 16 bytes of the rejected buffer */
} IWAN_WIN_DIAG, *PIWAN_WIN_DIAG;

IWAN_WIN_STATIC_ASSERT(sizeof(IWAN_WIN_DIAG) == 40, "IWAN_WIN_DIAG size");
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_DIAG + sizeof(IWAN_WIN_DIAG) <= 4096,
		       "diagnostic area must fit within the shared page");

#endif /* IWAN_WIN_ABI_H */
