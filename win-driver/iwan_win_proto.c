/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_proto.c -- NDIS protocol edge: move outer UDP over a carrier NIC.
 *
 * This half owns "how the outer layer goes out and comes back in":
 *
 *   Send: iwan_win_proto_send_outer4() hands the whole frame (Ethernet header
 *         included) assembled by the engine to the session's carrier NIC via
 *         NdisSendNetBufferLists; completion only frees buffer, decrements in-flight.
 *   Receive: the registered ReceiveNetBufferLists gets **every** frame on each
 *         bound NIC and filters per frame -- only "dest IP = session outer src,
 *         dest port = session sport, UDP" goes to the engine, rest read-only to NDIS.
 *
 * Three differences from the WFP plane, all due to "being elsewhere", not design:
 *
 * (1) Next hop is given by the control plane (sess.outer_hop), not from a
 *     driver lookup: Windows has no kernel-mode route query API for protocol
 *     drivers (netioapi.h exports GetBestRoute2 user-mode only; kernel only
 *     Convert*). The control plane already looks up a route for carrier_mtu
 *     at session open (src/common/kdp_win.c), so it fills ifindex+next hop
 *     into SESSION_OPEN; else "peer on link" (next hop = outer dst), the default tunnel topology.
 * (2) ARP is ours: this plane does not use the host IP stack and the protocol
 *     driver will not resolve for us. Requests are rate-limited by IWAN_MP_ARP_RETRY_MS,
 *     the cache aged by IWAN_MP_ARP_HOLD_MS; all timestamp-based, no timer/DPC/work item (whole-driver convention).
 * (3) Control frames are deliberately not absorbed: the regular TCP/IP binding on
 *     the carrier NIC is **another** protocol driver, and it still hands the same
 *     outer UDP to the user-mode socket, so the PT_OPEN_ACK, ECHO, CLOSE control
 *     plane stays usable as-is in user mode. This edge only accounts (rx_ctrl_frame, mark_rx/mark_close), truncates nothing
 *     and indicates nothing up -- a protocol driver has no "indicate up"; a frame is either consumed or returned to NDIS.
 *
 * Concurrency: callbacks may run at DISPATCH_LEVEL (ReceiveNetBufferLists passes
 * NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL, and so does the send completion callback).
 * This file never waits, takes no mutex, touches no paged memory; the binding table
 * is guarded by g_bind_lock, the session active/next-hop/neighbor cache by mp.lock; every critical section is a few assignments.
 */
#include "iwan_win.h"

/* Minimum interval between ARP requests and cache lifetime */
#define IWAN_MP_ARP_RETRY_MS	1000u
#define IWAN_MP_ARP_HOLD_MS	60000u

/* Maximum single-packet length accepted on receive: an outer datagram = carrier
 * MTU ceiling + slack. A frame longer than this cannot belong to this session. */
#define IWAN_MP_RECV_MAX	2048u

/* One carrier binding (one Ethernet NIC). Lifetime: BindAdapter -> UnbindAdapter. */
typedef struct _IWAN_MP_BINDING {
	LIST_ENTRY		link;
	IWAN_WIN_DEVICE_EXTENSION *ext;	/* control device extension (protocol driver context) */
	NDIS_HANDLE		binding;	/* NdisBindingHandle */
	NDIS_HANDLE		bind_context;	/* completion handle of BindAdapterEx */
	NDIS_HANDLE		unbind_context;	/* completion handle of UnbindAdapterEx */
	/* The two completion handles must be stored separately: if the device is
	 * pulled after bind returns PENDING, NDIS calls unbind first, and a single
	 * overwritten field makes open_complete pass the unbind handle to NdisCompleteBindAdapterEx (state machine/refcount corruption). */
	UINT32			ifindex;
	UINT8			mac[6];
	ULONG			mac_len;
	volatile LONG		opened;		/* 1 = open succeeded, RX/TX allowed */
	volatile LONG		closed;		/* 1 = closed, cannot be picked as TX carrier */
	volatile LONG		outstanding;	/* NBLs sent but not yet completed */
	/* One carrier may expose two "interface indexes": the
	 * NDIS_BIND_PARAMETERS.BoundIfIndex and the user-mode
	 * MIB_IPFORWARD_ROW2.InterfaceIndex (GetBestRoute2) nominally share the
	 * NDIS index space, but the control plane's number was never verified on
	 * the target, and "binding present but OPEN always DEVICE_NOT_READY" is
	 * the hardest symptom to chase. So BoundIfNetluid is converted again as
	 * a second criterion; either match counts on lookup, both numbers get a key (T74/T75, T84/T85), so one install settles whether they match. */
	UINT32			ifindex_net;	/* netio index converted from BoundIfNetluid */
	/* Carrier NIC interface GUID: parsed from NDIS_BIND_PARAMETERS.AdapterName
	 * (of the form "\DEVICE\{GUID}"). The control plane uses
	 * ConvertInterfaceLuidToGuid on the InterfaceLuid from GetBestRoute2 to
	 * send the same GUID down. The two interface index spaces measured
	 * differently on the target (Ethernet netio=7, binding reports 23/26); picking a carrier by index is guessing, GUID has no such problem. */
	UINT8			guid[16];	/* all zero = not parsed */
	ULONG			guid_valid;	/* 1 = guid is trustworthy */
} IWAN_MP_BINDING;

/* The binding table is driver-level: the protocol driver registers in DriverEntry,
 * before the miniport (PnP) appears and after it is gone; it cannot live in the device extension. */
static LIST_ENTRY	g_bindings;
static KSPIN_LOCK	g_bind_lock;
static volatile LONG	g_proto_started;	/* g_bindings/g_bind_lock initialized */
static volatile LONG	g_bind_table_broken;	/* list head read NULL (diagnostics only) */
/* Success/failure counts of open_complete: T72/T73. When a binding entered the
 * table but cannot open, these two are the only proof that NDIS called us at all. */
static volatile LONG	g_open_ok;
static volatile LONG	g_open_fail;
/* Raw NTSTATUS of the last open failure (T76) and the error NdisOpenAdapterEx
 * returned in bind (T77). Counts alone cannot show why it will not open, and that decides where to fix. */
static volatile LONG	g_open_status;
static volatile LONG	g_bind_status;
/* How many times NDIS called BindAdapterEx for us, and how many of those were
 * rejected for medium/MAC length. T71 only counts "nodes that got into the
 * table" and cannot split "NDIS never called us" from "called but rejected" -- the exact fork the target never resolves. */
static volatile LONG	g_bind_calls;
static volatile LONG	g_bind_rejected;


/* The TX in-flight context (IWAN_MP_TX_CTX) is defined in iwan_win.h; RX uses it too. */
/* The pool context area must hold it (the pool is built in iwan_win_mp.c from
 * IWAN_MP_NBL_CTX_SIZE; this assert is the only coupling between the two sides). */
C_ASSERT(sizeof(IWAN_MP_TX_CTX) <= IWAN_MP_NBL_CTX_SIZE);

/* Number of nodes on the list (closed ones included), diagnostics only. It takes
 * the lock itself: bindings come and go, and an unlocked walk reading half a pointer is a crash you made. */
static LONG
iwan_win_proto_binding_count(VOID)
{
	PLIST_ENTRY e;
	LONG n = 0;
	KIRQL old;

	KeAcquireSpinLock(&g_bind_lock, &old);
	if (g_bindings.Flink != NULL) {
		for (e = g_bindings.Flink;
		     e != NULL && e != &g_bindings; e = e->Flink)
			n++;
	} else {
		n = -1;
	}
	KeReleaseSpinLock(&g_bind_lock, old);
	return n;
}

/* Diagnostics: pack the n-th binding's (ifindex, opened, closed) into a LONG:
 *   bit0..13 = ifindex (-1 = no such node)
 *   bit14    = opened
 *   bit15    = closed
 * The session's oif_index is the carrier picked by user mode; if it is wrong the
 * lookup must miss. "There is a node but opened=0" means NdisOpenAdapterEx is
 * still PENDING and open_complete has not come back -- two completely different
 * causes, so all three numbers go out together. It locks itself; an unlocked walk that reads half a pointer is a self-made crash. */
#define IWAN_MP_BIND_INFO_NONE	(0x3FFF)

static LONG
iwan_win_proto_bind_info(_In_ ULONG nth)
{
	PLIST_ENTRY e;
	LONG v = IWAN_MP_BIND_INFO_NONE;
	ULONG i = 0;
	KIRQL old;

	KeAcquireSpinLock(&g_bind_lock, &old);
	if (g_bindings.Flink != NULL) {
		for (e = g_bindings.Flink;
		     e != NULL && e != &g_bindings; e = e->Flink) {
			IWAN_MP_BINDING *b;

			if (i++ != nth)
				continue;
			b = CONTAINING_RECORD(e, IWAN_MP_BINDING, link);
			v = (LONG)(b->ifindex & 0x3FFFu);
			if (b->opened)
				v |= 0x4000;
			if (b->closed)
				v |= 0x8000;
			break;
		}
	}
	KeReleaseSpinLock(&g_bind_lock, old);
	return v;
}

/* Same as bind_info but reports the netio-style index: reading T74/T75 against
 * T84/T85 separates "session oif_index does not match NDIS numbering" from "no such binding at all". */
static LONG
iwan_win_proto_bind_info_net(_In_ ULONG nth)
{
	PLIST_ENTRY e;
	LONG v = IWAN_MP_BIND_INFO_NONE;
	ULONG i = 0;
	KIRQL old;

	KeAcquireSpinLock(&g_bind_lock, &old);
	if (g_bindings.Flink != NULL) {
		for (e = g_bindings.Flink;
		     e != NULL && e != &g_bindings; e = e->Flink) {
			IWAN_MP_BINDING *b;

			if (i++ != nth)
				continue;
			b = CONTAINING_RECORD(e, IWAN_MP_BINDING, link);
			v = (LONG)(b->ifindex_net & 0x3FFFu);
			if (b->opened)
				v |= 0x4000;
			if (b->closed)
				v |= 0x8000;
			break;
		}
	}
	KeReleaseSpinLock(&g_bind_lock, old);
	return v;
}

/* An all-zero GUID in the session means "look up by index". */
static BOOLEAN
iwan_win_proto_guid_zero(_In_reads_(16) const UINT8 *guid)
{
	ULONG i;

	for (i = 0; i < 16; i++) {
		if (guid[i] != 0)
			return FALSE;
	}
	return TRUE;
}

static int
iwan_win_proto_hexval(WCHAR c)
{
	if (c >= L'0' && c <= L'9')
		return (int)(c - L'0');
	if (c >= L'a' && c <= L'f')
		return (int)(c - L'a') + 10;
	if (c >= L'A' && c <= L'F')
		return (int)(c - L'A') + 10;
	return -1;
}

/* Parse a GUID out of "\DEVICE\{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".
 *
 * Why not the inverse of RtlStringFromGUID: the kernel has no UuidFromString.
 * Hand parsing is only twenty lines, and it must return FALSE on failure -- a
 * wrong GUID guess pins the session to the wrong NIC, the hardest error to read from counters. */
_Success_(return != 0)
static BOOLEAN
iwan_win_proto_parse_guid(_In_opt_ const NDIS_STRING *name,
			  _Out_writes_(16) UINT8 *out)
{
	static const int dash_at[] = { 8, 13, 18, 23 };
	WCHAR digits[32];
	UINT8 t[16];
	ULONG i;
	ULONG d = 0;
	ULONG k = 0;

	if (name == NULL || name->Buffer == NULL || name->Length < 38 * 2)
		return FALSE;
	/* Skip \DEVICE\ to find '{': the name contains exactly one '{'. */
	while (k < (ULONG)(name->Length / sizeof(WCHAR)) &&
	       name->Buffer[k] != L'{')
		k++;
	if (k >= (ULONG)(name->Length / sizeof(WCHAR)))
		return FALSE;
	k++;
	for (i = 0; i < 36; i++) {
		WCHAR c;

		if (k + i >= (ULONG)(name->Length / sizeof(WCHAR)))
			return FALSE;
		c = name->Buffer[k + i];
		if (d < 4 && i == (ULONG)dash_at[d]) {
			if (c != L'-')
				return FALSE;
			d++;
			continue;
		}
		if (iwan_win_proto_hexval(c) < 0)
			return FALSE;
		/* Subtracting d from the index "removes the hyphens already skipped". */
		digits[i - d] = c;
	}
	if (d != 4)
		return FALSE;
	for (i = 0; i < 16; i++) {
		int hi = iwan_win_proto_hexval(digits[i * 2]);
		int lo = iwan_win_proto_hexval(digits[i * 2 + 1]);

		t[i] = (UINT8)((hi << 4) | lo);
	}
	/* The string order is big-endian text; the first three GUID fields in memory
	 * are little-endian. All 16 bytes are written index by index, with no tail
	 * loop and no RtlCopyMemory: PREfast only accepts "every success path fully
	 * writes the _Out_ param"; a tail loop or memcpy gets C6101 (uninitialized return), and every return TRUE here does fill it. */
	out[0] = t[3]; out[1] = t[2]; out[2] = t[1]; out[3] = t[0];
	out[4] = t[5]; out[5] = t[4];
	out[6] = t[7]; out[7] = t[6];
	out[8] = t[8]; out[9] = t[9]; out[10] = t[10]; out[11] = t[11];
	out[12] = t[12]; out[13] = t[13]; out[14] = t[14]; out[15] = t[15];
	return TRUE;
}

/* Is there a binding on this interface that is "already in the table but not
 * fully open"? When NdisOpenAdapterEx returns PENDING, open_complete comes back
 * asynchronously; if the control plane creates a session right inside that
 * window it sees T71>0 but no usable binding and OPEN fails at once. The test must stay narrow: wait only for the same ifindex, not closed, not open; no other failure is masked. */
static LONG
iwan_win_proto_binding_pending(_In_reads_(16) const UINT8 *guid,
			       _In_ UINT32 ifindex)
{
	PLIST_ENTRY e;
	LONG found = 0;
	KIRQL old;

	KeAcquireSpinLock(&g_bind_lock, &old);
	if (g_bindings.Flink != NULL) {
		for (e = g_bindings.Flink;
		     e != NULL && e != &g_bindings; e = e->Flink) {
			IWAN_MP_BINDING *b =
				CONTAINING_RECORD(e, IWAN_MP_BINDING, link);

			if (b->closed != 0 || b->opened != 0)
				continue;
			/* The test must match lookup literally, or we end up "waiting for
			 * a node that can never be found" and spin for two seconds. */
			if (iwan_win_proto_guid_zero(guid)) {
				if (b->ifindex == ifindex ||
				    b->ifindex_net == ifindex)
					found = 1;
			} else if (b->guid_valid &&
				   RtlCompareMemory(b->guid, guid, 16) == 16) {
				found = 1;
			}
			if (found)
				break;
		}
	}
	KeReleaseSpinLock(&g_bind_lock, old);
	return found;
}

/* Diagnostics: number of nodes whose guid parsed (low 8 bits) and number of
 * equal hits (high 8 bits). When T87=1 (session gave a GUID) and hits are 0
 * there are only two options: parsing failed, or the control plane got the wrong GUID -- these two numbers separate exactly those cases. */
static LONG
iwan_win_proto_binding_guid_stat(_In_reads_(16) const UINT8 *want)
{
	PLIST_ENTRY e;
	LONG valid = 0;
	LONG hits = 0;
	KIRQL old;

	KeAcquireSpinLock(&g_bind_lock, &old);
	if (g_bindings.Flink != NULL) {
		for (e = g_bindings.Flink;
		     e != NULL && e != &g_bindings; e = e->Flink) {
			IWAN_MP_BINDING *b =
				CONTAINING_RECORD(e, IWAN_MP_BINDING, link);

			if (!b->guid_valid)
				continue;
			valid++;
			if (RtlCompareMemory(b->guid, want, 16) == 16)
				hits++;
		}
	}
	KeReleaseSpinLock(&g_bind_lock, old);
	if (valid > 127)
		valid = 127;
	if (hits > 127)
		hits = 127;
	return (hits << 8) | valid;
}

/* Binding lookup: find an opened carrier by interface GUID or interface index.
 *
 * GUID first: if the session gave a GUID, match on GUID only, the index plays
 * no part at all -- "try both indexes" pins the session to the wrong NIC when
 * the index spaces really differ, and counters never show it. Caller holds g_bind_lock. */
static IWAN_MP_BINDING *
iwan_win_proto_lookup_locked(_In_reads_(16) const UINT8 *guid,
			     _In_ UINT32 ifindex)
{
	PLIST_ENTRY e;

	/* Check the flag before touching the list: only reading both under the same lock makes the table usable. */
	if (InterlockedCompareExchange(&g_proto_started, 1, 1) == 0)
		return NULL;

	/* The head must point to itself (empty list) or to a real node. A NULL
	 * Flink means this list was never initialized by InitializeListHead --
	 * this really happened on the target: 0xD1, the faulting instruction being
	 * the `cmpl %ecx,0x30(%r14)` inlined right here, r14=0 and 0x30 =
	 * IWAN_MP_BINDING.ifindex, the address accessed exactly 0x30, IRQL=DISPATCH.
	 * Lookup is the last step that may crash: a miss returns NULL, the caller returns STATUS_DEVICE_NOT_READY, data plane fail-closed. */
	if (g_bindings.Flink == NULL || g_bindings.Blink == NULL) {
		DbgPrint("iwanmp: binding table uninitialized (Flink=%p), lookup refused\n",
			 (void *)g_bindings.Flink);
		/* Only set an in-memory flag: this function is called under a spinlock,
		 * while writing the registry needs PASSIVE_LEVEL; the caller records T70 after unlocking. */
		InterlockedExchange(&g_bind_table_broken, 1);
		return NULL;
	}
	for (e = g_bindings.Flink; e != NULL && e != &g_bindings; e = e->Flink) {
		IWAN_MP_BINDING *b = CONTAINING_RECORD(e, IWAN_MP_BINDING, link);

		if (!b->opened || b->closed)
			continue;
		if (iwan_win_proto_guid_zero(guid)) {
			if (b->ifindex == ifindex || b->ifindex_net == ifindex)
				return b;
		} else if (b->guid_valid &&
			   RtlCompareMemory(b->guid, guid, 16) == 16) {
			return b;
		}
	}
	return NULL;
}

/* Close one binding: only set flags + drop the "session selected it" reference, **never free**.
 *
 * The binding is referenced by three async paths: bind completion
 * (open_complete), unbind completion (close_complete), and a send already given
 * to NDIS with no callback yet (send_complete must drop the in-flight count).
 * An early version called ExFreePoolWithTag as soon as bind/unbind returned
 * NDIS_STATUS_PENDING; the completion callback then hit a use-after-free --
 * the classic blue-screen shape. Now g_bindings holds every binding ever
 * allocated; close only sets closed, and the real free is deferred to iwan_win_proto_fini (no callback can arrive after NdisDeregisterProtocolDriver returns). */
static VOID
iwan_win_proto_binding_close(_Inout_ IWAN_MP_BINDING *b)
{
	IWAN_MP_PLANE *mp = &b->ext->mp;
	KIRQL old;

	InterlockedExchange(&b->opened, 0);
	InterlockedExchange(&b->closed, 1);

	/* If the session currently picks this NIC, drop it now: otherwise egress keeps
	 * sending on an already closed binding (NdisSendNetBufferLists with a closed handle ends badly). */
	KeAcquireSpinLock(&mp->lock, &old);
	if (mp->active == b) {
		mp->active = NULL;
		mp->active_ifindex = 0;
		mp->next_hop_be = 0;
		InterlockedExchange(&mp->peer_mac_valid, 0);
		InterlockedExchange(&mp->peer_mac_pending, 0);
		mp->arp_ts_ms = 0;
		mp->arp_last_ms = 0;
	}
	KeReleaseSpinLock(&mp->lock, old);
}

/* ---- neighbor (ARP) ---------------------------------------------------- */

/* ARP message length without the Ethernet header: hw type 2 + proto type 2 +
 * lengths 2 + op 2 + sender MAC 6 + sender IP 4 + target MAC 6 + target IP 4. */
#define IWAN_MP_ARP_LEN 28u

/* Build an ARP request: who-has next_hop tell local_mac. Returns frame length (Ethernet+ARP). */
/* Check bufsz before writing: the 14-byte Ethernet header + 28-byte ARP follow,
 * all written byte by byte. The _Out_writes_bytes_(bufsz) annotation is that
 * contract in writing (with only _Out_ the analyzer assumes 1 byte and reports a missing annotation, not an overrun). */
_Success_(return != 0)
static ULONG
iwan_win_proto_build_arp4(_In_ IWAN_WIN_DEVICE_EXTENSION *ext,
			  _Out_writes_bytes_(bufsz) UINT8 *eth,
			  _In_ ULONG bufsz)
{
	IWAN_MP_PLANE *mp = &ext->mp;
	UINT8 *a;
	UINT32 spa;
	ULONG i;

	if (bufsz < IWAN_MP_ETH_HDR_LEN + IWAN_MP_ARP_LEN)
		return 0;
	/* Static upper bounds for the two indexes below: writes to eth land in [0,14),
	 * writes to a land in [14, 14+28). Their sum is exactly the gate above; the
	 * analyzer needs this line to know a[27] is not an out-of-bounds write (C6386). */
	__analysis_assume(bufsz >= IWAN_MP_ETH_HDR_LEN + IWAN_MP_ARP_LEN);

	/* Ethernet header: broadcast */
	for (i = 0; i < 6; i++)
		eth[i] = 0xFFu;
	RtlCopyMemory(eth + 6, mp->local_mac, 6);
	eth[12] = (UINT8)(IWAN_MP_ETH_TYPE_ARP >> 8);
	eth[13] = (UINT8)(IWAN_MP_ETH_TYPE_ARP & 0xFFu);

	a = eth + IWAN_MP_ETH_HDR_LEN;
	a[0] = 0x00; a[1] = 0x01;	/* Ethernet */
	a[2] = 0x08; a[3] = 0x00;	/* IPv4 */
	a[4] = 6;			/* hardware address length */
	a[5] = 4;			/* protocol address length */
	a[6] = 0x00; a[7] = 0x01;	/* request */
	RtlCopyMemory(a + 8, mp->local_mac, 6);
	/* The sender protocol address must be the local IPv4 address on the carrier
	 * network: QEMU slirp drops 0 outright (it requires ar_sip inside the client
	 * subnet), so no reply ever comes and every egress packet is dropped with
	 * NO_NEIGHBOR while ARP looked "sent". Address = session outer_src (same as the outer header). */
	spa = ext->sess.outer_src;
	a[14] = (UINT8)(spa >> 24);
	a[15] = (UINT8)(spa >> 16);
	a[16] = (UINT8)(spa >> 8);
	a[17] = (UINT8)(spa);
	/* Target hardware address unknown: fill 0 (matching the broadcast Ethernet header) */
	a[18] = a[19] = a[20] = a[21] = a[22] = a[23] = 0;
	a[24] = (UINT8)(mp->next_hop_be >> 24);
	a[25] = (UINT8)(mp->next_hop_be >> 16);
	a[26] = (UINT8)(mp->next_hop_be >> 8);
	a[27] = (UINT8)(mp->next_hop_be);

	return IWAN_MP_ETH_HDR_LEN + IWAN_MP_ARP_LEN;
}

/* ARP received: record a reply whose sender protocol address == the next hop. */
static BOOLEAN
iwan_win_proto_learn_arp4(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			  _In_reads_bytes_(len) const UINT8 *a, _In_ ULONG len)
{
	IWAN_MP_PLANE *mp = &ext->mp;
	UINT32 spa;
	BOOLEAN ok = FALSE;
	KIRQL old;

	if (len < 28u || a[0] != 0x00 || a[1] != 0x01 || a[2] != 0x08 ||
	    a[3] != 0x00 || a[4] != 6 || a[5] != 4)
		return FALSE;
	if (a[6] != 0x00)		/* Ethernet/IPv4 */
		return FALSE;
	if (a[7] != 0x02)		/* learn from replies only: anyone can forge a request's spa */
		return FALSE;

	spa = ((UINT32)a[14] << 24) | ((UINT32)a[15] << 16) |
	      ((UINT32)a[16] << 8) | (UINT32)a[17];
	if (spa == 0)			/* a probe with sender address 0 does not count */
		return FALSE;

	KeAcquireSpinLock(&mp->lock, &old);
	if (spa == mp->next_hop_be) {
		RtlCopyMemory(mp->peer_mac, a + 8, 6);
		InterlockedExchange(&mp->peer_mac_valid, 1);
		InterlockedExchange(&mp->peer_mac_pending, 0);
		mp->arp_ts_ms = iwan_win_now_ms();
		InterlockedIncrement(&mp->arp_learn);
		ok = TRUE;
	}
	KeReleaseSpinLock(&mp->lock, old);
	return ok;
}

/* Send an ARP request. The caller must not hold mp.lock. */
static VOID
iwan_win_proto_send_arp4(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	UINT8 *buf;
	ULONG len;

	buf = (UINT8 *)IWAN_ALLOC(IWAN_MP_ETH_HDR_LEN + 28u, IWAN_TAG_PKT);
	if (buf == NULL) {
		IWAN_MP_STAT_INC(ext, tx_err);
		return;
	}
	len = iwan_win_proto_build_arp4(ext, buf, IWAN_MP_ETH_HDR_LEN + 28u);
	if (len == 0) {
		ExFreePoolWithTag(buf, IWAN_TAG_PKT);
		return;
	}
	/* Use the same TX path: send_outer4 only hands the frame to the NIC and does
	 * not look at the EtherType. On TRUE ownership moved with the NBL (freed by
	 * the completion callback); on FALSE it already freed the buffer -- either way buf must not be touched here, hence no else-branch free. */
	if (!iwan_win_proto_send_outer4(ext, buf, len))
		IWAN_MP_STAT_INC(ext, tx_err);
	else
		InterlockedIncrement(&ext->mp.arp_sent);
}

/* ---- engine egress ----------------------------------------------------- */

/* Fill the Ethernet header. TRUE = done; FALSE = neighbor unresolved (ARP sent
 * under the rate limit), this packet should be dropped. Buffer ownership unchanged: the engine frees on FALSE. */
BOOLEAN
iwan_win_proto_fill_eth4(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext, _Inout_ UINT8 *buf)
{
	IWAN_MP_PLANE *mp = &ext->mp;
	BOOLEAN valid, fire = FALSE;
	UINT64 now;
	KIRQL old;

	now = iwan_win_now_ms();
	/* Test knob wins: if the session carries a fixed MAC, no neighbor resolution
	 * and no aging is needed (arp_ts_ms = 0 means never expire). Production paths do not set this key; behavior unchanged. */
	if (ext->sess.peer_mac_fixed_valid != 0) {
		KeAcquireSpinLock(&mp->lock, &old);
		RtlCopyMemory(mp->peer_mac, ext->sess.peer_mac_fixed, 6);
		mp->arp_ts_ms = 0;
		InterlockedExchange(&mp->peer_mac_valid, 1);
		InterlockedExchange(&mp->peer_mac_pending, 0);
		KeReleaseSpinLock(&mp->lock, old);
	}
	KeAcquireSpinLock(&mp->lock, &old);
	valid = mp->peer_mac_valid != 0;
	if (valid && mp->arp_ts_ms != 0 &&
	    now - mp->arp_ts_ms > IWAN_MP_ARP_HOLD_MS) {
		InterlockedExchange(&mp->peer_mac_valid, 0);	/* aging */
		valid = FALSE;
	}
	/* pending only means "sent once, not learned yet", not "never send again": a
	 * lost reply, or a peer spa that differs from this session's next hop (proxy
	 * ARP, wrong next hop), must allow a retry, or every egress packet is dropped
	 * here, the session never comes up and the retry logic is dead code. arp_last_ms still limits the rate. */
	if (!valid && mp->active != NULL &&
	    (mp->peer_mac_pending == 0 ||
	     (mp->arp_last_ms != 0 &&
	      now - mp->arp_last_ms >= IWAN_MP_ARP_RETRY_MS))) {
		InterlockedExchange(&mp->peer_mac_pending, 1);
		mp->arp_last_ms = now;
		fire = TRUE;
	}
	if (valid) {
		RtlCopyMemory(buf, mp->peer_mac, 6);
		RtlCopyMemory(buf + 6, mp->local_mac, 6);
		buf[12] = (UINT8)(IWAN_MP_ETH_TYPE_IP4 >> 8);
		buf[13] = (UINT8)(IWAN_MP_ETH_TYPE_IP4 & 0xFFu);
	}
	KeReleaseSpinLock(&mp->lock, old);

	if (!valid && fire)
		iwan_win_proto_send_arp4(ext);
	return valid;
}

/* Hand the whole frame to the selected carrier NIC. TRUE = ownership moved (freed
 * by the completion callback); FALSE = not sent and the buffer was freed here. */
BOOLEAN
iwan_win_proto_send_outer4(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			   __drv_freesMem(_Out_) UINT8 *eth, _In_ ULONG len)
{
	IWAN_MP_PLANE *mp = &ext->mp;
	IWAN_MP_BINDING *b;
	IWAN_MP_TX_CTX *ctx;
	NET_BUFFER_LIST *nbl;
	PMDL mdl;
	KIRQL old;

	if (mp->mp_running == 0 || len == 0) {
		ExFreePoolWithTag(eth, IWAN_TAG_PKT);
		return FALSE;
	}
	/* The engine enforces the in-flight cap (IWAN_MP_MAX_OUTER_INFLIGHT); this only accounts and backstops */
	if ((ULONG)InterlockedIncrement(&mp->outer_outstanding) >
	    IWAN_MP_MAX_OUTER_INFLIGHT) {
		InterlockedDecrement(&mp->outer_outstanding);
		ExFreePoolWithTag(eth, IWAN_TAG_PKT);
		return FALSE;
	}

	KeAcquireSpinLock(&mp->lock, &old);
	b = mp->active;
	if (b != NULL && b->opened)
		InterlockedIncrement(&b->outstanding);
	else
		b = NULL;
	KeReleaseSpinLock(&mp->lock, old);
	if (b == NULL) {
		InterlockedDecrement(&mp->outer_outstanding);
		ExFreePoolWithTag(eth, IWAN_TAG_PKT);
		return FALSE;
	}

	mdl = IoAllocateMdl(eth, len, FALSE, FALSE, NULL);
	if (mdl != NULL)
		MmBuildMdlForNonPagedPool(mdl);
	nbl = mdl != NULL ?
		NdisAllocateNetBufferAndNetBufferList(mp->tx_pool,
						      sizeof(IWAN_MP_TX_CTX), 0,
						      mdl, 0, len) : NULL;
	if (nbl == NULL) {
		if (mdl != NULL)
			IoFreeMdl(mdl);
		InterlockedDecrement(&b->outstanding);
		InterlockedDecrement(&mp->outer_outstanding);
		ExFreePoolWithTag(eth, IWAN_TAG_PKT);
		return FALSE;
	}
	ctx = (IWAN_MP_TX_CTX *)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
	ctx->buf = eth;
	ctx->mdl = mdl;

	NdisSendNetBufferLists(b->binding, nbl, NDIS_DEFAULT_PORT_NUMBER,
			       (KeGetCurrentIrql() == DISPATCH_LEVEL) ?
				NDIS_SEND_FLAGS_DISPATCH_LEVEL : 0);
	return TRUE;
}

/* Send completion: return the buffer, clear in-flight. May run at DISPATCH_LEVEL. */
static
_Function_class_(PROTOCOL_SEND_NET_BUFFER_LISTS_COMPLETE)
VOID
iwan_win_proto_send_complete(_In_ NDIS_HANDLE ProtocolBindingContext,
			     _In_ PNET_BUFFER_LIST NetBufferLists,
			     _In_ ULONG SendCompleteFlags)
{
	IWAN_MP_BINDING *b = (IWAN_MP_BINDING *)ProtocolBindingContext;
	IWAN_WIN_DEVICE_EXTENSION *ext = b->ext;
	PNET_BUFFER_LIST nbl = NetBufferLists;
	PNET_BUFFER_LIST next;

	UNREFERENCED_PARAMETER(SendCompleteFlags);

	while (nbl != NULL) {
		IWAN_MP_TX_CTX *ctx =
			(IWAN_MP_TX_CTX *)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);

		next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;

		if (ctx->mdl != NULL)
			IoFreeMdl(ctx->mdl);
		if (ctx->buf != NULL)
			ExFreePoolWithTag(ctx->buf, IWAN_TAG_PKT);
		NdisFreeNetBufferList(nbl);

		InterlockedDecrement(&ext->mp.outer_outstanding);
		InterlockedDecrement(&b->outstanding);
		nbl = next;
	}
}

/* ---- receive ---------------------------------------------------------- */

/* Get a contiguous view of one NB. need bytes; if stor/stor_sz are non-NULL use
 * the caller's buffer first (NDIS copies into it on demand). NULL = unavailable or too long. Data stays valid during the call. */
_Success_(return != NULL)
static const UINT8 *
iwan_win_proto_view(_In_ NET_BUFFER *nb, _In_ ULONG need,
		    _Inout_opt_ UINT8 *stor, _In_ ULONG stor_sz)
{
	/* Compare against the real NB length first: NdisGetDataBuffer's behavior on an
	 * oversized request is not in the contract; the ARP branch asks for 42 bytes
	 * while the frame may be only 34..41 bytes (the caller guarantees the lower bound); trusting "it returns NULL" is luck, not design. */
	if (need == 0 || need > IWAN_MP_RECV_MAX ||
	    need > NET_BUFFER_DATA_LENGTH(nb))
		return NULL;
	if (stor != NULL && stor_sz >= need)
		return (const UINT8 *)NdisGetDataBuffer(nb, need, stor, 1, 0);
	return (const UINT8 *)NdisGetDataBuffer(nb, need, NULL, 1, 0);
}

/* Match test: in-frame IPv4 destination = session outer source address, UDP dst port = session source port.
 * Same rule as the WFP plane ingress gate (there the address comes from fixed fields, here it is read from the frame). */
_Success_(return != FALSE)
static BOOLEAN
iwan_win_proto_is_ours(_In_ const IWAN_WIN_SESSION *s,
		       _In_reads_bytes_(len) const UINT8 *ip, _In_ ULONG len,
		       _Out_ ULONG *iplen)
{
	ULONG ihl;

	if (len < 20u || (ip[0] >> 4) != 4)
		return FALSE;
	ihl = (ULONG)(ip[0] & 0x0Fu) * 4u;
	if (ihl < 20u || len < ihl + 8u)
		return FALSE;
	*iplen = iwan_win_rd16(ip + 2);
	if (*iplen < ihl + 8u || *iplen > len)
		return FALSE;
	if (iwan_win_rd32(ip + 16) != s->outer_src)
		return FALSE;
	if (ip[9] != IWAN_IPPROTO_UDP)
		return FALSE;
	return iwan_win_rd16(ip + ihl + 2) == s->sport;
}

/* One NB is one frame (NdisMedium802_3). TRUE means it is this session's outer
 * frame and was handed to the engine (i.e. "consumed"). */
static BOOLEAN
iwan_win_proto_recv_one(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			_In_ NET_BUFFER *nb)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	UINT8 hdr[IWAN_MP_ETH_HDR_LEN + 60u + 8u];
	const UINT8 *p;
	ULONG len, iplen, need;
	UINT16 eth_type;

	/* hdr is only read after "NdisGetDataBuffer copied the data in" (the
	 * iwan_win_proto_view contract). Zeroing gives static analysis a defined value and makes any contract violation read zero instead of stack garbage. */
	RtlZeroMemory(hdr, sizeof(hdr));
	len = NET_BUFFER_DATA_LENGTH(nb);
	if (len < IWAN_MP_ETH_HDR_LEN + 20u)
		return FALSE;
	p = iwan_win_proto_view(nb, IWAN_MP_ETH_HDR_LEN + 20u, hdr, sizeof(hdr));
	if (p == NULL)
		return FALSE;

	eth_type = (UINT16)(((UINT16)p[12] << 8) | p[13]);
	if (eth_type == IWAN_MP_ETH_TYPE_ARP) {
		InterlockedIncrement(&ext->mp.arp_rx);
		p = iwan_win_proto_view(nb, IWAN_MP_ETH_HDR_LEN + 28u, hdr,
					sizeof(hdr));
		if (p == NULL)
			return FALSE;
		iwan_win_proto_learn_arp4(ext, p + IWAN_MP_ETH_HDR_LEN,
					  len - IWAN_MP_ETH_HDR_LEN);
		return FALSE;	/* ARP is not a "session data frame", but it is not left to anyone either */
	}
	if (eth_type != IWAN_MP_ETH_TYPE_IP4)
		return FALSE;
	if (s->valid == 0 || s->outer_src == 0 || ext->mp.active == NULL)
		return FALSE;

	/* The IPv4 header may carry options (IHL up to 60); fetch up to "Ethernet +
	 * max header + UDP header" before deciding, so we never read past the stack buffer; if the frame is shorter, use its real length. */
	need = len < sizeof(hdr) ? len : (ULONG)sizeof(hdr);
	p = iwan_win_proto_view(nb, need, hdr, sizeof(hdr));
	if (p == NULL)
		return FALSE;
	if (!iwan_win_proto_is_ours(s, p + IWAN_MP_ETH_HDR_LEN,
				    len - IWAN_MP_ETH_HDR_LEN, &iplen))
		return FALSE;

	/* Diagnostic pass-through: count the frame as "would have been decapsulated" and leave it alone --
	 * returning FALSE means "not mine, do not touch", so NDIS hands it on to the regular binding, which is
	 * exactly the Linux plane's NF_ACCEPT. Nothing is parsed, nothing is copied, no session state is touched:
	 * the difference from the normal path is the decapsulation cost. */
	if ((ext->pass_through & IWAN_WIN_PASS_RX)) {
		IWAN_MP_STAT_INC(ext, rx_outer);
		return FALSE;
	}

	/* Hit: hand the whole packet to the engine. Short packets use the stack
	 * buffer; for long ones try zero-copy first (NdisGetDataBuffer returns a direct pointer when the data is in one chunk), otherwise let NDIS copy into a temp buffer. */
	if (iplen <= sizeof(hdr) - IWAN_MP_ETH_HDR_LEN) {
		p = iwan_win_proto_view(nb, IWAN_MP_ETH_HDR_LEN + iplen, hdr,
					sizeof(hdr));
		if (p == NULL) {
			/* A frame already judged ours but no contiguous header: eat it, but
			 * it must be counted -- the data plane may not have a silent drop path. */
			IWAN_MP_STAT_INC(ext, rx_bad_hdr);
			return TRUE;
		}
		iwan_win_mp_outer_recv(ext, p + IWAN_MP_ETH_HDR_LEN, iplen);
		return TRUE;
	}
	{
		ULONG pktlen = IWAN_MP_ETH_HDR_LEN + iplen;
		UINT8 *tmp = (UINT8 *)IWAN_ALLOC(pktlen, IWAN_TAG_PKT);

		if (tmp == NULL) {
			IWAN_MP_STAT_INC(ext, rx_nomem);
			return TRUE;	/* hit but cannot allocate: eat it, do not re-deliver */
		}
		p = iwan_win_proto_view(nb, pktlen, tmp, pktlen);
		if (p != NULL)
			iwan_win_mp_outer_recv(ext, p + IWAN_MP_ETH_HDR_LEN, iplen);
		else
			IWAN_MP_STAT_INC(ext, rx_bad_hdr);
		ExFreePoolWithTag(tmp, IWAN_TAG_PKT);
		return TRUE;
	}
}

/* A batch of NBLs arrived. This side indicates none of them up: the regular
 * TCP/IP binding on the same link is a different protocol driver and receives its own; we only pick out this session's outer frames and return the rest unchanged. */
static
_Function_class_(PROTOCOL_RECEIVE_NET_BUFFER_LISTS)
VOID
iwan_win_proto_recv_nbls(_In_ NDIS_HANDLE ProtocolBindingContext,
			 _In_ PNET_BUFFER_LIST NetBufferLists,
			 _In_ NDIS_PORT_NUMBER PortNumber,
			 _In_ ULONG NumberOfNetBufferLists,
			 _In_ ULONG ReceiveFlags)
{
	IWAN_MP_BINDING *b = (IWAN_MP_BINDING *)ProtocolBindingContext;
	IWAN_WIN_DEVICE_EXTENSION *ext = b->ext;
	PNET_BUFFER_LIST nbl;

	UNREFERENCED_PARAMETER(PortNumber);
	UNREFERENCED_PARAMETER(NumberOfNetBufferLists);

	for (nbl = NetBufferLists; nbl != NULL;
	     nbl = NET_BUFFER_LIST_NEXT_NBL(nbl)) {
		PNET_BUFFER nb;

		for (nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb != NULL;
		     nb = NET_BUFFER_NEXT_NB(nb)) {
			if (ext->mp.mp_running == 0 || ext->sess.valid == 0)
				break;
			iwan_win_proto_recv_one(ext, nb);
		}
	}
	/* With RESOURCES set this batch of NBLs is only **borrowed**, ownership stays
	 * below: it must not be kept, and certainly not returned (returning an NBL
	 * you do not own is a classic blue-screen entry). This side keeps no NBLs anyway, so this just skips the return. */
	if ((ReceiveFlags & NDIS_RECEIVE_FLAGS_RESOURCES) == 0) {
		NdisReturnNetBufferLists(b->binding, NetBufferLists,
					 (KeGetCurrentIrql() == DISPATCH_LEVEL) ?
						NDIS_RETURN_FLAGS_DISPATCH_LEVEL : 0);
	}
}

/* ---- receive filter --------------------------------------------------- */

/* A protocol driver must set OID_GEN_CURRENT_PACKET_FILTER on the binding
 * before it receives: unset is 0 (no packets). This is the divide for "did
 * outer frames come in at all": the regular TCP/IP binding on the same carrier
 * is a **different** protocol driver and sets its own; ours must set its own, or
 * user-mode sockets finish OPEN/OPEN_ACK (its binding got those packets) while the driver's rx_* stays 0 and every packet dies at DIAG_TX_NO_NEIGHBOR.
 *
 * The request must live until the NDIS callback (it may return PENDING), so the
 * request and its 4-byte info buffer are allocated together from non-paged pool,
 * buffer right after the struct. The done field lets both paths (sync return,
 * completion callback) free exactly once -- both endings must land safely instead of betting on whether the callback comes for non-PENDING. */
#define IWAN_MP_FILTER_FLAGS						\
	(NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_MULTICAST |	\
	 NDIS_PACKET_TYPE_ALL_MULTICAST | NDIS_PACKET_TYPE_BROADCAST)

/* Build 26100's ntddndis.h only has the deprecated NDIS_OBJECT_TYPE_REQUEST_EX (0x96),
 * while the sample comment in ndis/oidrequest.h still uses NDIS_OBJECT_TYPE_OID_REQUEST --
 * the same value, unchanged since NDIS 5. Add the fallback so we do not run a CI round for one integer constant. */
#ifndef NDIS_OBJECT_TYPE_OID_REQUEST
#define NDIS_OBJECT_TYPE_OID_REQUEST 0x96
#endif

typedef struct _IWAN_MP_OID_SET {
	NDIS_OID_REQUEST	req;
	ULONG			value;		/* filter bitmap (the request's information buffer) */
	volatile LONG		done;		/* 1 = freed; stops the two paths from double freeing */
} IWAN_MP_OID_SET;

static volatile LONG	g_oid_pending;	/* requests handed to NDIS and not yet finished */

/* Completion callback: only account + return the pool memory. */
static
_Function_class_(PROTOCOL_OID_REQUEST_COMPLETE)
VOID
iwan_win_proto_oid_complete(_In_ NDIS_HANDLE ProtocolBindingContext,
			    _In_ PNDIS_OID_REQUEST OidRequest,
			    _In_ NDIS_STATUS Status)
{
	UNREFERENCED_PARAMETER(ProtocolBindingContext);
	UNREFERENCED_PARAMETER(Status);
	if (OidRequest == NULL)
		return;
	{
		IWAN_MP_OID_SET *o =
			CONTAINING_RECORD(OidRequest, IWAN_MP_OID_SET, req);

		InterlockedDecrement(&g_oid_pending);
		if (InterlockedExchange(&o->done, 1) == 0)
			ExFreePoolWithTag(o, IWAN_TAG_PKT);
	}
}

/* Set the receive filter. Failure is only accounted, not fatal: without outer
 * frames the session can only send, not receive, a recognizable symptom (rx_outer stays 0); after a carrier restart open_complete sets it again. */
static VOID
iwan_win_proto_set_packet_filter(_Inout_ IWAN_MP_BINDING *b)
{
	IWAN_MP_OID_SET *o;
	NDIS_STATUS st;

	/* The two completion paths free once each: the sync return (the other half
	 * of the if below) and NDIS's OidRequestCompleteHandler callback (only on
	 * PENDING). The analyzer sees neither that NdisOidRequest holds the pointer
	 * nor the callback, so it reports C6014 -- same false-positive class as the WFP ctx/buf. */
#pragma warning(suppress: 6014)
	o = (IWAN_MP_OID_SET *)IWAN_ALLOC(sizeof(*o), IWAN_TAG_PKT);
	if (o == NULL) {
		DbgPrint("iwanmp: filter request allocation failed (if%u)\n",
			 (unsigned)b->ifindex);
		return;
	}
	RtlZeroMemory(o, sizeof(*o));
	o->value = IWAN_MP_FILTER_FLAGS;

	o->req.Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
	o->req.Header.Revision = NDIS_OID_REQUEST_REVISION_1;
	o->req.Header.Size = (USHORT)NDIS_SIZEOF_OID_REQUEST_REVISION_1;
	o->req.RequestType = NdisRequestSetInformation;
	o->req.Timeout = NDIS_OID_REQUEST_TIMEOUT_INFINITE;
	o->req.DATA.SET_INFORMATION.Oid = OID_GEN_CURRENT_PACKET_FILTER;
	o->req.DATA.SET_INFORMATION.InformationBuffer = &o->value;
	o->req.DATA.SET_INFORMATION.InformationBufferLength = sizeof(o->value);

	InterlockedIncrement(&g_oid_pending);
	st = NdisOidRequest(b->binding, &o->req);
	if (st != NDIS_STATUS_PENDING) {
		/* sync completion: NDIS did not take the request, finish it here */
		InterlockedDecrement(&g_oid_pending);
		if (InterlockedExchange(&o->done, 1) == 0)
			ExFreePoolWithTag(o, IWAN_TAG_PKT);
		DbgPrint("iwanmp: binding if%u receive filter 0x%08x -> 0x%08lx\n",
			 (unsigned)b->ifindex, (unsigned)IWAN_MP_FILTER_FLAGS,
			 (unsigned long)st);
	} else {
		DbgPrint("iwanmp: binding if%u receive filter 0x%08x (PENDING)\n",
			 (unsigned)b->ifindex, (unsigned)IWAN_MP_FILTER_FLAGS);
	}
}

/* ---- binding lifecycle ------------------------------------------------- */

static
_Function_class_(PROTOCOL_OPEN_ADAPTER_COMPLETE_EX)
VOID
iwan_win_proto_open_complete(_In_ NDIS_HANDLE ProtocolBindingContext,
			     _In_ NDIS_STATUS Status)
{
	IWAN_MP_BINDING *b = (IWAN_MP_BINDING *)ProtocolBindingContext;

	if (Status == NDIS_STATUS_SUCCESS) {
		/* The binding may already be unbound when open completes (eject/disable
		 * timing): the binding handle is being taken away by NdisCloseAdapterEx,
		 * so setting a filter now sends an OID to a closing handle. Checking
		 * closed alone suffices -- unbind sets closed first, waits for refs to drop, then closes the handle. */
		if (InterlockedCompareExchange(&b->closed, 1, 1) != 0) {
			InterlockedIncrement(&g_open_fail);
			InterlockedExchange(&g_open_status,
					    (LONG)STATUS_INVALID_DEVICE_STATE);
			DbgPrint("iwanmp: binding if%u already unbound when open completed, not setting the filter\n",
				 (unsigned)b->ifindex);
			NdisCompleteBindAdapterEx(b->bind_context, Status);
			return;
		}
		InterlockedIncrement(&g_open_ok);
		InterlockedExchange(&b->opened, 1);
		/* Set the filter first, only then count as usable: opened only means the
		 * handle opened; whether frames arrive is up to the filter. This is here
		 * because open_complete is the only moment b->binding is guaranteed usable. */
		iwan_win_proto_set_packet_filter(b);
	} else {
		/* Open failed: this binding is unusable, set the closed flag (do not free --
		 * the bind return path may still use it, and NDIS may already be indicating/sending on it). */
		InterlockedIncrement(&g_open_fail);
		InterlockedExchange(&g_open_status, (LONG)Status);
		DbgPrint("iwanmp: binding if%u open failed 0x%08lx\n",
			 (unsigned)b->ifindex, (unsigned long)Status);
		iwan_win_proto_binding_close(b);
	}
	/* bind completion receipt: finishes the bind when BindAdapterEx returned PENDING */
	NdisCompleteBindAdapterEx(b->bind_context, Status);
}

static
_Function_class_(PROTOCOL_CLOSE_ADAPTER_COMPLETE_EX)
VOID
iwan_win_proto_close_complete(_In_ NDIS_HANDLE ProtocolBindingContext)
{
	IWAN_MP_BINDING *b = (IWAN_MP_BINDING *)ProtocolBindingContext;

	iwan_win_proto_binding_close(b);
	NdisCompleteUnbindAdapterEx(b->unbind_context);
}

static
_Function_class_(PROTOCOL_BIND_ADAPTER_EX)
NDIS_STATUS
iwan_win_proto_bind(_In_ NDIS_HANDLE ProtocolDriverContext,
		    _In_ NDIS_HANDLE BindContext,
		    _In_ PNDIS_BIND_PARAMETERS BindParameters)
{
	IWAN_WIN_DEVICE_EXTENSION *ext =
		(IWAN_WIN_DEVICE_EXTENSION *)ProtocolDriverContext;
	IWAN_MP_BINDING *b;
	NDIS_OPEN_PARAMETERS op;
	NDIS_MEDIUM medium = NdisMedium802_3;
	UINT sel_medium = 0;
	NDIS_STATUS st;
	KIRQL old;

	InterlockedIncrement(&g_bind_calls);
	/* Only Ethernet carriers matter. Other media (loopback, tunnel pseudo-interfaces) are not this plane's business. */
	if (BindParameters->MediaType != NdisMedium802_3 ||
	    BindParameters->MacAddressLength != 6) {
		InterlockedIncrement(&g_bind_rejected);
		DbgPrint("iwanmp: rejecting binding, medium %u / MAC length %u (if%u)\n",
			 (unsigned)BindParameters->MediaType,
			 (unsigned)BindParameters->MacAddressLength,
			 (unsigned)BindParameters->BoundIfIndex);
		return NDIS_STATUS_NOT_SUPPORTED;
	}

	b = (IWAN_MP_BINDING *)IWAN_ALLOC(sizeof(*b), IWAN_TAG_PKT);
	if (b == NULL)
		return NDIS_STATUS_RESOURCES;
	RtlZeroMemory(b, sizeof(*b));
	b->ext = ext;
	b->bind_context = BindContext;
	b->ifindex = BindParameters->BoundIfIndex;
	/* BoundIfIndex may not match the user-mode oif_index, so convert it again
	 * from BoundIfNetluid (PASSIVE; the bind callback is PASSIVE). If the
	 * conversion fails, net stays 0 and the lookup matches on BoundIfIndex only, the old behavior. */
	{
		NET_IFINDEX nidx = 0;

		if (NdisIfGetInterfaceIndexFromNetLuid(
			    BindParameters->BoundIfNetluid, &nidx) ==
		    NDIS_STATUS_SUCCESS)
			b->ifindex_net = (UINT32)nidx;
	}
	b->mac_len = 6;
	RtlCopyMemory(b->mac, BindParameters->CurrentMacAddress, 6);
	/* AdapterName is a device path plus GUID, of the form \DEVICE\{GUID}.
	 * The lookup falls back to indexes (old behavior), but T88 exposes "not parsed" explicitly. */
	if (iwan_win_proto_parse_guid(BindParameters->AdapterName, b->guid))
		b->guid_valid = 1;
	else
		DbgPrint("iwanmp: cannot parse a GUID from AdapterName of binding %lu\n",
			 (unsigned long)b->ifindex);

	RtlZeroMemory(&op, sizeof(op));
	op.Header.Type = NDIS_OBJECT_TYPE_OPEN_PARAMETERS;
	op.Header.Revision = NDIS_OPEN_PARAMETERS_REVISION_1;
	op.Header.Size = NDIS_SIZEOF_OPEN_PARAMETERS_REVISION_1;
	op.AdapterName = BindParameters->AdapterName;
	op.MediumArray = &medium;
	op.MediumArraySize = 1;
	/* SelectedMediumIndex is a PUINT (an out pointer), not the index value.
	 * Writing 0 meant NULL: NDIS tolerates omission only when MediumArraySize == 1,
	 * and once the array holds another medium it would dereference NULL. Use a real variable here. */
	op.SelectedMediumIndex = &sel_medium;
	op.FrameTypeArray = NULL;
	op.FrameTypeArraySize = 0;

	KeAcquireSpinLock(&g_bind_lock, &old);
	InsertTailList(&g_bindings, &b->link);
	KeReleaseSpinLock(&g_bind_lock, old);

	st = NdisOpenAdapterEx(ext->mp.proto_handle, b, &op, BindContext,
			       &b->binding);
	InterlockedExchange(&g_bind_status, (LONG)st);
	if (st == NDIS_STATUS_SUCCESS) {
		/* A sync open success must also set the receive filter, and after opened=1:
		 * open_complete goes the same way (it calls set_packet_filter), but on a
		 * sync return there is **no open_complete callback at all** -- we once set
		 * the filter only in the async branch, so "binding in the table, opened=1,
		 * not one outer frame received", identical to a session with no carrier (rx_outer stays 0).
		 * Set it on every open success, one call for both paths, never split in two. */
		InterlockedIncrement(&g_open_ok);
		InterlockedExchange(&b->opened, 1);
		iwan_win_proto_set_packet_filter(b);
		/* Sync open success => bind does not return PENDING => no
		 * NdisCompleteBindAdapterEx needed; returning SUCCESS completes the bind. */
		return NDIS_STATUS_SUCCESS;
	}
	if (st == NDIS_STATUS_PENDING) {
		/* Async open: open_complete finishes it. Do **not** touch this binding
		 * here (we once freed it, and the later open_complete was a use-after-free). */
		return NDIS_STATUS_PENDING;
	}
	/* Hard failure: just set closed; memory is freed at fini */
	iwan_win_proto_binding_close(b);
	return st;
}

static
_Function_class_(PROTOCOL_UNBIND_ADAPTER_EX)
NDIS_STATUS
iwan_win_proto_unbind(_In_ NDIS_HANDLE UnbindContext,
		      _In_ NDIS_HANDLE ProtocolBindingContext)
{
	IWAN_MP_BINDING *b = (IWAN_MP_BINDING *)ProtocolBindingContext;
	NDIS_STATUS st;
	ULONG i;

	b->unbind_context = UnbindContext;
	/* The order is "unlink -> wait for in-flight to reach zero -> close the handle";
	 * (1) unlink first: binding_close sets closed and clears mp->active under
	 *     mp->lock, so new sends cannot get it (egress rechecks opened/closed under the lock);
	 * (2) then wait: a send that already got a reference allocates MDL/pool outside
	 *     the lock before calling NdisSendNetBufferLists; only when b->outstanding hits 0 is no one
	 *     still holding this binding handle (two allocations in that window, not a few instructions);
	 * (3) close last: the handle dies when NdisCloseAdapterEx returns, and no one can use it then.
	 * The reverse (close then wait) allows sends to a dead handle during close --
	 * 0xD1 at DISPATCH, or a binding refcount imbalance. */
	iwan_win_proto_binding_close(b);
	for (i = 0; i < 1000 && b->outstanding > 0; i++)
		KeStallExecutionProcessor(1000);
	if (b->outstanding > 0)
		DbgPrint("iwanmp: %ld sends still in flight at unbind, closing anyway\n",
			 (long)b->outstanding);
	st = NdisCloseAdapterEx(b->binding);
	if (st == NDIS_STATUS_PENDING) {
		/* async close: close_complete finishes it (the sync path must not complete the unbind) */
		return NDIS_STATUS_PENDING;
	}
	/* Sync close (success or failure): unbind does not return PENDING, NDIS considers
	 * it done, and we must **not** call NdisCompleteUnbindAdapterEx -- that API only
	 * finishes an unbind that returned PENDING; one extra call unbalances the unbind accounting. */
	return NDIS_STATUS_SUCCESS;
}

static
_Function_class_(SET_OPTIONS)
NDIS_STATUS
iwan_win_proto_set_options(_In_ NDIS_HANDLE NdisDriverHandle,
			   _In_ NDIS_HANDLE DriverContext)
{
	UNREFERENCED_PARAMETER(NdisDriverHandle);
	UNREFERENCED_PARAMETER(DriverContext);
	return NDIS_STATUS_SUCCESS;
}

static
_Function_class_(PROTOCOL_STATUS_EX)
VOID
iwan_win_proto_status(_In_ NDIS_HANDLE ProtocolBindingContext,
		      _In_ PNDIS_STATUS_INDICATION StatusIndication)
{
	UNREFERENCED_PARAMETER(ProtocolBindingContext);
	UNREFERENCED_PARAMETER(StatusIndication);
}

static
_Function_class_(PROTOCOL_NET_PNP_EVENT)
NDIS_STATUS
iwan_win_proto_pnp_event(_In_ NDIS_HANDLE ProtocolBindingContext,
			 _In_ PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification)
{
	UNREFERENCED_PARAMETER(ProtocolBindingContext);
	UNREFERENCED_PARAMETER(NetPnPEventNotification);
	return NDIS_STATUS_SUCCESS;
}

/* ---- carrier selection (session <-> NIC) ------------------------------ */

/* Called by IOCTL_OPEN after the session is set up. Criterion: the session's
 * oif_index must hit an opened Ethernet carrier; the next hop is the session's outer_hop, 0 meaning "peer is on-link". */
/* Publish the ARP diagnostic counters to the registry (PASSIVE only: control-device GET path).
 * T93 requests sent / T94 ARP frames received / T95 neighbors learned / T96 peer_mac_valid.
 * Only all three together distinguish "never sent", "sent but no reply" and "reply came but not accepted". */
VOID
iwan_win_mp_trace_arp(_In_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	IWAN_MP_PLANE *mp = &ext->mp;

	iwan_win_mp_trace(93, mp->arp_sent);
	iwan_win_mp_trace(94, mp->arp_rx);
	iwan_win_mp_trace(95, mp->arp_learn);
	iwan_win_mp_trace(96, mp->peer_mac_valid);
}

NTSTATUS
iwan_win_mp_select_carrier(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	IWAN_MP_PLANE *mp = &ext->mp;
	IWAN_MP_BINDING *b;
	KIRQL old;

	if (s->oif_index == 0) {
		DbgPrint("iwanmp: session specifies no carrier interface (oif_index=0), refusing to set up\n");
		return STATUS_INVALID_PARAMETER;
	}

	/* The flag (g_proto_started) is only raised after "table and lock are initialized",
	 * so 0 is equivalent to "the table is unreadable". NoProto=1, total protocol
	 * registration failure, or opening a session after unload all land here --
	 * reject here instead of letting the lookup dereference an all-zero table. */
	if (InterlockedCompareExchange(&g_proto_started, 1, 1) == 0) {
		DbgPrint("iwanmp: protocol side not started (g_proto_started=0), refusing to set up\n");
		return STATUS_DEVICE_NOT_READY;
	}

	/* T86 = the interface index the session asked for. Without this key the binding
	 * indexes in T74/T84 have no reference: "not found" and "different index" look identical in the log. */
	iwan_win_mp_trace(86, (LONG)s->oif_index);
	/* T87 = whether the control plane sent a GUID down (1 = yes, lookup by GUID only).
	 * T88 = (hits << 8) | nodes parsed OK. T87=1 with 0 hits means either
	 * AdapterName did not parse or the control plane computed the wrong GUID. */
	if (!iwan_win_proto_guid_zero(s->outer_if_guid)) {
		iwan_win_mp_trace(87, 1);
		iwan_win_mp_trace(88,
			iwan_win_proto_binding_guid_stat(s->outer_if_guid));
	} else {
		iwan_win_mp_trace(87, 0);
	}

	KeAcquireSpinLock(&g_bind_lock, &old);
	b = iwan_win_proto_lookup_locked(s->outer_if_guid, s->oif_index);
	KeReleaseSpinLock(&g_bind_lock, old);
	/* If the open is still in flight, wait a bit: the control plane (kdp_win) sends
	 * OPEN once when setting up a session, and if NDIS's open_complete is tens of
	 * ms late the whole session setup fails. Wait only in this case: a node for
	 * that interface in the table, not closed, not opened yet. At most 2 s, then
	 * return DEVICE_NOT_READY as before. KeStallExecutionProcessor is usable at PASSIVE (IOCTL path), and we deliberately avoid timers or other kernel objects. */
	{
		ULONG spins = 0;

		while (b == NULL &&
		       iwan_win_proto_binding_pending(s->outer_if_guid,
						      s->oif_index) &&
		       spins < 200) {
			/* Yield the CPU at PASSIVE: this is a control-plane IRP thread and
			 * busy-waiting for 2 s burns a core. KeDelayExecutionThread creates no
			 * kernel object, so it does not violate "no timers/threads in the driver".
			 * If we somehow get raised to DISPATCH (should not happen), fall back to stall-waiting. */
			if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
				LARGE_INTEGER iv;

				iv.QuadPart = -10 * 10000;	/* 10 ms, relative */
				KeDelayExecutionThread(KernelMode, FALSE, &iv);
			} else {
				KeStallExecutionProcessor(10000);
			}
			spins++;
			KeAcquireSpinLock(&g_bind_lock, &old);
			b = iwan_win_proto_lookup_locked(s->outer_if_guid,
							 s->oif_index);
			KeReleaseSpinLock(&g_bind_lock, old);
		}
		iwan_win_mp_trace(83, (LONG)spins);
	}
	/* Publish diagnostics only after unlocking: T70=1 => the table was never InitializeListHead'ed;
	 * T71 = node count. T70 absent with T71=0 => the table is fine but NDIS never
	 * gave one binding (the protocol side cannot bind a carrier). The two causes need completely different handling. */
	iwan_win_mp_trace(70,
			  InterlockedCompareExchange(&g_bind_table_broken, 1, 1));
	iwan_win_mp_trace(71, (LONG)iwan_win_proto_binding_count());
	/* T72/T73: open_complete success/failure counts. A binding in the table that
	 * cannot open (T73>0) and no NDIS callback at all (both 0) are different issues.
	 * T74/T75: the first two bindings packed as ifindex|opened<<14|closed<<15; with T71
	 * they distinguish "wrong index picked" from "bound but not opened". */
	iwan_win_mp_trace(72, InterlockedCompareExchange(&g_open_ok, 0, 0));
	iwan_win_mp_trace(73, InterlockedCompareExchange(&g_open_fail, 0, 0));
	iwan_win_mp_trace(74, iwan_win_proto_bind_info(0));
	iwan_win_mp_trace(75, iwan_win_proto_bind_info(1));
	/* T76 = the raw NTSTATUS open_complete reported, T77 = the error
	 * NdisOpenAdapterEx returned on the spot in bind. Both 0 with the opened bit 0 in
	 * T74/T75 => the open is still in flight (PENDING never returns), not a failure.
	 * T78 = how many times NDIS called BindAdapterEx, T79 = how many we rejected on
	 * medium/MAC: with T71=0, 78=0 means "NDIS never called us", 78>0 with 79=78 means "called, all rejected"; the fixes are completely different. */
	iwan_win_mp_trace(76, InterlockedCompareExchange(&g_open_status, 0, 0));
	iwan_win_mp_trace(77, InterlockedCompareExchange(&g_bind_status, 0, 0));
	iwan_win_mp_trace(78, InterlockedCompareExchange(&g_bind_calls, 0, 0));
	iwan_win_mp_trace(79, InterlockedCompareExchange(&g_bind_rejected, 0, 0));
	/* T84/T85 = the second index of the first two bindings converted from BoundIfNetluid
	 * (with opened/closed bits). Compare with BoundIfIndex in T74/T75: equal keys
	 * mean the two numbering schemes agree (look elsewhere), different means the lookup chose the wrong one. */
	iwan_win_mp_trace(84, iwan_win_proto_bind_info_net(0));
	iwan_win_mp_trace(85, iwan_win_proto_bind_info_net(1));
	if (b == NULL) {
		/* One key for each of the three outcomes: Stage/Status only records the last
		 * call, and two paths here both return DEVICE_NOT_READY, indistinguishable by Stage. */
		iwan_win_mp_trace(80, 1);
		DbgPrint("iwanmp: no usable Ethernet carrier on interface %lu, refusing to set up\n",
			 (unsigned long)s->oif_index);
		return STATUS_DEVICE_NOT_READY;
	}

	KeAcquireSpinLock(&mp->lock, &old);
	/* There is a window between the lookup (g_bind_lock) and the assignment here:
	 * if the binding is unbound right now, binding_close's cleanup test "mp->active == b" is
	 * still false, so mp->active stays on a closed binding -- sends are blocked by the
	 * opened recheck, but the session looks set up while not one byte can leave. Recheck under the same lock. */
	if (b->opened == 0 || b->closed != 0) {
		KeReleaseSpinLock(&mp->lock, old);
		iwan_win_mp_trace(81, 1);
		DbgPrint("iwanmp: carrier interface %lu was unbound the moment it was selected, refusing session setup\n",
			 (unsigned long)s->oif_index);
		return STATUS_DEVICE_NOT_READY;
	}
	mp->active = b;
	mp->active_ifindex = b->ifindex;
	mp->next_hop_be = s->outer_hop != 0 ? s->outer_hop : s->outer_dst;
	RtlCopyMemory(mp->local_mac, b->mac, 6);
	InterlockedExchange(&mp->peer_mac_valid, 0);
	InterlockedExchange(&mp->peer_mac_pending, 0);
	mp->arp_ts_ms = 0;
	mp->arp_last_ms = 0;
	KeReleaseSpinLock(&mp->lock, old);

	DbgPrint("iwanmp: carrier = interface %lu (%02x-%02x-%02x-%02x-%02x-%02x),"
		 "next hop %lu.%lu.%lu.%lu\n", (unsigned long)b->ifindex,
		 b->mac[0], b->mac[1], b->mac[2], b->mac[3], b->mac[4], b->mac[5],
		 (unsigned long)((mp->next_hop_be >> 24) & 0xFFu),
		 (unsigned long)((mp->next_hop_be >> 16) & 0xFFu),
		 (unsigned long)((mp->next_hop_be >> 8) & 0xFFu),
		 (unsigned long)(mp->next_hop_be & 0xFFu));
	iwan_win_mp_trace(82, (LONG)b->ifindex);
	return STATUS_SUCCESS;
}

VOID
iwan_win_mp_release_carrier(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	IWAN_MP_PLANE *mp = &ext->mp;
	KIRQL old;

	KeAcquireSpinLock(&mp->lock, &old);
	mp->active = NULL;
	mp->active_ifindex = 0;
	mp->next_hop_be = 0;
	InterlockedExchange(&mp->peer_mac_valid, 0);
	InterlockedExchange(&mp->peer_mac_pending, 0);
	mp->arp_ts_ms = 0;
	mp->arp_last_ms = 0;
	KeReleaseSpinLock(&mp->lock, old);
}

/* ---- register and deregister ------------------------------------------ */

NTSTATUS
iwan_win_proto_init(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	/* A single registration was rejected on the target (miniport side 0xC0010005 = NDIS_STATUS_BAD_
	 * CHARACTERISTICS, see the note in mp.c), and in the old experiment "the first version candidate hit" was reading a
	 * stale key. So restore the candidate table here: each candidate logs T60+i, the hit logs T69 (value = declared
	 * minor version), all failures log T58 = attempt count. Trying further after the first fails assumes
	 * "no handle is kept unless it succeeds": only the successful candidate writes proto_handle. */
	NDIS_PROTOCOL_DRIVER_CHARACTERISTICS ch;
	NDIS_STATUS last = NDIS_STATUS_BAD_CHARACTERISTICS;
	UCHAR runtime = (UCHAR)(NdisGetVersion() & 0xFFu);
	/* 0xFF = use the runtime minor version; later candidates are conservative declarations */
	static const UCHAR cand_minor[] = { 0xFF, 0xFF, 0, 0, 80, 60, 30 };
	static const UCHAR cand_rev[] = {
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1,
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2,
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1,
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2,
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1,
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1,
		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1
	};
	ULONG ci;

	/* The flag means "binding table readable, egress pool usable", so only the success path may raise it at the end.
	 * The reverse (raise first, initialize later) is that 0xD1 on the target: any reader
	 * that sees the flag may read an all-zero table -- a LIST_ENTRY in BSS is 16 zero
	 * bytes, not an empty list pointing at itself; walking it reads 0x30 as an ifindex. */
	if (InterlockedCompareExchange(&g_proto_started, 0, 0) != 0)
		return STATUS_SUCCESS;

	InterlockedExchange(&g_bind_table_broken, 0);
	/* The counters are cleared only at "first driver-level init": after registration
	 * NDIS calls bind over time; resetting these numbers elsewhere makes T72..T79 read "no callback" as "called back".
	 * This is in the same section and thread as the flag read and cannot be reached twice. */
	g_open_ok = 0;
	g_open_fail = 0;
	g_open_status = 0;
	g_bind_status = 0;
	g_bind_calls = 0;
	g_bind_rejected = 0;
	InitializeListHead(&g_bindings);
	KeInitializeSpinLock(&g_bind_lock);

	for (ci = 0; ci < RTL_NUMBER_OF(cand_minor); ci++) {
		UCHAR minor = cand_minor[ci] == 0xFF ? runtime : cand_minor[ci];
		NDIS_STATUS st;

		RtlZeroMemory(&ch, sizeof(ch));
		ch.Header.Type = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;
		ch.Header.Revision = cand_rev[ci];
		ch.Header.Size = (cand_rev[ci] ==
				  NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2) ?
			NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2 :
			NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1;
		ch.MajorNdisVersion = 6;
		ch.MinorNdisVersion = minor;
		ch.MajorDriverVersion = 1;
		ch.MinorDriverVersion = 0;
		ch.Flags = 0;
		NdisInitUnicodeString(&ch.Name, L"IWANMP");
		ch.SetOptionsHandler = iwan_win_proto_set_options;
		ch.BindAdapterHandlerEx = iwan_win_proto_bind;
		ch.UnbindAdapterHandlerEx = iwan_win_proto_unbind;
		ch.OpenAdapterCompleteHandlerEx = iwan_win_proto_open_complete;
		ch.CloseAdapterCompleteHandlerEx = iwan_win_proto_close_complete;
		ch.NetPnPEventHandler = iwan_win_proto_pnp_event;
		ch.OidRequestCompleteHandler = iwan_win_proto_oid_complete;
		ch.StatusHandlerEx = iwan_win_proto_status;
		ch.ReceiveNetBufferListsHandler = iwan_win_proto_recv_nbls;
		ch.SendNetBufferListsCompleteHandler = iwan_win_proto_send_complete;

		st = NdisRegisterProtocolDriver(ext, &ch,
						&ext->mp.proto_handle);
		iwan_win_mp_trace(60 + ci, (LONG)st);
		last = st;
		if (st == NDIS_STATUS_SUCCESS) {
			iwan_win_mp_trace(69, (LONG)minor);
			DbgPrint("iwanmp: protocol side registered (NDIS 6.%u, rev %u)\n",
				 (unsigned)minor, (unsigned)cand_rev[ci]);
			/* The egress NBL pool is owned by the protocol side: its lifetime must cover all
			 * in-flight outer sends (NdisFreeNetBufferList in the completion callback), so it cannot be created in the miniport --
			 * that pool is destroyed by MiniportHaltEx on device restart. */
			{
				NET_BUFFER_LIST_POOL_PARAMETERS pp;

				RtlZeroMemory(&pp, sizeof(pp));
				pp.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
				pp.Header.Revision =
					NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
				pp.Header.Size =
					NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
				pp.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
				pp.fAllocateNetBuffer = TRUE;
				pp.ContextSize = IWAN_MP_NBL_CTX_SIZE;
				pp.PoolTag = IWAN_TAG_PKT;
				ext->mp.tx_pool = NdisAllocateNetBufferListPool(
					ext->mp.proto_handle, &pp);
			}
			if (ext->mp.tx_pool == NULL) {
				/* Pool creation failed, deregister on the spot: the miniport is not registered yet, failure is clean. */
				iwan_win_mp_trace(57, NDIS_STATUS_RESOURCES);
				NdisDeregisterProtocolDriver(ext->mp.proto_handle);
				ext->mp.proto_handle = NULL;
				InterlockedExchange(&g_proto_started, 0);
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			/* Only now are "table readable, pool usable" both true; raise the flag at this point.
			 * Session requests arriving before this are rejected by select_carrier. */
			InterlockedExchange(&g_proto_started, 1);
			return STATUS_SUCCESS;
		}
	}
	/* No candidate succeeded: keep no half handle */
	ext->mp.proto_handle = NULL;
	InterlockedExchange(&g_proto_started, 0);
	iwan_win_mp_trace(58, (LONG)RTL_NUMBER_OF(cand_minor));
	DbgPrint("iwanmp: NdisRegisterProtocolDriver all candidates failed 0x%08lx\n",
		 (unsigned long)last);
	return last;
}

VOID
iwan_win_proto_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	PLIST_ENTRY e, n;
	ULONG i;
	KIRQL old;

	if (ext->mp.proto_handle == NULL)
		return;
	/* NdisDeregisterProtocolDriver is VOID (ndis.h:7975-7978), there is no return value
	 * to check. What really guarantees "callbacks stopped" is draining the in-flight counts below: if it does not drain, no memory is freed.
	 * It waits for all callbacks to return; after that the binding table stops changing -- the only safe free point. */
	NdisDeregisterProtocolDriver(ext->mp.proto_handle);
	ext->mp.proto_handle = NULL;
	InterlockedExchange(&g_proto_started, 0);
	iwan_win_mp_release_carrier(ext);
	/* Touch memory only after in-flight outer sends reach zero: the completion callback dereferences b->ext/b->outstanding
	 * and calls NdisFreeNetBufferList. If it does not drain, leak everything (the driver is about to unload). */
	for (i = 0; i < 1000 &&
	     (ext->mp.outer_outstanding > 0 || g_oid_pending > 0); i++)
		KeStallExecutionProcessor(1000);
	if (ext->mp.outer_outstanding > 0 || g_oid_pending > 0) {
		DbgPrint("iwanmp: %ld outer sends, %ld OIDs still incomplete at deregistration,"
			 "bindings and pool are not freed\n",
			 (long)ext->mp.outer_outstanding, (long)g_oid_pending);
		return;
	}
	if (ext->mp.tx_pool != NULL) {
		NdisFreeNetBufferListPool(ext->mp.tx_pool);
		ext->mp.tx_pool = NULL;
	}

	/* Unlink only, do not free: once a node is ExFreePoolWithTag'ed, any path still using b
	 * (select_carrier gets b, drops g_bind_lock, then rechecks
	 * b->opened/b->closed under mp->lock) reads freed memory. The driver is unloading; a few tens of
	 * bytes of leaked binding are far cheaper than a bugcheck; and with the nodes kept, the list pointers always point at valid
	 * memory, so even a stale pointer just walks to the list head and stops.
	 * We once set b->link.Flink=NULL before freeing -- that was the other trigger
	 * shape of 0xD1: the walk read Flink=NULL, then cmpl 0x30(%r14) hit 0x30. */
	KeAcquireSpinLock(&g_bind_lock, &old);
	/* Treat the list head as untrusted data too: on the unload path its value may come from an incomplete
	 * initialization (Flink=NULL). Before unlinking, make sure it points at itself or a real node. */
	if (g_bindings.Flink == NULL)
		InitializeListHead(&g_bindings);
	for (e = g_bindings.Flink; e != NULL && e != &g_bindings; e = n) {
		IWAN_MP_BINDING *b = CONTAINING_RECORD(e, IWAN_MP_BINDING, link);

		n = e->Flink;
		RemoveEntryList(e);
		b->opened = 0;
		b->closed = 1;
	}
	InitializeListHead(&g_bindings);
	KeReleaseSpinLock(&g_bind_lock, old);
}
