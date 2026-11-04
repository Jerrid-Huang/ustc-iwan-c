/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_wfp.c - WFP callout data plane: outbound encapsulation + (M2) inbound decapsulation.
 *
 * The placement of the two layers (the inbound layer is chosen deliberately):
 *   - outbound: FWPS_LAYER_OUTBOUND_IPPACKET_V4/V6 -- the IP header is already built, not yet fragmented;
 *   - inbound: FWPS_LAYER_INBOUND_TRANSPORT_V4/V6 -- **after protocol-stack reassembly**: outer fragments
 *     are already reassembled and the IP header is stripped; layerData starts at the UDP header, and the addresses come from WFP fixed fields.
 *     Linux side sits "between the two reassembly passes" and does its own ip_defrag (see the
 *     comment in kernel/iwan_rx.c); Windows hands this step to the protocol stack, in exchange for not having to handle fragments itself.
 *   - injection still goes back to **before reassembly** (network layer FwpsInjectNetworkReceiveAsync): inner packets
 *     go through the full IP parse, reassembly and dispatch as usual -- the same semantics as NF_ACCEPT/netif_rx on the Linux side after decap
 *     returning to before ip_defrag.
 *
 * Corresponds to iwan_xmit (outbound) in kernel/iwan_tx.c and the
 * hooks (inbound) in kernel/iwan_rx.c. The on-wire format is **byte-for-byte identical** to the Linux module; this is the hard prerequisite for interoperability:
 *
 *   outer IPv4(20) | outer UDP(8) | iWAN frame header(8) | [inner IP packet after XOR]
 *   iWAN frame header: fh[0] = PT_DATA(0x14) or PT_DATA_ENC(0x18)
 *              fh[1] = enc flag (1/0)
 *              fh[2..3] = sid (big-endian)
 *              fh[4..7] = tok (big-endian)
 *   XOR: the inner packet (including its own IP header) is XORed byte by byte with key[i & 7] starting at offset 0;
 *        the inner checksum must be the plaintext checksum **before** XOR (same comment on the Linux side:
 *        "at this point the checksum is already the plaintext checksum and stays self-consistent after XOR").
 *
 * Key differences from the Linux side (all platform differences, not semantic differences):
 *   - Linux decides which packets enter the tunnel by "routing to iwan0"; here the target set issued with the session does
 *     longest-prefix matching (WFP outbound runs after routing and cannot see user intent);
 *   - the outer server address must be excluded explicitly (equivalent to Linux' "server /32 pinned to the physical NIC"),
 *     otherwise a broad prefix in the target set would pull in the tunnel's own outer packets too;
 *   - inner packets may arrive carrying the "checksum offload" flag (on the Linux side the checksum is ready at this point,
 *     Windows side may not have it), so here the inner checksum is completed in software as needed before XOR.
 *
 * M1 boundaries (what is explicitly not done; everything fails closed and is counted, plaintext is never let out):
 *   - large segments from segmentation offload (inner length > inner MTU) are not encapsulated for now: counted and then **dropped**;
 *     no "pass-through" is implemented, to avoid plaintext leaks; for software segmentation see README M1.1;
 *   - non-linear packets (data spanning multiple MDLs) are not handled for now: counted and passed (not absorbed).
 */
#include "iwan_win.h"

/* Each callout uses a fixed GUID; static objects are used instead of DEFINE_GUID, to avoid initguid.h
 * instantiation rules causing duplicate definitions in the driver. */
static const GUID IWAN_CALLOUT_OUT4 = {
	0x7f3c1a10, 0x2b41, 0x4c8e, { 0x9a, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x01 }
};
static const GUID IWAN_CALLOUT_OUT6 = {
	0x7f3c1a10, 0x2b41, 0x4c8e, { 0x9a, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x02 }
};
static const GUID IWAN_CALLOUT_IN4 = {
	0x7f3c1a10, 0x2b41, 0x4c8e, { 0x9a, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x03 }
};
static const GUID IWAN_CALLOUT_IN6 = {
	0x7f3c1a10, 0x2b41, 0x4c8e, { 0x9a, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x04 }
};

#define IWAN_STAT_INC(ext, field) \
	InterlockedIncrement64((volatile LONG64 *)&(ext)->sess.stats.field)

/* Byte-count accumulation: same convention as IWAN_STAT_INC (the data plane only does interlocked adds,
 * user mode is read-only; statistics never take part in any decision, reading slightly stale values is allowed). */
#define IWAN_STAT_ADD(ext, field, v) \
	InterlockedAdd64((volatile LONG64 *)&(ext)->sess.stats.field, (LONG64)(v))

/* ---- outbound encapsulation --------------------------------------- */

/*
 * About C6014 in static analysis ("Leaking memory 'ctx' / 'buf' / 'nbl' / 'stor'"):
 * in this file all warnings of this kind are false positives; the rationale is written here so that next time nobody follows the warnings and
 * goes off to "fix" an ownership transfer that was correct in the first place.
 *
 *   - ctx / ctx->buf: after allocation handed to the completion callback of FwpsInject*Async,
 *     iwan_win_inject_complete is what frees them (same file :96-101). WFP's injection API
 *     has no SAL annotation describing this transfer, so the analyzer only sees "allocated, not freed before the function returns".
 *     In reality both failure paths (synchronous failure goto fail, asynchronous failure callback) each free exactly
 *     once, and the success path exactly once too -- verified by per-packet accounting on the target (1,375,401 frames
 *     100% delivered, no leak-related hard hang).
 *   - nbl (indicate_inner in iwan_win_mp.c): after it is handed to
 *     NdisMIndicateReceiveNetBufferLists -- once handed to it, it belongs to NDIS, and on return it is freed by
 *     MiniportReturnNetBufferLists -- that is NDIS's pool ownership convention.
 *   - stor (classify_out6): a temporary coalescing buffer inside the loop body; in this file there are three
 *     ExFreePoolWithTag + NULL assignments, and it is returned before every continue.
 *   - ext / devobj (DriverEntry): driver lifetime assets, freed with the device object and the unload path,
 *     not freed when a function returns.
 *
 * Rationale: as long as the "allocation point" and the "free point" are on two mutually exclusive paths of the same function, and each path
 * frees exactly once, this warning is a false positive. All four categories above were checked one by one.
 *
 * Handling: both analysis and build use /FI shared\warning.h, but C6014 is the analyzer's judgment that "ownership
 * transfer is not in a contract it can understand", and it does not go away with the header warnings; so at every allocation point
 * a line `#pragma warning(suppress: 6014)` is placed above it, with the rationale written on the spot. This is not
 * to scrub the log clean -- only by suppressing the known false positives one by one does the next newly appearing C6014
 * have any chance of being seen. When changing these suppressions, read the corresponding comment first, then read that code.
 */

typedef struct _IWAN_INJECT_CTX {
	PVOID	buf;		/* data buffer (freed after injection completes) */
	PMDL	mdl;		/* MDL of the data buffer */
	IWAN_WIN_DEVICE_EXTENSION	*ext;	/* used for the in-flight injection counter */
} IWAN_INJECT_CTX;

static VOID NTAPI
iwan_win_inject_complete(_In_ VOID *context, _Inout_ NET_BUFFER_LIST *nbl,
			 _In_ BOOLEAN dispatch_level)
{
	IWAN_INJECT_CTX *ctx = (IWAN_INJECT_CTX *)context;

	UNREFERENCED_PARAMETER(dispatch_level);
	/* "queued successfully" is not the same as "sent successfully": NET_BUFFER_LIST_STATUS in the completion callback
	 * is WFP's final verdict. A failure must land on a counter whose name matches
	 * (tx_err = encapsulation/injection failure); it must not borrow the inbound rx_* -- a borrowed counter makes
	 * the readings unexplainable when both planes share the same STATS. */
	if (ctx != NULL && ctx->ext != NULL) {
		ULONG ist = nbl != NULL ? NET_BUFFER_LIST_STATUS(nbl)
					: (ULONG)0xC0000001L;

		if (ist != STATUS_SUCCESS)
			IWAN_STAT_INC(ctx->ext, tx_err);
	}
	if (nbl != NULL)
		FwpsFreeNetBufferList(nbl);
	if (ctx != NULL) {
		if (ctx->mdl != NULL)
			IoFreeMdl(ctx->mdl);
		if (ctx->buf != NULL)
			ExFreePoolWithTag(ctx->buf, IWAN_TAG_PKT);
		if (ctx->ext != NULL)
			InterlockedDecrement(&ctx->ext->inject_outstanding);
		ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
	}
}

/*
 * Wrap a non-paged buffer in an NBL (the data is not counted in the NBL pool; ctx is responsible for freeing it).
 * Shared by outbound encapsulation and inbound decapsulation injection: both paths are "their own buffer + their own MDL".
 */
static NTSTATUS
iwan_win_nbl_wrap(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		  _Inout_ IWAN_INJECT_CTX *ctx, _Out_ NET_BUFFER_LIST **out_nbl,
		  _In_ ULONG len)
{
	NET_BUFFER_LIST *nbl = NULL;
	NTSTATUS st;

	ctx->mdl = IoAllocateMdl(ctx->buf, len, FALSE, FALSE, NULL);
	if (ctx->mdl == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	MmBuildMdlForNonPagedPool(ctx->mdl);

	/* MDL is handed to the allocator directly instead of being stuffed into NET_BUFFER_FIRST_MDL afterwards:
	 * NBL is in complete form from the moment it is born, and does not rely on this kind of
	 * undocumented usage: "allocate first, then modify internal fields". MDL ownership stays with the caller (ctx->mdl is freed by the completion callback or
	 * by the failure path IoFreeMdl); here it is only lent to the NBL to describe the data.
	 * The pool handle is prebuilt by iwan_win_wfp_init: FwpsAllocateNetBufferAndNetBufferList0
	 * wants a pool handle, not a stack copy of the pool parameters. */
	st = FwpsAllocateNetBufferAndNetBufferList(ext->nbl_pool, 0, 0, ctx->mdl,
						   0, len, &nbl);
	if (!NT_SUCCESS(st))
		return st;

	*out_nbl = nbl;
	return STATUS_SUCCESS;
}

/*
 * Encapsulate an inner IPv4 packet into an outer UDP packet and inject it into the protocol stack.
 * inner points at a **read-only** inner packet; this function copies it first and then transforms the copy,
 * and never touches the buffer the protocol stack is using (on Linux the skb is exclusively owned, so it can be modified in place).
 */

/*
 * Outbound encapsulation + injection. Whether the outer is v4 or v6 is decided by the **session** (outer_v6), independent of the inner
 * version -- this follows the Linux side: the inner version is determined by iwan_inner_hdr_check(), the outer version
 * by the carrier NIC, so both v6-in-v4 and v4-in-v6 are valid.
 *
 * Failures are always reclaimed locally; a "half-encapsulated" buffer is never allowed to flow out.
 */
/* In-flight injection limit (each in-flight packet occupies about 2 KB of non-paged pool: buffer + MDL + NBL, and is only returned
 * when the completion callback runs). What happens without a limit: the flood rate is far above the carrier channel (measured 21k pps),
 * outbound absorption also removes the sender's backpressure -- the pool grows net at GB/s scale and exhausts the non-paged
 * pool within seconds; the whole machine hard-hangs and there is no time to write a BugCheck (matches Kernel-Power 41 + 6008).
 * Over the limit, drop the current packet and count tx_bad_state, returning backpressure to the protocol stack. */
#define IWAN_WIN_MAX_INFLIGHT 1024u

/* Record of outbound rejection/drop reasons: implemented in iwan_win_session.c (shared by both data planes),
 * only the call sites remain here. */

static NTSTATUS
iwan_win_encap_inject(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		      _In_reads_bytes_(inner_len) const UINT8 *inner,
		      _In_ ULONG inner_len, _In_ BOOLEAN l4_offloaded,
		      _In_ UINT16 compartment, _In_ BOOLEAN outer_v6)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	IWAN_INJECT_CTX *ctx = NULL;
	NET_BUFFER_LIST *nbl = NULL;
	UINT8 *buf, *fh;
	ULONG overhead = outer_v6 ? IWAN_OUTER6_TOTAL : IWAN_OUTER4_TOTAL;
	ULONG total = overhead + inner_len;
	ULONG flen = IWAN_FRAME_HDR_LEN + inner_len;
	NTSTATUS st;

	if (inner_len == 0 || total > 0xFFFF) {
		return STATUS_INVALID_BUFFER_SIZE;
	}

	if (ext->inject_outstanding >= IWAN_WIN_MAX_INFLIGHT) {
		/* The in-flight window is full = deliberate throttling, not an encapsulation failure. The diagnostics area must record them separately,
		 * otherwise in the field "backpressure drop" gets read as "malformed packet". */
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_INFLIGHT, inner_len,
				 total, inner_len > 0 ? (ULONG)inner[0] : 0xFFFFu,
				 inner);
		IWAN_STAT_INC(ext, tx_bad_state);
		return STATUS_DEVICE_BUSY;
	}

	/* C6014 false positive: ownership of ctx and buf is handed to
	 * FwpsInjectNetworkSendAsync0, and the completion callback iwan_win_inject_complete
	 * frees them. WFP's injection API has no "ownership transfer" SAL annotation, so the analyzer only sees
	 * "allocated but not freed before return"; the suppression here is a judgment call, not a waiver. */
#pragma warning(suppress: 6014)
	ctx = (IWAN_INJECT_CTX *)IWAN_ALLOC(sizeof(*ctx), IWAN_TAG_PKT);
	if (ctx == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	/* Same as above: buf is freed by the completion callback. */
#pragma warning(suppress: 6014)
	buf = (UINT8 *)IWAN_ALLOC(total, IWAN_TAG_PKT);
	if (buf == NULL) {
		ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	ctx->buf = buf;
	ctx->ext = ext;
	/* Pool allocation is not guaranteed to be zeroed (see the IWAN_ALLOC comment in iwan_win.h): when building the outer header fails,
	 * the failure path is taken as well, and at that point mdl has not been assigned by nbl_wrap; without initialization it would read a wild pointer
	 * and hand it to IoFreeMdl. */
	ctx->mdl = NULL;

	/* The frame sits right after IP + UDP: overhead is the "total encapsulation overhead", one frame header length more than
	 * the frame's start offset. Lay the frame down first, then let the portable layer write the outer header (both checksums are there). */
	fh = buf + overhead - IWAN_FRAME_HDR_LEN;
	iwan_win_build_frame_hdr(fh, s->enc ? PT_DATA_ENC : PT_DATA, s->enc,
				 s->sid, s->tok);
	RtlCopyMemory(fh + IWAN_FRAME_HDR_LEN, inner, inner_len);
	/* Plaintext checksum -> XOR (the order must not be reversed: when the receive side recovers the plaintext, the checksum must already be correct) */
	iwan_win_inner_fix_csum(fh + IWAN_FRAME_HDR_LEN, inner_len, l4_offloaded);
	if (s->enc)
		iwan_win_xor(fh + IWAN_FRAME_HDR_LEN, inner_len, s->key, 0);

	if (outer_v6) {
		if (iwan_win_outer_hdr6(buf, total, flen, s->outer_src6,
					s->outer_dst6, s->sport,
					s->dport) != total) {
			goto fail;
		}
	} else {
		if (iwan_win_outer_hdr4(buf, total, flen, s->outer_src,
					s->outer_dst, s->sport,
					s->dport) != total) {
			goto fail;
		}
	}

	st = iwan_win_nbl_wrap(ext, ctx, &nbl, total);
	if (!NT_SUCCESS(st)) {
		goto fail;
	}

	/* In-flight injection count: unregister/unload must wait for it to reach zero before the injection handles and pool can be destroyed */
	InterlockedIncrement(&ext->inject_outstanding);
	/* The injection handle may fail synchronously or asynchronously (the completion callback reports an NTSTATUS).
	 * Both failures are handled by the completion callback, which frees ctx->buf / ctx->mdl / ctx uniformly,
	 * that is, "after handing them over this function no longer owns them". */
	st = FwpsInjectNetworkSendAsync(outer_v6 ? ext->inj_send6 : ext->inj_send4,
					NULL, 0, compartment, nbl,
					iwan_win_inject_complete, ctx);
	if (!NT_SUCCESS(st)) {
		/* Injection failed: injection ownership was not transferred, reclaim locally */
		InterlockedDecrement(&ext->inject_outstanding);
		FwpsFreeNetBufferList(nbl);
		/* Must be set to NULL: the fail branch checks nbl once more; without NULLing it the same NBL would be freed
		 * twice -- the same node linked twice on the free list, two allocators getting the same memory, which is
		 * silent pool corruption / random hard hang (not caught on the spot unless Verifier is enabled). */
		nbl = NULL;
		goto fail;
	}
	/* Injection succeeded: ownership of ctx and buf has been handed to WFP together with the NBL; the completion callback
	 * (iwan_win_inject_complete) frees them. Both local pointers are invalidated here; this is the only marker of
	 * "ownership has been transferred", and it also keeps static analysis from reading it as a leak (C6014). */
	ctx = NULL;
	buf = NULL;
	return STATUS_SUCCESS;

fail:
	if (nbl != NULL)
		FwpsFreeNetBufferList(nbl);
	if (ctx->mdl != NULL)
		IoFreeMdl(ctx->mdl);
	ExFreePoolWithTag(buf, IWAN_TAG_PKT);
	ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
	return STATUS_INSUFFICIENT_RESOURCES;
}

/*
 * Is this NBL one that we injected ourselves?
 *
 * Injection is not "bypassing the protocol stack": an injected packet walks the same layer again, so it enters our
 * classify. If it is not recognized it would be encapsulated twice (outer around outer), so outbound must pass its own injected
 * outer packets, and inbound must pass its own injected inner packets. WFP's own accounting
 * (FwpsQueryPacketInjectionState0) is used for the decision, rather than relying on such a coincidence as
 * "the destination address is not in the target set".
 */
static BOOLEAN
iwan_win_nbl_from_self(_In_ HANDLE handle, _In_ const NET_BUFFER_LIST *nbl)
{
	FWPS_PACKET_INJECTION_STATE st;

	if (handle == NULL || nbl == NULL)
		return FALSE;
	/* The third parameter is [out, optional]; NULL is passed here and only the return value is used -- the return value itself
	 * is the injection state. Reason: in WDK 10.0.26100 fwpsk.h declares it as HANDLE *
	 * (the docs say FWPS_PACKET_INJECTION_STATE *), and under /WX C4022 is treated as an error.
	 * With NULL both declarations compile, and the semantics do not depend on that out parameter.
	 *
	 * Also note: even if this check fails due to the declaration mismatch, it will not cause outer-around-outer --
	 * when judging the target set we explicitly exclude the peer address (s->outer_dst), so our own injected
	 * outer packets would never match the target anyway. This is a second safety net, not the only line of defense. */
	st = FwpsQueryPacketInjectionState0(handle, nbl, NULL);
	return st == FWPS_PACKET_INJECTED_BY_SELF ||
	       st == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF;
}

/*
 * Is there any packet in the whole chain that "belongs to this session and should enter the tunnel"?
 *
 * Only called when "the whole chain should not all enter the tunnel": WFP's decision granularity is the whole NBL chain, there is no
 * "absorb half" option. If none is ours, pass it unchanged (the vast majority of cases); if at least one is,
 * take over the whole chain -- passing it would leak this session's plaintext to the carrier, and this rule matters more than
 * "letting other people's packets through". The other affected packets are counted into ev_dropped here.
 */
static BOOLEAN
iwan_win_chain_has_ours(_In_ IWAN_WIN_SESSION *s,
			_In_ NET_BUFFER_LIST *nbl)
{
	NET_BUFFER_LIST *cur;
	UINT8 od[4];

	iwan_win_wr32(od, s->outer_dst);
	for (cur = nbl; cur != NULL; cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
		NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
		UINT8 hdr[IWAN_OUTER_IP4_LEN];
		UINT8 *pkt;
		ULONG len, ihl, tot;

		if (nb == NULL)
			continue;
		len = NET_BUFFER_DATA_LENGTH(nb);
		pkt = (UINT8 *)NdisGetDataBuffer(nb, IWAN_OUTER_IP4_LEN, hdr, 1, 0);
		if (pkt == NULL || len < IWAN_OUTER_IP4_LEN || (pkt[0] >> 4) != 4)
			continue;
		ihl = (ULONG)(pkt[0] & 0x0F) * 4;
		tot = iwan_win_rd16(pkt + 2);
		if (ihl < IWAN_OUTER_IP4_LEN || tot < ihl || tot > len)
			continue;
		if (iwan_win_should_tunnel4(s->targets, s->target_count, od,
					    pkt + 16))
			return TRUE;
	}
	return FALSE;
}

/*
 * Outbound entry: oversized inner packets are first fragmented according to the declared inner MTU, then encapsulated fragment by fragment.
 *
 * Same convention as Linux: on the Linux side the protocol stack fragments before ndo_start_xmit according to the outer device MTU
 * and the driver only encapsulates per fragment; we intercept at OUTBOUND_IPPACKET (before fragmentation), so we must
 * fill in this step ourselves. The fragment threshold is the declared inner MTU (= min(server negotiated value, carrier MTU - overhead)),
 * so every fragment necessarily fits into the carrier, and the outer still has DF=1 and never fragments.
 *
 * frames/bytes report back "how many outer frames were actually injected and how many outer bytes": counters must be per frame;
 * recording per original packet would make tx_pkts mismatch the NIC counters in fragmented scenarios.
 */
static NTSTATUS
iwan_win_encap_send_pkt(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			_In_reads_bytes_(len) const UINT8 *inner,
			_In_ ULONG len, _In_ BOOLEAN l4_offloaded,
			_In_ UINT16 compartment, _In_ BOOLEAN outer_v6,
			_Out_ ULONG *frames, _Out_ ULONG *bytes)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	UINT8 *copy = NULL, *frag = NULL;
	ULONG mtu = s->inner_mtu;
	ULONG n, i, flen = 0;
	NTSTATUS st;

	*frames = 1;
	*bytes = len + (outer_v6 ? IWAN_OUTER6_TOTAL : IWAN_OUTER4_TOTAL);
	if (outer_v6)
		return iwan_win_encap_inject(ext, inner, len, l4_offloaded,
					     compartment, TRUE);

	n = (mtu > IWAN_WIN_MTU_MIN) ? iwan_win_frag4_count(inner, len, mtu) : 0;
	if (n == 0)
		return iwan_win_encap_inject(ext, inner, len, l4_offloaded,
					     compartment, FALSE);

	copy = (UINT8 *)IWAN_ALLOC(len, IWAN_TAG_PKT);
	frag = (UINT8 *)IWAN_ALLOC(mtu, IWAN_TAG_PKT);
	if (copy == NULL || frag == NULL) {
		if (copy != NULL)
			ExFreePoolWithTag(copy, IWAN_TAG_PKT);
		if (frag != NULL)
			ExFreePoolWithTag(frag, IWAN_TAG_PKT);
		*frames = 0;
		*bytes = 0;
		IWAN_STAT_INC(ext, tx_bad_state);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlCopyMemory(copy, inner, len);
	/* L4 checksum must be fixed up before splitting: only the first fragment carries the L4 header, and fixing it per fragment afterwards is impossible.
	 * After the fix-up every fragment is encapsulated with "checksum already correct" (l4_offloaded = FALSE). */
	iwan_win_inner_fix_csum(copy, len, l4_offloaded);

	st = STATUS_SUCCESS;
	*frames = 0;
	*bytes = 0;
	for (i = 0; i < n; i++) {
		if (!iwan_win_frag4_build(frag, mtu, copy, len, mtu, i, &flen)) {
			IWAN_STAT_INC(ext, tx_bad_state);
			st = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		st = iwan_win_encap_inject(ext, frag, flen, FALSE, compartment,
					   FALSE);
		if (!NT_SUCCESS(st))
			break;
		(*frames)++;
		*bytes += flen + IWAN_OUTER4_TOTAL;
	}
	ExFreePoolWithTag(frag, IWAN_TAG_PKT);
	ExFreePoolWithTag(copy, IWAN_TAG_PKT);
	return st;
}

static VOID NTAPI
iwan_win_classify_out4(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
		       _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
		       _Inout_opt_ void *layerData,
		       _In_opt_ const void *classifyContext,
		       _In_ const FWPS_FILTER *filter,
		       _In_ UINT64 flowContext,
		       _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
	IWAN_WIN_DEVICE_EXTENSION *ext =
		(IWAN_WIN_DEVICE_EXTENSION *)(ULONG_PTR)filter->context;
	IWAN_WIN_SESSION *s;
	NET_BUFFER_LIST *nbl = (NET_BUFFER_LIST *)layerData;
	NET_BUFFER_LIST *cur;
	UINT16 compartment = 0;
	BOOLEAN all_hit = TRUE;
	NTSTATUS st;
	UINT8 od[4];

	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);

	/* Write "permit" into the verdict first, then talk about anything else.
	 *
	 * The filter installed at this layer is a **terminating** filter: terminating means there is no "next" to continue to, so the verdict can only be PERMIT
	 * or BLOCK. Writing CONTINUE ("no opinion") produced this: as soon as the session is established, machine-wide traffic in both directions
	 * stops immediately -- the outbound callout was clearly called 233 times and returned permit every time, yet not a single packet
	 * went out; the target itself stayed perfectly alive, and everything recovered as soon as CLOSE returned.
	 * The write right (FWPS_RIGHT_ACTION_WRITE) governs "can we tighten to BLOCK", not "can we
	 * permit": without it, only permit, never tighten. */
	classifyOut->actionType = FWP_ACTION_PERMIT;

	if (ext == NULL || nbl == NULL)
		return;

	/* Permitting is not a failure in itself, but it **must leave a trace**: otherwise "the session exists but not one packet entered the tunnel"
	 * shows up as 17 counters all zero, completely indistinguishable from "the callout was not called at all". */
	if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
		IWAN_STAT_INC(ext, tx_bad_state);
		return;
	}

	/* Fast path: with no session, a single volatile read returns (the Linux side also checks the switch first) */
	s = &ext->sess;
	if (s->valid == 0 || s->inner_ip == 0) {
		/* inner_ip is filled in by the client. A real client once left it unset for a long time -- this branch permitted
		 * all outbound traffic, encapsulated not a single packet, and all counters stayed zero (kdp_win.c:350 has
		 * the same record). So counting here is mandatory. */
		IWAN_STAT_INC(ext, tx_bad_state);
		return;
	}

	/* Outer packet injected by ourselves: permit, never encapsulate another layer */
	if (iwan_win_nbl_from_self(ext->inj_send4, nbl) ||
	    iwan_win_nbl_from_self(ext->inj_send6, nbl))
		return;

	if (!ExAcquireRundownProtection(&ext->rundown))
		return;

	if (s->valid == 0)			/* confirm once more after taking the protection */
		goto done;

	if (inMetaValues != NULL &&
	    FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
					   FWPS_METADATA_FIELD_COMPARTMENT_ID))
		compartment = (UINT16)inMetaValues->compartmentId;

	/* Judge the whole block first: the whole chain should enter the tunnel in the common case (WFP usually has one packet per chain at this layer).
	 * When a mixed chain appears, do not attempt the impossible verdict of "absorb half" -- see the two branches below:
	 * if any packet belongs to this session, take over the whole chain; only when none does, pass the whole chain. */
	for (cur = nbl; cur != NULL; cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
		NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
		UINT8 hdr[IWAN_OUTER_IP4_LEN];
		UINT8 *pkt;
		ULONG len, ihl, tot;

		if (nb == NULL) {
			iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_NB_NULL, 0, 0, 0xFFFFu, NULL);
			all_hit = FALSE;
			break;
		}
		len = NET_BUFFER_DATA_LENGTH(nb);
		/* The header may span MDLs (this happens when UDP uses checksum offload: header and payload are in
		 * different memory blocks). Give NDIS a 20-byte stack buffer to assemble the header into;
		 * do not behave as before, "if a contiguous pointer cannot be obtained, declare HDR_BAD" -- that way every non-contiguous
		 * outbound packet was passed to the carrier, and the field symptom was that the tunnel had no throughput.
		 * The buffer is only 20 bytes and on the stack, does not cross calls, and does not involve the non-paged pool. */
		pkt = (UINT8 *)NdisGetDataBuffer(nb, IWAN_OUTER_IP4_LEN, hdr, 1, 0);
		if (pkt == NULL || (pkt[0] >> 4) != 4) {
			/* pkt == NULL can only mean the packet is shorter than 20 bytes (cannot be assembled) */
			iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_HDR_BAD, len, 0,
					 pkt != NULL ? (ULONG)pkt[0] : 0xFFFFu, pkt);
			IWAN_STAT_INC(ext, tx_bad_inner);
			all_hit = FALSE;
			break;
		}
		ihl = (ULONG)(pkt[0] & 0x0F) * 4;
		tot = iwan_win_rd16(pkt + 2);
		if (ihl < IWAN_OUTER_IP4_LEN || tot < ihl || tot > len) {
			iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_LEN_BAD, len, tot, pkt[0], pkt);
			IWAN_STAT_INC(ext, tx_bad_inner);
			all_hit = FALSE;
			break;
		}
		iwan_win_wr32(od, s->outer_dst);	/* the session stores a big-endian integer, bytes are needed here */
		if (!iwan_win_should_tunnel4(s->targets, s->target_count,
						  od, pkt + 16)) {
			all_hit = FALSE;
			break;
		}
		/* Oversized is no longer dropped outright: v4 is handed to the fragmentation layer (same convention as the Linux protocol stack which fragments
		 * before ndo_start_xmit by device MTU). Only under the malformed threshold of "not even an 8-byte fragment payload fits"
		 * does it fail closed -- never pass plaintext through, and never let the NIC fragment either. */
		if (tot + IWAN_OUTER4_TOTAL > s->carrier_mtu &&
		    iwan_win_frag4_count(pkt, tot, s->inner_mtu) == 0) {
			iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_MTU, len, tot, pkt[0], pkt);
			IWAN_STAT_INC(ext, tx_bad_state);
			classifyOut->actionType = FWP_ACTION_BLOCK;
			classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
			goto done;
		}
	}

	if (!all_hit) {
		/* Mixed chain: the whole chain should not all enter the tunnel. As long as any one packet in the chain belongs to this session,
		 * absorb the whole chain (this session's packets are encapsulated as usual, the rest are dropped per packet below and counted);
		 * if none does, pass it unchanged. Per-packet re-injection (re-injecting other people's packets into
		 * OUTBOUND_IPPACKET) requires extra injection state and loop-prevention criteria, left for later. */
		if (!iwan_win_chain_has_ours(s, nbl))
			goto done;
	}

	for (cur = nbl; cur != NULL; cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
		NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
		NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO ci;
		BOOLEAN l4_offloaded = FALSE;
		UINT8 hdr[IWAN_OUTER_IP4_LEN];
		UINT8 *stor = NULL;
		UINT8 *pkt;
		ULONG nblen, tot, frames, fbytes;

		nblen = NET_BUFFER_DATA_LENGTH(nb);
		/* The decision only needs the first 20 contiguous bytes, but encapsulation needs the **whole packet** contiguous: once a large packet spans MDLs,
		 * NdisGetDataBuffer(tot, NULL) returns NULL -- the field symptom was "805 B ICMP
		 * gets into the tunnel, 1228 B UDP not a single one does", that is, the tunnel had no throughput.
		 * A non-paged buffer of size tot is provided here so NDIS can coalesce the scattered blocks; the coalesced content is immediately
		 * copied wholesale by the encapsulation layer, so it is returned right after use and not held across iterations.
		 * tot is bounded by the "drop if it does not fit" branch above (<= carrier_mtu), so no
		 * jumbo-frame-sized allocation.*/
		pkt = (UINT8 *)NdisGetDataBuffer(nb, IWAN_OUTER_IP4_LEN, hdr, 1, 0);
		if (pkt == NULL || nblen < IWAN_OUTER_IP4_LEN) {
			iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_COALESCE, nblen, 0,
					 pkt != NULL ? (ULONG)pkt[0] : 0xFFFFu, pkt);
			IWAN_STAT_INC(ext, tx_bad_inner);
			goto done;
		}
		tot = iwan_win_rd16(pkt + 2);
		if (tot < IWAN_OUTER_IP4_LEN || tot > nblen) {
			IWAN_STAT_INC(ext, tx_bad_inner);
			goto done;
		}
		pkt = (UINT8 *)NdisGetDataBuffer(nb, tot, NULL, 1, 0);
		if (pkt == NULL) {
			stor = (UINT8 *)IWAN_ALLOC(tot, IWAN_TAG_PKT);
			if (stor == NULL) {
				/* Under pool pressure plaintext must not be let out silently */
				IWAN_STAT_INC(ext, tx_err);
				classifyOut->actionType = FWP_ACTION_BLOCK;
				classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
				goto done;
			}
			pkt = (UINT8 *)NdisGetDataBuffer(nb, tot, stor, 1, 0);
			if (pkt == NULL) {
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_COALESCE,
						 nblen, tot, 0xFFFFu, NULL);
				ExFreePoolWithTag(stor, IWAN_TAG_PKT);
				IWAN_STAT_INC(ext, tx_bad_inner);
				goto done;
			}
		}
		if (!all_hit) {
			/* Mixed chain: this packet does not belong to this session, drop it (the whole chain has already been absorbed).
			 * Count it in ev_dropped, do not borrow tx_*: those are the tunnel's own
			 * send/receive accounting; once mixed in, they can never be reconciled with the NIC counters again.
			 * od is filled in here on the spot: when the first pass hits an illegal packet it breaks out early, and at that time od
			 * may not have been written (C6001); stor must also be returned first, because continue skips
			 * the free at the end of the loop (C6014, a real leak). */
			iwan_win_wr32(od, s->outer_dst);
			if (!iwan_win_should_tunnel4(s->targets, s->target_count,
						     od, pkt + 16)) {
				IWAN_STAT_INC(ext, ev_dropped);
				if (stor != NULL)
					ExFreePoolWithTag(stor, IWAN_TAG_PKT);
				continue;
			}
		}
		/* Diagnostic pass-through (egress): this packet matched the target set and would be encapsulated
		 * right here -- account it as such and swallow it. Nothing enters the tunnel, so the gap to the
		 * normal path is exactly the encapsulation + injection cost. Counters are the ones the meters
		 * already read, the same convention as the Linux plane's pass_through. */
		if ((ext->pass_through & IWAN_WIN_PASS_TX)) {
			IWAN_STAT_INC(ext, tx_pkts);
			IWAN_STAT_ADD(ext, tx_bytes, (LONG64)tot);
			if (stor != NULL) {
				ExFreePoolWithTag(stor, IWAN_TAG_PKT);
				stor = NULL;
			}
			continue;
		}
		/* Packets received at the outbound IP packet layer may still carry the "checksum to be filled by the NIC" flag:
		 * once the inner packet is XORed, the NIC can no longer fill it, so it must be computed here first. */
		ci.Value = NET_BUFFER_LIST_INFO(cur, TcpIpChecksumNetBufferListInfo);
		if (ci.Transmit.TcpChecksum || ci.Transmit.UdpChecksum)
			l4_offloaded = TRUE;

		st = iwan_win_encap_send_pkt(ext, pkt, tot, l4_offloaded, compartment,
					     iwan_win_session_is_v6(s),
					     &frames, &fbytes);
		if (stor != NULL) {
			/* The encapsulation layer already copied it wholesale, so return it now */
			ExFreePoolWithTag(stor, IWAN_TAG_PKT);
			/* Must be set to NULL: if the next iteration takes the zero-copy branch it will not allocate stor, but the end of the loop
			 * checks stor once more -- without NULLing, the same buffer would be freed twice. */
			stor = NULL;
		}
		if (!NT_SUCCESS(st)) {
			/* A packet that matched the target set failed to enter the tunnel = plaintext will leak to the carrier. Same rule as "drop if
			 * it does not fit" and the unconditional absorb at done: on the v6 side, rather drop
			 * than ever pass plaintext through. v4 here used to just goto done, and the action was still PERMIT.
			 * The in-flight window being full (DEVICE_BUSY) was already recorded as
			 * INFLIGHT, and must not be overwritten as ENCAP_FAIL here. */
			if (st != STATUS_DEVICE_BUSY) {
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_ENCAP_FAIL,
						 nblen, tot, pkt[0], pkt);
				/* The in-flight window being full is backpressure, not an encapsulation
				 * failure: it was already counted as tx_bad_state (and recorded as
				 * INFLIGHT) by the encapsulation layer, so it must not also be counted
				 * as tx_err -- that would report one throttled packet as two failures
				 * and make tx_err useless as "could not be encapsulated". */
				IWAN_STAT_INC(ext, tx_err);
			}
			classifyOut->actionType = FWP_ACTION_BLOCK;
			classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
			goto done;
		}
		/* Account per frame: when one inner packet is split into N fragments, the NIC sees N outer
		 * frames, and tx_pkts/tx_bytes must match them frame by frame. */
		IWAN_STAT_ADD(ext, tx_pkts, (LONG64)frames);
		/* tx_bytes records the outer bytes sent to the carrier NIC (including encapsulation overhead),
		 * so it can be compared directly with the NIC counters -- consistent with the convention comment on the Linux side. */
		IWAN_STAT_ADD(ext, tx_bytes, (LONG64)fbytes);
	}

	/* All encapsulation done: absorb the original packet so it no longer takes the normal outbound path */
	classifyOut->actionType = FWP_ACTION_BLOCK;
	classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

done:
	ExReleaseRundownProtection(&ext->rundown);
}

/* ---- callout: inbound (M2 decapsulates, M1 only matches and counts) -------- */

/*
 * Inbound decision: is this packet one of "this tunnel's data frames that we can handle"?
 * The address half of the five-tuple (protocol must be UDP, source address must be the outer server) is decided by the worker using
 * WFP fixed fields -- the transport-layer IP header has been stripped, nothing on the packet can be compared; the port half is decided here,
 * taken from the UDP header itself (iwan_win_dgram_parse fills it into IWAN_WIN_OUTER along the way).
 * After a hit,
 * anything we cannot handle is swallowed (never passed to the local protocol stack, otherwise corrupted/forged tunnel content would be
 * treated as normal inbound traffic); only control frames that pass verification are passed as-is to the user-mode socket --
 * same policy as kernel/iwan_rx.c: data frames are taken by the kernel, control frames are forwarded to user mode.
 */
/* At most this many packets per NBL chain are judged: WFP usually has one packet per chain, but batching is
 * a possible shape. Beyond the limit the whole block is swallowed (tunnel traffic may rather be dropped than leak to the local
 * protocol stack), and ev_dropped is counted. */
#define IWAN_WIN_MAX_BATCH	64u

#define IWAN_WIN_IN_NONE	0u	/* not our packet: permit */
#define IWAN_WIN_IN_CTRL	1u	/* control frame: account, then pass to user mode */
#define IWAN_WIN_IN_DATA	2u	/* data frame: decapsulate, then inject into the local protocol stack */
#define IWAN_WIN_IN_DROP	3u	/* our packet but unhandleable: swallow */

static UINT32
iwan_win_inbound_kind(_In_ const IWAN_WIN_SESSION *s,
		      _In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		      _Out_ IWAN_WIN_OUTER *o)
{
	/* Ports come in pairs: source port = server port, destination port = this session's port (the client socket
	 * is bound to it). The address half has already passed the worker's fixed-field gate. */
	if (!iwan_win_dgram_parse(pkt, len, o))
		return IWAN_WIN_IN_DROP;	/* this session's packet but structurally invalid: swallow */
	if (o->sport != s->dport || o->dport != s->sport)
		return IWAN_WIN_IN_NONE;

	switch (iwan_win_frame_classify(o, s->sid, s->tok, s->enc != 0, TRUE)) {
	case IWAN_WIN_FRAME_DATA:
		return IWAN_WIN_IN_DATA;
	case IWAN_WIN_FRAME_CTRL:
		return IWAN_WIN_IN_CTRL;
	default:
		return IWAN_WIN_IN_DROP;
	}
}

/* Decapsulated inner packet handed back to the network layer (one handle each for v4/v6) */
static NTSTATUS
iwan_win_inject_net_recv(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			 _In_reads_bytes_(len) const UINT8 *inner, _In_ ULONG len,
			 _In_ UINT32 family, _In_ UINT32 ifindex,
			 _In_ UINT32 sub_ifindex, _In_ UINT16 compartment)
{
	IWAN_INJECT_CTX *ctx;
	NET_BUFFER_LIST *nbl = NULL;
	HANDLE handle;
	NTSTATUS st;

	handle = (family == 6) ? ext->inj_recv6 : ext->inj_recv4;

	/* C6014 false positive: ctx/ctx->buf are handed to FwpsInjectNetworkReceiveAsync0,
	 * and freed by the same completion callback. */
#pragma warning(suppress: 6014)
	ctx = (IWAN_INJECT_CTX *)IWAN_ALLOC(sizeof(*ctx), IWAN_TAG_PKT);
	if (ctx == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	/* Same as above. */
#pragma warning(suppress: 6014)
	ctx->buf = IWAN_ALLOC(len, IWAN_TAG_PKT);
	ctx->ext = ext;
	ctx->mdl = NULL;		/* pool allocation is not zeroed, see the same handling on the encap side */
	if (ctx->buf == NULL) {
		ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlCopyMemory(ctx->buf, inner, len);

	st = iwan_win_nbl_wrap(ext, ctx, &nbl, len);
	if (!NT_SUCCESS(st)) {
		if (ctx->mdl != NULL)
			IoFreeMdl(ctx->mdl);
		ExFreePoolWithTag(ctx->buf, IWAN_TAG_PKT);
		ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
		return st;
	}

	InterlockedIncrement(&ext->inject_outstanding);
	/* The parameter list is exactly 9 entries: handle, context, flags, compartment, interfaceIndex,
	 * subInterfaceIndex, nbl, complete, completeContext.
	 * Last time I "added an addressFamily following the docs", which was actually wrong -- the compiler printed the real prototype
	 * (C2197), and changing it back to match was correct: this API has no address family parameter,
	 * the address family is carried by the injection handle itself (inj_recv4 / inj_recv6 registered separately). */
	st = FwpsInjectNetworkReceiveAsync(handle, NULL, 0, compartment,
					   (IF_INDEX)ifindex,
					   (IF_INDEX)sub_ifindex, nbl,
					   iwan_win_inject_complete, ctx);
	if (!NT_SUCCESS(st)) {
		InterlockedDecrement(&ext->inject_outstanding);
		FwpsFreeNetBufferList(nbl);
		IoFreeMdl(ctx->mdl);
		ExFreePoolWithTag(ctx->buf, IWAN_TAG_PKT);
		ExFreePoolWithTag(ctx, IWAN_TAG_PKT);
		return st;
	}
	/* Injection succeeded: ctx (together with buf/mdl) is freed by iwan_win_inject_complete,
	 * and this function no longer owns any of it. */
	ctx = NULL;
	return st;
}

/* Forward declarations: in4/in6 are thin wrappers, the worker body comes after them (the first real compile reported here
 * "undefined; assuming extern returning int" + redefinition) */
static VOID NTAPI
iwan_win_inbound_worker(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
			_In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
			_Inout_opt_ void *layerData,
			_In_opt_ const void *classifyContext,
			_In_ const FWPS_FILTER *filter,
			_In_ UINT64 flowContext,
			_Inout_ FWPS_CLASSIFY_OUT *classifyOut,
			_In_ BOOLEAN outer_v6);

static VOID NTAPI
iwan_win_classify_in4(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
		      _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
		      _Inout_opt_ void *layerData,
		      _In_opt_ const void *classifyContext,
		      _In_ const FWPS_FILTER *filter,
		      _In_ UINT64 flowContext,
		      _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
	iwan_win_inbound_worker(inFixedValues, inMetaValues, layerData,
				classifyContext, filter, flowContext,
				classifyOut, FALSE);
}

static VOID NTAPI
iwan_win_classify_in6(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
		      _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
		      _Inout_opt_ void *layerData,
		      _In_opt_ const void *classifyContext,
		      _In_ const FWPS_FILTER *filter,
		      _In_ UINT64 flowContext,
		      _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
	iwan_win_inbound_worker(inFixedValues, inMetaValues, layerData,
				classifyContext, filter, flowContext,
				classifyOut, TRUE);
}

static VOID NTAPI
iwan_win_inbound_worker(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
		      _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
		      _Inout_opt_ void *layerData,
		      _In_opt_ const void *classifyContext,
		      _In_ const FWPS_FILTER *filter,
		      _In_ UINT64 flowContext,
		      _Inout_ FWPS_CLASSIFY_OUT *classifyOut,
		      _In_ BOOLEAN outer_v6)
{
	IWAN_WIN_DEVICE_EXTENSION *ext =
		(IWAN_WIN_DEVICE_EXTENSION *)(ULONG_PTR)filter->context;
	IWAN_WIN_SESSION *s;
	NET_BUFFER_LIST *nbl = (NET_BUFFER_LIST *)layerData;
	NET_BUFFER_LIST *cur;
	UINT16 compartment = 0;
	UINT32 ifindex = 0;
	UINT32 sub_ifindex = 0;
	BOOLEAN all_ours = TRUE, overflow = FALSE;
	UINT32 kinds[IWAN_WIN_MAX_BATCH];
	ULONG lens[IWAN_WIN_MAX_BATCH];
	ULONG n = 0;			/* number of packets in this batch */
	ULONG i;
	UINT32 fidx;

	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);

	/* Write "permit" into the verdict first, then talk about anything else.
	 *
	 * The filter installed at this layer is a **terminating** filter: terminating means there is no "next" to continue to, so the verdict can only be PERMIT
	 * or BLOCK. Writing CONTINUE ("no opinion") produced this: as soon as the session is established, machine-wide traffic in both directions
	 * stops immediately -- the outbound callout was clearly called 233 times and returned permit every time, yet not a single packet
	 * went out; the target itself stayed perfectly alive, and everything recovered as soon as CLOSE returned.
	 * The write right (FWPS_RIGHT_ACTION_WRITE) governs "can we tighten to BLOCK", not "can we
	 * permit": without it, only permit, never tighten. */
	classifyOut->actionType = FWP_ACTION_PERMIT;
	if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
		return;
	if (ext == NULL || nbl == NULL)
		return;
	s = &ext->sess;
	if (s->valid == 0 || iwan_win_session_is_v6(s) != outer_v6)
		return;
	/* The transport layer has no IP header to look at: the protocol and the outer peer address can only be asked from WFP fixed fields.
	 * Assert the type before reading the value (a type mismatch yields garbage); if it cannot be obtained, permit -- if ownership
	 * cannot be determined, the packet should not be touched. Check the index against the upper bound first: the fixed-field array is allocated
	 * per the actual number of fields at the layer, and an out-of-bounds read reads someone else's memory. */
	if (inFixedValues == NULL)
		return;
	fidx = outer_v6 ? FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL
			: FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL;
	if (fidx >= inFixedValues->valueCount)
		return;
	if (inFixedValues->incomingValue[fidx].value.type != FWP_UINT8 ||
	    inFixedValues->incomingValue[fidx].value.uint8 != IWAN_IPPROTO_UDP)
		return;
	fidx = outer_v6 ? FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS
			: FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS;
	if (fidx >= inFixedValues->valueCount)
		return;
	if (outer_v6) {
		if (inFixedValues->incomingValue[fidx].value.type !=
			    FWP_BYTE_ARRAY16_TYPE ||
		    RtlCompareMemory(inFixedValues->incomingValue[fidx]
					     .value.byteArray16->byteArray16,
				     s->outer_dst6, 16) != 16)
			return;
	} else {
		if (inFixedValues->incomingValue[fidx].value.type != FWP_UINT32 ||
		    inFixedValues->incomingValue[fidx].value.uint32 != s->outer_dst)
			return;
	}

	/* Inner packet injected by ourselves: permit, let it be delivered upwards normally */
	if (iwan_win_nbl_from_self(ext->inj_recv4, nbl) ||
	    iwan_win_nbl_from_self(ext->inj_recv6, nbl))
		return;
	if (!ExAcquireRundownProtection(&ext->rundown))
		return;
	if (s->valid == 0)
		goto done;
	/* Diagnostic pass-through (ingress): the packet has already passed the fixed-field gate, i.e. it is
	 * "this session's outer frame" and nothing else -- account it and let it continue untouched. No parsing,
	 * no decapsulation, no injection: the difference from the normal path is the decapsulation cost.
	 * The verdict is still PERMIT from the top of this function, so returning here is the whole action. */
	if ((ext->pass_through & IWAN_WIN_PASS_RX)) {
		for (cur = nbl; cur != NULL; cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
			if (NET_BUFFER_LIST_FIRST_NB(cur) != NULL)
				IWAN_STAT_INC(ext, rx_outer);
		}
		goto done;
	}

	/* Inbound injection must tell WFP "which NIC and which sub-interface this packet was received on", while the authoritative
	 * source for inbound is the **fixed fields** (the values themselves depend on the layer, see
	 * FWPS_FIELDS_INBOUND_TRANSPORT_V4: INTERFACE_INDEX / SUB_INTERFACE_INDEX).
	 * Previously sourceInterfaceIndex was taken only from metadata, and on INBOUND_TRANSPORT that does not give
	 * the true value, which amounted to passing interfaceIndex = 0 to the injection API -- packets could be queued (the call returned
	 * success and rx_delivered kept rising), and were then returned asynchronously by WFP: in the completion callback
	 * NET_BUFFER_LIST_STATUS was always 0xC000000D (STATUS_INVALID_PARAMETER),
	 * 33 packets, 33 failures, not one of them reached the stack. Outbound injection does not need an interface index, so outbound
	 * was always working -- that asymmetry was the clue at the time.
	 * As usual, check upper bound and type before reading: fixed fields are allocated per layer, out of bounds is reading someone else's memory. */
	fidx = outer_v6 ? FWPS_FIELD_INBOUND_TRANSPORT_V6_INTERFACE_INDEX
			: FWPS_FIELD_INBOUND_TRANSPORT_V4_INTERFACE_INDEX;
	if (inFixedValues != NULL && fidx < inFixedValues->valueCount &&
	    inFixedValues->incomingValue[fidx].value.type == FWP_UINT32)
		ifindex = inFixedValues->incomingValue[fidx].value.uint32;
	fidx = outer_v6 ? FWPS_FIELD_INBOUND_TRANSPORT_V6_SUB_INTERFACE_INDEX
			: FWPS_FIELD_INBOUND_TRANSPORT_V4_SUB_INTERFACE_INDEX;
	if (inFixedValues != NULL && fidx < inFixedValues->valueCount &&
	    inFixedValues->incomingValue[fidx].value.type == FWP_UINT32)
		sub_ifindex = inFixedValues->incomingValue[fidx].value.uint32;

	if (inMetaValues != NULL) {
		if (FWPS_IS_METADATA_FIELD_PRESENT(
			    inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID))
			compartment = (UINT16)inMetaValues->compartmentId;
		/* Fallback: sourceInterfaceIndex from metadata. Note that in the header it sits right next to
		 * destinationInterfaceIndex and is an **outbound-semantics** member; inbound usually cannot get the
		 * true value -- the authoritative source is the fixed-field block below. */
		if (FWPS_IS_METADATA_FIELD_PRESENT(
			    inMetaValues,
			    FWPS_METADATA_FIELD_SOURCE_INTERFACE_INDEX) &&
		    inMetaValues->sourceInterfaceIndex != 0)
			ifindex = (UINT32)inMetaValues->sourceInterfaceIndex;
	}

	/* There was a temporary experiment here that accumulated ifindex / compartment / metadata mask into
	 * tx_bad_state / tx_bad_inner / tx_err, used to locate "every packet is rejected with
	 * STATUS_INVALID_PARAMETER". Wire-test measurements (diagnostic value = original value x injection count):
	 *   tx_bad_state/12 = 7   -- the NIC index is taken from the fixed field INTERFACE_INDEX, which is
	 *                            NDIS index (7), which uses a different numbering scheme from the MIB index (6)
	 *                            stored in the session; with the wrong one WFP rejects the whole batch;
	 *   tx_bad_inner/12 = 1   -- compartment 1;
	 *   tx_err/12       = 15  -- all four metadata fields present (1|2|4|8).
	 * After the fix, 12 packets, 12 injections all succeeded (rx_batch_skip=12, rx_batch=0).
	 * These three counters are back to their original semantics; do not borrow them again -- borrowed counters pollute later measurements. */

	/* First pass: judge the whole block. If even one packet is not ours (or exceeds the batch buffer),
	 * pass the whole block -- never "absorb half". */
	for (cur = nbl; cur != NULL; cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
		NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
		UINT8 *pkt;
		ULONG len;
		IWAN_WIN_OUTER o;
		UINT32 kind;

		if (nb == NULL || n >= IWAN_WIN_MAX_BATCH) {
			/* structural anomaly (empty NB) or batch too large: swallow the whole block */
			overflow = TRUE;
			break;
		}
		len = NET_BUFFER_DATA_LENGTH(nb);
		pkt = (UINT8 *)NdisGetDataBuffer(nb, len, NULL, 1, 0);
		if (pkt == NULL) {
			/* non-linear: do not handle and do not absorb */
			all_ours = FALSE;
			break;
		}
		kind = iwan_win_inbound_kind(s, pkt, len, &o);
		if (kind == IWAN_WIN_IN_NONE) {
			all_ours = FALSE;
			break;
		}
		kinds[n] = kind;
		lens[n] = len;
		n++;
	}

	if (overflow) {
		IWAN_STAT_INC(ext, ev_dropped);
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		goto done;
	}
	if (!all_ours || n == 0)
		goto done;

	/* Second pass: process packet by packet. Control frames are passed (not absorbed), everything else is swallowed. */
	{
		BOOLEAN absorb = FALSE;

		i = 0;
		for (cur = nbl; cur != NULL;
		     cur = NET_BUFFER_LIST_NEXT_NBL(cur), i++) {
			NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
			UINT8 *pkt = (UINT8 *)NdisGetDataBuffer(nb, lens[i], NULL, 1, 0);
			IWAN_WIN_OUTER o;

			if (pkt == NULL || !iwan_win_dgram_parse(pkt, lens[i], &o)) {
				IWAN_STAT_INC(ext, rx_bad_hdr);
				absorb = TRUE;
				continue;
			}

			switch (kinds[i]) {
			case IWAN_WIN_IN_CTRL:
				/* Valid control frame => peer is alive; PT_CLOSE then resets the timestamp to zero
				 * (user mode sees 0 and judges a disconnect, same semantics as Linux).
				 * The frame itself is not absorbed: the user-mode socket must receive it. */
				iwan_win_session_mark_rx(s, 1);
				if (o.type == PT_CLOSE)
					iwan_win_session_mark_close(s);
				IWAN_STAT_INC(ext, rx_ctrl_frame);
				break;
			case IWAN_WIN_IN_DATA: {
				UINT8 *inner;
				ULONG ilen;

				iwan_win_session_mark_rx(s, 0);
				IWAN_STAT_INC(ext, rx_outer);
				IWAN_STAT_INC(ext, rx_frames);
				IWAN_STAT_INC(ext, rx_pkts);

				inner = (UINT8 *)IWAN_ALLOC(o.inner_len, IWAN_TAG_PKT);
				if (inner == NULL) {
					IWAN_STAT_INC(ext, rx_nomem);
					absorb = TRUE;
					break;
				}
				UINT32 fam;

				ilen = iwan_win_decap(pkt, lens[i], &o, s->key,
						      inner, o.inner_len);
				fam = ilen != 0 ? iwan_win_inner_family(inner, ilen)
						: 0;
				if (ilen == 0 || fam == 0 ||
				    !iwan_win_inner_sane(inner, ilen)) {
					/* structurally invalid, do not inject: rather drop this one inner packet
					 * than let a malformed packet enter the local protocol stack */
					IWAN_STAT_INC(ext, rx_bad_inner);
					ExFreePoolWithTag(inner, IWAN_TAG_PKT);
					absorb = TRUE;
					break;
				}
				if (!NT_SUCCESS(iwan_win_inject_net_recv(
						ext, inner, ilen, fam, ifindex,
						sub_ifindex, compartment))) {
					IWAN_STAT_INC(ext, rx_nomem);
				} else {
					IWAN_STAT_INC(ext, rx_delivered);
				}
				ExFreePoolWithTag(inner, IWAN_TAG_PKT);
				absorb = TRUE;	/* inner delivered, outer no longer goes up the stack */
				break;
			}
			default:
				IWAN_STAT_INC(ext, rx_bad_hdr);
				absorb = TRUE;
				break;
			}
		}

		if (absorb) {
			classifyOut->actionType = FWP_ACTION_BLOCK;
			classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		}
	}

done:
	ExReleaseRundownProtection(&ext->rundown);
}

/*
 * Outbound v6: the decision uses the v6 target set entirely (longest prefix + excluding the server outer addresses); at encapsulation time
 * the outer family is decided by the session -- so v6-in-v4 (outer v4 session carrying inner v6) and v6-in-v6
 * go through here, just as Linux-side iwan_tx_outer4/6 are independent of the inner version.
 *
 * Size gate: inner + outer encapsulation overhead must not exceed 65535 (outer v6 never fragments, so anything larger can only be dropped).
 */
static VOID NTAPI
iwan_win_classify_out6(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
		       _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
		       _Inout_opt_ void *layerData,
		       _In_opt_ const void *classifyContext,
		       _In_ const FWPS_FILTER *filter,
		       _In_ UINT64 flowContext,
		       _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
	IWAN_WIN_DEVICE_EXTENSION *ext =
		(IWAN_WIN_DEVICE_EXTENSION *)(ULONG_PTR)filter->context;
	IWAN_WIN_SESSION *s;
	NET_BUFFER_LIST *nbl = (NET_BUFFER_LIST *)layerData;
	ULONG overhead;
	BOOLEAN all_ours = TRUE, overflow = FALSE, fail_closed = FALSE;
	UINT32 kinds[IWAN_WIN_MAX_BATCH];
	ULONG n = 0;

	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);

	/* Write "permit" into the verdict first, then talk about anything else.
	 *
	 * The filter installed at this layer is a **terminating** filter: terminating means there is no "next" to continue to, so the verdict can only be PERMIT
	 * or BLOCK. Writing CONTINUE ("no opinion") produced this: as soon as the session is established, machine-wide traffic in both directions
	 * stops immediately -- the outbound callout was clearly called 233 times and returned permit every time, yet not a single packet
	 * went out; the target itself stayed perfectly alive, and everything recovered as soon as CLOSE returned.
	 * The write right (FWPS_RIGHT_ACTION_WRITE) governs "can we tighten to BLOCK", not "can we
	 * permit": without it, only permit, never tighten. */
	classifyOut->actionType = FWP_ACTION_PERMIT;
	if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
		return;
	if (ext == NULL || nbl == NULL)
		return;

	s = &ext->sess;
	if (s->valid == 0)
		return;

	/* Outer packet injected by ourselves: permit, never encapsulate another layer */
	if (iwan_win_nbl_from_self(ext->inj_send4, nbl) ||
	    iwan_win_nbl_from_self(ext->inj_send6, nbl))
		return;
	overhead = iwan_win_session_is_v6(s) ? IWAN_OUTER6_TOTAL
					     : IWAN_OUTER4_TOTAL;

	{
		NET_BUFFER_LIST *cur;

		for (cur = nbl; cur != NULL;
		     cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
			NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
			UINT8 hdr6[IWAN_INNER_IP6_LEN];
			UINT8 *pkt;
			ULONG len;

			if (nb == NULL || n >= IWAN_WIN_MAX_BATCH) {
				overflow = TRUE;
				break;
			}
			len = NET_BUFFER_DATA_LENGTH(nb);
			/* The decision only needs the 40 bytes of the inner v6 header: give a stack buffer so NDIS
			 * can assemble it across MDLs. Previously this required the **whole packet** to be contiguous
			 * (NdisGetDataBuffer(nb, len, NULL, ...)), but under checksum offload
			 * normal packets have header and payload in different MDLs, so these packets were judged
			 * "not ours" and plaintext walked onto the carrier -- the same bug that outbound v4 fixed
			 * was still leaking on the v6 side. */
			pkt = (UINT8 *)NdisGetDataBuffer(nb, IWAN_INNER_IP6_LEN,
							 hdr6, 1, 0);
			if (pkt == NULL || len < IWAN_INNER_IP6_LEN ||
			    iwan_win_inner_family(pkt, len) != 6) {
				/* shorter than the header or not v6: not this session's packet, permit */
				all_ours = FALSE;
				break;
			}
			if (!iwan_win_inner_sane(pkt, len)) {
				/* our packet but the declared length contradicts the whole frame: drop, never let plaintext out */
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_LEN_BAD, len,
						 (ULONG)IWAN_INNER_IP6_LEN +
						 iwan_win_rd16(pkt + 4), pkt[0], pkt);
				IWAN_STAT_INC(ext, tx_bad_inner);
				fail_closed = TRUE;
				break;
			}
			if (!iwan_win_should_tunnel6(s->targets, s->target_count,
						     s->outer_dst6, pkt + 24)) {
				all_ours = FALSE;
				break;
			}
			if ((ULONG)(overhead + len) > 0xFFFF) {
				/* outer total length crosses 16 bits: drop if it does not fit (same rule as the v4 MTU
				 * gate), no pass-through */
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_MTU, len,
						 (ULONG)IWAN_INNER_IP6_LEN +
						 iwan_win_rd16(pkt + 4), pkt[0], pkt);
				IWAN_STAT_INC(ext, tx_bad_state);
				fail_closed = TRUE;
				break;
			}
			kinds[n] = IWAN_WIN_IN_DATA;
			n++;
		}
	}

	if (overflow) {
		IWAN_STAT_INC(ext, ev_dropped);
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		return;
	}
	if (fail_closed) {
		/* our packet, but it cannot be encapsulated: drop. The counter was already incremented at the decision point,
		 * so only the verdict is set here, avoiding the same reason being counted twice. */
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		return;
	}
	if (!all_ours || n == 0)
		return;
	if (!ExAcquireRundownProtection(&ext->rundown))
		return;
	if (s->valid == 0)
		goto done;

	{
		NET_BUFFER_LIST *cur;
		UINT16 compartment = 0;

		if (inMetaValues != NULL &&
		    FWPS_IS_METADATA_FIELD_PRESENT(
			    inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID))
			compartment = (UINT16)inMetaValues->compartmentId;

		for (cur = nbl; cur != NULL;
		     cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
			NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(cur);
			NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO ci;
			BOOLEAN l4_offloaded = FALSE;
			UINT8 hdr6[IWAN_INNER_IP6_LEN];
			UINT8 *stor = NULL;
			UINT8 *pkt;
			ULONG nblen, tot;
			NTSTATUS st;

			nblen = NET_BUFFER_DATA_LENGTH(nb);
			/* Same convention as outbound v4: the decision only uses the 40 header bytes; give a stack buffer so
			 * NDIS assembles across MDLs; probe whole-packet contiguity separately, and if not contiguous, coalesce into a temporary
			 * buffer. Previously the whole packet was fetched at once and dropped if unavailable, which kept all normal v6
			 * packets under checksum offload out of the tunnel. */
			pkt = (UINT8 *)NdisGetDataBuffer(nb, IWAN_INNER_IP6_LEN,
							 hdr6, 1, 0);
			if (pkt == NULL || nblen < IWAN_INNER_IP6_LEN) {
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_COALESCE,
						 nblen, 0,
						 pkt != NULL ? (ULONG)pkt[0] : 0xFFFFu,
						 pkt);
				IWAN_STAT_INC(ext, tx_bad_inner);
				continue;
			}
			tot = (ULONG)IWAN_INNER_IP6_LEN + iwan_win_rd16(pkt + 4);
			if (tot > nblen) {
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_LEN_BAD,
						 nblen, tot, pkt[0], pkt);
				IWAN_STAT_INC(ext, tx_bad_inner);
				continue;
			}
			pkt = (UINT8 *)NdisGetDataBuffer(nb, tot, NULL, 1, 0);
			if (pkt == NULL) {
			/* C6014 false positive: stor is this iteration's coalescing buffer; every exit below
			 * (buffer fetch failure, does not fit the MTU, returned right after encapsulation) has freed and
			 * NULLed it; the analyzer counts the already-freed path again via the loop back edge. */
#pragma warning(suppress: 6014)
				stor = (UINT8 *)IWAN_ALLOC(tot, IWAN_TAG_PKT);
				if (stor == NULL) {
					/* under pool pressure, do not silently let plaintext out */
					IWAN_STAT_INC(ext, tx_err);
					continue;
				}
				pkt = (UINT8 *)NdisGetDataBuffer(nb, tot, stor, 1, 0);
				if (pkt == NULL) {
					iwan_win_diag_tx(s,
							 IWAN_WIN_DIAG_TX_COALESCE,
							 nblen, tot, 0xFFFFu, NULL);
					ExFreePoolWithTag(stor, IWAN_TAG_PKT);
					/* Must be set to NULL: stor is declared inside the loop body, and without NULLing
					 * the next iteration would still hold a freed pointer -- if that path succeeds at zero-
					 * copy, the trailing `if (stor != NULL)`
					 * would free the same buffer again (pool corruption). */
					stor = NULL;
					IWAN_STAT_INC(ext, tx_bad_inner);
					continue;
				}
			}
			ci.Value = NET_BUFFER_LIST_INFO(cur,
							TcpIpChecksumNetBufferListInfo);
			if (ci.Transmit.TcpChecksum || ci.Transmit.UdpChecksum)
				l4_offloaded = TRUE;
			/* Checksum offload does not mean a large segment: most TCP/UDP carries this flag, and the NIC
			 * cannot fill in an inner packet that has already been XORed, so it must be computed here. This takes the same
			 * path as outbound v4 -- l4_offloaded is handed to the encapsulation layer, and
			 * iwan_win_inner_fix_csum() computes the L4 checksum. There was a time when this whole class
			 * was dropped in bulk, which kept the vast majority of v6 traffic out of the tunnel.
			 *
			 * Segments that truly do not fit (LSO/jumbo frames) still fail closed: outer v6
			 * does not take part in fragmentation, so if inner plus encapsulation overhead exceeds the carrier MTU it is dropped, never letting the NIC
			 * fragment it again. The Linux reference implementation also drops on GSO (recording
			 * tx_bad_state), does not do software segmentation either -- so this is not a defect,
			 * it is a choice both sides make identically. */
			if (tot + IWAN_OUTER6_TOTAL > s->carrier_mtu) {
				iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_MTU, nblen,
						 tot, pkt[0], pkt);
				IWAN_STAT_INC(ext, tx_bad_state);
				if (stor != NULL) {
					ExFreePoolWithTag(stor, IWAN_TAG_PKT);
					/* Must be set to NULL: stor is declared inside the loop body, but the analyzer
					 * flags C6014 as "the loop back edge still holds a freed pointer"; what matters
					 * more is the real semantics -- NULLing is the only marker that "this iteration's buffer has
					 * been returned", and the next iteration allocates it again. */
					stor = NULL;
				}
				continue;
			}

			/* Diagnostic pass-through (egress), same as v4: matched the target set and passed every
			 * validity gate, so this is exactly the point where the encapsulation cost would be paid. */
			if ((ext->pass_through & IWAN_WIN_PASS_TX)) {
				IWAN_STAT_INC(ext, tx_pkts);
				IWAN_STAT_ADD(ext, tx_bytes, (LONG64)tot);
				if (stor != NULL) {
					ExFreePoolWithTag(stor, IWAN_TAG_PKT);
					stor = NULL;
				}
				continue;
			}
			st = iwan_win_encap_inject(ext, pkt, tot, l4_offloaded,
						   compartment,
						   iwan_win_session_is_v6(s));
			if (stor != NULL) {
				/* The encapsulation layer already copied it wholesale, return it right away */
				ExFreePoolWithTag(stor, IWAN_TAG_PKT);
				stor = NULL;
			}
			if (!NT_SUCCESS(st)) {
				/* The in-flight window being full was already recorded as INFLIGHT in encap_inject,
				 * and must not be overwritten as ENCAP_FAIL here. */
				if (st != STATUS_DEVICE_BUSY) {
					iwan_win_diag_tx(s,
							 IWAN_WIN_DIAG_TX_ENCAP_FAIL,
							 nblen, tot, pkt[0], pkt);
					/* Same rule as the v4 path: backpressure is counted once, as
					 * tx_bad_state in the encapsulation layer. */
					IWAN_STAT_INC(ext, tx_err);
				}
				continue;
			}
			IWAN_STAT_INC(ext, tx_pkts);
			IWAN_STAT_ADD(ext, tx_bytes, tot + overhead);
		}
	}

done:
	ExReleaseRundownProtection(&ext->rundown);
	/* Reaching here means the whole batch matched the target set: absorb everything (already encapsulated and injected as outer packets).
	 * A single-packet injection failure also counted tx_err above -- rather drop this one packet than ever let plaintext out. */
	classifyOut->actionType = FWP_ACTION_BLOCK;
	classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
}

static NTSTATUS NTAPI
iwan_win_notify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
		_In_ const GUID *filterKey, _Inout_ FWPS_FILTER *filter)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);
	return STATUS_SUCCESS;
}

/* ---- registration/unregistration ---------------------------------- */

static NTSTATUS
iwan_win_add_callout(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		     _In_ PDEVICE_OBJECT devobj, _In_ const GUID *key,
		     _In_ FWPS_CALLOUT_CLASSIFY_FN classify,
		     _In_ FWP_ACTION_TYPE action,
		     _In_ const GUID *layer, _In_ PCWSTR name,
		     _Out_ UINT32 *callout_id)
{
	FWPS_CALLOUT callout;
	FWPM_CALLOUT mcallout;
	FWPM_FILTER filter;
	NTSTATUS st;

	RtlZeroMemory(&callout, sizeof(callout));
	callout.calloutKey = *key;
	callout.flags = 0;
	callout.classifyFn = classify;
	callout.notifyFn = iwan_win_notify;
	callout.flowDeleteFn = NULL;

	st = FwpsCalloutRegister(devobj, &callout, callout_id);
	if (!NT_SUCCESS(st))
		return st;

	RtlZeroMemory(&mcallout, sizeof(mcallout));
	mcallout.calloutKey = *key;
	mcallout.displayData.name = (PWSTR)name;
	mcallout.flags = 0;		/* not persistent in a dynamic session: cleared as soon as the handle is closed */
	mcallout.applicableLayer = *layer;
	st = FwpmCalloutAdd(ext->engine, &mcallout, NULL, NULL);
	if (!NT_SUCCESS(st))
		return st;

	RtlZeroMemory(&filter, sizeof(filter));
	/* The filter also uses the callout's GUID as its key: deletion at unregister time is by key (filterKey and
	 * calloutKey are two independent namespaces, the same GUID does not conflict), so there is no need to remember what
	 * FwpmFilterAdd returns. */
	filter.filterKey = *key;
	filter.layerKey = *layer;
	filter.displayData.name = (PWSTR)name;
	filter.action.type = action;
	filter.action.calloutKey = *key;
	filter.weight.type = FWP_EMPTY;		/* weight assigned automatically by BFE */
	filter.numFilterConditions = 0;		/* all packets enter the callout, we decide */
	filter.filterCondition = NULL;
	/* FWPM_FILTER0 has a member for user context called rawContext; the classify callback
	 * reads exactly that through FWPS_FILTER0.context (different names, do not assume). */
	filter.rawContext = (UINT64)(ULONG_PTR)ext;
	return FwpmFilterAdd(ext->engine, &filter, NULL, NULL);
}

/*
 * The layer keys (layerKey) of the four built-in layers -- hard-coded public constants.
 *
 * Value source: user-mode fwpuclnt.lib from the WDK (user mode can link against these symbols). The kernel-mode
 * fwpkclnt.lib / fwpuclnt.lib / netio.lib do not export them, the link step reports
 * unresolved external, so the values can only be copied in by hand.
 *
 * The former approach was to look them up at run time with FwpmLayerGetById0(engine, FWPS_LAYER_* enum value);
 * that id space is not the same as the FWPM layer IDs: the returned layer key points elsewhere (most likely landing on
 * ALE (an authorization layer), and once the filter was installed the callout verdict could not be resolved at all -- the symptom was
 * "as soon as the session opens, machine-wide traffic is cut off at once in both directions while the target itself is alive and well; the callout
 * was never called even once (all counters zero); the network recovers immediately as soon as CLOSE returns". Layer keys are stable
 * constants; copying the values is more reliable than guessing across an id space.
 */
static const GUID IWAN_LAYER_OUT4 = {
	0x1E5C9FAE, 0x8A84, 0x4135,
	{ 0xA3, 0x31, 0x95, 0x0B, 0x54, 0x22, 0x9E, 0xCD }
};					/* FWPM_LAYER_OUTBOUND_IPPACKET_V4 */
static const GUID IWAN_LAYER_IN4 = {
	0x5926DFC8, 0xE3CF, 0x4426,
	{ 0xA2, 0x83, 0xDC, 0x39, 0x3F, 0x5D, 0x0F, 0x9D }
};					/* FWPM_LAYER_INBOUND_TRANSPORT_V4 */
static const GUID IWAN_LAYER_OUT6 = {
	0xA3B3AB6B, 0x3564, 0x488C,
	{ 0x91, 0x17, 0xF3, 0x4E, 0x82, 0x14, 0x27, 0x63 }
};					/* FWPM_LAYER_OUTBOUND_IPPACKET_V6 */
static const GUID IWAN_LAYER_IN6 = {
	0x634A869F, 0xFC23, 0x4B90,
	{ 0xB0, 0xC1, 0xBF, 0x62, 0x0A, 0x36, 0xAE, 0x6F }
};					/* FWPM_LAYER_INBOUND_TRANSPORT_V6 */

NTSTATUS
iwan_win_wfp_init(_In_ PDEVICE_OBJECT devobj,
		  _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	FWPM_SESSION session;
	NTSTATUS st;

	ext->devobj = devobj;	/* callout registration is deferred until the session is established, that is when it is needed */

	RtlZeroMemory(&session, sizeof(session));
	/* Dynamic session: once the engine handle is closed, the callouts and filters added by this driver all disappear
	 * (even a driver crash leaves no half-installed rule set), equivalent to removing the hooks when the Linux module unloads. */
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	st = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &ext->engine);
	if (!NT_SUCCESS(st))
		return st;

	/* NBL pool for injection: one per driver, packet buffers are allocated separately */
	{
		NET_BUFFER_LIST_POOL_PARAMETERS pp;

		RtlZeroMemory(&pp, sizeof(pp));
		pp.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
		pp.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
		pp.Header.Size =
			NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
		pp.fAllocateNetBuffer = TRUE;
		pp.PoolTag = IWAN_TAG_PKT;
		/* The pool handle is a **return value**, not an out parameter: NdisAllocateNetBufferListPool(
		 * NDIS_HANDLE, const NET_BUFFER_LIST_POOL_PARAMETERS *) -> NDIS_HANDLE.
		 * A non-NDIS driver passes NULL as the first parameter. */
		ext->nbl_pool = NdisAllocateNetBufferListPool(NULL, &pp);
		if (ext->nbl_pool == NULL)
			return STATUS_INSUFFICIENT_RESOURCES;
	}

	st = FwpsInjectionHandleCreate(AF_INET, FWPS_INJECTION_TYPE_NETWORK,
				       &ext->inj_send4);
	if (!NT_SUCCESS(st))
		return st;
	st = FwpsInjectionHandleCreate(AF_INET6, FWPS_INJECTION_TYPE_NETWORK,
				       &ext->inj_send6);
	if (!NT_SUCCESS(st))
		return st;
	/* After inbound decapsulation the inner IP packet must be handed back to the network layer (FwpsInjectNetworkReceiveAsync0),
	 * so the type here is NETWORK as well, not TRANSPORT -- transport-layer injection receives
	 * "transport payload", but what we hand back is a complete inner IP packet. */
	st = FwpsInjectionHandleCreate(AF_INET, FWPS_INJECTION_TYPE_NETWORK,
				       &ext->inj_recv4);
	if (!NT_SUCCESS(st))
		return st;
	st = FwpsInjectionHandleCreate(AF_INET6, FWPS_INJECTION_TYPE_NETWORK,
				       &ext->inj_recv6);
	if (!NT_SUCCESS(st))
		return st;

	/* At this point it is only "tools ready": the engine, NBL pool and four injection handles do not intercept any
	 * packet. The four callouts and filters are installed by iwan_win_wfp_start when the session is established
	 * -- so sc start only verifies "the driver can load, the device can open". */
	InterlockedExchange(&ext->wfp_started, 0);
	return STATUS_SUCCESS;
}

/*
 * Install the data plane: fetch the layer keys of the four layers from BFE, then register callout + filter layer by layer.
 * The two outbound layers are at the IP packet layer; the two inbound layers are at the **transport layer** (after protocol-stack reassembly, see the file header).
 *
 * Why not do it in DriverEntry: as soon as something is registered, every outbound/inbound IP packet on the machine has to
 * pass through our classify first, and "can the driver load" and "take over traffic" should be verified separately. With it placed
 * here, the scope for debugging a load failure is only DriverEntry and the control plane.
 *
 * Idempotent: wfp_started is a one-shot gate, so among concurrent OPENs only one really registers.
 */
NTSTATUS
iwan_win_wfp_start(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	NTSTATUS st;

	if (InterlockedCompareExchange(&ext->wfp_started, 1, 0) != 0)
		return STATUS_SUCCESS;		/* already installed, or someone is installing it */
	if (ext->engine == NULL || ext->devobj == NULL) {
		InterlockedExchange(&ext->wfp_started, 0);
		return STATUS_INVALID_DEVICE_STATE;
	}

	/* The layer keys are hard-coded public constants (see the notes on the four GUIDs above): no more run-time lookups from BFE */
	st = iwan_win_add_callout(ext, ext->devobj, &IWAN_CALLOUT_OUT4,
				  iwan_win_classify_out4,
				  FWP_ACTION_CALLOUT_TERMINATING,
				  &IWAN_LAYER_OUT4, L"iwan out4",
				  &ext->callout_id_out4);
	if (NT_SUCCESS(st)) {
		st = iwan_win_add_callout(ext, ext->devobj, &IWAN_CALLOUT_IN4,
					  iwan_win_classify_in4,
					  FWP_ACTION_CALLOUT_TERMINATING,
					  &IWAN_LAYER_IN4, L"iwan in4",
					  &ext->callout_id_in4);
	}
	if (NT_SUCCESS(st)) {
		st = iwan_win_add_callout(ext, ext->devobj, &IWAN_CALLOUT_OUT6,
					  iwan_win_classify_out6,
					  FWP_ACTION_CALLOUT_TERMINATING,
					  &IWAN_LAYER_OUT6, L"iwan out6",
					  &ext->callout_id_out6);
	}
	if (NT_SUCCESS(st)) {
		st = iwan_win_add_callout(ext, ext->devobj, &IWAN_CALLOUT_IN6,
					  iwan_win_classify_in6,
					  FWP_ACTION_CALLOUT_TERMINATING,
					  &IWAN_LAYER_IN6, L"iwan in6",
					  &ext->callout_id_in6);
	}
	if (!NT_SUCCESS(st)) {
		iwan_win_wfp_stop(ext);		/* half a data plane is more dangerous than none */
		return st;
	}

	InterlockedExchange(&ext->wfp_started, 2);
	return STATUS_SUCCESS;
}

/*
 * Remove the data plane. The order must not be reversed: delete the filters first, then unregister the callouts -- the reverse would leave
 * terminating filters referencing "already unregistered callouts", which is a black hole for machine-wide traffic (the protocol stack can only drop
 * packets when the action cannot be resolved), more dangerous than not installing at all.
 *
 * Delete by key instead of by id: filterKey is explicitly set to
 * each callout's own GUID in iwan_win_add_callout, so there is no need to save the id filled back by FwpmFilterAdd.
 * All callers are on the control-plane serial path (IOCTL or unload); the gate here only guards against duplicates and re-entry.
 */
VOID
iwan_win_wfp_stop(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	if (InterlockedCompareExchange(&ext->wfp_started, 1, 2) != 2)
		return;				/* was never installed, or someone is installing/removing it */

	if (ext->engine != NULL) {
		FwpmFilterDeleteByKey0(ext->engine, &IWAN_CALLOUT_OUT4);
		FwpmFilterDeleteByKey0(ext->engine, &IWAN_CALLOUT_IN4);
		FwpmFilterDeleteByKey0(ext->engine, &IWAN_CALLOUT_OUT6);
		FwpmFilterDeleteByKey0(ext->engine, &IWAN_CALLOUT_IN6);
	}

	if (ext->callout_id_out4 != 0)
		FwpsCalloutUnregisterById(ext->callout_id_out4);
	if (ext->callout_id_in4 != 0)
		FwpsCalloutUnregisterById(ext->callout_id_in4);
	if (ext->callout_id_out6 != 0)
		FwpsCalloutUnregisterById(ext->callout_id_out6);
	if (ext->callout_id_in6 != 0)
		FwpsCalloutUnregisterById(ext->callout_id_in6);
	ext->callout_id_out4 = ext->callout_id_in4 = 0;
	ext->callout_id_out6 = ext->callout_id_in6 = 0;

	if (ext->engine != NULL) {
		FwpmCalloutDeleteByKey0(ext->engine, &IWAN_CALLOUT_OUT4);
		FwpmCalloutDeleteByKey0(ext->engine, &IWAN_CALLOUT_IN4);
		FwpmCalloutDeleteByKey0(ext->engine, &IWAN_CALLOUT_OUT6);
		FwpmCalloutDeleteByKey0(ext->engine, &IWAN_CALLOUT_IN6);
	}

	InterlockedExchange(&ext->wfp_started, 0);
}


VOID
iwan_win_wfp_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	ULONG spin;

	iwan_win_wfp_stop(ext);		/* stop the data plane first (idempotent) */

	/* Drain in-flight injections: the completion callback must return NBLs to the pool and free packet buffers. Unregistering the callouts
	 * already guarantees no new injections come in; here we only wait for the batch already sent out to come back. After the bounded wait it still
	 * does not reach zero, which means an injection is stuck inside the protocol stack; at that point, rather leave the handles and pool unfreed
	 * (a memory leak) than risk a use-after-free -- on the unload path, a leak is more acceptable
	 * than a blue screen. */
	for (spin = 0; spin < 20000; spin++) {
		if (ext->inject_outstanding == 0)
			break;
		KeStallExecutionProcessor(100);
	}
	if (ext->inject_outstanding != 0) {
		DbgPrint("iwan-win: %ld stale injections remain; keeping the injection handles and NBL pool allocated\n",
			 ext->inject_outstanding);
		ext->engine = NULL;
		InterlockedExchange(&ext->wfp_started, 0);
		return;
	}

	if (ext->inj_send4 != NULL)
		FwpsInjectionHandleDestroy(ext->inj_send4);
	if (ext->inj_send6 != NULL)
		FwpsInjectionHandleDestroy(ext->inj_send6);
	if (ext->inj_recv4 != NULL)
		FwpsInjectionHandleDestroy(ext->inj_recv4);
	if (ext->inj_recv6 != NULL)
		FwpsInjectionHandleDestroy(ext->inj_recv6);
	ext->inj_send4 = ext->inj_send6 = ext->inj_recv4 = ext->inj_recv6 = NULL;

	if (ext->nbl_pool != NULL) {
		NdisFreeNetBufferListPool(ext->nbl_pool);
		ext->nbl_pool = NULL;
	}

	if (ext->engine != NULL) {
		FwpmEngineClose(ext->engine);
		ext->engine = NULL;
	}
	InterlockedExchange(&ext->wfp_started, 0);
}
