/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_mpdata.c - tunnel engine for the NDIS miniport + protocol driver plane.
 *
 * Relation to the WFP plane (iwan_win_wfp.c): on-wire bytes must match byte for byte -- frame header,
 * XOR, inner checksum and outer header all use the same iwan_win_frame.c; session params and stat
 * accounting are the same set too (same names and meanings in sess.stats). Only the packet in/out path differs:
 *
 *   TX path (inner -> outer)
 *     WFP plane: intercept at OUTBOUND_IPPACKET -> encapsulate -> FwpsInjectNetworkSendAsync
 *     this plane: miniport gets the inner datagram handed down by the stack -> encapsulate ->
 *               NdisSendNetBufferLists (protocol edge, bound to the carrier NIC)
 *   RX path (outer -> inner)
 *     WFP plane: intercept at INBOUND_TRANSPORT -> decapsulate -> FwpsInjectNetworkReceiveAsync
 *     this plane: protocol edge receives outer UDP from the carrier NIC -> decapsulate ->
 *               NdisMIndicateReceiveNetBufferLists (miniport indicates upward)
 *
 * So three things are simpler: (1) TX only handles packets whose route points to this adapter, no
 * destination-set match; (2) RX indicates upward directly, unlike injection it does not re-enter the stack; (3) no
 * 'buffer must stay alive until injection completes' constraint, but the in-flight cap is kept (see below).
 *
 * Control frames (OPEN/ECHO/CLOSE) are only accounted here, not indicated upward: the carrier NIC's normal
 * TCP/IP binding already delivers these UDP packets to user-mode sockets (the original client process receives
 * PT_OPEN_ACK earlier than the driver), so the control plane naturally keeps working. Data frames differ -- they
 * are just noise at the user-mode socket and must be absorbed by the engine (outer never enters the host stack).
 *
 * Concurrency: everything in this file is called at <= DISPATCH_LEVEL (miniport send, protocol-edge receive),
 * no waiting, no locking, no pageable memory. Session params are read under rundown protection per the same
 * convention as the WFP plane.
 */
#include "iwan_win.h"

/* Outer in-flight cap: each in-flight outer NBL holds non-paged pool and is returned only after the
 * NDIS send completion callback. The inner can be far faster than the carrier (10 Gbps inner feeding a 100 Mbps carrier);
 * without a cap it would grow net at GB/s and exhaust non-paged pool within seconds -- this is exactly how the WFP plane
 * hard-hung (Kernel-Power 41 + 6008); do not step into the same pit twice.
 * Over the cap, drop the current packet and count ev_dropped (queue overflow drop), but **report success to the stack**:
 * reporting failure gets translated into WSAEINVAL from sendto(), disguising 'carrier cannot keep up' as 'invalid
 * application arguments'. Packet loss is a normal UDP outcome; counters are the only diagnostic channel. */

/* 'What is this frame to this session', same meaning as WFP plane iwan_win_inbound_kind */
#define IWAN_MP_IN_NONE		0u	/* not a frame of this session (ports not paired) */
#define IWAN_MP_IN_DROP		1u	/* is this session's frame but structure or credential is invalid */
#define IWAN_MP_IN_DATA		2u
#define IWAN_MP_IN_CTRL		3u

/* Port pairing + credential + type: the criteria must match the WFP plane item by item, otherwise the same packet
 * would get a different verdict on the two planes. The address half is gated by the protocol edge before the call (outer
 * dest address must equal outer_src); here only the transport and tunnel layers are handled. */
static UINT32
iwan_win_mp_outer_kind(_In_ const IWAN_WIN_SESSION *s,
		       _In_ const IWAN_WIN_OUTER *o)
{
	if (o->sport != s->dport || o->dport != s->sport)
		return IWAN_MP_IN_NONE;

	switch (iwan_win_frame_classify(o, s->sid, s->tok, s->enc != 0, TRUE)) {
	case IWAN_WIN_FRAME_DATA:
		return IWAN_MP_IN_DATA;
	case IWAN_WIN_FRAME_CTRL:
		return IWAN_MP_IN_CTRL;
	default:
		return IWAN_MP_IN_DROP;
	}
}

/* ---- TX path: inner datagram -> outer frame ---------------------------- */

UINT32
iwan_win_mp_encap_send(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		       _In_reads_bytes_(len) const UINT8 *inner,
		       _In_ ULONG len, _In_ BOOLEAN l4_offloaded)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	UINT8 *buf, *ip, *fh;
	ULONG overhead = IWAN_OUTER4_TOTAL;
	ULONG total, flen;
	BOOLEAN sent;

	if (!ExAcquireRundownProtection(&ext->rundown))
		return IWAN_MP_TX_DROP;	/* session is being torn down: drop this packet, do not report an error */

	if (s->valid == 0) {
		/* No session: the only reason this adapter exists is the tunnel, so the packet stops here.
		 * Fail explicitly (the miniport returns the status to the stack) and count -- silent drop is
		 * where the WFP plane got burned.
		 *
		 * **Deliberately ignore** s->inner_ip here: the WFP plane uses it as the criterion for 'which packets should
		 * enter the tunnel', while this plane's criterion is routing (a packet that reaches this adapter means
		 * it should enter the tunnel); the inner identity is set on the adapter by the control plane with netsh. The real
		 * control plane (kdp_win.c) never fills inner_ip in SESSION_OPEN; if it were also
		 * required to be non-zero here, the result would be 'session established, not a byte gets out'. */
		IWAN_MP_STAT_INC(ext, tx_bad_state);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_DROP;
	}
	/* Outer v6 neighbor discovery (NS/NA) is left to phase 2: reject outright now, never fall back to
	 * plaintext or 'guess a gateway MAC'. */
	if (iwan_win_session_is_v6(s)) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_V6_NOT_IMPL, len, len,
				 len > 0 ? (ULONG)inner[0] : 0xFFFFu, inner);
		IWAN_MP_STAT_INC(ext, tx_bad_state);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_DROP;
	}
	/* Inner sanity: the caller (miniport) already read the total length from the header; re-check independently here.
	 * Both inner versions are accepted (v4 and v6): this plane used to require (inner[0] >> 4) == 4 and read the
	 * total length from the v4 header unconditionally, while the indication side has always handled v6 -- the result was
	 * "downlink v6 works, uplink v6 is dropped as malformed", which looks like a v6 routing problem rather than a version gate.
	 * The frame type on the wire is PT_DATA / PT_DATA_ENC for either inner version (same as the Linux plane:
	 * iwan_tx.c writes fh[0] from dp.enc only and never looks at the inner version), so nothing else changes. */
	if (len < IWAN_INNER_IP4_LEN || iwan_win_inner_family(inner, len) == 0 ||
	    !iwan_win_inner_sane(inner, len)) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_LEN_BAD, len, len,
				 len > 0 ? (ULONG)inner[0] : 0xFFFFu, inner);
		IWAN_MP_STAT_INC(ext, tx_bad_inner);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_FAIL;
	}

	/* Check before adding: unsigned wrap makes the total computed from an oversized len (e.g. 0xFFFFFFF0) smaller,
	 * so the 0xFFFF, carrier MTU and in-flight cap checks all pass, while the copy still uses len.
	 * The caller cannot produce such a length today (NET_BUFFER_DATA_LENGTH cannot reach 4G),
	 * but a data-plane length gate should not rest on the caller's good faith. */
	if (overhead > 0xFFFFu || len > 0xFFFFu - overhead) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_LEN_BAD, len, len,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, tx_bad_inner);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_FAIL;
	}
	total = overhead + len;
	flen = IWAN_FRAME_HDR_LEN + len;
	if (total > 0xFFFFu) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_LEN_BAD, len, total,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, tx_bad_inner);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_FAIL;
	}
	/* Carrier NIC MTU: the outer IP datagram must not exceed it (outer is not fragmented; if it does not fit, drop).
	 * Same criterion and same counter as the WFP plane. */
	if (total > s->carrier_mtu) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_MTU, len, total,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, tx_bad_state);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_DROP;
	}
	/* The in-flight cap means 'send queue overflow': semantically it belongs to ev_dropped (queue overflow drop),
	 * not tx_bad_state (state is broken). Mixing the two makes 'driver broken' and 'carrier cannot keep up'
	 * look identical in the counters. */
	if ((ULONG)ext->mp.outer_outstanding >= IWAN_MP_MAX_OUTER_INFLIGHT) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_INFLIGHT, len, total,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, ev_dropped);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_DROP;
	}

	/* Diagnostic pass-through: account the datagram as "would have been encapsulated" and drop it. No encryption, no
	 * outer header, no send to the carrier -- the difference from the normal path is exactly the encapsulation cost.
	 * The counters are the ones the meters already read (tx_pkts / tx_bytes), the same convention as the Linux plane's
	 * pass_through, so a run needs no new tooling and no ABI change. */
	if ((ext->pass_through & IWAN_WIN_PASS_TX)) {
		IWAN_MP_STAT_INC(ext, tx_pkts);
		IWAN_MP_STAT_ADD(ext, tx_bytes, (LONG64)len);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_OK;
	}
	/* Buffer allocated in one shot: Ethernet header (14) + outer IP+UDP (28) + frame header (8) + payload */
	buf = (UINT8 *)IWAN_ALLOC(IWAN_MP_ETH_HDR_LEN + total, IWAN_TAG_PKT);
	if (buf == NULL) {
		IWAN_MP_STAT_INC(ext, tx_err);
		ExReleaseRundownProtection(&ext->rundown);
		return IWAN_MP_TX_DROP;
	}
	ip = buf + IWAN_MP_ETH_HDR_LEN;
	fh = ip + overhead - IWAN_FRAME_HDR_LEN;

	/* Session params are read within this section; release rundown once header and payload are written */
	iwan_win_build_frame_hdr(fh, s->enc ? PT_DATA_ENC : PT_DATA, s->enc,
				 s->sid, s->tok);
	RtlCopyMemory(fh + IWAN_FRAME_HDR_LEN, inner, len);
	/* Inner checksum must be fixed up before XOR (the NIC can no longer fix an XORed inner) */
	iwan_win_inner_fix_csum(fh + IWAN_FRAME_HDR_LEN, len, l4_offloaded);
	if (s->enc)
		iwan_win_xor(fh + IWAN_FRAME_HDR_LEN, len, s->key, 0);
	if (iwan_win_outer_hdr4(ip, total, flen, s->outer_src, s->outer_dst,
				s->sport, s->dport) != total) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_ENCAP_FAIL, len, total,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, tx_bad_state);
		ExReleaseRundownProtection(&ext->rundown);
		ExFreePoolWithTag(buf, IWAN_TAG_PKT);
		return IWAN_MP_TX_DROP;
	}
	/* rundown is held until this function returns: diagnostics (iwan_win_diag_tx dereferences s->shm
	 * and writes 40 bytes) must fall inside rundown. Otherwise a concurrent IOCTL_CLOSE takes
	 * session_reset -> shm_destroy -> ExFreePoolWithTag, while the data plane is still
	 * at DISPATCH_LEVEL writing into freed non-paged pool. Same rule on the WFP plane: after taking rundown
	 * all diag runs before the release. */

	/* Ethernet header: src = MAC of the selected carrier, dst = next-hop MAC. When the next hop is not yet resolved
	 * this function sends ARP and returns FALSE (packet dropped, tx_bad_state counted + diagnostic). */
	if (!iwan_win_proto_fill_eth4(ext, buf)) {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_NO_NEIGHBOR, len, total,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, tx_bad_state);
		ExReleaseRundownProtection(&ext->rundown);
		ExFreePoolWithTag(buf, IWAN_TAG_PKT);
		return IWAN_MP_TX_DROP;
	}

	/* Both outcomes of send_outer4 leave no buf to us: TRUE = ownership transfers with the NBL
	 * (completion callback does ExFreePoolWithTag), FALSE = it has already freed it internally. This is
	 * the only 'hand it over and let go' buffer, so clear it explicitly; do not let later readers think it is still usable. */
	sent = iwan_win_proto_send_outer4(ext, buf, IWAN_MP_ETH_HDR_LEN + total);
	buf = NULL;
	if (sent) {
		/* Same rule as the WFP plane: tx_bytes records outer bytes (including outer IP+UDP),
		 * excluding the Ethernet header -- that is the carrier's link-layer overhead, not tunnel overhead. */
		IWAN_MP_STAT_INC(ext, tx_pkts);
		IWAN_MP_STAT_ADD(ext, tx_bytes, total);
	} else {
		iwan_win_diag_tx(s, IWAN_WIN_DIAG_TX_SEND_FAIL, len, total,
				 (ULONG)inner[0], inner);
		IWAN_MP_STAT_INC(ext, tx_bad_state);
	}
	ExReleaseRundownProtection(&ext->rundown);
	return sent ? IWAN_MP_TX_OK : IWAN_MP_TX_DROP;
}

/*
 * TX entry: oversized inner packets are first fragmented by the declared inner MTU, then encapsulated fragment by fragment.
 *
 * Alignment with Linux: on Linux the stack fragments by device MTU before ndo_start_xmit and
 * the driver only encapsulates each fragment. This plane intercepts at the miniport send entry (also before sending), so
 * add this step. The threshold is s->inner_mtu (= min(server negotiated value, carrier MTU - overhead)), so each fragment
 * necessarily fits into the carrier, and the outer still has DF=1.
 *
 * If any fragment cannot be sent, abandon everything (half a datagram cannot reach the peer; it equals dropping one packet);
 * fragments already sent each counted tx_pkts, no need to settle accounts here.
 */
UINT32
iwan_win_mp_encap_send_pkt(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			   _In_reads_bytes_(len) const UINT8 *inner,
			   _In_ ULONG len, _In_ BOOLEAN l4_offloaded)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	UINT8 *copy = NULL, *frag = NULL;
	ULONG mtu, n, i, flen = 0;
	UINT32 rc;

	/* Do not read inner_mtu without a session: let the encap layer report failure and count */
	if (s->valid == 0)
		return iwan_win_mp_encap_send(ext, inner, len, l4_offloaded);
	mtu = s->inner_mtu;
	n = (mtu > IWAN_WIN_MTU_MIN) ? iwan_win_frag4_count(inner, len, mtu) : 0;
	if (n == 0)
		return iwan_win_mp_encap_send(ext, inner, len, l4_offloaded);

	copy = (UINT8 *)IWAN_ALLOC(len, IWAN_TAG_PKT);
	frag = (UINT8 *)IWAN_ALLOC(mtu, IWAN_TAG_PKT);
	if (copy == NULL || frag == NULL) {
		if (copy != NULL)
			ExFreePoolWithTag(copy, IWAN_TAG_PKT);
		if (frag != NULL)
			ExFreePoolWithTag(frag, IWAN_TAG_PKT);
		IWAN_MP_STAT_INC(ext, tx_err);
		return IWAN_MP_TX_DROP;
	}
	RtlCopyMemory(copy, inner, len);
	/* L4 checksum must be fixed before splitting: only the first fragment carries the L4 header */
	iwan_win_inner_fix_csum(copy, len, l4_offloaded);

	rc = IWAN_MP_TX_OK;
	for (i = 0; i < n; i++) {
		if (!iwan_win_frag4_build(frag, mtu, copy, len, mtu, i, &flen)) {
			IWAN_MP_STAT_INC(ext, tx_bad_state);
			rc = IWAN_MP_TX_DROP;
			break;
		}
		rc = iwan_win_mp_encap_send(ext, frag, flen, FALSE);
		if (rc != IWAN_MP_TX_OK)
			break;
	}
	ExFreePoolWithTag(frag, IWAN_TAG_PKT);
	ExFreePoolWithTag(copy, IWAN_TAG_PKT);
	return rc;
}

/* ---- RX path: outer frame -> inner datagram ---------------------------- */

/*
 * RX entry: reassemble outer fragments first, then hand the complete datagram to the parser body.
 *
 * Aligned across three planes: on Linux the outer goes through ip_defrag() (kernel/iwan.mod.c imports ip_defrag,
 * default hookprio -300 is right after defrag), the WFP plane receives INBOUND_TRANSPORT
 * (tcpip has already reassembled), and only the MP plane still gets fragments at the protocol edge. Both ends default DF=1,
 * so this path is usually not taken; but 'flows with both inner and outer fragmented must also be received' is a capability requirement, not something to rely on the peer obeying the rules.
 */
/* The parser body is defined below; the reassembly wrapper uses it first, so declare it here. */
static VOID
iwan_win_mp_outer_frame(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			_In_reads_bytes_(len) const UINT8 *ip, _In_ ULONG len);

VOID
iwan_win_mp_outer_recv(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		       _In_reads_bytes_(len) const UINT8 *ip, _In_ ULONG len)
{
	ULONG idx = 0, flen = 0;
	int fr;

	fr = iwan_win_frag_input(ext->mp.frag, IWAN_WIN_FRAG_SLOTS, ip, len,
				 (ULONG)iwan_win_now_ms(), IWAN_WIN_FRAG_TTL_MS,
				 &idx, &flen);
	if (fr == IWAN_WIN_FRAG_PASS) {
		iwan_win_mp_outer_frame(ext, ip, len);
		return;
	}
	if (fr == IWAN_WIN_FRAG_STORED) {
		IWAN_MP_STAT_INC(ext, rx_reasm);
		return;
	}
	if (fr != IWAN_WIN_FRAG_DONE || idx >= IWAN_WIN_FRAG_SLOTS) {
		/* Cannot reassemble (over cap / length contradiction / invalid args): swallow as a bad header and count,
		 * the data plane must not have silent drop channels. */
		IWAN_MP_STAT_INC(ext, rx_bad_hdr);
		return;
	}
	IWAN_MP_STAT_INC(ext, rx_reasm);
	iwan_win_mp_outer_frame(ext, ext->mp.frag[idx].buf, flen);
	/* A DONE slot belongs to the caller: it must be returned after parsing, otherwise it is never reclaimed */
	ext->mp.frag[idx].used = FALSE;
}

/* Parse and deliver one complete outer datagram (or the whole packet after reassembly). */
static VOID
iwan_win_mp_outer_frame(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			_In_reads_bytes_(len) const UINT8 *ip, _In_ ULONG len)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	IWAN_WIN_OUTER o;
	UINT8 *inner;
	ULONG ilen;
	UINT32 kind, fam;

	if (!ExAcquireRundownProtection(&ext->rundown))
		return;
	if (s->valid == 0) {
		ExReleaseRundownProtection(&ext->rundown);
		return;
	}

	/* The address gate (outer dest address == outer_src) is gated by the protocol edge before the call; here
	 * we parse the tunnel layer and classify. Parse failure means a packet of this session's 5-tuple but structurally invalid. */
	if (!iwan_win_dgram_parse(ip, len, &o)) {
		IWAN_MP_STAT_INC(ext, rx_bad_hdr);
		ExReleaseRundownProtection(&ext->rundown);
		return;
	}
	kind = iwan_win_mp_outer_kind(s, &o);
	if (kind == IWAN_MP_IN_NONE || kind == IWAN_MP_IN_DROP) {
		/* IN_NONE means the protocol edge's port criterion disagrees with this function (should not happen);
		 * IN_DROP is this session's frame but its credential/type is invalid. Swallow and count both. */
		if (kind == IWAN_MP_IN_DROP)
			IWAN_MP_STAT_INC(ext, rx_bad_hdr);
		ExReleaseRundownProtection(&ext->rundown);
		return;
	}

	if (kind == IWAN_MP_IN_CTRL) {
		/* Control frame: only account, do not indicate upward (the carrier NIC's normal binding has already
		 * handed the same UDP to a user-mode socket; the control plane is there). */
		iwan_win_session_mark_rx(s, 1);
		if (o.type == PT_CLOSE)
			iwan_win_session_mark_close(s);
		IWAN_MP_STAT_INC(ext, rx_ctrl_frame);
		ExReleaseRundownProtection(&ext->rundown);
		return;
	}

	/* Data frame */
	iwan_win_session_mark_rx(s, 0);
	IWAN_MP_STAT_INC(ext, rx_outer);
	IWAN_MP_STAT_INC(ext, rx_frames);
	IWAN_MP_STAT_INC(ext, rx_pkts);

	inner = (UINT8 *)IWAN_ALLOC(o.inner_len, IWAN_TAG_PKT);
	if (inner == NULL) {
		IWAN_MP_STAT_INC(ext, rx_nomem);
		ExReleaseRundownProtection(&ext->rundown);
		return;
	}
	ilen = iwan_win_decap(ip, len, &o, s->key, inner, o.inner_len);
	fam = ilen != 0 ? iwan_win_inner_family(inner, ilen) : 0;
	if (ilen == 0 || fam == 0 || !iwan_win_inner_sane(inner, ilen)) {
		/* If structurally invalid, do not indicate upward: better to drop this one inner packet than let a malformed packet
		 * enter the local stack. Criteria match the WFP plane item by item. */
		IWAN_MP_STAT_INC(ext, rx_bad_inner);
		ExFreePoolWithTag(inner, IWAN_TAG_PKT);
		ExReleaseRundownProtection(&ext->rundown);
		return;
	}

	/* Same convention as TX: indicate_inner either hands the inner buffer plus the NBL to NDIS
	 * (TRUE), or frees it itself and returns FALSE. Either way we no longer own it here. */
	if (iwan_win_mp_indicate_inner(ext, inner, ilen))
		IWAN_MP_STAT_INC(ext, rx_delivered);
	else
		IWAN_MP_STAT_INC(ext, rx_nomem);

	ExReleaseRundownProtection(&ext->rundown);
}
