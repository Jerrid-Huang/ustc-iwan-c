/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_frame.c -- see iwan_win_frame.h. Pure functions: no locks, no allocation, no WDK dependencies.
 */
#include "iwan_win_frame.h"

VOID
iwan_win_build_frame_hdr(_Out_writes_bytes_(IWAN_FRAME_HDR_LEN) UINT8 *out,
			 _In_ UINT8 typ, _In_ UINT8 enc,
			 _In_ UINT16 sid, _In_ UINT32 tok)
{
	out[0] = typ;
	out[1] = enc;
	out[2] = (UINT8)(sid >> 8);
	out[3] = (UINT8)sid;
	out[4] = (UINT8)(tok >> 24);
	out[5] = (UINT8)(tok >> 16);
	out[6] = (UINT8)(tok >> 8);
	out[7] = (UINT8)tok;
}

/*
 * Rotate the 8-byte key to the phase "starting at off" to get a 64-bit mask word.
 * The byte-wise form is p[i] ^= key[(off + i) & 7]; when working in 8-byte groups, byte j
 * within a group uses key index (off + j) & 7 (the group start index is a multiple of 8), which matches
 * byte j of the mask word, so the two forms are bit-for-bit equivalent regardless of host byte order.
 */
static UINT64
iwan_win_xor_mask(_In_reads_bytes_(IWAN_KEY_LEN) const UINT8 *key, _In_ ULONG off)
{
	UINT64 k = 0;
	ULONG j;

	for (j = 0; j < IWAN_KEY_LEN; j++)
		k |= (UINT64)key[(off + j) & (IWAN_KEY_LEN - 1)] << (8 * j);
	return k;
}

VOID
iwan_win_xor(_Inout_updates_bytes_(len) UINT8 *p, _In_ ULONG len,
	     _In_reads_bytes_(IWAN_KEY_LEN) const UINT8 *key, _In_ ULONG off)
{
	UINT64 k = iwan_win_xor_mask(key, off);
	ULONG i = 0;

	/* One 64-bit word per round; RtlCopyMemory is used to load and store, so unaligned access is safe */
	while (i + IWAN_KEY_LEN <= len) {
		UINT64 v;

		RtlCopyMemory(&v, p + i, sizeof(v));
		v ^= k;
		RtlCopyMemory(p + i, &v, sizeof(v));
		i += IWAN_KEY_LEN;
	}
	for (; i < len; i++)
		p[i] ^= key[(off + i) & (IWAN_KEY_LEN - 1)];
}

/*
 * Copy and decrypt in a single pass, equivalent to "copy byte by byte, then iwan_win_xor(out, len, key, 0)".
 * The caller guarantees out and in do not overlap: in the driver, out is a freshly allocated decapsulation buffer.
 */
static VOID
iwan_win_copy_dec(_Out_writes_bytes_(len) UINT8 *out,
		  _In_reads_bytes_(len) const UINT8 *in, _In_ ULONG len,
		  _In_reads_bytes_(IWAN_KEY_LEN) const UINT8 *key)
{
	UINT64 k = iwan_win_xor_mask(key, 0);
	ULONG i = 0;

	while (i + IWAN_KEY_LEN <= len) {
		UINT64 v;

		RtlCopyMemory(&v, in + i, sizeof(v));
		v ^= k;
		RtlCopyMemory(out + i, &v, sizeof(v));
		i += IWAN_KEY_LEN;
	}
	for (; i < len; i++)
		out[i] = in[i] ^ key[i & (IWAN_KEY_LEN - 1)];
}

USHORT
iwan_win_rd16(_In_reads_bytes_(2) const UINT8 *p)
{
	return (USHORT)((p[0] << 8) | p[1]);
}

VOID
iwan_win_wr32(_Out_writes_bytes_(4) UINT8 *p, _In_ UINT32 v)
{
	p[0] = (UINT8)(v >> 24);
	p[1] = (UINT8)(v >> 16);
	p[2] = (UINT8)(v >> 8);
	p[3] = (UINT8)v;
}

UINT32
iwan_win_rd32(_In_reads_bytes_(4) const UINT8 *p)
{
	return ((UINT32)p[0] << 24) | ((UINT32)p[1] << 16) |
	       ((UINT32)p[2] << 8) | (UINT32)p[3];
}

VOID
iwan_win_wr16(_Out_writes_bytes_(2) UINT8 *p, _In_ USHORT v)
{
	p[0] = (UINT8)(v >> 8);
	p[1] = (UINT8)v;
}

static USHORT
iwan_win_csum_finish(_In_ ULONG sum)
{
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return (USHORT)~sum;
}

static ULONG
iwan_win_csum_add(_In_ ULONG sum, _In_reads_bytes_(len) const UINT8 *p,
		  _In_ ULONG len, _In_ ULONG odd_parity)
{
	ULONG i;

	for (i = 0; i + 1 < len; i += 2)
		sum += ((ULONG)p[i] << 8) | p[i + 1];
	if (i < len)
		sum += ((ULONG)p[i] << 8) | odd_parity;
	return sum;
}

VOID
iwan_win_inner_fix_csum(_Inout_updates_bytes_(len) UINT8 *pkt, _In_ ULONG len,
			_In_ BOOLEAN l4_offloaded)
{
	ULONG ihl, tot, sum, l4len, csum;
	UINT8 proto;

	if (len < IWAN_OUTER_IP4_LEN)
		return;
	if ((pkt[0] >> 4) != 4)
		return;

	ihl = (ULONG)(pkt[0] & 0x0F) * 4;
	if (ihl < IWAN_OUTER_IP4_LEN || ihl > len)
		return;

	proto = pkt[9];
	tot = iwan_win_rd16(pkt + 2);
	if (tot == 0 || tot > len)
		tot = len;
	/* All writes below are confined to [ihl, tot), and tot <= len was just pinned down.
	 * The explicit clamp exists for static analysis: iwan_win_csum_add() indexes with ULONG,
	 * PREfast cannot derive the relationship between l4len and tot and treats the L4 header write as out of bounds (C6386). */
	__analysis_assume(tot <= len);
	__analysis_assume(ihl <= tot);

	/* IPv4 header checksum: zero it, then recompute.
	 * The offset is 10, not 12 -- 12 is the first two bytes of the **source address**. Get it wrong and two things happen at once:
	 * the inner source address is overwritten by the checksum (in the field it shows up as a value like 122.x.0.2 that decreases per packet, because
	 * the IP ID goes up by 2 per packet and the checksum therefore goes down by 2), replies never come back; and the L4 pseudo-header
	 * computed below reads that same corrupted address, so the TCP/UDP checksums are wrong too.
	 * The golden test case cannot catch it: it proves itself with "the sum is 0xFFFF when the checksum field is included", and the checksum
	 * is computed over "the header with 12/13 zeroed" and written back to the same place, so it is self-consistent.
	 * test_inner_fix_csum_keeps_addrs() in tests/win_frame_test.c uses
	 * "the addresses must stay as they are" as its anchor and guards exactly this spot. */
	pkt[10] = 0;
	pkt[11] = 0;
	sum = iwan_win_csum_add(0, pkt, ihl, 0);
	iwan_win_wr16(pkt + 10, iwan_win_csum_finish(sum));

	if (!l4_offloaded)
		return;
	if (proto != IWAN_IPPROTO_TCP && proto != IWAN_IPPROTO_UDP)
		return;
	if (tot <= ihl)
		return;

	/* Pseudo-header: source/destination address + protocol number + L4 length */
	l4len = tot - ihl;
	if (l4len > len - ihl)
		l4len = len - ihl;	/* tot <= len is already guaranteed; this line makes the upper bound visible to the analyzer */
	sum = iwan_win_csum_add(0, pkt + 12, 8, 0);
	sum += (ULONG)proto;
	sum += l4len;

	if (proto == IWAN_IPPROTO_TCP) {
		/* Both gates are needed, and both are written in the "forward" direction: whether the packet's L4 length is enough
		 * (l4len >= 20) and whether the buffer itself is large enough (len >= ihl + 18).
		 * The second one is the form static analysis accepts -- it derives the upper bound from the literal index ihl + 17,
		 * and with an inverted form or an indirect relation such as "header length" it cannot make progress and reports
		 * "possible write of 77 bytes" (C6386). */
		if (l4len < IWAN_INNER_TCP_HDR_LEN || len < ihl + 18u)
			return;
		/* The two checksum bytes are zeroed with a single 2-byte write: the same helper
		 * function as the write-back below, so there is only one place with a bound check. */
		iwan_win_wr16(pkt + ihl + 16, 0);
		sum = iwan_win_csum_add(sum, pkt + ihl, l4len, 0);
		iwan_win_wr16(pkt + ihl + 16, iwan_win_csum_finish(sum));
	} else {
		if (l4len < IWAN_INNER_UDP_HDR_LEN || len < ihl + 8u)
			return;
		iwan_win_wr16(pkt + ihl + 6, 0);
		sum = iwan_win_csum_add(sum, pkt + ihl, l4len, 0);
		csum = iwan_win_csum_finish(sum);
		if (csum == 0)
			csum = 0xFFFF;	/* UDP: 0 means "no checksum", so all ones is substituted */
		iwan_win_wr16(pkt + ihl + 6, (USHORT)csum);
	}
}

/*
 * Inner IPv4 fragmentation.
 *
 * Why the driver fragments: the interception point is OUTBOUND_IPPACKET (the IP layer has assembled the header but has not fragmented yet),
 * whereas in the Linux version the stack fragments by the outer device MTU before ndo_start_xmit and the driver only
 * encapsulates fragment by fragment. To "align with Linux" the driver must cut an oversized datagram at the declared inner MTU
 * and encapsulate each fragment as its own outer frame -- the receiving side sees one complete inner fragment stream, and reassembly
 * is done by the peer's IP layer.
 *
 * Only v4 is handled: in-transit fragmentation of v6 violates RFC 8200, so an oversized v6 packet can only rely on source-side PMTU
 * (the NDIS plane has an adapter MTU available; the WFP plane has no interface to declare it on, still a known gap).
 */
ULONG
iwan_win_frag4_count(_In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		     _In_ ULONG mtu)
{
	ULONG ihl, chunk, payload;

	if (len < IWAN_OUTER_IP4_LEN || (pkt[0] >> 4) != 4)
		return 0;
	ihl = (ULONG)(pkt[0] & 0x0F) * 4;
	if (ihl < IWAN_OUTER_IP4_LEN || ihl > len || mtu <= ihl)
		return 0;
	/* Fragment offsets are in 8-byte units: each fragment's payload must be a multiple of 8 */
	chunk = (mtu - ihl) & ~7UL;
	if (chunk < 8)
		return 0;
	payload = len - ihl;
	if (payload <= chunk)
		return 0;		/* no fragmentation needed */
	return (payload + chunk - 1) / chunk;
}

/* The annotation must match the header verbatim (C28252): if the declaration has _Success_, so must the definition. */
_Success_(return != FALSE)
BOOLEAN
iwan_win_frag4_build(_Out_writes_bytes_(out_cap) UINT8 *out, _In_ ULONG out_cap,
		     _In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		     _In_ ULONG mtu, _In_ ULONG idx, _Out_ ULONG *out_len)
{
	ULONG ihl, chunk, payload, off, this_len, sum;
	USHORT fo;

	if (out_len == NULL)
		return FALSE;
	*out_len = 0;
	if (len < IWAN_OUTER_IP4_LEN || (pkt[0] >> 4) != 4)
		return FALSE;
	ihl = (ULONG)(pkt[0] & 0x0F) * 4;
	if (ihl < IWAN_OUTER_IP4_LEN || ihl > len || mtu <= ihl)
		return FALSE;
	chunk = (mtu - ihl) & ~7UL;
	if (chunk < 8)
		return FALSE;
	payload = len - ihl;
	/* The fragment offset field is only 13 bits: more than 8191 fragments is malformed input, no multiply-overflow fallback */
	if (idx >= 0x2000UL)
		return FALSE;
	off = idx * chunk;
	if (off >= payload)
		return FALSE;
	this_len = payload - off;
	if (this_len > chunk)
		this_len = chunk;
	if (ihl + this_len > out_cap)
		return FALSE;

	RtlCopyMemory(out, pkt, ihl);
	RtlCopyMemory(out + ihl, pkt + ihl + off, this_len);
	iwan_win_wr16(out + 2, (UINT16)(ihl + this_len));
	/* MF + 13-bit fragment offset. DF must be cleared: a large packet with DF set by the source is fragmented by this function,
	 * and keeping DF would make the receiver treat a middle fragment as invalid (in the v4 spec DF should only be set by the source). */
	fo = (USHORT)((off / 8) & 0x1FFF);
	if (off + this_len < payload)
		fo |= 0x2000;
	iwan_win_wr16(out + 6, fo);
	/* Every fragment is an independent IP packet: the header checksum must be recomputed (the payload is not included) */
	out[10] = 0;
	out[11] = 0;
	sum = iwan_win_csum_add(0, out, ihl, 0);
	iwan_win_wr16(out + 10, (USHORT)iwan_win_csum_finish(sum));
	*out_len = ihl + this_len;
	return TRUE;
}

/*
 * Outer fragment reassembly: group the fragments of one datagram into the same slot by "outer IPv4 ID + addresses".
 *
 * Why it exists: on the Linux side the outer layer goes through ip_defrag() (kernel/iwan.mod.c imports ip_defrag,
 * hookprio defaults to -300 = after defrag), so once the peer turns outer DF off, Linux still receives;
 * the Windows side used to reject anything with MF or a non-zero fragment offset, dropping such a stream entirely.
 * This path is normally not taken (both ends default to DF=1), but "accepting streams where both inner and outer layers are fragmented" is a capability requirement.
 *
 * Three hard constraints, all forced by past incidents:
 *  - slot count and per-datagram cap are hard-coded: the non-paged pool was once filled without bound and the machine hung;
 *  - the bitmap tracks 8-byte blocks: fragments may arrive out of order and may overlap, and an overlapping block counts once;
 *  - aging uses the caller-supplied now_ms; the data plane never reads a clock, let alone starts a timer.
 */
int
iwan_win_frag_input(_Inout_ IWAN_WIN_FRAG_SLOT *slots,
		    _In_ ULONG nslots,
		    _In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		    _In_ ULONG now_ms, _In_ ULONG ttl_ms,
		    _Out_ ULONG *out_idx, _Out_ ULONG *out_len)
{
	IWAN_WIN_FRAG_SLOT *s = NULL;
	IWAN_WIN_FRAG_SLOT *victim = NULL;
	ULONG ihl, tot, flen, off, i, first_blk, last_blk, need, age;
	ULONG best_age = 0;
	USHORT frag;
	UINT32 src, dst;
	UINT16 id;
	BOOLEAN more;

	if (slots == NULL || nslots == 0 || pkt == NULL ||
	    out_idx == NULL || out_len == NULL)
		return IWAN_WIN_FRAG_DROP;
	/* Both _Out_ parameters must have a defined value on every return path: the caller reads them
	 * even when it gets DROP (some treat it as diagnostics), and leaving them uninitialized is UB -- exactly
	 * what static analysis C6101 catches. */
	*out_idx = 0;
	*out_len = 0;
	/* Not IPv4 or the header is incomplete: not a fragment, let the normal path decide */
	if (len < IWAN_OUTER_IP4_LEN || (pkt[0] >> 4) != 4)
		return IWAN_WIN_FRAG_PASS;
	ihl = (ULONG)(pkt[0] & 0x0Fu) * 4u;
	if (ihl < IWAN_OUTER_IP4_LEN || ihl > len)
		return IWAN_WIN_FRAG_PASS;
	tot = (ULONG)iwan_win_rd16(pkt + 2);
	if (tot < ihl || tot > len)
		return IWAN_WIN_FRAG_PASS;
	frag = iwan_win_rd16(pkt + 6);
	more = (frag & 0x2000u) != 0;
	off = (ULONG)(frag & 0x1FFFu) * 8u;
	if (!more && off == 0)
		return IWAN_WIN_FRAG_PASS;	/* not a fragment */
	flen = tot - ihl;
	if (flen == 0)
		return IWAN_WIN_FRAG_DROP;
	if (off + flen > IWAN_WIN_FRAG_BUF_SIZE)
		return IWAN_WIN_FRAG_DROP;

	src = iwan_win_rd32(pkt + 12);
	dst = iwan_win_rd32(pkt + 16);
	id = iwan_win_rd16(pkt + 4);

	/* 1) Reuse an existing slot with the same source and ID; an expired one is treated as free */
	for (i = 0; i < nslots; i++) {
		if (!slots[i].used)
			continue;
		if (slots[i].src != src || slots[i].dst != dst ||
		    slots[i].id != id)
			continue;
		if (now_ms - slots[i].start_ms > ttl_ms) {
			slots[i].used = FALSE;
			break;
		}
		s = &slots[i];
		break;
	}

	/* 2) Otherwise find a free slot; if there is none, take the oldest one (bounded, non-blocking) */
	if (s == NULL) {
		for (i = 0; i < nslots; i++) {
			if (!slots[i].used) {
				s = &slots[i];
				break;
			}
		}
	}
	if (s == NULL) {
		for (i = 0; i < nslots; i++) {
			age = now_ms - slots[i].start_ms;
			if (age >= best_age) {
				best_age = age;
				victim = &slots[i];
			}
		}
		s = victim;
		if (s == NULL)
			return IWAN_WIN_FRAG_DROP;
	}
	if (!s->used) {
		s->used = TRUE;
		s->src = src;
		s->dst = dst;
		s->id = id;
		s->start_ms = now_ms;
		s->total = 0;
		s->end = 0;
		s->have = 0;
		RtlZeroMemory(s->bits, sizeof(s->bits));
	}

	/* 3) The last fragment gives the total length; if it contradicts the known total, kill the slot (the peer is reordering/spoofing) */
	if (!more) {
		/* The last fragment gives the total length. Both contradictions kill the slot: a different total than
		 * the one given before, or "content already received" extending past that total (typical of peer reordering/spoofing). */
		if (s->total != 0 && s->total != off + flen) {
			s->used = FALSE;
			return IWAN_WIN_FRAG_DROP;
		}
		if (s->end > off + flen) {
			s->used = FALSE;
			return IWAN_WIN_FRAG_DROP;
		}
		s->total = off + flen;
	}
	if (s->total != 0 && off + flen > s->total) {
		s->used = FALSE;
		return IWAN_WIN_FRAG_DROP;
	}
	if (off + flen > s->end)
		s->end = off + flen;

	/* 4) Store + mark blocks. Fragments may be out of order and overlap: an overlapping block counts once */
	RtlCopyMemory(s->buf + off, pkt + ihl, flen);
	first_blk = off / 8u;
	last_blk = (off + flen + 7u) / 8u;
	for (i = first_blk; i < last_blk && i < IWAN_WIN_FRAG_BUF_SIZE / 8u; i++) {
		UINT8 mask = (UINT8)(1u << (i & 7u));

		if ((s->bits[i >> 3] & mask) == 0) {
			s->bits[i >> 3] |= mask;
			s->have++;
		}
	}

	*out_idx = (ULONG)(s - slots);
	if (s->total == 0)
		return IWAN_WIN_FRAG_STORED;
	need = (s->total + 7u) / 8u;
	if (s->have < need)
		return IWAN_WIN_FRAG_STORED;
	*out_len = s->total;
	return IWAN_WIN_FRAG_DONE;
}

BOOLEAN
iwan_win_target_match(_In_reads_(count) const IWAN_WIN_TARGET *targets,
		      _In_ UINT32 count, _In_ UINT32 family,
		      _In_reads_bytes_((family == IWAN_WIN_AF_V4) ? 4 : 16)
		      const UINT8 *addr)
{
	ULONG best = 0;
	BOOLEAN hit = FALSE;
	ULONG i;

	for (i = 0; i < count; i++) {
		const IWAN_WIN_TARGET *t = &targets[i];
		ULONG bits, bytes, rem, b;

		if (t->family != family)
			continue;
		bits = t->prefix_len;
		if (family == IWAN_WIN_AF_V4 && bits > 32)
			continue;
		if (family == IWAN_WIN_AF_V6 && bits > 128)
			continue;
		if (bits < best)
			continue;

		bytes = bits / 8;
		rem = bits % 8;
		for (b = 0; b < bytes; b++)
			if (t->addr[b] != addr[b])
				break;
		if (b != bytes)
			continue;
		if (rem != 0) {
			UINT8 mask = (UINT8)(0xFFu << (8 - rem));

			if ((t->addr[bytes] & mask) != (addr[bytes] & mask))
				continue;
		}
		best = bits;
		hit = TRUE;
	}
	return hit;
}

_Success_(return != FALSE)
BOOLEAN
iwan_win_should_tunnel4(_In_reads_(count) const IWAN_WIN_TARGET *targets,
			_In_ UINT32 count,
			_In_reads_bytes_(4) const UINT8 *outer_dst_be,
			_In_reads_bytes_(4) const UINT8 *daddr)
{
	UINT32 i;

	for (i = 0; i < 4; i++)
		if (daddr[i] != outer_dst_be[i])
			break;
	if (i == 4)
		return FALSE;		/* the outer server itself: never enters the tunnel */
	return iwan_win_target_match(targets, count, IWAN_WIN_AF_V4, daddr);
}

/* ---- Inbound (M2): outer parsing, frame classification, decapsulation ------------------------------- */

/* Read type/enc/sid/tok from the frame header: one copy shared by all three outer shapes, so one edit cannot miss two places */
/* Only the four fields type/enc/sid/tok of out are written (frame_off must already be filled in by the caller),
 * hence _Inout_ here rather than _Out_: _Out_ would make the analyzer believe out is rewritten entirely,
 * while the frame_off/frame_len filled in earlier are exactly what is read here. */
static VOID
iwan_win_frame_hdr_read(_In_ const UINT8 *pkt, _Inout_ IWAN_WIN_OUTER *out)
{
	out->type = pkt[out->frame_off + 0];
	out->enc = pkt[out->frame_off + 1];
	out->sid = iwan_win_rd16(pkt + out->frame_off + 2);
	out->tok = ((UINT32)pkt[out->frame_off + 4] << 24) |
		   ((UINT32)pkt[out->frame_off + 5] << 16) |
		   ((UINT32)pkt[out->frame_off + 6] << 8) |
		   (UINT32)pkt[out->frame_off + 7];
}

_Success_(return != FALSE)
BOOLEAN
iwan_win_outer_parse4(_In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		      _Out_ IWAN_WIN_OUTER *out)
{
	ULONG ihl, ulen, need, avail;
	UINT8 proto;

	/* The contract is that failure paths do not fill out, but "not filled" and "uninitialized" look
	 * the same to static analysis (C6101). Zero it first, then fill: on failure the caller reads all zeros at worst,
	 * never a leftover offset from the previous packet on the stack. */
	RtlZeroMemory(out, sizeof(*out));
	if (len < IWAN_OUTER_IP4_LEN || (pkt[0] >> 4) != 4)
		return FALSE;
	ihl = (ULONG)(pkt[0] & 0x0F) * 4;
	if (ihl < IWAN_OUTER_IP4_LEN || ihl > len)
		return FALSE;
	proto = pkt[9];
	if (proto != IWAN_IPPROTO_UDP)
		return FALSE;
	/* The parser accepts only complete datagrams: both the MF bit and the fragment offset must be 0. The first fragment does
	 * carry UDP and the frame header, but its inner packet is partial, so decapsulating it would inject a truncated inner packet.
	 * Who reassembles fragments: on the Linux side the outer layer goes through ip_defrag(); on the WFP plane we get
	 * INBOUND_TRANSPORT (already reassembled by tcpip); on the MP plane, iwan_win_mp_outer_recv
	 * runs iwan_win_frag_input first and then parses with this function. So anything that still has fragment bits set here
	 * can only be a datagram that could not be assembled during reassembly: the caller counts it as "five-tuple hit but unhandled"
	 * and swallows it, never handing a partial packet to the local stack. */
	if ((iwan_win_rd16(pkt + 6) & 0x3FFF) != 0)
		return FALSE;
	/* Outer UDP length: derive the frame length from it, with the actual packet length as fallback */
	if (len < ihl + IWAN_OUTER_UDP_LEN)
		return FALSE;
	ulen = iwan_win_rd16(pkt + ihl + 4);
	if (ulen < IWAN_OUTER_UDP_LEN)
		return FALSE;
	avail = len - ihl;
	if (ulen > avail)
		ulen = avail;

	need = ihl + IWAN_OUTER_UDP_LEN + IWAN_FRAME_HDR_LEN;
	if (len < need)
		return FALSE;

	out->sport = iwan_win_rd16(pkt + ihl + 0);
	out->dport = iwan_win_rd16(pkt + ihl + 2);
	out->frame_off = ihl + IWAN_OUTER_UDP_LEN;
	out->frame_len = ulen - IWAN_OUTER_UDP_LEN;
	if (out->frame_len < IWAN_FRAME_HDR_LEN)
		return FALSE;
	out->inner_off = out->frame_off + IWAN_FRAME_HDR_LEN;
	out->inner_len = out->frame_len - IWAN_FRAME_HDR_LEN;
	if (out->inner_len == 0)
		return FALSE;

	iwan_win_frame_hdr_read(pkt, out);
	return TRUE;
}

UINT32
iwan_win_frame_classify(_In_ const IWAN_WIN_OUTER *o, _In_ UINT16 sess_sid,
			_In_ UINT32 sess_tok, _In_ BOOLEAN sess_enc,
			_In_ BOOLEAN session_established)
{
	BOOLEAN cred_ok = (o->sid == sess_sid && o->tok == sess_tok);

	switch (o->type) {
	case PT_DATA:
		if (sess_enc)
			return IWAN_WIN_FRAME_BAD;
		break;
	case PT_DATA_ENC:
		if (!sess_enc)
			return IWAN_WIN_FRAME_BAD;
		break;
	case PT_OPEN:
	case PT_OPEN_ACK:
	case PT_OPEN_REJECT:
	case PT_ECHO_REQ:
	case PT_ECHO_RES:
	case PT_CLOSE:
	case PT_PING_REQ:
	case PT_PING_RSP:
		if (!session_established)
			return IWAN_WIN_FRAME_BAD;
		if (o->type == PT_OPEN || o->type == PT_OPEN_ACK ||
		    o->type == PT_OPEN_REJECT)
			return IWAN_WIN_FRAME_CTRL;	/* credentials left for user space to validate */
		if (o->type == PT_PING_REQ || o->type == PT_PING_RSP)
			return (cred_ok || (o->sid == IWAN_PING_SID &&
					    o->tok == IWAN_PING_TOK))
				       ? IWAN_WIN_FRAME_CTRL
				       : IWAN_WIN_FRAME_BAD;
		return cred_ok ? IWAN_WIN_FRAME_CTRL : IWAN_WIN_FRAME_BAD;
	default:
		return IWAN_WIN_FRAME_BAD;
	}
	/* Only PT_DATA / PT_DATA_ENC reach this point. Both must agree with the enc byte in the frame
	 * header: decapsulation decides whether to decrypt from o->enc in the frame (iwan_win_decap), so
	 * looking at the type alone can be downgraded -- with an encrypted session, an attacker sends type=PT_DATA_ENC but
	 * enc=0 (sid/tok are plaintext in the frame header, so copy them) and decap takes the plaintext branch, passing any inner packet
	 * straight through. The check must come from the same source as the decrypting side. */
	if (o->enc != (sess_enc ? 1u : 0u))
		return IWAN_WIN_FRAME_BAD;
	return cred_ok ? IWAN_WIN_FRAME_DATA : IWAN_WIN_FRAME_BAD;
}

_Success_(return != 0)
ULONG
iwan_win_decap(_In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
	       _In_ const IWAN_WIN_OUTER *o,
	       _In_reads_bytes_(IWAN_KEY_LEN) const UINT8 *key,
	       _Out_writes_bytes_(outsz) UINT8 *out, _In_ ULONG outsz)
{
	if (o->inner_len == 0 || o->inner_len > outsz)
		return 0;
	if (o->inner_off + o->inner_len > len)
		return 0;

	if (o->enc)
		iwan_win_copy_dec(out, pkt + o->inner_off, o->inner_len, key);
	else
		RtlCopyMemory(out, pkt + o->inner_off, o->inner_len);
	return o->inner_len;
}

UINT32
iwan_win_inner_family(_In_reads_bytes_(len) const UINT8 *inner, _In_ ULONG len)
{
	if (len < 1)
		return 0;
	if ((inner[0] >> 4) == 4)
		return 4;
	if ((inner[0] >> 4) == 6)
		return 6;
	return 0;
}

BOOLEAN
iwan_win_inner_sane(_In_reads_bytes_(len) const UINT8 *inner, _In_ ULONG len)
{
	ULONG hlen, total;

	if (len < 1)
		return FALSE;
	switch (inner[0] >> 4) {
	case 4:
		if (len < 20)
			return FALSE;
		hlen = (ULONG)(inner[0] & 0x0F) * 4;
		if (hlen < 20 || hlen > len)
			return FALSE;
		total = iwan_win_rd16(inner + 2);
		break;
	case 6:
		if (len < 40)
			return FALSE;
		hlen = 40;			/* extension headers are not expanded here */
		total = hlen + iwan_win_rd16(inner + 4);
		break;
	default:
		return FALSE;
	}
	/* Reject only when the length declared in the header does not cover the whole frame (extra trailing bytes are not rejected; same rule as the kernel side) */
	return total >= hlen && total <= len;
}

/* ---- Outbound: outer header construction ------------------------------------------------- */

ULONG
iwan_win_outer_build4(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
		      _In_reads_bytes_(flen) const UINT8 *frame, _In_ ULONG flen,
		      _In_ UINT32 src_be, _In_ UINT32 dst_be, _In_ USHORT sport,
		      _In_ USHORT dport)
{
	if (flen == 0 || IWAN_OUTER4_TOTAL + flen > bufsz)
		return 0;
	/* The frame follows the IP + UDP headers directly: IWAN_OUTER4_TOTAL is the "total encapsulation overhead", which is
	 * one frame-header length more than the frame's start offset. Get it wrong and the packet has the right total length but misaligned content. */
	RtlCopyMemory(buf + IWAN_OUTER4_TOTAL - IWAN_FRAME_HDR_LEN, frame, flen);
	return iwan_win_outer_hdr4(buf, bufsz, flen, src_be, dst_be, sport, dport);
}

ULONG
iwan_win_outer_hdr4(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
		    _In_ ULONG flen, _In_ UINT32 src_be, _In_ UINT32 dst_be,
		    _In_ USHORT sport, _In_ USHORT dport)
{
	/* flen is the whole frame length (including the 8-byte frame header), and IWAN_OUTER4_TOTAL already
	 * counts the frame header into the "total encapsulation overhead": the real packet length = frame start offset + flen, i.e.
	 * IWAN_OUTER4_TOTAL - IWAN_FRAME_HDR_LEN + flen. Without subtracting this one frame-header length, the outer IP
	 * header claims 8 bytes more than reality, and the receiver reading to the declared length gets garbage at the tail. */
	ULONG total = IWAN_OUTER4_TOTAL - IWAN_FRAME_HDR_LEN + flen;
	ULONG ulen = IWAN_OUTER_UDP_LEN + flen;
	ULONG sum;

	if (flen < IWAN_FRAME_HDR_LEN || total > bufsz || total > 0xFFFF ||
	    ulen > 0xFFFF)
		return 0;
	/* Outer UDP (checksum zeroed first, then computed) */
	iwan_win_wr16(buf + IWAN_OUTER_IP4_LEN + 0, sport);
	iwan_win_wr16(buf + IWAN_OUTER_IP4_LEN + 2, dport);
	iwan_win_wr16(buf + IWAN_OUTER_IP4_LEN + 4, (USHORT)ulen);
	iwan_win_wr16(buf + IWAN_OUTER_IP4_LEN + 6, 0);

	/* Outer IPv4: ttl 64, DF=1 (the outer layer is never fragmented; the MTU is guaranteed by the session's inner MTU) */
	RtlZeroMemory(buf, IWAN_OUTER_IP4_LEN);
	buf[0] = 0x45;
	iwan_win_wr16(buf + 2, (USHORT)total);
	iwan_win_wr16(buf + 6, IWAN_IP4_DF);
	buf[8] = 64;
	buf[9] = IWAN_IPPROTO_UDP;
	iwan_win_wr32(buf + 12, src_be);
	iwan_win_wr32(buf + 16, dst_be);
	sum = iwan_win_csum_add(0, buf, IWAN_OUTER_IP4_LEN, 0);
	iwan_win_wr16(buf + 10, iwan_win_csum_finish(sum));

	/* UDP checksum: pseudo-header (src/dst/zero/proto/len) + UDP header + payload */
	{
		/* the zero + protocol two bytes of the pseudo-header */
		UINT8 zp[2] = { 0, IWAN_IPPROTO_UDP };

		sum = iwan_win_csum_add(0, buf + 12, 8, 0);
		sum = iwan_win_csum_add(sum, zp, 2, 0);
	}
	sum = iwan_win_csum_add(sum, buf + IWAN_OUTER_IP4_LEN + 4, 2, 0);
	sum = iwan_win_csum_add(sum, buf + IWAN_OUTER_IP4_LEN, ulen, 0);
	sum = iwan_win_csum_finish(sum);
	if (sum == 0)
		sum = 0xFFFF;	/* 0 means "no checksum", so all ones is substituted */
	iwan_win_wr16(buf + IWAN_OUTER_IP4_LEN + 6, (USHORT)sum);
	return total;
}

ULONG
iwan_win_outer_build6(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
		      _In_reads_bytes_(flen) const UINT8 *frame, _In_ ULONG flen,
		      _In_reads_bytes_(16) const UINT8 *src6,
		      _In_reads_bytes_(16) const UINT8 *dst6, _In_ USHORT sport,
		      _In_ USHORT dport)
{
	if (flen == 0 || IWAN_OUTER6_TOTAL + flen > bufsz)
		return 0;
	RtlCopyMemory(buf + IWAN_OUTER6_TOTAL - IWAN_FRAME_HDR_LEN, frame, flen);
	return iwan_win_outer_hdr6(buf, bufsz, flen, src6, dst6, sport, dport);
}

ULONG
iwan_win_outer_hdr6(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
		    _In_ ULONG flen, _In_reads_bytes_(16) const UINT8 *src6,
		    _In_reads_bytes_(16) const UINT8 *dst6, _In_ USHORT sport,
		    _In_ USHORT dport)
{
	/* flen is the whole frame length (including the 8-byte frame header), and IWAN_OUTER6_TOTAL already
	 * counts the frame header into the "total encapsulation overhead": the real packet length = frame start offset + flen, i.e.
	 * IWAN_OUTER6_TOTAL - IWAN_FRAME_HDR_LEN + flen. Without subtracting this one frame-header length, the outer IP
	 * header claims 8 bytes more than reality, and the receiver reading to the declared length gets garbage at the tail. */
	ULONG total = IWAN_OUTER6_TOTAL - IWAN_FRAME_HDR_LEN + flen;
	ULONG ulen = IWAN_OUTER_UDP_LEN + flen;
	ULONG sum;

	if (flen < IWAN_FRAME_HDR_LEN || total > bufsz || ulen > 0xFFFF)
		return 0;
	iwan_win_wr16(buf + IWAN_OUTER_IP6_LEN + 0, sport);
	iwan_win_wr16(buf + IWAN_OUTER_IP6_LEN + 2, dport);
	iwan_win_wr16(buf + IWAN_OUTER_IP6_LEN + 4, (USHORT)ulen);
	iwan_win_wr16(buf + IWAN_OUTER_IP6_LEN + 6, 0);

	/* Outer IPv6: traffic class and flow label all 0 (consistent with iwan_tx_outer6, which after
	 * memset fills in only version/nexthdr/hop_limit/payload_len/addresses) */
	RtlZeroMemory(buf, IWAN_OUTER_IP6_LEN);
	buf[0] = 0x60;			/* version 6, tc 0, flow label 0 */
	iwan_win_wr16(buf + 4, (USHORT)ulen);	/* payload_len = UDP header + payload */
	buf[6] = IWAN_IPPROTO_UDP;
	buf[7] = 64;
	RtlCopyMemory(buf + 8, src6, 16);
	RtlCopyMemory(buf + 24, dst6, 16);

	/* UDP checksum: the v6 pseudo-header is 16B source + 16B destination + 4B length + 3B zeros + 1B next header */
	{
		/* pseudo-header tail: 3 zero bytes + next header; only the low 16 bits of the length field can be non-zero */
		UINT8 zp[4] = { 0, 0, 0, IWAN_IPPROTO_UDP };

		sum = iwan_win_csum_add(0, src6, 16, 0);
		sum = iwan_win_csum_add(sum, dst6, 16, 0);
		sum = iwan_win_csum_add(sum, zp, 4, 0);
	}
	sum = iwan_win_csum_add(sum, buf + IWAN_OUTER_IP6_LEN + 4, 2, 0);
	sum = iwan_win_csum_add(sum, buf + IWAN_OUTER_IP6_LEN, ulen, 0);
	sum = iwan_win_csum_finish(sum);
	if (sum == 0)
		sum = 0xFFFF;
	iwan_win_wr16(buf + IWAN_OUTER_IP6_LEN + 6, (USHORT)sum);
	return total;
}

_Success_(return != FALSE)
BOOLEAN
iwan_win_outer_parse6(_In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		      _Out_ IWAN_WIN_OUTER *out)
{
	ULONG ulen, avail, need;

	RtlZeroMemory(out, sizeof(*out));
	if (len < IWAN_OUTER6_TOTAL || (pkt[0] >> 4) != 6)
		return FALSE;
	/* The outer v6 header is built by iwan_tx_outer6: nexthdr is directly UDP with no extension headers;
	 * an extension header means this is not this tunnel's format, so hand it back to the stack. */
	if (pkt[6] != IWAN_IPPROTO_UDP)
		return FALSE;
	ulen = iwan_win_rd16(pkt + IWAN_OUTER_IP6_LEN + 4);
	if (ulen < IWAN_OUTER_UDP_LEN)
		return FALSE;
	avail = len - IWAN_OUTER_IP6_LEN;
	if (ulen > avail)
		ulen = avail;

	need = IWAN_OUTER6_TOTAL + IWAN_FRAME_HDR_LEN;
	if (len < need)
		return FALSE;

	out->sport = iwan_win_rd16(pkt + IWAN_OUTER_IP6_LEN + 0);
	out->dport = iwan_win_rd16(pkt + IWAN_OUTER_IP6_LEN + 2);
	out->frame_off = IWAN_OUTER6_TOTAL - IWAN_FRAME_HDR_LEN;
	out->frame_len = ulen - IWAN_OUTER_UDP_LEN;
	if (out->frame_len < IWAN_FRAME_HDR_LEN)
		return FALSE;
	out->inner_off = out->frame_off + IWAN_FRAME_HDR_LEN;
	out->inner_len = out->frame_len - IWAN_FRAME_HDR_LEN;
	if (out->inner_len == 0)
		return FALSE;

	iwan_win_frame_hdr_read(pkt, out);
	return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
iwan_win_dgram_parse(_In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		     _Out_ IWAN_WIN_OUTER *out)
{
	ULONG off = 0, ulen, avail;

	RtlZeroMemory(out, sizeof(*out));
	if (len < IWAN_OUTER_UDP_LEN)
		return FALSE;

	/* First decide "does it still carry an IP header": accept only if the four checks agree, else treat it as a bare datagram */
	if ((pkt[0] >> 4) == 4 && len >= IWAN_OUTER_IP4_LEN) {
		ULONG ihl = (ULONG)(pkt[0] & 0x0F) * 4;

		if (ihl >= IWAN_OUTER_IP4_LEN && ihl <= len &&
		    pkt[9] == IWAN_IPPROTO_UDP &&
		    (iwan_win_rd16(pkt + 6) & 0x3FFF) == 0)
			off = ihl;
	} else if ((pkt[0] >> 4) == 6 && len >= IWAN_OUTER_IP6_LEN) {
		if (pkt[6] == IWAN_IPPROTO_UDP)
			off = IWAN_OUTER_IP6_LEN;
	}

	if (len < off + IWAN_OUTER_UDP_LEN + IWAN_FRAME_HDR_LEN)
		return FALSE;
	ulen = iwan_win_rd16(pkt + off + 4);
	if (ulen < IWAN_OUTER_UDP_LEN)
		return FALSE;
	avail = len - off;
	if (ulen > avail)
		ulen = avail;		/* if the UDP length lies, fall back to the actual length */

	out->sport = iwan_win_rd16(pkt + off + 0);
	out->dport = iwan_win_rd16(pkt + off + 2);
	out->frame_off = off + IWAN_OUTER_UDP_LEN;
	out->frame_len = ulen - IWAN_OUTER_UDP_LEN;
	if (out->frame_len < IWAN_FRAME_HDR_LEN)
		return FALSE;
	out->inner_off = out->frame_off + IWAN_FRAME_HDR_LEN;
	out->inner_len = out->frame_len - IWAN_FRAME_HDR_LEN;
	if (out->inner_len == 0)
		return FALSE;

	iwan_win_frame_hdr_read(pkt, out);
	return TRUE;
}

BOOLEAN
iwan_win_should_tunnel6(_In_reads_(count) const IWAN_WIN_TARGET *targets,
			_In_ UINT32 count, _In_reads_bytes_(16) const UINT8 *outer_dst6,
			_In_reads_bytes_(16) const UINT8 *daddr6)
{
	if (targets == NULL || outer_dst6 == NULL || daddr6 == NULL)
		return FALSE;
	/* The outer server itself: never enters the tunnel (otherwise the encapsulated packet matches itself again and loops) */
	if (RtlCompareMemory(daddr6, outer_dst6, 16) == 16)
		return FALSE;
	return iwan_win_target_match(targets, count, IWAN_WIN_AF_V6, daddr6);
}
