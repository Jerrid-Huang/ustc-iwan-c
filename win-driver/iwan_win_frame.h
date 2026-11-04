/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_frame.h -- Pure logic of the Windows data plane: on-wire format, XOR, checksum, target matching.
 *
 * Deliberately no WDK dependency here (except type aliases): the same code is built into
 * the driver and also built on the host for the golden test (tests/win_frame_test.c),
 * pinning down the on-wire format early -- the part most error-prone and hardest to debug on Windows.
 *
 * The on-wire format is byte-for-byte identical to the Linux module. Sources:
 *   - kernel/iwan_tx.c's fh[] construction          -- 8-byte iWAN frame header
 *   - kernel/iwan_core.c's iwan_xor()       -- key[(off + i) & 7]
 *   - kernel/iwan_tx.c's outer IPv4/UDP construction  -- ttl 64, DF, source address taken from the session
 *   - src/common/protocol.c's pkt_hdr()     -- the same frame header in user space, used for the golden test
 */
#ifndef IWAN_WIN_FRAME_H
#define IWAN_WIN_FRAME_H

#if defined(_KERNEL_MODE)
#  include <ntddk.h>
#else
#  include <stdint.h>
#  include <stddef.h>
#  include <string.h>
typedef uint8_t  UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uint16_t USHORT;

/* Host side (static checks and golden tests on Linux) has no WDK Rtl* routines: an
 * equivalent implementation is provided, effective on non-Windows hosts only -- mingw/Windows SDK
 * winnt.h defines these names already; redefining them would collide (the real driver build uses the _KERNEL_MODE branch, unrelated here).
 *
 * Semantics per the WDK docs: RtlCopyMemory/RtlZeroMemory/RtlFillMemory are synonyms of mem*,
 * and RtlCompareMemory returns the number of bytes identical from the start (it stops at the first difference). */
#if !defined(_WIN32)
static __inline void iwan_win_host_copy(void *dst, const void *src, size_t n)
{
	memcpy(dst, src, n);
}
static __inline void iwan_win_host_zero(void *dst, size_t n)
{
	memset(dst, 0, n);
}
static __inline size_t iwan_win_host_cmp(const void *a, const void *b, size_t n)
{
	const unsigned char *x = (const unsigned char *)a;
	const unsigned char *y = (const unsigned char *)b;
	size_t i;

	for (i = 0; i < n; i++)
		if (x[i] != y[i])
			break;
	return i;
}
#define RtlCopyMemory(d, s2, n) iwan_win_host_copy((d), (s2), (n))
#define RtlZeroMemory(d, n)     iwan_win_host_zero((d), (n))
#define RtlCompareMemory(a, b, n) iwan_win_host_cmp((a), (b), (n))
#endif /* !_WIN32 */
typedef unsigned long ULONG;
typedef int BOOLEAN;
typedef long NTSTATUS;
#  ifndef TRUE
#    define TRUE 1
#  endif
#  ifndef FALSE
#    define FALSE 0
#  endif

/* Host side neutralizes the WDK VOID and SAL annotations; one source serves both the driver and the golden test */
#  define VOID void
#  define _In_
#  define _In_opt_
#  define _In_z_
#  define _Out_
#  define _Out_opt_
#  define _Inout_
#  define _Inout_opt_
#  define _In_reads_(x)
#  define _In_reads_opt_(x)
#  define _In_reads_bytes_(x)
#  define _Out_writes_(x)
#  define _Out_writes_bytes_(x)
#  define _Out_writes_bytes_opt_(x)
#  define _Inout_updates_bytes_(x)
#  define _Outptr_
#  define _Outptr_opt_
#  define _Inout_updates_(x)
#  define _Success_(x)
/* Memory-ownership annotations: at a driver boundary "who allocates" and "who frees" are two different contracts,
 * and only spelling them out stops static analysis from treating "ownership transferred" as a leak (C6014). The host side (golden
 * reference) has no WDK sal.h, so it falls back to empty macros here. */
#  define __drv_allocatesMem(x)
#  define __drv_freesMem(x)
#  define __drv_aliasesMem
#  define __analysis_assume(x)
#endif

#include "iwan_win_abi.h"

/* On-wire constants in sync with kernel/iwan.h */
#define IWAN_PT_DATA		0x14	/* plaintext inner IP packet */
#define IWAN_PT_DATA_ENC	0x18	/* XOR'd inner IP packet */
#define IWAN_KEY_LEN		8
#define IWAN_FRAME_HDR_LEN	8
#define IWAN_OUTER_UDP_LEN	8
#define IWAN_OUTER_IP4_LEN	20
#define IWAN_OUTER4_TOTAL \
	(IWAN_OUTER_IP4_LEN + IWAN_OUTER_UDP_LEN + IWAN_FRAME_HDR_LEN)	/* 36 */
#define IWAN_OUTER_IP6_LEN	40
#define IWAN_OUTER6_TOTAL	(IWAN_OUTER_IP6_LEN + IWAN_OUTER_UDP_LEN + IWAN_FRAME_HDR_LEN)
/* Inner IPv6 header (excluding extension headers). Same value as IWAN_OUTER_IP6_LEN but a different meaning:
 * the first is the inner packet's own header, the second is the outer encapsulation header; do not mix them. */
#define IWAN_INNER_IP6_LEN	40
#define IWAN_INNER_IP4_LEN	20	/* inner IPv4 header (same reasoning) */

#define IWAN_IPPROTO_TCP	6
#define IWAN_IPPROTO_UDP	17

/* Minimum L4 header length: the checksum field sits at byte 16 of TCP and byte 6 of UDP,
 * so it may be written only when the header is complete (the bound check in iwan_win_inner_fix_csum). */
#define IWAN_INNER_TCP_HDR_LEN	20
#define IWAN_INNER_UDP_HDR_LEN	8
#define IWAN_IP4_DF		0x4000

/* Frame types. The values must match kernel/iwan.h and src/common/protocol.h exactly:
 * tests/win_frame_test.c has a set of assertions pinning them to protocol.h; changing one
 * makes the test fail (this is the easiest place to be silently wrong, and it shows up only as "the peer drops everything"). */
#define PT_OPEN_REJECT		0x11
#define PT_OPEN_ACK		0x12
#define PT_OPEN			0x13
#define PT_DATA			0x14
#define PT_ECHO_REQ		0x15
#define PT_ECHO_RES		0x16
#define PT_CLOSE		0x17
#define PT_DATA_ENC		0x18
#define PT_PING_REQ		0x29
#define PT_PING_RSP		0x2A

#define IWAN_PING_SID		0xFFFF
#define IWAN_PING_TOK		0xFFFFFFFFu

/* Frame classification results, one-to-one with enum iwan_frame_kind in kernel/iwan_rx.c */
#define IWAN_WIN_FRAME_BAD	0u	/* drop (bad credentials / unknown type / malformed) */
#define IWAN_WIN_FRAME_DATA	1u	/* decapsulate, then inject into the local stack */
#define IWAN_WIN_FRAME_CTRL	2u	/* pass through unchanged to the user-space socket */

/* Outer parse result */
typedef struct _IWAN_WIN_OUTER {
	UINT32	frame_off;	/* offset of the iWAN frame header from the packet start */
	UINT32	frame_len;	/* frame length in bytes (including the 8-byte header) */
	UINT32	inner_off;	/* offset of the inner packet from the packet start */
	UINT32	inner_len;	/* inner packet length */
	UINT16	sport;		/* outer UDP source port (network order, taken from the UDP header itself) */
	UINT16	dport;		/* outer UDP destination port */
	UINT8	type;
	UINT8	enc;
	UINT16	sid;
	UINT32	tok;
} IWAN_WIN_OUTER;

/* ---- Outbound (M1/M3): outer header construction ---------------------------------------- */

/*
 * Wrap an "already encrypted frame" (8B header + payload) into a complete outer datagram.
 *
 * Aligned field by field with kernel/iwan_tx.c: outer IPv4 ttl 64 / DF=1 / protocol UDP;
 * outer IPv6 traffic class and flow label all 0 / hop limit 64 / nexthdr is directly
 * UDP (no extension headers) / no fragmentation.
 *
 * The UDP checksum is real on both paths: on Linux, v4 uses udp_set_csum() and v6 uses
 * udp6_set_csum(); Windows does the same -- the v6 UDP checksum is mandatory per RFC 8200, and for v4
 * a correct value keeps middleboxes and NAT happy. Returns the whole datagram length; 0 = invalid argument.
 */
/* Writes only the outer IP/UDP headers (including both checksums): the caller must already have
 * placed the frame at IWAN_OUTERx_TOTAL - IWAN_FRAME_HDR_LEN. flen is the frame length (8B header + payload).
 * Returns the whole datagram length; 0 = invalid argument. The driver uses this one (the frame is already in its own buffer),
 * the test uses the build variant below (which copies the frame itself). */
ULONG iwan_win_outer_hdr4(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
			  _In_ ULONG flen, _In_ UINT32 src_be, _In_ UINT32 dst_be,
			  _In_ USHORT sport, _In_ USHORT dport);

ULONG iwan_win_outer_hdr6(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
			  _In_ ULONG flen,
			  _In_reads_bytes_(16) const UINT8 *src6,
			  _In_reads_bytes_(16) const UINT8 *dst6,
			  _In_ USHORT sport, _In_ USHORT dport);

ULONG iwan_win_outer_build4(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
			    _In_reads_bytes_(flen) const UINT8 *frame,
			    _In_ ULONG flen, _In_ UINT32 src_be,
			    _In_ UINT32 dst_be, _In_ USHORT sport,
			    _In_ USHORT dport);

ULONG iwan_win_outer_build6(_Out_writes_bytes_(bufsz) UINT8 *buf, _In_ ULONG bufsz,
			    _In_reads_bytes_(flen) const UINT8 *frame,
			    _In_ ULONG flen,
			    _In_reads_bytes_(16) const UINT8 *src6,
			    _In_reads_bytes_(16) const UINT8 *dst6,
			    _In_ USHORT sport, _In_ USHORT dport);

/* Parse outer IPv6 + UDP + iWAN frame header (field semantics as in IWAN_WIN_OUTER). */
_Success_(return != FALSE)
BOOLEAN iwan_win_outer_parse6(_In_reads_bytes_(len) const UINT8 *pkt,
			      _In_ ULONG len, _Out_ IWAN_WIN_OUTER *out);

/*
 * Whether outbound traffic should be tunneled: longest-prefix match over the v6 target set. The outer server's own
 * address never enters the tunnel (otherwise the encapsulated packet would match itself again and loop forever).
 */
BOOLEAN iwan_win_should_tunnel6(_In_reads_(count) const IWAN_WIN_TARGET *targets,
				_In_ UINT32 count,
				_In_reads_bytes_(16) const UINT8 *outer_dst6,
				_In_reads_bytes_(16) const UINT8 *daddr6);

/* Parse outer IPv4 + UDP + iWAN frame header. FALSE = malformed (version/protocol/length).
 * No credential check here (that is iwan_win_frame_classify's job). */
_Success_(return != FALSE)
BOOLEAN iwan_win_outer_parse4(_In_reads_bytes_(len) const UINT8 *pkt,
			      _In_ ULONG len, _Out_ IWAN_WIN_OUTER *out);

/*
 * Parse the datagram form "already reassembled by the stack": the inbound callout is installed at INBOUND_TRANSPORT_V4/V6,
 * where fragments are already reassembled and the IP header is already stripped, so layerData starts at the outer UDP header.
 * Ports and lengths are taken from the UDP header itself, so this layer does not depend on the ports in the fixed WFP fields.
 *
 * Also tolerates the form "still carrying an IP header": the IP header is skipped only when all four of version, IHL,
 * protocol (UDP) and the no-fragment bit are self-consistent; otherwise it parses as a bare datagram -- so a layer shape
 * that differs from expectations does not silently fail, and a misdetection cannot slip in either: at offset 9 of a bare
 * datagram sits the frame header's enc field (only ever 0/1), which can never equal 17.
 */
_Success_(return != FALSE)
BOOLEAN iwan_win_dgram_parse(_In_reads_bytes_(len) const UINT8 *pkt,
			     _In_ ULONG len, _Out_ IWAN_WIN_OUTER *out);

/* Frame classification: rule-for-rule identical to iwan_frame_check in kernel/iwan_rx.c --
 *   - PT_DATA / PT_DATA_ENC: the type must agree with the session enc mode and sid/tok must match;
 *   - PT_OPEN/OPEN_ACK/OPEN_REJECT: handshake frames; only user space can validate the
 *     credentials, so with an established session they are always forwarded;
 *   - PT_ECHO_REQ/RES, PT_CLOSE: must carry the session sid/tok;
 *   - PT_PING_REQ/RSP: accepts the protocol's fixed credentials or the session credentials;
 *   - everything else: drop. */
UINT32 iwan_win_frame_classify(_In_ const IWAN_WIN_OUTER *o,
			       _In_ UINT16 sess_sid, _In_ UINT32 sess_tok,
			       _In_ BOOLEAN sess_enc,
			       _In_ BOOLEAN session_established);

/* Decapsulate: copy the inner packet to out and XOR it back when enc is set. Returns the number of bytes written;
 * 0 = invalid argument. The returned plaintext packet has valid checksums (computed by the sender before
 * the XOR, the same convention as kernel/iwan_core.c), so no checksum recomputation is needed here. */
_Success_(return != 0)
ULONG iwan_win_decap(_In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
		     _In_ const IWAN_WIN_OUTER *o,
		     _In_reads_bytes_(IWAN_KEY_LEN) const UINT8 *key,
		     _Out_writes_bytes_(outsz) UINT8 *out, _In_ ULONG outsz);

/* Protocol family of the inner packet (4 or 6): decides which injection handle re-enters the stack. 0 = unknown version. */
UINT32 iwan_win_inner_family(_In_reads_bytes_(len) const UINT8 *inner,
			     _In_ ULONG len);

/* Header self-consistency of a plaintext inner packet: version + header length + the total length declared in the header must cover the whole frame.
 * Same rule as the RX check in kernel/iwan_rx.c (lenient: extra trailing bytes are not rejected). */
BOOLEAN iwan_win_inner_sane(_In_reads_bytes_(len) const UINT8 *inner,
			    _In_ ULONG len);

/* 8-byte iWAN frame header: byte-for-byte identical to fh[] in kernel/iwan_tx.c and to
 * pkt_hdr() in src/common/protocol.c (typ is supplied by the caller as PT_DATA/PT_DATA_ENC). */
VOID iwan_win_build_frame_hdr(_Out_writes_bytes_(IWAN_FRAME_HDR_LEN) UINT8 *out,
			      _In_ UINT8 typ, _In_ UINT8 enc,
			      _In_ UINT16 sid, _In_ UINT32 tok);

/* In-place XOR: p[i] ^= key[(off + i) & 7] (matches iwan_xor in kernel/iwan_core.c) */
VOID iwan_win_xor(_Inout_updates_bytes_(len) UINT8 *p, _In_ ULONG len,
		  _In_reads_bytes_(IWAN_KEY_LEN) const UINT8 *key, _In_ ULONG off);

/* Fix up checksums on the plaintext inner IPv4 packet **before** the XOR: the IP header checksum is always recomputed,
 * the TCP/UDP checksum only when the packet carries the checksum-offload flag (l4_offloaded). */
VOID iwan_win_inner_fix_csum(_Inout_updates_bytes_(len) UINT8 *pkt, _In_ ULONG len,
			     _In_ BOOLEAN l4_offloaded);

/* Inner IPv4 fragmentation: returns the number of fragments needed; 0 means "no fragmentation needed" (not v4, length does not
 * exceed mtu, or mtu cannot even hold 8 bytes of payload). Aligned with Linux stack fragmentation: an oversized
 * datagram is cut at mtu into 8-byte-aligned fragments, and each fragment is encapsulated as its own outer frame.
 * When the return value is >= 2, the caller builds each fragment with iwan_win_frag4_build(idx=0..count-1). */
ULONG iwan_win_frag4_count(_In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
			   _In_ ULONG mtu);

/* Build fragment idx (with a recomputed IP header checksum, MF/fragment offset set, DF cleared). Returns FALSE when out_cap
 * is too small or an argument is invalid. Fragmentation must happen after the L4 checksum is fixed up -- otherwise every
 * fragment carries a wrong L4 checksum. */
_Success_(return != FALSE)
BOOLEAN iwan_win_frag4_build(_Out_writes_bytes_(out_cap) UINT8 *out,
			     _In_ ULONG out_cap,
			     _In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
			     _In_ ULONG mtu, _In_ ULONG idx,
			     _Out_ ULONG *out_len);

/* ---- Outer fragment reassembly (MP plane; on the WFP plane tcpip's ip_defrag does the work) ------ */

/* Upper bound on datagrams being reassembled concurrently. This is not a throughput knob but the limit on how many incomplete
 * datagrams one peer can have in flight: a normal peer (both of ours are) always sets outer DF=1 and never reaches
 * this path, so keep it small. */
#define IWAN_WIN_FRAG_SLOTS	4u

/* Per-datagram reassembly cap (including the outer UDP header). Outer datagrams never exceed the carrier MTU anyway;
 * the 9 KB here is headroom for the unusual configuration "the peer turns outer DF off"; anything larger is dropped,
 * with no unbounded growth (historically the non-paged pool was filled up and the whole machine hung). */
#define IWAN_WIN_FRAG_BUF_SIZE	9216u

/* How far a fragment has been assembled. Everything except used/total/have is internal state; callers must not touch it. */
typedef struct _IWAN_WIN_FRAG_SLOT {
	BOOLEAN	used;		/* this slot is assembling a datagram */
	UINT32	src;		/* outer source address, raw big-endian bytes */
	UINT32	dst;		/* outer destination address */
	UINT16	id;		/* outer IPv4 identification */
	UINT32	start_ms;	/* arrival time of the first fragment, used for age-out */
	UINT32	total;		/* 0 until the last fragment arrives */
	UINT32	end;		/* highest byte offset received (to detect "total contradicts what was received") */
	UINT32	have;		/* number of 8-byte blocks received */
	UINT8	buf[IWAN_WIN_FRAG_BUF_SIZE];
	UINT8	bits[IWAN_WIN_FRAG_BUF_SIZE / 64u];	/* block bitmap */
} IWAN_WIN_FRAG_SLOT;

/* Result codes: PASS means "this is not a fragment" and the caller continues with the normal packet path. */
#define IWAN_WIN_FRAG_PASS	0
#define IWAN_WIN_FRAG_STORED	1	/* accepted, not yet complete */
#define IWAN_WIN_FRAG_DONE	2	/* complete: the full datagram is in slot->buf[0..out_len) */
#define IWAN_WIN_FRAG_DROP	3	/* cannot assemble: no free slot / over the cap / length contradiction */

/* Feed one fragment. out_idx gives the slot index on STORED/DONE; DONE means "the content is ready,
 * but the slot still belongs to the caller" -- the caller must set slots[*out_idx].used to FALSE after parsing it,
 * or the slot is never reclaimed (deliberate: the reassembly logic does not decide for the caller when the data is done). */
int iwan_win_frag_input(_Inout_ IWAN_WIN_FRAG_SLOT *slots,
			_In_ ULONG nslots,
			_In_reads_bytes_(len) const UINT8 *pkt, _In_ ULONG len,
			_In_ ULONG now_ms, _In_ ULONG ttl_ms,
			_Out_ ULONG *out_idx, _Out_ ULONG *out_len);

/* Longest-prefix match against the target set (pure function, easy to test). family is IWAN_WIN_AF_V4/V6 and
 * addr points to a 4- or 16-byte network-order address. */
/* The length of addr is decided by family (v4 = 4 bytes, v6 = 16 bytes): writing 16 truthfully would let
 * static analysis flag the v4 call sites (which hand over only those 4 bytes from the IP header) as out-of-bounds reads (C6385),
 * while reading 12 extra bytes is something the implementation never does -- prefix matching walks byte by byte over prefix_len/8. */
BOOLEAN iwan_win_target_match(_In_reads_(count) const IWAN_WIN_TARGET *targets,
			      _In_ UINT32 count, _In_ UINT32 family,
			      _In_reads_bytes_((family == IWAN_WIN_AF_V4) ? 4 : 16)
			      const UINT8 *addr);

/* Whether to tunnel: the target set is hit and the destination is not the outer server itself
 * (corresponds to the Linux side pinning "server /32 to the physical NIC" so tunnel outer packets never re-enter the tunnel). */
_Success_(return != FALSE)
BOOLEAN iwan_win_should_tunnel4(_In_reads_(count) const IWAN_WIN_TARGET *targets,
				_In_ UINT32 count,
				_In_reads_bytes_(4) const UINT8 *outer_dst_be,
				_In_reads_bytes_(4) const UINT8 *daddr);

/* Small helpers (used both inside the driver and by tests) */
USHORT iwan_win_rd16(_In_reads_bytes_(2) const UINT8 *p);
VOID iwan_win_wr16(_Out_writes_bytes_(2) UINT8 *p, _In_ USHORT v);
VOID iwan_win_wr32(_Out_writes_bytes_(4) UINT8 *p, _In_ UINT32 v);
UINT32 iwan_win_rd32(_In_reads_bytes_(4) const UINT8 *p);

#endif /* IWAN_WIN_FRAME_H */
