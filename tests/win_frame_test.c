/* SPDX-License-Identifier: GPL-2.0 */
/*
 * win_frame_test.c - cross-check and self-test of the pure Windows data-plane logic (runs on Linux).
 *
 * Why this test: encapsulation is the hard prerequisite for interop among the
 * Windows driver, the Linux module and the user-space client, yet it is the part
 * easiest to get wrong and hardest to debug on Windows (a mistake shows only as
 * "the peer drops every packet"). Pure logic is in win-driver/iwan_win_frame.c, cross-checked here with the host compiler against the repo's **independent implementations**:
 *
 *   - frame header: byte-for-byte against pkt_hdr() in src/common/protocol.c;
 *   - XOR: byte-for-byte against xor_crypt(key, 8) in src/common/crypto.c;
 *   - checksum: recomputed by an independent verifier (sum incl. the checksum field must be 0xFFFF);
 *   - target match: longest-prefix semantics + "outer server address never enters the tunnel".
 *
 * Build (verified on this host):
 *   gcc -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
 *       -DIWAN_WIN_ABI_BARE -Isrc/common -Iwin-driver \
 *       tests/win_frame_test.c win-driver/iwan_win_frame.c \
 *       src/common/protocol.c src/common/crypto.c src/common/util.c \
 *       -Wl,--gc-sections -lcrypto -o /tmp/win_frame_test
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "iwan_win_frame.h"

/* Existing user-space implementation in the repo (separate from the driver's), used for cross-checking */
void pkt_hdr(uint8_t typ, uint8_t enc, uint16_t sid, uint32_t tok,
	     uint8_t out[8]);
void xor_crypt(uint8_t *data, size_t len, const uint8_t *key, size_t klen);

static int g_fail;
static int g_pass;

#define CHECK(cond, ...) do {						\
	if (cond) {							\
		g_pass++;						\
	} else {							\
		g_fail++;						\
		printf("FAIL %s:%d: ", __FILE__, __LINE__);		\
		printf(__VA_ARGS__);					\
		printf("\n");						\
	}								\
} while (0)

/* ---- 1. Frame header: byte-for-byte vs user-space pkt_hdr() -------------- */

static void
test_frame_hdr(void)
{
	static const struct {
		uint8_t typ, enc;
		uint16_t sid;
		uint32_t tok;
	} cases[] = {
		{ IWAN_PT_DATA,     0, 0x0000, 0x00000000 },
		{ IWAN_PT_DATA_ENC, 1, 0x1234, 0xdeadbeef },
		{ IWAN_PT_DATA_ENC, 1, 0x030c, 0x00000001 },
		{ IWAN_PT_DATA,     0, 0xffff, 0xffffffff },
		{ IWAN_PT_DATA_ENC, 1, 0x00ff, 0x01000000 },
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		uint8_t mine[8], theirs[8];

		iwan_win_build_frame_hdr(mine, cases[i].typ, cases[i].enc,
					 cases[i].sid, cases[i].tok);
		pkt_hdr(cases[i].typ, cases[i].enc, cases[i].sid, cases[i].tok,
			theirs);
		CHECK(memcmp(mine, theirs, 8) == 0,
		      "frame header differs from user-space pkt_hdr (sid=%04x tok=%08x)",
		      cases[i].sid, cases[i].tok);
	}

	/* Field order is pinned by fh[] in kernel/iwan_tx.c: type, enc,
	 * sid big-endian 16-bit, tok big-endian 32-bit */
	{
		uint8_t h[8];

		iwan_win_build_frame_hdr(h, IWAN_PT_DATA_ENC, 1, 0x030c,
					 0x01020304);
		CHECK(h[0] == 0x18 && h[1] == 0x01 && h[2] == 0x03 &&
		      h[3] == 0x0c && h[4] == 0x01 && h[5] == 0x02 &&
		      h[6] == 0x03 && h[7] == 0x04,
		      "frame header byte order mismatch: %02x %02x %02x %02x %02x %02x %02x %02x",
		      h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
	}
}

/* ---- 2. XOR: byte-for-byte vs user-space xor_crypt() + round-trip self-check - */

static void
test_xor(void)
{
	uint8_t key[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
	uint8_t a[1024], b[1024];
	size_t lens[] = { 0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 1000, 1024 };
	uint32_t offs[] = { 0, 1, 3, 8 };
	size_t i, j;

	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		for (j = 0; j < sizeof(offs) / sizeof(offs[0]); j++) {
			size_t n = lens[i];
			uint8_t ref[1024];
			size_t k;

			for (k = 0; k < n; k++)
				a[k] = b[k] = (uint8_t)(k * 31 + 7);
			/* Byte-by-byte reference: the block form (one 64-bit word per round) must match bit for bit.
			 * A round-trip self-check alone is blind to a wrong phase - a wrong phase still restores. */
			for (k = 0; k < n; k++)
				ref[k] = (uint8_t)((uint8_t)(k * 31 + 7) ^
						   key[(offs[j] + k) & 7]);

			/* The driver only uses it on whole packets with off 0, but the function itself
			 * supports off (same semantics as kernel iwan_xor); verify that here as well */
			iwan_win_xor(a, (ULONG)n, key, (ULONG)offs[j]);
			CHECK(memcmp(a, ref, n) == 0,
			      "XOR differs from the byte-by-byte reference (len=%zu off=%u)",
			      n, offs[j]);
			if (offs[j] == 0) {
				xor_crypt(b, n, key, sizeof(key));
				CHECK(memcmp(a, b, n) == 0,
				      "XOR differs from user-space xor_crypt (len=%zu)", n);
			}

			/* Round trip: a second XOR must restore */
			iwan_win_xor(a, (ULONG)n, key, (ULONG)offs[j]);
			for (k = 0; k < n; k++)
				if (a[k] != (uint8_t)(k * 31 + 7))
					break;
			CHECK(k == n, "XOR round trip did not restore (len=%zu off=%u)",
			      n, offs[j]);
		}
	}
}

/* ---- 3. Checksum: recomputed by an independent verifier ----------------- */

/* Standard verification: "sum including the checksum field == 0xFFFF" */
static uint32_t
sum16(const uint8_t *p, size_t len)
{
	uint32_t s = 0;
	size_t i;

	for (i = 0; i + 1 < len; i += 2)
		s += ((uint32_t)p[i] << 8) | p[i + 1];
	if (i < len)
		s += ((uint32_t)p[i] << 8);
	while (s >> 16)
		s = (s & 0xFFFF) + (s >> 16);
	return s;
}

static void
test_csum(void)
{
	uint8_t pkt[64];
	uint32_t l4;

	/* Build an IPv4 + UDP packet (20 + 8 + 16 bytes of payload); checksum fields left 0 */
	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x45;
	pkt[8] = 64;
	pkt[9] = 17;			/* UDP */
	pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1;
	pkt[16] = 10; pkt[17] = 0; pkt[18] = 0; pkt[19] = 2;
	pkt[20] = 0x04; pkt[21] = 0xd2;	/* 1234 */
	pkt[22] = 0x16; pkt[23] = 0x2e;	/* 5678 */
	pkt[24] = 0x00; pkt[25] = 0x18;	/* 24 = 8 + 16 */
	{
		uint16_t tot = 44;
		uint8_t t[24];
		size_t k;

		for (k = 0; k < 16; k++)
			pkt[28 + k] = (uint8_t)(k * 7 + 1);
		t[0] = (uint8_t)(tot >> 8);
		t[1] = (uint8_t)tot;
		pkt[2] = t[0];
		pkt[3] = t[1];
	}

	/* With the "checksum offload" flag: both checksums must be filled in */
	iwan_win_inner_fix_csum(pkt, 44, TRUE);

	CHECK(sum16(pkt, 20) == 0xFFFF, "IPv4 header checksum verification failed (sum=%04x)",
	      sum16(pkt, 20));

	/* UDP checksum verification must include the pseudo-header */
	l4 = 44 - 20;
	{
		uint32_t s = 0;
		uint8_t pseudo[12];
		uint32_t i;

		memcpy(pseudo, pkt + 12, 8);
		pseudo[8] = 0;
		pseudo[9] = 17;
		pseudo[10] = (uint8_t)(l4 >> 8);
		pseudo[11] = (uint8_t)l4;
		s = sum16(pseudo, sizeof(pseudo));
		for (i = 20; i < 44; i += 2)
			s += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
		while (s >> 16)
			s = (s & 0xFFFF) + (s >> 16);
		CHECK(s == 0xFFFF, "UDP checksum verification failed (sum=%04x)", s);
	}

	/* Without the offload flag only the IP header is recomputed; L4 is untouched */
	{
		uint8_t before[64];

		memset(pkt + 20, 0, 24);
		pkt[20] = 0x04; pkt[21] = 0xd2;
		pkt[22] = 0x16; pkt[23] = 0x2e;
		pkt[24] = 0x00; pkt[25] = 0x18;
		memcpy(before, pkt, 44);
		iwan_win_inner_fix_csum(pkt, 44, FALSE);
		CHECK(memcmp(before + 20, pkt + 20, 24) == 0,
		      "L4 area changed although offload was not flagged");
		CHECK(sum16(pkt, 20) == 0xFFFF, "IP header checksum not recomputed");
	}

	/* Non-IPv4 or invalid length: must return unchanged, no out-of-bounds write */
	{
		uint8_t junk[8] = { 0x60, 0, 0, 0, 0, 0, 0, 0 };

		iwan_win_inner_fix_csum(junk, sizeof(junk), TRUE);
		CHECK(junk[0] == 0x60, "non-IPv4 packet was modified");
	}
}


/*
 * Inner checksum fix must keep the "addresses untouched".
 *
 * The only reason this case exists: iwan_win_inner_fix_csum() once wrote the IPv4 header checksum
 * at offset 12 (correct is 10) - exactly covering the high half-word of the inner source address.
 * Existing cases could not catch it: both checksum checks prove themselves with "sum incl. the checksum
 * field == 0xFFFF", and the checksum is computed over the header with 12/13 zeroed and then written back to
 * the same location, so it is self-consistent; the UDP pseudo-header reads that same corrupted address,
 * so both checks were fooled together. Field symptom: frame format, sid/tok and length all correct, the peer
 * decodes the frame, but the inner source address becomes a value like 122.x.0.2 decreasing per packet
 * (IP ID +2 per packet, so the checksum is -2 per packet); replies never come back - ping 100% loss, no UDP response.
 */
static void
test_inner_fix_csum_keeps_addrs(void)
{
	uint8_t pkt[44];
	const uint8_t src[4] = { 10, 99, 0, 2 };
	const uint8_t dst[4] = { 10, 0, 2, 15 };
	uint32_t s, i;

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x45;
	pkt[2] = 0; pkt[3] = 44;
	pkt[8] = 64;
	pkt[9] = 17;			/* UDP */
	memcpy(pkt + 12, src, 4);
	memcpy(pkt + 16, dst, 4);
	pkt[20] = 0x9c; pkt[21] = 0x41;	/* source port 40001 */
	pkt[22] = 0x27; pkt[23] = 0x0f;	/* destination port 9999 */
	pkt[24] = 0x00; pkt[25] = 0x18;	/* UDP length 24 = 8 + 16 */
	for (i = 0; i < 16; i++)
		pkt[28 + i] = 0xAB;

	iwan_win_inner_fix_csum(pkt, sizeof(pkt), TRUE);

	CHECK(memcmp(pkt + 12, src, 4) == 0,
	      "inner source address was rewritten (IPv4 header checksum is at offset 10/11, not 12/13)");
	CHECK(memcmp(pkt + 16, dst, 4) == 0, "inner destination address was rewritten");
	CHECK(!(pkt[10] == 0 && pkt[11] == 0),
	      "IPv4 header checksum was not written at offset 10/11");
	CHECK(sum16(pkt, 20) == 0xFFFF, "IPv4 header checksum self-consistency check failed");

	/* The UDP checksum must hold for a pseudo-header built from the "real source address". We **deliberately
	 * do not read pkt bytes 12..19**, but compute the pseudo-header from the known src/dst constants - reading
	 * the packet's own addresses would repeat the implementation's mistake (it used the corrupted ones) and prove nothing. */
	s = 0;
	for (i = 0; i < 4; i += 2)
		s += ((uint32_t)src[i] << 8) | src[i + 1];
	for (i = 0; i < 4; i += 2)
		s += ((uint32_t)dst[i] << 8) | dst[i + 1];
	s += 17 + 24;
	for (i = 20; i < 44; i += 2)
		s += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
	while (s >> 16)
		s = (s & 0xFFFF) + (s >> 16);
	CHECK(s == 0xFFFF, "UDP checksum does not hold for the real source address (sum=%04x)", s);
}

/* ---- 4. Target matching + outer server exclusion ----------------------- */

static void
put_v4(IWAN_WIN_TARGET *t, const uint8_t *a, uint32_t plen)
{
	t->family = IWAN_WIN_AF_V4;
	t->prefix_len = plen;
	memset(t->addr, 0, sizeof(t->addr));
	memcpy(t->addr, a, 4);
}

static void
test_targets(void)
{
	IWAN_WIN_TARGET t[4];
	uint8_t server[4] = { 202, 38, 64, 106 };
	uint8_t wide[4] = { 202, 38, 0, 0 };
	uint8_t campus[4] = { 202, 38, 95, 0 };
	uint8_t other[4] = { 8, 8, 8, 8 };
	uint8_t in_campus[4] = { 202, 38, 95, 110 };
	uint8_t in_other[4] = { 202, 38, 100, 1 };

	put_v4(&t[0], wide, 16);		/* 202.38.0.0/16 */
	put_v4(&t[1], campus, 24);	/* 202.38.95.0/24 */
	put_v4(&t[2], server, 32);	/* the server /32 is in the set too */
	put_v4(&t[3], other, 32);	/* 8.8.8.8/32 */

	CHECK(iwan_win_target_match(t, 4, IWAN_WIN_AF_V4, in_campus),
	      "202.38.95.110 should match the set");
	CHECK(iwan_win_target_match(t, 4, IWAN_WIN_AF_V4, in_other),
	      "202.38.100.1 should match via the /16");
	CHECK(iwan_win_target_match(t, 4, IWAN_WIN_AF_V4, other),
	      "8.8.8.8 matches its own /32");
	/* The server address is covered only by the /16; with only the campus /24 left it must not match */
	CHECK(!iwan_win_target_match(t + 1, 1, IWAN_WIN_AF_V4, server),
	      "server address must not match the campus /24");

	/* Key point: even if the set contains a wide prefix covering the server, the outer server address never enters the tunnel */
	CHECK(!iwan_win_should_tunnel4(t, 4, server, server),
	      "outer server address was wrongly judged as tunnel-bound");
	CHECK(iwan_win_should_tunnel4(t, 4, server, in_campus),
	      "campus address should enter the tunnel");
	CHECK(iwan_win_should_tunnel4(t, 4, server, other),
	      "8.8.8.8/32 in the set should enter the tunnel");

	/* v6: /128 and /64 */
	{
		IWAN_WIN_TARGET v6;
		uint8_t net[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
				    0, 0, 0, 0, 0, 0, 0, 0 };
		uint8_t a1[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
				   0, 0, 0, 0, 0, 0, 0, 1 };
		uint8_t a2[16] = { 0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0,
				   0, 0, 0, 0, 0, 0, 0, 1 };
		uint8_t a3[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x80, 0, 0, 0,
				   0, 0, 0, 0, 0, 0, 0, 1 };

		v6.family = IWAN_WIN_AF_V6;
		v6.prefix_len = 33;
		memcpy(v6.addr, net, 16);
		v6.addr[4] = 0x80;	/* 2001:db8:8000::/33 */
		CHECK(iwan_win_target_match(&v6, 1, IWAN_WIN_AF_V6, a3),
		      "v6 /33 non-byte-aligned prefix match failed");
		CHECK(!iwan_win_target_match(&v6, 1, IWAN_WIN_AF_V6, a1),
		      "v6 out-of-range address wrongly matched");
		CHECK(!iwan_win_target_match(&v6, 1, IWAN_WIN_AF_V6, a2),
		      "v6 another prefix wrongly matched");
	}
}


/* ---- 5. Inbound M2: outer parse / frame classification / decap ---------- */

/* Wire constants must match kernel/iwan.h and src/common/protocol.h. The values themselves are a frozen
 * wire contract; group 6 below builds frames with user-space pkt_hdr() and feeds them to the driver-side
 * parser, which is one more cross-check of this value table. */
static void
test_wire_constants(void)
{
	CHECK(PT_OPEN_REJECT == 0x11 && PT_OPEN_ACK == 0x12 && PT_OPEN == 0x13,
	      "handshake frame types do not match the wire");
	CHECK(PT_DATA == 0x14 && PT_ECHO_REQ == 0x15 && PT_ECHO_RES == 0x16 &&
	      PT_CLOSE == 0x17 && PT_DATA_ENC == 0x18,
	      "data/echo/close frame types do not match the wire");
	CHECK(PT_PING_REQ == 0x29 && PT_PING_RSP == 0x2A,
	      "ping frame types do not match the wire");
	CHECK(IWAN_PING_SID == 0xFFFF && IWAN_PING_TOK == 0xFFFFFFFFu,
	      "fixed ping credentials do not match the wire");
	CHECK(IWAN_OUTER4_TOTAL == 36, "outer IPv4 encapsulation overhead should be 36 bytes");
}

/* Build an outer IPv4 + UDP + frame header + payload packet (payload filled in by caller) */
static size_t
build_outer(uint8_t *buf, size_t inner_len, uint16_t sport, uint16_t dport,
	    uint8_t type, uint8_t enc, uint16_t sid, uint32_t tok,
	    uint16_t frag_off)
{
	uint8_t *ip = buf, *udp = buf + 20;
	size_t total = 20 + 8 + 8 + inner_len;
	uint32_t sum;

	memset(buf, 0, total);
	ip[0] = 0x45;
	ip[2] = (uint8_t)(total >> 8);
	ip[3] = (uint8_t)total;
	frag_off = (uint16_t)(frag_off | 0x4000u);   /* DF */
	ip[6] = (uint8_t)(frag_off >> 8);
	ip[7] = (uint8_t)frag_off;
	ip[8] = 64;
	ip[9] = 17;
	ip[12] = 202; ip[13] = 38; ip[14] = 64; ip[15] = 106;  /* server */
	ip[16] = 10; ip[17] = 0; ip[18] = 0; ip[19] = 2;
	udp[0] = (uint8_t)(sport >> 8); udp[1] = (uint8_t)sport;
	udp[2] = (uint8_t)(dport >> 8); udp[3] = (uint8_t)dport;
	{
		uint16_t ul = (uint16_t)(8 + 8 + inner_len);

		udp[4] = (uint8_t)(ul >> 8);
		udp[5] = (uint8_t)ul;
	}
	iwan_win_build_frame_hdr(buf + 28, type, enc, sid, tok);
	sum = 0;
	for (size_t i = 0; i + 1 < 20; i += 2)
		sum += ((uint32_t)ip[i] << 8) | ip[i + 1];
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	sum = ~sum & 0xFFFF;
	ip[10] = (uint8_t)(sum >> 8);
	ip[11] = (uint8_t)sum;
	return total;
}

static void
test_inbound(void)
{
	const uint8_t key[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t inner[64], outer[256], out[128];
	IWAN_WIN_OUTER o;
	size_t total, n;
	uint16_t sid = 0x030c;
	uint32_t tok = 0xdeadbeef;

	/* Inner IPv4 packet (20-byte header + 8-byte UDP header + 4-byte payload) */
	memset(inner, 0, sizeof(inner));
	inner[0] = 0x45;
	inner[2] = 0; inner[3] = 32;
	inner[8] = 64;
	inner[9] = 17;
	inner[12] = 10; inner[13] = 0; inner[14] = 0; inner[15] = 2;
	inner[16] = 8; inner[17] = 8; inner[18] = 8; inner[19] = 8;
	inner[20] = 0x04; inner[21] = 0xd2;
	inner[22] = 0x16; inner[23] = 0x2e;
	inner[24] = 0; inner[25] = 12;
	inner[28] = 'i'; inner[29] = 'w'; inner[30] = 'a'; inner[31] = 'n';

	/* --- Encrypted frame: parse + classify + decap, restoring the inner packet as-is --- */
	{
		uint8_t enc_inner[64];

		memcpy(enc_inner, inner, 32);
		xor_crypt(enc_inner, 32, key, 8);
		total = build_outer(outer, 32, 40000, 6001, PT_DATA_ENC, 1, sid, tok, 0);
		memcpy(outer + 36, enc_inner, 32);

		CHECK(iwan_win_outer_parse4(outer, total, &o), "valid outer packet failed to parse");
		CHECK(o.type == PT_DATA_ENC && o.enc == 1 && o.sid == sid &&
		      o.tok == tok, "frame header fields parsed out of place");
		CHECK(o.inner_off == 36 && o.inner_len == 32, "inner offset/length miscalculated");
		CHECK(iwan_win_inner_family(outer + 36, 32) == 4,
		      "encrypted inner packet must not be classified by protocol family directly (should be v4 first byte)");
		CHECK(iwan_win_frame_classify(&o, sid, tok, TRUE, TRUE) ==
		      IWAN_WIN_FRAME_DATA, "valid encrypted data frame should classify as DATA");
		n = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
		CHECK(n == 32, "decap length wrong");
		CHECK(memcmp(out, inner, 32) == 0, "decap result differs from the original inner packet");
		CHECK(iwan_win_inner_family(out, n) == 4, "decap result should be recognized as inner v4");
	}

	/* --- Plaintext frame --- */
	{
		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0);
		memcpy(outer + 36, inner, 32);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "plaintext outer packet failed to parse");
		CHECK(iwan_win_frame_classify(&o, sid, tok, FALSE, TRUE) ==
		      IWAN_WIN_FRAME_DATA, "valid plaintext data frame should classify as DATA");
		n = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
		CHECK(n == 32 && memcmp(out, inner, 32) == 0, "plaintext decap should return the packet as-is");
	}

	/* --- Inner v6 (outer is still v4): injection needs the v6 handle --- */
	{
		uint8_t in6[48];

		memset(in6, 0, sizeof(in6));
		in6[0] = 0x60;
		in6[4] = 0; in6[5] = 8;          /* payload len */
		in6[6] = 17;                     /* next header = UDP */
		in6[7] = 64;
		in6[8] = 0x20; in6[9] = 0x01;
		total = build_outer(outer, 48, 40000, 6001, PT_DATA, 0, sid, tok, 0);
		memcpy(outer + 36, in6, 48);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "v6-in-v4 parse failed");
		n = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
		CHECK(n == 48 && iwan_win_inner_family(out, n) == 6,
		      "inner v6 should be recognized as protocol family 6");
	}

	/* --- Credentials and type gates --- */
	{
		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0);
		memcpy(outer + 36, inner, 32);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "parse failed");
		CHECK(iwan_win_frame_classify(&o, sid, tok + 1, FALSE, TRUE) ==
		      IWAN_WIN_FRAME_BAD, "data frame with mismatched sid/tok must be dropped");
		CHECK(iwan_win_frame_classify(&o, sid, tok, TRUE, TRUE) ==
		      IWAN_WIN_FRAME_BAD, "data frame with mismatched enc mode must be dropped");
		/* Data frames do not look at the session gate (iwan_frame_check in kernel/iwan_rx.c checks dp->session
		 * only for control frames); whether a session exists is decided first at the call site - in the driver
		 * it checks s->valid first and lets the whole callout pass untouched when there is no session. */
		CHECK(iwan_win_frame_classify(&o, sid, tok, FALSE, FALSE) ==
		      IWAN_WIN_FRAME_DATA, "data frame classification must not depend on the session gate");
	}

	/* --- Type and frame-header enc must be consistent: otherwise an encrypted session can be downgraded to plaintext passthrough ---
	 * The decap side (iwan_win_decap) decides whether to decrypt from the frame's o->enc; classification looking
	 * only at type leaves a gap: the session is encrypted, an attacker sends type=PT_DATA_ENC but enc=0 (sid/tok are
	 * plaintext in the frame header and can simply be copied), decap takes the plaintext branch and any inner packet
	 * passes straight through. The two groups below are evidence that "the gate must stop it, while decap cannot". */
	{
		total = build_outer(outer, 32, 40000, 6001, PT_DATA_ENC, 0, sid, tok, 0);
		memcpy(outer + 36, inner, 32);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "parse failed");
		CHECK(o.type == PT_DATA_ENC && o.enc == 0, "frame header fields parsed out of place");
		CHECK(iwan_win_frame_classify(&o, sid, tok, TRUE, TRUE) ==
		      IWAN_WIN_FRAME_BAD, "data frame with enc=0 in an encrypted session must be dropped");
		CHECK(iwan_win_decap(outer, total, &o, key, out, sizeof(out)) == 32 &&
		      memcmp(out, inner, 32) == 0,
		      "control: decap really takes the plaintext branch from the frame's enc; only classification can gate it");

		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 1, sid, tok, 0);
		memcpy(outer + 36, inner, 32);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "parse failed");
		CHECK(o.enc == 1, "frame header enc parsed out of place");
		CHECK(iwan_win_frame_classify(&o, sid, tok, FALSE, TRUE) ==
		      IWAN_WIN_FRAME_BAD, "data frame with enc=1 in a plaintext session must be dropped");
	}

	/* --- Control frames: ECHO/CLOSE need credentials, handshake frames are always passed; ping accepts fixed credentials --- */
	{
		static const struct { uint8_t type; uint16_t sid; uint32_t tok;
				      uint32_t want; } c[] = {
			{ PT_ECHO_REQ, 0x030c, 0xdeadbeef, IWAN_WIN_FRAME_CTRL },
			{ PT_ECHO_RES, 0x030c, 0xdeadbeef, IWAN_WIN_FRAME_CTRL },
			{ PT_CLOSE,    0x030c, 0xdeadbeef, IWAN_WIN_FRAME_CTRL },
			{ PT_ECHO_REQ, 0x0001, 0xdeadbeef, IWAN_WIN_FRAME_BAD },
			{ PT_OPEN,     0x0000, 0x00000000, IWAN_WIN_FRAME_CTRL },
			{ PT_OPEN_ACK, 0x1234, 0xabcdef01, IWAN_WIN_FRAME_CTRL },
			{ PT_OPEN_REJECT, 0x0000, 0x00000000, IWAN_WIN_FRAME_CTRL },
			{ PT_PING_REQ, IWAN_PING_SID, IWAN_PING_TOK,
			  IWAN_WIN_FRAME_CTRL },
			{ PT_PING_RSP, 0x030c, 0xdeadbeef, IWAN_WIN_FRAME_CTRL },
			{ PT_PING_REQ, 0x030c, 0x11111111, IWAN_WIN_FRAME_BAD },
		};
		size_t i;

		for (i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
			total = build_outer(outer, 8, 40000, 6001, c[i].type, 0,
					    c[i].sid, c[i].tok, 0);
			CHECK(iwan_win_outer_parse4(outer, total, &o),
			      "control frame failed to parse (type=%02x)", c[i].type);
			CHECK(iwan_win_frame_classify(&o, 0x030c, 0xdeadbeef,
						      FALSE, TRUE) == c[i].want,
			      "control frame classification mismatch (type=%02x sid=%04x)",
			      c[i].type, c[i].sid);
		}
		/* Even handshake frames are dropped when no session exists (matches the kernel-side session gate) */
		total = build_outer(outer, 8, 40000, 6001, PT_OPEN_ACK, 0, 1, 2, 0);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "parse failed");
		CHECK(iwan_win_frame_classify(&o, 0x030c, 0xdeadbeef, FALSE, FALSE) ==
		      IWAN_WIN_FRAME_BAD, "handshake frame must also be dropped when no session exists");
	}

	/* --- Malformed structure: fragments, truncation, non-UDP, lying length must all be safely rejected --- */
	{
		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok,
				    0x2000);      /* MF set */
		CHECK(!iwan_win_outer_parse4(outer, total, &o), "fragment must not be parsed");
		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok,
				    100);         /* non-first-fragment offset */
		CHECK(!iwan_win_outer_parse4(outer, total, &o), "non-first fragment must not be parsed");
		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0);
		outer[9] = 6;                          /* TCP */
		CHECK(!iwan_win_outer_parse4(outer, total, &o), "non-UDP must not be parsed");
		outer[9] = 17;
		CHECK(!iwan_win_outer_parse4(outer, 30, &o), "truncated packet must not be parsed");
		CHECK(!iwan_win_outer_parse4(outer, 0, &o), "empty packet must not be parsed");
		/* UDP length larger than actual: fall back to the actual length, still parses (same lenient rule as kernel side) */
		outer[24] = 0xff; outer[25] = 0xff;
		CHECK(iwan_win_outer_parse4(outer, total, &o), "lying UDP length should still parse via fallback");
		CHECK(o.inner_len == total - 36, "inner length after fallback is wrong");
		/* Zero-length inner: reject */
		total = build_outer(outer, 0, 40000, 6001, PT_DATA, 0, sid, tok, 0);
		CHECK(!iwan_win_outer_parse4(outer, total, &o), "zero-length inner must be rejected");
	}

	/* --- Decap output buffer too small: must reject rather than overflow --- */
	{
		total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0);
		memcpy(outer + 36, inner, 32);
		CHECK(iwan_win_outer_parse4(outer, total, &o), "parse failed");
		CHECK(iwan_win_decap(outer, total, &o, key, out, 16) == 0,
		      "must reject when the output buffer is too small");
	}

	/* --- Inner header sanity (the last gate before injection) --- */
	{
		CHECK(iwan_win_inner_sane(inner, 32), "valid inner v4 packet should pass");
		CHECK(!iwan_win_inner_sane(inner, 12), "incomplete inner v4 header must be rejected");
		{
			uint8_t bad[32];

			memcpy(bad, inner, 32);
			bad[3] = 200;           /* declared total length exceeds actual */
			CHECK(!iwan_win_inner_sane(bad, 32),
			      "inner declared length exceeding the whole frame must be rejected");
			memcpy(bad, inner, 32);
			bad[0] = 0x35;          /* ihl=5 => 20, valid; then try 0x4f */
			bad[0] = 0x4f;          /* ihl=15 => 60 > len */
			CHECK(!iwan_win_inner_sane(bad, 32), "inner ihl out of range must be rejected");
			memcpy(bad, inner, 32);
			bad[0] = 0x70;          /* version 7 */
			CHECK(!iwan_win_inner_sane(bad, 32), "unknown inner version must be rejected");
		}
		{
			uint8_t in6[48];

			memset(in6, 0, sizeof(in6));
			in6[0] = 0x60;
			in6[4] = 0; in6[5] = 8;         /* payload len = 8 */
			in6[6] = 17;
			CHECK(iwan_win_inner_sane(in6, 48), "valid inner v6 packet should pass");
			in6[5] = 200;                   /* declared length exceeds the whole frame */
			CHECK(!iwan_win_inner_sane(in6, 48),
			      "inner v6 declared length exceeding the whole frame must be rejected");
			CHECK(!iwan_win_inner_sane(in6, 20), "incomplete inner v6 header must be rejected");
		}
	}
}

/* ---- 5b. Decap by length class: every length must match "byte-wise copy then XOR" --- */

static void
test_decap_lengths(void)
{
	const uint8_t key[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				 0x88 };
	size_t lens[] = { 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
			  127, 128, 129, 1000 };
	uint8_t plain[1200], enc[1200], outer[1400], out[1200];
	uint16_t sid = 0x030c;
	uint32_t tok = 0xdeadbeef;
	size_t i, k;

	for (k = 0; k < sizeof(plain); k++)
		plain[k] = (uint8_t)(k * 7 + 3);

	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		size_t n = lens[i];
		IWAN_WIN_OUTER o;
		size_t total, got;

		/* Encrypted frame: decap must recover the plaintext */
		memcpy(enc, plain, n);
		xor_crypt(enc, n, key, sizeof(key));
		total = build_outer(outer, n, 40000, 6001, PT_DATA_ENC, 1, sid,
				    tok, 0);
		memcpy(outer + 36, enc, n);
		CHECK(iwan_win_outer_parse4(outer, total, &o),
		      "encrypted frame failed to parse (len=%zu)", n);
		got = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
		CHECK(got == n, "decap length wrong (len=%zu got=%zu)", n, got);
		CHECK(memcmp(out, plain, n) == 0, "decap result mismatch (len=%zu)", n);

		/* Plaintext frame: decap must copy it as-is */
		total = build_outer(outer, n, 40000, 6001, PT_DATA, 0, sid, tok,
				    0);
		memcpy(outer + 36, plain, n);
		CHECK(iwan_win_outer_parse4(outer, total, &o),
		      "plaintext frame failed to parse (len=%zu)", n);
		memset(out, 0xA5, sizeof(out));
		got = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
		CHECK(got == n, "plaintext decap length wrong (len=%zu got=%zu)", n, got);
		CHECK(memcmp(out, plain, n) == 0, "plaintext decap result mismatch (len=%zu)",
		      n);

		/* Output buffer too small: must reject rather than write a truncated result */
		CHECK(iwan_win_decap(outer, total, &o, key, out,
				     (ULONG)(n - 1)) == 0,
		      "must reject when the output buffer is too small (len=%zu)", n);
	}
}

/* ---- 5c. The out parameter on failure paths must be written to a defined value -------------------
 *
 * The four parse functions (outer_parse4 / outer_parse6 / dgram_parse / decap) do not promise to fill out on
 * failure - callers should not read it. But "not promised" and "stack garbage" are indistinguishable to
 * static analysis, and the real hazard is: if a caller still reads some field of out after failure (e.g.
 * inner_len to compute a length), it will use data from the previous packet.
 * Here out is pre-filled with 0xCD and fed all kinds of bad packets; the functions must **either fail
 * without touching the semantic fields of out, or fail and clear them to 0** - currently the latter.
 */
static void
test_parse_failure_clears_out(void)
{
	uint8_t shortpkt[8];
	uint8_t badver[60];
	IWAN_WIN_OUTER o;
	uint8_t out[64];
	const uint8_t key[8] = { 0 };

	memset(shortpkt, 0x00, sizeof(shortpkt));
	memset(badver, 0x00, sizeof(badver));
	badver[0] = 0x65;	/* a version-6 packet fed to the v4 parser */

	/* v4 parse: too short / wrong version */
	memset(&o, 0xCD, sizeof(o));
	CHECK(!iwan_win_outer_parse4(shortpkt, sizeof(shortpkt), &o),
	      "8-byte packet must not be accepted as a valid outer v4");
	CHECK(o.inner_len == 0 && o.inner_off == 0 && o.frame_len == 0,
	      "offset fields of out must be cleared after failure (inner_len=%u frame_len=%u)",
	      o.inner_len, o.frame_len);

	memset(&o, 0xCD, sizeof(o));
	CHECK(!iwan_win_outer_parse4(badver, sizeof(badver), &o),
	      "version-6 packet must not be accepted by the v4 parser");
	CHECK(o.inner_len == 0 && o.type == 0 && o.enc == 0,
	      "type fields of out must be cleared after failure");

	/* Raw datagram parse: too short */
	memset(&o, 0xCD, sizeof(o));
	CHECK(!iwan_win_dgram_parse(shortpkt, sizeof(shortpkt), &o),
	      "8-byte raw packet must not be accepted");
	CHECK(o.inner_len == 0 && o.frame_off == 0,
	      "offset fields of out must be cleared after raw datagram parse failure");

	/* Decap: output buffer too small / invalid context */
	memset(out, 0xCD, sizeof(out));
	o.inner_len = 4;
	o.inner_off = 0;
	o.enc = 0;
	CHECK(iwan_win_decap(shortpkt, sizeof(shortpkt), &o, key, out, 3) == 0,
	      "outsz smaller than inner_len must reject");
	CHECK(out[0] == 0xCD, "rejected decap must not write the output buffer");

	memset(&o, 0, sizeof(o));
	CHECK(iwan_win_decap(shortpkt, sizeof(shortpkt), &o, key, out,
			     sizeof(out)) == 0,
	      "zero inner_len must reject");
}

/* ---- 5d. Both parsers must yield identical fields for the same stream ----------------- */

static void
test_parse4_vs_dgram_agree(void)
{
	uint8_t outer[600];
	uint8_t payload[100];
	IWAN_WIN_OUTER a, b;
	size_t total, i;

	for (i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)(i ^ 0x5A);

	/* build_outer builds a complete IPv4+UDP outer header; for input that "still carries an IP header"
	 * dgram_parse should resolve exactly the same fields as outer_parse4. The two inbound paths (protocol
	 * edge / WFP plane) use one each, and the fields must be equal item by item, otherwise the same packet
	 * would resolve to different inner boundaries on the two paths. */
	total = build_outer(outer, sizeof(payload), 40000, 6001, PT_DATA, 0,
			    0x1234, 0x12345678, 0);
	memcpy(outer + 36, payload, sizeof(payload));

	CHECK(iwan_win_outer_parse4(outer, total, &a), "v4 parse failed");
	CHECK(iwan_win_dgram_parse(outer, total, &b), "dgram parse failed");
	CHECK(a.frame_off == b.frame_off && a.frame_len == b.frame_len &&
	      a.inner_off == b.inner_off && a.inner_len == b.inner_len,
	      "the two parsers disagree on offsets (%u/%u/%u/%u vs %u/%u/%u/%u)",
	      a.frame_off, a.frame_len, a.inner_off, a.inner_len,
	      b.frame_off, b.frame_len, b.inner_off, b.inner_len);
	CHECK(a.type == b.type && a.enc == b.enc && a.sid == b.sid &&
	      a.tok == b.tok,
	      "the two parsers disagree on frame header fields");
	CHECK(a.inner_len == sizeof(payload), "inner length should be %zu (got %u)",
	      sizeof(payload), a.inner_len);
}

/* ---- 6. Cross-check with the user-space send side: frames built by pkt_hdr()/xor_crypt() fed to the driver parser --- */

static void
test_inbound_crosscheck(void)
{
	const uint8_t key[8] = { 0x9a, 0x77, 0x01, 0xff, 0x40, 0x22, 0xbe, 0xef };
	uint16_t sid = 0x4a1b;
	uint32_t tok = 0x0badc0de;
	uint8_t inner[48], outer[256], out[128], enc[48];
	IWAN_WIN_OUTER o;
	uint8_t hdr[8];
	size_t total, n;

	memset(inner, 0, sizeof(inner));
	inner[0] = 0x45;
	inner[3] = (uint8_t)sizeof(inner);
	inner[9] = 17;
	inner[13] = 1; inner[15] = 9;
	inner[17] = 2; inner[19] = 9;
	for (size_t i = 20; i < sizeof(inner); i++)
		inner[i] = (uint8_t)(i * 13 + 5);

	/* This is exactly what the user-space send side does: pkt_hdr() builds the header, xor_crypt() encrypts the payload */
	pkt_hdr(PT_DATA_ENC, 1, sid, tok, hdr);
	memcpy(enc, inner, sizeof(inner));
	xor_crypt(enc, sizeof(enc), key, 8);

	total = build_outer(outer, sizeof(inner), 40000, 6001, PT_DATA_ENC, 1,
			    sid, tok, 0);
	memcpy(outer + 28, hdr, 8);          /* overwrite with the user-space frame header */
	memcpy(outer + 36, enc, sizeof(enc));

	CHECK(memcmp(outer + 28, hdr, 8) == 0, "frame header write-back failed");
	CHECK(iwan_win_outer_parse4(outer, total, &o), "user-space built frame failed to parse");
	CHECK(iwan_win_frame_classify(&o, sid, tok, TRUE, TRUE) ==
	      IWAN_WIN_FRAME_DATA, "user-space built data frame should classify as DATA");
	n = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
	CHECK(n == sizeof(inner), "decap length differs from the user-space send length");
	CHECK(memcmp(out, inner, sizeof(inner)) == 0,
	      "decap result differs from the plaintext before user-space encryption");
}


/* ---- 7. Outbound outer header construction (v4/v6) and v6 target decision ------------- */

/* An independent checksum implementation (not reused from the code under test), to cross-check the outer header checksums */
static uint32_t
t_sum(const uint8_t *p, size_t n, uint32_t sum)
{
	for (size_t i = 0; i + 1 < n; i += 2)
		sum += ((uint32_t)p[i] << 8) | p[i + 1];
	if (n & 1)
		sum += (uint32_t)p[n - 1] << 8;
	return sum;
}

static uint16_t
t_fin(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return (uint16_t)(~sum & 0xFFFF);
}

static void
test_outer_build4(void)
{
	const uint8_t key[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
	uint8_t frame[8 + 40], outer[256], out[128];
	uint32_t src = 0x0a000002, dst = 0xca26406a;   /* 10.0.0.2 -> 202.38.64.106 */
	IWAN_WIN_OUTER o;
	uint16_t sport = 0x9c40, dport = 0x1771;       /* 40000 -> 6001 */
	size_t flen = 8 + 40, total, n;

	for (size_t i = 0; i < 40; i++)
		frame[8 + i] = (uint8_t)(i * 7 + 1);
	iwan_win_build_frame_hdr(frame, PT_DATA, 0, 0x030c, 0xdeadbeef);

	total = iwan_win_outer_build4(outer, sizeof(outer), frame, flen, src, dst,
				      sport, dport);
	CHECK(total == 36 - 8 + flen, "v4 outer total length wrong");
	CHECK(outer[0] == 0x45, "v4 version/header length wrong");
	CHECK(outer[8] == 64, "v4 ttl should be 64");
	CHECK(outer[9] == 17, "v4 protocol should be UDP");
	CHECK((outer[6] << 8 | outer[7]) == 0x4000, "v4 should set DF");
	CHECK(memcmp(outer + 12, "\x0a\x00\x00\x02", 4) == 0, "v4 source address wrong");
	CHECK(memcmp(outer + 16, "\xca\x26\x40\x6a", 4) == 0, "v4 destination address wrong");
	CHECK(memcmp(outer + 20, "\x9c\x40\x17\x71", 4) == 0, "v4 UDP ports wrong");
	CHECK((size_t)((outer[24] << 8) | outer[25]) == 8 + flen,
	      "v4 UDP length wrong");

	/* Independently verify the IP header checksum */
	{
		uint32_t sum = 0;

		for (size_t i = 0; i < 20; i += 2)
			sum += ((uint32_t)outer[i] << 8) | outer[i + 1];
		CHECK(t_fin(sum) == 0, "v4 header checksum self-check should be 0");
	}

	/* Independently verify the UDP checksum (pseudo-header + UDP header + payload) */
	{
		uint32_t sum = 0;

		sum = t_sum(outer + 12, 8, sum);
		sum = t_sum((const uint8_t *)"\x00\x11", 2, sum);
		sum = t_sum(outer + 24, 2, sum);
		sum = t_sum(outer + 20, 8 + flen, sum);
		CHECK(t_fin(sum) == 0, "v4 UDP checksum (incl. pseudo-header) should be 0");
		CHECK(((outer[26] << 8) | outer[27]) != 0 ||
		      ((outer[26] << 8) | outer[27]) == 0xFFFF,
		      "v4 UDP checksum must not be 0 (0 means no checksum)");
	}

	/* Cross-check with inbound parse: build -> parse -> decap */
	CHECK(iwan_win_outer_parse4(outer, total, &o), "constructed v4 outer failed to parse");
	CHECK(o.inner_off == 36 && o.inner_len == 40, "v4 inner offset/length wrong");
	CHECK(iwan_win_frame_classify(&o, 0x030c, 0xdeadbeef, FALSE, TRUE) ==
	      IWAN_WIN_FRAME_DATA, "constructed plaintext frame should classify as DATA");
	n = iwan_win_decap(outer, total, &o, key, out, sizeof(out));
	CHECK(n == 40 && memcmp(out, frame + 8, 40) == 0, "v4 decap differs from payload");
}

static void
test_outer_build6(void)
{
	uint8_t frame[8 + 40], outer[256], out[128];
	static const uint8_t src6[16] = { 0x20, 0x01, 0xda, 0x08, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 2 };
	static const uint8_t dst6[16] = { 0x20, 0x01, 0xda, 0x08, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 9 };
	uint16_t sport = 0x9c40, dport = 0x1771;
	size_t flen = 8 + 40, total, n;
	IWAN_WIN_OUTER o;

	for (size_t i = 0; i < 40; i++)
		frame[8 + i] = (uint8_t)(0xa0 - i);
	iwan_win_build_frame_hdr(frame, PT_DATA, 0, 0x030c, 0xdeadbeef);

	total = iwan_win_outer_build6(outer, sizeof(outer), frame, flen, src6, dst6,
				      sport, dport);
	CHECK(total == 56 - 8 + flen, "v6 outer total length wrong");
	CHECK((outer[0] >> 4) == 6, "v6 version wrong");
	CHECK((outer[0] & 0x0F) == 0 && outer[1] == 0 && outer[2] == 0 &&
	      outer[3] == 0, "v6 traffic class / flow label should be 0");
	CHECK(outer[6] == 17, "v6 nexthdr should be UDP (no extension header)");
	CHECK(outer[7] == 64, "v6 hop limit should be 64");
	CHECK((size_t)((outer[4] << 8) | outer[5]) == 8 + flen,
	      "v6 payload_len wrong");
	CHECK(memcmp(outer + 8, src6, 16) == 0 && memcmp(outer + 24, dst6, 16) == 0,
	      "v6 addresses wrong");
	CHECK(memcmp(outer + 40, "\x9c\x40\x17\x71", 4) == 0, "v6 UDP ports wrong");
	CHECK((size_t)((outer[44] << 8) | outer[45]) == 8 + flen,
	      "v6 UDP length wrong");

	/* Independently verify the UDP checksum: v6 pseudo-header = 16B source + 16B destination + 4B length + 3B zero
	 * + 1B next header. RFC 8200 mandates non-zero. */
	{
		uint32_t sum = 0;
		uint8_t tail[4] = { 0, 0, 0, 17 };
		uint8_t ulen[4] = { 0, 0, 0, 0 };
		uint16_t ul = (uint16_t)(8 + flen);

		ulen[2] = (uint8_t)(ul >> 8);
		ulen[3] = (uint8_t)ul;
		sum = t_sum(src6, 16, sum);
		sum = t_sum(dst6, 16, sum);
		sum = t_sum(ulen, 4, sum);
		sum = t_sum(tail, 4, sum);
		sum = t_sum(outer + 40, 8 + flen, sum);
		CHECK(t_fin(sum) == 0, "v6 UDP checksum (incl. v6 pseudo-header) should be 0");
		CHECK(((outer[46] << 8) | outer[47]) != 0,
		      "v6 UDP checksum must not be 0 (mandated by RFC 8200)");
	}

	/* build -> parse -> decap (v6 outer carrying v6 inner) */
	CHECK(iwan_win_outer_parse6(outer, total, &o), "constructed v6 outer failed to parse");
	CHECK(o.inner_off == 56 && o.inner_len == 40, "v6 inner offset/length wrong");
	CHECK(iwan_win_frame_classify(&o, 0x030c, 0xdeadbeef, FALSE, TRUE) ==
	      IWAN_WIN_FRAME_DATA, "plaintext frame in a v6 outer should classify as DATA");
	n = iwan_win_decap(outer, total, &o, NULL, out, sizeof(out));
	CHECK(n == 40 && memcmp(out, frame + 8, 40) == 0, "v6 decap differs from payload");

	/* Invalid structure: truncation / extension header / non-UDP */
	CHECK(!iwan_win_outer_parse6(outer, 40, &o), "truncated v6 packet must not be parsed");
	{
		uint8_t save = outer[6];

		outer[6] = 0;                  /* hop-by-hop extension header */
		CHECK(!iwan_win_outer_parse6(outer, total, &o),
		      "v6 outer with an extension header must not be parsed");
		outer[6] = 6;                  /* TCP */
		CHECK(!iwan_win_outer_parse6(outer, total, &o),
		      "non-UDP v6 outer must not be parsed");
		outer[6] = save;
	}
}

static void
test_should_tunnel6(void)
{
	static const uint8_t outer6[16] = { 0x20, 0x01, 0xda, 0x08, 0, 0, 0, 0,
					    0, 0, 0, 0, 0, 0, 0, 9 };
	IWAN_WIN_TARGET t[3];
	static const uint8_t campus[16] = { 0x20, 0x01, 0xda, 0x08, 0x02, 0x00, 0, 0,
					    0, 0, 0, 0, 0, 0, 0, 0 };

	memset(t, 0, sizeof(t));
	t[0].family = IWAN_WIN_AF_V6;
	t[0].prefix_len = 32;                  /* 2001:da8::/32 */
	memcpy(t[0].addr, campus, 16);
	t[1].family = IWAN_WIN_AF_V6;
	t[1].prefix_len = 48;                  /* 2001:da8:2::/48 */
	t[1].addr[0] = 0x20; t[1].addr[1] = 0x01; t[1].addr[2] = 0xda;
	t[1].addr[3] = 0x08; t[1].addr[4] = 0x02;
	t[2].family = IWAN_WIN_AF_V4;          /* v4 entry has no effect on v6 decisions */
	t[2].prefix_len = 0;

	{
		static const uint8_t in6[16] = { 0x20, 0x01, 0xda, 0x08, 0x02, 0x00,
						 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
		static const uint8_t other[16] = { 0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0,
						   0, 0, 0, 0, 0, 0, 0, 1 };

		CHECK(iwan_win_should_tunnel6(t, 3, outer6, in6),
		      "campus v6 address should enter the tunnel");
		CHECK(!iwan_win_should_tunnel6(t, 3, outer6, other),
		      "v6 address outside the set must not enter the tunnel");
		CHECK(!iwan_win_should_tunnel6(t, 3, outer6, outer6),
		      "outer server address never enters the tunnel");
	}
	CHECK(!iwan_win_should_tunnel6(NULL, 0, outer6, outer6),
	      "empty target set must not enter the tunnel");
}

/*
 * Reassembled datagram form (inbound callout at INBOUND_TRANSPORT_V4/V6):
 * the UDP header is at the packet start, the IP header has been stripped by the stack. The same bytes in both
 * the "raw datagram" and the "still carrying an IP header" form must parse to the same result.
 */
static void
test_dgram_parse(void)
{
	const uint8_t key[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t inner[64], outer[256], out[128];
	IWAN_WIN_OUTER o;
	size_t total, n;
	uint16_t sid = 0x030c;
	uint32_t tok = 0xdeadbeef;

	memset(inner, 0, sizeof(inner));
	inner[0] = 0x45;
	inner[2] = 0; inner[3] = 32;
	inner[8] = 64;
	inner[9] = 17;
	inner[12] = 10; inner[13] = 0; inner[14] = 0; inner[15] = 1;
	inner[16] = 10; inner[17] = 0; inner[18] = 0; inner[19] = 2;
	inner[20] = 0x9c; inner[21] = 0x41;
	inner[22] = 0x27; inner[23] = 0x0f;
	inner[24] = 0; inner[25] = 12;
	inner[28] = 'i'; inner[29] = 'w'; inner[30] = 'a'; inner[31] = 'n';

	/* Raw datagram: this is exactly what the stack hands up after reassembly. The encrypted frame's payload
	 * must be XORed first and then placed in (on the wire it is ciphertext; only decap yields plaintext). */
	{
		uint8_t enc_inner[64];

		memcpy(enc_inner, inner, 32);
		xor_crypt(enc_inner, 32, key, 8);
		total = build_outer(outer, 32, 40000, 6001, PT_DATA_ENC, 1, sid, tok, 0);
		memcpy(outer + 36, enc_inner, 32);
	}
	CHECK(iwan_win_dgram_parse(outer + 20, total - 20, &o),
	      "raw datagram form failed to parse");
	CHECK(o.sport == 40000 && o.dport == 6001, "outer port parse wrong");
	CHECK(o.frame_off == 8 && o.inner_off == 16 && o.inner_len == 32,
	      "raw datagram offset/length miscalculated");
	CHECK(o.type == PT_DATA_ENC && o.enc == 1 && o.sid == sid && o.tok == tok,
	      "raw datagram frame header fields out of place");
	n = iwan_win_decap(outer + 20, total - 20, &o, key, out, sizeof(out));
	CHECK(n == 32 && memcmp(out, inner, 32) == 0, "raw datagram decap result mismatch");
	CHECK(iwan_win_frame_classify(&o, sid, tok, TRUE, TRUE) ==
	      IWAN_WIN_FRAME_DATA, "raw datagram should classify as DATA");

	/* Still carrying the IP header: all offsets shift by 20, all other conclusions must agree */
	total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0);
	memcpy(outer + 36, inner, 32);
	CHECK(iwan_win_dgram_parse(outer, total, &o), "IP-header form failed to parse");
	CHECK(o.sport == 40000 && o.dport == 6001 && o.frame_off == 28 &&
	      o.inner_off == 36 && o.inner_len == 32 && o.enc == 0,
	      "offsets/ports with IP header miscalculated");

	/* IP header present but fragment bit non-zero: wrong form, reject (this layer must only ever see reassembled packets) */
	total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0x2000);
	CHECK(!iwan_win_dgram_parse(outer, total, &o),
	      "packet with a fragment bit must not be parsed as a complete datagram");

	/* Raw datagram + source port high nibble looking like a version: must fall back to raw parsing */
	total = build_outer(outer, 32, 0x4a12, 6001, PT_DATA, 0, sid, tok, 0);
	memcpy(outer + 36, inner, 32);
	CHECK(iwan_win_dgram_parse(outer + 20, total - 20, &o),
	      "fallback failed when the source port high nibble looks like a version");
	CHECK(o.sport == 0x4a12 && o.frame_off == 8 && o.inner_len == 32,
	      "offset/length after fallback wrong");

	/* UDP length lies (larger than actual): fall back to the actual length */
	total = build_outer(outer, 32, 40000, 6001, PT_DATA, 0, sid, tok, 0);
	memcpy(outer + 36, inner, 32);
	outer[20 + 4] = 0xff; outer[20 + 5] = 0xff;
	CHECK(iwan_win_dgram_parse(outer + 20, total - 20, &o),
	      "lying UDP length should parse via fallback");
	CHECK(o.inner_len == 32, "inner length after fallback is wrong");

	/* Rejection paths */
	CHECK(!iwan_win_dgram_parse(outer + 20, 8, &o), "UDP header alone must not parse");
	CHECK(!iwan_win_dgram_parse(outer + 20, 0, &o), "empty packet must not parse");
	{
		uint8_t only_hdr[16];

		memset(only_hdr, 0, sizeof(only_hdr));
		only_hdr[0] = 0x9c; only_hdr[1] = 0x40;	/* sport = 40000 */
		only_hdr[4] = 0; only_hdr[5] = 16;	/* ulen = 16 = UDP header + frame header */
		CHECK(!iwan_win_dgram_parse(only_hdr, sizeof(only_hdr), &o),
		      "zero-length inner must not parse");
	}
}

/*
 * Golden vector for the wire-test harness: the 57-byte outer datagram built by tests/win_wire_peer.py
 * (8-byte UDP header + 8-byte frame header + 41-byte inner packet), fed as-is to the driver-side parse,
 * classification and decap. The host peer script is "the other half of the verification"; once it disagrees
 * with the driver, the field symptom is just a guest-side counter that does not move, hard to chase; freezing
 * its output as a golden vector lets a host build catch a script that breaks the wire format (no guest needed).
 *
 * 41-byte inner = IPv4(20) + UDP(8) + "IWAN-INNER-OK"(13),
 * port pair 40001 -> 9999, inner destination 10.0.2.15.
 */
static void
test_wire_harness_golden(void)
{
	const uint8_t key[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	const uint8_t good[57] = {
		0xb2, 0x6e, 0x9e, 0xd4, 0x00, 0x39, 0x00, 0x00,
		0x18, 0x01, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
		0x44, 0x02, 0x03, 0x2d, 0x05, 0x06, 0x07, 0x08,
		0x41, 0x13, 0x67, 0x56, 0x0f, 0x65, 0x07, 0x09,
		0x0b, 0x02, 0x01, 0x0b, 0x99, 0x47, 0x20, 0x07,
		0x01, 0x17, 0x03, 0x04, 0x4c, 0x51, 0x46, 0x46,
		0x2c, 0x4b, 0x4d, 0x4a, 0x40, 0x54, 0x2a, 0x47,
		0x4a,
	};
	const uint8_t bad[57] = {
		0xb2, 0x6e, 0x9e, 0xd4, 0x00, 0x39, 0x00, 0x00,
		0x18, 0x01, 0x12, 0x34, 0x12, 0x34, 0x56, 0x79,
		0x44, 0x02, 0x03, 0x2d, 0x05, 0x06, 0x07, 0x08,
		0x41, 0x13, 0x67, 0x56, 0x0f, 0x65, 0x07, 0x09,
		0x0b, 0x02, 0x01, 0x0b, 0x99, 0x47, 0x20, 0x07,
		0x01, 0x17, 0x03, 0x04, 0x4c, 0x51, 0x46, 0x46,
		0x2c, 0x4b, 0x4d, 0x4a, 0x40, 0x54, 0x2a, 0x47,
		0x4a,
	};
	IWAN_WIN_OUTER o;
	uint8_t out[64];
	ULONG n;

	CHECK(iwan_win_dgram_parse(good, sizeof(good), &o), "wire-test normal frame failed to parse");
	CHECK(o.sport == 45678 && o.dport == 40660,
	      "outer ports do not match (script writes big-endian bytes, driver compares big-endian integers)");
	CHECK(o.frame_off == 8 && o.inner_off == 16 && o.inner_len == 41,
	      "frame/inner offset or length mismatch");
	CHECK(o.type == PT_DATA_ENC && o.enc == 1 && o.sid == 0x1234 &&
	      o.tok == 0x12345678, "frame header fields differ from the script");
	CHECK(iwan_win_frame_classify(&o, 0x1234, 0x12345678, TRUE, TRUE) ==
	      IWAN_WIN_FRAME_DATA, "wire-test normal frame should classify as a data frame");

	n = iwan_win_decap(good, sizeof(good), &o, key, out, sizeof(out));
	CHECK(n == 41, "decap length should be 41 (got %lu)", (unsigned long)n);
	CHECK(out[0] == 0x45 && out[9] == 17, "decapped inner is not IPv4/UDP");
	CHECK(out[16] == 10 && out[17] == 0 && out[18] == 2 && out[19] == 15,
	      "decapped inner destination address is not 10.0.2.15");
	CHECK(out[22] == 0x27 && out[23] == 0x0f, "decapped inner destination port is not 9999");
	CHECK(memcmp(out + 28, "IWAN-INNER-OK", 13) == 0,
	      "decapped payload is not IWAN-INNER-OK");
	CHECK(sum16(out, 20) == 0xFFFF, "decapped inner IP checksum invalid (script computed it wrong)");

	CHECK(iwan_win_dgram_parse(bad, sizeof(bad), &o),
	      "bad-credential sample is structurally valid and should parse");
	CHECK(iwan_win_frame_classify(&o, 0x1234, 0x12345678, TRUE, TRUE) ==
	      IWAN_WIN_FRAME_BAD, "frame with a mismatched token must classify as BAD");
}

/* ---- 16. Inner IPv4 fragmentation: aligned with Linux stack fragmentation ------------- */

static uint16_t
mk_pkt4(uint8_t *pkt, size_t len, uint8_t ihl_words, uint16_t frag_off)
{
	size_t ihl = (size_t)ihl_words * 4;
	size_t i;

	memset(pkt, 0, len);
	pkt[0] = (uint8_t)(0x40 | ihl_words);
	pkt[2] = (uint8_t)(len >> 8);
	pkt[3] = (uint8_t)len;
	pkt[4] = 0x12;
	pkt[5] = 0x34;
	pkt[6] = (uint8_t)(frag_off >> 8);
	pkt[7] = (uint8_t)frag_off;
	pkt[8] = 64;
	pkt[9] = 17;
	pkt[12] = 10;
	pkt[15] = 1;
	pkt[16] = 10;
	pkt[19] = 2;
	for (i = ihl; i < len; i++)
		pkt[i] = (uint8_t)(i * 7u + 3u);
	return (uint16_t)ihl;
}

static void
test_frag4(void)
{
	uint8_t pkt[3000], frag[3000], joined[3000];
	ULONG out_len, n, i, off, total;
	uint16_t ihl;
	int ok;

	/* Short packet is not fragmented */
	ihl = mk_pkt4(pkt, 1200, 5, 0);
	CHECK(iwan_win_frag4_count(pkt, 1200, 1380) == 0,
	      "1200 bytes fit in 1380, must not fragment (ihl=%u)", (unsigned)ihl);
	CHECK(iwan_win_frag4_build(frag, sizeof(frag), pkt, 1200, 1380, 0,
				   &out_len) == TRUE &&
	      out_len == 1200, "even idx=0 should build the packet as-is when not fragmenting");
	/* build always recomputes the header checksum and normalizes flags/offset (the synthetic sample's checksum
	 * was originally 0), so "no fragmentation" only guarantees a byte-identical payload and a self-consistent header. */
	CHECK(memcmp(frag + 20, pkt + 20, 1180) == 0,
	      "payload must be byte-identical when not fragmenting");
	CHECK(sum16(frag, 20) == 0xFFFF, "header checksum must also be self-consistent when not fragmenting");

	/* 3000 bytes / mtu 1380: payload 2980, per-fragment payload 1360 => 3 fragments */
	ihl = mk_pkt4(pkt, 3000, 5, 0);
	n = iwan_win_frag4_count(pkt, 3000, 1380);
	CHECK(n == 3, "3000/mtu1380 should be 3 fragments (got %u)", (unsigned)n);

	total = 0;
	for (i = 0; i < n; i++) {
		uint32_t want;
		uint16_t fo;

		ok = iwan_win_frag4_build(frag, sizeof(frag), pkt, 3000, 1380,
					  i, &out_len);
		CHECK(ok == TRUE, "fragment %u failed to build", (unsigned)i);
		if (!ok)
			return;
		off = i * 1360u;
		want = (2980u - off > 1360u) ? 1380u : (20u + (2980u - off));
		CHECK(out_len == want, "fragment %u length should be %u (got %u)",
		      (unsigned)i, (unsigned)want, (unsigned)out_len);
		CHECK(sum16(frag, 20) == 0xFFFF,
		      "fragment %u has an invalid IP header checksum (sum=%04x)", (unsigned)i,
		      (unsigned)sum16(frag, 20));
		fo = iwan_win_rd16(frag + 6);
		CHECK((fo & 0x4000) == 0, "fragment %u must clear DF", (unsigned)i);
		CHECK((fo & 0x1FFF) == (off / 8),
		      "fragment %u offset field should be %u (got %u)", (unsigned)i,
		      (unsigned)(off / 8), (unsigned)(fo & 0x1FFF));
		CHECK(((fo & 0x2000) != 0) == (off + 1360u < 2980u),
		      "fragment %u MF inconsistent with whether more fragments follow", (unsigned)i);
		CHECK(iwan_win_rd16(frag + 2) == out_len,
		      "fragment %u IP total length field inconsistent with actual length", (unsigned)i);
		memcpy(joined + total, frag + 20, out_len - 20);
		total += out_len - 20;
	}
	CHECK(total == 2980, "total fragment payload should be 2980 (got %u)", (unsigned)total);
	CHECK(memcmp(joined, pkt + 20, 2980) == 0,
	      "reassembled fragment payload must be byte-identical to the original packet");

	/* Boundaries and invalid inputs */
	CHECK(iwan_win_frag4_count(pkt, 3000, 24) == 0,
	      "mtu=24 cannot fit even 8 payload bytes, fragmentation must be rejected");
	pkt[0] = 0x65;
	CHECK(iwan_win_frag4_count(pkt, 3000, 1380) == 0, "non-v4 is not fragmented");
	pkt[0] = 0x45;
	CHECK(iwan_win_frag4_build(frag, sizeof(frag), pkt, 3000, 1380, 3,
				   &out_len) == FALSE, "out-of-range fragment index must be rejected");
	CHECK(iwan_win_frag4_build(frag, 40, pkt, 3000, 1380, 0, &out_len) ==
	      FALSE, "insufficient buffer must be rejected");

	/* ihl=24 (with options): fragment payload must be a multiple of 8 => (1380-24)&~7 = 1352 */
	ihl = mk_pkt4(pkt, 1400, 6, 0);
	CHECK(ihl == 24, "constructed ihl should be 24");
	n = iwan_win_frag4_count(pkt, 1400, 1380);
	CHECK(n == 2, "ihl=24, 1400 bytes should be 2 fragments (got %u)", (unsigned)n);
	ok = iwan_win_frag4_build(frag, sizeof(frag), pkt, 1400, 1380, 0,
				  &out_len);
	CHECK(ok == TRUE && out_len == 24 + 1352,
	      "first fragment with ihl=24 should be 1376 bytes (got %u)", (unsigned)out_len);
	CHECK(sum16(frag, 24) == 0xFFFF, "first fragment with ihl=24 has an invalid checksum");

	/* Large packet with DF set by the source: after the driver fragments it DF must be cleared, otherwise the receiver rejects middle fragments */
	mk_pkt4(pkt, 2000, 5, 0x4000);
	CHECK((iwan_win_rd16(pkt + 6) & 0x4000) != 0, "constructed sample should carry DF");
	ok = iwan_win_frag4_build(frag, sizeof(frag), pkt, 2000, 1380, 0,
				  &out_len);
	CHECK(ok == TRUE, "large packet with DF should also be fragmentable");
	CHECK((iwan_win_rd16(frag + 6) & 0x4000) == 0, "DF must be cleared after fragmentation");
	CHECK((iwan_win_rd16(frag + 6) & 0x2000) != 0, "first fragment must set MF");
	CHECK(iwan_win_rd16(frag + 4) == 0x1234, "IP ID must be preserved");
}

/* ---- 17. Outer fragment reassembly: aligned with Linux ip_defrag --------------------- */

static size_t
mk_ofrag4(uint8_t *pkt, uint32_t src, uint32_t dst, uint16_t id,
	  size_t byte_off, int more, const uint8_t *pl, size_t plen)
{
	uint16_t fr = (uint16_t)((byte_off / 8u) & 0x1FFFu);

	if (more)
		fr |= 0x2000u;
	memset(pkt, 0, 20 + plen);
	pkt[0] = 0x45;
	pkt[2] = (uint8_t)((20 + plen) >> 8);
	pkt[3] = (uint8_t)(20 + plen);
	pkt[4] = (uint8_t)(id >> 8);
	pkt[5] = (uint8_t)id;
	pkt[6] = (uint8_t)(fr >> 8);
	pkt[7] = (uint8_t)fr;
	pkt[8] = 64;
	pkt[9] = 17;
	pkt[12] = (uint8_t)(src >> 24);
	pkt[13] = (uint8_t)(src >> 16);
	pkt[14] = (uint8_t)(src >> 8);
	pkt[15] = (uint8_t)src;
	pkt[16] = (uint8_t)(dst >> 24);
	pkt[17] = (uint8_t)(dst >> 16);
	pkt[18] = (uint8_t)(dst >> 8);
	pkt[19] = (uint8_t)dst;
	if (plen != 0)
		memcpy(pkt + 20, pl, plen);
	return 20 + plen;
}

static void
test_frag_reasm(void)
{
	static IWAN_WIN_FRAG_SLOT slots[IWAN_WIN_FRAG_SLOTS];
	const uint32_t SRC = 0x0a000202u, DST = 0x0a00020fu;
	uint8_t dat[3000], pkt[4096];
	size_t i, len;
	ULONG idx = 0, out_len = 0;
	int r;

	/* Fragment offset is in 8-byte units, so fragment lengths must be multiples of 8 (except the last):
	 * 3000 = 1384 + 1384 + 232. */
	for (i = 0; i < sizeof(dat); i++)
		dat[i] = (uint8_t)(i * 11u + 5u);
	memset(slots, 0, sizeof(slots));

	/* Non-fragment: PASS, occupies no slot */
	len = mk_ofrag4(pkt, SRC, DST, 7, 0, 0, dat, 200);
	r = iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt, (ULONG)len,
				1000, 2000, &idx, &out_len);
	CHECK(r == IWAN_WIN_FRAG_PASS, "non-fragment should PASS (got %d)", r);

	/* Out-of-order arrival: last fragment, first fragment, middle fragment */
	len = mk_ofrag4(pkt, SRC, DST, 0x4242, 2768, 0, dat + 2768, 232);
	r = iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt, (ULONG)len,
				1000, 2000, &idx, &out_len);
	CHECK(r == IWAN_WIN_FRAG_STORED, "last fragment arriving first should be stored (got %d)", r);
	len = mk_ofrag4(pkt, SRC, DST, 0x4242, 0, 1, dat, 1384);
	r = iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt, (ULONG)len,
				1001, 2000, &idx, &out_len);
	CHECK(r == IWAN_WIN_FRAG_STORED, "should store while the middle fragment is still missing (got %d)", r);
	len = mk_ofrag4(pkt, SRC, DST, 0x4242, 1384, 1, dat + 1384, 1384);
	r = iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt, (ULONG)len,
				1002, 2000, &idx, &out_len);
	CHECK(r == IWAN_WIN_FRAG_DONE, "all three fragments present should complete (got %d)", r);
	CHECK(out_len == 3000, "reassembled length should be 3000 (got %u)", (unsigned)out_len);
	CHECK(idx < IWAN_WIN_FRAG_SLOTS &&
	      memcmp(slots[idx].buf, dat, 3000) == 0,
	      "reassembled content must be byte-identical to the original datagram");
	slots[idx].used = FALSE;

	/* Overlapping fragments: the same range arriving twice is counted once and does not affect completion */
	memset(slots, 0, sizeof(slots));
	len = mk_ofrag4(pkt, SRC, DST, 0x5151, 0, 1, dat, 1384);
	(void)iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt, (ULONG)len,
				  2000, 2000, &idx, &out_len);
	(void)iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt, (ULONG)len,
				  2001, 2000, &idx, &out_len);
	CHECK(slots[0].have == 1384u / 8u,
	      "overlapping fragments must not be counted twice (got %u blocks)", (unsigned)slots[0].have);
	len = mk_ofrag4(pkt, SRC, DST, 0x5151, 1384, 0, dat + 1384, 1616);
	r = iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt, (ULONG)len,
				2002, 2000, &idx, &out_len);
	CHECK(r == IWAN_WIN_FRAG_DONE && out_len == 3000,
	      "both fragments present should complete (r=%d len=%u)", r, (unsigned)out_len);
	slots[idx].used = FALSE;

	/* Contradictory length: the last fragment's total is shorter than the "content already received" => discard */
	memset(slots, 0, sizeof(slots));
	len = mk_ofrag4(pkt, SRC, DST, 0x6161, 0, 1, dat, 1384);
	(void)iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt, (ULONG)len,
				  3000, 2000, &idx, &out_len);
	len = mk_ofrag4(pkt, SRC, DST, 0x6161, 800, 0, dat + 800, 400);
	r = iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt, (ULONG)len,
				3001, 2000, &idx, &out_len);
	CHECK(r == IWAN_WIN_FRAG_DROP, "contradictory total length should drop (got %d)", r);
	CHECK(slots[0].used == FALSE, "slot must be released after a drop");

	/* Above the limit: a single datagram is at most 9216 bytes */
	memset(slots, 0, sizeof(slots));
	len = mk_ofrag4(pkt, SRC, DST, 0x7171, 8192, 1, dat, 2000);
	r = iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt, (ULONG)len,
				4000, 2000, &idx, &out_len);
	CHECK(r == IWAN_WIN_FRAG_DROP, "above the single-datagram limit should drop (got %d)", r);

	/* Expiry: the next fragment of the same identifier must start over (old content discarded) */
	memset(slots, 0, sizeof(slots));
	len = mk_ofrag4(pkt, SRC, DST, 0x8181, 0, 1, dat, 1384);
	(void)iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt, (ULONG)len,
				  5000, 1000, &idx, &out_len);
	len = mk_ofrag4(pkt, SRC, DST, 0x8181, 1384, 0, dat + 1384, 1616);
	r = iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt, (ULONG)len,
				7000, 1000, &idx, &out_len);
	CHECK(r == IWAN_WIN_FRAG_STORED, "should start over after expiry (got %d)", r);
	CHECK(slots[idx].have == 1616u / 8u,
	      "after expiry restart only the last fragment's blocks should exist (got %u)", (unsigned)slots[idx].have);

	/* Slots full: with 4 incomplete datagrams occupying the slots, a new identifier must be able to steal the oldest */
	memset(slots, 0, sizeof(slots));
	for (i = 0; i < IWAN_WIN_FRAG_SLOTS; i++) {
		len = mk_ofrag4(pkt, SRC, DST, (uint16_t)(0x9000u + i), 0, 1,
				dat, 1384);
		r = iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt,
					(ULONG)len, 8000 + (ULONG)i, 100000,
					&idx, &out_len);
		CHECK(r == IWAN_WIN_FRAG_STORED, "fragment %u should be stored (got %d)",
		      (unsigned)i, r);
	}
	len = mk_ofrag4(pkt, SRC, DST, 0xA0A0, 0, 1, dat, 1384);
	r = iwan_win_frag_input(slots, IWAN_WIN_FRAG_SLOTS, pkt, (ULONG)len,
				8100, 100000, &idx, &out_len);
	CHECK(r == IWAN_WIN_FRAG_STORED, "when slots are full the oldest should be stolen (got %d)", r);
}

int
main(void)
{
	test_frame_hdr();
	test_xor();
	test_csum();
	test_inner_fix_csum_keeps_addrs();
	test_frag4();
	test_frag_reasm();
	test_targets();
	test_wire_constants();
	test_inbound();
	test_decap_lengths();
	test_dgram_parse();
	test_inbound_crosscheck();
	test_outer_build4();
	test_outer_build6();
	test_should_tunnel6();
	test_wire_harness_golden();
	test_parse_failure_clears_out();
	test_parse4_vs_dgram_agree();

	printf("win_frame_test: %d passed, %d failed\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
