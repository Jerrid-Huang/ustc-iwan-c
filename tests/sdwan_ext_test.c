/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sdwan_ext_test.c -- pure-logic self-check of the Panabit SD-WAN extension plane (runs on Linux).
 *
 * Why this test exists: fragmentation (0x22/0x24), source routing (0x28), SR key derivation and
 * the 36-byte ECHO payload layout all come from reverse-engineering the official client
 * (docs/sdwan-protocol.md sections 7/8); any mistake shows up only as "the peer does not accept packets",
 * which cannot be debugged against the Linux server. Fixed vectors and hand-built packets pin them down here.
 *
 * Build:
 *   gcc -std=c11 -Wall -Wextra -Werror -Isrc/common \
 *       tests/sdwan_ext_test.c src/common/frag.c src/common/sr.c \
 *       src/common/protocol.c src/common/crypto.c src/common/util.c \
 *       src/common/buffer.c -lcrypto -o /tmp/sdwan_ext_test
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "frag.h"
#include "protocol.h"
#include "sr.h"
#include "echo.h"

static int g_fail;
static int g_pass;

#define CHECK(cond, msg) do {                                          \
        if (cond) {                                                    \
            g_pass++;                                                  \
        } else {                                                       \
            g_fail++;                                                  \
            printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);     \
        }                                                              \
    } while (0)

static void test_frag_hdr(void)
{
    struct iwan_frag_hdr h, g;
    uint8_t b[IWAN_FRAG_HDR_LEN];
    uint8_t dg[IWAN_FRAG_HDR_LEN + 600];

    memset(&h, 0, sizeof h);
    h.id = 0xdeadbeefu;
    h.eop = true;
    h.fromin = true;
    h.fragoff = 1400;
    h.fraglen = 600;
    frag_hdr_put(b, &h);
    /* id is host byte order */
    CHECK(b[0] == 0xef && b[1] == 0xbe && b[2] == 0xad && b[3] == 0xde,
          "frag id must be written in host byte order");

    memset(dg, 0, sizeof dg);
    memcpy(dg, b, sizeof b);
    CHECK(frag_hdr_get(dg, sizeof dg, &g), "valid fragment header must parse");
    CHECK(g.id == h.id && g.eop == h.eop && g.fromin == h.fromin &&
          g.fragoff == h.fragoff && g.fraglen == h.fraglen,
          "fragment header fields must round-trip");

    CHECK(!frag_hdr_get(dg, sizeof dg - 1, &g), "length mismatch with fraglen must be rejected");
    CHECK(!frag_hdr_get(b, IWAN_FRAG_HDR_LEN, &g), "empty payload must be rejected");

    h.fragoff = 4000;              /* 4000 + 600 > 4096: out of bounds */
    frag_hdr_put(b, &h);
    memcpy(dg, b, sizeof b);
    CHECK(!frag_hdr_get(dg, sizeof dg, &g), "crossing the reassembly buffer bound must be rejected");
}

static void test_frag_emit_and_reasm(void)
{
    uint8_t pkt[2000], d0[IWAN_FRAG_HDR_LEN + 2000], d1[IWAN_FRAG_HDR_LEN + 2000];
    const uint8_t *out;
    size_t n0, n1, outlen;
    bool last;
    struct iwan_frag_pool pool;

    for (size_t i = 0; i < sizeof pkt; i++)
        pkt[i] = (uint8_t)(i * 7 + 3);

    /* single fragment: whole packet fits */
    n0 = iwan_frag_emit(pkt, 1000, 1400, 42, 0, d0, sizeof d0, &last);
    CHECK(n0 == IWAN_FRAG_HDR_LEN + 1000 && last, "short packet should become one fragment with eop set");

    /* two fragments */
    {
        bool last0 = true, last1 = false;
        n0 = iwan_frag_emit(pkt, sizeof pkt, 1400, 42, 0, d0, sizeof d0, &last0);
        n1 = iwan_frag_emit(pkt, sizeof pkt, 1400, 42, 1, d1, sizeof d1, &last1);
        CHECK(n0 == IWAN_FRAG_HDR_LEN + 1400 && !last0,
              "first fragment must be 1400 bytes without eop");
        CHECK(n1 == IWAN_FRAG_HDR_LEN + 600 && last1,
              "last fragment must be 600 bytes with eop set");
    }
    CHECK(iwan_frag_emit(pkt, 3000, 1400, 42, 0, d0, sizeof d0, &last) == 0,
          "exceeding the two-fragment limit must return 0 (caller drops it)");

    /* out-of-order reassembly: last fragment arrives first, first arrives later */
    iwan_frag_pool_reset(&pool);
    CHECK(iwan_frag_in(&pool, 0x1234, 0x12345678u, d1, n1, 100, &out,
                       &outlen) == IWAN_FRAG_MORE,
          "with only the last fragment, wait");
    CHECK(iwan_frag_in(&pool, 0x1234, 0x12345678u, d0, n0, 101, &out,
                       &outlen) == IWAN_FRAG_DONE,
          "after the first fragment arrives, reassembly must complete");
    CHECK(outlen == sizeof pkt && memcmp(out, pkt, sizeof pkt) == 0,
          "reassembled result must match the original byte for byte");

    /* same id, different sessions must not cross */
    iwan_frag_pool_reset(&pool);
    CHECK(iwan_frag_in(&pool, 1, 0xa, d0, n0, 200, &out, &outlen) ==
          IWAN_FRAG_MORE, "session A first fragment enters its slot");
    CHECK(iwan_frag_in(&pool, 2, 0xb, d1, n1, 200, &out, &outlen) ==
          IWAN_FRAG_MORE, "session B last fragment must open another slot");
    CHECK(iwan_frag_in(&pool, 1, 0xa, d1, n1, 201, &out, &outlen) ==
          IWAN_FRAG_DONE, "session A complete after filling");
    CHECK(iwan_frag_in(&pool, 2, 0xb, d0, n0, 201, &out, &outlen) ==
          IWAN_FRAG_DONE, "session B complete after filling");

    /* old slot is reclaimed after timeout: a lone last fragment can only wait */
    iwan_frag_pool_reset(&pool);
    CHECK(iwan_frag_in(&pool, 3, 0xc, d0, n0, 1000, &out, &outlen) ==
          IWAN_FRAG_MORE, "first fragment enters its slot");
    CHECK(iwan_frag_in(&pool, 3, 0xc, d1, n1, 1000 + IWAN_FRAG_TIMEOUT_MS,
                       &out, &outlen) == IWAN_FRAG_MORE,
          "after timeout, an expired first fragment must not complete a packet");

    /* after completion the same session can immediately start another group (slot reclaimed) */
    CHECK(iwan_frag_in(&pool, 3, 0xc, d0, n0, 2000, &out, &outlen) ==
          IWAN_FRAG_MORE, "a new group's first fragment should re-enter a slot");
}

static void test_frag_rejects(void)
{
    uint8_t dg[IWAN_FRAG_HDR_LEN + 16];
    struct iwan_frag_hdr h = {0};
    const uint8_t *out;
    size_t outlen;
    struct iwan_frag_pool pool;

    iwan_frag_pool_reset(&pool);
    h.id = 0;                      /* empty-slot marker */
    h.eop = true;
    h.fraglen = 16;
    frag_hdr_put(dg, &h);
    CHECK(iwan_frag_in(&pool, 1, 1, dg, sizeof dg, 1, &out, &outlen) ==
          IWAN_FRAG_DROP, "id 0 must be dropped");

    h.id = 7;
    frag_hdr_put(dg, &h);
    CHECK(iwan_frag_in(&pool, 1, 1, dg, sizeof dg - 1, 1, &out, &outlen) ==
          IWAN_FRAG_DROP, "length mismatch must be dropped");
}

static void test_jhash_vectors(void)
{
    /* vectors come from the reference implementation's (Rust sr.rs) unit tests, which align with the official client */
    static const uint8_t v1[4] = {0, 0, 0, 1};
    static const uint8_t v2[8] = {0, 0, 0, 2, 0, 0, 0, 1};

    CHECK(iwan_jhash(v1, sizeof v1, 0) == 0xaf948ed6u, "jhash vector 1 mismatch");
    CHECK(iwan_jhash(v2, sizeof v2, 0) == 0xec505b9cu, "jhash vector 2 mismatch");
}

static void test_sr_key(void)
{
    const uint32_t links[2] = {1, 2};
    const uint32_t rlinks[2] = {2, 1};
    uint8_t be1[8] = {0, 0, 0, 1, 0, 0, 0, 2};
    uint8_t be2[8] = {0, 0, 0, 2, 0, 0, 0, 1};
    uint8_t k1[32], k2[32], k3[32];
    uint32_t hash;
    size_t n;

    n = iwan_sr_key("abc", links, 2, 1, k1);
    CHECK(n == 16, "algo 1 should derive a 16-byte key");
    CHECK(memcmp(k1, "abc", 3) == 0, "key must start with the password");
    hash = iwan_jhash(be1, sizeof be1, 0) + iwan_jhash(be2, sizeof be2, 0);
    CHECK(k1[3] == (uint8_t)hash && k1[4] == (uint8_t)(hash >> 8) &&
          k1[5] == (uint8_t)(hash >> 16) && k1[6] == (uint8_t)(hash >> 24),
          "padding bytes must be the little-endian bytes of the hash");
    CHECK(iwan_sr_key("abc", rlinks, 2, 1, k1) == 16, "reverse links must also derive");
    CHECK(iwan_sr_key("abc", links, 0, 1, k2) == 16, "hash is 0 with no links");
    CHECK(memcmp(k1, k2, 16) != 0, "link order must affect the key");

    /* checksum from the reference implementation: password "test" + links[1] + mode 1 */
    {
        static const uint32_t one[1] = {1};
        static const uint8_t want[16] = {
            0x74, 0x65, 0x73, 0x74, 0xac, 0x1d, 0x29, 0x5f,
            0xac, 0x1d, 0x29, 0x5f, 0xac, 0x1d, 0x29, 0x5f,
        };
        CHECK(iwan_sr_key("test", one, 1, 1, k3) == 16 &&
              memcmp(k3, want, sizeof want) == 0,
              "SR key must match the reference implementation (test/links=[1]/AES-128)");
    }

    n = iwan_sr_key("0123456789abcdef0123456789abcdef", links, 2, 2, k3);
    CHECK(n == 32, "algo other than 1 should derive a 32-byte key");
    CHECK(iwan_sr_key("p", NULL, 0, 5, k3) == 32, "algo 5 is also treated as AES-256");
}

static void test_sr_hdr(void)
{
    struct iwan_sr_hdr h, g;
    uint8_t buf[64];
    size_t hl = 0, n;

    memset(&h, 0, sizeof h);
    h.type = IWAN_SR_TYPE;
    h.nextid = 3;
    h.linkcnt = 2;
    h.algo = 1;
    h.padlen = 5;
    h.links[0] = 0x01020304u;
    h.links[1] = 0xa0b0c0d0u;
    n = iwan_sr_build(buf, sizeof buf, &h);
    CHECK(n == 12, "srhdr for two links should be 12 bytes");
    CHECK(buf[3] == (uint8_t)(1 | (5 << 3)), "byte3 must be algo:3|padlen:5");
    CHECK(iwan_sr_parse(buf, n, &g, &hl), "srhdr must parse");
    CHECK(hl == 12 && g.linkcnt == 2 && g.algo == 1 && g.padlen == 5 &&
          g.nextid == 3 && g.links[0] == h.links[0] &&
          g.links[1] == h.links[1], "srhdr fields must round-trip");

    buf[2] = 7;                     /* linkcnt out of bounds */
    CHECK(!iwan_sr_parse(buf, 32, &g, &hl), "linkcnt above 6 must be rejected");
    h.linkcnt = 7;
    CHECK(iwan_sr_build(buf, sizeof buf, &h) == 0, "build must also reject an out-of-range link count");
    h.linkcnt = 2;
    CHECK(iwan_sr_build(buf, 8, &h) == 0, "insufficient capacity must return 0");
}

static void test_sr_crypt(void)
{
    uint8_t key[32], buf[32], orig[32];
    int i;

    for (i = 0; i < 32; i++)
        key[i] = (uint8_t)(0x40 + i);
    for (i = 0; i < 32; i++)
        buf[i] = (uint8_t)(i * 3);
    memcpy(orig, buf, sizeof buf);

    CHECK(iwan_sr_crypt(buf, sizeof buf, key, 128, true), "AES-128 encryption should succeed");
    CHECK(memcmp(buf, orig, sizeof buf) != 0, "ciphertext must differ from plaintext");
    CHECK(iwan_sr_crypt(buf, sizeof buf, key, 128, false), "AES-128 decryption should succeed");
    CHECK(memcmp(buf, orig, sizeof buf) == 0, "AES-128 round trip must restore");

    CHECK(iwan_sr_crypt(buf, sizeof buf, key, 256, true), "AES-256 encryption should succeed");
    CHECK(iwan_sr_crypt(buf, sizeof buf, key, 256, false), "AES-256 decryption should succeed");
    CHECK(memcmp(buf, orig, sizeof buf) == 0, "AES-256 round trip must restore");

    CHECK(!iwan_sr_crypt(buf, 17, key, 128, true), "non-block-aligned length must be rejected");
    CHECK(!iwan_sr_crypt(buf, 0, key, 128, true), "empty length must be rejected");
}

static void test_echo_payload(void)
{
    struct iwan_echo e, g;
    buf_t b;
    uint8_t raw[IWAN_ECHO_LEN];

    memset(&e, 0, sizeof e);
    e.tick = 0x1122334455667788ull;
    e.cur = 1200;
    e.min = 900;
    e.max = 5000;
    e.sdrt = true;
    e.sdrt_magic = 0x01020304u;
    e.sdrt_cnt = 7;

    buf_init(&b);
    echo_put(&b, &e);
    CHECK(b.len == IWAN_ECHO_LEN, "ECHO payload must be 36 bytes");
    memcpy(raw, b.data, sizeof raw);
    CHECK(raw[0] == 0x88 && raw[7] == 0x11, "tick must be written little-endian");
    CHECK(memcmp(raw + 24, "SDRT", 4) == 0, "offset 24 must be the SDRT marker");
    CHECK(raw[28] == 0x01 && raw[31] == 0x04, "SDRT magic must be big-endian");
    CHECK(echo_parse(raw, sizeof raw, &g), "ECHO payload must parse");
    CHECK(g.tick == e.tick && g.cur == e.cur && g.min == e.min &&
          g.max == e.max && g.sdrt && g.sdrt_magic == e.sdrt_magic &&
          g.sdrt_cnt == e.sdrt_cnt, "ECHO fields must round-trip");
    CHECK(!echo_parse(raw, IWAN_ECHO_LEN - 1, &g), "short payload must be rejected");
    buf_free(&b);
}

/* 60-byte ECHOREQ: frame header + 16-byte signature + 36-byte payload, with the payload tick readable back */
static void test_echo_frame(void)
{
    buf_t b;
    struct iwan_echo_stats st;
    uint64_t now = 1000000;

    buf_init(&b);
    iwan_echo_stats_init(&st);
    iwan_echo_build(&b, PT_ECHO_REQ, 1, 0x1234, 0x12345678, &st, now);
    CHECK(b.len == IWAN_CTRL_LEN + IWAN_ECHO_LEN,
          "ECHOREQ must be 8+16+36=60 bytes");
    CHECK(b.data[0] == PT_ECHO_REQ && b.data[1] == 1, "ECHOREQ type/encryption bit");
    CHECK(verify_sig(b.data, b.len), "ECHOREQ must carry a valid signature");
    {
        struct iwan_echo e;
        CHECK(echo_parse(b.data + IWAN_CTRL_LEN, IWAN_ECHO_LEN, &e),
              "embedded payload must parse");
        CHECK(e.tick == now, "tick must equal the construction time");
        CHECK(e.min == IWAN_ECHO_MIN_INIT && e.cur == 0 && e.max == 0,
              "before the first sample, the client initial values must be cur=0/min=5s/max=0");
    }
    /* the reply echoes the payload unchanged: delay stats settle on the "first sample" */
    CHECK(iwan_echo_observe(&st, b.data + IWAN_CTRL_LEN, IWAN_ECHO_LEN,
                            now + 250), "reply must be accepted");
    CHECK(st.have && st.cur == 250 && st.min == 250 && st.max == 250,
          "first sample must settle cur/min/max together");
    CHECK(iwan_echo_observe(&st, b.data + IWAN_CTRL_LEN, IWAN_ECHO_LEN,
                            now + 100), "second sample must be accepted");
    CHECK(st.cur == 100 && st.min == 100 && st.max == 250, "min/max tracking");
    CHECK(!iwan_echo_observe(&st, b.data + IWAN_CTRL_LEN, IWAN_ECHO_LEN,
                             now - 5), "future tick must be rejected (not our response)");
    CHECK(!iwan_echo_observe(&st, b.data + IWAN_CTRL_LEN, 3, now),
          "short payload must be rejected");
    buf_free(&b);
}

int main(void)
{
    test_frag_hdr();
    test_frag_emit_and_reasm();
    test_frag_rejects();
    test_jhash_vectors();
    test_sr_key();
    test_sr_hdr();
    test_sr_crypt();
    test_echo_payload();
    test_echo_frame();
    printf("sdwan_ext_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
