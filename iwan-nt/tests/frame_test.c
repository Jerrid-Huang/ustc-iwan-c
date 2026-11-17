/*
 * Host unit test for driver/iwan_nt_frame.c.
 *
 * The codec is deliberately kernel-free, so this test runs on any host:
 *
 *   gcc -std=c11 -Wall -Wextra -Werror -I driver tests/frame_test.c \
 *       driver/iwan_nt_frame.c -o /tmp/iwan_nt_frame_test && /tmp/iwan_nt_frame_test
 */

#include <stdio.h>
#include <string.h>

#include "iwan_nt_frame.h"

static unsigned gChecks;
static unsigned gFailures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        gChecks++;                                                           \
        if (!(cond)) {                                                       \
            gFailures++;                                                     \
            printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);            \
        }                                                                    \
    } while (0)

#define CHECK_EQ(a, b)                                                       \
    do {                                                                     \
        long long va = (long long)(a);                                       \
        long long vb = (long long)(b);                                       \
        gChecks++;                                                           \
        if (va != vb) {                                                      \
            gFailures++;                                                     \
            printf("FAIL %s:%d %s=%lld != %s=%lld\n", __FILE__, __LINE__,    \
                   #a, va, #b, vb);                                          \
        }                                                                    \
    } while (0)

static const uint8_t kKey[IWAN_NT_FRAME_KEY_LEN] =
    { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

/* Build a minimal well-formed IPv4 / IPv6 packet carrying PayloadLen bytes. */
static size_t
BuildIpv4(uint8_t *Out, size_t Cap, size_t PayloadLen)
{
    size_t total = 20 + PayloadLen;
    size_t i;

    if (total > Cap) {
        return 0;
    }
    memset(Out, 0, total);
    Out[0] = 0x45;                    /* version 4, IHL 5 */
    Out[2] = (uint8_t)(total >> 8);
    Out[3] = (uint8_t)(total & 0xff);
    Out[8] = 64;                      /* TTL */
    Out[9] = 17;                      /* UDP */
    for (i = 20; i < total; i++) {
        Out[i] = (uint8_t)(i * 7u);
    }
    return total;
}

static size_t
BuildIpv6(uint8_t *Out, size_t Cap, size_t PayloadLen)
{
    size_t total = 40 + PayloadLen;
    size_t i;

    if (total > Cap) {
        return 0;
    }
    memset(Out, 0, total);
    Out[0] = 0x60;
    Out[4] = (uint8_t)(PayloadLen >> 8);
    Out[5] = (uint8_t)(PayloadLen & 0xff);
    Out[6] = 17;                      /* next header: UDP */
    Out[7] = 64;                      /* hop limit */
    for (i = 40; i < total; i++) {
        Out[i] = (uint8_t)(i * 3u);
    }
    return total;
}

static void
TestHeaderRoundTrip(void)
{
    IWAN_NT_FRAME_HEADER header;
    IWAN_NT_FRAME_HEADER decoded;
    uint8_t raw[IWAN_NT_FRAME_HDR_LEN];

    header.Type = IWAN_NT_TYPE_DATA_ENC;
    header.Encrypt = 1;
    header.Sid = 0x1234;
    header.Token = 0x12345678u;

    IwanNtFrameHeaderEncode(raw, &header);

    /* Little-endian on the wire: sid 0x1234 -> 34 12, token -> 78 56 34 12. */
    CHECK_EQ(raw[0], 0x18);
    CHECK_EQ(raw[1], 0x01);
    CHECK_EQ(raw[2], 0x34);
    CHECK_EQ(raw[3], 0x12);
    CHECK_EQ(raw[4], 0x78);
    CHECK_EQ(raw[5], 0x56);
    CHECK_EQ(raw[6], 0x34);
    CHECK_EQ(raw[7], 0x12);

    CHECK_EQ(IwanNtFrameHeaderDecode(raw, sizeof(raw), &decoded), IwanNtFrameOk);
    CHECK_EQ(decoded.Type, header.Type);
    CHECK_EQ(decoded.Encrypt, header.Encrypt);
    CHECK_EQ(decoded.Sid, header.Sid);
    CHECK_EQ(decoded.Token, header.Token);

    CHECK_EQ(IwanNtFrameHeaderDecode(raw, sizeof(raw) - 1, &decoded),
             IwanNtFrameTooShort);
    CHECK_EQ(IwanNtFrameHeaderDecode(NULL, sizeof(raw), &decoded),
             IwanNtFrameBadArgument);
}

static void
TestXorIsInvolution(void)
{
    uint8_t buf[37];
    uint8_t copy[37];
    size_t i;
    int same;

    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = (uint8_t)(i + 1u);
    }
    memcpy(copy, buf, sizeof(buf));

    IwanNtFrameXor(buf, sizeof(buf), kKey);
    same = (memcmp(buf, copy, sizeof(buf)) == 0);
    CHECK(!same);

    IwanNtFrameXor(buf, sizeof(buf), kKey);
    CHECK(memcmp(buf, copy, sizeof(buf)) == 0);

    /* Key repetition is 8 bytes: byte 0, 8, 16 use the same key byte. */
    memset(buf, 0, sizeof(buf));
    IwanNtFrameXor(buf, sizeof(buf), kKey);
    CHECK_EQ(buf[0], kKey[0]);
    CHECK_EQ(buf[8], kKey[0]);
    CHECK_EQ(buf[9], kKey[1]);
}

static void
TestInnerChecks(void)
{
    uint8_t v4[64];
    uint8_t v6[80];
    size_t n4 = BuildIpv4(v4, sizeof(v4), 24);
    size_t n6 = BuildIpv6(v6, sizeof(v6), 16);

    CHECK_EQ(IwanNtFrameInnerFamily(v4, n4), 4);
    CHECK_EQ(IwanNtFrameInnerFamily(v6, n6), 6);
    CHECK_EQ(IwanNtFrameInnerFamily(v4, 8), 0);   /* shorter than a v4 header */
    CHECK_EQ(IwanNtFrameInnerSane(v4, n4), IwanNtFrameOk);
    CHECK_EQ(IwanNtFrameInnerSane(v6, n6), IwanNtFrameOk);

    /* Declared total length larger than what is present. */
    v4[2] = 0x00;
    v4[3] = (uint8_t)(n4 + 8);
    CHECK_EQ(IwanNtFrameInnerSane(v4, n4), IwanNtFrameBadLength);
    v4[3] = (uint8_t)n4;
    CHECK_EQ(IwanNtFrameInnerSane(v4, n4), IwanNtFrameOk);

    /* Trailing bytes beyond the declared length are tolerated. */
    CHECK_EQ(IwanNtFrameInnerSane(v4, n4 + 4), IwanNtFrameOk);

    /* IHL smaller than the minimum header. */
    v4[0] = 0x43;
    CHECK_EQ(IwanNtFrameInnerSane(v4, n4), IwanNtFrameBadLength);
    v4[0] = 0x45;

    /* IPv6 payload length beyond the buffer. */
    v6[4] = 0xff;
    v6[5] = 0xff;
    CHECK_EQ(IwanNtFrameInnerSane(v6, n6), IwanNtFrameBadLength);
    v6[4] = 0x00;
    v6[5] = (uint8_t)(n6 - IWAN_NT_INNER_IP6_MIN);

    /* IPv4 fragments. The first fragment declares the original total length,
     * which cannot fit in the fragment it travels in; the stack on the far
     * side reassembles, so this must not be rejected. */
    {
        uint8_t frag[64];
        size_t nf = BuildIpv4(frag, sizeof(frag), 24);
        size_t i;

        /* First fragment: MF set, offset 0, total = whole datagram. */
        for (i = IWAN_NT_INNER_IP4_MIN; i < nf; i++) {
            frag[i] = (uint8_t)(0x10u + i);
        }
        frag[2] = 0x05;
        frag[3] = 0xdc;         /* 1500 byte datagram, this fragment is 44 */
        frag[6] = 0x20;         /* MF */
        frag[7] = 0x00;
        CHECK_EQ(IwanNtFrameInnerSane(frag, nf), IwanNtFrameOk);

        /* Middle fragment: offset 185, no MF, length is its own. */
        frag[2] = 0x00;
        frag[3] = (uint8_t)nf;
        frag[6] = 0x00;
        frag[7] = 0xb9;
        CHECK_EQ(IwanNtFrameInnerSane(frag, nf), IwanNtFrameOk);

        /* Last fragment: MF clear, offset 370. */
        frag[7] = 0x72;
        frag[6] = 0x01;
        CHECK_EQ(IwanNtFrameInnerSane(frag, nf), IwanNtFrameOk);

        /* Non-fragment packet with a bogus declared length is still refused. */
        frag[6] = 0x00;
        frag[7] = 0x00;
        frag[2] = 0x00;
        frag[3] = (uint8_t)(nf + 16);
        CHECK_EQ(IwanNtFrameInnerSane(frag, nf), IwanNtFrameBadLength);

        /* A fragment whose declared length is below its own header is
         * malformed no matter what the fragment bits say. */
        frag[2] = 0x00;
        frag[3] = 0x08;
        frag[6] = 0x20;
        frag[7] = 0x00;
        CHECK_EQ(IwanNtFrameInnerSane(frag, nf), IwanNtFrameBadLength);
    }

    /* IPv6 fragment header (next header 44): every fragment states its own
     * payload length, so the plain check already holds. */
    {
        uint8_t frag6[80];
        size_t nf6 = BuildIpv6(frag6, sizeof(frag6), 24);

        frag6[6] = 44;          /* next header = fragment */
        frag6[40] = 17;         /* fragment header: next header = UDP */
        frag6[41] = 0x00;
        frag6[42] = 0x00;       /* offset 0, M = 1 */
        frag6[43] = 0x01;
        CHECK_EQ(IwanNtFrameInnerSane(frag6, nf6), IwanNtFrameOk);
    }
}

static void
SealOpenRoundTrip(uint8_t type, int expectEncrypt, int v6)
{
    uint8_t inner[256];
    uint8_t payload[512];
    const uint8_t *opened = NULL;
    IWAN_NT_FRAME_HEADER header;
    IWAN_NT_FRAME_HEADER decoded;
    size_t innerLen;
    size_t payloadLen = 0;
    size_t openedLen = 0;
    size_t i;
    int differs = 0;

    innerLen = v6 ? BuildIpv6(inner, sizeof(inner), 48)
                  : BuildIpv4(inner, sizeof(inner), 32);

    header.Type = type;
    header.Encrypt = 0;
    header.Sid = 0x00ff;
    header.Token = 0xdeadbeefu;

    CHECK_EQ(IwanNtFrameSeal(payload, sizeof(payload), inner, innerLen,
                             &header, kKey, &payloadLen), IwanNtFrameOk);
    CHECK_EQ(payloadLen, innerLen + IWAN_NT_FRAME_HDR_LEN);
    CHECK_EQ(payload[0], type);
    CHECK_EQ(payload[1], expectEncrypt ? 1 : 0);
    CHECK_EQ(payload[2], 0xff);
    CHECK_EQ(payload[3], 0x00);

    if (expectEncrypt) {
        for (i = 0; i < innerLen; i++) {
            if (payload[IWAN_NT_FRAME_HDR_LEN + i] != inner[i]) {
                differs = 1;
                break;
            }
        }
        CHECK(differs);
    } else {
        CHECK(memcmp(payload + IWAN_NT_FRAME_HDR_LEN, inner, innerLen) == 0);
    }

    CHECK_EQ(IwanNtFrameOpen(payload, payloadLen, kKey, &decoded,
                             &opened, &openedLen), IwanNtFrameOk);
    CHECK_EQ(openedLen, innerLen);
    CHECK_EQ(decoded.Type, type);
    CHECK_EQ(decoded.Sid, 0x00ff);
    CHECK_EQ(decoded.Token, 0xdeadbeefu);
    CHECK(memcmp(opened, inner, innerLen) == 0);
}

static void
TestOpenRejections(void)
{
    uint8_t inner[128];
    uint8_t payload[256];
    IWAN_NT_FRAME_HEADER header;
    IWAN_NT_FRAME_HEADER decoded;
    const uint8_t *opened = NULL;
    size_t innerLen;
    size_t payloadLen = 0;
    size_t openedLen = 0;
    uint8_t cipher[256];

    innerLen = BuildIpv4(inner, sizeof(inner), 16);

    /* Unknown frame type. */
    header.Type = 0x15;
    header.Encrypt = 0;
    header.Sid = 1;
    header.Token = 2;
    payload[0] = 0x15;
    payload[1] = 0;
    memset(payload + IWAN_NT_FRAME_HDR_LEN, 0, innerLen);
    CHECK_EQ(IwanNtFrameOpen(payload, innerLen + IWAN_NT_FRAME_HDR_LEN, kKey,
                             &decoded, &opened, &openedLen),
             IwanNtFrameBadType);

    /* Encrypt flag disagreeing with the frame type. */
    header.Type = IWAN_NT_TYPE_DATA;
    CHECK_EQ(IwanNtFrameSeal(payload, sizeof(payload), inner, innerLen,
                             &header, kKey, &payloadLen), IwanNtFrameOk);
    payload[1] = 1;
    CHECK_EQ(IwanNtFrameOpen(payload, payloadLen, kKey, &decoded, &opened,
                             &openedLen), IwanNtFrameBadType);

    /* Truncated to less than a header. */
    CHECK_EQ(IwanNtFrameOpen(payload, IWAN_NT_FRAME_HDR_LEN - 1, kKey,
                             &decoded, &opened, &openedLen),
             IwanNtFrameTooShort);

    /* Garbage inner family after a valid header. */
    payload[0] = IWAN_NT_TYPE_DATA;
    payload[1] = 0;
    memset(payload + IWAN_NT_FRAME_HDR_LEN, 0x5a, innerLen);
    CHECK_EQ(IwanNtFrameOpen(payload, innerLen + IWAN_NT_FRAME_HDR_LEN, kKey,
                             &decoded, &opened, &openedLen),
             IwanNtFrameBadFamily);

    /*
     * A rejected encrypted frame must be left exactly as it arrived, so the
     * caller can still log the original bytes.
     */
    header.Type = IWAN_NT_TYPE_DATA_ENC;
    CHECK_EQ(IwanNtFrameSeal(payload, sizeof(payload), inner, innerLen,
                             &header, kKey, &payloadLen), IwanNtFrameOk);
    memcpy(cipher, payload, payloadLen);
    /* Corrupt the version nibble so the inner packet becomes invalid. */
    payload[IWAN_NT_FRAME_HDR_LEN] = (uint8_t)(payload[IWAN_NT_FRAME_HDR_LEN] ^ 0xf0u);
    memcpy(cipher, payload, payloadLen);
    CHECK_EQ(IwanNtFrameOpen(payload, payloadLen, kKey, &decoded, &opened,
                             &openedLen), IwanNtFrameBadFamily);
    CHECK(memcmp(payload, cipher, payloadLen) == 0);
}

static void
TestSealRejections(void)
{
    uint8_t inner[128];
    uint8_t payload[64];
    IWAN_NT_FRAME_HEADER header;
    size_t innerLen;
    size_t payloadLen = 0;

    innerLen = BuildIpv4(inner, sizeof(inner), 16);

    header.Type = IWAN_NT_TYPE_DATA;
    header.Encrypt = 0;
    header.Sid = 1;
    header.Token = 2;

    /* Output buffer too small for header + inner. */
    CHECK_EQ(IwanNtFrameSeal(payload, innerLen + IWAN_NT_FRAME_HDR_LEN - 1,
                             inner, innerLen, &header, kKey, &payloadLen),
             IwanNtFrameTooLong);

    /* Encrypted type without a key. */
    header.Type = IWAN_NT_TYPE_DATA_ENC;
    CHECK_EQ(IwanNtFrameSeal(payload, sizeof(payload), inner, innerLen,
                             &header, NULL, &payloadLen),
             IwanNtFrameBadArgument);

    /* Non-data type. */
    header.Type = 0x13;
    CHECK_EQ(IwanNtFrameSeal(payload, sizeof(payload), inner, innerLen,
                             &header, kKey, &payloadLen),
             IwanNtFrameBadType);
}

/*
 * Sealing in place has to produce byte-identical frames to sealing with a
 * separate source buffer. The send path relies on that: it copies the payload
 * straight into the slot body and lets the pool seal it where it lies, so a
 * divergence here would corrupt every packet on the wire.
 */
static void
TestSealInPlace(void)
{
    uint8_t inner[128];
    uint8_t copied[256];
    uint8_t inPlace[256];
    IWAN_NT_FRAME_HEADER header;
    size_t innerLen;
    size_t copiedLen = 0;
    size_t inPlaceLen = 0;
    uint8_t types[4];
    unsigned t;

    types[0] = IWAN_NT_TYPE_DATA;
    types[1] = IWAN_NT_TYPE_DATA_ENC;
    types[2] = IWAN_NT_TYPE_DATA6;
    types[3] = IWAN_NT_TYPE_DATA6_ENC;

    for (t = 0; t < 4; t++) {
        const uint8_t *key = (t == 1 || t == 3) ? kKey : NULL;

        header.Type = types[t];
        header.Encrypt = 0;
        header.Sid = 0x1234;
        header.Token = 0x89abcdefu;

        /*
         * Odd lengths exercise the trailing bytes after the 8-byte loop, and
         * the v6 types get a v6 inner packet.
         */
        innerLen = (t < 2) ? BuildIpv4(inner, sizeof(inner), 13)
                           : BuildIpv6(inner, sizeof(inner), 17);

        CHECK_EQ(IwanNtFrameSeal(copied, sizeof(copied), inner, innerLen,
                                 &header, key, &copiedLen), IwanNtFrameOk);

        memset(inPlace, 0xa5, sizeof(inPlace));
        memcpy(inPlace + IWAN_NT_FRAME_HDR_LEN, inner, innerLen);
        CHECK_EQ(IwanNtFrameSealInPlace(inPlace, sizeof(inPlace), innerLen,
                                        &header, key, &inPlaceLen),
                 IwanNtFrameOk);
        CHECK_EQ(inPlaceLen, copiedLen);
        CHECK(memcmp(inPlace, copied, copiedLen) == 0);
    }

    /* Capacity is measured from the frame, not from the body. */
    memcpy(inPlace + IWAN_NT_FRAME_HDR_LEN, inner, 33);
    header.Type = IWAN_NT_TYPE_DATA;
    CHECK_EQ(IwanNtFrameSealInPlace(inPlace, 33 + IWAN_NT_FRAME_HDR_LEN - 1,
                                    33, &header, NULL, &inPlaceLen),
             IwanNtFrameTooLong);

    /*
     * Encrypted in place without a key is rejected before anything is written,
     * and a body that is not a sane inner packet is rejected even with a key.
     * Both checks run before the header or the body is touched.
     */
    innerLen = BuildIpv4(inner, sizeof(inner), 13);
    header.Type = IWAN_NT_TYPE_DATA_ENC;
    memcpy(inPlace + IWAN_NT_FRAME_HDR_LEN, inner, innerLen);
    CHECK_EQ(IwanNtFrameSealInPlace(inPlace, sizeof(inPlace), innerLen,
                                    &header, NULL, &inPlaceLen),
             IwanNtFrameBadArgument);
    CHECK(memcmp(inPlace + IWAN_NT_FRAME_HDR_LEN, inner, innerLen) == 0);

    memset(inPlace + IWAN_NT_FRAME_HDR_LEN, 0x5a, innerLen);
    CHECK_EQ(IwanNtFrameSealInPlace(inPlace, sizeof(inPlace), innerLen,
                                    &header, kKey, &inPlaceLen),
             IwanNtFrameBadFamily);
    CHECK_EQ(inPlace[IWAN_NT_FRAME_HDR_LEN], 0x5a);
}

int
main(void)
{
    TestHeaderRoundTrip();
    TestXorIsInvolution();
    TestInnerChecks();

    SealOpenRoundTrip(IWAN_NT_TYPE_DATA, 0, 0);
    SealOpenRoundTrip(IWAN_NT_TYPE_DATA_ENC, 1, 0);
    SealOpenRoundTrip(IWAN_NT_TYPE_DATA6, 0, 1);
    SealOpenRoundTrip(IWAN_NT_TYPE_DATA6_ENC, 1, 1);

    TestOpenRejections();
    TestSealRejections();
    TestSealInPlace();

    printf("frame: %u checks, %u failures\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
