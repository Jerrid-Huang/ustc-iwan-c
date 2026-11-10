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

    printf("frame: %u checks, %u failures\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
