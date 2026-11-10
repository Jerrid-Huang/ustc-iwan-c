/*
 * Host unit test for driver/iwan_nt_demux.c.
 *
 * The demux is deliberately kernel-free, so this test runs on any host:
 *
 *   gcc -std=c11 -Wall -Wextra -Werror -I driver tests/demux_test.c \
 *       driver/iwan_nt_demux.c driver/iwan_nt_frame.c \
 *       -o /tmp/iwan_nt_demux_test && /tmp/iwan_nt_demux_test
 */

#include <stdio.h>
#include <string.h>

#include "iwan_nt_demux.h"
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

#define TEST_SID 0x1234u
#define TEST_TOKEN 0xa1b2c3d4u

static const uint8_t kKey[IWAN_NT_FRAME_KEY_LEN] =
    { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

static const IWAN_NT_DEMUX_SESSION kPlainSession =
    { TEST_SID, TEST_TOKEN, 0 };

static const IWAN_NT_DEMUX_SESSION kEncryptedSession =
    { TEST_SID, TEST_TOKEN, 1 };

/* Build a minimal well-formed IPv4 / IPv6 packet carrying PayloadLen bytes. */
static size_t
BuildIpv4(uint8_t *Out, size_t Cap, size_t PayloadLen)
{
    size_t total = 20 + PayloadLen;
    size_t i;

    if (Out == NULL || total > Cap) {
        return 0;
    }
    memset(Out, 0, total);
    Out[0] = 0x45;                    /* version 4, IHL 5 */
    Out[2] = (uint8_t)(total >> 8);
    Out[3] = (uint8_t)(total & 0xffu);
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

    if (Out == NULL || total > Cap) {
        return 0;
    }
    memset(Out, 0, total);
    Out[0] = 0x60;                    /* version 6 */
    Out[4] = (uint8_t)(PayloadLen >> 8);
    Out[5] = (uint8_t)(PayloadLen & 0xffu);
    Out[6] = 17;                      /* next header: UDP */
    Out[7] = 64;                      /* hop limit */
    for (i = 40; i < total; i++) {
        Out[i] = (uint8_t)(i * 3u);
    }
    return total;
}

static size_t
BuildNormal(
    uint8_t *Out,
    size_t Cap,
    uint8_t Type,
    uint8_t Encrypt,
    uint16_t Sid,
    uint32_t Token,
    const uint8_t *Body,
    size_t BodyLength
    )
{
    IWAN_NT_FRAME_HEADER header;
    size_t total = IWAN_NT_FRAME_HDR_LEN + BodyLength;

    if (Out == NULL || total > Cap ||
        (Body == NULL && BodyLength != 0)) {
        return 0;
    }

    header.Type = Type;
    header.Encrypt = Encrypt;
    header.Sid = Sid;
    header.Token = Token;
    IwanNtFrameHeaderEncode(Out, &header);

    if (BodyLength != 0) {
        memcpy(Out + IWAN_NT_FRAME_HDR_LEN, Body, BodyLength);
    }
    return total;
}

static size_t
BuildControl(
    uint8_t *Out,
    size_t Cap,
    uint8_t Type,
    uint8_t Encrypt,
    uint16_t Sid,
    uint32_t Token,
    size_t ExtraLength
    )
{
    IWAN_NT_FRAME_HEADER header;
    size_t total = IWAN_NT_CONTROL_MIN_LEN + ExtraLength;
    size_t i;

    if (Out == NULL || total > Cap) {
        return 0;
    }

    header.Type = Type;
    header.Encrypt = Encrypt;
    header.Sid = Sid;
    header.Token = Token;
    IwanNtFrameHeaderEncode(Out, &header);

    for (i = 0; i < IWAN_NT_CONTROL_SIGNATURE_LEN; i++) {
        Out[IWAN_NT_FRAME_HDR_LEN + i] = (uint8_t)(0xa0u + i);
    }
    for (i = 0; i < ExtraLength; i++) {
        Out[IWAN_NT_CONTROL_MIN_LEN + i] = (uint8_t)(0x50u + i);
    }
    return total;
}

/*
 * SEGRT bytes deliberately contain values that would be a bad normal header:
 * nonzero encrypt byte, wrong sid and wrong token. The demux must not read
 * those positions as header fields.
 */
static size_t
BuildSegrt(uint8_t *Out, size_t Cap)
{
    if (Out == NULL || Cap < 12) {
        return 0;
    }
    memset(Out, 0, 12);
    Out[0] = IWAN_NT_TYPE_SEGRT;
    Out[1] = 0x7f;
    Out[2] = 0xaa;
    Out[3] = 0xbb;
    Out[4] = 0xde;
    Out[5] = 0xad;
    Out[6] = 0xbe;
    Out[7] = 0xef;
    Out[8] = 0x10;
    Out[9] = 0x20;
    Out[10] = 0x30;
    Out[11] = 0x40;
    return 12;
}

static size_t
SealData(
    uint8_t *Out,
    size_t Cap,
    const uint8_t *Inner,
    size_t InnerLength,
    uint8_t Type
    )
{
    IWAN_NT_FRAME_HEADER header;
    size_t outLength = 0;

    header.Type = Type;
    header.Encrypt = 0;
    header.Sid = TEST_SID;
    header.Token = TEST_TOKEN;

    if (IwanNtFrameSeal(Out, Cap, Inner, InnerLength, &header, kKey,
                        &outLength) != IwanNtFrameOk) {
        return 0;
    }
    return outLength;
}

static void
ExpectAccepted(
    const uint8_t *Payload,
    size_t Length,
    const IWAN_NT_DEMUX_SESSION *Session,
    IWAN_NT_DEMUX_CLASS Class,
    size_t RegionOffset,
    size_t RegionLength
    )
{
    IWAN_NT_DEMUX_DECISION decision;
    IWAN_NT_DEMUX_RESULT result;

    memset(&decision, 0xa5, sizeof(decision));
    result = IwanNtDemuxPayload(Payload, Length, Session, &decision);

    CHECK_EQ(result, IwanNtDemuxOk);
    CHECK_EQ(decision.Result, IwanNtDemuxOk);
    CHECK_EQ(decision.Class, Class);
    CHECK_EQ(decision.HeaderValid,
             Class == IwanNtDemuxClassSegrt ? 0 : 1);
    CHECK_EQ(decision.RegionOffset, RegionOffset);
    CHECK_EQ(decision.RegionLength, RegionLength);
}

static void
ExpectReject(
    const uint8_t *Payload,
    size_t Length,
    const IWAN_NT_DEMUX_SESSION *Session,
    IWAN_NT_DEMUX_RESULT Expected,
    IWAN_NT_DEMUX_CLASS ExpectedClass
    )
{
    IWAN_NT_DEMUX_DECISION decision;
    IWAN_NT_DEMUX_RESULT result;

    memset(&decision, 0xa5, sizeof(decision));
    result = IwanNtDemuxPayload(Payload, Length, Session, &decision);

    CHECK_EQ(result, Expected);
    CHECK_EQ(decision.Result, Expected);
    CHECK_EQ(decision.Class, ExpectedClass);
    CHECK_EQ(decision.RegionOffset, 0);
    CHECK_EQ(decision.RegionLength, 0);
}

static void
TestDataFrames(void)
{
    uint8_t inner[256];
    uint8_t payload[512];
    IWAN_NT_DEMUX_DECISION decision;
    size_t innerLength;
    size_t length;

    /* Plain IPv4. */
    innerLength = BuildIpv4(inner, sizeof(inner), 16);
    CHECK(innerLength > 0);
    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA, 0,
                         TEST_SID, TEST_TOKEN, inner, innerLength);
    CHECK(length > 0);
    ExpectAccepted(payload, length, &kPlainSession,
                   IwanNtDemuxClassData, IWAN_NT_FRAME_HDR_LEN, innerLength);

    CHECK_EQ(IwanNtDemuxPayload(payload, length, &kPlainSession, &decision),
             IwanNtDemuxOk);
    CHECK_EQ(decision.Header.Type, IWAN_NT_TYPE_DATA);
    CHECK_EQ(decision.Header.Encrypt, 0);
    CHECK_EQ(decision.Header.Sid, TEST_SID);
    CHECK_EQ(decision.Header.Token, TEST_TOKEN);
    CHECK(memcmp(payload + decision.RegionOffset, inner, innerLength) == 0);

    /* Plain IPv6. */
    innerLength = BuildIpv6(inner, sizeof(inner), 24);
    CHECK(innerLength > 0);
    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA6, 0,
                         TEST_SID, TEST_TOKEN, inner, innerLength);
    CHECK(length > 0);
    ExpectAccepted(payload, length, &kPlainSession,
                   IwanNtDemuxClassData, IWAN_NT_FRAME_HDR_LEN, innerLength);
    CHECK(memcmp(payload + IWAN_NT_FRAME_HDR_LEN, inner, innerLength) == 0);

    /* Encrypted IPv4: the demux accepts the opaque body and exposes it. */
    innerLength = BuildIpv4(inner, sizeof(inner), 32);
    CHECK(innerLength > 0);
    length = SealData(payload, sizeof(payload), inner, innerLength,
                      IWAN_NT_TYPE_DATA_ENC);
    CHECK(length > 0);
    ExpectAccepted(payload, length, &kEncryptedSession,
                   IwanNtDemuxClassData, IWAN_NT_FRAME_HDR_LEN, innerLength);
    CHECK_EQ(payload[1], 1);
    CHECK(memcmp(payload + IWAN_NT_FRAME_HDR_LEN, inner, innerLength) != 0);

    /* Encrypted IPv6. */
    innerLength = BuildIpv6(inner, sizeof(inner), 16);
    CHECK(innerLength > 0);
    length = SealData(payload, sizeof(payload), inner, innerLength,
                      IWAN_NT_TYPE_DATA6_ENC);
    CHECK(length > 0);
    ExpectAccepted(payload, length, &kEncryptedSession,
                   IwanNtDemuxClassData, IWAN_NT_FRAME_HDR_LEN, innerLength);
}

static void
TestControlFrames(void)
{
    static const uint8_t types[] = {
        IWAN_NT_TYPE_OPEN_REJECT,
        IWAN_NT_TYPE_OPEN_ACK,
        IWAN_NT_TYPE_OPEN,
        IWAN_NT_TYPE_ECHO_REQ,
        IWAN_NT_TYPE_ECHO_RESPONSE,
        IWAN_NT_TYPE_CLOSE
    };
    uint8_t payload[256];
    IWAN_NT_DEMUX_DECISION decision;
    size_t length;
    size_t i;

    for (i = 0; i < sizeof(types); i++) {
        length = BuildControl(payload, sizeof(payload), types[i], 0,
                              TEST_SID, TEST_TOKEN, 4);
        CHECK(length > 0);
        ExpectAccepted(payload, length, &kPlainSession,
                       IwanNtDemuxClassControl,
                       IWAN_NT_CONTROL_MIN_LEN, 4);

        CHECK_EQ(IwanNtDemuxPayload(payload, length, &kPlainSession,
                                    &decision), IwanNtDemuxOk);
        CHECK_EQ(decision.Header.Type, types[i]);
        CHECK_EQ(decision.Header.Encrypt, 0);
        CHECK(memcmp(payload + decision.RegionOffset,
                     payload + IWAN_NT_CONTROL_MIN_LEN, 4) == 0);
    }

    /* A control frame with no bytes after its signature is still complete. */
    length = BuildControl(payload, sizeof(payload), IWAN_NT_TYPE_OPEN, 0,
                          TEST_SID, TEST_TOKEN, 0);
    CHECK(length > 0);
    ExpectAccepted(payload, length, &kPlainSession,
                   IwanNtDemuxClassControl, IWAN_NT_CONTROL_MIN_LEN, 0);
}

static void
TestSegrt(void)
{
    uint8_t payload[64];
    IWAN_NT_DEMUX_DECISION decision;
    IWAN_NT_DEMUX_RESULT result;
    size_t length;

    length = BuildSegrt(payload, sizeof(payload));
    CHECK(length > 0);
    ExpectAccepted(payload, length, &kPlainSession,
                   IwanNtDemuxClassSegrt, 0, length);

    /*
     * Even a session with different expectations must not make SEGRT fail:
     * there is no normal header to compare with. The decision's Header must
     * stay zeroed, proving no header fields were decoded from offset 0.
     */
    result = IwanNtDemuxPayload(payload, length, &kEncryptedSession, &decision);
    CHECK_EQ(result, IwanNtDemuxOk);
    CHECK_EQ(decision.Header.Type, 0);
    CHECK_EQ(decision.Header.Encrypt, 0);
    CHECK_EQ(decision.Header.Sid, 0);
    CHECK_EQ(decision.Header.Token, 0);
    CHECK_EQ(decision.RegionOffset, 0);
    CHECK_EQ(decision.RegionLength, length);

    /*
     * The 4-byte source-routing header with zero links is the minimum SEGRT
     * this layer can recognize; anything shorter is a truncated frame, not a
     * routing header with an implicit empty link list.
     */
    payload[0] = IWAN_NT_TYPE_SEGRT;
    ExpectAccepted(payload, IWAN_NT_SEGRT_MIN_LEN, &kPlainSession,
                   IwanNtDemuxClassSegrt, 0, IWAN_NT_SEGRT_MIN_LEN);

    result = IwanNtDemuxPayload(payload, IWAN_NT_SEGRT_MIN_LEN - 1,
                                &kPlainSession, &decision);
    CHECK_EQ(result, IwanNtDemuxTooShort);
    CHECK_EQ(decision.Class, IwanNtDemuxClassSegrt);
}

static void
TestUnknownTypes(void)
{
    static const uint8_t types[] = { 0x19, 0x20, 0x22, 0x29, 0x2a };
    static const uint8_t tail[] = { 0xde, 0xad, 0xbe, 0xef, 0x11 };
    uint8_t payload[128];
    IWAN_NT_DEMUX_DECISION decision;
    size_t length;
    size_t i;

    for (i = 0; i < sizeof(types); i++) {
        length = BuildNormal(payload, sizeof(payload), types[i], 0,
                             TEST_SID, TEST_TOKEN, tail, sizeof(tail));
        CHECK(length > 0);
        ExpectAccepted(payload, length, &kPlainSession,
                       IwanNtDemuxClassUnknown,
                       IWAN_NT_FRAME_HDR_LEN, sizeof(tail));

        CHECK_EQ(IwanNtDemuxPayload(payload, length, &kPlainSession,
                                    &decision), IwanNtDemuxOk);
        CHECK_EQ(decision.Header.Type, types[i]);
        CHECK(memcmp(payload + decision.RegionOffset, tail, sizeof(tail)) == 0);
    }

    /* No tail is fine; the class, not a body requirement, defines the frame. */
    length = BuildNormal(payload, sizeof(payload), 0x22, 0,
                         TEST_SID, TEST_TOKEN, NULL, 0);
    CHECK(length > 0);
    ExpectAccepted(payload, length, &kPlainSession,
                   IwanNtDemuxClassUnknown, IWAN_NT_FRAME_HDR_LEN, 0);

    /*
     * No encryption rule is known for an unknown type, so the flag alone must
     * not turn it into an error. The tail stays opaque to this layer.
     */
    length = BuildNormal(payload, sizeof(payload), 0x19, 1,
                         TEST_SID, TEST_TOKEN, tail, sizeof(tail));
    CHECK(length > 0);
    ExpectAccepted(payload, length, &kPlainSession,
                   IwanNtDemuxClassUnknown,
                   IWAN_NT_FRAME_HDR_LEN, sizeof(tail));

    /* An unknown type with a truncated normal header is still too short. */
    length = BuildNormal(payload, sizeof(payload), 0x19, 0,
                         TEST_SID, TEST_TOKEN, tail, sizeof(tail));
    CHECK(length > 0);
    memset(&decision, 0xa5, sizeof(decision));
    CHECK_EQ(IwanNtDemuxPayload(payload, IWAN_NT_FRAME_HDR_LEN - 1,
                                &kPlainSession, &decision),
             IwanNtDemuxTooShort);
    CHECK_EQ(decision.Class, IwanNtDemuxClassUnknown);
    CHECK_EQ(decision.HeaderValid, 0);
}

static void
TestRejections(void)
{
    uint8_t inner[256];
    uint8_t payload[512];
    size_t innerLength;
    size_t length;

    innerLength = BuildIpv4(inner, sizeof(inner), 16);
    CHECK(innerLength > 0);

    /* Session identity is mandatory for every normal header. */
    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA, 0,
                         (uint16_t)(TEST_SID + 1u), TEST_TOKEN,
                         inner, innerLength);
    CHECK(length > 0);
    ExpectReject(payload, length, &kPlainSession,
                 IwanNtDemuxSidMismatch, IwanNtDemuxClassData);

    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA, 0,
                         TEST_SID, TEST_TOKEN ^ 1u, inner, innerLength);
    CHECK(length > 0);
    ExpectReject(payload, length, &kPlainSession,
                 IwanNtDemuxTokenMismatch, IwanNtDemuxClassData);

    length = BuildControl(payload, sizeof(payload), IWAN_NT_TYPE_OPEN_ACK, 0,
                          (uint16_t)(TEST_SID + 1u), TEST_TOKEN, 0);
    CHECK(length > 0);
    ExpectReject(payload, length, &kPlainSession,
                 IwanNtDemuxSidMismatch, IwanNtDemuxClassControl);

    /* Encrypt flag versus frame type. */
    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA, 1,
                         TEST_SID, TEST_TOKEN, inner, innerLength);
    CHECK(length > 0);
    ExpectReject(payload, length, &kPlainSession,
                 IwanNtDemuxEncryptMismatch, IwanNtDemuxClassData);

    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA_ENC, 0,
                         TEST_SID, TEST_TOKEN, inner, innerLength);
    CHECK(length > 0);
    ExpectReject(payload, length, &kPlainSession,
                 IwanNtDemuxEncryptMismatch, IwanNtDemuxClassData);

    /* Encrypt state versus session state, in both directions. */
    length = SealData(payload, sizeof(payload), inner, innerLength,
                      IWAN_NT_TYPE_DATA_ENC);
    CHECK(length > 0);
    ExpectReject(payload, length, &kPlainSession,
                 IwanNtDemuxEncryptMismatch, IwanNtDemuxClassData);

    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA, 0,
                         TEST_SID, TEST_TOKEN, inner, innerLength);
    CHECK(length > 0);
    ExpectReject(payload, length, &kEncryptedSession,
                 IwanNtDemuxEncryptMismatch, IwanNtDemuxClassData);

    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA_ENC, 0,
                         TEST_SID, TEST_TOKEN, inner, innerLength);
    CHECK(length > 0);
    ExpectReject(payload, length, &kEncryptedSession,
                 IwanNtDemuxEncryptMismatch, IwanNtDemuxClassData);

    /* Control frames are plaintext. */
    length = BuildControl(payload, sizeof(payload), IWAN_NT_TYPE_OPEN, 1,
                          TEST_SID, TEST_TOKEN, 0);
    CHECK(length > 0);
    ExpectReject(payload, length, &kPlainSession,
                 IwanNtDemuxEncryptMismatch, IwanNtDemuxClassControl);

    /* Truncated normal headers. */
    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA, 0,
                         TEST_SID, TEST_TOKEN, inner, innerLength);
    CHECK(length > 0);
    ExpectReject(payload, IWAN_NT_FRAME_HDR_LEN - 1, &kPlainSession,
                 IwanNtDemuxTooShort, IwanNtDemuxClassData);
    ExpectReject(payload, 1, &kPlainSession,
                 IwanNtDemuxTooShort, IwanNtDemuxClassData);

    /* Truncated control signatures: header only, and one byte short. */
    length = BuildControl(payload, sizeof(payload), IWAN_NT_TYPE_OPEN, 0,
                          TEST_SID, TEST_TOKEN, 0);
    CHECK(length > 0);
    ExpectReject(payload, IWAN_NT_FRAME_HDR_LEN, &kPlainSession,
                 IwanNtDemuxBadSignatureLength, IwanNtDemuxClassControl);
    ExpectReject(payload, IWAN_NT_CONTROL_MIN_LEN - 1, &kPlainSession,
                 IwanNtDemuxBadSignatureLength, IwanNtDemuxClassControl);

    /* Inner IP version must agree with the DATA frame type. */
    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA6, 0,
                         TEST_SID, TEST_TOKEN, inner, innerLength);
    CHECK(length > 0);
    ExpectReject(payload, length, &kPlainSession,
                 IwanNtDemuxBadInnerFamily, IwanNtDemuxClassData);

    innerLength = BuildIpv6(inner, sizeof(inner), 8);
    CHECK(innerLength > 0);
    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA, 0,
                         TEST_SID, TEST_TOKEN, inner, innerLength);
    CHECK(length > 0);
    ExpectReject(payload, length, &kPlainSession,
                 IwanNtDemuxBadInnerFamily, IwanNtDemuxClassData);

    /* An IPv4 packet whose declared total length exceeds the body. */
    innerLength = BuildIpv4(inner, sizeof(inner), 16);
    CHECK(innerLength > 0);
    inner[2] = 0x00;
    inner[3] = (uint8_t)(innerLength + 8u);
    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA, 0,
                         TEST_SID, TEST_TOKEN, inner, innerLength);
    CHECK(length > 0);
    ExpectReject(payload, length, &kPlainSession,
                 IwanNtDemuxBadInnerLength, IwanNtDemuxClassData);

    /* A body shorter than any inner IP header, including a bare DATA header. */
    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA, 0,
                         TEST_SID, TEST_TOKEN, inner, 8);
    CHECK(length > 0);
    ExpectReject(payload, length, &kPlainSession,
                 IwanNtDemuxBadInnerLength, IwanNtDemuxClassData);

    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA, 0,
                         TEST_SID, TEST_TOKEN, NULL, 0);
    CHECK(length > 0);
    ExpectReject(payload, length, &kPlainSession,
                 IwanNtDemuxBadInnerLength, IwanNtDemuxClassData);
}

static void
TestArguments(void)
{
    uint8_t inner[64];
    uint8_t payload[128];
    IWAN_NT_DEMUX_DECISION decision;
    IWAN_NT_DEMUX_RESULT result;
    size_t innerLength;
    size_t length;

    innerLength = BuildIpv4(inner, sizeof(inner), 8);
    CHECK(innerLength > 0);
    length = BuildNormal(payload, sizeof(payload), IWAN_NT_TYPE_DATA, 0,
                         TEST_SID, TEST_TOKEN, inner, innerLength);
    CHECK(length > 0);

    /* Zero-length payload: the first thing missing is the normal header. */
    ExpectReject(payload, 0, &kPlainSession,
                 IwanNtDemuxTooShort, IwanNtDemuxClassUnknown);

    /* Missing payload or missing session. */
    ExpectReject(NULL, length, &kPlainSession,
                 IwanNtDemuxBadArgument, IwanNtDemuxClassUnknown);
    ExpectReject(payload, length, NULL,
                 IwanNtDemuxBadArgument, IwanNtDemuxClassUnknown);

    /* A NULL decision cannot be filled; the return value is the only output. */
    result = IwanNtDemuxPayload(payload, length, &kPlainSession, NULL);
    CHECK_EQ(result, IwanNtDemuxBadArgument);

    /*
     * A caller-provided decision must be overwritten even on rejection.
     * HeaderValid is set only after a complete decode.
     */
    memset(&decision, 0xa5, sizeof(decision));
    result = IwanNtDemuxPayload(payload, IWAN_NT_FRAME_HDR_LEN - 1,
                                &kPlainSession, &decision);
    CHECK_EQ(result, IwanNtDemuxTooShort);
    CHECK_EQ(decision.HeaderValid, 0);
    CHECK_EQ(decision.Header.Sid, 0);
}

int
main(void)
{
    TestDataFrames();
    TestControlFrames();
    TestSegrt();
    TestUnknownTypes();
    TestRejections();
    TestArguments();

    printf("demux: %u checks, %u failures\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
