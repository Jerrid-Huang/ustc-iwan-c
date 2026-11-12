/*
 * Host unit test for driver/iwan_nt_ingress.c.
 *
 * The receive pipeline is deliberately kernel-free, so this test runs on any
 * host:
 *
 *   gcc -std=c11 -Wall -Wextra -Werror -I driver tests/ingress_test.c \
 *       driver/iwan_nt_ingress.c driver/iwan_nt_demux.c \
 *       driver/iwan_nt_frame.c driver/iwan_nt_ring.c \
 *       -o /tmp/iwan_nt_ingress_test && /tmp/iwan_nt_ingress_test
 *
 * It checks routing decisions and counter exactness. It does not and cannot
 * check IRQL behaviour, concurrency, or anything the WSK callback does.
 */

#include <stdio.h>
#include <string.h>

#include "iwan_nt_ingress.h"

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

#define TEST_SID 0x1234u
#define TEST_TOKEN 0x89abcdefu

/* What the fake sink received on the last delivery. */
typedef struct _SINK_RECORD {
    unsigned Calls;
    size_t LastLength;
    unsigned LastFamily;
    uint8_t Last[2048];
    void *ContextSeen;
    void *LastView;
} SINK_RECORD;

static SINK_RECORD gSink;

static void
FakeSink(
    void *Context,
    const uint8_t *Inner,
    size_t Length,
    unsigned Family,
    void *View
    )
{
    gSink.Calls++;
    gSink.LastView = View;
    gSink.LastLength = Length;
    gSink.LastFamily = Family;
    gSink.ContextSeen = Context;
    if (Length <= sizeof(gSink.Last)) {
        memcpy(gSink.Last, Inner, Length);
    }
}

static size_t
BuildIpv4(
    uint8_t *Out,
    size_t Capacity,
    size_t PayloadLength
    )
{
    size_t total = 20 + PayloadLength;
    size_t i;

    if (total > Capacity) {
        return 0;
    }
    memset(Out, 0, total);
    Out[0] = 0x45;
    Out[2] = (uint8_t)((total >> 8) & 0xff);
    Out[3] = (uint8_t)(total & 0xff);
    Out[8] = 64;
    Out[9] = 17;
    Out[12] = 10;
    Out[13] = 0;
    Out[14] = 0;
    Out[15] = 1;
    Out[16] = 10;
    Out[17] = 0;
    Out[18] = 0;
    Out[19] = 2;
    for (i = 0; i < PayloadLength; i++) {
        Out[20 + i] = (uint8_t)(0xa0 + (i & 0x0f));
    }
    return total;
}

static size_t
BuildIpv6(
    uint8_t *Out,
    size_t Capacity,
    size_t PayloadLength
    )
{
    size_t total = 40 + PayloadLength;
    size_t i;

    if (total > Capacity) {
        return 0;
    }
    memset(Out, 0, total);
    Out[0] = 0x60;
    Out[4] = (uint8_t)((PayloadLength >> 8) & 0xff);
    Out[5] = (uint8_t)(PayloadLength & 0xff);
    Out[6] = 17;
    Out[7] = 64;
    Out[8] = 0xfd;
    Out[23] = 0x01;
    Out[24] = 0xfd;
    Out[39] = 0x02;
    for (i = 0; i < PayloadLength; i++) {
        Out[40 + i] = (uint8_t)(0x50 + (i & 0x0f));
    }
    return total;
}

static size_t
SealData(
    uint8_t *Out,
    size_t Capacity,
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
    if (IwanNtFrameSeal(Out, Capacity, Inner, InnerLength, &header, kKey,
                        &outLength) != IwanNtFrameOk) {
        return 0;
    }
    return outLength;
}

static size_t
BuildControl(
    uint8_t *Out,
    size_t Capacity,
    uint8_t Type,
    size_t BodyLength
    )
{
    size_t total = IWAN_NT_CONTROL_MIN_LEN + BodyLength;
    size_t i;

    if (total > Capacity) {
        return 0;
    }
    memset(Out, 0, total);
    Out[0] = Type;
    Out[1] = 0;
    Out[2] = (uint8_t)(TEST_SID & 0xff);
    Out[3] = (uint8_t)((TEST_SID >> 8) & 0xff);
    Out[4] = (uint8_t)(TEST_TOKEN & 0xff);
    Out[5] = (uint8_t)((TEST_TOKEN >> 8) & 0xff);
    Out[6] = (uint8_t)((TEST_TOKEN >> 16) & 0xff);
    Out[7] = (uint8_t)((TEST_TOKEN >> 24) & 0xff);
    for (i = 0; i < IWAN_NT_CONTROL_SIGNATURE_LEN; i++) {
        Out[8 + i] = (uint8_t)(0x60 + i);
    }
    for (i = 0; i < BodyLength; i++) {
        Out[IWAN_NT_CONTROL_MIN_LEN + i] = (uint8_t)(0x30 + i);
    }
    return total;
}

static void
SetPlainSession(
    PIWAN_NT_INGRESS Ingress
    )
{
    IWAN_NT_INGRESS_SESSION session;

    memset(&session, 0, sizeof(session));
    session.Sid = TEST_SID;
    session.Token = TEST_TOKEN;
    session.Encrypted = 0;
    IwanNtIngressSetSession(Ingress, &session);
}

static void
SetEncryptedSession(
    PIWAN_NT_INGRESS Ingress
    )
{
    IWAN_NT_INGRESS_SESSION session;

    memset(&session, 0, sizeof(session));
    session.Sid = TEST_SID;
    session.Token = TEST_TOKEN;
    session.Encrypted = 1;
    memcpy(session.Key, kKey, sizeof(kKey));
    IwanNtIngressSetSession(Ingress, &session);
}

/* A stand-in for the adapter indication: records the inner packet. */
static IWAN_NT_INGRESS gIngress;
static IWAN_NT_RING gRing;
static uint8_t gRingBuffer[512];
static uint8_t gPayload[2048];

static void
TestNoSession(void)
{
    IwanNtIngressInitialize(&gIngress);
    IwanNtIngressAttach(&gIngress, NULL, FakeSink, NULL);

    memset(gPayload, 0, sizeof(gPayload));
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, sizeof(gPayload)),
             IwanNtIngressDroppedNoSession);
    CHECK_EQ(gIngress.Counters.Receives, 1);
    CHECK_EQ(gIngress.Counters.DroppedNoSession, 1);
    CHECK_EQ(gSink.Calls, 0);
}

/*
 * The handshake answer arrives while there is still no session. Without a
 * special case it is counted as DroppedNoSession and the tunnel can never come
 * up, which is exactly the kind of deadlock that only shows on a live peer.
 */
static void
TestHandshakeBeforeSession(void)
{
    uint8_t ack[53];
    uint8_t out[512];
    size_t outLength = 0;

    IwanNtIngressInitialize(&gIngress);
    CHECK_EQ(IwanNtRingInitialize(&gRing, gRingBuffer, sizeof(gRingBuffer)),
             IwanNtRingOk);
    IwanNtIngressAttach(&gIngress, &gRing, FakeSink, NULL);

    memset(ack, 0, sizeof(ack));
    ack[0] = IWAN_NT_TYPE_OPEN_ACK;
    ack[1] = 1;
    ack[2] = 0x00;
    ack[3] = 0x09;
    ack[4] = 0xe4;
    ack[5] = 0x97;
    ack[6] = 0x77;
    ack[7] = 0x30;

    CHECK_EQ(IwanNtIngressReceive(&gIngress, ack, sizeof(ack)),
             IwanNtIngressQueuedControl);
    CHECK_EQ(gIngress.Counters.QueuedControl, 1);
    CHECK_EQ(gIngress.Counters.DroppedNoSession, 0);
    CHECK_EQ(IwanNtRingPop(&gRing, out, sizeof(out), &outLength),
             IwanNtRingOk);
    CHECK_EQ(outLength, sizeof(ack));
    CHECK_EQ(out[0], IWAN_NT_TYPE_OPEN_ACK);

    /* DATA still has nothing to validate against, so it stays dropped. */
    {
        uint8_t data[64];

        memset(data, 0, sizeof(data));
        data[0] = IWAN_NT_TYPE_DATA;
        CHECK_EQ(IwanNtIngressReceive(&gIngress, data, sizeof(data)),
                 IwanNtIngressDroppedNoSession);
    }
}

static void
TestDataIpv4(void)
{
    uint8_t inner[512];
    size_t innerLength;
    size_t payloadLength;

    IwanNtIngressInitialize(&gIngress);
    SetPlainSession(&gIngress);
    IwanNtIngressAttach(&gIngress, NULL, FakeSink, &gRing);
    gSink.Calls = 0;

    innerLength = BuildIpv4(inner, sizeof(inner), 64);
    payloadLength = SealData(gPayload, sizeof(gPayload), inner, innerLength,
                             IWAN_NT_TYPE_DATA);
    CHECK(payloadLength > 0);

    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, payloadLength),
             IwanNtIngressDelivered);
    CHECK_EQ(gIngress.Counters.Delivered, 1);
    CHECK_EQ(gIngress.Counters.BytesDelivered, innerLength);
    CHECK_EQ(gSink.Calls, 1);
    CHECK_EQ(gSink.LastFamily, 4);
    CHECK_EQ(gSink.LastLength, innerLength);
    CHECK_EQ(memcmp(gSink.Last, inner, innerLength), 0);
    CHECK(gSink.ContextSeen == &gRing);
}

static void
TestDataIpv6(void)
{
    uint8_t inner[512];
    size_t innerLength;
    size_t payloadLength;

    IwanNtIngressInitialize(&gIngress);
    SetPlainSession(&gIngress);
    IwanNtIngressAttach(&gIngress, NULL, FakeSink, NULL);
    gSink.Calls = 0;

    innerLength = BuildIpv6(inner, sizeof(inner), 96);
    payloadLength = SealData(gPayload, sizeof(gPayload), inner, innerLength,
                             IWAN_NT_TYPE_DATA6);
    CHECK(payloadLength > 0);

    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, payloadLength),
             IwanNtIngressDelivered);
    CHECK_EQ(gSink.LastFamily, 6);
    CHECK_EQ(gSink.LastLength, innerLength);
    CHECK_EQ(memcmp(gSink.Last, inner, innerLength), 0);
}

static void
TestEncryptedData(void)
{
    uint8_t inner[512];
    size_t innerLength;
    size_t payloadLength;

    innerLength = BuildIpv4(inner, sizeof(inner), 32);
    payloadLength = SealData(gPayload, sizeof(gPayload), inner, innerLength,
                             IWAN_NT_TYPE_DATA_ENC);
    CHECK(payloadLength > 0);

    /* The same payload must fail against a plaintext session. */
    IwanNtIngressInitialize(&gIngress);
    SetPlainSession(&gIngress);
    IwanNtIngressAttach(&gIngress, NULL, FakeSink, NULL);
    gSink.Calls = 0;
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, payloadLength),
             IwanNtIngressDroppedMalformed);
    CHECK_EQ(gSink.Calls, 0);

    /* And must be decoded, not merely accepted, against the right session. */
    IwanNtIngressInitialize(&gIngress);
    SetEncryptedSession(&gIngress);
    IwanNtIngressAttach(&gIngress, NULL, FakeSink, NULL);
    gSink.Calls = 0;
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, payloadLength),
             IwanNtIngressDelivered);
    CHECK_EQ(gSink.Calls, 1);
    CHECK_EQ(gSink.LastFamily, 4);
    CHECK_EQ(gSink.LastLength, innerLength);
    CHECK_EQ(memcmp(gSink.Last, inner, innerLength), 0);
}

static void
TestSessionMismatch(void)
{
    uint8_t inner[256];
    size_t innerLength;
    size_t payloadLength;

    innerLength = BuildIpv4(inner, sizeof(inner), 16);
    payloadLength = SealData(gPayload, sizeof(gPayload), inner, innerLength,
                             IWAN_NT_TYPE_DATA);
    CHECK(payloadLength > 0);

    IwanNtIngressInitialize(&gIngress);
    SetPlainSession(&gIngress);
    IwanNtIngressAttach(&gIngress, NULL, FakeSink, NULL);
    gSink.Calls = 0;

    /* Change only the sid in the payload. */
    gPayload[2] = (uint8_t)((TEST_SID + 1u) & 0xff);
    gPayload[3] = (uint8_t)(((TEST_SID + 1u) >> 8) & 0xff);
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, payloadLength),
             IwanNtIngressDroppedMalformed);
    CHECK_EQ(gIngress.Counters.DroppedMalformed, 1);

    /* Restore the sid, corrupt the token instead. */
    gPayload[2] = (uint8_t)(TEST_SID & 0xff);
    gPayload[3] = (uint8_t)((TEST_SID >> 8) & 0xff);
    gPayload[4] ^= 0x01u;
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, payloadLength),
             IwanNtIngressDroppedMalformed);
    CHECK_EQ(gIngress.Counters.DroppedMalformed, 2);
    CHECK_EQ(gSink.Calls, 0);
}

static void
TestBadInner(void)
{
    uint8_t inner[256];
    size_t innerLength;
    size_t payloadLength;

    innerLength = BuildIpv4(inner, sizeof(inner), 16);
    payloadLength = SealData(gPayload, sizeof(gPayload), inner, innerLength,
                             IWAN_NT_TYPE_DATA);
    CHECK(payloadLength > 0);

    IwanNtIngressInitialize(&gIngress);
    SetPlainSession(&gIngress);
    IwanNtIngressAttach(&gIngress, NULL, FakeSink, NULL);
    gSink.Calls = 0;

    /* Declare more inner bytes than the payload can hold. */
    gPayload[10] = 0x0f;
    gPayload[11] = 0xff;
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, payloadLength),
             IwanNtIngressDroppedMalformed);
    CHECK_EQ(gSink.Calls, 0);
}

static void
TestControlQueue(void)
{
    uint8_t control[256];
    size_t controlLength;
    uint8_t popped[256];
    size_t poppedLength = 0;
    IWAN_NT_DEMUX_SESSION demuxSession;
    IWAN_NT_DEMUX_DECISION decision;

    controlLength = BuildControl(control, sizeof(control),
                                 IWAN_NT_TYPE_ECHO_REQ, 32);
    CHECK(controlLength > 0);

    IwanNtIngressInitialize(&gIngress);
    SetPlainSession(&gIngress);
    CHECK_EQ(IwanNtRingInitialize(&gRing, gRingBuffer, sizeof(gRingBuffer)),
             IwanNtRingOk);
    IwanNtIngressAttach(&gIngress, &gRing, FakeSink, NULL);

    memcpy(gPayload, control, controlLength);
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, controlLength),
             IwanNtIngressQueuedControl);
    CHECK_EQ(gIngress.Counters.QueuedControl, 1);
    CHECK_EQ(gRing.Pushes, 1);

    /*
     * The queued record is the whole frame, so the PASSIVE consumer can run
     * the demux again rather than depend on a second, divergent parser.
     */
    CHECK_EQ(IwanNtRingPop(&gRing, popped, sizeof(popped), &poppedLength),
             IwanNtRingOk);
    CHECK_EQ(poppedLength, controlLength);
    CHECK_EQ(memcmp(popped, control, controlLength), 0);
    demuxSession.Sid = TEST_SID;
    demuxSession.Token = TEST_TOKEN;
    demuxSession.Encrypted = 0;
    CHECK_EQ(IwanNtDemuxPayload(popped, poppedLength, &demuxSession,
                                &decision), IwanNtDemuxOk);
    CHECK_EQ(decision.Class, IwanNtDemuxClassControl);
    CHECK_EQ(decision.Header.Type, IWAN_NT_TYPE_ECHO_REQ);
}

static void
TestControlNoRing(void)
{
    uint8_t control[256];
    size_t controlLength;

    controlLength = BuildControl(control, sizeof(control),
                                 IWAN_NT_TYPE_CLOSE, 0);
    CHECK(controlLength > 0);

    IwanNtIngressInitialize(&gIngress);
    SetPlainSession(&gIngress);
    IwanNtIngressAttach(&gIngress, NULL, FakeSink, NULL);

    memcpy(gPayload, control, controlLength);
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, controlLength),
             IwanNtIngressDroppedControlNoRing);
    CHECK_EQ(gIngress.Counters.DroppedControlNoRing, 1);
}

static void
TestControlTooLarge(void)
{
    uint8_t control[512];
    size_t controlLength;
    uint8_t tinyRing[40];

    controlLength = BuildControl(control, sizeof(control),
                                 IWAN_NT_TYPE_OPEN_ACK, 256);
    CHECK(controlLength > sizeof(tinyRing));

    IwanNtIngressInitialize(&gIngress);
    SetPlainSession(&gIngress);
    CHECK_EQ(IwanNtRingInitialize(&gRing, tinyRing, sizeof(tinyRing)),
             IwanNtRingOk);
    IwanNtIngressAttach(&gIngress, &gRing, FakeSink, NULL);

    memcpy(gPayload, control, controlLength);
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, controlLength),
             IwanNtIngressDroppedControlTooLarge);
    CHECK_EQ(gIngress.Counters.DroppedControlTooLarge, 1);
    CHECK_EQ(gRing.Pushes, 0);
}

static void
TestControlRingFull(void)
{
    uint8_t control[128];
    uint8_t smallRing[64];
    size_t controlLength;
    unsigned i;
    unsigned dropped = 0;

    controlLength = BuildControl(control, sizeof(control),
                                 IWAN_NT_TYPE_ECHO_RESPONSE, 8);
    CHECK(controlLength > 0);
    CHECK(controlLength <= sizeof(smallRing));

    IwanNtIngressInitialize(&gIngress);
    SetPlainSession(&gIngress);
    CHECK_EQ(IwanNtRingInitialize(&gRing, smallRing, sizeof(smallRing)),
             IwanNtRingOk);
    IwanNtIngressAttach(&gIngress, &gRing, FakeSink, NULL);

    /* With no consumer, the ring must stop accepting and count the drops. */
    for (i = 0; i < 10; i++) {
        memcpy(gPayload, control, controlLength);
        if (IwanNtIngressReceive(&gIngress, gPayload, controlLength) ==
            IwanNtIngressDroppedControlFull) {
            dropped++;
        }
    }
    CHECK(dropped > 0);
    CHECK_EQ(gIngress.Counters.DroppedControlFull, dropped);
    CHECK_EQ(gIngress.Counters.QueuedControl + dropped, 10);
}

static void
TestUnhandledClasses(void)
{
    uint8_t segrt[8] = { IWAN_NT_TYPE_SEGRT, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t unknown[16];

    IwanNtIngressInitialize(&gIngress);
    SetPlainSession(&gIngress);
    IwanNtIngressAttach(&gIngress, NULL, FakeSink, NULL);

    memcpy(gPayload, segrt, sizeof(segrt));
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, sizeof(segrt)),
             IwanNtIngressDroppedSegrt);
    CHECK_EQ(gIngress.Counters.DroppedSegrt, 1);

    memset(unknown, 0, sizeof(unknown));
    unknown[0] = 0x29;
    unknown[2] = (uint8_t)(TEST_SID & 0xff);
    unknown[3] = (uint8_t)((TEST_SID >> 8) & 0xff);
    unknown[4] = (uint8_t)(TEST_TOKEN & 0xff);
    unknown[5] = (uint8_t)((TEST_TOKEN >> 8) & 0xff);
    unknown[6] = (uint8_t)((TEST_TOKEN >> 16) & 0xff);
    unknown[7] = (uint8_t)((TEST_TOKEN >> 24) & 0xff);
    memcpy(gPayload, unknown, sizeof(unknown));
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, sizeof(unknown)),
             IwanNtIngressDroppedUnknown);
    CHECK_EQ(gIngress.Counters.DroppedUnknown, 1);
}

static void
TestNoSink(void)
{
    uint8_t inner[256];
    size_t innerLength;
    size_t payloadLength;

    innerLength = BuildIpv4(inner, sizeof(inner), 16);
    payloadLength = SealData(gPayload, sizeof(gPayload), inner, innerLength,
                             IWAN_NT_TYPE_DATA);
    CHECK(payloadLength > 0);

    IwanNtIngressInitialize(&gIngress);
    SetPlainSession(&gIngress);
    IwanNtIngressAttach(&gIngress, NULL, NULL, NULL);

    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, payloadLength),
             IwanNtIngressDroppedNoSink);
    CHECK_EQ(gIngress.Counters.DroppedNoSink, 1);
    CHECK_EQ(gIngress.Counters.Delivered, 0);
}

static void
TestShortPayload(void)
{
    IwanNtIngressInitialize(&gIngress);
    SetPlainSession(&gIngress);
    IwanNtIngressAttach(&gIngress, NULL, FakeSink, NULL);

    memset(gPayload, 0, 4);
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, 4),
             IwanNtIngressDroppedMalformed);
    CHECK_EQ(gIngress.Counters.Receives, 1);
    CHECK_EQ(gIngress.Counters.DroppedMalformed, 1);
}

/*
 * Every receive must be accounted for exactly once. If a future change adds a
 * drop path without a counter, this reconciliation fails.
 */
static void
TestCountersReconcile(void)
{
    uint8_t inner[256];
    size_t innerLength;
    size_t payloadLength;

    IwanNtIngressInitialize(&gIngress);
    SetPlainSession(&gIngress);
    CHECK_EQ(IwanNtRingInitialize(&gRing, gRingBuffer, sizeof(gRingBuffer)),
             IwanNtRingOk);
    IwanNtIngressAttach(&gIngress, &gRing, FakeSink, NULL);

    innerLength = BuildIpv4(inner, sizeof(inner), 16);
    payloadLength = SealData(gPayload, sizeof(gPayload), inner, innerLength,
                             IWAN_NT_TYPE_DATA);
    CHECK(payloadLength > 0);
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, payloadLength),
             IwanNtIngressDelivered);

    memset(gPayload, 0, 4);
    CHECK_EQ(IwanNtIngressReceive(&gIngress, gPayload, 4),
             IwanNtIngressDroppedMalformed);

    CHECK_EQ(gIngress.Counters.Receives,
             gIngress.Counters.Delivered +
             gIngress.Counters.QueuedControl +
             gIngress.Counters.DroppedNoSession +
             gIngress.Counters.DroppedMalformed +
             gIngress.Counters.DroppedBadInner +
             gIngress.Counters.DroppedControlFull +
             gIngress.Counters.DroppedControlTooLarge +
             gIngress.Counters.DroppedControlNoRing +
             gIngress.Counters.DroppedNoSink +
             gIngress.Counters.DroppedSegrt +
             gIngress.Counters.DroppedUnknown);
}

/*
 * The snapshot accessor must copy the live counters and must tolerate a NULL
 * destination without touching memory.
 */
static void
TestCounterSnapshot(void)
{
    IWAN_NT_INGRESS ingress;
    IWAN_NT_INGRESS_COUNTERS snapshot;
    uint8_t frame[64];
    size_t length;
    size_t innerLength;

    /*
     * Build the inner packet in the tail of the buffer so that sealing it to
     * the front never overlaps source and destination.
     */
    innerLength = BuildIpv4(frame + 32, sizeof(frame) - 32, 8);
    length = SealData(frame, sizeof(frame), frame + 32, innerLength,
                      IWAN_NT_TYPE_DATA);
    CHECK(length > 0);

    IwanNtIngressInitialize(&ingress);

    CHECK(IwanNtIngressReceive(&ingress, frame, length) ==
          IwanNtIngressDroppedNoSession);

    memset(&snapshot, 0xFF, sizeof(snapshot));
    IwanNtIngressGetCounters(&ingress, &snapshot);
    CHECK(snapshot.Receives == 1u);
    CHECK(snapshot.DroppedNoSession == 1u);
    CHECK(snapshot.Delivered == 0u);

    IwanNtIngressGetCounters(&ingress, NULL);
    IwanNtIngressGetCounters(NULL, &snapshot);
    CHECK(snapshot.Receives == 1u);
}

int
main(void)
{
    TestNoSession();
    TestDataIpv4();
    TestDataIpv6();
    TestEncryptedData();
    TestSessionMismatch();
    TestBadInner();
    TestControlQueue();
    TestControlNoRing();
    TestControlTooLarge();
    TestControlRingFull();
    TestUnhandledClasses();
    TestNoSink();
    TestShortPayload();
    TestCountersReconcile();
    TestHandshakeBeforeSession();
    TestCounterSnapshot();

    printf("ingress: %u checks, %u failures\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
