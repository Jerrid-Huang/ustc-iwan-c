/*
 * One test that walks the whole receive half the way a live session does:
 *
 *   handshake answer arrives with no session yet
 *     -> it must reach the control ring, not be dropped
 *     -> the parsed answer installs the session
 *   DATA arrives with that session
 *     -> it must be decrypted and handed over byte for byte
 *
 * Each module has its own test; this one exists because the modules' tests can
 * all pass while the composition is wrong. The pre-session drop was exactly that:
 * every unit was correct and the tunnel still could not come up.
 */

#include <stdio.h>
#include <string.h>

#include "iwan_nt_demux.h"
#include "iwan_nt_frame.h"
#include "iwan_nt_ingress.h"
#include "iwan_nt_ring.h"
#include "iwan_nt_session.h"

static int Failures = 0;
static int Checks = 0;

#define CHECK(Condition)                                                       \
    do {                                                                       \
        Checks++;                                                              \
        if (!(Condition)) {                                                    \
            printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #Condition);         \
            Failures++;                                                        \
        }                                                                      \
    } while (0)

/* The answer the deployment actually sends for sid 9, token 0xe4977730. */
static const uint8_t kAck[] = {
    0x12, 0x01, 0x00, 0x09, 0xe4, 0x97, 0x77, 0x30,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x04, 0x05, 0x78,
    0x04, 0x06, 0xc6, 0x12, 0x03, 0xe9,
    0x06, 0x06, 0x64, 0x64, 0x01, 0x01,
    0x05, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x03, 0x01
};

static IWAN_NT_INGRESS gIngress;
static IWAN_NT_RING gRing;
static uint8_t gRingStorage[1024];

static uint8_t gDelivered[2048];
static size_t gDeliveredLength;
static unsigned gDeliveredFamily;
static unsigned gDeliveredCalls;

static void
Sink(
    void *Context,
    const uint8_t *Inner,
    size_t Length,
    unsigned Family,
    void *View
    )
{
    (void)Context;
    (void)View;
    gDeliveredCalls++;
    gDeliveredFamily = Family;
    gDeliveredLength = Length;
    if (Length <= sizeof(gDelivered)) {
        memcpy(gDelivered, Inner, Length);
    }
}

static size_t
BuildIpv4(
    uint8_t *Buffer,
    size_t Capacity,
    size_t PayloadLength
    )
{
    size_t total = 20u + PayloadLength;
    size_t index;

    if (total > Capacity) {
        return 0;
    }
    memset(Buffer, 0, total);
    Buffer[0] = 0x45;                    /* version 4, IHL 5 */
    Buffer[2] = (uint8_t)(total >> 8);
    Buffer[3] = (uint8_t)(total & 0xFFu);
    Buffer[8] = 64;                      /* TTL */
    Buffer[9] = 17;                      /* UDP */
    for (index = 20u; index < total; index++) {
        Buffer[index] = (uint8_t)(index & 0xFFu);
    }
    return total;
}

int
main(void)
{
    IWAN_NT_SESSION_ACK ack;
    uint8_t key[8];
    uint8_t popped[512];
    size_t poppedLength = 0;
    uint8_t payload[2048];
    size_t payloadLength;
    uint8_t inner[512];
    size_t innerLength;
    IWAN_NT_FRAME_HEADER header;
    IWAN_NT_INGRESS_SESSION session;
    size_t index;

    /* Step 1: the answer arrives before any session exists. */
    IwanNtIngressInitialize(&gIngress);
    CHECK(IwanNtRingInitialize(&gRing, gRingStorage, sizeof(gRingStorage)) ==
          IwanNtRingOk);
    IwanNtIngressAttach(&gIngress, &gRing, Sink, NULL);

    /*
     * The recorded answer has a placeholder signature, so sign the copy the way
     * the peer would before it goes in at the wire.
     */
    memcpy(payload, kAck, sizeof(kAck));
    IwanNtSessionSignFrame(payload);
    CHECK(IwanNtIngressReceive(&gIngress, payload, sizeof(kAck)) ==
          IwanNtIngressQueuedControl);
    CHECK(gIngress.Counters.QueuedControl == 1);
    CHECK(gIngress.Counters.DroppedNoSession == 0);

    /* Step 2: the consumer reads it back unchanged and parses it. */
    CHECK(IwanNtRingPop(&gRing, popped, sizeof(popped), &poppedLength) ==
          IwanNtRingOk);
    CHECK(poppedLength == sizeof(kAck));
    CHECK(memcmp(popped, payload, sizeof(kAck)) == 0);
    CHECK(IwanNtSessionParseAck(popped, poppedLength, &ack) == IwanNtSessionOk);
    /* Machine-order words: 00 09 reads as 0x0900, e4 97 77 30 as 0x307797e4. */
    CHECK(ack.Sid == 0x0900u);
    CHECK(ack.Token == 0x307797e4u);
    CHECK(ack.Mtu == 1400u);
    CHECK(ack.Encrypted == 1u);

    /* Step 3: install the session the answer just taught us. */
    IwanNtSessionKey("_rev_m_2", "secret", key);
    memset(&session, 0, sizeof(session));
    session.Sid = ack.Sid;
    session.Token = ack.Token;
    session.Encrypted = 1;
    memcpy(session.Key, key, sizeof(key));
    IwanNtIngressSetSession(&gIngress, &session);

    /* Step 4: an encrypted DATA frame from the peer must reach the sink. */
    innerLength = BuildIpv4(inner, sizeof(inner), 100u);
    CHECK(innerLength == 120u);
    memset(&header, 0, sizeof(header));
    header.Type = IWAN_NT_TYPE_DATA_ENC;
    header.Encrypt = 1;
    header.Sid = ack.Sid;
    header.Token = ack.Token;
    CHECK(IwanNtFrameSeal(payload, sizeof(payload), inner, innerLength, &header,
                          key, &payloadLength) == IwanNtFrameOk);

    gDeliveredCalls = 0;
    CHECK(IwanNtIngressReceive(&gIngress, payload, payloadLength) ==
          IwanNtIngressDelivered);
    CHECK(gDeliveredCalls == 1);
    CHECK(gDeliveredFamily == 4u);
    CHECK(gDeliveredLength == innerLength);
    CHECK(memcmp(gDelivered, inner, innerLength) == 0);
    CHECK(gIngress.Counters.Delivered == 1);

    /* Step 5: the counters must still reconcile with what was received. */
    {
        uint64_t accounted =
            gIngress.Counters.Delivered + gIngress.Counters.QueuedControl +
            gIngress.Counters.DroppedNoSession +
            gIngress.Counters.DroppedMalformed +
            gIngress.Counters.DroppedBadInner +
            gIngress.Counters.DroppedControlFull +
            gIngress.Counters.DroppedControlTooLarge +
            gIngress.Counters.DroppedControlNoRing +
            gIngress.Counters.DroppedNoSink + gIngress.Counters.DroppedSegrt +
            gIngress.Counters.DroppedUnknown;

        CHECK(accounted == gIngress.Counters.Receives);
    }

    /* Step 6: a frame for another session must not be delivered. */
    {
        IWAN_NT_FRAME_HEADER other = header;

        other.Token = 0xDEADBEEFu;
        CHECK(IwanNtFrameSeal(payload, sizeof(payload), inner, innerLength, &other,
                              key, &payloadLength) == IwanNtFrameOk);
        gDeliveredCalls = 0;
        CHECK(IwanNtIngressReceive(&gIngress, payload, payloadLength) ==
              IwanNtIngressDroppedMalformed);
        CHECK(gDeliveredCalls == 0);
    }

    /*
     * Step 7: a CLOSE from the peer is a control frame, so it has to reach the
     * consumer even though it is not DATA: that is the only way the consumer can
     * learn the session is gone before the next frame arrives.
     */
    {
        uint8_t closed[64];

        memset(closed, 0, sizeof(closed));
        closed[0] = IWAN_NT_TYPE_CLOSE;
        closed[1] = 0;
        /*
         * The peer identifies the session in every control frame, and it writes the
         * identifiers as machine-order words, so they go back out little endian.
         */
        closed[2] = (uint8_t)(ack.Sid & 0xFFu);
        closed[3] = (uint8_t)((ack.Sid >> 8) & 0xFFu);
        closed[4] = (uint8_t)(ack.Token & 0xFFu);
        closed[5] = (uint8_t)((ack.Token >> 8) & 0xFFu);
        closed[6] = (uint8_t)((ack.Token >> 16) & 0xFFu);
        closed[7] = (uint8_t)((ack.Token >> 24) & 0xFFu);
        closed[23] = 0x11;   /* a signature byte: the ingress does not judge them */
        gDeliveredCalls = 0;
        CHECK(IwanNtIngressReceive(&gIngress, closed, 24u) ==
              IwanNtIngressQueuedControl);
        CHECK(gDeliveredCalls == 0);
        CHECK(IwanNtRingPop(&gRing, popped, sizeof(popped), &poppedLength) ==
              IwanNtRingOk);
        CHECK(poppedLength == 24u);
        CHECK(IwanNtSessionType(popped, poppedLength) == IWAN_NT_TYPE_CLOSE);
    }

    /*
     * Step 8: after a restart the peer comes back with new identifiers and a new
     * key. The stale session must not keep accepting frames sealed with the old
     * one, or a restarted tunnel would decrypt garbage into the stack.
     */
    {
        uint8_t newKey[8];
        IWAN_NT_INGRESS_SESSION next;
        IWAN_NT_FRAME_HEADER fresh = header;

        fresh.Sid = 0x0010u;
        fresh.Token = 0x11223344u;

        IwanNtIngressClearSession(&gIngress);
        IwanNtSessionKey("_rev_m_2", "secret2", newKey);
        memset(&next, 0, sizeof(next));
        next.Sid = fresh.Sid;
        next.Token = fresh.Token;
        next.Encrypted = 1;
        memcpy(next.Key, newKey, sizeof(newKey));
        IwanNtIngressSetSession(&gIngress, &next);

        CHECK(IwanNtFrameSeal(payload, sizeof(payload), inner, innerLength, &fresh,
                              newKey, &payloadLength) == IwanNtFrameOk);
        gDeliveredCalls = 0;
        CHECK(IwanNtIngressReceive(&gIngress, payload, payloadLength) ==
              IwanNtIngressDelivered);
        CHECK(gDeliveredCalls == 1);
        CHECK(memcmp(gDelivered, inner, innerLength) == 0);

        /* The same frame shape sealed with the retired key must not get through. */
        CHECK(IwanNtFrameSeal(payload, sizeof(payload), inner, innerLength, &fresh,
                              key, &payloadLength) == IwanNtFrameOk);
        gDeliveredCalls = 0;
        CHECK(IwanNtIngressReceive(&gIngress, payload, payloadLength) ==
              IwanNtIngressDroppedBadInner);
        CHECK(gDeliveredCalls == 0);
    }

    /* Step 9: clearing the session must also wipe the stored key. */
    IwanNtIngressClearSession(&gIngress);
    for (index = 0; index < IWAN_NT_FRAME_KEY_LEN; index++) {
        CHECK(gIngress.Session.Key[index] == 0);
    }

    if (Failures != 0) {
        printf("pipeline: %d failures\n", Failures);
        return 1;
    }
    printf("pipeline: %d checks, 0 failures\n", Checks);
    return 0;
}
