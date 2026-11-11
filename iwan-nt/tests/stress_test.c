/*
 * Stress the paths that only failure produces: random bytes into the
 * demultiplexer and the receive pipeline, and a ring that wraps while it is
 * nearly full. The point is not throughput, it is that every rejected input is
 * accounted for and that no index arithmetic depends on the input being sane.
 */
#include "iwan_nt_demux.h"
#include "iwan_nt_frame.h"
#include "iwan_nt_ingress.h"
#include "iwan_nt_ring.h"

#include <stdio.h>
#include <string.h>

static int Checks = 0;
static int Failures = 0;

static void
Check(
    const char *Name,
    int Condition
    )
{
    Checks++;
    if (!Condition) {
        printf("FAIL %s\n", Name);
        Failures++;
    }
}

/* Deterministic, so a failure can be replayed. */
static uint32_t Seed = 0x12345678u;

static uint32_t
NextRandom(void)
{
    Seed ^= Seed << 13;
    Seed ^= Seed >> 17;
    Seed ^= Seed << 5;
    return Seed;
}

static void
FillRandom(
    uint8_t *Buffer,
    size_t Length
    )
{
    size_t index;

    for (index = 0; index < Length; index++) {
        Buffer[index] = (uint8_t)(NextRandom() >> 24);
    }
}

static void
TestDemuxRandom(void)
{
    uint8_t payload[256];
    IWAN_NT_DEMUX_SESSION session;
    IWAN_NT_DEMUX_DECISION decision;
    unsigned iteration;

    session.Sid = 0x1234u;
    session.Token = 0x12345678u;
    session.Encrypted = 1;

    for (iteration = 0; iteration < 10000u; iteration++) {
        size_t length = (size_t)(NextRandom() % sizeof(payload));
        IWAN_NT_DEMUX_RESULT result;

        FillRandom(payload, length);
        memset(&decision, 0xAA, sizeof(decision));
        result = IwanNtDemuxPayload(payload, length, &session, &decision);

        if (result == IwanNtDemuxOk) {
            Check("demux-ok-class",
                  decision.Class == IwanNtDemuxClassData ||
                  decision.Class == IwanNtDemuxClassControl ||
                  decision.Class == IwanNtDemuxClassSegrt ||
                  decision.Class == IwanNtDemuxClassUnknown);
            Check("demux-ok-region",
                  decision.RegionOffset <= length &&
                  decision.RegionLength <= length - decision.RegionOffset);
            if (decision.Class == IwanNtDemuxClassSegrt) {
                /* A segment route carries at least its four fixed bytes. */
                Check("demux-segrt-min", length >= 4u);
            }
        } else {
            Check("demux-bad-result", result >= IwanNtDemuxBadArgument);
        }
    }
}

/* Sum of the outcomes must equal what went in: an unaccounted drop is a bug. */
static int
Conserved(
    const IWAN_NT_INGRESS *Ingress
    )
{
    const IWAN_NT_INGRESS_COUNTERS *c = &Ingress->Counters;
    uint64_t total;

    total = c->Delivered + c->QueuedControl + c->DroppedNoSession +
            c->DroppedMalformed + c->DroppedBadInner + c->DroppedControlFull +
            c->DroppedControlTooLarge + c->DroppedControlNoRing +
            c->DroppedNoSink + c->DroppedSegrt + c->DroppedUnknown;

    return total == c->Receives;
}

static void
TestIngressRandom(void)
{
    IWAN_NT_INGRESS ingress;
    IWAN_NT_INGRESS_SESSION session;
    IWAN_NT_RING ring;
    uint8_t ringStorage[512];
    uint8_t payload[256];
    unsigned delivered = 0;
    unsigned iteration;

    (void)delivered;
    IwanNtRingInitialize(&ring, ringStorage, sizeof(ringStorage));
    IwanNtIngressInitialize(&ingress);
    IwanNtIngressAttach(&ingress, &ring, NULL, NULL);

    session.Sid = 0x1234u;
    session.Token = 0x12345678u;
    session.Encrypted = 0;
    memset(session.Key, 0, sizeof(session.Key));
    IwanNtIngressSetSession(&ingress, &session);

    for (iteration = 0; iteration < 5000u; iteration++) {
        size_t length = (size_t)(NextRandom() % sizeof(payload));

        FillRandom(payload, length);
        (void)IwanNtIngressReceive(&ingress, payload, length);
        if (!Conserved(&ingress)) {
            Check("ingress-conserved", 0);
            break;
        }
    }
    Check("ingress-conserved-final", Conserved(&ingress));
    Check("ingress-counted", ingress.Counters.Receives == 5000u);

    /* Without a session, DATA is dropped but the counters still balance. */
    IwanNtIngressClearSession(&ingress);
    for (iteration = 0; iteration < 2000u; iteration++) {
        size_t length = (size_t)(NextRandom() % sizeof(payload));

        FillRandom(payload, length);
        (void)IwanNtIngressReceive(&ingress, payload, length);
    }
    Check("ingress-conserved-cleared", Conserved(&ingress));
    Check("ingress-cleared-counted", ingress.Counters.Receives == 7000u);
}

static void
TestRingWrap(void)
{
    IWAN_NT_RING ring;
    uint8_t storage[1024];
    uint8_t record[64];
    uint8_t popped[64];
    uint64_t attempted = 0;
    uint64_t pushed = 0;
    uint64_t poppedCount = 0;
    unsigned iteration;

    IwanNtRingInitialize(&ring, storage, sizeof(storage));

    for (iteration = 0; iteration < 5000u; iteration++) {
        /*
         * Keep the ring near full so the indices wrap while it is occupied, which
         * is where a length-prefix walk is most likely to step off the end.
         */
        if ((NextRandom() & 1u) != 0 || pushed == poppedCount) {
            size_t length = 1u + (size_t)(NextRandom() % sizeof(record));
            size_t index;

            for (index = 0; index < length; index++) {
                record[index] = (uint8_t)(pushed + index);
            }
            attempted++;
            if (IwanNtRingPush(&ring, record, length) == IwanNtRingOk) {
                pushed++;
            }
        } else {
            size_t length = 0;
            size_t index;
            int same = 1;

            Check("ring-peek", IwanNtRingPeekLength(&ring, &length) == IwanNtRingOk);
            Check("ring-length", length >= 1u && length <= sizeof(popped));
            Check("ring-pop",
                  IwanNtRingPop(&ring, popped, sizeof(popped), &length) ==
                  IwanNtRingOk);
            /*
             * Records carry the sequence number they were pushed with, so a value
             * read back out of order means the length-prefix walk crossed a wrap.
             */
            for (index = 0; index < length; index++) {
                if (popped[index] != (uint8_t)(poppedCount + index)) {
                    same = 0;
                }
            }
            Check("ring-order", same);
            poppedCount++;
        }
        /*
         * Every attempt either became a record or was counted as a drop. Records
         * are far below the capacity, so "too large" cannot be the reason and the
         * only other outcome is the ring being full.
         */
        if (attempted != pushed + (uint64_t)ring.Drops) {
            Check("ring-accounted", 0);
            break;
        }
    }
    Check("ring-accounted-final", attempted == pushed + (uint64_t)ring.Drops);
    Check("ring-progressed", pushed > 100u && poppedCount > 100u);
}

int
main(void)
{
    TestDemuxRandom();
    TestIngressRandom();
    TestRingWrap();

    if (Failures != 0) {
        printf("stress: %d failures\n", Failures);
        return 1;
    }
    printf("stress: %d checks, 0 failures\n", Checks);
    return 0;
}
