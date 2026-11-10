#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <threads.h>

#include "iwan_nt_ring.h"

static unsigned gChecks;
static unsigned gFailures;

#define CHECK(condition) \
    do { \
        gChecks++; \
        if (!(condition)) { \
            gFailures++; \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        } \
    } while (0)

#define CHECK_EQ(actual, expected) \
    do { \
        long long checkActual = (long long)(actual); \
        long long checkExpected = (long long)(expected); \
        gChecks++; \
        if (checkActual != checkExpected) { \
            gFailures++; \
            printf("FAIL %s:%d: %s == %s (%lld != %lld)\n", \
                   __FILE__, __LINE__, #actual, #expected, \
                   checkActual, checkExpected); \
        } \
    } while (0)

static void
BuildPayload(
    uint8_t *Out,
    size_t Length,
    unsigned Seed
    )
{
    size_t i;

    for (i = 0; i < Length; i++) {
        Out[i] = (uint8_t)(Seed * 37u + i * 11u + 1u);
    }
}

static int
PayloadMatches(
    const uint8_t *Payload,
    size_t Length,
    unsigned Seed
    )
{
    size_t i;

    for (i = 0; i < Length; i++) {
        if (Payload[i] != (uint8_t)(Seed * 37u + i * 11u + 1u)) {
            return 0;
        }
    }
    return 1;
}

static void
TestInitializeAndEmpty(void)
{
    uint8_t storage[64];
    IWAN_NT_RING ring;
    size_t length;

    CHECK_EQ(IwanNtRingInitialize(NULL, storage, sizeof(storage)),
             IwanNtRingBadArgument);
    CHECK_EQ(IwanNtRingInitialize(&ring, NULL, sizeof(storage)),
             IwanNtRingBadArgument);
    CHECK_EQ(IwanNtRingInitialize(&ring, storage, 0),
             IwanNtRingBadArgument);
    CHECK_EQ(IwanNtRingInitialize(&ring, storage,
                                  IWAN_NT_RING_RECORD_HEADER_LEN),
             IwanNtRingBadArgument);
    CHECK_EQ(IwanNtRingInitialize(&ring, storage,
                                  IWAN_NT_RING_RECORD_HEADER_LEN + 1u),
             IwanNtRingOk);
    CHECK(ring.Buffer == storage);
    CHECK_EQ(ring.Capacity, IWAN_NT_RING_RECORD_HEADER_LEN + 1u);
    CHECK_EQ(ring.Head, 0);
    CHECK_EQ(ring.Tail, 0);
    CHECK_EQ(ring.Pushes, 0);
    CHECK_EQ(ring.Pops, 0);
    CHECK_EQ(ring.Drops, 0);
    CHECK_EQ(ring.BytesDropped, 0);
    CHECK_EQ(ring.MaxRecordLength, 0);

    CHECK_EQ(IwanNtRingInitialize(&ring, storage, sizeof(storage)),
             IwanNtRingOk);
    CHECK_EQ(ring.Capacity, sizeof(storage));

    length = 99;
    CHECK_EQ(IwanNtRingPeekLength(&ring, &length), IwanNtRingEmpty);
    CHECK_EQ(length, 0);

    length = 99;
    CHECK_EQ(IwanNtRingPop(&ring, NULL, 0, &length), IwanNtRingEmpty);
    CHECK_EQ(length, 0);

    CHECK_EQ(IwanNtRingPeekLength(NULL, &length), IwanNtRingBadArgument);
    CHECK_EQ(IwanNtRingPeekLength(&ring, NULL), IwanNtRingBadArgument);
    CHECK_EQ(IwanNtRingPop(NULL, storage, sizeof(storage), &length),
             IwanNtRingBadArgument);
    CHECK_EQ(IwanNtRingPop(&ring, storage, sizeof(storage), NULL),
             IwanNtRingBadArgument);
}

static void
TestRecordLimits(void)
{
    enum { CAPACITY = 32 };
    uint8_t storage[CAPACITY];
    uint8_t snapshot[CAPACITY];
    uint8_t record[64];
    uint8_t out[64];
    IWAN_NT_RING ring;
    size_t length;
    size_t i;
    uint64_t pops;

    for (i = 0; i < sizeof(record); i++) {
        record[i] = (uint8_t)(i * 7u + 3u);
    }
    CHECK_EQ(IwanNtRingInitialize(&ring, storage, CAPACITY),
             IwanNtRingOk);

    /* A one-byte record is legal and round-trips exactly. */
    CHECK_EQ(IwanNtRingPush(&ring, record, 1), IwanNtRingOk);
    CHECK_EQ(ring.Pushes, 1);
    CHECK_EQ(ring.MaxRecordLength, 1);
    CHECK_EQ(IwanNtRingPeekLength(&ring, &length), IwanNtRingOk);
    CHECK_EQ(length, 1);
    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, 1);
    CHECK_EQ(out[0], record[0]);
    CHECK_EQ(ring.Pops, 1);

    /*
     * A maximum-length record exactly fills the ring: prefix + payload uses
     * every byte. A further one-byte push must fail without changing any ring
     * byte, proving that a rejected push cannot expose a partial record.
     */
    CHECK_EQ(IwanNtRingPush(&ring, record,
                            CAPACITY - IWAN_NT_RING_RECORD_HEADER_LEN),
             IwanNtRingOk);
    CHECK_EQ(ring.Head - ring.Tail, CAPACITY);
    CHECK_EQ(ring.MaxRecordLength,
             CAPACITY - IWAN_NT_RING_RECORD_HEADER_LEN);
    CHECK_EQ(IwanNtRingPeekLength(&ring, &length), IwanNtRingOk);
    CHECK_EQ(length, CAPACITY - IWAN_NT_RING_RECORD_HEADER_LEN);

    memcpy(snapshot, storage, sizeof(storage));
    CHECK_EQ(IwanNtRingPush(&ring, record, 1), IwanNtRingFull);
    CHECK(memcmp(storage, snapshot, sizeof(storage)) == 0);
    CHECK_EQ(ring.Pushes, 2);
    CHECK_EQ(ring.Drops, 1);
    CHECK_EQ(ring.BytesDropped, 1);
    CHECK_EQ(IwanNtRingPeekLength(&ring, &length), IwanNtRingOk);
    CHECK_EQ(length, CAPACITY - IWAN_NT_RING_RECORD_HEADER_LEN);

    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, CAPACITY - IWAN_NT_RING_RECORD_HEADER_LEN);
    CHECK(memcmp(out, record,
                 CAPACITY - IWAN_NT_RING_RECORD_HEADER_LEN) == 0);
    CHECK_EQ(ring.Pops, 2);
    CHECK_EQ(IwanNtRingPeekLength(&ring, &length), IwanNtRingEmpty);

    /*
     * max + 1 can never fit, even in an empty ring. It is a record-size
     * error, not a fullness drop, but MaxRecordLength still observes it.
     */
    CHECK_EQ(IwanNtRingPush(&ring, record,
                            CAPACITY - IWAN_NT_RING_RECORD_HEADER_LEN + 1u),
             IwanNtRingRecordTooLarge);
    CHECK_EQ(ring.Pushes, 2);
    CHECK_EQ(ring.Drops, 1);
    CHECK_EQ(ring.BytesDropped, 1);
    CHECK_EQ(ring.MaxRecordLength,
             CAPACITY - IWAN_NT_RING_RECORD_HEADER_LEN + 1u);
    CHECK_EQ(IwanNtRingPeekLength(&ring, &length), IwanNtRingEmpty);

    /* Too-small output is a hard error: no bytes written, record retained. */
    CHECK_EQ(IwanNtRingPush(&ring, record, 10), IwanNtRingOk);
    pops = ring.Pops;
    memset(out, 0xAA, sizeof(out));
    length = 77;
    CHECK_EQ(IwanNtRingPop(&ring, out, 9, &length),
             IwanNtRingBufferTooSmall);
    CHECK_EQ(length, 10);
    CHECK_EQ(out[0], 0xAA);
    CHECK_EQ(ring.Pops, pops);
    CHECK_EQ(IwanNtRingPeekLength(&ring, &length), IwanNtRingOk);
    CHECK_EQ(length, 10);

    length = 77;
    CHECK_EQ(IwanNtRingPop(&ring, NULL, 10, &length),
             IwanNtRingBadArgument);
    CHECK_EQ(length, 77);
    CHECK_EQ(IwanNtRingPeekLength(&ring, &length), IwanNtRingOk);
    CHECK_EQ(length, 10);

    CHECK_EQ(IwanNtRingPop(&ring, out, 10, &length), IwanNtRingOk);
    CHECK_EQ(length, 10);
    CHECK(memcmp(out, record, 10) == 0);
    CHECK_EQ(IwanNtRingPeekLength(&ring, &length), IwanNtRingEmpty);
}

static void
TestWrapAround(void)
{
    enum { CAPACITY = 32 };
    uint8_t storage[CAPACITY];
    uint8_t record[32];
    uint8_t out[32];
    IWAN_NT_RING ring;
    size_t length;

    CHECK_EQ(IwanNtRingInitialize(&ring, storage, CAPACITY),
             IwanNtRingOk);

    /* Advance Head and Tail to 14, then write a 20-byte payload across 31/0. */
    BuildPayload(record, 10, 1);
    CHECK_EQ(IwanNtRingPush(&ring, record, 10), IwanNtRingOk);
    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, 10);
    CHECK(PayloadMatches(out, 10, 1));

    BuildPayload(record, 20, 2);
    CHECK_EQ(IwanNtRingPush(&ring, record, 20), IwanNtRingOk);
    CHECK_EQ(ring.Head - ring.Tail, 24);
    CHECK_EQ(storage[14], 20);
    CHECK_EQ(storage[15], 0);
    CHECK_EQ(storage[16], 0);
    CHECK_EQ(storage[17], 0);
    CHECK(memcmp(storage + 18, record, 14) == 0);
    CHECK(memcmp(storage, record + 14, 6) == 0);
    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, 20);
    CHECK(PayloadMatches(out, 20, 2));

    /*
     * Move Tail to 94 (mod 32 == 30). A two-byte record then starts at 30, so
     * its 4-byte prefix itself wraps: bytes 30, 31, 0, 1.
     */
    BuildPayload(record, 24, 3);
    CHECK_EQ(IwanNtRingPush(&ring, record, 24), IwanNtRingOk);
    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, 24);
    CHECK(PayloadMatches(out, 24, 3));
    CHECK_EQ(IwanNtRingPush(&ring, record, 24), IwanNtRingOk);
    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, 24);
    CHECK(PayloadMatches(out, 24, 3));

    BuildPayload(record, 2, 4);
    CHECK_EQ(IwanNtRingPush(&ring, record, 2), IwanNtRingOk);
    CHECK_EQ(storage[30], 2);
    CHECK_EQ(storage[31], 0);
    CHECK_EQ(storage[0], 0);
    CHECK_EQ(storage[1], 0);
    CHECK_EQ(storage[2], record[0]);
    CHECK_EQ(storage[3], record[1]);
    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, 2);
    CHECK(PayloadMatches(out, 2, 4));

    /* Move Tail to 126 (mod 32 == 30) and write a maximum record there. */
    BuildPayload(record, 22, 5);
    CHECK_EQ(IwanNtRingPush(&ring, record, 22), IwanNtRingOk);
    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, 22);
    CHECK(PayloadMatches(out, 22, 5));

    BuildPayload(record, 28, 6);
    CHECK_EQ(IwanNtRingPush(&ring, record, 28), IwanNtRingOk);
    CHECK_EQ(ring.Head - ring.Tail, CAPACITY);
    CHECK_EQ(storage[30], 28);
    CHECK_EQ(storage[31], 0);
    CHECK_EQ(storage[0], 0);
    CHECK_EQ(storage[1], 0);
    CHECK_EQ(storage[2], record[0]);
    CHECK_EQ(storage[29], record[27]);
    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, 28);
    CHECK(PayloadMatches(out, 28, 6));
    CHECK_EQ(IwanNtRingPeekLength(&ring, &length), IwanNtRingEmpty);
}

static void
TestCounterExactness(void)
{
    enum { CAPACITY = 48, MAX_RECORD = CAPACITY - 4 };
    uint8_t storage[CAPACITY];
    uint8_t record[50];
    uint8_t out[50];
    IWAN_NT_RING ring;
    size_t length;

    CHECK_EQ(IwanNtRingInitialize(&ring, storage, CAPACITY),
             IwanNtRingOk);

    /* A 5-byte map to a seed, used by every push below. */
    BuildPayload(record, 5, 1);
    CHECK_EQ(IwanNtRingPush(&ring, record, 5), IwanNtRingOk);
    CHECK_EQ(ring.Pushes, 1);
    CHECK_EQ(ring.MaxRecordLength, 5);

    BuildPayload(record, 10, 2);
    CHECK_EQ(IwanNtRingPush(&ring, record, 10), IwanNtRingOk);
    CHECK_EQ(ring.Pushes, 2);
    CHECK_EQ(ring.Head - ring.Tail, 9 + 14);

    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, 5);
    CHECK(PayloadMatches(out, 5, 1));
    CHECK_EQ(ring.Pops, 1);

    BuildPayload(record, 20, 3);
    CHECK_EQ(IwanNtRingPush(&ring, record, 20), IwanNtRingOk);
    CHECK_EQ(ring.Head - ring.Tail, 14 + 24);
    CHECK_EQ(ring.Pushes, 3);
    CHECK_EQ(ring.MaxRecordLength, 20);

    /* Used = 38, free = 10: an 11-byte record drops, a 10-byte record fits. */
    BuildPayload(record, 7, 4);
    CHECK_EQ(IwanNtRingPush(&ring, record, 7), IwanNtRingFull);
    CHECK_EQ(ring.Drops, 1);
    CHECK_EQ(ring.BytesDropped, 7);

    BuildPayload(record, 6, 5);
    CHECK_EQ(IwanNtRingPush(&ring, record, 6), IwanNtRingOk);
    CHECK_EQ(ring.Head - ring.Tail, 48);
    CHECK_EQ(ring.Pushes, 4);
    CHECK_EQ(ring.MaxRecordLength, 20);

    BuildPayload(record, 1, 6);
    CHECK_EQ(IwanNtRingPush(&ring, record, 1), IwanNtRingFull);
    CHECK_EQ(ring.Drops, 2);
    CHECK_EQ(ring.BytesDropped, 8);

    BuildPayload(record, MAX_RECORD + 1, 7);
    CHECK_EQ(IwanNtRingPush(&ring, record, MAX_RECORD + 1),
             IwanNtRingRecordTooLarge);
    CHECK_EQ(ring.Drops, 2);
    CHECK_EQ(ring.BytesDropped, 8);
    CHECK_EQ(ring.MaxRecordLength, MAX_RECORD + 1);

    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, 10);
    CHECK(PayloadMatches(out, 10, 2));
    CHECK_EQ(ring.Pops, 2);

    /* Used = 34, free = 14: a 16-byte record drops, a 10-byte record fits. */
    BuildPayload(record, 12, 8);
    CHECK_EQ(IwanNtRingPush(&ring, record, 12), IwanNtRingFull);
    CHECK_EQ(ring.Drops, 3);
    CHECK_EQ(ring.BytesDropped, 20);

    BuildPayload(record, 6, 9);
    CHECK_EQ(IwanNtRingPush(&ring, record, 6), IwanNtRingOk);
    CHECK_EQ(ring.Pushes, 5);
    CHECK_EQ(ring.Head - ring.Tail, 44);

    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, 20);
    CHECK(PayloadMatches(out, 20, 3));
    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, 6);
    CHECK(PayloadMatches(out, 6, 5));
    CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
             IwanNtRingOk);
    CHECK_EQ(length, 6);
    CHECK(PayloadMatches(out, 6, 9));

    CHECK_EQ(ring.Pushes, 5);
    CHECK_EQ(ring.Pops, 5);
    CHECK_EQ(ring.Drops, 3);
    CHECK_EQ(ring.BytesDropped, 20);
    CHECK_EQ(ring.MaxRecordLength, MAX_RECORD + 1);
    CHECK_EQ(ring.Head, ring.Tail);
    CHECK_EQ(IwanNtRingPeekLength(&ring, &length), IwanNtRingEmpty);
}

/*
 * Deterministic producer/consumer interleaving: one record at a time, except
 * every third round pushes two records before popping both. This exercises the
 * "consumer reads the record, then releases Tail" path with data still queued
 * behind the record being removed.
 *
 * What it proves: FIFO order, exact byte copies, and exact counters for a
 * serial interleaving of Push and Pop, including a record split across the
 * physical end of the storage.
 *
 * What it cannot prove: the acquire/release pair. A serial test cannot run
 * the consumer in the middle of Push, and this host is x86-64, where the CPU
 * already orders ordinary loads and stores. Removing the barriers would not
 * reliably fail this test. The threaded test below adds real concurrency but
 * still runs on this host's memory model, so it also cannot prove that the
 * barriers are present on a weakly ordered machine.
 */
static void
TestSequentialInterleaving(void)
{
    enum { CAPACITY = 64, ROUNDS = 120 };
    uint8_t storage[CAPACITY];
    uint8_t record[32];
    uint8_t out[64];
    IWAN_NT_RING ring;
    size_t length;
    unsigned round;

    CHECK_EQ(IwanNtRingInitialize(&ring, storage, CAPACITY),
             IwanNtRingOk);

    for (round = 0; round < ROUNDS; round++) {
        size_t firstLength = (size_t)((round % 17u) + 1u);
        size_t secondLength = (size_t)(((round * 5u) % 19u) + 1u);

        BuildPayload(record, firstLength, round);
        CHECK_EQ(IwanNtRingPush(&ring, record, firstLength), IwanNtRingOk);

        if ((round % 3u) == 2u) {
            BuildPayload(record, secondLength, round + 1000u);
            CHECK_EQ(IwanNtRingPush(&ring, record, secondLength),
                     IwanNtRingOk);

            CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
                     IwanNtRingOk);
            CHECK_EQ(length, firstLength);
            CHECK(PayloadMatches(out, firstLength, round));

            CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
                     IwanNtRingOk);
            CHECK_EQ(length, secondLength);
            CHECK(PayloadMatches(out, secondLength, round + 1000u));
        } else {
            CHECK_EQ(IwanNtRingPop(&ring, out, sizeof(out), &length),
                     IwanNtRingOk);
            CHECK_EQ(length, firstLength);
            CHECK(PayloadMatches(out, firstLength, round));
        }
    }

    CHECK_EQ(ring.Pushes, 160);
    CHECK_EQ(ring.Pops, 160);
    CHECK_EQ(ring.Drops, 0);
    CHECK_EQ(ring.BytesDropped, 0);
    CHECK_EQ(ring.MaxRecordLength, 19);
    CHECK_EQ(ring.Head, ring.Tail);
    CHECK_EQ(IwanNtRingPeekLength(&ring, &length), IwanNtRingEmpty);
}

#define STRESS_CAPACITY 128
#define STRESS_TOTAL 20000
#define STRESS_MAX_RECORD 33

typedef struct _STRESS_STATE {
    IWAN_NT_RING Ring;
    uint8_t Storage[STRESS_CAPACITY];
    unsigned Total;
    _Atomic int Abort;
    unsigned ProducerError;
    unsigned ConsumerError;
    uint64_t Dropped;
    uint64_t BytesDropped;
} STRESS_STATE;

static size_t
StressLength(
    unsigned Index
    )
{
    return (size_t)((Index % STRESS_MAX_RECORD) + 1u);
}

/*
 * Producer thread. It never blocks in Push: on Full it counts the rejection
 * and retries the same record. The counts it keeps must match the ring's
 * counters after the consumer is drained.
 */
static int
StressProducer(
    void *Argument
    )
{
    STRESS_STATE *state = (STRESS_STATE *)Argument;
    uint8_t record[STRESS_MAX_RECORD];
    unsigned i;

    for (i = 0; i < state->Total; i++) {
        size_t length = StressLength(i);

        BuildPayload(record, length, i);
        for (;;) {
            IWAN_NT_RING_RESULT result;

            if (atomic_load_explicit(&state->Abort,
                                     memory_order_relaxed) != 0) {
                return 0;
            }
            result = IwanNtRingPush(&state->Ring, record, length);
            if (result == IwanNtRingOk) {
                break;
            }
            if (result != IwanNtRingFull) {
                state->ProducerError = 1;
                atomic_store_explicit(&state->Abort, 1,
                                      memory_order_relaxed);
                return 0;
            }
            state->Dropped++;
            state->BytesDropped += (uint64_t)length;
            thrd_yield();
        }
    }
    return 0;
}

/*
 * Consumer thread. Every record must arrive once, in sequence order, with the
 * exact payload the producer generated for that sequence number.
 */
static int
StressConsumer(
    void *Argument
    )
{
    STRESS_STATE *state = (STRESS_STATE *)Argument;
    uint8_t record[STRESS_CAPACITY];
    uint8_t expected[STRESS_MAX_RECORD];
    unsigned received = 0;
    size_t length;

    while (received < state->Total) {
        IWAN_NT_RING_RESULT result;

        if (atomic_load_explicit(&state->Abort,
                                 memory_order_relaxed) != 0) {
            return 0;
        }
        result = IwanNtRingPop(&state->Ring, record, sizeof(record),
                               &length);
        if (result == IwanNtRingEmpty) {
            thrd_yield();
            continue;
        }
        if (result != IwanNtRingOk) {
            state->ConsumerError = 1;
            atomic_store_explicit(&state->Abort, 1, memory_order_relaxed);
            return 0;
        }
        if (length != StressLength(received)) {
            state->ConsumerError = 1;
            atomic_store_explicit(&state->Abort, 1, memory_order_relaxed);
            return 0;
        }
        BuildPayload(expected, length, received);
        if (memcmp(record, expected, length) != 0) {
            state->ConsumerError = 1;
            atomic_store_explicit(&state->Abort, 1, memory_order_relaxed);
            return 0;
        }
        received++;
    }
    return 0;
}

/*
 * Real concurrent 1P1C stress over 20000 records. The producer runs faster
 * than the consumer, so the ring fills and Full/drop/retry paths execute many
 * times. Payloads are derived from the sequence number, so a lost, duplicated,
 * reordered, torn, or overwritten record is detected without any shared queue.
 *
 * What it proves: on this host, concurrent Push and Pop preserve FIFO order,
 * exact bytes, and exact counters after quiescence.
 *
 * What it cannot prove: memory ordering on a weakly ordered CPU. x86-64 does
 * not reorder these loads and stores, so a barrier-free build can pass. It
 * also cannot prove the IRQL contract, which exists only in the real driver.
 */
static void
TestConcurrentInterleaving(void)
{
    static STRESS_STATE state;
    thrd_t producer;
    thrd_t consumer;
    int producerResult = 0;
    int consumerResult = 0;
    int createdProducer;
    int createdConsumer;

    state.Total = STRESS_TOTAL;
    state.ProducerError = 0;
    state.ConsumerError = 0;
    state.Dropped = 0;
    state.BytesDropped = 0;
    atomic_init(&state.Abort, 0);

    CHECK_EQ(IwanNtRingInitialize(&state.Ring, state.Storage,
                                  sizeof(state.Storage)),
             IwanNtRingOk);

    createdProducer = thrd_create(&producer, StressProducer, &state);
    CHECK_EQ(createdProducer, thrd_success);
    if (createdProducer != thrd_success) {
        return;
    }

    createdConsumer = thrd_create(&consumer, StressConsumer, &state);
    CHECK_EQ(createdConsumer, thrd_success);
    if (createdConsumer != thrd_success) {
        atomic_store_explicit(&state.Abort, 1, memory_order_relaxed);
        CHECK_EQ(thrd_join(producer, &producerResult), thrd_success);
        return;
    }

    CHECK_EQ(thrd_join(producer, &producerResult), thrd_success);
    CHECK_EQ(thrd_join(consumer, &consumerResult), thrd_success);
    CHECK_EQ(producerResult, 0);
    CHECK_EQ(consumerResult, 0);
    CHECK_EQ(state.ProducerError, 0);
    CHECK_EQ(state.ConsumerError, 0);
    CHECK_EQ(state.Ring.Pushes, STRESS_TOTAL);
    CHECK_EQ(state.Ring.Pops, STRESS_TOTAL);
    CHECK_EQ(state.Ring.Drops, state.Dropped);
    CHECK_EQ(state.Ring.BytesDropped, state.BytesDropped);
    CHECK_EQ(state.Ring.MaxRecordLength, STRESS_MAX_RECORD);
    CHECK_EQ(state.Ring.Head, state.Ring.Tail);
}

int
main(void)
{
    TestInitializeAndEmpty();
    TestRecordLimits();
    TestWrapAround();
    TestCounterExactness();
    TestSequentialInterleaving();
    TestConcurrentInterleaving();

    printf("ring: %u checks, %u failures\n", gChecks, gFailures);
    return (gFailures == 0) ? 0 : 1;
}
