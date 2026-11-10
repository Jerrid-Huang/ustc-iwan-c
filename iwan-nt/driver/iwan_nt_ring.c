#include "iwan_nt_ring.h"

/*
 * Index ordering primitives.
 *
 * The ring has exactly two synchronizing variables:
 *
 *   Head: release-stored by the producer, acquire-loaded by the consumer.
 *   Tail: release-stored by the consumer, acquire-loaded by the producer.
 *
 * The producer copies a complete record and then release-stores Head. The
 * consumer acquire-loads Head before touching that record, so every copy is
 * visible and no partial record can be observed. The consumer copies the
 * record out and then release-stores Tail. The producer acquire-loads Tail
 * before reusing space, so it cannot overwrite bytes that the consumer is
 * still reading.
 *
 * Each index has exactly one writer, so a single atomic load/store pair per
 * index is sufficient. There is no read-modify-write, no lock, and no need for
 * a compare-exchange. The pair is also what makes the SPSC protocol valid
 * across IRQLs: DISPATCH_LEVEL prevents preemption on the local CPU but does
 * not stop another CPU, so ordering has to come from release/acquire, not
 * from the IRQL.
 *
 * No volatile is used. Volatile can constrain compiler accesses but provides
 * no cross-processor ordering; the operations below are the ordering
 * primitive.
 */
#if defined(__GNUC__) || defined(__clang__)

/*
 * IRQL: any. Ownership: the caller must own the side of the ring that owns
 * Index; this load synchronizes with the other side's release store.
 */
static size_t
IwanNtRingIndexReadAcquire(
    const volatile size_t *Index
    )
{
    return __atomic_load_n(Index, __ATOMIC_ACQUIRE);
}

/*
 * IRQL: any. Ownership: only the single owner of Index may call this; every
 * write sequenced before the store becomes visible before the store itself.
 */
static void
IwanNtRingIndexWriteRelease(
    volatile size_t *Index,
    size_t Value
    )
{
    __atomic_store_n(Index, Value, __ATOMIC_RELEASE);
}

#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))

/*
 * MSVC in WDK C mode has no C11 atomics. On x86 and x64, a naturally aligned
 * size_t load or store is atomic, and the processor already orders loads
 * after loads and stores after stores (TSO). _ReadWriteBarrier keeps the
 * compiler from moving the record bytes across the index access:
 *
 *   release = compiler barrier, then index store
 *   acquire = index load, then compiler barrier
 *
 * This path is deliberately limited to x86/x64. A weak-memory MSVC target
 * stops the build instead of silently weakening the protocol.
 */
void _ReadWriteBarrier(void);
#pragma intrinsic(_ReadWriteBarrier)

/* IRQL: any. Ownership: same contract as the GCC/Clang acquire above. */
static size_t
IwanNtRingIndexReadAcquire(
    const volatile size_t *Index
    )
{
    size_t value = *Index;

    _ReadWriteBarrier();
    return value;
}

/* IRQL: any. Ownership: same contract as the GCC/Clang release above. */
static void
IwanNtRingIndexWriteRelease(
    volatile size_t *Index,
    size_t Value
    )
{
    _ReadWriteBarrier();
    *Index = Value;
}

#else

#error "iWAN NT ring needs __atomic builtins or an MSVC x86/x64 target"

#endif

/*
 * Copy Length bytes into the circular storage starting at logical byte offset
 * Offset. Offset is a monotonic index that may exceed Capacity; only its
 * position modulo Capacity matters. IRQL: caller's IRQL. Ownership: the
 * producer guarantees the destination bytes are free. No barrier is implied.
 */
static void
IwanNtRingCopyInto(
    IWAN_NT_RING *Ring,
    size_t Offset,
    const uint8_t *Source,
    size_t Length
    )
{
    size_t at = Offset % Ring->Capacity;
    size_t first = Ring->Capacity - at;
    size_t i;

    if (first > Length) {
        first = Length;
    }
    for (i = 0; i < first; i++) {
        Ring->Buffer[at + i] = Source[i];
    }
    for (i = 0; i < Length - first; i++) {
        Ring->Buffer[i] = Source[first + i];
    }
}

/*
 * Copy Length bytes out of the circular storage starting at logical byte
 * offset Offset. IRQL: caller's IRQL. Ownership: the consumer guarantees the
 * source range is a published, complete record. No barrier is implied.
 */
static void
IwanNtRingCopyOut(
    const IWAN_NT_RING *Ring,
    size_t Offset,
    uint8_t *Destination,
    size_t Length
    )
{
    size_t at = Offset % Ring->Capacity;
    size_t first = Ring->Capacity - at;
    size_t i;

    if (first > Length) {
        first = Length;
    }
    for (i = 0; i < first; i++) {
        Destination[i] = Ring->Buffer[at + i];
    }
    for (i = 0; i < Length - first; i++) {
        Destination[first + i] = Ring->Buffer[i];
    }
}

/*
 * Encode a record length into the 4-byte little-endian prefix. IRQL: caller's
 * IRQL. Ownership: Prefix is caller-owned scratch. Callers only pass lengths
 * bounded by Capacity, which Initialize limits to UINT32_MAX.
 */
static void
IwanNtRingEncodeLength(
    uint8_t Prefix[IWAN_NT_RING_RECORD_HEADER_LEN],
    size_t Length
    )
{
    Prefix[0] = (uint8_t)((uint32_t)Length & 0xffu);
    Prefix[1] = (uint8_t)(((uint32_t)Length >> 8) & 0xffu);
    Prefix[2] = (uint8_t)(((uint32_t)Length >> 16) & 0xffu);
    Prefix[3] = (uint8_t)(((uint32_t)Length >> 24) & 0xffu);
}

/*
 * Decode the 4-byte little-endian record prefix. IRQL: caller's IRQL.
 * Ownership: Prefix is caller-owned and readable for at least 4 bytes.
 */
static size_t
IwanNtRingDecodeLength(
    const uint8_t *Prefix
    )
{
    uint32_t length = ((uint32_t)Prefix[0]) |
                      ((uint32_t)Prefix[1] << 8) |
                      ((uint32_t)Prefix[2] << 16) |
                      ((uint32_t)Prefix[3] << 24);

    return (size_t)length;
}

/*
 * IRQL: PASSIVE_LEVEL.
 * Ownership: the caller owns Ring and Buffer. No producer or consumer may run
 * concurrently with this call.
 */
IWAN_NT_RING_RESULT
IwanNtRingInitialize(
    IWAN_NT_RING *Ring,
    uint8_t *Buffer,
    size_t Capacity
    )
{
    if (Ring == NULL || Buffer == NULL) {
        return IwanNtRingBadArgument;
    }
    if (Capacity < IWAN_NT_RING_MIN_CAPACITY) {
        return IwanNtRingBadArgument;
    }
    if (Capacity > SIZE_MAX / 2u) {
        return IwanNtRingBadArgument;
    }
    if (Capacity - IWAN_NT_RING_RECORD_HEADER_LEN > (size_t)UINT32_MAX) {
        return IwanNtRingBadArgument;
    }

    Ring->Buffer = Buffer;
    Ring->Capacity = Capacity;
    Ring->Head = 0;
    Ring->Tail = 0;
    Ring->Pushes = 0;
    Ring->Pops = 0;
    Ring->Drops = 0;
    Ring->BytesDropped = 0;
    Ring->MaxRecordLength = 0;
    return IwanNtRingOk;
}

/*
 * IRQL: <= DISPATCH_LEVEL.
 * Ownership: exactly one producer. It owns Head, Pushes, Drops, BytesDropped,
 * and MaxRecordLength. Record stays caller-owned and is only read here.
 */
IWAN_NT_RING_RESULT
IwanNtRingPush(
    IWAN_NT_RING *Ring,
    const uint8_t *Record,
    size_t Length
    )
{
    size_t head;
    size_t tail;
    size_t used;
    size_t total;
    uint8_t prefix[IWAN_NT_RING_RECORD_HEADER_LEN];

    if (Ring == NULL || Record == NULL || Length == 0) {
        return IwanNtRingBadArgument;
    }
    if (Ring->Buffer == NULL ||
        Ring->Capacity < IWAN_NT_RING_MIN_CAPACITY) {
        return IwanNtRingBadArgument;
    }

    /* MaxRecordLength is demand-side telemetry: count every valid attempt. */
    if (Length > Ring->MaxRecordLength) {
        Ring->MaxRecordLength = Length;
    }

    if (Length > Ring->Capacity - IWAN_NT_RING_RECORD_HEADER_LEN) {
        return IwanNtRingRecordTooLarge;
    }

    head = Ring->Head;
    tail = IwanNtRingIndexReadAcquire(&Ring->Tail);
    used = head - tail;
    if (used > Ring->Capacity) {
        return IwanNtRingCorrupt;
    }

    total = IWAN_NT_RING_RECORD_HEADER_LEN + Length;
    if (total > Ring->Capacity - used) {
        Ring->Drops++;
        Ring->BytesDropped += (uint64_t)Length;
        return IwanNtRingFull;
    }

    /*
     * Copy the complete record before publishing Head. A consumer that sees
     * the new Head therefore sees both the prefix and every payload byte.
     */
    IwanNtRingEncodeLength(prefix, Length);
    IwanNtRingCopyInto(Ring, head, prefix,
                       IWAN_NT_RING_RECORD_HEADER_LEN);
    IwanNtRingCopyInto(Ring, head + IWAN_NT_RING_RECORD_HEADER_LEN,
                       Record, Length);

    IwanNtRingIndexWriteRelease(&Ring->Head, head + total);

    Ring->Pushes++;
    return IwanNtRingOk;
}

/*
 * IRQL: PASSIVE_LEVEL.
 * Ownership: exactly one consumer. Ring is only read; Length is caller-owned.
 */
IWAN_NT_RING_RESULT
IwanNtRingPeekLength(
    const IWAN_NT_RING *Ring,
    size_t *Length
    )
{
    size_t head;
    size_t tail;
    size_t used;
    size_t length;
    uint8_t prefix[IWAN_NT_RING_RECORD_HEADER_LEN];

    if (Ring == NULL || Length == NULL) {
        return IwanNtRingBadArgument;
    }
    if (Ring->Buffer == NULL ||
        Ring->Capacity < IWAN_NT_RING_MIN_CAPACITY) {
        return IwanNtRingBadArgument;
    }

    head = IwanNtRingIndexReadAcquire(&Ring->Head);
    tail = Ring->Tail;
    if (head == tail) {
        *Length = 0;
        return IwanNtRingEmpty;
    }

    used = head - tail;
    if (used > Ring->Capacity || used < IWAN_NT_RING_RECORD_HEADER_LEN) {
        return IwanNtRingCorrupt;
    }

    IwanNtRingCopyOut(Ring, tail, prefix,
                      IWAN_NT_RING_RECORD_HEADER_LEN);
    length = IwanNtRingDecodeLength(prefix);
    if (length == 0 ||
        length > Ring->Capacity - IWAN_NT_RING_RECORD_HEADER_LEN) {
        return IwanNtRingCorrupt;
    }
    if (IWAN_NT_RING_RECORD_HEADER_LEN + length > used) {
        return IwanNtRingCorrupt;
    }

    *Length = length;
    return IwanNtRingOk;
}

/*
 * IRQL: PASSIVE_LEVEL.
 * Ownership: exactly one consumer. Out is caller-owned storage of
 * OutCapacity bytes. The record is removed only after a complete copy.
 */
IWAN_NT_RING_RESULT
IwanNtRingPop(
    IWAN_NT_RING *Ring,
    uint8_t *Out,
    size_t OutCapacity,
    size_t *OutLength
    )
{
    size_t head;
    size_t tail;
    size_t used;
    size_t length;
    size_t total;
    uint8_t prefix[IWAN_NT_RING_RECORD_HEADER_LEN];

    if (Ring == NULL || OutLength == NULL) {
        return IwanNtRingBadArgument;
    }
    if (Ring->Buffer == NULL ||
        Ring->Capacity < IWAN_NT_RING_MIN_CAPACITY) {
        return IwanNtRingBadArgument;
    }

    head = IwanNtRingIndexReadAcquire(&Ring->Head);
    tail = Ring->Tail;
    if (head == tail) {
        *OutLength = 0;
        return IwanNtRingEmpty;
    }
    if (Out == NULL) {
        return IwanNtRingBadArgument;
    }

    used = head - tail;
    if (used > Ring->Capacity || used < IWAN_NT_RING_RECORD_HEADER_LEN) {
        return IwanNtRingCorrupt;
    }

    IwanNtRingCopyOut(Ring, tail, prefix,
                      IWAN_NT_RING_RECORD_HEADER_LEN);
    length = IwanNtRingDecodeLength(prefix);
    if (length == 0 ||
        length > Ring->Capacity - IWAN_NT_RING_RECORD_HEADER_LEN) {
        return IwanNtRingCorrupt;
    }
    total = IWAN_NT_RING_RECORD_HEADER_LEN + length;
    if (total > used) {
        return IwanNtRingCorrupt;
    }

    /*
     * Too-small output is a hard error: report the needed size and leave the
     * record queued. Nothing is truncated and Tail is not advanced.
     */
    if (length > OutCapacity) {
        *OutLength = length;
        return IwanNtRingBufferTooSmall;
    }

    IwanNtRingCopyOut(Ring, tail + IWAN_NT_RING_RECORD_HEADER_LEN,
                      Out, length);

    /*
     * Publish the freed space only after the record has been copied out, so
     * the producer cannot overwrite bytes the consumer was still reading.
     */
    IwanNtRingIndexWriteRelease(&Ring->Tail, tail + total);

    Ring->Pops++;
    *OutLength = length;
    return IwanNtRingOk;
}
