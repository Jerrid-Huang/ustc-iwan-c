#ifndef IWAN_NT_RING_H
#define IWAN_NT_RING_H

/*
 * iWAN NT control-frame byte ring.
 *
 * A bounded, lock-free, single-producer/single-consumer queue of
 * variable-length byte records. This module has no kernel dependency: it uses
 * only size_t and fixed-width integers, performs no allocation, takes no
 * locks, and makes no kernel calls. The same source builds inside the WDK and
 * in a host unit test.
 *
 * Storage is caller-supplied and its capacity is fixed by
 * IwanNtRingInitialize. One producer runs at IRQL <= DISPATCH_LEVEL (the WSK
 * receive callback) and one consumer runs at PASSIVE_LEVEL. Push never blocks:
 * if the record does not fit, it fails and counts a full drop. IWAN_NT_RING
 * must be naturally aligned and must not be packed: Head and Tail are accessed
 * with word-sized atomic loads and stores.
 *
 * Buffer layout of one record:
 *
 *   +0   length  (4 B, little-endian, payload bytes only)
 *   +4   payload (length B, copied verbatim)
 *
 * Records are packed back-to-back in a circular byte buffer. Either the
 * 4-byte length or the payload may wrap across the physical end of Buffer.
 * The length is internal metadata and never leaves this module.
 *
 * Ordering contract:
 *
 *   producer: copy record bytes; release-store Head
 *   consumer: acquire-load Head; copy record bytes
 *   consumer: release-store Tail
 *   producer: acquire-load Tail; reuse the freed space
 *
 * Only the producer writes Head and only the consumer writes Tail, so each
 * index has one writer and no read-modify-write is needed. The release store
 * publishes every byte written before it; the matching acquire load prevents
 * later accesses from moving before it. A record observed through Head is
 * therefore complete, and space observed through Tail is no longer being
 * read. See driver/iwan_nt_ring.c for the primitives and the proof sketch.
 *
 * The counters are diagnostic state, not part of the transport. Each counter
 * has exactly one writer: the producer owns Pushes, Drops, BytesDropped, and
 * MaxRecordLength; the consumer owns Pops. Read them after quiescing the ring
 * when an exact, coherent snapshot is required.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SAL spellings a host compiler does not provide. Each macro is guarded
 * on its own: these kernel-free headers include one another, so one
 * shared outer guard would leave a later header with an incomplete set.
 */
#ifndef _In_
#define _In_
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Inout_
#define _Inout_
#endif
#ifndef _In_opt_
#define _In_opt_
#endif
#ifndef _Out_opt_
#define _Out_opt_
#endif
#ifndef _Out_writes_
#define _Out_writes_(n)
#endif
#ifndef _In_reads_bytes_
#define _In_reads_bytes_(n)
#endif
#ifndef _In_reads_bytes_opt_
#define _In_reads_bytes_opt_(n)
#endif
#ifndef _Inout_updates_bytes_
#define _Inout_updates_bytes_(n)
#endif
#ifndef _Out_writes_bytes_to_
#define _Out_writes_bytes_to_(c, l)
#endif
#ifndef _Out_writes_bytes_opt_
#define _Out_writes_bytes_opt_(n)
#endif
#ifndef _Outptr_result_buffer_
#define _Outptr_result_buffer_(n)
#endif
#ifndef _Out_writes_bytes_
#define _Out_writes_bytes_(n)
#endif
#ifndef _Inout_updates_bytes_opt_
#define _Inout_updates_bytes_opt_(n)
#endif

/* Bytes of length metadata in front of every record. */
#define IWAN_NT_RING_RECORD_HEADER_LEN 4u

/* Smallest capacity that can hold a one-byte record. */
#define IWAN_NT_RING_MIN_CAPACITY \
    (IWAN_NT_RING_RECORD_HEADER_LEN + 1u)

typedef enum _IWAN_NT_RING_RESULT {
    IwanNtRingOk = 0,
    IwanNtRingBadArgument,     /* NULL pointer, zero length, bad capacity */
    IwanNtRingEmpty,           /* consumer found no record */
    IwanNtRingFull,            /* record would fit an empty ring, not now */
    IwanNtRingRecordTooLarge,  /* record can never fit this ring */
    IwanNtRingBufferTooSmall,  /* output buffer smaller than the record */
    IwanNtRingCorrupt          /* internal metadata invariant failed */
} IWAN_NT_RING_RESULT;

typedef struct _IWAN_NT_RING {
    uint8_t *Buffer;        /* caller-owned storage, Capacity bytes */
    size_t Capacity;        /* fixed byte capacity, prefixes included */
    /*
     * Head and Tail are volatile so the MSVC path re-reads them on every
     * access instead of caching them in a register; the GCC/Clang path uses
     * __atomic builtins on these same objects, which supplies the ordering
     * that volatile alone would not.
     */
    volatile size_t Head;   /* producer index, monotonic byte count */
    volatile size_t Tail;   /* consumer index, monotonic byte count */
    uint64_t Pushes;        /* records successfully enqueued */
    uint64_t Pops;          /* records successfully dequeued */
    uint64_t Drops;         /* Push calls rejected by fullness */
    uint64_t BytesDropped;  /* payload bytes of Drops, prefixes excluded */
    size_t MaxRecordLength; /* largest valid Length seen by Push */
} IWAN_NT_RING, *PIWAN_NT_RING;

/*
 * Initialize an empty ring over caller-supplied storage.
 *
 * IRQL: PASSIVE_LEVEL.
 * Ownership: Ring and Buffer stay owned by the caller and must outlive every
 * use of the ring. Buffer must not be freed, resized, or written by anyone
 * else while the ring is live. No Push or Pop may run concurrently with this
 * call. Buffer contents are not read or initialized. If Push can run at
 * DISPATCH_LEVEL, Ring and Buffer must be non-paged (or locked resident) for
 * the ring's lifetime; this module neither allocates nor locks pages.
 *
 * Capacity is in bytes and fixed for the ring's lifetime. It must be at least
 * IWAN_NT_RING_MIN_CAPACITY, at most SIZE_MAX / 2 (so monotonic indices
 * cannot alias), and at most UINT32_MAX + the record header (record lengths
 * are stored in a 32-bit prefix). Returns IwanNtRingBadArgument otherwise.
 */
IWAN_NT_RING_RESULT
IwanNtRingInitialize(
    _Out_ IWAN_NT_RING *Ring,
    _In_ uint8_t *Buffer,
    _In_ size_t Capacity
    );

/*
 * Copy one whole record into the ring without blocking.
 *
 * IRQL: <= DISPATCH_LEVEL.
 * Ownership: exactly one producer calls Push, and that producer is the only
 * writer of Head, Pushes, Drops, BytesDropped, and MaxRecordLength. Record is
 * caller-owned and is read only during this call; it may be freed or reused
 * as soon as Push returns. Record must not overlap Buffer or Ring; Push does
 * not support aliasing. The caller must serialize all pushes.
 *
 * A successful push copies the complete record before release-publishing
 * Head, so the consumer can never observe a partial record. A failed push
 * writes no ring bytes. A record longer than Capacity - header can never fit
 * and is rejected with IwanNtRingRecordTooLarge; it is not a fullness drop.
 * Otherwise, if the current free space is too small, the call returns
 * IwanNtRingFull and counts one drop plus Length dropped payload bytes.
 *
 * MaxRecordLength records the largest valid Length ever passed to Push
 * (nonzero, with a non-NULL Record), including lengths that were rejected, so
 * demanded record sizes remain observable. Length zero is rejected as
 * IwanNtRingBadArgument.
 */
IWAN_NT_RING_RESULT
IwanNtRingPush(
    _Inout_ IWAN_NT_RING *Ring,
    _In_reads_bytes_(Length) const uint8_t *Record,
    _In_ size_t Length
    );

/*
 * Read the length of the next record without removing it.
 *
 * IRQL: PASSIVE_LEVEL.
 * Ownership: exactly one consumer calls PeekLength and Pop, in that order or
 * independently. PeekLength does not modify the ring or its counters. Length
 * is caller-owned; it receives 0 on IwanNtRingEmpty, the record length on
 * IwanNtRingOk, and is unchanged on IwanNtRingBadArgument or
 * IwanNtRingCorrupt.
 */
IWAN_NT_RING_RESULT
IwanNtRingPeekLength(
    _In_ const IWAN_NT_RING *Ring,
    _Out_ size_t *Length
    );

/*
 * Copy out and remove the next record in one call.
 *
 * IRQL: PASSIVE_LEVEL.
 * Ownership: the same single consumer that calls PeekLength; it is the only
 * reader of ring records and the only writer of Tail and Pops. Out is
 * caller-owned storage of OutCapacity bytes and must not overlap Buffer or
 * Ring; Pop does not support aliasing. The record is written only if it fits,
 * and only then is it removed and Tail release-published.
 *
 * If the record is longer than OutCapacity, the call returns
 * IwanNtRingBufferTooSmall, sets OutLength to the required length, and leaves
 * the record queued. Overrunning the caller's buffer is a hard error, never a
 * truncation. If the ring is empty, the call returns IwanNtRingEmpty and sets
 * OutLength to 0. Out == NULL is IwanNtRingBadArgument for a non-empty ring.
 * OutLength is unchanged on IwanNtRingBadArgument and IwanNtRingCorrupt.
 */
IWAN_NT_RING_RESULT
IwanNtRingPop(
    _Inout_ IWAN_NT_RING *Ring,
    _Out_writes_bytes_opt_(OutCapacity) uint8_t *Out,
    _In_ size_t OutCapacity,
    _Out_ size_t *OutLength
    );

#ifdef __cplusplus
}
#endif

#endif
