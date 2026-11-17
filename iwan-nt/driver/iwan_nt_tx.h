#ifndef IWAN_NT_TX_H
#define IWAN_NT_TX_H

#include "iwan_nt_types.h"
#include "iwan_nt_addr.h"

#include "iwan_nt_frame.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Outbound slot pool with a deferred submit queue.
 *
 * The send path must not allocate on the transmit path: an NDIS send can arrive
 * at DISPATCH_LEVEL, where neither IRPs nor MDLs may be created. Every slot is
 * therefore built once at PASSIVE_LEVEL and recycled by the IRP completion
 * routine, which runs at DISPATCH_LEVEL.
 *
 * The pool also decides *when* to talk to the socket. One WskSendMessages call
 * costs far more than copying a packet, and the stack hands the miniport one
 * NBL per call, so submitting inside the NDIS send call means one provider call
 * per packet. Instead, every staged packet joins a pending chain which a system
 * thread drains in batches, and the miniport completes the NBL as soon as the
 * bytes have been copied into a slot. Measured on the test link: batch size 1
 * gave ~15 kpps, and the cost was per-submit, not per-byte (64 B and 1400 B
 * payloads reached the same packet rate).
 *
 * One slot per staged datagram. The depth bounds how many sends may be in
 * flight at once; a send that finds no free slot fails instead of queueing, so
 * backpressure reaches the NDIS caller as NDIS_STATUS_RESOURCES rather than as
 * unbounded kernel memory.
 */
#define IWAN_NT_TX_SLOTS 128UL
#define IWAN_NT_TX_BUFFER_BYTES 2048UL

/*
 * Largest number of frames handed to the provider in one call. This is the
 * batching window: with a 1 ms drain interval it fills at roughly packets per
 * millisecond, so it only caps very fast links.
 */
#define IWAN_NT_TX_MAX_CHAIN 32UL

/*
 * How long the drain thread waits for the pending chain to grow before it
 * submits what it has. This is only a safety net: the send path submits by
 * itself as soon as it has a worthwhile chain, and signals the thread for the
 * tail it leaves behind.
 */
#define IWAN_NT_TX_DRAIN_INTERVAL_MS 1UL

/*
 * Chain length the send path submits itself, from inside the NDIS send call.
 *
 * Measured, not guessed: a fixed polling interval (1 ms) grew the chain to 23
 * frames per call but cost too much latency and dropped the link from 30 kpps
 * to 20 kpps; submitting every frame immediately cost one provider call per
 * packet. This threshold takes the middle: no added latency under load, and one
 * provider call per cluster of frames instead of per frame.
 */
#define IWAN_NT_TX_INLINE_THRESHOLD 8UL

typedef struct _IWAN_NT_TX IWAN_NT_TX, *PIWAN_NT_TX;

typedef struct _IWAN_NT_TX_SLOT {
    struct _IWAN_NT_TX *Owner;
    PVOID Buffer;
    PMDL Mdl;
    PIRP Irp;
    WSK_BUF_LIST List;
    ULONG Index;
    BOOLEAN InUse;
    /* Set while the slot hangs on the pending chain, waiting for the drain. */
    BOOLEAN Staged;
} IWAN_NT_TX_SLOT, *PIWAN_NT_TX_SLOT;

/*
 * Submit one or more datagrams. Implemented by the socket layer; the pool only
 * decides when to call it. A single IRP covers the whole chain, so the slot
 * that owns the IRP releases every slot in the batch when it completes.
 */
typedef NTSTATUS (*IWAN_NT_TX_SUBMIT)(
    _In_opt_ void *Context,
    _In_ PWSK_BUF_LIST List,
    _In_ ULONG Messages,
    _In_ const IWAN_NT_SOCKADDR *Remote,
    _In_ PIRP Irp
    );

/*
 * One inner packet of a batch. The header and key are shared by the batch,
 * because a batch belongs to a single session and a single frame type.
 */
typedef struct _IWAN_NT_TX_ITEM {
    const uint8_t *Inner;
    size_t InnerLength;
} IWAN_NT_TX_ITEM, *PIWAN_NT_TX_ITEM;

struct _IWAN_NT_TX {
    KSPIN_LOCK Lock;
    KEVENT IdleEvent;
    IWAN_NT_TX_SUBMIT Submit;
    void *SubmitContext;
    IWAN_NT_SOCKADDR Remote;
    BOOLEAN RemoteValid;
    ULONG SlotCount;
    /*
     * One batch is one submit, which is one WskSendMessages call. Accepted/this
     * is the average number of frames handed to the socket at once, which is the
     * number to watch when per-frame cost dominates.
     */
    ULONG Batches;
    ULONG FreeCount;
    ULONG InFlight;
    /* Counters are updated under Lock, so they stay exact. */
    ULONG64 Submitted;
    ULONG64 Completed;
    ULONG64 SubmitErrors;
    ULONG64 NoSlot;
    ULONG64 TooLarge;
    /* Largest chain the drain thread ever built; proves batching is working. */
    ULONG64 MaxBatch;
    IWAN_NT_TX_SLOT Slots[IWAN_NT_TX_SLOTS];

    /* Deferred submit queue: filled slots waiting for the drain thread. */
    PIWAN_NT_TX_SLOT PendingHead;
    PIWAN_NT_TX_SLOT PendingTail;
    ULONG PendingCount;
    KEVENT DrainEvent;
    PVOID DrainThread;
    BOOLEAN DrainStop;
    BOOLEAN DrainRunning;
};

/*
 * Build the slot pool and start the drain thread.
 *
 * IRQL: PASSIVE_LEVEL.
 * Ownership: Tx is caller-owned and must outlive every send.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtTxInitialize(
    _Out_ PIWAN_NT_TX Tx,
    _In_ IWAN_NT_TX_SUBMIT Submit,
    _In_opt_ void *SubmitContext
    );

/*
 * Release the pool. Stops and waits for the drain thread, then flushes what is
 * still pending, and finally requires that nothing is in flight: a completion
 * routine touch of a freed slot cannot be recovered from.
 *
 * IRQL: PASSIVE_LEVEL.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTxFinalize(
    _Inout_ PIWAN_NT_TX Tx
    );

/* Peer address for every subsequent send. IRQL: PASSIVE_LEVEL. */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTxSetRemote(
    _Inout_ PIWAN_NT_TX Tx,
    _In_ const IWAN_NT_SOCKADDR *Remote
    );

/*
 * Transform one inner packet and submit it as one outer datagram, without
 * batching.
 *
 * IRQL: <= DISPATCH_LEVEL.
 * Ownership: Inner is read only and may be released when this returns; the
 * payload is copied into the slot before the submit.
 *
 * Returns STATUS_SUCCESS when the datagram was accepted by the provider, a
 * pending status when it was submitted and will complete later (counted as
 * accepted), STATUS_INSUFFICIENT_RESOURCES when every slot is busy, and
 * STATUS_INVALID_PARAMETER when the inner packet does not fit.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
IwanNtTxSend(
    _Inout_ PIWAN_NT_TX Tx,
    _In_ const IWAN_NT_FRAME_HEADER *Header,
    _In_reads_bytes_opt_(IWAN_NT_FRAME_KEY_LEN) const uint8_t *Key,
    _In_reads_bytes_(InnerLength) const uint8_t *Inner,
    _In_ size_t InnerLength
    );

/*
 * Stage up to Count inner packets for the next batched submit.
 *
 * IRQL: <= DISPATCH_LEVEL.
 * Ownership: Inner is copied before this returns, so the caller may release
 * the packet immediately, even though the submit happens later.
 *
 * Returns the number of packets staged (0..Count) through Accepted, and a
 * status that is an error only when nothing was staged. A short batch is
 * backpressure: the caller keeps the remainder and reports it as resources.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
IwanNtTxSendBatch(
    _Inout_ PIWAN_NT_TX Tx,
    _In_ const IWAN_NT_FRAME_HEADER *Header,
    _In_reads_bytes_opt_(IWAN_NT_FRAME_KEY_LEN) const uint8_t *Key,
    _In_reads_(Count) const IWAN_NT_TX_ITEM *Items,
    _In_ ULONG Count,
    _Out_ PULONG Accepted
    );

/*
 * Submit one already-assembled datagram payload verbatim, without batching.
 *
 * IRQL: <= DISPATCH_LEVEL.
 * Used by the control plane: OPEN, OPEN_ACK, ECHO and CLOSE frames are built
 * in user mode (header, signature and TLVs included), so this path performs
 * no transform at all and must not wait for the drain thread.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
IwanNtTxSendRaw(
    _Inout_ PIWAN_NT_TX Tx,
    _In_reads_bytes_(Length) const uint8_t *Payload,
    _In_ size_t Length
    );

/*
 * Wait until nothing is staged or in flight. Pending frames are flushed first.
 *
 * IRQL: PASSIVE_LEVEL.
 * Returns TRUE when the pool drained, FALSE on timeout. A timeout is a real
 * failure: the caller must not close the socket or free the pool afterwards.
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IwanNtTxWaitIdle(
    _Inout_ PIWAN_NT_TX Tx,
    _In_ ULONG TimeoutMilliseconds
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
IwanNtTxInFlight(
    _In_ PIWAN_NT_TX Tx
    );

/* Frames staged but not yet handed to the provider. IRQL: any. */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
IwanNtTxPending(
    _In_ PIWAN_NT_TX Tx
    );

#ifdef __cplusplus
}
#endif

#endif
