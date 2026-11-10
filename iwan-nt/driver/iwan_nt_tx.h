#ifndef IWAN_NT_TX_H
#define IWAN_NT_TX_H

#include <ntddk.h>
#include "iwan_nt_types.h"

#include "iwan_nt_frame.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Outbound slot pool.
 *
 * The send path must not allocate on the transmit path: an NDIS send can arrive
 * at DISPATCH_LEVEL, where neither IRPs nor MDLs may be created. Every slot is
 * therefore built once at PASSIVE_LEVEL and recycled by the IRP completion
 * routine, which runs at DISPATCH_LEVEL.
 *
 * One slot per outstanding datagram. The depth bounds how many sends may be in
 * flight at once; a send that finds no free slot fails instead of queueing, so
 * backpressure reaches the NDIS caller as NDIS_STATUS_RESOURCES rather than as
 * unbounded kernel memory.
 */
#define IWAN_NT_TX_SLOTS 32UL
#define IWAN_NT_TX_BUFFER_BYTES 2048UL

typedef struct _IWAN_NT_TX IWAN_NT_TX, *PIWAN_NT_TX;

typedef struct _IWAN_NT_TX_SLOT {
    struct _IWAN_NT_TX *Owner;
    PVOID Buffer;
    PMDL Mdl;
    PIRP Irp;
    ULONG Index;
    BOOLEAN InUse;
} IWAN_NT_TX_SLOT, *PIWAN_NT_TX_SLOT;

/*
 * Submit one datagram. Implemented by the socket layer; the pool only decides
 * when to call it.
 */
typedef NTSTATUS (*IWAN_NT_TX_SUBMIT)(
    _In_opt_ void *Context,
    _In_ PMDL Mdl,
    _In_ ULONG Length,
    _In_ const SOCKADDR_IN *Remote,
    _In_ PIRP Irp
    );

struct _IWAN_NT_TX {
    KSPIN_LOCK Lock;
    KEVENT IdleEvent;
    IWAN_NT_TX_SUBMIT Submit;
    void *SubmitContext;
    SOCKADDR_IN Remote;
    BOOLEAN RemoteValid;
    ULONG SlotCount;
    ULONG FreeCount;
    ULONG InFlight;
    /* Counters are updated under Lock, so they stay exact. */
    ULONG64 Submitted;
    ULONG64 Completed;
    ULONG64 SubmitErrors;
    ULONG64 NoSlot;
    ULONG64 TooLarge;
    IWAN_NT_TX_SLOT Slots[IWAN_NT_TX_SLOTS];
};

/*
 * Build the slot pool.
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
 * Release the pool. The caller must have stopped sending and waited for
 * IwanNtTxWaitIdle, because a completion routine touch of a freed slot cannot
 * be recovered from.
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
    _In_ const SOCKADDR_IN *Remote
    );

/*
 * Transform one inner packet and submit it as one outer datagram.
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
 * Wait until no datagram is in flight.
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

#ifdef __cplusplus
}
#endif

#endif
