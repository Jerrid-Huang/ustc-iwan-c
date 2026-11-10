#ifndef IWAN_NT_TRANSPORT_H
#define IWAN_NT_TRANSPORT_H

#include "iwan_nt_types.h"
#include "iwan_nt_wsk.h"
#include "iwan_nt_wsk_socket.h"
#include "iwan_nt_ingress.h"
#include "iwan_nt_tx.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IWAN_NT_MAX_SENDS 64UL

/*
 * Scratch bytes for one received datagram. The in-place frame transform needs
 * contiguous memory, and a WSK datagram arrives as an MDL chain. The receive
 * lock serializes callbacks, so one buffer serves every datagram.
 */
#define IWAN_NT_SCRATCH_BYTES 2048UL

/* How long Stop waits for in-flight datagrams before closing the socket. */
#define IWAN_NT_TX_DRAIN_MS 2000UL


typedef enum _IWAN_NT_TRANSPORT_STATE {
    IwanNtTransportUninitialized = 0,
    IwanNtTransportStopped,
    IwanNtTransportRunning,
    IwanNtTransportStopping,
    IwanNtTransportFinalizing,
    IwanNtTransportFinalized
} IWAN_NT_TRANSPORT_STATE;

typedef struct _IWAN_NT_TRANSPORT {
    EX_RUNDOWN_REF Rundown;
    KSPIN_LOCK StateLock;
    /*
     * Guards the session that the receive path reads and the send path copies.
     * Lock order, where both are held: datagram ReceiveLock, then SessionLock.
     */
    KSPIN_LOCK SessionLock;
    IWAN_NT_TRANSPORT_STATE State;
    ULONG SendLimit;
    ULONG OutstandingSends;
    BOOLEAN RundownCompleted;
    IWAN_NT_WSK_CLIENT Wsk;
    IWAN_NT_WSK_DATAGRAM Datagram;
    IWAN_NT_INGRESS Ingress;
    IWAN_NT_RING ControlRing;
    BOOLEAN ControlRingInitialized;
    /* Non-paged: the WSK callback runs at IRQL <= DISPATCH_LEVEL. */
    uint8_t *Scratch;
    size_t ScratchCapacity;
    BOOLEAN IngressAttached;
    IWAN_NT_TX Tx;
} IWAN_NT_TRANSPORT, *PIWAN_NT_TRANSPORT;

/* Lifecycle calls are serialized by the owning device and run at PASSIVE_LEVEL. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtTransportInitialize(
    _Out_ PIWAN_NT_TRANSPORT Transport,
    _In_ ULONG SendLimit
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtTransportStart(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportStop(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportFinalize(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    );

/*
 * Session state for the receive path. The session is what makes a datagram
 * "ours": sid, token and the encryption flag come from the user-mode control
 * plane after OPEN/OPEN_ACK. IRQL: PASSIVE_LEVEL; callers serialize against
 * Start/Stop because the receive path reads these fields.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportSetSession(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_ const IWAN_NT_INGRESS_SESSION *Session
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportClearSession(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    );

/* Decrypted inner packet destination and the control queue storage. */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportSetDataSink(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_opt_ IWAN_NT_INGRESS_DATA_SINK Sink,
    _In_opt_ void *Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportSetControlRing(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_reads_bytes_opt_(StorageBytes) uint8_t *Storage,
    _In_ size_t StorageBytes
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
IwanNtTransportGetIngressCounters(
    _In_ PIWAN_NT_TRANSPORT Transport,
    _Out_ IWAN_NT_INGRESS_COUNTERS *Counters
    );

/* Peer endpoint for the send path. IRQL: PASSIVE_LEVEL. */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportSetPeer(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_ const SOCKADDR_IN *Remote
    );

/*
 * Encapsulate one inner packet and submit it as one outer datagram.
 *
 * IRQL: <= DISPATCH_LEVEL.
 * Ownership: Inner is read only; the payload is copied into a slot.
 * Returns STATUS_INVALID_DEVICE_STATE when there is no session or peer,
 * STATUS_INSUFFICIENT_RESOURCES when every slot is busy (backpressure, not an
 * error), and the provider status otherwise.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
IwanNtTransportSendInner(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_reads_bytes_(InnerLength) const uint8_t *Inner,
    _In_ size_t InnerLength
    );

/* These two routines reserve bounded send slots for future transport I/O. */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
IwanNtTransportTryAcquireSend(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
IwanNtTransportReleaseSend(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    );

#ifdef __cplusplus
}
#endif

#endif
