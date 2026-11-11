#ifndef IWAN_NT_TRANSPORT_H
#define IWAN_NT_TRANSPORT_H

#include "iwan_nt_types.h"
#include "iwan_nt_wsk.h"
#include "iwan_nt_wsk_socket.h"
#include "iwan_nt_ingress.h"
#include "iwan_nt_peer.h"
#include "iwan_nt_tx.h"
#include "iwan_nt_ioctl.h"

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
    /*
     * Family the socket is (re)started with. The peer decides it, but the
     * adapter can start before any peer is known, so it defaults to IPv4.
     */
    uint16_t SocketFamily;
    IWAN_NT_INGRESS Ingress;
    IWAN_NT_RING ControlRing;
    BOOLEAN ControlRingInitialized;
    /* Non-paged: the WSK callback runs at IRQL <= DISPATCH_LEVEL. */
    uint8_t *Scratch;
    size_t ScratchCapacity;
    BOOLEAN IngressAttached;
    IWAN_NT_TX Tx;
    /*
     * The peer owns the handshake. It lives in the driver for the same reason
     * WireGuard's does: the socket belongs to the kernel, so the frames that
     * keep the session alive have to be produced and consumed here.
     */
    IWAN_NT_PEER Peer;
    BOOLEAN PeerReady;
    /* Control-plane counters; one writer each, see the getter below. */
    ULONG64 ControlSent;
    ULONG64 ControlSendFailed;
    ULONG64 ControlRead;
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

/*
 * Peer endpoint for the send path, in either family. IRQL: PASSIVE_LEVEL.
 *
 * The socket family is fixed when the socket is created, so a peer in the other
 * family forces the transport to recycle the socket: it drains the send pool,
 * stops the datagram socket, and starts a new one with that family. The session
 * and the receive path are untouched. Returns the provider status when the new
 * socket cannot be created; the transport is Stopped in that case, because a
 * Running transport with no socket would report success and carry nothing.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtTransportSetPeer(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_ const IWAN_NT_SOCKADDR *Remote
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
/*
 * The address the transport's socket is bound to. Available while the transport
 * is running; used by the control device so the operator can see the port the
 * peer will answer to.
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IwanNtTransportGetLocal(
    _In_ const IWAN_NT_TRANSPORT *Transport,
    _Out_ PIWAN_NT_SOCKADDR Local
    );

_IRQL_requires_(PASSIVE_LEVEL)
/*
 * Install the credentials and start the handshake.
 *
 * IRQL: PASSIVE_LEVEL.
 * Called once the peer address is known; from then on the driver keeps the
 * session up by itself and reports state changes through the control device.
 */
NTSTATUS
IwanNtTransportStartPeer(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_reads_z_(64) const char *User,
    _In_reads_z_(64) const char *Password,
    _In_ uint16_t Mtu
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportStopPeer(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
/*
 * Encapsulate and submit up to Count inner packets under one provider call.
 *
 * IRQL: <= DISPATCH_LEVEL.
 * The items are wrapped in a single frame header, so they all have to belong to
 * the same inner family; a mixed batch is rejected rather than half sent.
 */
NTSTATUS
IwanNtTransportSendInnerBatch(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_reads_(Count) const IWAN_NT_TX_ITEM *Items,
    _In_ ULONG Count,
    _Out_ PULONG Accepted
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
IwanNtTransportSendInner(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_reads_bytes_(InnerLength) const uint8_t *Inner,
    _In_ size_t InnerLength
    );

/*
 * Send one complete control datagram payload verbatim.
 *
 * IRQL: PASSIVE_LEVEL.
 * The caller builds the frame header, the 16-byte signature and every TLV;
 * this path copies the bytes into a send slot and submits them unchanged.
 * Returns STATUS_INVALID_DEVICE_STATE when the transport is not Running or no
 * peer is installed, STATUS_INSUFFICIENT_RESOURCES when the pool is full.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtTransportSendControl(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_reads_bytes_(Length) const uint8_t *Payload,
    _In_ size_t Length
    );

/*
 * Dequeue one complete control datagram payload.
 *
 * IRQL: PASSIVE_LEVEL.
 * Single consumer: the control device serializes callers. On
 * STATUS_BUFFER_TOO_SMALL the frame stays queued and Required receives its
 * length, so a caller can retry with a larger buffer without losing it.
 * Returns STATUS_NO_MORE_ENTRIES when the ring is empty.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtTransportReadControl(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _Out_writes_bytes_opt_(Capacity) uint8_t *Out,
    _In_ size_t Capacity,
    _Out_ size_t *OutLength,
    _Out_opt_ size_t *Required
    );

/*
 * Snapshot every counter the transport owns.
 *
 * IRQL: PASSIVE_LEVEL.
 * TxAccepted, TxRejected, RxIndicated and RxDropped belong to the adapter, so
 * they are left zero here; the control device overlays them from its counter
 * source and this module never has to know about the miniport.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportGetStats(
    _In_ PIWAN_NT_TRANSPORT Transport,
    _Out_ IWAN_NT_STATS_ABI *Stats
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
