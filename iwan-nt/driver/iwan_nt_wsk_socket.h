#ifndef IWAN_NT_WSK_SOCKET_H
#define IWAN_NT_WSK_SOCKET_H

#include "iwan_nt_types.h"
#if defined(IWAN_NT_KERNEL)
#include <wsk.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This module owns one IPv4 UDP socket. The local port is zero so the
 * transport does not invent a user-mode or control-plane configuration.
 * A later stage can replace the address before Start when that interface is
 * defined.
 */
#define IWAN_NT_WSK_DATAGRAM_PORT 0U

typedef enum _IWAN_NT_WSK_DATAGRAM_STATE {
    IwanNtWskDatagramUninitialized = 0,
    IwanNtWskDatagramStopped,
    IwanNtWskDatagramStarting,
    IwanNtWskDatagramRunning,
    IwanNtWskDatagramStopping,
    IwanNtWskDatagramFinalized
} IWAN_NT_WSK_DATAGRAM_STATE;

/*
 * The context is embedded in the transport owner and must remain allocated
 * until Finalize succeeds. Callers serialize Initialize/Start/Stop/Finalize
 * at PASSIVE_LEVEL. The callback may run at IRQL <= DISPATCH_LEVEL.
 *
 * WDK assumptions isolated here:
 * - the project is compiled as C and includes the Windows 10 WDK wsk.h;
 * - WSK_PROVIDER_BASIC_DISPATCH is the anonymous prefix of the C dispatch
 *   tables, so the implementation casts Socket->Dispatch to that type;
 * - WskSocket, WskBind, WskControlSocket (disable path) and WskCloseSocket
 *   use a caller-owned IRP and report the outcome through that IRP, on both
 *   the immediate and the pending submission path;
 * - the event callback consumes the complete indication list and returns
 *   STATUS_SUCCESS, so no indication list is retained across the callback.
 *
 * Two independent run-down objects fence the two kinds of WSK activity:
 * OperationRundown tracks calls that are entering provider code, and
 * CallbackRundown tracks the event callback. Neither is ever reinitialized
 * while an operation is in flight; both are completed only after their wait
 * returned.
 */
/*
 * Hand one received datagram to the owner for processing.
 *
 * IRQL: <= DISPATCH_LEVEL, inside the receive lock.
 * Ownership: Payload points into the datagram scratch buffer, which is reused
 * by the next datagram, so the sink must consume it synchronously or copy it
 * out. The sink must not block, must not allocate, and must not call back into
 * this datagram.
 *
 * The scratch buffer exists because the frame transform is in-place and needs
 * contiguous bytes, while a WSK datagram arrives as an MDL chain. One buffer
 * is enough because the receive lock serializes callbacks; it costs one copy
 * per datagram, which is the deliberate first-stage trade against the pool and
 * direct-MDL transform that a later stage adds.
 */
typedef void (*IWAN_NT_WSK_DATAGRAM_RECEIVE_SINK)(
    _In_opt_ void *Context,
    _Inout_updates_bytes_(Length) uint8_t *Payload,
    _In_ size_t Length
    );

typedef struct _IWAN_NT_WSK_DATAGRAM {
    KSPIN_LOCK StateLock;
    /* Serializes datagrams so the in-place transform stays single-threaded. */
    KSPIN_LOCK ReceiveLock;
    EX_RUNDOWN_REF OperationRundown;
    EX_RUNDOWN_REF CallbackRundown;
    KEVENT LifecycleEvent;
    KEVENT FaultEvent;
    SOCKADDR_IN LocalAddress;
    /* Kept from Start so that the send path can reach the dispatch table. */
    WSK_PROVIDER_NPI Provider;
    PWSK_SOCKET Socket;
    PIRP LifecycleIrp;
    ULONG IndicationCount;
    IWAN_NT_WSK_DATAGRAM_STATE State;
    BOOLEAN OperationRundownClosed;
    BOOLEAN CallbackRundownClosed;
    BOOLEAN LifecycleIrpUsed;
    BOOLEAN LifecycleBusy;
    BOOLEAN SocketCreated;
    BOOLEAN SocketBound;
    BOOLEAN ReceiveEnabled;
    BOOLEAN CloseIssued;
    BOOLEAN CloseCompleted;
    BOOLEAN CloseRequired;
    /* Receive plumbing; NULL until AttachReceive runs and after Detach. */
    uint8_t *Scratch;
    size_t ScratchCapacity;
    IWAN_NT_WSK_DATAGRAM_RECEIVE_SINK ReceiveSink;
    void *ReceiveSinkContext;
    ULONG OversizeDrops;
    ULONG SinkErrors;
} IWAN_NT_WSK_DATAGRAM, *PIWAN_NT_WSK_DATAGRAM;

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtWskDatagramInitialize(
    _Out_ PIWAN_NT_WSK_DATAGRAM Datagram
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtWskDatagramStart(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_ const WSK_PROVIDER_NPI *Provider
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtWskDatagramStop(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtWskDatagramFinalize(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram
    );

/*
 * Install the receive path.
 *
 * IRQL: PASSIVE_LEVEL, before Start and after Stop; no callback may be running.
 * Ownership: Scratch stays owned by the caller and must be non-paged, because
 * the callback runs at IRQL <= DISPATCH_LEVEL. Neither pointer is retained
 * beyond Detach. A NULL sink detaches the path, which makes the callback drop
 * datagrams instead of processing them.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtWskDatagramAttachReceive(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_reads_bytes_opt_(ScratchCapacity) uint8_t *Scratch,
    _In_ size_t ScratchCapacity,
    _In_opt_ IWAN_NT_WSK_DATAGRAM_RECEIVE_SINK Sink,
    _In_opt_ void *Context
    );

/*
 * Submit one datagram to the peer.
 *
 * IRQL: <= DISPATCH_LEVEL. The caller owns Buffer->Mdl and Irp; WSK does not
 * copy datagrams, so both must stay valid until the IRP completes. The caller
 * must also have arranged that no send is outstanding when Stop closes the
 * socket, because closing cancels pending IRPs.
 *
 * Returns the status of the submit call itself. A pending status means the IRP
 * will complete later; any other status means WSK rejected it immediately and
 * the IRP is not in use.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
IwanNtWskDatagramSubmitSend(
    _In_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_ PMDL Mdl,
    _In_ ULONG Length,
    _In_ const SOCKADDR_IN *Remote,
    _In_ PIRP Irp
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
IwanNtWskDatagramCloseRequired(
    _In_ PIWAN_NT_WSK_DATAGRAM Datagram
    );

#ifdef __cplusplus
}
#endif

#endif
