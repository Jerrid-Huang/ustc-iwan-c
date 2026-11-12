#ifndef IWAN_NT_WSK_SOCKET_H
#define IWAN_NT_WSK_SOCKET_H

#include "iwan_nt_types.h"
#include "iwan_nt_addr.h"
#if defined(IWAN_NT_KERNEL)
#include <wsk.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This module owns one UDP socket, in whichever family Start is given. The
 * local port is zero so the transport does not invent a user-mode or
 * control-plane configuration; the provider assigns one and GetLocal reports
 * it.
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
  * Ownership passes with the indication. The sink gets the provider's own MDL
 * and offset, so a consumer that can work in place points NDIS straight at the
 * received buffer and copies nothing. A consumer that cannot (for example the
 * datagram is split across pages) returns FALSE: the caller releases that
 * indication and the datagram is gone, so the sink owns the drop.
 *
 * A TRUE return means the sink kept the indication, and it must call
 * IwanNtWskDatagramReleaseReceive with the same Reference once it is done with
 * the bytes. Until then the socket stays open: Stop waits out every callback,
 * and Close would invalidate the buffer under the sink.
 */
typedef BOOLEAN (*IWAN_NT_WSK_DATAGRAM_RECEIVE_SINK)(
    _In_opt_ void *Context,
    _In_ PMDL Mdl,
    _In_ SIZE_T Offset,
    _In_ SIZE_T Length,
    _In_opt_ void *Reference
    );

/*
 * Called once after the last indication of one receive callback, still under the
 * socket's receive lock. A consumer that accumulates chunks (the miniport does,
 * so it can indicate a chain instead of one NBL at a time) uses this as the batch
 * boundary; a consumer that handles each chunk immediately passes NULL.
 */
typedef void (*IWAN_NT_WSK_DATAGRAM_RECEIVE_FLUSH)(
    _In_opt_ void *Context
    );

typedef struct _IWAN_NT_WSK_DATAGRAM {
    KSPIN_LOCK StateLock;
    /* Serializes datagrams so the in-place transform stays single-threaded. */
    KSPIN_LOCK ReceiveLock;
    EX_RUNDOWN_REF OperationRundown;
    EX_RUNDOWN_REF CallbackRundown;
    KEVENT LifecycleEvent;
    KEVENT FaultEvent;
    IWAN_NT_SOCKADDR LocalAddress;
    /* The family this socket was created with; it cannot change while running. */
    uint16_t Family;
    /*
     * What the bind actually produced. LocalAddress is the request (wildcard,
     * port zero); this is the address the provider returned, and it is the only
     * way to learn the port that frames come back to.
     */
    IWAN_NT_SOCKADDR BoundAddress;
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
    IWAN_NT_WSK_DATAGRAM_RECEIVE_SINK ReceiveSink;
    IWAN_NT_WSK_DATAGRAM_RECEIVE_FLUSH ReceiveFlush;
    void *ReceiveSinkContext;
    ULONG OversizeDrops;
    ULONG SinkErrors;
    /*
     * Indications the sink kept and has not released. Teardown waits for this to
     * reach zero before closing the socket: the provider's buffers are still
     * being read by the stack, and closing would invalidate them.
     */
    volatile LONG OutstandingReceives;
    KEVENT ReceiveIdle;
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
    _In_ const WSK_PROVIDER_NPI *Provider,
    _In_ uint16_t Family
    );

/*
 * Copy out the address the socket is bound to. Valid once Start has succeeded;
 * returns FALSE while the socket is not bound.
 */
BOOLEAN
IwanNtWskDatagramGetLocal(
    _In_ const IWAN_NT_WSK_DATAGRAM *Datagram,
    _Out_ PIWAN_NT_SOCKADDR Local
    );

/* Family the running socket speaks, or 0 when it is not running. */
uint16_t
IwanNtWskDatagramFamily(
    _In_ const IWAN_NT_WSK_DATAGRAM *Datagram
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
 * Ownership: no pointer is retained beyond Detach. A NULL sink detaches the
 * path, which makes the callback release datagrams instead of processing
 * them.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtWskDatagramAttachReceive(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_opt_ IWAN_NT_WSK_DATAGRAM_RECEIVE_SINK Sink,
    _In_opt_ IWAN_NT_WSK_DATAGRAM_RECEIVE_FLUSH Flush,
    _In_opt_ void *Context
    );

/*
 * Copy one datagram out of the provider's MDL chain.
 *
 * IRQL: <= DISPATCH_LEVEL. Returns FALSE when the chain is shorter than it
 * claims or an MDL cannot be mapped; the caller counts that as a sink error
 * rather than processing a partially filled buffer.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
IwanNtWskDatagramCopyBuffer(
    _In_ const WSK_BUF *Buffer,
    _Out_writes_bytes_(Capacity) uint8_t *Destination,
    _In_ size_t Capacity,
    _Out_ size_t *Copied
    );

/*
 * Release one indication the sink kept.
 *
 * IRQL: <= DISPATCH_LEVEL. Reference is exactly the one the sink received;
 * calling it twice is a bug that corrupts the provider's lists.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
IwanNtWskDatagramReleaseReceive(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_opt_ void *Reference
    );

/*
 * Tell whether one datagram is a single contiguous run, and where it starts.
 *
 * IRQL: <= DISPATCH_LEVEL. On success *VirtualAddress points at the first byte
 * and the whole Length can be read or written through it; on failure the
 * datagram straddles a page boundary and the caller must copy it instead.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
IwanNtWskDatagramContiguous(
    _In_ const WSK_BUF *Buffer,
    _Out_ PUCHAR *VirtualAddress
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
/*
 * Hand a chain of datagrams to the provider under one IRP. The buffers stay
 * owned by the caller until the IRP completes.
 */
NTSTATUS
IwanNtWskDatagramSubmitSendList(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_ PWSK_BUF_LIST List,
    _In_ ULONG Messages,
    _In_ const IWAN_NT_SOCKADDR *Remote,
    _In_ PIRP Irp
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
IwanNtWskDatagramSubmitSend(
    _In_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_ PMDL Mdl,
    _In_ ULONG Length,
    _In_ const IWAN_NT_SOCKADDR *Remote,
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
