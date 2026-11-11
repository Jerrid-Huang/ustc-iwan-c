#include "iwan_nt_wsk_socket.h"

/*
 * The WSK event callback and the IRP completion routine run at IRQL <=
 * DISPATCH_LEVEL. Keep them independent of pageable transport code.
 */
static NTSTATUS WSKAPI
IwanNtWskDatagramReceiveFromEvent(
    _In_opt_ PVOID SocketContext,
    _In_ ULONG Flags,
    _In_opt_ PWSK_DATAGRAM_INDICATION DataIndication
    );

static const WSK_CLIENT_DATAGRAM_DISPATCH IwanNtWskDatagramClientDispatch = {
    IwanNtWskDatagramReceiveFromEvent
};

static NTSTATUS
IwanNtWskDatagramIrpComplete(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_opt_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/*
 * Lifecycle serialization
 * -----------------------
 * One caller-owned IRP is reused for every lifecycle request, so two
 * lifecycle operations must never overlap. Initialize/Start/Stop/Finalize are
 * documented as serialized by the owner; this flag turns a contract violation
 * into STATUS_DEVICE_BUSY instead of a corrupted IRP.
 */
static BOOLEAN
IwanNtWskDatagramBeginLifecycle(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram
    )
{
    KIRQL oldIrql;
    BOOLEAN began;

    KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
    if (Datagram->LifecycleBusy) {
        began = FALSE;
    } else {
        Datagram->LifecycleBusy = TRUE;
        began = TRUE;
    }
    KeReleaseSpinLock(&Datagram->StateLock, oldIrql);
    return began;
}

static VOID
IwanNtWskDatagramEndLifecycle(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
    Datagram->LifecycleBusy = FALSE;
    KeReleaseSpinLock(&Datagram->StateLock, oldIrql);
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
IwanNtWskDatagramPrepareIrp(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram
    )
{
    PAGED_CODE();

    if (Datagram->LifecycleIrp == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (Datagram->LifecycleIrpUsed) {
        return STATUS_DEVICE_BUSY;
    }

    IoReuseIrp(Datagram->LifecycleIrp, STATUS_SUCCESS);
    KeClearEvent(&Datagram->LifecycleEvent);
    IoSetCompletionRoutine(
        Datagram->LifecycleIrp,
        IwanNtWskDatagramIrpComplete,
        &Datagram->LifecycleEvent,
        TRUE,
        TRUE,
        TRUE);
    Datagram->LifecycleIrpUsed = TRUE;
    return STATUS_SUCCESS;
}

/*
 * WSK completes the supplied IRP for both the immediate and the pending
 * submission path, so the completion event is the authoritative signal.
 * A non-pending submission status with no completion means the provider
 * rejected the request before completing it; IoStatus is then stale and the
 * submission status is the result. Information is only reported when the IRP
 * really completed.
 */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
IwanNtWskDatagramFinishIrp(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_ NTSTATUS SubmitStatus,
    _Out_opt_ PULONG_PTR Information
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (Information != NULL) {
        *Information = 0;
    }

    if (KeReadStateEvent(&Datagram->LifecycleEvent) == 0) {
        if (SubmitStatus != STATUS_PENDING) {
            Datagram->LifecycleIrpUsed = FALSE;
            return SubmitStatus;
        }
        KeWaitForSingleObject(
            &Datagram->LifecycleEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);
    }

    status = Datagram->LifecycleIrp->IoStatus.Status;
    if (Information != NULL) {
        *Information = Datagram->LifecycleIrp->IoStatus.Information;
    }
    Datagram->LifecycleIrpUsed = FALSE;
    return status;
}

static const WSK_PROVIDER_BASIC_DISPATCH *
IwanNtWskDatagramGetBasicDispatch(
    _In_ PWSK_SOCKET Socket
    )
{
    /* In C, WSK_PROVIDER_DATAGRAM_DISPATCH has an anonymous Basic prefix. */
    return (const WSK_PROVIDER_BASIC_DISPATCH *)Socket->Dispatch;
}

static const WSK_PROVIDER_DATAGRAM_DISPATCH *
IwanNtWskDatagramGetDatagramDispatch(
    _In_ PWSK_SOCKET Socket
    )
{
    return (const WSK_PROVIDER_DATAGRAM_DISPATCH *)Socket->Dispatch;
}

/*
 * Run-down helpers
 * ----------------
 * OperationRundown fences calls entering provider code; CallbackRundown
 * fences the event callback. A wait always runs the object down and is
 * followed by ExRundownCompleted so a later ExReInitializeRundownProtection
 * sees a completed run-down, as documented for that routine.
 */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
IwanNtWskDatagramRunDown(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_ BOOLEAN Operation
    )
{
    KIRQL oldIrql;
    BOOLEAN alreadyClosed;

    PAGED_CODE();

    KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
    alreadyClosed = Operation ?
        Datagram->OperationRundownClosed : Datagram->CallbackRundownClosed;
    if (Operation) {
        Datagram->OperationRundownClosed = TRUE;
    } else {
        Datagram->CallbackRundownClosed = TRUE;
    }
    KeReleaseSpinLock(&Datagram->StateLock, oldIrql);

    if (alreadyClosed) {
        return;
    }

    if (Operation) {
        ExWaitForRundownProtectionRelease(&Datagram->OperationRundown);
        ExRundownCompleted(&Datagram->OperationRundown);
    } else {
        ExWaitForRundownProtectionRelease(&Datagram->CallbackRundown);
        ExRundownCompleted(&Datagram->CallbackRundown);
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
IwanNtWskDatagramRestart(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_ BOOLEAN Operation
    )
{
    KIRQL oldIrql;
    BOOLEAN wasClosed;

    PAGED_CODE();

    KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
    wasClosed = Operation ?
        Datagram->OperationRundownClosed : Datagram->CallbackRundownClosed;
    if (Operation) {
        Datagram->OperationRundownClosed = FALSE;
    } else {
        Datagram->CallbackRundownClosed = FALSE;
    }
    KeReleaseSpinLock(&Datagram->StateLock, oldIrql);

    if (!wasClosed) {
        return;
    }

    /* ExReInitializeRundownProtection requires IRQL <= APC_LEVEL. */
    if (Operation) {
        ExReInitializeRundownProtection(&Datagram->OperationRundown);
    } else {
        ExReInitializeRundownProtection(&Datagram->CallbackRundown);
    }
}

static BOOLEAN
IwanNtWskDatagramAcquireOperation(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram
    )
{
    KIRQL oldIrql;
    BOOLEAN acquired;

    KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
    if (Datagram->State != IwanNtWskDatagramStarting &&
        Datagram->State != IwanNtWskDatagramRunning) {
        KeReleaseSpinLock(&Datagram->StateLock, oldIrql);
        return FALSE;
    }

    acquired = ExAcquireRundownProtection(&Datagram->OperationRundown);
    KeReleaseSpinLock(&Datagram->StateLock, oldIrql);
    return acquired;
}

static VOID
IwanNtWskDatagramReleaseOperation(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram
    )
{
    ExReleaseRundownProtection(&Datagram->OperationRundown);
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
IwanNtWskDatagramCreateSocket(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_ const WSK_PROVIDER_NPI *Provider
    )
{
    NTSTATUS status;
    ULONG_PTR information = 0;
    PWSK_SOCKET socket;

    PAGED_CODE();

    if (!IwanNtWskDatagramAcquireOperation(Datagram)) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = IwanNtWskDatagramPrepareIrp(Datagram);
    if (NT_SUCCESS(status)) {
        status = Provider->Dispatch->WskSocket(
            Provider->Client,
            AF_INET,
            SOCK_DGRAM,
            IPPROTO_UDP,
            WSK_FLAG_DATAGRAM_SOCKET,
            Datagram,
            &IwanNtWskDatagramClientDispatch,
            NULL,
            NULL,
            NULL,
            Datagram->LifecycleIrp);
        status = IwanNtWskDatagramFinishIrp(Datagram, status, &information);
    }
    IwanNtWskDatagramReleaseOperation(Datagram);

    socket = (PWSK_SOCKET)information;
    if (socket != NULL) {
        /*
         * The provider can hand back a socket together with a failing status.
         * Keep it so teardown closes exactly one object.
         */
        Datagram->Socket = socket;
        Datagram->SocketCreated = TRUE;
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (socket == NULL || socket->Dispatch == NULL) {
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
IwanNtWskDatagramBind(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram
    )
{
    const WSK_PROVIDER_DATAGRAM_DISPATCH *dispatch;
    NTSTATUS status;
    ULONG_PTR information;

    PAGED_CODE();

    dispatch = IwanNtWskDatagramGetDatagramDispatch(Datagram->Socket);
    if (dispatch == NULL || dispatch->WskBind == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!IwanNtWskDatagramAcquireOperation(Datagram)) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = IwanNtWskDatagramPrepareIrp(Datagram);
    if (NT_SUCCESS(status)) {
        status = dispatch->WskBind(
            Datagram->Socket,
            (PSOCKADDR)&Datagram->LocalAddress,
            0,
            Datagram->LifecycleIrp);
        status = IwanNtWskDatagramFinishIrp(Datagram, status, &information);
    }
    /*
     * The bind asked for port zero, so the real port is only known now. Without
     * reading it back nothing could ever address this socket deliberately, and
     * the operator could not tell a NAT problem from a protocol one. The query
     * takes an IRP like every other provider call, so it runs inside the same
     * operation gate, and failing it is not fatal: the tunnel works either way.
     */
    if (NT_SUCCESS(status) && dispatch->WskGetLocalAddress != NULL) {
        NTSTATUS localStatus = IwanNtWskDatagramPrepareIrp(Datagram);

        if (NT_SUCCESS(localStatus)) {
            ULONG length = (ULONG)sizeof(Datagram->BoundAddress);

            localStatus = dispatch->WskGetLocalAddress(
                Datagram->Socket, (PSOCKADDR)&Datagram->BoundAddress, &length,
                Datagram->LifecycleIrp);
            (void)IwanNtWskDatagramFinishIrp(Datagram, localStatus, &information);
        }
    }

    IwanNtWskDatagramReleaseOperation(Datagram);

    if (NT_SUCCESS(status)) {
        Datagram->SocketBound = TRUE;
    }
    return status;
}

/*
 * Enable is a normal provider call and is admitted through the operation gate.
 * Disable is a lifecycle operation: the caller uses its completion as the
 * proof that no event callback is still running, and by then the operation
 * gate is already closed on purpose. It therefore must not re-acquire that
 * gate, or shutdown would deadlock waiting for a callback that can never be
 * disabled.
 *
 * Enabling event callbacks requires Irp == NULL. Disabling requires an IRP,
 * whose completion is the callback-return barrier.
 */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
IwanNtWskDatagramSetReceiveEnabled(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_ BOOLEAN Enable
    )
{
    const WSK_PROVIDER_BASIC_DISPATCH *dispatch;
    WSK_EVENT_CALLBACK_CONTROL control;
    NTSTATUS status;
    ULONG_PTR information;

    PAGED_CODE();

    if (Datagram->Socket == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    dispatch = IwanNtWskDatagramGetBasicDispatch(Datagram->Socket);
    if (dispatch == NULL || dispatch->WskControlSocket == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&control, sizeof(control));
    control.NpiId = &NPI_WSK_INTERFACE_ID;
    control.EventMask = WSK_EVENT_RECEIVE_FROM;

    if (Enable) {
        if (!IwanNtWskDatagramAcquireOperation(Datagram)) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        status = dispatch->WskControlSocket(
            Datagram->Socket,
            WskSetOption,
            SO_WSK_EVENT_CALLBACK,
            SOL_SOCKET,
            sizeof(control),
            &control,
            0,
            NULL,
            NULL,
            NULL);
        IwanNtWskDatagramReleaseOperation(Datagram);
        if (NT_SUCCESS(status)) {
            Datagram->ReceiveEnabled = TRUE;
        }
        return status;
    }

    control.EventMask |= WSK_EVENT_DISABLE;
    status = IwanNtWskDatagramPrepareIrp(Datagram);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = dispatch->WskControlSocket(
        Datagram->Socket,
        WskSetOption,
        SO_WSK_EVENT_CALLBACK,
        SOL_SOCKET,
        sizeof(control),
        &control,
        0,
        NULL,
        NULL,
        Datagram->LifecycleIrp);
    status = IwanNtWskDatagramFinishIrp(Datagram, status, &information);
    if (NT_SUCCESS(status)) {
        Datagram->ReceiveEnabled = FALSE;
    }
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
IwanNtWskDatagramCloseSocket(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram
    )
{
    const WSK_PROVIDER_BASIC_DISPATCH *dispatch;
    NTSTATUS status;
    ULONG_PTR information;

    PAGED_CODE();

    if (Datagram->Socket == NULL) {
        return STATUS_SUCCESS;
    }

    dispatch = IwanNtWskDatagramGetBasicDispatch(Datagram->Socket);
    if (dispatch == NULL || dispatch->WskCloseSocket == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = IwanNtWskDatagramPrepareIrp(Datagram);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Datagram->CloseIssued = TRUE;
    status = dispatch->WskCloseSocket(
        Datagram->Socket,
        Datagram->LifecycleIrp);
    status = IwanNtWskDatagramFinishIrp(Datagram, status, &information);
    if (!NT_SUCCESS(status)) {
        /* Leave every object owned so the next Stop can retry the close. */
        Datagram->CloseIssued = FALSE;
        return status;
    }

    Datagram->CloseCompleted = TRUE;
    return STATUS_SUCCESS;
}

/*
 * Teardown order is fixed and must not be rearranged:
 *   1. close the operation gate and wait for calls inside provider code;
 *   2. disable the callback (its completion is the callback barrier);
 *   3. run the callback run-down down and wait for a racing callback;
 *   4. close the socket, which also cancels the provider's pending IRPs.
 */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
IwanNtWskDatagramTearDownInternal(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS closeStatus;
    PWSK_SOCKET socket;

    PAGED_CODE();

    IwanNtWskDatagramRunDown(Datagram, TRUE);

    socket = Datagram->Socket;
    if (socket != NULL && Datagram->ReceiveEnabled) {
        status = IwanNtWskDatagramSetReceiveEnabled(Datagram, FALSE);
    }

    IwanNtWskDatagramRunDown(Datagram, FALSE);

    if (socket != NULL) {
        closeStatus = IwanNtWskDatagramCloseSocket(Datagram);
        if (!NT_SUCCESS(closeStatus)) {
            if (NT_SUCCESS(status)) {
                status = closeStatus;
            }
            return status;
        }
    }

    Datagram->Socket = NULL;
    Datagram->SocketCreated = FALSE;
    Datagram->SocketBound = FALSE;
    Datagram->ReceiveEnabled = FALSE;
    Datagram->CloseRequired = FALSE;
    Datagram->CloseIssued = FALSE;
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
IwanNtWskDatagramTearDown(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram
    )
{
    KIRQL oldIrql;
    NTSTATUS status;

    PAGED_CODE();

    if (!IwanNtWskDatagramBeginLifecycle(Datagram)) {
        return STATUS_DEVICE_BUSY;
    }

    KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
    if (Datagram->State == IwanNtWskDatagramFinalized ||
        Datagram->State == IwanNtWskDatagramUninitialized) {
        KeReleaseSpinLock(&Datagram->StateLock, oldIrql);
        IwanNtWskDatagramEndLifecycle(Datagram);
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (Datagram->State == IwanNtWskDatagramStopped) {
        KeReleaseSpinLock(&Datagram->StateLock, oldIrql);
        IwanNtWskDatagramEndLifecycle(Datagram);
        return STATUS_SUCCESS;
    }
    Datagram->State = IwanNtWskDatagramStopping;
    KeReleaseSpinLock(&Datagram->StateLock, oldIrql);

    status = IwanNtWskDatagramTearDownInternal(Datagram);

    KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
    Datagram->State = NT_SUCCESS(status) ?
        IwanNtWskDatagramStopped : IwanNtWskDatagramStopping;
    KeReleaseSpinLock(&Datagram->StateLock, oldIrql);

    IwanNtWskDatagramEndLifecycle(Datagram);
    return status;
}

/*
 * Copy one WSK datagram into a contiguous buffer.
 *
 * A datagram arrives as an MDL chain. The frame transform is in-place and
 * needs contiguous bytes, so a copy happens here. MmGetSystemAddressForMdlSafe
 * is legal at IRQL <= DISPATCH_LEVEL for non-paged MDLs, which is what a WSK
 * receive buffer is.
 *
 * Returns FALSE when the chain is shorter than it claims or an MDL cannot be
 * mapped; the caller counts that as a sink error rather than processing a
 * partially filled buffer.
 */
static BOOLEAN
IwanNtWskDatagramCopyBuffer(
    _In_ const WSK_BUF *Buffer,
    _Out_writes_bytes_(Capacity) uint8_t *Destination,
    _In_ size_t Capacity,
    _Out_ size_t *Copied
    )
{
    PMDL mdl;
    SIZE_T skip;
    SIZE_T remaining;
    size_t written = 0;

    *Copied = 0;
    if (Buffer == NULL || Buffer->Mdl == NULL) {
        return FALSE;
    }
    if ((size_t)Buffer->Length > Capacity) {
        return FALSE;
    }

    mdl = Buffer->Mdl;
    skip = Buffer->Offset;
    remaining = Buffer->Length;

    while (mdl != NULL && remaining > 0) {
        ULONG mdlBytes = MmGetMdlByteCount(mdl);
        ULONG chunk;
        PVOID base;

        if (skip >= mdlBytes) {
            skip -= mdlBytes;
            mdl = mdl->Next;
            continue;
        }

        chunk = (ULONG)((SIZE_T)mdlBytes - skip);
        if ((SIZE_T)chunk > remaining) {
            chunk = (ULONG)remaining;
        }

        base = MmGetSystemAddressForMdlSafe(
            mdl,
            NormalPagePriority | MdlMappingNoExecute);
        if (base == NULL) {
            return FALSE;
        }

        RtlCopyMemory(Destination + written,
                      (const uint8_t *)base + skip,
                      chunk);
        written += chunk;
        remaining -= chunk;
        skip = 0;
        mdl = mdl->Next;
    }

    if (remaining != 0) {
        return FALSE;
    }

    *Copied = written;
    return TRUE;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtWskDatagramAttachReceive(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_reads_bytes_opt_(ScratchCapacity) uint8_t *Scratch,
    _In_ size_t ScratchCapacity,
    _In_opt_ IWAN_NT_WSK_DATAGRAM_RECEIVE_SINK Sink,
    _In_opt_ void *Context
    )
{
    KIRQL oldIrql;
    BOOLEAN detach;

    if (Datagram == NULL) {
        return;
    }

    PAGED_CODE();

    detach = (Sink == NULL || Scratch == NULL || ScratchCapacity == 0) ?
             TRUE : FALSE;

    KeAcquireSpinLock(&Datagram->ReceiveLock, &oldIrql);
    if (detach) {
        Datagram->Scratch = NULL;
        Datagram->ScratchCapacity = 0;
        Datagram->ReceiveSink = NULL;
        Datagram->ReceiveSinkContext = NULL;
    } else {
        Datagram->Scratch = Scratch;
        Datagram->ScratchCapacity = ScratchCapacity;
        Datagram->ReceiveSink = Sink;
        Datagram->ReceiveSinkContext = Context;
    }
    KeReleaseSpinLock(&Datagram->ReceiveLock, oldIrql);
}

static NTSTATUS WSKAPI
IwanNtWskDatagramReceiveFromEvent(
    _In_opt_ PVOID SocketContext,
    _In_ ULONG Flags,
    _In_opt_ PWSK_DATAGRAM_INDICATION DataIndication
    )
{
    PIWAN_NT_WSK_DATAGRAM datagram;
    PWSK_DATAGRAM_INDICATION indication;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(Flags);

    datagram = (PIWAN_NT_WSK_DATAGRAM)SocketContext;
    if (datagram == NULL ||
        !ExAcquireRundownProtection(&datagram->CallbackRundown)) {
        /* The socket is being torn down; WSK reclaims the indication list. */
        return STATUS_SUCCESS;
    }

    if (DataIndication == NULL) {
        KeAcquireSpinLock(&datagram->StateLock, &oldIrql);
        datagram->CloseRequired = TRUE;
        KeReleaseSpinLock(&datagram->StateLock, oldIrql);
        KeSetEvent(&datagram->FaultEvent, IO_NO_INCREMENT, FALSE);
        ExReleaseRundownProtection(&datagram->CallbackRundown);
        return STATUS_SUCCESS;
    }

    /*
     * Returning STATUS_SUCCESS consumes the complete linked indication list,
     * which is then reclaimed by WSK; calling WskRelease here would release it
     * twice. Nothing is retained across the callback, so no WskRelease is ever
     * owed by this module.
     */
    /*
     * The receive lock makes the whole batch single-threaded: the frame
     * transform is in-place, the ingress counters have one writer, and the
     * control ring is single-producer. It is held across the sink call, which
     * is why the sink must not block.
     */
    KeAcquireSpinLock(&datagram->ReceiveLock, &oldIrql);
    for (indication = DataIndication;
         indication != NULL;
         indication = indication->Next) {
        size_t copied = 0;

        KeAcquireSpinLockAtDpcLevel(&datagram->StateLock);
        if (datagram->IndicationCount != MAXULONG) {
            datagram->IndicationCount++;
        }
        KeReleaseSpinLockFromDpcLevel(&datagram->StateLock);

        if (datagram->ReceiveSink == NULL || datagram->Scratch == NULL) {
            /* No consumer attached: counted, not silently absorbed. */
            KeAcquireSpinLockAtDpcLevel(&datagram->StateLock);
            if (datagram->SinkErrors != MAXULONG) {
                datagram->SinkErrors++;
            }
            KeReleaseSpinLockFromDpcLevel(&datagram->StateLock);
            continue;
        }

        if ((size_t)indication->Buffer.Length >
            datagram->ScratchCapacity) {
            KeAcquireSpinLockAtDpcLevel(&datagram->StateLock);
            if (datagram->OversizeDrops != MAXULONG) {
                datagram->OversizeDrops++;
            }
            KeReleaseSpinLockFromDpcLevel(&datagram->StateLock);
            continue;
        }

        if (!IwanNtWskDatagramCopyBuffer(&indication->Buffer,
                                         datagram->Scratch,
                                         datagram->ScratchCapacity,
                                         &copied)) {
            KeAcquireSpinLockAtDpcLevel(&datagram->StateLock);
            if (datagram->SinkErrors != MAXULONG) {
                datagram->SinkErrors++;
            }
            KeReleaseSpinLockFromDpcLevel(&datagram->StateLock);
            continue;
        }

        datagram->ReceiveSink(datagram->ReceiveSinkContext,
                              datagram->Scratch,
                              copied);
    }
    KeReleaseSpinLock(&datagram->ReceiveLock, oldIrql);

    ExReleaseRundownProtection(&datagram->CallbackRundown);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtWskDatagramInitialize(
    _Out_ PIWAN_NT_WSK_DATAGRAM Datagram
    )
{
    PAGED_CODE();

    if (Datagram == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Datagram, sizeof(*Datagram));
    KeInitializeSpinLock(&Datagram->StateLock);
    KeInitializeSpinLock(&Datagram->ReceiveLock);
    ExInitializeRundownProtection(&Datagram->OperationRundown);
    ExInitializeRundownProtection(&Datagram->CallbackRundown);
    KeInitializeEvent(&Datagram->LifecycleEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&Datagram->FaultEvent, NotificationEvent, FALSE);
    RtlZeroMemory(&Datagram->LocalAddress, sizeof(Datagram->LocalAddress));
    Datagram->LocalAddress.sin_family = AF_INET;
    Datagram->LocalAddress.sin_port = RtlUshortByteSwap(
        (USHORT)IWAN_NT_WSK_DATAGRAM_PORT);
    Datagram->LifecycleIrp = IoAllocateIrp(1, FALSE);
    if (Datagram->LifecycleIrp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Datagram->State = IwanNtWskDatagramStopped;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtWskDatagramStart(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_ const WSK_PROVIDER_NPI *Provider
    )
{
    KIRQL oldIrql;
    NTSTATUS status;

    PAGED_CODE();

    if (Datagram == NULL || Provider == NULL || Provider->Client == NULL ||
        Provider->Dispatch == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!IwanNtWskDatagramBeginLifecycle(Datagram)) {
        return STATUS_DEVICE_BUSY;
    }

    KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
    if (Datagram->State != IwanNtWskDatagramStopped ||
        Datagram->LifecycleIrp == NULL) {
        KeReleaseSpinLock(&Datagram->StateLock, oldIrql);
        IwanNtWskDatagramEndLifecycle(Datagram);
        return STATUS_INVALID_DEVICE_STATE;
    }
    Datagram->State = IwanNtWskDatagramStarting;
    Datagram->CloseRequired = FALSE;
    Datagram->CloseCompleted = FALSE;
    Datagram->IndicationCount = 0;
    KeReleaseSpinLock(&Datagram->StateLock, oldIrql);
    KeClearEvent(&Datagram->FaultEvent);

    IwanNtWskDatagramRestart(Datagram, TRUE);
    IwanNtWskDatagramRestart(Datagram, FALSE);

    /*
     * Retain the provider NPI for the send path. The reference itself is owned
     * by the transport, which releases it only after this socket is closed.
     */
    Datagram->Provider = *Provider;

    status = IwanNtWskDatagramCreateSocket(Datagram, Provider);
    if (NT_SUCCESS(status)) {
        status = IwanNtWskDatagramBind(Datagram);
    }
    if (NT_SUCCESS(status)) {
        status = IwanNtWskDatagramSetReceiveEnabled(Datagram, TRUE);
    }

    if (!NT_SUCCESS(status)) {
        NTSTATUS teardownStatus = IwanNtWskDatagramTearDownInternal(Datagram);

        KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
        Datagram->State = NT_SUCCESS(teardownStatus) ?
            IwanNtWskDatagramStopped : IwanNtWskDatagramStopping;
        KeReleaseSpinLock(&Datagram->StateLock, oldIrql);

        IwanNtWskDatagramEndLifecycle(Datagram);
        return status;
    }

    KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
    Datagram->State = IwanNtWskDatagramRunning;
    KeReleaseSpinLock(&Datagram->StateLock, oldIrql);

    IwanNtWskDatagramEndLifecycle(Datagram);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtWskDatagramStop(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram
    )
{
    PAGED_CODE();

    if (Datagram == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    return IwanNtWskDatagramTearDown(Datagram);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtWskDatagramFinalize(
    _Inout_ PIWAN_NT_WSK_DATAGRAM Datagram
    )
{
    KIRQL oldIrql;
    NTSTATUS status;

    PAGED_CODE();

    if (Datagram == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!IwanNtWskDatagramBeginLifecycle(Datagram)) {
        return STATUS_DEVICE_BUSY;
    }

    KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
    if (Datagram->State == IwanNtWskDatagramFinalized) {
        KeReleaseSpinLock(&Datagram->StateLock, oldIrql);
        IwanNtWskDatagramEndLifecycle(Datagram);
        return STATUS_SUCCESS;
    }
    if (Datagram->State == IwanNtWskDatagramUninitialized) {
        KeReleaseSpinLock(&Datagram->StateLock, oldIrql);
        IwanNtWskDatagramEndLifecycle(Datagram);
        return STATUS_INVALID_DEVICE_STATE;
    }
    Datagram->State = IwanNtWskDatagramStopping;
    KeReleaseSpinLock(&Datagram->StateLock, oldIrql);

    status = IwanNtWskDatagramTearDownInternal(Datagram);
    if (!NT_SUCCESS(status)) {
        KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
        Datagram->State = IwanNtWskDatagramStopping;
        KeReleaseSpinLock(&Datagram->StateLock, oldIrql);
        IwanNtWskDatagramEndLifecycle(Datagram);
        return status;
    }

    if (Datagram->LifecycleIrp != NULL) {
        IoFreeIrp(Datagram->LifecycleIrp);
        Datagram->LifecycleIrp = NULL;
    }

    KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
    Datagram->State = IwanNtWskDatagramFinalized;
    KeReleaseSpinLock(&Datagram->StateLock, oldIrql);

    IwanNtWskDatagramEndLifecycle(Datagram);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
IwanNtWskDatagramSubmitSend(
    _In_ PIWAN_NT_WSK_DATAGRAM Datagram,
    _In_ PMDL Mdl,
    _In_ ULONG Length,
    _In_ const SOCKADDR_IN *Remote,
    _In_ PIRP Irp
    )
{
    const WSK_PROVIDER_DATAGRAM_DISPATCH *dispatch;
    WSK_BUF buffer;
    KIRQL oldIrql;
    BOOLEAN running;

    if (Datagram == NULL || Mdl == NULL || Length == 0 || Remote == NULL ||
        Irp == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * The dispatch table is cached in the socket object, so reading it once
     * per send avoids a dereference chain but still needs the socket to exist.
     */
    if (Datagram->Socket == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
    running = (BOOLEAN)(Datagram->State == IwanNtWskDatagramRunning);
    KeReleaseSpinLock(&Datagram->StateLock, oldIrql);
    if (!running) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    dispatch = IwanNtWskDatagramGetDatagramDispatch(Datagram->Socket);
    if (dispatch == NULL || dispatch->WskSendTo == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    buffer.Mdl = Mdl;
    buffer.Offset = 0;
    buffer.Length = Length;

    return dispatch->WskSendTo(
        Datagram->Socket,
        &buffer,
        0,
        (PSOCKADDR)Remote,
        0,
        NULL,
        Irp);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
IwanNtWskDatagramCloseRequired(
    _In_ PIWAN_NT_WSK_DATAGRAM Datagram
    )
{
    KIRQL oldIrql;
    BOOLEAN closeRequired;

    if (Datagram == NULL) {
        return FALSE;
    }

    KeAcquireSpinLock(&Datagram->StateLock, &oldIrql);
    closeRequired = Datagram->CloseRequired;
    KeReleaseSpinLock(&Datagram->StateLock, oldIrql);
    return closeRequired;
}

BOOLEAN
IwanNtWskDatagramGetLocal(
    _In_ const IWAN_NT_WSK_DATAGRAM *Datagram,
    _Out_ SOCKADDR_IN *Local
    )
{
    PIWAN_NT_WSK_DATAGRAM datagram = (PIWAN_NT_WSK_DATAGRAM)Datagram;
    KIRQL oldIrql;
    BOOLEAN bound;

    if (Datagram == NULL || Local == NULL) {
        return FALSE;
    }

    /* The lock is mutable state; the getter still takes a const view. */
    KeAcquireSpinLock(&datagram->StateLock, &oldIrql);
    bound = (datagram->State == IwanNtWskDatagramRunning &&
             datagram->BoundAddress.sin_family != 0) ? TRUE : FALSE;
    if (bound != FALSE) {
        *Local = datagram->BoundAddress;
    }
    KeReleaseSpinLock(&datagram->StateLock, oldIrql);
    return bound;
}
