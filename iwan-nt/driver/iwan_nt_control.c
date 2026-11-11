#include "iwan_nt_control.h"

#define IWAN_NT_TAG_CONTROL 'ncNI'

/* Protocol minimum: 8-byte frame header plus the 16-byte control signature. */
#define IWAN_NT_CONTROL_MIN_BYTES (8u + 16u)

typedef struct _IWAN_NT_CONTROL_STATE {
    EX_RUNDOWN_REF AdapterRundown;
    KSPIN_LOCK AdapterLock;
    PIWAN_NT_TRANSPORT Transport;
    IWAN_NT_CONTROL_COUNTER_SOURCE Source;
    BOOLEAN AdapterAttached;
    BOOLEAN RundownCompleted;
    NDIS_HANDLE DeviceHandle;
    PDEVICE_OBJECT DeviceObject;
    BOOLEAN Registered;
} IWAN_NT_CONTROL_STATE;

static IWAN_NT_CONTROL_STATE g_Control;
static PDRIVER_DISPATCH g_MajorFunctions[IRP_MJ_MAXIMUM_FUNCTION + 1];

/*
 * Read the transport pointer without letting a concurrent detach free it: the
 * caller must already hold a rundown reference.
 */
static PIWAN_NT_TRANSPORT
IwanNtControlTransportLocked(
    _Out_opt_ IWAN_NT_CONTROL_COUNTER_SOURCE *Source
    )
{
    KIRQL oldIrql;
    PIWAN_NT_TRANSPORT transport;

    KeAcquireSpinLock(&g_Control.AdapterLock, &oldIrql);
    transport = g_Control.Transport;
    if (Source != NULL) {
        *Source = g_Control.Source;
    }
    KeReleaseSpinLock(&g_Control.AdapterLock, oldIrql);

    return transport;
}

/*
 * Tell the adapter whether a session exists. Called with the rundown
 * reference held, so the source may not disappear underneath us.
 */
static VOID
IwanNtControlNotifySession(
    _In_ int Valid
    )
{
    IWAN_NT_CONTROL_COUNTER_SOURCE source;

    RtlZeroMemory(&source, sizeof(source));
    (void)IwanNtControlTransportLocked(&source);
    if (source.SessionChanged != NULL) {
        source.SessionChanged(source.Context, Valid);
    }
}

/*
 * Every request runs the same preamble: one rundown reference, one transport
 * pointer, and one guaranteed release on the way out.
 */
static NTSTATUS
IwanNtControlBegin(
    _Out_ PIWAN_NT_TRANSPORT *Transport
    )
{
    *Transport = NULL;

    if (g_Control.Registered == FALSE) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (ExAcquireRundownProtection(&g_Control.AdapterRundown) == FALSE) {
        return STATUS_DEVICE_NOT_READY;
    }

    *Transport = IwanNtControlTransportLocked(NULL);
    if (*Transport == NULL) {
        ExReleaseRundownProtection(&g_Control.AdapterRundown);
        return STATUS_DEVICE_NOT_READY;
    }

    return STATUS_SUCCESS;
}

static VOID
IwanNtControlEnd(
    VOID
    )
{
    ExReleaseRundownProtection(&g_Control.AdapterRundown);
}

static NTSTATUS
IwanNtControlSetSession(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack
    )
{
    const IWAN_NT_SESSION_ABI *request;
    IWAN_NT_INGRESS_SESSION session;
    PIWAN_NT_TRANSPORT transport;
    NTSTATUS status;

    if (Stack->Parameters.DeviceIoControl.InputBufferLength <
        IWAN_NT_SESSION_STRUCT_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    request = (const IWAN_NT_SESSION_ABI *)Irp->AssociatedIrp.SystemBuffer;
    if (request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = IwanNtControlBegin(&transport);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * Copy field by field: user mode supplied this buffer, and the session
     * structure the transport keeps is a different (kernel) shape.
     */
    RtlZeroMemory(&session, sizeof(session));
    session.Sid = request->Sid;
    session.Token = request->Token;
    session.Encrypted = (request->Encrypted != 0) ? 1 : 0;
    if (session.Encrypted != 0) {
        RtlCopyMemory(session.Key, request->Key, sizeof(session.Key));
    }

    IwanNtTransportSetSession(transport, &session);
    RtlZeroMemory(&session, sizeof(session));

    IwanNtControlNotifySession(1);

    IwanNtControlEnd();
    return STATUS_SUCCESS;
}

static NTSTATUS
IwanNtControlClearSession(
    VOID
    )
{
    PIWAN_NT_TRANSPORT transport;
    NTSTATUS status;

    status = IwanNtControlBegin(&transport);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    IwanNtTransportClearSession(transport);

    IwanNtControlNotifySession(0);

    IwanNtControlEnd();
    return STATUS_SUCCESS;
}

static NTSTATUS
IwanNtControlSetPeer(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack
    )
{
    const IWAN_NT_PEER_ABI *request;
    SOCKADDR_IN remote;
    PIWAN_NT_TRANSPORT transport;
    NTSTATUS status;

    if (Stack->Parameters.DeviceIoControl.InputBufferLength <
        IWAN_NT_PEER_STRUCT_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    request = (const IWAN_NT_PEER_ABI *)Irp->AssociatedIrp.SystemBuffer;
    if (request == NULL || request->Port == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = IwanNtControlBegin(&transport);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&remote, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_port = request->Port;
    /*
     * Copy the address as four bytes instead of naming a union member: the
     * WDK spells the kernel-side field differently from winsock2.h, and the
     * wire value is opaque here anyway.
     */
    RtlCopyMemory(&remote.sin_addr, &request->Address, sizeof(request->Address));

    IwanNtTransportSetPeer(transport, &remote);

    IwanNtControlEnd();
    return STATUS_SUCCESS;
}

static NTSTATUS
IwanNtControlSendControlFrame(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack
    )
{
    const uint8_t *frame;
    ULONG length;
    PIWAN_NT_TRANSPORT transport;
    NTSTATUS status;

    length = Stack->Parameters.DeviceIoControl.InputBufferLength;
    if (length < IWAN_NT_CONTROL_MIN_BYTES || length > IWAN_NT_CONTROL_MAX) {
        return STATUS_INVALID_PARAMETER;
    }

    frame = (const uint8_t *)Irp->AssociatedIrp.SystemBuffer;
    if (frame == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = IwanNtControlBegin(&transport);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* The bytes leave untouched; the transport only frames them for WSK. */
    status = IwanNtTransportSendControl(transport, frame, (size_t)length);

    IwanNtControlEnd();
    return status;
}

static NTSTATUS
IwanNtControlReadControlFrame(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack
    )
{
    PIWAN_NT_TRANSPORT transport;
    size_t capacity;
    size_t length = 0;
    size_t required = 0;
    NTSTATUS status;

    capacity = (size_t)Stack->Parameters.DeviceIoControl.OutputBufferLength;
    if (capacity == 0 || Irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (capacity > IWAN_NT_CONTROL_MAX) {
        capacity = IWAN_NT_CONTROL_MAX;
    }

    status = IwanNtControlBegin(&transport);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IwanNtTransportReadControl(
        transport, (uint8_t *)Irp->AssociatedIrp.SystemBuffer, capacity,
        &length, &required);

    IwanNtControlEnd();

    if (status == STATUS_BUFFER_TOO_SMALL) {
        Irp->IoStatus.Information = (ULONG_PTR)required;
        return status;
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Irp->IoStatus.Information = (ULONG_PTR)length;
    return STATUS_SUCCESS;
}

static NTSTATUS
IwanNtControlGetStats(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack
    )
{
    IWAN_NT_CONTROL_COUNTER_SOURCE source;
    IWAN_NT_STATS_ABI *stats;
    PIWAN_NT_TRANSPORT transport;
    uint64_t txAccepted = 0;
    uint64_t txRejected = 0;
    uint64_t rxIndicated = 0;
    uint64_t rxDropped = 0;
    NTSTATUS status;

    if (Stack->Parameters.DeviceIoControl.OutputBufferLength <
        IWAN_NT_STATS_STRUCT_SIZE) {
        Irp->IoStatus.Information = (ULONG_PTR)IWAN_NT_STATS_STRUCT_SIZE;
        return STATUS_BUFFER_TOO_SMALL;
    }

    stats = (IWAN_NT_STATS_ABI *)Irp->AssociatedIrp.SystemBuffer;
    if (stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = IwanNtControlBegin(&transport);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(stats, sizeof(*stats));
    IwanNtTransportGetStats(transport, stats);

    /*
     * The adapter counters live with the adapter, so ask the registered
     * source. Holding the rundown reference keeps it alive for this call.
     */
    RtlZeroMemory(&source, sizeof(source));
    (void)IwanNtControlTransportLocked(&source);
    if (source.Query != NULL) {
        source.Query(
            source.Context, &txAccepted, &txRejected, &rxIndicated,
            &rxDropped);
        stats->TxAccepted = txAccepted;
        stats->TxRejected = txRejected;
        stats->RxIndicated = rxIndicated;
        stats->RxDropped = rxDropped;
    }

    IwanNtControlEnd();

    Irp->IoStatus.Information = (ULONG_PTR)sizeof(*stats);
    return STATUS_SUCCESS;
}

static NTSTATUS
IwanNtControlDispatchDeviceControl(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack
    )
{
    switch (Stack->Parameters.DeviceIoControl.IoControlCode) {
    case IWAN_NT_IOCTL_SET_SESSION:
        return IwanNtControlSetSession(Irp, Stack);
    case IWAN_NT_IOCTL_CLEAR_SESSION:
        return IwanNtControlClearSession();
    case IWAN_NT_IOCTL_SET_PEER:
        return IwanNtControlSetPeer(Irp, Stack);
    case IWAN_NT_IOCTL_SEND_CONTROL:
        return IwanNtControlSendControlFrame(Irp, Stack);
    case IWAN_NT_IOCTL_READ_CONTROL:
        return IwanNtControlReadControlFrame(Irp, Stack);
    case IWAN_NT_IOCTL_GET_STATS:
        return IwanNtControlGetStats(Irp, Stack);
    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static NTSTATUS
IwanNtControlDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    stack = IoGetCurrentIrpStackLocation(Irp);
    if (stack == NULL) {
        status = STATUS_INVALID_PARAMETER;
    } else {
        switch (stack->MajorFunction) {
        case IRP_MJ_CREATE:
        case IRP_MJ_CLOSE:
        case IRP_MJ_CLEANUP:
            status = STATUS_SUCCESS;
            break;
        case IRP_MJ_DEVICE_CONTROL:
            status = IwanNtControlDispatchDeviceControl(Irp, stack);
            break;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    /*
     * Buffered I/O: the I/O manager owns the system buffer and completes the
     * IRP here with the byte count the handler left in IoStatus.Information.
     */
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtControlRegister(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NDIS_DEVICE_OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicName;
    UNICODE_STRING sddl;
    NTSTATUS status;
    ULONG index;

    PAGED_CODE();

    if (DriverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (g_Control.Registered != FALSE) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&g_Control, sizeof(g_Control));
    KeInitializeSpinLock(&g_Control.AdapterLock);
    ExInitializeRundownProtection(&g_Control.AdapterRundown);
    g_Control.RundownCompleted = FALSE;

    for (index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; index++) {
        g_MajorFunctions[index] = NULL;
    }
    g_MajorFunctions[IRP_MJ_CREATE] = IwanNtControlDispatch;
    g_MajorFunctions[IRP_MJ_CLOSE] = IwanNtControlDispatch;
    g_MajorFunctions[IRP_MJ_CLEANUP] = IwanNtControlDispatch;
    g_MajorFunctions[IRP_MJ_DEVICE_CONTROL] = IwanNtControlDispatch;

    NdisInitUnicodeString(&deviceName, IWAN_NT_DEVICE_NAME);
    NdisInitUnicodeString(&symbolicName, IWAN_NT_SYMBOLIC_NAME);
    /*
     * Admin and SYSTEM only. The tunnel carries the user's credentials, so a
     * standard user must not be able to read control frames or install a
     * session.
     */
    NdisInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    RtlZeroMemory(&attributes, sizeof(attributes));
    attributes.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    attributes.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    attributes.Header.Size = NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    attributes.DeviceName = &deviceName;
    attributes.SymbolicName = &symbolicName;
    attributes.MajorFunctions = g_MajorFunctions;
    attributes.ExtensionSize = 0;
    attributes.DefaultSDDLString = &sddl;
    attributes.DeviceClassGuid = NULL;

    status = NdisRegisterDeviceEx(
        DriverObject, &attributes, &g_Control.DeviceObject,
        &g_Control.DeviceHandle);
    if (!NT_SUCCESS(status)) {
        g_Control.DeviceObject = NULL;
        g_Control.DeviceHandle = NULL;
        return status;
    }

    g_Control.Registered = TRUE;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtControlDeregister(
    VOID
    )
{
    PAGED_CODE();

    if (g_Control.Registered == FALSE) {
        return;
    }

    /*
     * Withdraw the adapter first: once the device is gone, an in-flight
     * request could otherwise still be holding a transport that Halt already
     * finalized.
     */
    IwanNtControlDetachAdapter(NULL);

    /* Drain the rundown even when no adapter was published this cycle. */
    if (g_Control.RundownCompleted == FALSE) {
        ExWaitForRundownProtectionRelease(&g_Control.AdapterRundown);
        ExRundownCompleted(&g_Control.AdapterRundown);
        g_Control.RundownCompleted = TRUE;
    }

    if (g_Control.DeviceHandle != NULL) {
        NdisDeregisterDeviceEx(g_Control.DeviceHandle);
    }

    g_Control.DeviceHandle = NULL;
    g_Control.DeviceObject = NULL;
    g_Control.Registered = FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtControlAttachAdapter(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_opt_ const IWAN_NT_CONTROL_COUNTER_SOURCE *Source
    )
{
    KIRQL oldIrql;

    PAGED_CODE();

    if (Transport == NULL) {
        return;
    }

    if (g_Control.RundownCompleted != FALSE) {
        ExReInitializeRundownProtection(&g_Control.AdapterRundown);
        g_Control.RundownCompleted = FALSE;
    }

    KeAcquireSpinLock(&g_Control.AdapterLock, &oldIrql);
    g_Control.Transport = Transport;
    if (Source != NULL) {
        g_Control.Source = *Source;
    } else {
        RtlZeroMemory(&g_Control.Source, sizeof(g_Control.Source));
    }
    g_Control.AdapterAttached = TRUE;
    KeReleaseSpinLock(&g_Control.AdapterLock, oldIrql);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtControlDetachAdapter(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    )
{
    KIRQL oldIrql;
    BOOLEAN attached;

    PAGED_CODE();

    KeAcquireSpinLock(&g_Control.AdapterLock, &oldIrql);
    attached = g_Control.AdapterAttached;
    if (attached != FALSE &&
        (Transport == NULL || g_Control.Transport == Transport)) {
        g_Control.Transport = NULL;
        RtlZeroMemory(&g_Control.Source, sizeof(g_Control.Source));
        g_Control.AdapterAttached = FALSE;
    } else {
        attached = FALSE;
    }
    KeReleaseSpinLock(&g_Control.AdapterLock, oldIrql);

    if (attached == FALSE) {
        return;
    }

    /*
     * Wait for every request that already holds a reference. After the wait
     * no new reference can be acquired, so the caller may free the transport.
     */
    ExWaitForRundownProtectionRelease(&g_Control.AdapterRundown);
    ExRundownCompleted(&g_Control.AdapterRundown);
    g_Control.RundownCompleted = TRUE;
}
