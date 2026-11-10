#include "iwan_nt_miniport.h"
#include "iwan_nt_transport.h"

#define IWAN_NT_MINIPORT_POOL_TAG 'mNwI'
#define IWAN_NT_MINIPORT_LINK_SPEED 1000000000ULL
#define IWAN_NT_MINIPORT_PACKET_FILTERS \
    (NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_MULTICAST | \
     NDIS_PACKET_TYPE_ALL_MULTICAST | NDIS_PACKET_TYPE_BROADCAST)
#define IWAN_NT_MINIPORT_STATISTICS \
    (NDIS_STATISTICS_DIRECTED_FRAMES_RCV_SUPPORTED | \
     NDIS_STATISTICS_DIRECTED_FRAMES_XMIT_SUPPORTED | \
     NDIS_STATISTICS_BYTES_RCV_SUPPORTED | \
     NDIS_STATISTICS_BYTES_XMIT_SUPPORTED)
#define IWAN_NT_MINIPORT_VALID_STATISTICS \
    (NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV | \
     NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT | \
     NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV | \
     NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT)

typedef enum _IWAN_NT_MINIPORT_STATE {
    IwanNtMiniportPaused,
    IwanNtMiniportRunning,
    IwanNtMiniportStopped
} IWAN_NT_MINIPORT_STATE;

typedef struct _IWAN_NT_MINIPORT_ADAPTER {
    NDIS_HANDLE AdapterHandle;
    volatile LONG State;
    ULONG PacketFilter;
    ULONG Lookahead;
    NDIS_DEVICE_POWER_STATE PowerState;
    IWAN_NT_TRANSPORT Transport;
    BOOLEAN TransportReady;
} IWAN_NT_MINIPORT_ADAPTER, *PIWAN_NT_MINIPORT_ADAPTER;

/* NDIS role types supply the callback IRQL and parameter annotations. */
static MINIPORT_INITIALIZE IwanNtMiniportInitializeEx;
static MINIPORT_HALT IwanNtMiniportHaltEx;
static MINIPORT_PAUSE IwanNtMiniportPause;
static MINIPORT_RESTART IwanNtMiniportRestart;
static MINIPORT_SEND_NET_BUFFER_LISTS IwanNtMiniportSendNetBufferLists;
static MINIPORT_RETURN_NET_BUFFER_LISTS IwanNtMiniportReturnNetBufferLists;
static MINIPORT_OID_REQUEST IwanNtMiniportOidRequest;
static MINIPORT_CANCEL_SEND IwanNtMiniportCancelSend;
static MINIPORT_CANCEL_OID_REQUEST IwanNtMiniportCancelOidRequest;
static MINIPORT_DEVICE_PNP_EVENT_NOTIFY IwanNtMiniportDevicePnPEventNotify;
static MINIPORT_SHUTDOWN IwanNtMiniportShutdownEx;

/* NDIS caches the general-attribute OIDs on our behalf. */
static NDIS_OID IwanNtMiniportSupportedOids[] = {
    OID_GEN_SUPPORTED_LIST,
    OID_GEN_HARDWARE_STATUS,
    OID_GEN_MEDIA_SUPPORTED,
    OID_GEN_MEDIA_IN_USE,
    OID_GEN_MAXIMUM_LOOKAHEAD,
    OID_GEN_MAXIMUM_FRAME_SIZE,
    OID_GEN_MAXIMUM_TOTAL_SIZE,
    OID_GEN_MAC_OPTIONS,
    OID_GEN_MEDIA_CONNECT_STATUS,
    OID_GEN_PHYSICAL_MEDIUM,
    OID_GEN_LINK_SPEED,
    OID_GEN_VENDOR_ID,
    OID_GEN_VENDOR_DESCRIPTION,
    OID_GEN_VENDOR_DRIVER_VERSION,
    OID_GEN_DRIVER_VERSION,
    OID_GEN_CURRENT_PACKET_FILTER,
    OID_GEN_CURRENT_LOOKAHEAD,
    OID_GEN_XMIT_OK,
    OID_GEN_RCV_OK,
    OID_GEN_INTERRUPT_MODERATION,
    OID_GEN_STATISTICS,
    OID_PNP_QUERY_POWER,
    OID_PNP_SET_POWER
};

_Use_decl_annotations_
NDIS_STATUS
IwanNtMiniportRegisterDriver(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath,
    MINIPORT_UNLOAD *UnloadHandler,
    PNDIS_HANDLE DriverHandle
    )
{
    NDIS_MINIPORT_DRIVER_CHARACTERISTICS characteristics;

    *DriverHandle = NULL;
    if (UnloadHandler == NULL) {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    NdisZeroMemory(&characteristics, sizeof(characteristics));
    characteristics.Header.Type =
        NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
    characteristics.Header.Revision =
        NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
    characteristics.Header.Size =
        NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
    characteristics.MajorNdisVersion = 6;
    characteristics.MinorNdisVersion = 30;
    characteristics.MajorDriverVersion = 1;
    characteristics.MinorDriverVersion = 0;
    characteristics.InitializeHandlerEx = IwanNtMiniportInitializeEx;
    characteristics.HaltHandlerEx = IwanNtMiniportHaltEx;
    characteristics.UnloadHandler = UnloadHandler;
    characteristics.PauseHandler = IwanNtMiniportPause;
    characteristics.RestartHandler = IwanNtMiniportRestart;
    characteristics.OidRequestHandler = IwanNtMiniportOidRequest;
    characteristics.SendNetBufferListsHandler =
        IwanNtMiniportSendNetBufferLists;
    characteristics.ReturnNetBufferListsHandler =
        IwanNtMiniportReturnNetBufferLists;
    characteristics.CancelSendHandler = IwanNtMiniportCancelSend;
    characteristics.CancelOidRequestHandler = IwanNtMiniportCancelOidRequest;
    characteristics.DevicePnPEventNotifyHandler =
        IwanNtMiniportDevicePnPEventNotify;
    characteristics.ShutdownHandlerEx = IwanNtMiniportShutdownEx;

    /* No physical hardware: no check-for-hang timer or reset handler. */
    return NdisMRegisterMiniportDriver(
        DriverObject, RegistryPath, NULL, &characteristics, DriverHandle);
}

_Use_decl_annotations_
VOID
IwanNtMiniportUnregisterDriver(
    PNDIS_HANDLE DriverHandle
    )
{
    NDIS_HANDLE handle;

    /* The parent serializes registration/unregistration at PASSIVE_LEVEL. */
    handle = *DriverHandle;
    *DriverHandle = NULL;
    if (handle != NULL) {
        NdisMDeregisterMiniportDriver(handle);
    }
}

_Use_decl_annotations_
static NDIS_STATUS
IwanNtMiniportInitializeEx(
    NDIS_HANDLE MiniportAdapterHandle,
    NDIS_HANDLE MiniportDriverContext,
    PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters
    )
{
    PIWAN_NT_MINIPORT_ADAPTER adapter;
    NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES registration;
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES general;
    NDIS_PM_CAPABILITIES power;
    NDIS_STATUS status;

    UNREFERENCED_PARAMETER(MiniportDriverContext);
    UNREFERENCED_PARAMETER(MiniportInitParameters);

    /* The only allocation is one fixed-size, nonpaged adapter context. */
    adapter = NdisAllocateMemoryWithTagPriority(
        MiniportAdapterHandle, sizeof(*adapter), IWAN_NT_MINIPORT_POOL_TAG,
        NormalPoolPriority);
    if (adapter == NULL) {
        return NDIS_STATUS_RESOURCES;
    }

    NdisZeroMemory(adapter, sizeof(*adapter));
    adapter->AdapterHandle = MiniportAdapterHandle;
    adapter->State = IwanNtMiniportPaused;
    adapter->Lookahead = IWAN_NT_MINIPORT_MTU;
    adapter->PowerState = NdisDeviceStateD0;

    status = IwanNtTransportInitialize(&adapter->Transport, 16);
    if (!NT_SUCCESS(status)) {
        goto Failure;
    }
    adapter->TransportReady = TRUE;
    NdisZeroMemory(&registration, sizeof(registration));
        NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;
    registration.Header.Revision =
        NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2;
    registration.Header.Size =
        NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2;
    registration.MiniportAdapterContext = adapter;
    registration.AttributeFlags =
        NDIS_MINIPORT_ATTRIBUTES_SURPRISE_REMOVE_OK;
    registration.InterfaceType = NdisInterfaceInternal;
    status = NdisMSetMiniportAttributes(
        MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&registration);
    if (status != NDIS_STATUS_SUCCESS) {
        goto Failure;
    }

    NdisZeroMemory(&power, sizeof(power));
    power.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    power.Header.Revision = NDIS_PM_CAPABILITIES_REVISION_2;
    power.Header.Size = NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_2;
    power.MinMagicPacketWakeUp = NdisDeviceStateUnspecified;
    power.MinPatternWakeUp = NdisDeviceStateUnspecified;
    power.MinLinkChangeWakeUp = NdisDeviceStateUnspecified;

    NdisZeroMemory(&general, sizeof(general));
    general.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;
    general.Header.Revision =
        NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
    general.Header.Size =
        NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
    general.MediaType = NdisMediumIP;
    general.PhysicalMediumType = NdisPhysicalMediumUnspecified;
    general.MtuSize = IWAN_NT_MINIPORT_MTU;
    general.MaxXmitLinkSpeed = IWAN_NT_MINIPORT_LINK_SPEED;
    general.MaxRcvLinkSpeed = IWAN_NT_MINIPORT_LINK_SPEED;
    general.XmitLinkSpeed = NDIS_LINK_SPEED_UNKNOWN;
    general.RcvLinkSpeed = NDIS_LINK_SPEED_UNKNOWN;
    general.MediaConnectState = MediaConnectStateDisconnected;
    general.MediaDuplexState = MediaDuplexStateFull;
    general.LookaheadSize = IWAN_NT_MINIPORT_MTU;
    general.MacOptions = NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA |
        NDIS_MAC_OPTION_TRANSFERS_NOT_PEND | NDIS_MAC_OPTION_NO_LOOPBACK;
    general.SupportedPacketFilters = IWAN_NT_MINIPORT_PACKET_FILTERS;
    /* Raw IP has no link-layer address or multicast address table. */
    general.MacAddressLength = 0;
    general.AccessType = NET_IF_ACCESS_POINT_TO_POINT;
    general.DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
    general.ConnectionType = NET_IF_CONNECTION_DEDICATED;
    general.IfType = IF_TYPE_PROP_VIRTUAL;
    general.IfConnectorPresent = FALSE;
    general.SupportedStatistics = IWAN_NT_MINIPORT_STATISTICS;
    general.SupportedPauseFunctions = NdisPauseFunctionsUnsupported;
    general.SupportedOidList = IwanNtMiniportSupportedOids;
    general.SupportedOidListLength = sizeof(IwanNtMiniportSupportedOids);
    general.PowerManagementCapabilitiesEx = &power;
    /* NULL RecvScaleCapabilities disables RSS: one logical TX/RX queue. */
    status = NdisMSetMiniportAttributes(
        MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&general);
    if (status != NDIS_STATUS_SUCCESS) {
        goto Failure;
    }

    /* NDIS initializes an adapter in Paused; Restart enables its data path. */
    return NDIS_STATUS_SUCCESS;

Failure:
    /* NDIS does not call HaltEx when InitializeEx fails. */
    if (adapter->TransportReady) {
        IwanNtTransportFinalize(&adapter->Transport);
        adapter->TransportReady = FALSE;
    }
    NdisFreeMemory(adapter, 0, 0);
    return status;
}

_Use_decl_annotations_
static VOID
IwanNtMiniportHaltEx(
    NDIS_HANDLE MiniportAdapterContext,
    NDIS_HALT_ACTION HaltAction
    )
{
    PIWAN_NT_MINIPORT_ADAPTER adapter = MiniportAdapterContext;

    UNREFERENCED_PARAMETER(HaltAction);
    InterlockedExchange(&adapter->State, IwanNtMiniportStopped);
    if (adapter->TransportReady) {
        IwanNtTransportFinalize(&adapter->Transport);
        adapter->TransportReady = FALSE;
    }
    NdisFreeMemory(adapter, 0, 0);
}

_Use_decl_annotations_
static NDIS_STATUS
IwanNtMiniportPause(
    NDIS_HANDLE MiniportAdapterContext,
    PNDIS_MINIPORT_PAUSE_PARAMETERS MiniportPauseParameters
    )
{
    PIWAN_NT_MINIPORT_ADAPTER adapter = MiniportAdapterContext;

    UNREFERENCED_PARAMETER(MiniportPauseParameters);
    InterlockedCompareExchange(
        &adapter->State, IwanNtMiniportPaused, IwanNtMiniportRunning);
    if (adapter->TransportReady) {
        IwanNtTransportStop(&adapter->Transport);
    }
    /* All sends finish inline; no asynchronous work requires draining. */
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
static NDIS_STATUS
IwanNtMiniportRestart(
    NDIS_HANDLE MiniportAdapterContext,
    PNDIS_MINIPORT_RESTART_PARAMETERS MiniportRestartParameters
    )
{
    PIWAN_NT_MINIPORT_ADAPTER adapter = MiniportAdapterContext;
    LONG previous;

    UNREFERENCED_PARAMETER(MiniportRestartParameters);
    previous = InterlockedCompareExchange(
        &adapter->State, IwanNtMiniportRunning, IwanNtMiniportPaused);
    if (previous == IwanNtMiniportStopped) {
        return NDIS_STATUS_NOT_ACCEPTED;
    }
    if (adapter->TransportReady) {
        NDIS_STATUS status = IwanNtTransportStart(&adapter->Transport);
        if (!NT_SUCCESS(status)) {
            InterlockedExchange(&adapter->State, IwanNtMiniportPaused);
            return NDIS_STATUS_DEVICE_FAILED;
        }
    }
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
static VOID
IwanNtMiniportSendNetBufferLists(
    NDIS_HANDLE MiniportAdapterContext,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG SendFlags
    )
{
    PIWAN_NT_MINIPORT_ADAPTER adapter = MiniportAdapterContext;
    NDIS_HANDLE handle = adapter->AdapterHandle;
    PNET_BUFFER_LIST current;
    ULONG completeFlags = 0;

    UNREFERENCED_PARAMETER(PortNumber);
    for (current = NetBufferLists; current != NULL;
         current = NET_BUFFER_LIST_NEXT_NBL(current)) {
        LONG state = InterlockedCompareExchange(
            &adapter->State, IwanNtMiniportPaused, IwanNtMiniportPaused);

        NET_BUFFER_LIST_STATUS(current) =
            (state == IwanNtMiniportRunning) ?
            NDIS_STATUS_NOT_SUPPORTED : NDIS_STATUS_PAUSED;
    }
    if ((SendFlags & NDIS_SEND_FLAGS_DISPATCH_LEVEL) != 0) {
        completeFlags = NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL;
    }
    /* No access to an NBL or adapter is made after returning its ownership. */
    NdisMSendNetBufferListsComplete(handle, NetBufferLists, completeFlags);
}

_Use_decl_annotations_
static VOID
IwanNtMiniportReturnNetBufferLists(
    NDIS_HANDLE MiniportAdapterContext,
    PNET_BUFFER_LIST NetBufferLists,
    ULONG ReturnFlags
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(NetBufferLists);
    UNREFERENCED_PARAMETER(ReturnFlags);
    /*
     * Unreachable while no receives are indicated. Before adding WSK RX,
     * implement explicit NBL ownership, return reclamation and pause rundown.
     */
    NT_ASSERT(NetBufferLists == NULL);
}

static NDIS_STATUS
IwanNtMiniportCopyQuery(
    _Inout_ PNDIS_OID_REQUEST Request,
    _In_reads_bytes_(Length) const VOID *Value,
    _In_ ULONG Length
    )
{
    Request->DATA.QUERY_INFORMATION.BytesWritten = 0;
    Request->DATA.QUERY_INFORMATION.BytesNeeded = Length;
    if (Request->DATA.QUERY_INFORMATION.InformationBufferLength < Length) {
        return NDIS_STATUS_BUFFER_TOO_SHORT;
    }
    if (Length != 0 && Request->DATA.QUERY_INFORMATION.InformationBuffer == NULL) {
        return NDIS_STATUS_INVALID_DATA;
    }
    NdisMoveMemory(Request->DATA.QUERY_INFORMATION.InformationBuffer,
        Value, Length);
    Request->DATA.QUERY_INFORMATION.BytesWritten = Length;
    Request->DATA.QUERY_INFORMATION.BytesNeeded = 0;
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
IwanNtMiniportCopyCounterQuery(
    _Inout_ PNDIS_OID_REQUEST Request,
    _In_ ULONG64 Counter
    )
{
    PVOID buffer;
    ULONG length;
    ULONG low;

    buffer = Request->DATA.QUERY_INFORMATION.InformationBuffer;
    length = Request->DATA.QUERY_INFORMATION.InformationBufferLength;
    Request->DATA.QUERY_INFORMATION.BytesWritten = 0;
    Request->DATA.QUERY_INFORMATION.BytesNeeded = sizeof(ULONG);
    if (length < sizeof(ULONG)) {
        return NDIS_STATUS_BUFFER_TOO_SHORT;
    }
    if (buffer == NULL) {
        return NDIS_STATUS_INVALID_DATA;
    }

    if (length < sizeof(ULONG64)) {
        low = (ULONG)Counter;
        NdisMoveMemory(buffer, &low, sizeof(low));
        Request->DATA.QUERY_INFORMATION.BytesWritten = sizeof(low);
    } else {
        NdisMoveMemory(buffer, &Counter, sizeof(Counter));
        Request->DATA.QUERY_INFORMATION.BytesWritten = sizeof(Counter);
    }
    Request->DATA.QUERY_INFORMATION.BytesNeeded = 0;
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
static NDIS_STATUS
IwanNtMiniportOidRequest(
    NDIS_HANDLE MiniportAdapterContext,
    PNDIS_OID_REQUEST OidRequest
    )
{
    PIWAN_NT_MINIPORT_ADAPTER adapter = MiniportAdapterContext;
    ULONG value;
    ULONG oid;
    ULONG length;
    USHORT version;
    ULONG64 counter;
    NDIS_INTERRUPT_MODERATION_PARAMETERS moderation;
    NDIS_INTERRUPT_MODERATION_PARAMETERS requestedModeration;
    NDIS_STATISTICS_INFO statistics;
    static const CHAR description[] = "iWAN NT raw-IP lifecycle scaffold";

    if (OidRequest->RequestType == NdisRequestSetInformation) {
        OidRequest->DATA.SET_INFORMATION.BytesRead = 0;
        OidRequest->DATA.SET_INFORMATION.BytesNeeded = 0;
        if (InterlockedCompareExchange(&adapter->State,
                IwanNtMiniportStopped, IwanNtMiniportStopped) ==
            IwanNtMiniportStopped) {
            return NDIS_STATUS_NOT_ACCEPTED;
        }
        oid = OidRequest->DATA.SET_INFORMATION.Oid;
        if (oid == OID_GEN_INTERRUPT_MODERATION) {
            length = OidRequest->DATA.SET_INFORMATION.InformationBufferLength;
            if (length < sizeof(requestedModeration)) {
                OidRequest->DATA.SET_INFORMATION.BytesNeeded =
                    sizeof(requestedModeration);
                return NDIS_STATUS_INVALID_LENGTH;
            }
            if (OidRequest->DATA.SET_INFORMATION.InformationBuffer == NULL) {
                return NDIS_STATUS_INVALID_DATA;
            }
            NdisMoveMemory(&requestedModeration,
                OidRequest->DATA.SET_INFORMATION.InformationBuffer,
                sizeof(requestedModeration));
            if (requestedModeration.Header.Type != NDIS_OBJECT_TYPE_DEFAULT ||
                requestedModeration.Header.Revision !=
                    NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1 ||
                requestedModeration.Header.Size <
                    NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1 ||
                (requestedModeration.InterruptModeration !=
                    NdisInterruptModerationEnabled &&
                 requestedModeration.InterruptModeration !=
                    NdisInterruptModerationDisabled)) {
                return NDIS_STATUS_INVALID_DATA;
            }
            return NDIS_STATUS_NOT_SUPPORTED;
        }
        if (oid != OID_GEN_CURRENT_PACKET_FILTER &&
            oid != OID_GEN_CURRENT_LOOKAHEAD && oid != OID_PNP_SET_POWER) {
            return NDIS_STATUS_NOT_SUPPORTED;
        }
        length = OidRequest->DATA.SET_INFORMATION.InformationBufferLength;
        if (length != sizeof(value)) {
            OidRequest->DATA.SET_INFORMATION.BytesNeeded = sizeof(value);
            return NDIS_STATUS_INVALID_LENGTH;
        }
        if (OidRequest->DATA.SET_INFORMATION.InformationBuffer == NULL) {
            return NDIS_STATUS_INVALID_DATA;
        }
        NdisMoveMemory(&value,
            OidRequest->DATA.SET_INFORMATION.InformationBuffer, sizeof(value));
        if (oid == OID_GEN_CURRENT_PACKET_FILTER) {
            if ((value & ~IWAN_NT_MINIPORT_PACKET_FILTERS) != 0) {
                return NDIS_STATUS_NOT_SUPPORTED;
            }
            adapter->PacketFilter = value;
        } else if (oid == OID_GEN_CURRENT_LOOKAHEAD) {
            if (value > IWAN_NT_MINIPORT_MTU) {
                return NDIS_STATUS_INVALID_DATA;
            }
            adapter->Lookahead = value;
        } else {
            if (value < NdisDeviceStateD0 || value > NdisDeviceStateD3) {
                return NDIS_STATUS_INVALID_DATA;
            }
            adapter->PowerState = (NDIS_DEVICE_POWER_STATE)value;
        }
        OidRequest->DATA.SET_INFORMATION.BytesRead = sizeof(value);
        return NDIS_STATUS_SUCCESS;
    }

    if (OidRequest->RequestType == NdisRequestMethod) {
        OidRequest->DATA.METHOD_INFORMATION.BytesRead = 0;
        OidRequest->DATA.METHOD_INFORMATION.BytesWritten = 0;
        OidRequest->DATA.METHOD_INFORMATION.BytesNeeded = 0;
        return NDIS_STATUS_NOT_SUPPORTED;
    }
    if (OidRequest->RequestType != NdisRequestQueryInformation &&
        OidRequest->RequestType != NdisRequestQueryStatistics) {
        return NDIS_STATUS_NOT_SUPPORTED;
    }
    OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
    OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = 0;
    if (InterlockedCompareExchange(&adapter->State,
            IwanNtMiniportStopped, IwanNtMiniportStopped) ==
        IwanNtMiniportStopped) {
        return NDIS_STATUS_NOT_ACCEPTED;
    }
    switch (OidRequest->DATA.QUERY_INFORMATION.Oid) {
    case OID_GEN_SUPPORTED_LIST:
        return IwanNtMiniportCopyQuery(OidRequest, IwanNtMiniportSupportedOids,
            sizeof(IwanNtMiniportSupportedOids));
    case OID_GEN_VENDOR_DESCRIPTION:
        return IwanNtMiniportCopyQuery(OidRequest, description,
            sizeof(description));
    case OID_GEN_DRIVER_VERSION:
        version = (USHORT)((6U << 8) | 30U);
        return IwanNtMiniportCopyQuery(OidRequest, &version, sizeof(version));
    case OID_GEN_XMIT_OK:
    case OID_GEN_RCV_OK:
        /* No successful sends or receive indications exist in this stage. */
        counter = 0;
        return IwanNtMiniportCopyCounterQuery(OidRequest, counter);
    case OID_GEN_INTERRUPT_MODERATION:
        NdisZeroMemory(&moderation, sizeof(moderation));
        moderation.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        moderation.Header.Revision =
            NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
        moderation.Header.Size =
            NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
        moderation.InterruptModeration = NdisInterruptModerationNotSupported;
        return IwanNtMiniportCopyQuery(OidRequest, &moderation,
            sizeof(moderation));
    case OID_GEN_STATISTICS:
        NdisZeroMemory(&statistics, sizeof(statistics));
        statistics.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        statistics.Header.Revision = NDIS_STATISTICS_INFO_REVISION_1;
        statistics.Header.Size = NDIS_SIZEOF_STATISTICS_INFO_REVISION_1;
        statistics.SupportedStatistics = IWAN_NT_MINIPORT_VALID_STATISTICS;
        return IwanNtMiniportCopyQuery(OidRequest, &statistics,
            sizeof(statistics));
    case OID_PNP_QUERY_POWER:
        /* No hardware state, pending I/O, or wake capability restricts power. */
        return NDIS_STATUS_SUCCESS;
    case OID_GEN_HARDWARE_STATUS:
        value = NdisHardwareStatusReady;
        break;
    case OID_GEN_MEDIA_SUPPORTED:
    case OID_GEN_MEDIA_IN_USE:
        value = NdisMediumIP;
        break;
    case OID_GEN_MAXIMUM_LOOKAHEAD:
    case OID_GEN_MAXIMUM_FRAME_SIZE:
    case OID_GEN_MAXIMUM_TOTAL_SIZE:
        value = IWAN_NT_MINIPORT_MTU;
        break;
    case OID_GEN_MAC_OPTIONS:
        value = NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA |
            NDIS_MAC_OPTION_TRANSFERS_NOT_PEND | NDIS_MAC_OPTION_NO_LOOPBACK;
        break;
    case OID_GEN_MEDIA_CONNECT_STATUS:
        value = NdisMediaStateDisconnected;
        break;
    case OID_GEN_PHYSICAL_MEDIUM:
        value = NdisPhysicalMediumUnspecified;
        break;
    case OID_GEN_LINK_SPEED:
        value = 0;
        break;
    case OID_GEN_VENDOR_ID:
        value = 0x00FFFFFFUL;
        break;
    case OID_GEN_VENDOR_DRIVER_VERSION:
        value = 0x00010000UL;
        break;
    case OID_GEN_CURRENT_PACKET_FILTER:
        value = adapter->PacketFilter;
        break;
    case OID_GEN_CURRENT_LOOKAHEAD:
        value = adapter->Lookahead;
        break;
    default:
        return NDIS_STATUS_NOT_SUPPORTED;
    }
    return IwanNtMiniportCopyQuery(OidRequest, &value, sizeof(value));
}

_Use_decl_annotations_
static VOID
IwanNtMiniportCancelSend(
    NDIS_HANDLE MiniportAdapterContext,
    PVOID CancelId
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(CancelId);
    /* SendNetBufferLists never leaves a send pending. */
}

_Use_decl_annotations_
static VOID
IwanNtMiniportCancelOidRequest(
    NDIS_HANDLE MiniportAdapterContext,
    PVOID RequestId
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(RequestId);
    /* OidRequest never returns NDIS_STATUS_PENDING. */
}

_Use_decl_annotations_
static VOID
IwanNtMiniportDevicePnPEventNotify(
    NDIS_HANDLE MiniportAdapterContext,
    PNET_DEVICE_PNP_EVENT NetDevicePnPEvent
    )
{
    PIWAN_NT_MINIPORT_ADAPTER adapter = MiniportAdapterContext;

    if (NetDevicePnPEvent->DevicePnPEvent == NdisDevicePnPEventSurpriseRemoved) {
        InterlockedExchange(&adapter->State, IwanNtMiniportStopped);
    }
}

_Use_decl_annotations_
static VOID
IwanNtMiniportShutdownEx(
    NDIS_HANDLE MiniportAdapterContext,
    NDIS_SHUTDOWN_ACTION ShutdownAction
    )
{
    PIWAN_NT_MINIPORT_ADAPTER adapter = MiniportAdapterContext;

    UNREFERENCED_PARAMETER(ShutdownAction);
    /* Shutdown can run above DISPATCH_LEVEL: no waits or NDIS calls here. */
    InterlockedExchange(&adapter->State, IwanNtMiniportStopped);
}
