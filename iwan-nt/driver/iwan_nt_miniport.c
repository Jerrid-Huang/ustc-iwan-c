#include "iwan_nt_miniport.h"
#include "iwan_nt_frame.h"
#include "iwan_nt_transport.h"
#include "iwan_nt_trace.h"
#include "iwan_nt_tx.h"
#include "iwan_nt_control.h"

#define IWAN_NT_MINIPORT_POOL_TAG 'mNwI'

/* Two hundred 60-byte control frames fit; the ring drops and counts instead. */
#define IWAN_NT_CONTROL_RING_BYTES 16384u
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

/*
 * One receive slot owns one non-paged buffer, one MDL and one NBL, all built
 * once at InitializeEx. A datagram either claims a free slot or is dropped and
 * counted, so the indication path never allocates at DISPATCH_LEVEL. The pool is
 * bounded because the receive callback is its only producer and NDIS is the only
 * consumer that returns slots.
 */
/*
 * Packets per provider call. The pool has 32 slots, so a batch never asks for
 * more than it could hold; 8 keeps the staging memory small while still
 * collapsing the common case of one busy queue into one WskSendMessages.
 */
/*
 * Packets per WskSendMessages call. WireGuardNT hands over whatever its staging
 * queue holds (MAX_STAGED_PACKETS 128); the ceiling here is the send pool, so
 * one batch can claim every slot at most.
 */
#define IWAN_NT_MINIPORT_SEND_BATCH IWAN_NT_TX_SLOTS

#define IWAN_NT_MINIPORT_RX_SLOTS 4u

/*
 * NDIS rounds a net buffer list context up to a 16-byte boundary and rejects
 * anything smaller, so the slot pointer gets a full aligned block rather
 * than sizeof(PVOID).
 */
#define IWAN_NT_MINIPORT_RX_CONTEXT_BYTES 16u

typedef struct _IWAN_NT_MINIPORT_RX_CONTEXT {
    void *Slot;
    UCHAR Reserved[IWAN_NT_MINIPORT_RX_CONTEXT_BYTES - sizeof(void *)];
} IWAN_NT_MINIPORT_RX_CONTEXT, *PIWAN_NT_MINIPORT_RX_CONTEXT;

typedef struct _IWAN_NT_MINIPORT_RX_SLOT {
    PUCHAR Buffer;
    PMDL Mdl;
    PNET_BUFFER_LIST Nbl;
    /*
     * Set only when this frame points straight at the provider's buffer: the
     * indication must then be released when NDIS gives the frame back, not when
     * the receive callback ends.
     */
    void *Reference;
    volatile LONG InUse;
} IWAN_NT_MINIPORT_RX_SLOT;

typedef struct _IWAN_NT_MINIPORT_ADAPTER {
    NDIS_HANDLE AdapterHandle;
    volatile LONG State;
    ULONG PacketFilter;
    ULONG Lookahead;
    NDIS_DEVICE_POWER_STATE PowerState;
    IWAN_NT_TRANSPORT Transport;
    BOOLEAN TransportReady;
    /*
     * The link is up only while a session exists. Reporting it earlier would let
     * the stack route traffic into an adapter that can only drop it.
     */
    volatile LONG LinkUp;
    /*
     * One contiguous staging buffer per adapter: NdisGetDataBuffer can be asked
     * to flatten a scattered NET_BUFFER into it, and the frame transform then
     * runs on contiguous bytes. The lock keeps that shared buffer, and the
     * transform itself, single threaded as the design requires.
     */
    NDIS_SPIN_LOCK SendLock;
    BOOLEAN SendLockReady;
    PUCHAR SendScratch;
    NDIS_HANDLE RxPool;
    IWAN_NT_MINIPORT_RX_SLOT RxSlots[IWAN_NT_MINIPORT_RX_SLOTS];
    ULONG RxSlotCount;
    volatile LONG RxInFlight;
    KEVENT RxIdle;
    BOOLEAN RxIdleReady;
    volatile LONG TxAccepted;
    volatile LONG TxRejected;
    volatile LONG RxIndicated;
    volatile LONG RxDropped;
    volatile LONG RxBatched;
    /*
     * Chain assembled during one WSK receive callback. The callback holds the
     * socket's receive lock for the whole batch, so a single set of head/tail
     * pointers is enough.
     */
    PNET_BUFFER_LIST RxChainHead;
    PNET_BUFFER_LIST RxChainTail;
    ULONG RxChainCount;
    /*
     * Bounded storage for the control ring that carries inbound OPEN_ACK,
     * ECHO and CLOSE frames to the user-mode control plane. Fixed size, so a
     * noisy or hostile peer can only fill the ring, never grow the pool.
     */
    PUCHAR ControlStorage;
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

static VOID
IwanNtMiniportIndicateInner(
    void *Context,
    const uint8_t *Inner,
    size_t Length,
    unsigned Family,
    void *View
    );

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

/*
 * Frees every slot that was built, in reverse order of construction. Called from
 * the InitializeEx failure path and from HaltEx, and in both cases nothing can be
 * indicating any more: the transport is already finalized.
 */
static VOID
IwanNtMiniportFreeRxSlots(
    _Inout_ PIWAN_NT_MINIPORT_ADAPTER Adapter
    )
{
    while (Adapter->RxSlotCount > 0) {
        IWAN_NT_MINIPORT_RX_SLOT *slot;

        Adapter->RxSlotCount--;
        slot = &Adapter->RxSlots[Adapter->RxSlotCount];
        if (slot->Nbl != NULL) {
            NdisFreeNetBufferList(slot->Nbl);
            slot->Nbl = NULL;
        }
        if (slot->Mdl != NULL) {
            NdisFreeMdl(slot->Mdl);
            slot->Mdl = NULL;
        }
        if (slot->Buffer != NULL) {
            NdisFreeMemory(slot->Buffer, 0, 0);
            slot->Buffer = NULL;
        }
    }
}

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

/*
 * Publish the media connect state. NDIS_LINK_STATE is the only supported way to
 * move a running adapter between connected and disconnected.
 */
static VOID
IwanNtMiniportIndicateLink(
    _Inout_ PIWAN_NT_MINIPORT_ADAPTER Adapter,
    _In_ int Up
    )
{
    NDIS_STATUS_INDICATION indication;
    NDIS_LINK_STATE state;

    if (Adapter->AdapterHandle == NULL) {
        return;
    }

    NdisZeroMemory(&state, sizeof(state));
    state.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    state.Header.Revision = NDIS_LINK_STATE_REVISION_1;
    state.Header.Size = NDIS_SIZEOF_LINK_STATE_REVISION_1;
    state.MediaConnectState = (Up != 0) ? MediaConnectStateConnected :
        MediaConnectStateDisconnected;
    state.MediaDuplexState = MediaDuplexStateFull;
    state.XmitLinkSpeed = (Up != 0) ? IWAN_NT_MINIPORT_LINK_SPEED :
        NDIS_LINK_SPEED_UNKNOWN;
    state.RcvLinkSpeed = state.XmitLinkSpeed;

    NdisZeroMemory(&indication, sizeof(indication));
    indication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    indication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    indication.Header.Size = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1;
    indication.SourceHandle = Adapter->AdapterHandle;
    indication.StatusCode = NDIS_STATUS_LINK_STATE;
    indication.StatusBuffer = &state;
    indication.StatusBufferSize = sizeof(state);

    (void)NdisMIndicateStatusEx(Adapter->AdapterHandle, &indication);
}

/*
 * Called by the control device when a session appears or disappears, from
 * PASSIVE_LEVEL with the control rundown reference held.
 */
static VOID
IwanNtMiniportSessionChanged(
    _In_opt_ void *Context,
    _In_ int Valid
    )
{
    PIWAN_NT_MINIPORT_ADAPTER adapter = (PIWAN_NT_MINIPORT_ADAPTER)Context;

    if (adapter == NULL) {
        return;
    }
    if (InterlockedExchange(&adapter->LinkUp, (Valid != 0) ? 1 : 0) ==
        ((Valid != 0) ? 1 : 0)) {
        return;
    }
    IwanNtMiniportIndicateLink(adapter, Valid);
}

/*
 * Adapter counters for IWAN_NT_IOCTL_GET_STATS. Called at PASSIVE_LEVEL while
 * the adapter is halted only after the control device drained its callers, so
 * reading the volatile counters here needs no lock.
 */
static VOID
IwanNtMiniportQueryCounters(
    _In_opt_ void *Context,
    _Out_ uint64_t *TxAccepted,
    _Out_ uint64_t *TxRejected,
    _Out_ uint64_t *RxIndicated,
    _Out_ uint64_t *RxDropped,
    _Out_ uint64_t *RxBatches
    )
{
    PIWAN_NT_MINIPORT_ADAPTER adapter = (PIWAN_NT_MINIPORT_ADAPTER)Context;

    if (adapter == NULL) {
        *TxAccepted = 0;
        *TxRejected = 0;
        *RxIndicated = 0;
        *RxDropped = 0;
        *RxBatches = 0;
        return;
    }

    *TxAccepted = (uint64_t)InterlockedCompareExchange(
        &adapter->TxAccepted, 0, 0);
    *TxRejected = (uint64_t)InterlockedCompareExchange(
        &adapter->TxRejected, 0, 0);
    *RxIndicated = (uint64_t)InterlockedCompareExchange(
        &adapter->RxIndicated, 0, 0);
    *RxDropped = (uint64_t)InterlockedCompareExchange(
        &adapter->RxDropped, 0, 0);
    *RxBatches = (uint64_t)InterlockedCompareExchange(
        &adapter->RxBatched, 0, 0);
}

static VOID
IwanNtMiniportFlushInner(
    _In_opt_ void *Context
    );

/*
 * Event log fallback. The registry trace can lose writes (pool pressure, hive
 * trouble), and a silent init failure is the worst possible outcome, so every
 * failure branch also drops an entry with its stage and status.
 */
static VOID
IwanNtMiniportFault(
    _In_ NDIS_HANDLE MiniportAdapterHandle,
    _In_ ULONG Stage,
    _In_ ULONG Status
    )
{
    NdisWriteErrorLogEntry(MiniportAdapterHandle, NDIS_ERROR_CODE_OUT_OF_RESOURCES,
                           3, Stage, Status, 0);
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

    IwanNtTrace(IWAN_NT_STAGE_INIT_ENTER);

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
    IwanNtTrace(IWAN_NT_STAGE_TRANSPORT);
    NdisAllocateSpinLock(&adapter->SendLock);
    adapter->SendLockReady = TRUE;
    adapter->SendScratch = NdisAllocateMemoryWithTagPriority(
        MiniportAdapterHandle,
        IWAN_NT_TX_BUFFER_BYTES * IWAN_NT_MINIPORT_SEND_BATCH,
        IWAN_NT_MINIPORT_POOL_TAG,
        NormalPoolPriority);
    if (adapter->SendScratch == NULL) {
        status = NDIS_STATUS_RESOURCES;
        goto Failure;
    }
    {
        NET_BUFFER_LIST_POOL_PARAMETERS params;

        NdisZeroMemory(&params, sizeof(params));
        params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        params.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        params.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        params.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
        params.fAllocateNetBuffer = FALSE;
        params.PoolTag = IWAN_NT_MINIPORT_POOL_TAG;
        adapter->RxPool = NdisAllocateNetBufferListPool(MiniportAdapterHandle,
                                                        &params);
    IwanNtTrace(IWAN_NT_STAGE_RXPOOL);
        if (adapter->RxPool == NULL) {
            IwanNtTrace(31u);
            status = NDIS_STATUS_RESOURCES;
            goto Failure;
        }
    }

    /*
     * RxIdle starts signalled: nothing is in flight until the first indication.
     * Halt waits on it, so the pool is never freed under the stack.
     */
    KeInitializeEvent(&adapter->RxIdle, NotificationEvent, TRUE);
    adapter->RxIdleReady = TRUE;
    IwanNtTrace(18u);
    {
        ULONG index;

        for (index = 0; index < IWAN_NT_MINIPORT_RX_SLOTS; index++) {
            IWAN_NT_MINIPORT_RX_SLOT *slot = &adapter->RxSlots[index];
            PVOID *context;

            IwanNtTrace(40u + index);

            slot->Buffer = NdisAllocateMemoryWithTagPriority(
                MiniportAdapterHandle, IWAN_NT_MINIPORT_MTU,
                IWAN_NT_MINIPORT_POOL_TAG, NormalPoolPriority);
            if (slot->Buffer == NULL) {
                IwanNtMiniportFault(MiniportAdapterHandle, 201u, 0);
                IwanNtTrace(201u);
                status = NDIS_STATUS_RESOURCES;
                goto Failure;
            }
            slot->Mdl = NdisAllocateMdl(MiniportAdapterHandle, slot->Buffer,
                                        IWAN_NT_MINIPORT_MTU);
            if (slot->Mdl == NULL) {
                IwanNtMiniportFault(MiniportAdapterHandle, 202u, 0);
                IwanNtTrace(202u);
                status = NDIS_STATUS_RESOURCES;
                goto Failure;
            }
            slot->Nbl = NdisAllocateNetBufferAndNetBufferList(
                adapter->RxPool, sizeof(IWAN_NT_MINIPORT_RX_CONTEXT), 0,
                slot->Mdl, 0, IWAN_NT_MINIPORT_MTU);
            if (slot->Nbl == NULL) {
                IwanNtMiniportFault(MiniportAdapterHandle, 203u, 0);
                IwanNtTrace(203u);
                status = NDIS_STATUS_RESOURCES;
                goto Failure;
            }
            /*
             * ReturnNetBufferLists only gets the NBL, so the slot pointer
             * travels in the NBL context sized by the call above.
             */
            context = (PVOID *)NET_BUFFER_LIST_CONTEXT_DATA_START(slot->Nbl);
            ((PIWAN_NT_MINIPORT_RX_CONTEXT)context)->Slot = slot;
            slot->InUse = 0;
            adapter->RxSlotCount = index + 1;
        }
    }
    IwanNtTrace(IWAN_NT_STAGE_SLOTS);
    IwanNtTransportSetDataSink(
        &adapter->Transport, IwanNtMiniportIndicateInner,
        IwanNtMiniportFlushInner, adapter);

    /*
     * Control frames need somewhere to wait for the user-mode control plane,
     * so the ring storage is allocated once here rather than per datagram.
     */
    adapter->ControlStorage = NdisAllocateMemoryWithTagPriority(
        MiniportAdapterHandle, IWAN_NT_CONTROL_RING_BYTES,
        IWAN_NT_MINIPORT_POOL_TAG, NormalPoolPriority);
    if (adapter->ControlStorage == NULL) {
        /*
         * The control ring only carries handshake and keepalive frames for the
         * user-mode control plane. Losing it degrades the adapter to data-only
         * instead of taking the whole interface down, so report it and carry
         * on: a device that never starts cannot be diagnosed from user mode at
         * all, while a running one reports the gap in its counters.
         */
        IwanNtTrace(205u);
    } else {
        IwanNtTrace(IWAN_NT_STAGE_RINGS);
        IwanNtTransportSetControlRing(&adapter->Transport,
                                      adapter->ControlStorage,
                                      IWAN_NT_CONTROL_RING_BYTES);
    }
    NdisZeroMemory(&registration, sizeof(registration));
    registration.Header.Type =
        NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;
    registration.Header.Revision =
        NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2;
    registration.Header.Size =
        NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2;
    registration.MiniportAdapterContext = adapter;
    registration.AttributeFlags =
        NDIS_MINIPORT_ATTRIBUTES_SURPRISE_REMOVE_OK;
    registration.InterfaceType = NdisInterfaceInternal;
    IwanNtTrace(19u);
    status = NdisMSetMiniportAttributes(
        MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&registration);
    if (status != NDIS_STATUS_SUCCESS) {
        IwanNtMiniportFault(MiniportAdapterHandle, 301u, (ULONG)status);
        IwanNtTrace(301u);
        goto Failure;
    }

    IwanNtTrace(IWAN_NT_STAGE_ATTRIBUTES);

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
    IwanNtTrace(21u);
    status = NdisMSetMiniportAttributes(
        MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&general);
    if (status != NDIS_STATUS_SUCCESS) {
        /* 0xC000009A here means NDIS disliked the attributes, not memory. */
        IwanNtMiniportFault(MiniportAdapterHandle, 302u, (ULONG)status);
        IwanNtTrace(302u);
        goto Failure;
    }

    /*
     * Publish the transport to the control device last: from here on an IOCTL
     * can reach this adapter, so everything it touches must already be live.
     */
    {
        IWAN_NT_CONTROL_COUNTER_SOURCE source;

        source.Context = adapter;
        source.Query = IwanNtMiniportQueryCounters;
        source.SessionChanged = IwanNtMiniportSessionChanged;
        IwanNtControlAttachAdapter(&adapter->Transport, &source);
    }

    IwanNtTrace(IWAN_NT_STAGE_CONTROL);

    IwanNtTrace(IWAN_NT_STAGE_INIT_DONE);

    /* NDIS initializes an adapter in Paused; Restart enables its data path. */
    return NDIS_STATUS_SUCCESS;

Failure:
    IwanNtTraceStatus(IWAN_NT_STAGE_STATUS, (ULONG)status);
    /* NDIS does not call HaltEx when InitializeEx fails. */
    if (adapter->TransportReady) {
        IwanNtControlDetachAdapter(&adapter->Transport);
    }
    if (adapter->ControlStorage != NULL) {
        NdisFreeMemory(adapter->ControlStorage, 0, 0);
        adapter->ControlStorage = NULL;
    }
    if (adapter->TransportReady) {
        IwanNtTransportFinalize(&adapter->Transport);
        adapter->TransportReady = FALSE;
    }
    if (adapter->SendLockReady) {
        NdisFreeSpinLock(&adapter->SendLock);
        adapter->SendLockReady = FALSE;
    }
    IwanNtMiniportFreeRxSlots(adapter);
    if (adapter->RxPool != NULL) {
        NdisFreeNetBufferListPool(adapter->RxPool);
        adapter->RxPool = NULL;
    }
    if (adapter->SendScratch != NULL) {
        NdisFreeMemory(adapter->SendScratch, 0, 0);
        adapter->SendScratch = NULL;
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
    /*
     * Withdraw the control device first: it drains every IOCTL that already
     * holds a reference, so no request can touch the transport while it is
     * being finalized below.
     */
    if (adapter->TransportReady) {
        IwanNtControlDetachAdapter(&adapter->Transport);
    }
    if (adapter->ControlStorage != NULL) {
        NdisFreeMemory(adapter->ControlStorage, 0, 0);
        adapter->ControlStorage = NULL;
    }
    /* The transport drain waits out the receive callback before this returns. */
    if (adapter->TransportReady) {
        IwanNtTransportFinalize(&adapter->Transport);
        adapter->TransportReady = FALSE;
    }
    if (adapter->SendLockReady) {
        NdisFreeSpinLock(&adapter->SendLock);
        adapter->SendLockReady = FALSE;
    }
    if (adapter->RxIdleReady) {
        LARGE_INTEGER timeout;

        /*
         * Halt runs at PASSIVE_LEVEL, so it can wait. If the stack still holds a
         * frame after two seconds something is very wrong, and leaking the pool
         * beats freeing it under a live indication.
         */
        timeout.QuadPart = -20000000;
        (VOID)KeWaitForSingleObject(&adapter->RxIdle, Executive, KernelMode,
                                    FALSE, &timeout);
        adapter->RxIdleReady = FALSE;
    }
    if (InterlockedCompareExchange(&adapter->RxInFlight, 0, 0) == 0) {
        IwanNtMiniportFreeRxSlots(adapter);
    }
    if (adapter->RxPool != NULL) {
        NdisFreeNetBufferListPool(adapter->RxPool);
        adapter->RxPool = NULL;
    }
    if (adapter->SendScratch != NULL) {
        NdisFreeMemory(adapter->SendScratch, 0, 0);
        adapter->SendScratch = NULL;
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
        NDIS_STATUS status;

        IwanNtTrace(IWAN_NT_STAGE_RESTART_ENTER);
        status = IwanNtTransportStart(&adapter->Transport);
        if (!NT_SUCCESS(status)) {
            InterlockedExchange(&adapter->State, IwanNtMiniportPaused);
            return NDIS_STATUS_DEVICE_FAILED;
        }
    }
    return NDIS_STATUS_SUCCESS;
}

/*
 * Hand everything staged during this callback to NDIS in one call.
 *
 * IRQL: DISPATCH_LEVEL. The chain is built by IwanNtMiniportIndicateInner and
 * lives until NDIS returns the NBLs through IwanNtMiniportReturnNetBufferLists;
 * each NBL carries its own pool slot in its context, so the return path does not
 * need to know about batching at all.
 */
static VOID
IwanNtMiniportFlushInner(
    _In_opt_ void *Context
    )
{
    PIWAN_NT_MINIPORT_ADAPTER adapter = Context;
    PNET_BUFFER_LIST chain;
    ULONG count;

    if (adapter == NULL || adapter->RxChainHead == NULL) {
        return;
    }

    chain = adapter->RxChainHead;
    count = adapter->RxChainCount;
    adapter->RxChainHead = NULL;
    adapter->RxChainTail = NULL;
    adapter->RxChainCount = 0;

    if (InterlockedCompareExchange(&adapter->State, IwanNtMiniportPaused,
                                   IwanNtMiniportPaused) !=
        IwanNtMiniportRunning) {
        /*
         * Halt or Pause won the race: handing an NBL up now would give the stack
         * a frame whose adapter context is being torn down. Recycle the slots
         * ourselves instead, exactly as the return path would.
         */
        PNET_BUFFER_LIST current;

        for (current = chain; current != NULL;
             current = NET_BUFFER_LIST_NEXT_NBL(current)) {
            PIWAN_NT_MINIPORT_RX_CONTEXT context =
                (PIWAN_NT_MINIPORT_RX_CONTEXT)
                    NET_BUFFER_LIST_CONTEXT_DATA_START(current);
            IWAN_NT_MINIPORT_RX_SLOT *slot =
                (context != NULL) ? (IWAN_NT_MINIPORT_RX_SLOT *)context->Slot
                                  : NULL;

            NET_BUFFER_LIST_NEXT_NBL(current) = NULL;
            if (slot == NULL) {
                continue;
            }
            /*
             * The frame was built on the provider's buffer, so give that back
             * before the slot: teardown waits for this count to reach zero and
             * would otherwise wait forever.
             */
            if (slot->Reference != NULL) {
                IwanNtWskDatagramReleaseReceive(&adapter->Transport.Datagram,
                                                slot->Reference);
                slot->Reference = NULL;
            }
            InterlockedExchange(&slot->InUse, 0);
            if (InterlockedDecrement(&adapter->RxInFlight) == 0) {
                KeSetEvent(&adapter->RxIdle, IO_NO_INCREMENT, FALSE);
            }
        }
        InterlockedAdd(&adapter->RxDropped, (LONG)count);
        return;
    }

    if (count > 1) {
        InterlockedIncrement(&adapter->RxBatched);
    }

    /*
     * Flags are zero on purpose. A chain may mix IPv4 and IPv6 frames, and on a
     * raw IP miniport each frame states its own version; SINGLE_ETHER_TYPE would
     * assert one value for the whole chain.
     */
    NdisMIndicateReceiveNetBufferLists(adapter->AdapterHandle, chain,
                                       NDIS_DEFAULT_PORT_NUMBER, count, 0);
}

/*
 * Runs at DISPATCH_LEVEL inside the WSK receive callback. It claims one slot of
 * the receive pool, copies the inner packet into it and appends the NBL to the
 * chain that the flush call will hand to NDIS in one go; nothing here allocates,
 * blocks or keeps the WSK buffer alive past the call.
 */
static VOID
IwanNtMiniportIndicateInner(
    void *Context,
    const uint8_t *Inner,
    size_t Length,
    unsigned Family,
    void *View
    )
{
    PIWAN_NT_MINIPORT_ADAPTER adapter = Context;
    PIWAN_NT_RECEIVE_VIEW view = (PIWAN_NT_RECEIVE_VIEW)View;
    IWAN_NT_MINIPORT_RX_SLOT *slot = NULL;
    PNET_BUFFER nb;
    ULONG index;
    LONG state;

    UNREFERENCED_PARAMETER(Family);

    /*
     * The adapter advertises IWAN_NT_MINIPORT_MTU, so the stack should never hand
     * us more. If it does, drop rather than build a datagram that would fragment
     * on the way out.
     */
    if (Inner == NULL || Length == 0 || Length > IWAN_NT_MINIPORT_MTU) {
        InterlockedIncrement(&adapter->RxDropped);
        return;
    }
    state = InterlockedCompareExchange(
        &adapter->State, IwanNtMiniportPaused, IwanNtMiniportPaused);
    if (state != IwanNtMiniportRunning) {
        InterlockedIncrement(&adapter->RxDropped);
        return;
    }

    for (index = 0; index < adapter->RxSlotCount; index++) {
        if (InterlockedCompareExchange(&adapter->RxSlots[index].InUse, 1, 0) ==
            0) {
            slot = &adapter->RxSlots[index];
            break;
        }
    }
    if (slot == NULL) {
        /* Backpressure, not a fault: the stack is not returning frames. */
        InterlockedIncrement(&adapter->RxDropped);
        return;
    }

    KeClearEvent(&adapter->RxIdle);
    nb = NET_BUFFER_LIST_FIRST_NB(slot->Nbl);
    if (view != NULL) {
        /*
         * Zero copy: the frame sits inside the provider's buffer, behind the
         * eight byte header the transform just rewrote in place. Point the net
         * buffer at that MDL instead of copying, and keep the indication until
         * NDIS returns the frame.
         */
        NET_BUFFER_FIRST_MDL(nb) = view->Mdl;
        NET_BUFFER_CURRENT_MDL(nb) = view->Mdl;
        /* Both offsets are ULONG in the net buffer, so narrow once, on purpose. */
        NET_BUFFER_CURRENT_MDL_OFFSET(nb) =
            (ULONG)(view->Offset + IWAN_NT_FRAME_HDR_LEN);
        NET_BUFFER_DATA_OFFSET(nb) =
            (ULONG)(view->Offset + IWAN_NT_FRAME_HDR_LEN);
        NET_BUFFER_DATA_LENGTH(nb) = (ULONG)Length;
        slot->Reference = view->Reference;
        view->Taken = TRUE;
    } else {
        NdisMoveMemory(slot->Buffer, Inner, Length);
        NET_BUFFER_FIRST_MDL(nb) = slot->Mdl;
        NET_BUFFER_CURRENT_MDL(nb) = slot->Mdl;
        NET_BUFFER_CURRENT_MDL_OFFSET(nb) = 0;
        NET_BUFFER_DATA_OFFSET(nb) = 0;
        NET_BUFFER_DATA_LENGTH(nb) = (ULONG)Length;
        slot->Reference = NULL;
    }

    /*
     * No EtherType metadata and no NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE: this is
     * a raw IP miniport, so NDIS reads the version nibble from the packet itself.
     * Both the frame-type info and that flag describe Ethernet framing, which
     * does not exist here.
     */
    NET_BUFFER_LIST_STATUS(slot->Nbl) = NDIS_STATUS_SUCCESS;
    NET_BUFFER_LIST_NEXT_NBL(slot->Nbl) = NULL;

    InterlockedIncrement(&adapter->RxInFlight);
    InterlockedIncrement(&adapter->RxIndicated);
    if (adapter->RxChainHead == NULL) {
        adapter->RxChainHead = slot->Nbl;
    } else {
        NET_BUFFER_LIST_NEXT_NBL(adapter->RxChainTail) = slot->Nbl;
    }
    adapter->RxChainTail = slot->Nbl;
    adapter->RxChainCount++;
}

/*
 * Flatten one net buffer into its own staging area.
 *
 * The staging area has to be distinct per packet in a batch, because the pool
 * copies from these pointers only after the whole batch is assembled.
 */
_Use_decl_annotations_
static BOOLEAN
IwanNtMiniportStagePacket(
    _Inout_ PIWAN_NT_MINIPORT_ADAPTER Adapter,
    _In_ PNET_BUFFER Nb,
    _In_ ULONG Slot,
    _Out_ IWAN_NT_TX_ITEM *Item
    )
{
    ULONG length = NET_BUFFER_DATA_LENGTH(Nb);
    PUCHAR bytes;

    if (length == 0 || length > IWAN_NT_TX_BUFFER_BYTES) {
        return FALSE;
    }

    bytes = NdisGetDataBuffer(
        Nb, length, Adapter->SendScratch + (SIZE_T)Slot * IWAN_NT_TX_BUFFER_BYTES,
        1, 0);
    if (bytes == NULL) {
        return FALSE;
    }

    Item->Inner = bytes;
    Item->InnerLength = length;
    return TRUE;
}

/*
 * Hand one assembled batch to the transport and account for what it took.
 *
 * A short batch is backpressure, not an error: the packets the pool could not
 * hold are reported as resources so the stack retries them.
 */
_Use_decl_annotations_
static VOID
IwanNtMiniportFlushBatch(
    _Inout_ PIWAN_NT_MINIPORT_ADAPTER Adapter,
    _In_reads_(Count) const IWAN_NT_TX_ITEM *Items,
    _In_ ULONG Count,
    _Inout_ PNDIS_STATUS PacketStatus
    )
{
    ULONG accepted = 0;

    if (Count == 0) {
        return;
    }

    (VOID)IwanNtTransportSendInnerBatch(
        &Adapter->Transport, Items, Count, &accepted);

    InterlockedExchangeAdd(&Adapter->TxAccepted, (LONG)accepted);
    if (accepted < Count) {
        InterlockedExchangeAdd(&Adapter->TxRejected, (LONG)(Count - accepted));
        *PacketStatus = NDIS_STATUS_RESOURCES;
    }
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
    LONG state;

    UNREFERENCED_PARAMETER(PortNumber);

    if ((SendFlags & NDIS_SEND_FLAGS_DISPATCH_LEVEL) != 0) {
        completeFlags = NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL;
    }

    state = InterlockedCompareExchange(
        &adapter->State, IwanNtMiniportPaused, IwanNtMiniportPaused);
    if (state != IwanNtMiniportRunning) {
        for (current = NetBufferLists; current != NULL;
             current = NET_BUFFER_LIST_NEXT_NBL(current)) {
            NET_BUFFER_LIST_STATUS(current) = NDIS_STATUS_PAUSED;
        }
        NdisMSendNetBufferListsComplete(handle, NetBufferLists, completeFlags);
        return;
    }

    /*
     * One lock covers the shared staging buffer and the transform, so the
     * synchronous path stays single threaded even when several CPUs send.
     */
    NdisAcquireSpinLock(&adapter->SendLock);
    for (current = NetBufferLists; current != NULL;
         current = NET_BUFFER_LIST_NEXT_NBL(current)) {
        PNET_BUFFER nb;
        NDIS_STATUS packetStatus = NDIS_STATUS_SUCCESS;

        /*
         * Accumulate up to SEND_BATCH packets of one inner family and hand
         * them over together. A family change flushes first: one frame header
         * serves the batch, so the packets must agree.
         */
        {
            IWAN_NT_TX_ITEM items[IWAN_NT_MINIPORT_SEND_BATCH];
            ULONG count = 0;
            unsigned family = 0;

            for (nb = NET_BUFFER_LIST_FIRST_NB(current);
                 nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
                IWAN_NT_TX_ITEM item;
                unsigned nbFamily;
                ULONG length = NET_BUFFER_DATA_LENGTH(nb);

                if (length == 0) {
                    continue;
                }
                if (length > IWAN_NT_TX_BUFFER_BYTES) {
                    packetStatus = NDIS_STATUS_INVALID_PACKET;
                    continue;
                }

                /*
                 * Flush before staging, so the slot index used here is always
                 * inside the staging array.
                 */
                if (count == IWAN_NT_MINIPORT_SEND_BATCH) {
                    IwanNtMiniportFlushBatch(adapter, items, count,
                                             &packetStatus);
                    count = 0;
                }

                if (!IwanNtMiniportStagePacket(adapter, nb, count, &item)) {
                    packetStatus = NDIS_STATUS_RESOURCES;
                    continue;
                }
                nbFamily = IwanNtFrameInnerFamily(item.Inner, length);

                /*
                 * A frame header serves the whole batch, so a family change
                 * has to break it. The pending packets go out now; this one
                 * moves to the front of the next batch.
                 */
                if (count != 0 && nbFamily != family) {
                    IwanNtMiniportFlushBatch(adapter, items, count,
                                             &packetStatus);
                    RtlCopyMemory(adapter->SendScratch, item.Inner, length);
                    item.Inner = adapter->SendScratch;
                    count = 0;
                }

                family = nbFamily;
                items[count] = item;
                count++;
            }

            IwanNtMiniportFlushBatch(adapter, items, count, &packetStatus);
        }
        NET_BUFFER_LIST_STATUS(current) = packetStatus;
    }
    NdisReleaseSpinLock(&adapter->SendLock);
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
    PIWAN_NT_MINIPORT_ADAPTER adapter = MiniportAdapterContext;
    PNET_BUFFER_LIST current;

    UNREFERENCED_PARAMETER(ReturnFlags);

    /*
     * Every indicated NBL carries its slot pointer in the NBL context, so this
     * path never searches the pool: it clears the slot and, when the last frame
     * comes back, wakes Halt.
     */
    for (current = NetBufferLists; current != NULL;
         current = NET_BUFFER_LIST_NEXT_NBL(current)) {
        PIWAN_NT_MINIPORT_RX_CONTEXT context =
            (PIWAN_NT_MINIPORT_RX_CONTEXT)
                NET_BUFFER_LIST_CONTEXT_DATA_START(current);
        IWAN_NT_MINIPORT_RX_SLOT *slot =
            (context != NULL) ? (IWAN_NT_MINIPORT_RX_SLOT *)context->Slot
                              : NULL;

        if (slot == NULL) {
            continue;
        }
        if (slot->Reference != NULL) {
            /*
             * The frame lived in the provider's buffer, so the indication is only
             * safe to release now that the stack is done reading it. This runs at
             * DISPATCH_LEVEL, which WskRelease allows.
             */
            IwanNtWskDatagramReleaseReceive(&adapter->Transport.Datagram,
                                            slot->Reference);
            slot->Reference = NULL;
        }
        InterlockedExchange(&slot->InUse, 0);
        if (InterlockedDecrement(&adapter->RxInFlight) == 0) {
            KeSetEvent(&adapter->RxIdle, IO_NO_INCREMENT, FALSE);
        }
    }
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
        value = (InterlockedCompareExchange(&adapter->LinkUp, 0, 0) != 0) ?
            NdisMediaStateConnected : NdisMediaStateDisconnected;
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
