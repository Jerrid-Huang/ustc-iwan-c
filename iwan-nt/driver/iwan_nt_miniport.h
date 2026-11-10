#ifndef IWAN_NT_MINIPORT_H
#define IWAN_NT_MINIPORT_H

/* Include this header before any other inclusion of ndis.h. */
#ifndef NDIS630_MINIPORT
#define NDIS630_MINIPORT 1
#endif
#include <ndis.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IWAN_NT_MINIPORT_MTU 1500UL
#define IWAN_NT_MINIPORT_TX_QUEUE_COUNT 1UL
#define IWAN_NT_MINIPORT_RX_QUEUE_COUNT 1UL

/*
 * Call from DriverEntry at PASSIVE_LEVEL. The caller owns DriverHandle and
 * supplies a MINIPORT_UNLOAD callback that calls IwanNtMiniportUnregisterDriver
 * before releasing any other driver-wide resources. NDIS installs the WDM
 * DriverUnload routine; do not replace DriverObject->DriverUnload afterwards.
 *
 * The registered adapter is a disconnected, raw-IP lifecycle scaffold. It has
 * one logical transmit queue and one logical receive queue, but retains no
 * packets. There is no RSS, VMQ, offload, worker, receive indication, or WSK
 * integration. An unsupported send is never reported as successfully sent.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NDIS_STATUS
IwanNtMiniportRegisterDriver(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ MINIPORT_UNLOAD *UnloadHandler,
    _Out_ PNDIS_HANDLE DriverHandle
    );

/* Call from the NDIS unload callback or a DriverEntry failure unwind. */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtMiniportUnregisterDriver(
    _Inout_ PNDIS_HANDLE DriverHandle
    );

#ifdef __cplusplus
}
#endif

#endif
