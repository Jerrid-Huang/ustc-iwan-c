#ifndef IWAN_NT_MINIPORT_H
#define IWAN_NT_MINIPORT_H

/* Include this header before any other inclusion of ndis.h. */
#ifndef NDIS630_MINIPORT
#define NDIS630_MINIPORT 1
#endif
#include <ndis.h>
#include "iwan_nt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 1400, not 1500: the outer datagram is the inner packet plus an 8-byte frame
 * header, plus 20 bytes of outer IPv4 and 8 of UDP. An inner 1500 would therefore
 * leave the adapter as a 1536-byte datagram and be fragmented by the IP stack,
 * which is exactly what the deployed client avoids by negotiating 1400. The
 * carrier MTU minus the documented overhead (36 bytes for IPv4) gives 1464 as the
 * ceiling; the protocol's own value is the safer one to advertise.
 */
#define IWAN_NT_MINIPORT_MTU 1400UL
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
