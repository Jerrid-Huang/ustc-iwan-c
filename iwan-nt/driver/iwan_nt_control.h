#ifndef IWAN_NT_CONTROL_H
#define IWAN_NT_CONTROL_H

#include "iwan_nt_types.h"

#if defined(IWAN_NT_KERNEL)
#include <ndis.h>
#endif

#include "iwan_nt_ioctl.h"
#include "iwan_nt_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Adapter-owned counters for the stats request. The control device owns no
 * packet state, so the miniport supplies a small interface instead of the
 * device reaching into the adapter context.
 */
typedef struct _IWAN_NT_CONTROL_COUNTER_SOURCE {
    _In_opt_ void *Context;
    _In_ VOID (*Query)(
        _In_opt_ void *Context,
        _Out_ uint64_t *TxAccepted,
        _Out_ uint64_t *TxRejected,
        _Out_ uint64_t *RxIndicated,
        _Out_ uint64_t *RxDropped,
        _Out_ uint64_t *RxBatches
        );
    /*
     * Optional. Called after a session is installed (Valid != 0) or dropped
     * (Valid == 0), so the adapter can report its link state. The transport is
     * up long before a session exists; telling the stack that the link is up
     * too early turns every packet into a silent drop.
     */
    _In_opt_ VOID (*SessionChanged)(
        _In_opt_ void *Context,
        _In_ int Valid
        );
} IWAN_NT_CONTROL_COUNTER_SOURCE;

/*
 * Create the control device and its symbolic link.
 *
 * IRQL: PASSIVE_LEVEL, once from DriverEntry.
 * The device is registered through NDIS because a miniport driver does not own
 * its driver object's dispatch table; plain IoCreateDevice would conflict with
 * the entry points NDIS installed.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtControlRegister(
    _In_ NDIS_HANDLE MiniportDriverHandle
    );

/*
 * Tear the control device down.
 *
 * IRQL: PASSIVE_LEVEL, once from the miniport unload callback.
 * Detaches the current adapter first, so an I/O request in flight finishes
 * against a live transport before the device goes away.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtControlDeregister(
    VOID
    );

/*
 * Publish the transport that I/O requests operate on.
 *
 * IRQL: PASSIVE_LEVEL, from the miniport initialize path.
 * One adapter at a time: the guest uses a single tunnel, and a second
 * registration would silently redirect somebody else's packets.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtControlAttachAdapter(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_opt_ const IWAN_NT_CONTROL_COUNTER_SOURCE *Source
    );

/*
 * Withdraw the transport and wait until no I/O request is using it.
 *
 * IRQL: PASSIVE_LEVEL, from the miniport halt path, before the adapter
 * context is released.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtControlDetachAdapter(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    );

#ifdef __cplusplus
}
#endif

#endif
