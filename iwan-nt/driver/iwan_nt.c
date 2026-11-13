#include "iwan_nt_miniport.h"
#include "iwan_nt_control.h"
#include "iwan_nt_trace.h"

#ifndef IWAN_NT_BISECT_EMPTY_ENTRY
static NDIS_HANDLE IwanNtMiniportDriverHandle;
#endif

#ifndef IWAN_NT_BISECT_EMPTY_ENTRY
_Function_class_(MINIPORT_UNLOAD)
_Use_decl_annotations_
static VOID
IwanNtMiniportUnload(
    PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    /*
     * Every adapter has already halted by the time NDIS calls this, so no
     * IOCTL can still be running against a transport. Deregister the control
     * device before the miniport driver itself.
     */
    IwanNtControlDeregister();

    /* NDIS requires deregistration from this callback after all adapters halt. */
    IwanNtMiniportUnregisterDriver(&IwanNtMiniportDriverHandle);
}
#endif

_Function_class_(DRIVER_INITIALIZE)
_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
#ifdef IWAN_NT_BISECT_EMPTY_ENTRY
    /*
     * Bisect switch: prove whether the loader reaches DriverEntry at all. The
     * whole body is compiled out rather than skipped with an early return,
     * because unreachable code is a warning and this project builds with /WX.
     */
    IwanNtTrace(IWAN_NT_STAGE_ENTRY);

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    return STATUS_SUCCESS;
#else
    NTSTATUS status;

    IwanNtTrace(IWAN_NT_STAGE_ENTRY);

    IwanNtMiniportDriverHandle = NULL;

    /*
     * Register the miniport driver first. NdisRegisterDeviceEx below relies on
     * the wrapper state that NdisMRegisterMiniportDriver installs; calling it
     * before any miniport registration faults inside NDIS with a near-null
     * write (observed as bugcheck 0x50).
     */
    status = IwanNtMiniportRegisterDriver(
        DriverObject, RegistryPath, IwanNtMiniportUnload,
        &IwanNtMiniportDriverHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    IwanNtTrace(IWAN_NT_STAGE_MINIPORT);

    /*
     * The control device comes second. A miniport that came up without a way
     * to install a session would advertise a tunnel that never carries
     * traffic, so failing here rolls the miniport registration back.
     */
    status = IwanNtControlRegister(DriverObject);
    if (!NT_SUCCESS(status)) {
        IwanNtMiniportUnregisterDriver(&IwanNtMiniportDriverHandle);
        return status;
    }

    IwanNtTrace(IWAN_NT_STAGE_CONTROL);

    IwanNtTrace(IWAN_NT_STAGE_ENTRY_DONE);

    return STATUS_SUCCESS;
#endif
}
