#include "iwan_nt_miniport.h"
#include "iwan_nt_control.h"
#include "iwan_nt_trace.h"

static NDIS_HANDLE IwanNtMiniportDriverHandle;

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

_Function_class_(DRIVER_INITIALIZE)
_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

#ifdef IWAN_NT_BISECT_EMPTY_ENTRY
    /* Bisect switch: prove whether the loader reaches DriverEntry at all. */
    IwanNtTrace(IWAN_NT_STAGE_ENTRY);
    UNREFERENCED_PARAMETER(RegistryPath);
    return STATUS_SUCCESS;
#endif

    IwanNtMiniportDriverHandle = NULL;

    IwanNtTrace(IWAN_NT_STAGE_ENTRY);

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
}
