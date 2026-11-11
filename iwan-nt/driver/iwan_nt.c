#include "iwan_nt_miniport.h"
#include "iwan_nt_control.h"

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

    IwanNtMiniportDriverHandle = NULL;

    /*
     * The control device comes first: a miniport that came up without a way to
     * install a session would advertise a tunnel that can never carry traffic.
     */
    status = IwanNtControlRegister(DriverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IwanNtMiniportRegisterDriver(
        DriverObject, RegistryPath, IwanNtMiniportUnload,
        &IwanNtMiniportDriverHandle);
    if (!NT_SUCCESS(status)) {
        IwanNtControlDeregister();
        return status;
    }

    return STATUS_SUCCESS;
}
