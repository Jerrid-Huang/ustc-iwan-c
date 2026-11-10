#include "iwan_nt_miniport.h"

static NDIS_HANDLE IwanNtMiniportDriverHandle;

_Function_class_(MINIPORT_UNLOAD)
_Use_decl_annotations_
static VOID
IwanNtMiniportUnload(
    PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

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

    status = IwanNtMiniportRegisterDriver(
        DriverObject, RegistryPath, IwanNtMiniportUnload,
        &IwanNtMiniportDriverHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}
