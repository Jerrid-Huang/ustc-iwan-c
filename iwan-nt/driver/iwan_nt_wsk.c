#include "iwan_nt_wsk.h"

static const WSK_CLIENT_DISPATCH IwanNtWskClientDispatch = {
    MAKE_WSK_VERSION(1, 0),
    0,
    NULL
};

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtWskCaptureProvider(
    _Inout_ PIWAN_NT_WSK_CLIENT Client
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (Client == NULL || !Client->Registered) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (Client->ProviderCaptured) {
        return STATUS_SUCCESS;
    }

    status = WskCaptureProviderNPI(
        &Client->Registration,
        WSK_NO_WAIT,
        &Client->ProviderNpi);
    if (NT_SUCCESS(status)) {
        Client->ProviderCaptured = TRUE;
    }

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtWskReleaseProvider(
    _Inout_ PIWAN_NT_WSK_CLIENT Client
    )
{
    PAGED_CODE();

    if (Client == NULL || !Client->ProviderCaptured) {
        return;
    }

    WskReleaseProviderNPI(&Client->Registration);
    RtlZeroMemory(&Client->ProviderNpi, sizeof(Client->ProviderNpi));
    Client->ProviderCaptured = FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtWskInitialize(
    _Out_ PIWAN_NT_WSK_CLIENT Client
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (Client == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Client, sizeof(*Client));
    Client->ClientNpi.ClientContext = Client;
    Client->ClientNpi.Dispatch = &IwanNtWskClientDispatch;

    status = WskRegister(&Client->ClientNpi, &Client->Registration);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Client->Registered = TRUE;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtWskUninitialize(
    _Inout_ PIWAN_NT_WSK_CLIENT Client
    )
{
    PAGED_CODE();

    if (Client == NULL) {
        return;
    }

    IwanNtWskReleaseProvider(Client);

    if (Client->Registered) {
        WskDeregister(&Client->Registration);
        RtlZeroMemory(&Client->Registration, sizeof(Client->Registration));
        Client->Registered = FALSE;
    }

    RtlZeroMemory(&Client->ClientNpi, sizeof(Client->ClientNpi));
}
