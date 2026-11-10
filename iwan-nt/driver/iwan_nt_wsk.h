#ifndef IWAN_NT_WSK_H
#define IWAN_NT_WSK_H

#include <ntddk.h>
#include <stddef.h>
#include <stdint.h>
#include <wsk.h>

#ifdef __cplusplus
extern "C" {
#endif

/* WSK client state owned by the transport context. */
typedef struct _IWAN_NT_WSK_CLIENT {
    WSK_REGISTRATION Registration;
    WSK_CLIENT_NPI ClientNpi;
    WSK_PROVIDER_NPI ProviderNpi;
    BOOLEAN Registered;
    BOOLEAN ProviderCaptured;
} IWAN_NT_WSK_CLIENT, *PIWAN_NT_WSK_CLIENT;

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtWskInitialize(
    _Out_ PIWAN_NT_WSK_CLIENT Client
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtWskCaptureProvider(
    _Inout_ PIWAN_NT_WSK_CLIENT Client
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtWskReleaseProvider(
    _Inout_ PIWAN_NT_WSK_CLIENT Client
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtWskUninitialize(
    _Inout_ PIWAN_NT_WSK_CLIENT Client
    );

#ifdef __cplusplus
}
#endif

#endif
