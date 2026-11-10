/*
 * Local syntax-check stub for the slice of ndis.h used by the iWAN NT
 * miniport entry points. See README.md in this directory.
 */
#ifndef IWAN_NT_STUB_NDIS_H
#define IWAN_NT_STUB_NDIS_H

#include <ntddk.h>

typedef LONG NDIS_STATUS;
typedef PVOID NDIS_HANDLE, *PNDIS_HANDLE;

/* Function type, matching the WDK function-class idiom: MINIPORT_UNLOAD * is a
 * pointer to the unload routine. */
typedef VOID MINIPORT_UNLOAD(PDRIVER_OBJECT DriverObject);

#define NDIS_STATUS_SUCCESS ((NDIS_STATUS)0)
#define NDIS_STATUS_FAILURE ((NDIS_STATUS)0xC0000001L)
#define NDIS_STATUS_NOT_SUPPORTED ((NDIS_STATUS)0xC00000BBL)
#define NDIS_STATUS_PAUSED ((NDIS_STATUS)0x00000001L)
#define NDIS_STATUS_NOT_ACCEPTED ((NDIS_STATUS)0x00000002L)
#define NDIS_STATUS_DEVICE_FAILED ((NDIS_STATUS)0xC0000006L)
#define NDIS_STATUS_BUFFER_TOO_SHORT ((NDIS_STATUS)0xC0000023L)

#endif
