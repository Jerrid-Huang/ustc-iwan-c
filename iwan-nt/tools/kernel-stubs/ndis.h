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

/* Device-object registration, used by the control device. */
typedef struct _NDIS_OBJECT_HEADER {
    UCHAR Type;
    UCHAR Revision;
    USHORT Size;
} NDIS_OBJECT_HEADER;

typedef UNICODE_STRING NDIS_STRING, *PNDIS_STRING;

typedef struct _NDIS_DEVICE_OBJECT_ATTRIBUTES {
    NDIS_OBJECT_HEADER Header;
    PNDIS_STRING DeviceName;
    PNDIS_STRING SymbolicName;
    PDRIVER_DISPATCH *MajorFunctions;
    ULONG ExtensionSize;
    PCUNICODE_STRING DefaultSDDLString;
    LPCGUID DeviceClassGuid;
} NDIS_DEVICE_OBJECT_ATTRIBUTES, *PNDIS_DEVICE_OBJECT_ATTRIBUTES;

#define NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES 0x89
#define NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1 1
#define NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1 \
    ((USHORT)sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES))

NTSTATUS
NdisRegisterDeviceEx(
    PDRIVER_OBJECT DriverObject,
    PNDIS_DEVICE_OBJECT_ATTRIBUTES DeviceObjectAttributes,
    PDEVICE_OBJECT *DeviceObject,
    PNDIS_HANDLE NdisDeviceHandle
    );

VOID
NdisDeregisterDeviceEx(
    NDIS_HANDLE NdisDeviceHandle
    );

VOID
NdisInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

#endif
