/*
 * Local syntax-check stub for the Windows kernel surface used by iWAN NT.
 *
 * This is NOT a WDK replacement. It exists only so that a Linux host can run a
 * parser over the driver sources and the host unit tests can include the same
 * headers. A clean run here proves nothing about API semantics, IRQL rules, SAL
 * coverage, PREfast, or INF validation; only the WDK build does.
 *
 * Layout rules that this file follows, because breaking them silently produces
 * a header that parses in one translation unit and explodes in another:
 *   1. SAL macros first, each guarded on its own.
 *   2. Base scalar typedefs.
 *   3. Structs in dependency order, or forward declared before use.
 *   4. Function prototypes last, once every parameter type exists.
 */
#ifndef IWAN_NT_STUB_NTDDK_H
#define IWAN_NT_STUB_NTDDK_H

#include <stddef.h>
#include <stdint.h>

/* SAL macros: the stub only needs them to disappear. */
#ifndef _In_
#define _In_
#define _Out_
#define _Inout_
#define _In_opt_
#define _Out_opt_
#define _Inout_opt_
#define _Outptr_
#define _Outptr_opt_
#define _Outptr_opt_result_buffer_(n)
#define _Outptr_result_buffer_(n)
#define _Out_writes_(n)
#define _Out_writes_opt_(n)
#define _Out_writes_bytes_(n)
#define _Out_writes_bytes_opt_(n)
#define _Out_writes_bytes_to_(c, l)
#define _In_reads_(n)
#define _In_reads_opt_(n)
#define _In_reads_bytes_(n)
#define _In_reads_bytes_opt_(n)
#define _Inout_updates_bytes_(n)
#define _Inout_updates_bytes_opt_(n)
#define _IRQL_requires_(x)
#define _IRQL_requires_max_(x)
#define _IRQL_requires_min_(x)
#define _IRQL_requires_same_
#define _Function_class_(x)
#define _Use_decl_annotations_
#define _Must_inspect_result_
#define _Success_(x)
#define _Check_return_
#define _Ret_maybenull_
#define _Field_size_(n)
#define _Field_size_bytes_(n)
#define _Post_invalid_
#define _Pre_notnull_
#define _Pre_maybenull_
#endif

typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef unsigned long ULONG;
typedef unsigned long long ULONG64;
typedef long LONG;
typedef long long LONGLONG;
typedef long long LONG64;
typedef long NTSTATUS;
typedef int BOOLEAN;
typedef char CHAR;
typedef char CCHAR;
typedef unsigned short WCHAR;
typedef WCHAR *PWSTR;
typedef unsigned long *PULONG;
typedef unsigned long const *PCULONG;
typedef unsigned long long *PULONG_PTR;
typedef unsigned long *PULONG64;
typedef unsigned long long ULONG_PTR;
typedef unsigned long long SIZE_T;
typedef void VOID;
typedef void *PVOID;
typedef const void *PCVOID;
typedef void *HANDLE;
typedef unsigned long KIRQL;
typedef ULONG_PTR KSPIN_LOCK;

#define TRUE 1
#define FALSE 0
#define MAXULONG 0xffffffffUL

#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_PENDING ((NTSTATUS)0x00000103L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184L)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011L)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_DEVICE_PROTOCOL_ERROR ((NTSTATUS)0xC0000189L)
/* Same value in ntstatus.h; both spellings exist because callers use both. */
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define STATUS_BUFFER_TOO_SHORT ((NTSTATUS)0xC0000023L)
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xC00000A3L)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)
#define STATUS_MORE_PROCESSING_REQUIRED ((NTSTATUS)0xC0000016L)

#define PASSIVE_LEVEL 0
#define DISPATCH_LEVEL 2
#define IO_NO_INCREMENT 0
#define POOL_FLAG_NON_PAGED 0x0000000000000010ULL

#define PAGED_CODE() ((void)0)
#define UNREFERENCED_PARAMETER(p) ((void)(p))
#define NT_ASSERT(e) ((void)0)

#define RtlZeroMemory(d, n) __builtin_memset((d), 0, (n))
#define RtlCopyMemory(d, s, n) __builtin_memcpy((d), (s), (n))

typedef union _LARGE_INTEGER {
    struct {
        ULONG LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _EX_RUNDOWN_REF { ULONG_PTR Count; } EX_RUNDOWN_REF;
typedef struct _KEVENT { ULONG State; } KEVENT, *PKEVENT;
typedef enum _EVENT_TYPE { NotificationEvent, SynchronizationEvent } EVENT_TYPE;
typedef enum _MODE { KernelMode, UserMode } MODE;
typedef enum _KWAIT_REASON { Executive = 0 } KWAIT_REASON;

typedef struct _IO_STATUS_BLOCK {
    NTSTATUS Status;
    ULONG_PTR Information;
} IO_STATUS_BLOCK;

typedef struct _DEVICE_OBJECT DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct _IRP IRP, *PIRP;
typedef struct _MDL MDL, *PMDL;

typedef struct _GUID {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
} GUID, *PGUID;
typedef const GUID *LPCGUID;

/*
 * Enough of the I/O-manager surface for a control device: a buffered
 * device-control request reaches the driver with the parameters in the stack
 * location and one system buffer in the IRP.
 */
#define IRP_MJ_CREATE 0x00
#define IRP_MJ_CLOSE 0x02
#define IRP_MJ_CLEANUP 0x12
#define IRP_MJ_DEVICE_CONTROL 0x0e
#define IRP_MJ_MAXIMUM_FUNCTION 0x1b

#define FILE_ANY_ACCESS 0

typedef enum _IRP_REQUESTOR_MODE { IrpRequestorKernelMode, IrpRequestorUserMode } IRP_REQUESTOR_MODE;

typedef struct _IO_STACK_LOCATION {
    UCHAR MajorFunction;
    union {
        struct {
            ULONG OutputBufferLength;
            ULONG InputBufferLength;
            ULONG IoControlCode;
            PVOID Type3InputBuffer;
        } DeviceIoControl;
    } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

struct _IRP {
    IO_STATUS_BLOCK IoStatus;
    struct {
        union {
            PIO_STACK_LOCATION CurrentStackLocation;
        } Overlay;
    } Tail;
    union {
        PVOID SystemBuffer;
        PVOID UserBuffer;
    } AssociatedIrp;
    MODE RequestorMode;
    ULONG Flags;
};

PIO_STACK_LOCATION
IoGetCurrentIrpStackLocation(
    PIRP Irp
    );

VOID
IoCompleteRequest(
    PIRP Irp,
    CCHAR PriorityBoost
    );

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
typedef const wchar_t *PCWSTR;

typedef NTSTATUS (*PDRIVER_DISPATCH)(PDEVICE_OBJECT, PIRP);

typedef struct _DRIVER_OBJECT {
    PDRIVER_DISPATCH MajorFunction[28];
    PVOID DriverUnload;
    PVOID DeviceObject;
} DRIVER_OBJECT, *PDRIVER_OBJECT;

#define DRIVER_INITIALIZE DriverEntry
#define DRIVER_UNLOAD(Prefix) VOID Prefix(PDRIVER_OBJECT DriverObject)

/* SOCKADDR/SOCKADDR_IN come from <wsk.h> in the real WDK, so the stub keeps
 * them there too: a header that forgets <wsk.h> must fail here as well. */

#define AF_INET 2
#define AF_INET6 23
typedef USHORT ADDRESS_FAMILY;
#define SOCK_DGRAM 2
#define IPPROTO_UDP 17
#define SOL_SOCKET 0xffff
#define SO_WSK_EVENT_CALLBACK 0x3004

/*
 * MDL surface used by the transform and send paths. The stub models an MDL as
 * a node carrying its own byte count and system address, which is enough for
 * the parser and for the host tests.
 */
struct _MDL {
    struct _MDL *Next;
    ULONG ByteCount;
    PVOID MappedSystemVa;
};

typedef enum _MM_PAGE_PRIORITY {
    LowPagePriority = 0,
    NormalPagePriority = 16,
    HighPagePriority = 32
} MM_PAGE_PRIORITY;

#define MdlMappingNoExecute 0x40000000

#define MmGetMdlByteCount(Mdl) ((ULONG)((Mdl)->ByteCount))
#define MmGetSystemAddressForMdlSafe(Mdl, Priority) \
    ((PVOID)((Mdl)->MappedSystemVa))
#define MmBuildMdlForNonPagedPool(Mdl) ((void)(Mdl))

VOID ExInitializeRundownProtection(EX_RUNDOWN_REF *);
BOOLEAN ExAcquireRundownProtection(EX_RUNDOWN_REF *);
VOID ExReleaseRundownProtection(EX_RUNDOWN_REF *);
VOID ExWaitForRundownProtectionRelease(EX_RUNDOWN_REF *);
VOID ExRundownCompleted(EX_RUNDOWN_REF *);
VOID ExReInitializeRundownProtection(EX_RUNDOWN_REF *);

PVOID ExAllocatePool2(ULONG64 Flags, SIZE_T NumberOfBytes, ULONG Tag);
VOID ExFreePoolWithTag(PVOID P, ULONG Tag);

VOID KeInitializeSpinLock(KSPIN_LOCK *);
VOID KeAcquireSpinLock(KSPIN_LOCK *, KIRQL *);
VOID KeReleaseSpinLock(KSPIN_LOCK *, KIRQL);
VOID KeAcquireSpinLockAtDpcLevel(KSPIN_LOCK *);
VOID KeReleaseSpinLockFromDpcLevel(KSPIN_LOCK *);

VOID KeInitializeEvent(PKEVENT, EVENT_TYPE, BOOLEAN);
LONG KeSetEvent(PKEVENT, LONG, BOOLEAN);
VOID KeClearEvent(PKEVENT);
LONG KeReadStateEvent(PKEVENT);
NTSTATUS KeWaitForSingleObject(
    PVOID Object, KWAIT_REASON WaitReason, MODE WaitMode,
    BOOLEAN Alertable, LARGE_INTEGER *Timeout);

PIRP IoAllocateIrp(CCHAR StackSize, BOOLEAN ChargeQuota);
VOID IoFreeIrp(PIRP);
VOID IoReuseIrp(PIRP, NTSTATUS);
VOID IoSetCompletionRoutine(
    PIRP Irp, void *CompletionRoutine, PVOID Context,
    BOOLEAN InvokeOnSuccess, BOOLEAN InvokeOnError, BOOLEAN InvokeOnCancel);
PMDL IoAllocateMdl(
    PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer,
    BOOLEAN ChargeQuota, PIRP Irp);
VOID IoFreeMdl(PMDL);

USHORT RtlUshortByteSwap(USHORT);

#endif
