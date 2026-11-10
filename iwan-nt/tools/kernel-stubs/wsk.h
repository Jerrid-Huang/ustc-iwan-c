/* Local syntax-check stub for wsk.h; see ntddk.h in this directory. */
#ifndef IWAN_NT_STUB_WSK_H
#define IWAN_NT_STUB_WSK_H

#include <ntddk.h>

#define WSKAPI
#define WSK_FLAG_DATAGRAM_SOCKET 0x00000008
#define WSK_EVENT_RECEIVE_FROM 0x00000002
#define WSK_EVENT_DISABLE 0x00000080

/* The real SOCKADDR/SOCKADDR_IN definitions arrive through <wsk.h>, not through
 * <ntddk.h>; the stub keeps that split so a header that forgets <wsk.h> fails
 * here the same way it fails on the WDK. */
typedef struct _SOCKADDR { USHORT sa_family; } SOCKADDR, *PSOCKADDR;
typedef struct _SOCKADDR_IN {
    USHORT sin_family;
    USHORT sin_port;
    ULONG sin_addr;
    UCHAR sin_zero[8];
} SOCKADDR_IN, *PSOCKADDR_IN;

typedef enum _WSK_CONTROL_SOCKET_TYPE {
    WskSetOption = 0,
    WskGetOption,
    WskIoctl
} WSK_CONTROL_SOCKET_TYPE;

#define MAKE_WSK_VERSION(major, minor) ((((ULONG)(minor)) << 16) | (ULONG)(major))

struct _WSK_CLIENT_DISPATCH_FWD;

typedef struct _WSK_REGISTRATION { PVOID Reserved; } WSK_REGISTRATION, *PWSK_REGISTRATION;

typedef struct _WSK_CLIENT_NPI {
    PVOID ClientContext;
    const void *Dispatch;
} WSK_CLIENT_NPI, *PWSK_CLIENT_NPI;

typedef struct _WSK_BUF {
    PVOID Mdl;
    ULONG Offset;
    ULONG Length;
} WSK_BUF, *PWSK_BUF;

typedef struct _WSK_DATAGRAM_INDICATION {
    struct _WSK_DATAGRAM_INDICATION *Next;
    WSK_BUF Buffer;
    PVOID ControlInfo;
    ULONG ControlInfoLength;
    PSOCKADDR RemoteAddress;
} WSK_DATAGRAM_INDICATION, *PWSK_DATAGRAM_INDICATION;

typedef NTSTATUS(WSKAPI *PFN_WSK_RECEIVE_FROM_EVENT)(
    PVOID SocketContext, ULONG Flags, PWSK_DATAGRAM_INDICATION DataIndication);

typedef struct _WSK_CLIENT_DISPATCH {
    USHORT Version;
    USHORT Reserved;
    PVOID Dispatch;
} WSK_CLIENT_DISPATCH;

typedef struct _WSK_CLIENT_DATAGRAM_DISPATCH {
    PFN_WSK_RECEIVE_FROM_EVENT WskReceiveFromEvent;
} WSK_CLIENT_DATAGRAM_DISPATCH;

typedef struct _WSK_PROVIDER_BASIC_DISPATCH {
    NTSTATUS (*WskControlSocket)(PVOID, WSK_CONTROL_SOCKET_TYPE, ULONG, ULONG,
                                 SIZE_T, PVOID, SIZE_T, PVOID, SIZE_T *, PIRP);
    NTSTATUS (*WskCloseSocket)(PVOID, PIRP);
} WSK_PROVIDER_BASIC_DISPATCH;

typedef struct _WSK_SOCKET { const void *Dispatch; } WSK_SOCKET, *PWSK_SOCKET;

typedef struct _CMSGHDR { SIZE_T DataOffset; SIZE_T DataLength; } CMSGHDR, *PCMSGHDR;

typedef NTSTATUS(WSKAPI *PFN_WSK_SEND_TO)(
    PWSK_SOCKET Socket,
    PWSK_BUF Buffer,
    ULONG Flags,
    PSOCKADDR RemoteAddress,
    ULONG ControlInfoLength,
    PCMSGHDR ControlInfo,
    PIRP Irp);

/*
 * Field order matches the documented layout: the basic dispatch comes first,
 * then the datagram entry points in their published order. Only the members
 * used by this driver are named.
 */
typedef struct _WSK_PROVIDER_DATAGRAM_DISPATCH {
    WSK_PROVIDER_BASIC_DISPATCH Basic;
    NTSTATUS (*WskBind)(PVOID, PSOCKADDR, ULONG, PIRP);
    PFN_WSK_SEND_TO WskSendTo;
} WSK_PROVIDER_DATAGRAM_DISPATCH;


typedef struct _WSK_PROVIDER_NPI {
    PVOID Client;
    struct {
        NTSTATUS (*WskSocket)(PVOID, USHORT, USHORT, USHORT, ULONG, PVOID,
                              const void *, PVOID, PVOID, PVOID, PIRP);
    } *Dispatch;
} WSK_PROVIDER_NPI, *PWSK_PROVIDER_NPI;

typedef struct _WSK_EVENT_CALLBACK_CONTROL {
    const void *NpiId;
    ULONG EventMask;
} WSK_EVENT_CALLBACK_CONTROL;

extern const char NPI_WSK_INTERFACE_ID;

#define WSK_NO_WAIT 0x00000001UL

NTSTATUS WskRegister(PWSK_CLIENT_NPI ClientNpi, PWSK_REGISTRATION Registration);
VOID WskDeregister(PWSK_REGISTRATION Registration);
NTSTATUS WskCaptureProviderNPI(PWSK_REGISTRATION Registration, ULONG WaitTimeout,
                               WSK_PROVIDER_NPI *ProviderNpi);
VOID WskReleaseProviderNPI(PWSK_REGISTRATION Registration);

#endif
