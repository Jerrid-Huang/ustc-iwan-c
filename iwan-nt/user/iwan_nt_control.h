#ifndef IWAN_NT_USER_CONTROL_H
#define IWAN_NT_USER_CONTROL_H

/*
 * User-mode side of the iWAN NT control device.
 *
 * The device ABI itself lives in one header shared with the driver, so this
 * module only adds Win32 plumbing: open, close, and one wrapper per IOCTL that
 * maps a failure to GetLastError.
 *
 * Threading: IWAN_NT_DEVICE is not thread safe. Give the reader (READ_CONTROL
 * in a loop) and the writer (SEND_CONTROL, session updates) their own handles
 * if both must run at once; the driver serializes internally either way.
 */

#include <windows.h>

/*
 * The two families this ABI accepts. <windows.h> pulls in winsock v1, which
 * spells AF_INET but does not always carry AF_INET6, and the library does not
 * otherwise need the winsock headers.
 */
#ifndef AF_INET6
#define AF_INET6 23
#endif

#include "../driver/iwan_nt_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _IWAN_NT_DEVICE {
    HANDLE Handle;
} IWAN_NT_DEVICE, *PIWAN_NT_DEVICE;

/* Open \\.\IwanNt. FALSE on failure; call GetLastError. */
BOOL
IwanNtOpen(
    _Out_ PIWAN_NT_DEVICE Device
    );

VOID
IwanNtClose(
    _Inout_ PIWAN_NT_DEVICE Device
    );

/* Install the session the OPEN_ACK described. */
BOOL
IwanNtSetSession(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ UINT16 Sid,
    _In_ UINT32 Token,
    _In_ BOOL Encrypted,
    _In_reads_bytes_(8) const UCHAR *Key
    );

BOOL
IwanNtClearSession(
    _In_ PIWAN_NT_DEVICE Device
    );

/*
 * Hand the handshake to the driver. From here the tunnel stays up as long as the
 * driver runs, whatever this process does; stop it with IwanNtStopPeer.
 */
BOOL
IwanNtStartPeer(
    _In_ PIWAN_NT_DEVICE Device,
    _In_z_ const char *User,
    _In_z_ const char *Password,
    _In_ UINT16 Mtu
    );

/* Stop the in-kernel handshake and drop the session it installed. */
BOOL
IwanNtStopPeer(
    _In_ PIWAN_NT_DEVICE Device
    );

/*
 * Peer endpoint, in either family. Address is the network-order address for
 * Family (the first four bytes for AF_INET, all sixteen for AF_INET6) and Port
 * is in network order. A family change on a running transport makes the driver
 * build a new socket, which keeps the session.
 */
BOOL
IwanNtSetPeer(
    _In_ PIWAN_NT_DEVICE Device,
    _In_reads_bytes_(16) const UINT8 *Address,
    _In_ UINT16 Family,
    _In_ UINT16 Port
    );

/* Send one complete control frame (frame header, signature and TLVs). */
BOOL
IwanNtSendControl(
    _In_ PIWAN_NT_DEVICE Device,
    _In_reads_bytes_(Length) const void *Frame,
    _In_ UINT32 Length
    );

/*
 * Dequeue one control frame.
 *
 * Returns the frame length, 0 when nothing is queued, or -1 on failure. A
 * frame longer than Capacity is not lost: the call returns -1 with
 * GetLastError() == ERROR_INSUFFICIENT_BUFFER and RequiredLength set, so the
 * caller can retry with a bigger buffer.
 */
/*
 * Read the address the driver's socket is bound to, in network order. Useful for
 * telling "the peer never answered" from "the answer went to another port".
 */
BOOL
IwanNtGetLocal(
    _In_ PIWAN_NT_DEVICE Device,
    _Out_writes_bytes_(16) UINT8 *Address,
    _Out_ UINT16 *Family,
    _Out_ UINT16 *Port
    );

int
IwanNtReadControl(
    _In_ PIWAN_NT_DEVICE Device,
    _Out_writes_bytes_(Capacity) void *Buffer,
    _In_ UINT32 Capacity,
    _Out_opt_ UINT32 *RequiredLength
    );

BOOL
IwanNtGetStats(
    _In_ PIWAN_NT_DEVICE Device,
    _Out_ IWAN_NT_STATS_ABI *Stats
    );

#ifdef __cplusplus
}
#endif

#endif
