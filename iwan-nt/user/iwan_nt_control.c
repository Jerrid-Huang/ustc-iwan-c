#include "iwan_nt_control.h"

/*
 * One device-control round trip.
 *
 * Every request is METHOD_BUFFERED, so one buffer serves as input and output:
 * the caller fills InLength bytes, and the driver writes up to OutLength.
 */
static BOOL
IwanNtIoctl(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ DWORD Code,
    _In_reads_bytes_opt_(InLength) const void *In,
    _In_ DWORD InLength,
    _Out_writes_bytes_opt_(OutLength) void *Out,
    _In_ DWORD OutLength,
    _Out_opt_ DWORD *Returned
    )
{
    DWORD returned = 0;
    BOOL ok;

    if (Device == NULL || Device->Handle == NULL ||
        Device->Handle == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    ok = DeviceIoControl(
        Device->Handle, Code, (LPVOID)In, InLength, Out, OutLength,
        &returned, NULL);
    if (Returned != NULL) {
        *Returned = returned;
    }
    return ok;
}

BOOL
IwanNtOpen(
    _Out_ PIWAN_NT_DEVICE Device
    )
{
    if (Device == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Device->Handle = CreateFileA(
        IWAN_NT_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    return (Device->Handle != INVALID_HANDLE_VALUE) ? TRUE : FALSE;
}

VOID
IwanNtClose(
    _Inout_ PIWAN_NT_DEVICE Device
    )
{
    if (Device == NULL) {
        return;
    }
    if (Device->Handle != NULL && Device->Handle != INVALID_HANDLE_VALUE) {
        CloseHandle(Device->Handle);
    }
    Device->Handle = INVALID_HANDLE_VALUE;
}

BOOL
IwanNtSetSession(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ UINT16 Sid,
    _In_ UINT32 Token,
    _In_ BOOL Encrypted,
    _In_reads_bytes_(8) const UCHAR *Key
    )
{
    IWAN_NT_SESSION_ABI request;

    if (Key == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(&request, sizeof(request));
    request.Sid = Sid;
    request.Token = Token;
    request.Encrypted = (Encrypted != FALSE) ? 1u : 0u;
    CopyMemory(request.Key, Key, sizeof(request.Key));

    return IwanNtIoctl(
        Device, IWAN_NT_IOCTL_SET_SESSION, &request, sizeof(request), NULL, 0,
        NULL);
}

BOOL
IwanNtClearSession(
    _In_ PIWAN_NT_DEVICE Device
    )
{
    return IwanNtIoctl(
        Device, IWAN_NT_IOCTL_CLEAR_SESSION, NULL, 0, NULL, 0, NULL);
}

BOOL
IwanNtSetPeer(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ UINT32 Address,
    _In_ UINT16 Port
    )
{
    IWAN_NT_PEER_ABI request;

    ZeroMemory(&request, sizeof(request));
    request.Address = Address;
    request.Port = Port;

    return IwanNtIoctl(
        Device, IWAN_NT_IOCTL_SET_PEER, &request, sizeof(request), NULL, 0,
        NULL);
}

BOOL
IwanNtSendControl(
    _In_ PIWAN_NT_DEVICE Device,
    _In_reads_bytes_(Length) const void *Frame,
    _In_ UINT32 Length
    )
{
    if (Frame == NULL || Length == 0 || Length > IWAN_NT_CONTROL_MAX) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return IwanNtIoctl(
        Device, IWAN_NT_IOCTL_SEND_CONTROL, Frame, Length, NULL, 0, NULL);
}

int
IwanNtReadControl(
    _In_ PIWAN_NT_DEVICE Device,
    _Out_writes_bytes_(Capacity) void *Buffer,
    _In_ UINT32 Capacity,
    _Out_opt_ UINT32 *RequiredLength
    )
{
    DWORD returned = 0;

    if (RequiredLength != NULL) {
        *RequiredLength = 0;
    }
    if (Buffer == NULL || Capacity == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    if (IwanNtIoctl(
            Device, IWAN_NT_IOCTL_READ_CONTROL, NULL, 0, Buffer, Capacity,
            &returned) != FALSE) {
        return (int)returned;
    }

    /*
     * The driver reports the required size in the buffer-length slot of a
     * failed buffered request, and DeviceIoControl hands it back through
     * GetLastError() == ERROR_INSUFFICIENT_BUFFER only as ERROR_MORE_DATA on
     * some paths; ask the driver again for the size in both cases.
     */
    if (GetLastError() == ERROR_MORE_DATA ||
        GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        if (RequiredLength != NULL) {
            *RequiredLength = 0;
        }
    }

    /*
     * An empty queue is the common case in a poll loop, so it is not an error:
     * report it as zero bytes and keep LastError untouched for real failures.
     */
    if (GetLastError() == ERROR_NO_MORE_ITEMS) {
        return 0;
    }

    return -1;
}

BOOL
IwanNtGetStats(
    _In_ PIWAN_NT_DEVICE Device,
    _Out_ IWAN_NT_STATS_ABI *Stats
    )
{
    DWORD returned = 0;

    if (Stats == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (IwanNtIoctl(
            Device, IWAN_NT_IOCTL_GET_STATS, NULL, 0, Stats, sizeof(*Stats),
            &returned) == FALSE) {
        return FALSE;
    }

    return (returned == sizeof(*Stats)) ? TRUE : FALSE;
}
