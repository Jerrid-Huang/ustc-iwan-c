/*
 * Carrier MTU plumbing for the control tool.
 *
 * The driver cannot query the path MTU itself (it has no NSI dependency and asks
 * the registry at init instead), so user space measures it and leaves the answer
 * where the driver reads it:
 *
 *   HKLM\SYSTEM\CurrentControlSet\Services\iwannt\Parameters\CarrierMtu
 *
 * Everything here is Windows-only and lives outside the kernel.
 */
#ifndef IWAN_NT_MTU_WIN_H
#define IWAN_NT_MTU_WIN_H

#include <windows.h>

/* Registry value the driver reads at adapter init. */
#define IWAN_NT_MTU_REGISTRY_SUBKEY \
    "SYSTEM\\CurrentControlSet\\Services\\iwannt\\Parameters"
#define IWAN_NT_MTU_REGISTRY_VALUE "CarrierMtu"

/* Read Parameters\CarrierMtu. Returns FALSE when the value does not exist or is
 * not a DWORD; the caller then proceeds with the driver's own default. */
BOOL
IwanNtMtuReadCarrier(
    _Out_ DWORD *CarrierMtu
    );

/* Write Parameters\CarrierMtu, creating the key if needed. */
BOOL
IwanNtMtuWriteCarrier(
    _In_ DWORD CarrierMtu
    );

/* Ask the routing table which interface and MTU a peer is reached through. The
 * address must be a literal IPv4 address in dotted quad form. */
BOOL
IwanNtMtuProbeRoute(
    _In_ const char *PeerIp,
    _Out_ DWORD *CarrierMtu,
    _Out_ DWORD *IfIndex
    );

#endif /* IWAN_NT_MTU_WIN_H */
