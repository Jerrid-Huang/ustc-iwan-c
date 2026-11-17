/*
 * Included before <windows.h> on purpose: winsock2.h has to come first or the
 * winsock 1 headers win and the address structures change shape.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <stdio.h>
#include <string.h>

#include "iwan_nt_mtu_win.h"

BOOL
IwanNtMtuReadCarrier(
    _Out_ DWORD *CarrierMtu
    )
{
    HKEY key = NULL;
    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    LONG status;

    if (CarrierMtu == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, IWAN_NT_MTU_REGISTRY_SUBKEY,
                           0, KEY_QUERY_VALUE, &key);
    if (status != ERROR_SUCCESS) {
        SetLastError((DWORD)status);
        return FALSE;
    }
    status = RegQueryValueExA(key, IWAN_NT_MTU_REGISTRY_VALUE, NULL, &type,
                              (LPBYTE)&value, &size);
    RegCloseKey(key);
    if (status != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(value)) {
        SetLastError((status == ERROR_SUCCESS) ? ERROR_INVALID_DATA : (DWORD)status);
        return FALSE;
    }
    *CarrierMtu = value;
    return TRUE;
}

BOOL
IwanNtMtuWriteCarrier(
    _In_ DWORD CarrierMtu
    )
{
    HKEY key = NULL;
    DWORD disposition = 0;
    LONG status;

    status = RegCreateKeyExA(HKEY_LOCAL_MACHINE, IWAN_NT_MTU_REGISTRY_SUBKEY, 0,
                             NULL, 0, KEY_SET_VALUE, NULL, &key, &disposition);
    if (status != ERROR_SUCCESS) {
        SetLastError((DWORD)status);
        return FALSE;
    }
    status = RegSetValueExA(key, IWAN_NT_MTU_REGISTRY_VALUE, 0, REG_DWORD,
                            (const BYTE *)&CarrierMtu, sizeof(CarrierMtu));
    RegCloseKey(key);
    if (status != ERROR_SUCCESS) {
        SetLastError((DWORD)status);
        return FALSE;
    }
    return TRUE;
}

BOOL
IwanNtMtuProbeRoute(
    _In_ const char *PeerIp,
    _Out_ DWORD *CarrierMtu,
    _Out_ DWORD *IfIndex
    )
{
    IN_ADDR address;
    MIB_IPFORWARDROW route;
    MIB_IPINTERFACE_ROW ipInterface;
    DWORD status;

    if (PeerIp == NULL || CarrierMtu == NULL || IfIndex == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    /* InetPton rather than inet_addr: the deprecated form returns the same
     * INADDR_NONE for 255.255.255.255 as it does for a parse failure. */
    if (InetPtonA(AF_INET, PeerIp, &address) != 1) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(&route, sizeof(route));
    status = GetBestRoute(address.s_addr, 0, &route);
    if (status != NO_ERROR) {
        SetLastError(status);
        return FALSE;
    }

    ZeroMemory(&ipInterface, sizeof(ipInterface));
    InitializeIpInterfaceEntry(&ipInterface);
    ipInterface.Family = AF_INET;
    ipInterface.InterfaceIndex = route.dwForwardIfIndex;
    status = GetIpInterfaceEntry(&ipInterface);
    if (status != NO_ERROR) {
        SetLastError(status);
        return FALSE;
    }

    *IfIndex = route.dwForwardIfIndex;
    /*
     * NlMtu is the interface's own MTU, which is what the carrier can carry. The
     * driver subtracts the tunnel overhead and caps the result, so an unusual
     * value here is not dangerous, it is only a bad guess.
     */
    *CarrierMtu = ipInterface.NlMtu;
    return TRUE;
}
