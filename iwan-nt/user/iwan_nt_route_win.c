/*
 * Included before <windows.h> on purpose, same reason as the other user-mode
 * translation units: winsock2.h has to come first or the address structures
 * change shape underneath <iphlpapi.h>.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <stdio.h>
#include <string.h>

#include "iwan_nt_route_win.h"

/*
 * Parse "address/length" into the two halves the routing API wants. A missing
 * length is treated as a host route, which is what an operator writing a bare
 * address usually means.
 */
static BOOL
IwanNtRouteParse(
    _In_ PCSTR Prefix,
    _Out_ SOCKADDR_INET *Address,
    _Out_ UINT8 *Length
    )
{
    char text[64];
    char *slash;
    size_t length;
    INT converted;
    INT family;

    if (Prefix == NULL || Address == NULL || Length == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    length = strlen(Prefix);
    if (length == 0 || length >= sizeof(text)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    memcpy(text, Prefix, length + 1);

    slash = strchr(text, '/');
    if (slash != NULL) {
        /*
         * Digits only, converted by hand: sscanf is flagged as unsafe by the MSVC
         * CRT (C4996) and would need _CRT_SECURE_NO_WARNINGS for one call.
         */
        const char *digit = slash + 1;
        unsigned value = 0;
        unsigned digits = 0;

        *slash = '\0';
        while (*digit >= '0' && *digit <= '9') {
            value = value * 10u + (unsigned)(*digit - '0');
            if (value > 128u) {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            digit++;
            digits++;
        }
        if (digits == 0 || *digit != '\0') {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        if (value > 128u) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        *Length = (UINT8)value;
    } else {
        *Length = 0;
    }

    memset(Address, 0, sizeof(*Address));
    family = strchr(text, ':') != NULL ? AF_INET6 : AF_INET;
    converted = InetPtonA(family, text, &Address->Ipv4.sin_addr);
    if (converted != 1) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    Address->si_family = (ADDRESS_FAMILY)family;
    if (slash == NULL) {
        *Length = (family == AF_INET6) ? 128u : 32u;
    } else if (family == AF_INET && *Length > 32u) {
        /* A v4 prefix cannot be longer than its address. */
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

BOOL
IwanNtRouteAddPrefix(
    _In_ ULONG IfIndex,
    _In_ PCSTR Prefix
    )
{
    MIB_IPFORWARD_ROW2 row;
    SOCKADDR_INET address;
    UINT8 length = 0;
    NETIO_STATUS status;

    if (IwanNtRouteParse(Prefix, &address, &length) == FALSE) {
        return FALSE;
    }
    InitializeIpForwardEntry(&row);
    row.InterfaceIndex = IfIndex;
    row.DestinationPrefix.Prefix.si_family = address.si_family;
    if (address.si_family == AF_INET6) {
        row.DestinationPrefix.Prefix.Ipv6.sin6_addr = address.Ipv6.sin6_addr;
    } else {
        row.DestinationPrefix.Prefix.Ipv4.sin_addr = address.Ipv4.sin_addr;
    }
    row.DestinationPrefix.PrefixLength = length;
    /*
     * NextHop stays 0: the tunnel is point to point, so the destination is
     * reachable on link once the prefix route itself exists.
     */
    row.NextHop.si_family = address.si_family;
    row.SitePrefixLength = 0;
    row.Metric = 1;
    row.Protocol = MIB_IPPROTO_NETMGMT;

    status = CreateIpForwardEntry2(&row);
    if (status != NO_ERROR) {
        SetLastError((DWORD)status);
        return FALSE;
    }
    return TRUE;
}

BOOL
IwanNtRouteDeletePrefix(
    _In_ ULONG IfIndex,
    _In_ PCSTR Prefix
    )
{
    MIB_IPFORWARD_ROW2 row;
    SOCKADDR_INET address;
    UINT8 length = 0;
    NETIO_STATUS status;

    if (IwanNtRouteParse(Prefix, &address, &length) == FALSE) {
        return FALSE;
    }
    InitializeIpForwardEntry(&row);
    row.InterfaceIndex = IfIndex;
    row.DestinationPrefix.Prefix.si_family = address.si_family;
    if (address.si_family == AF_INET6) {
        row.DestinationPrefix.Prefix.Ipv6.sin6_addr = address.Ipv6.sin6_addr;
    } else {
        row.DestinationPrefix.Prefix.Ipv4.sin_addr = address.Ipv4.sin_addr;
    }
    row.DestinationPrefix.PrefixLength = length;
    row.NextHop.si_family = address.si_family;

    status = DeleteIpForwardEntry2(&row);
    if (status != NO_ERROR) {
        /* Already gone is the state the caller wanted. */
        if (status == ERROR_NOT_FOUND) {
            return TRUE;
        }
        SetLastError((DWORD)status);
        return FALSE;
    }
    return TRUE;
}

/*
 * A host route for the server on the tunnel interface is the wrong thing here:
 * the server is reached through the carrier, and pinning it to the tunnel would
 * send every encapsulated datagram into the tunnel. The function is kept so the
 * intent is written down, and it pins the address to the carrier interface the
 * caller names, which is the interface the driver's socket already bound to.
 */
BOOL
IwanNtRoutePinServer(
    _In_ PCSTR Address,
    _In_ ULONG IfIndex
    )
{
    char prefix[64];
    int written;

    if (Address == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    written = snprintf(prefix, sizeof(prefix), "%s/32", Address);
    if (written <= 0 || (size_t)written >= sizeof(prefix)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return IwanNtRouteAddPrefix(IfIndex, prefix);
}

BOOL
IwanNtRouteUnpinServer(
    _In_ PCSTR Address,
    _In_ ULONG IfIndex
    )
{
    char prefix[64];
    int written;

    if (Address == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    written = snprintf(prefix, sizeof(prefix), "%s/32", Address);
    if (written <= 0 || (size_t)written >= sizeof(prefix)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return IwanNtRouteDeletePrefix(IfIndex, prefix);
}
