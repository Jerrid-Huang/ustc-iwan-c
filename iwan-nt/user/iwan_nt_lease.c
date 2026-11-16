/*
 * Apply a lease with iphlpapi.
 *
 * Included before <windows.h> on purpose: winsock2.h has to come first or the
 * winsock 1 headers win and the address structures change shape.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include "iwan_nt_lease.h"

BOOL
IwanNtLeaseApply(
    _In_ UINT32 IfIndex,
    _In_ const IWAN_NT_LEASE_ABI *Lease
    )
{
    MIB_UNICASTIPADDRESS_ROW row;
    DWORD status;

    if (IfIndex == 0 || Lease == NULL || Lease->HasAddress == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceIndex = IfIndex;
    row.Address.si_family = AF_INET;
    CopyMemory(&row.Address.Ipv4.sin_addr, Lease->Address, 4);
    /*
     * The wire carries no netmask. /24 is what puts the gateway on link for the
     * subnet the server allocates from, and a caller that knows better can add
     * the address itself.
     */
    row.OnLinkPrefixLength = (UINT8)((Lease->Prefix == 0) ? 24 : Lease->Prefix);
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
    row.DadState = IpDadStatePreferred;
    row.ValidLifetime = 0xFFFFFFFFu;
    row.PreferredLifetime = 0xFFFFFFFFu;
    row.SkipAsSource = FALSE;

    status = CreateUnicastIpAddressEntry(&row);
    if (status == ERROR_SUCCESS || status == ERROR_OBJECT_ALREADY_EXISTS) {
        return TRUE;
    }

    SetLastError(status);
    return FALSE;
}
