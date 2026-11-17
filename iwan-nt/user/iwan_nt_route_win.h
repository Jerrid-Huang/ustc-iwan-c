#ifndef IWAN_NT_ROUTE_WIN_H
#define IWAN_NT_ROUTE_WIN_H

/*
 * Route installation for the inner side.
 *
 * An address alone is not a tunnel: without a route that points the inner prefix
 * at the tunnel adapter, the stack either cannot send at all or sends through the
 * physical interface. The reference client installs one route per configured
 * prefix plus a /32 pin for the server so the encapsulated datagrams do not
 * follow the route they create.
 *
 * Everything here is best effort and reversible: the add returns FALSE with a
 * Win32 error, and delete ignores a missing entry so a failed run can be cleaned
 * up twice without lying about it.
 */

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Add or remove one prefix route on the given interface. Prefix is written the
 * way an operator writes it: "198.18.0.0/24" or "fd00::/64". The next hop is the
 * interface itself, which is what a point-to-point tunnel wants.
 */
BOOL
IwanNtRouteAddPrefix(
    _In_ ULONG IfIndex,
    _In_ PCSTR Prefix
    );

BOOL
IwanNtRouteDeletePrefix(
    _In_ ULONG IfIndex,
    _In_ PCSTR Prefix
    );

/*
 * Pin the server address to a specific interface. Without this the encapsulated
 * datagrams to the server can match a route that was just installed for the inner
 * network, and the tunnel ends up routing itself.
 */
BOOL
IwanNtRoutePinServer(
    _In_ PCSTR Address,
    _In_ ULONG IfIndex
    );

BOOL
IwanNtRouteUnpinServer(
    _In_ PCSTR Address,
    _In_ ULONG IfIndex
    );

#ifdef __cplusplus
}
#endif

#endif /* IWAN_NT_ROUTE_WIN_H */
