#include "iwan_nt_addr.h"

VOID
IwanNtAddrSetWildcard(
    _Out_ PIWAN_NT_SOCKADDR Address,
    _In_ uint16_t Family
    )
{
    RtlZeroMemory(Address, sizeof(*Address));

    if (Family == (uint16_t)AF_INET6) {
        Address->V6.sin6_family = (ADDRESS_FAMILY)AF_INET6;
        Address->V6.sin6_port = 0;
    } else {
        Address->V4.sin_family = (ADDRESS_FAMILY)AF_INET;
        Address->V4.sin_port = 0;
    }
}

uint16_t
IwanNtAddrFamily(
    _In_ const IWAN_NT_SOCKADDR *Address
    )
{
    if (Address->V4.sin_family == (ADDRESS_FAMILY)AF_INET) {
        return (uint16_t)AF_INET;
    }
    if (Address->V4.sin_family == (ADDRESS_FAMILY)AF_INET6) {
        return (uint16_t)AF_INET6;
    }
    return 0;
}

size_t
IwanNtAddrLength(
    _In_ const IWAN_NT_SOCKADDR *Address
    )
{
    switch (IwanNtAddrFamily(Address)) {
    case AF_INET:
        return sizeof(SOCKADDR_IN);
    case AF_INET6:
        return sizeof(SOCKADDR_IN6);
    default:
        return 0;
    }
}
