#ifndef IWAN_NT_ADDR_H
#define IWAN_NT_ADDR_H

#include "iwan_nt_types.h"
/* SOCKADDR_IN and SOCKADDR_IN6 live in the WSK header, not in <ntddk.h>. */
#if defined(IWAN_NT_KERNEL)
#include <wsk.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * One peer address, either family.
 *
 * The outer packet is carried by a kernel datagram socket, and which family
 * that socket speaks decides the size of the address. Keeping both shapes in
 * one variable lets the callers pass a single pointer to the provider, whose
 * own calls take PSOCKADDR and read the family out of it.
 *
 * Family is AF_INET or AF_INET6; Port is in network order, because that is what
 * the provider expects and converting at the edges only invites one conversion
 * to be forgotten.
 */
typedef union _IWAN_NT_SOCKADDR {
    SOCKADDR_IN V4;
    SOCKADDR_IN6 V6;
} IWAN_NT_SOCKADDR, *PIWAN_NT_SOCKADDR;

/*
 * Fill in the wildcard address of a family: the socket binds to it and the
 * provider assigns the port.
 */
VOID
IwanNtAddrSetWildcard(
    _Out_ PIWAN_NT_SOCKADDR Address,
    _In_ uint16_t Family
    );

/*
 * Family of an already filled address, or 0 when it is neither AF_INET nor
 * AF_INET6. Reading this from the structure rather than tracking a separate tag
 * keeps the two from disagreeing.
 */
uint16_t
IwanNtAddrFamily(
    _In_ const IWAN_NT_SOCKADDR *Address
    );

/* Length of the address as the provider expects it, given its family. */
size_t
IwanNtAddrLength(
    _In_ const IWAN_NT_SOCKADDR *Address
    );

#ifdef __cplusplus
}
#endif

#endif
