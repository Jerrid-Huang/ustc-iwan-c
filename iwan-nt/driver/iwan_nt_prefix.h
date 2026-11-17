#ifndef IWAN_NT_PREFIX_H
#define IWAN_NT_PREFIX_H

/*
 * Allowed inner prefixes: the receive-side half of WireGuard's AllowedIPs.
 *
 * The reference client uses its prefix list twice, to choose a peer on egress
 * and to check the inner source address on ingress. A single-session tunnel has
 * only one peer to choose from, so only the ingress check carries information
 * here: without it the adapter indicates anything the peer puts inside a frame,
 * including a source address the operator never routed to this node.
 *
 * An empty table means "not configured" and allows everything, which keeps the
 * driver usable before user mode has pushed a list.
 */

#include "iwan_nt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IWAN_NT_MAX_PREFIXES 32u

typedef struct _IWAN_NT_PREFIX {
    uint32_t Family;      /* 4 or 6 */
    uint32_t Length;      /* bits of the address that must match */
    uint8_t Address[16];  /* network byte order, the rest must be zero */
} IWAN_NT_PREFIX, *PIWAN_NT_PREFIX;

/*
 * Copy at most Capacity entries out of Source, dropping malformed ones (unknown
 * family, prefix longer than the family allows) instead of rejecting the whole
 * list: one bad line in a configuration file must not disable the others.
 *
 * Returns the number of entries stored.
 */
unsigned
IwanNtPrefixSetAllowed(
    IWAN_NT_PREFIX *Table,
    unsigned Capacity,
    const IWAN_NT_PREFIX *Source,
    unsigned Count
    );

/*
 * Does Address fall inside any entry of the same family?
 *
 * Returns 0 when nothing matches. An empty table is handled by the caller, not
 * here, so that this stays a pure predicate.
 */
int
IwanNtPrefixMatch(
    const IWAN_NT_PREFIX *Table,
    unsigned Count,
    unsigned Family,
    const uint8_t *Address
    );

/*
 * Is this inner packet allowed in? Empty table means yes.
 *
 * Length is the whole inner packet, used to reject truncated headers rather
 * than reading past them.
 */
int
IwanNtPrefixInnerAllowed(
    const IWAN_NT_PREFIX *Table,
    unsigned Count,
    unsigned Family,
    const uint8_t *Inner,
    size_t Length
    );

#ifdef __cplusplus
}
#endif

#endif /* IWAN_NT_PREFIX_H */
