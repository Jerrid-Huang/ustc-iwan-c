#ifndef IWAN_NT_LEASE_H
#define IWAN_NT_LEASE_H

/*
 * Putting the server's lease onto a local interface.
 *
 * The driver only reports the address: an NDIS miniport does not own the
 * stack's address table, so the assignment has to come from user mode. This is
 * the one place that talks to iphlpapi about it.
 */

#include <windows.h>

#include "iwan_nt_ioctl.h"

/*
 * Add the lease address to IfIndex with the prefix the driver reported. An
 * address that already exists counts as success. IRQL: PASSIVE_LEVEL.
 */
BOOL
IwanNtLeaseApply(
    _In_ UINT32 IfIndex,
    _In_ const IWAN_NT_LEASE_ABI *Lease
    );

#endif
