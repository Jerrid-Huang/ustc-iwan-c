#include "iwan_nt_prefix.h"

/*
 * Address comparison is done byte by byte on the prefix, never through a
 * 32-bit load: the inner header is not guaranteed to be aligned, and a
 * misaligned read at DISPATCH_LEVEL is a bug the compiler will not report.
 */

static unsigned
IwanNtPrefixAddressBytes(
    unsigned Family
    )
{
    return (Family == 6u) ? 16u : 4u;
}

static int
IwanNtPrefixValid(
    const IWAN_NT_PREFIX *Entry
    )
{
    unsigned bytes;
    unsigned index;
    unsigned full;
    unsigned remaining;

    if (Entry == NULL) {
        return 0;
    }
    if (Entry->Family != 4u && Entry->Family != 6u) {
        return 0;
    }
    bytes = IwanNtPrefixAddressBytes(Entry->Family);
    if (Entry->Length > bytes * 8u) {
        return 0;
    }

    /*
     * Bits outside the prefix must be zero, otherwise two entries that look the
     * same in a configuration file could compare differently on the wire.
     */
    full = Entry->Length / 8u;
    remaining = Entry->Length % 8u;
    for (index = full; index < bytes; index++) {
        uint8_t value = Entry->Address[index];

        if (index == full && remaining != 0u) {
            value = (uint8_t)(value & (uint8_t)(0xffu << (8u - remaining)));
            if (value != Entry->Address[index]) {
                return 0;
            }
            value = 0;
        }
        if (value != 0u) {
            return 0;
        }
    }
    return 1;
}

static int
IwanNtPrefixCovers(
    const IWAN_NT_PREFIX *Entry,
    const uint8_t *Address
    )
{
    unsigned full = Entry->Length / 8u;
    unsigned remaining = Entry->Length % 8u;
    unsigned index;

    for (index = 0; index < full; index++) {
        if (Entry->Address[index] != Address[index]) {
            return 0;
        }
    }
    if (remaining != 0u) {
        uint8_t mask = (uint8_t)(0xffu << (8u - remaining));

        if ((Entry->Address[full] & mask) != (Address[full] & mask)) {
            return 0;
        }
    }
    return 1;
}

unsigned
IwanNtPrefixSetAllowed(
    IWAN_NT_PREFIX *Table,
    unsigned Capacity,
    const IWAN_NT_PREFIX *Source,
    unsigned Count
    )
{
    unsigned stored = 0;
    unsigned index;

    if (Table == NULL || Capacity == 0u) {
        return 0;
    }
    if (Source == NULL || Count == 0u) {
        return 0;
    }
    for (index = 0; index < Count && stored < Capacity; index++) {
        if (!IwanNtPrefixValid(&Source[index])) {
            continue;
        }
        Table[stored] = Source[index];
        stored++;
    }
    return stored;
}

int
IwanNtPrefixMatch(
    const IWAN_NT_PREFIX *Table,
    unsigned Count,
    unsigned Family,
    const uint8_t *Address
    )
{
    unsigned index;

    if (Table == NULL || Address == NULL || Count == 0u) {
        return 0;
    }
    for (index = 0; index < Count; index++) {
        if (Table[index].Family != Family) {
            continue;
        }
        if (IwanNtPrefixCovers(&Table[index], Address)) {
            return 1;
        }
    }
    return 0;
}

static int
IwanNtPrefixInnerAddressAllowed(
    const IWAN_NT_PREFIX *Table,
    unsigned Count,
    unsigned Family,
    const uint8_t *Inner,
    size_t Length,
    unsigned Offset4,
    unsigned Offset6,
    unsigned Minimum4,
    unsigned Minimum6
    )
{
    const uint8_t *point;

    if (Count == 0u) {
        /* Not configured: the operator has not said what belongs in here. */
        return 1;
    }
    if (Inner == NULL) {
        return 0;
    }
    if (Family == 4u) {
        if (Length < (size_t)Minimum4) {
            return 0;
        }
        point = Inner + Offset4;
    } else if (Family == 6u) {
        if (Length < (size_t)Minimum6) {
            return 0;
        }
        point = Inner + Offset6;
    } else {
        return 0;
    }
    return IwanNtPrefixMatch(Table, Count, Family, point);
}

int
IwanNtPrefixInnerAllowed(
    const IWAN_NT_PREFIX *Table,
    unsigned Count,
    unsigned Family,
    const uint8_t *Inner,
    size_t Length
    )
{
    /* Source: 4 bytes into an IPv4 header, 8 bytes into an IPv6 header. */
    return IwanNtPrefixInnerAddressAllowed(Table, Count, Family, Inner, Length,
                                           12u, 8u, 20u, 40u);
}

int
IwanNtPrefixInnerAllowedTarget(
    const IWAN_NT_PREFIX *Table,
    unsigned Count,
    unsigned Family,
    const uint8_t *Inner,
    size_t Length
    )
{
    /* Destination: 16 bytes into an IPv4 header, 24 bytes into an IPv6 one. */
    return IwanNtPrefixInnerAddressAllowed(Table, Count, Family, Inner, Length,
                                           16u, 24u, 20u, 40u);
}
