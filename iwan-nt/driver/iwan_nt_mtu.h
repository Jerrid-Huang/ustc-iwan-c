/* Inner MTU derivation.
 *
 * The adapter has to advertise one MTU before any session exists, and the
 * peer only states its own MTU in the acknowledgement that arrives much
 * later. Both numbers are therefore resolved through one pure function so the
 * driver, the control tool and the tests agree on the arithmetic.
 *
 * The inner MTU must leave room for our frame header and the outer IP/UDP
 * headers, otherwise a full-size inner packet would fragment outside the
 * tunnel, where the peer cannot reassemble it.
 */
#ifndef IWAN_NT_MTU_H
#define IWAN_NT_MTU_H

#include "iwan_nt_types.h"

/* 8 byte frame header + 20 byte IPv4 header + 8 byte UDP header. */
#define IWAN_NT_MTU_OVERHEAD_V4 36u
/* 8 byte frame header + 40 byte IPv6 header + 8 byte UDP header. */
#define IWAN_NT_MTU_OVERHEAD_V6 56u
/* Smallest inner MTU the stack accepts, per RFC 791. */
#define IWAN_NT_MTU_MIN 68u
/* Protocol ceiling shared with the Linux implementation. */
#define IWAN_NT_MTU_MAX 1500u
/* Carrier MTU assumed when the user space tool has not recorded one. */
#define IWAN_NT_MTU_CARRIER_DEFAULT 1500u
/* Largest carrier MTU worth accepting from the registry. Anything above this is
 * a typo rather than a jumbo frame, and the effective MTU is capped anyway. */
#define IWAN_NT_MTU_MAX_CARRIER 9216u

/* Overhead of one family. An unknown family is treated as IPv4, which is the
 * conservative choice for the sender that never sets DF. */
uint32_t
IwanNtMtuOverhead(
    unsigned Family
    );

/* Usable inner MTU.
 *
 * Candidate = CarrierMtu - overhead, further limited by PeerMtu when the peer
 * has stated one (PeerMtu == 0 means "not known yet"), then clamped into
 * [IWAN_NT_MTU_MIN, IWAN_NT_MTU_MAX]. A carrier that cannot even carry the
 * minimum yields IWAN_NT_MTU_MIN rather than zero: init must not fail on a
 * nonsense registry value, and 68 is the only legal answer left. */
uint32_t
IwanNtMtuEffective(
    uint32_t CarrierMtu,
    uint32_t PeerMtu,
    unsigned Family
    );

#endif /* IWAN_NT_MTU_H */
