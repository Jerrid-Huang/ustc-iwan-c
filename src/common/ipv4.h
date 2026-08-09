#ifndef IWAN_IPV4_H
#define IWAN_IPV4_H

#include <stddef.h>
#include <stdint.h>

/* Validate a raw IPv4 datagram (header + payload, as received on the
 * wire) and extract the addresses.
 *
 * pkt points at the start of the IP header, len is the number of bytes
 * available. Returns 0 when the header is structurally sound and the
 * addresses are usable; *saddr / *daddr are then filled. Returns -1
 * otherwise, leaving *saddr / *daddr untouched.
 *
 * Address convention: the numeric value with the first octet most
 * significant — 10.0.0.2 -> 0x0A000002 — identical on any endianness
 * and equal to the project's ip4_u32() helper (protocol.h); i.e. the
 * value ntohl() yields for the on-wire big-endian u32.
 *
 * Rejection criteria (all return -1):
 *   - pkt/saddr/daddr NULL, or len < 20
 *   - version != 4, IHL < 5, or IHL*4 > len
 *   - IP total length < IHL*4 or > len (truncated / padded garbage)
 *   - src: 0.0.0.0, 224.0.0.0/4 multicast, 255.255.255.255 broadcast
 *     (127.0.0.0/8 loopback sources are an allowed exception: local
 *     services such as systemd-resolved answer tunneled queries with a
 *     loopback source; the caller's uplink src check, which loopback
 *     can never pass, still protects that direction)
 *   - dst: 224.0.0.0/4 multicast, 255.255.255.255 broadcast
 *
 * Pure pointer-offset parse: no allocation, no logging (the caller
 * decides whether and how to report a drop).
 */
int ipv4_pkt_ok(const uint8_t *pkt, size_t len,
                uint32_t *saddr, uint32_t *daddr);

#endif /* IWAN_IPV4_H */
