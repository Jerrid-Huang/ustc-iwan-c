#ifndef IWAN_IPV4_H
#define IWAN_IPV4_H

#include <stddef.h>
#include <stdint.h>

/* ---------------- one's-complement checksums (RFC 1071) ----------------
 * Shared by netstack.c (TCP) and socks_flow.c (UDP): previously three
 * independent copies of the same 16-bit BE accumulation. */

/* accumulate 16-bit big-endian words; `sum` chains calls (start 0).
 * gcc auto-vectorizes this loop (57ns/1340B @ -O2). */
uint32_t ip_csum_accum(uint32_t sum, const void *p, size_t n);
/* fold a 32-bit accumulation and return the complemented 16-bit value */
uint16_t ip_csum_fold(uint32_t sum);
/* TCP checksum over the 12-byte IPv4 pseudo header + TCP segment. The
 * caller must zero the checksum field in the segment first. */
uint16_t ip_tcp_csum(uint32_t sip, uint32_t dip, const void *tcp, size_t n);
/* TCP checksum over the 40-byte IPv6 pseudo header (16-byte src+dst,
 * next-header TCP, 32-bit segment length) + TCP segment. The caller
 * must zero the checksum field in the segment first. */
uint16_t ip6_tcp_csum(const uint8_t sip[16], const uint8_t dip[16],
                      const void *tcp, size_t n);
/* UDP checksum over the IPv4 pseudo header + UDP datagram. The caller
 * must zero the checksum field in the datagram first. */
uint16_t ip_udp_csum(uint32_t sip, uint32_t dip, const void *udp, size_t n);

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

/* Validate a raw IPv6 datagram (header + payload, as received on the
 * wire) and extract the addresses as raw 16-byte values.
 *
 * Rejection criteria (all return -1):
 *   - pkt/saddr/daddr NULL, or len < 40
 *   - version != 6
 *   - payload length (plen) + 40 > len (truncated / padded garbage)
 *   - src: :: (any), ff00::/8 multicast
 *   - dst: ff00::/8 multicast
 *
 * Same pointer-offset parse discipline as ipv4_pkt_ok: no allocation,
 * no logging. */
int ip6_pkt_ok(const uint8_t *pkt, size_t len,
               uint8_t saddr[16], uint8_t daddr[16]);

#endif /* IWAN_IPV4_H */
