#ifndef IWAN_NT_INET_H
#define IWAN_NT_INET_H

#include <stddef.h>
#include <stdint.h>

/*
 * SAL annotations, empty off Windows. The parser is also built by a host
 * compiler for the unit tests, which has no sal.h.
 */
#ifndef _In_
#define _In_
#endif
#ifndef _In_z_
#define _In_z_
#endif
#ifndef _In_reads_bytes_
#define _In_reads_bytes_(size)
#endif
#ifndef _Out_writes_bytes_
#define _Out_writes_bytes_(size)
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Out_writes_
#define _Out_writes_(size)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Address literals, parsed without winsock.
 *
 * The control library passes addresses as raw bytes in network order, and the
 * command line has to turn what the operator types into those bytes. Using
 * inet_pton would drag winsock2.h ahead of windows.h into every translation unit
 * that touches the ABI, so the two forms are parsed here instead: it keeps the
 * dependency out and it makes the parser testable on the host.
 *
 * IPv6 support covers the textual forms with up to eight hextets and at most one
 * "::" run. An embedded IPv4 tail (the "::ffff:1.2.3.4" spelling) is rejected
 * rather than half-supported.
 */

/* Returns nonzero and writes four network-order bytes on success. */
int
IwanNtParseIPv4(
    _In_z_ const char *Text,
    _Out_writes_bytes_(4) uint8_t *Address
    );

/* Returns nonzero and writes sixteen network-order bytes on success. */
int
IwanNtParseIPv6(
    _In_z_ const char *Text,
    _Out_writes_bytes_(16) uint8_t *Address
    );

/*
 * Parse either form. On success Family is 4 or 6 and the first four bytes of
 * Address are meaningful for IPv4, all sixteen for IPv6 (the rest zeroed).
 */
int
IwanNtParseEndpoint(
    _In_z_ const char *Text,
    _Out_writes_bytes_(16) uint8_t *Address,
    _Out_ uint16_t *Family
    );

/*
 * Render an address in the form the operator can paste into a command. IPv6 is
 * printed as eight plain hextets: no compression, because a form that always
 * round-trips through IwanNtParseIPv6 is worth more here than the shortest
 * possible spelling.
 */
const char *
IwanNtFormatAddress(
    _In_reads_bytes_(16) const uint8_t *Address,
    _In_ uint16_t Family,
    _Out_writes_(Capacity) char *Buffer,
    _In_ size_t Capacity
    );

#ifdef __cplusplus
}
#endif

#endif
