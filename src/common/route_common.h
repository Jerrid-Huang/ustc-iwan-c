#ifndef IWAN_ROUTE_COMMON_H
#define IWAN_ROUTE_COMMON_H

#include "route.h"

/* Canonical "a.b.c.d/plen" network string (host bits cleared).
 * Returns true if parsed and formatted, false if invalid CIDR. */
bool canon_v4_cidr(const char *c, char out[24]);

/* Derived inner ULA (fd00::/96 + the inner IPv4) as text;
 * returns false when tun_ip is not a valid IPv4. */
bool tun_ula_str(const char *tun_ip, char out[64]);

/* Returns true if c is "default" or "0.0.0.0/0". */
bool is_default_v4(const char *c);

/* Safe string token copy up to cap - 1 bytes and NUL terminates. */
void copy_token(char *dst, size_t cap, const char *tok);

/* Policy-route loop guard: true when the target net/prefix (bytes in
 * wire order: net[0] is the most-significant octet; prefix in bits)
 * covers the tunnel server srv (bare IPv4/IPv6 literal or hostname,
 * resolved on demand). When non-NULL, *exact is set only if the target
 * is the server's own host route (/32, /128): that entry collides with
 * the server pin directly (Linux `route replace` overwrites the pin,
 * Windows races it on interface metrics), while a wider covering prefix
 * only loops once the pin is gone. Callers DROP exact hits and KEEP
 * wider ones with a warning: the pin always outranks the wider prefix,
 * and --ustc legitimately routes a campus net that contains the server.
 * Prefix 0 is NEVER a hit: full-tunnel
 * mode covers the server by design and the /32 pin always wins by
 * longest prefix; that is the documented mechanism, not a mistake.
 * A NULL/unparsable srv never matches. */
bool route_target_hits_server(int family, const uint8_t *net, int prefix,
                              const char *srv, bool *exact);

#endif /* IWAN_ROUTE_COMMON_H */
