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

#endif /* IWAN_ROUTE_COMMON_H */
