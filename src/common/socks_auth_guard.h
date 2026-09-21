#ifndef IWAN_SOCKS_AUTH_GUARD_H
#define IWAN_SOCKS_AUTH_GUARD_H

#include <stdbool.h>
#include <stdint.h>

/* Brute-force auth lockout: tracks wrong-password RFC1929 failures
 * per source IPv4 so a brute-forcing client cannot hammer the token check. */
void auth_fail_note(uint32_t ip, bool success);
bool auth_fail_blocked(uint32_t ip);

#endif /* IWAN_SOCKS_AUTH_GUARD_H */
