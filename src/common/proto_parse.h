#ifndef IWAN_PROTO_PARSE_H
#define IWAN_PROTO_PARSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Protocol parsing shared by the lwIP SOCKS5 mode (socks_flow.c) and
 * the TUN-mode kernel-stack relay proxy (relay_proxy.c): SOCKS5
 * greeting / RFC1929 auth / CONNECT frames and HTTP request targets.
 * All functions are pure: no state, no I/O, no allocation — callers
 * own the input buffer and the parsed result. */

/* Parsed network target. af selects the meaningful fields:
 *   0 = domain (host), 4 = IPv4 literal, 6 = IPv6 literal. */
typedef struct {
    int      af;
    uint32_t ip4;         /* network byte order (af == 4) */
    uint8_t  ip6[16];     /* raw wire bytes (af == 6) */
    char     host[256];   /* domain (af == 0); empty otherwise */
    uint16_t port;
} pp_target;

/* Probe a greeting buffer for an HTTP method line: 1 = starts with a
 * known method token + space (switch to HTTP mode), -1 = could still
 * become one (token incomplete; wait for more data), 0 = not HTTP. */
int pp_http_probe(const uint8_t *d, size_t n);

/* Parse an HTTP request target: for CONNECT an authority "host:port"
 * (default port 443), for other methods an absolute-URI
 * "http://host[:port]/path" (scheme stripped; default port 80).
 * Bracketed IPv6 literals supported. Returns 0 on success, -1 on
 * malformed input. */
int pp_http_target(const char *s, size_t n, bool is_connect,
                   pp_target *out);

/* SOCKS5 greeting [5, nmethods, methods...]: with have_token the
 * client must offer RFC1929 (0x02), otherwise no-auth (0x00). Returns
 * 0 when the full frame is present and *method holds the negotiated
 * method (0xff when the client offered no acceptable one); -1 when
 * the frame is incomplete (caller waits for more bytes). */
int pp_socks_greeting(const uint8_t *d, size_t n, bool have_token,
                      uint8_t *method);

/* RFC1929 auth frame [1, ulen, user..., plen, pass...]: returns 1 when
 * complete and valid (user NUL-terminated, pass/plen filled); 0 when
 * complete but malformed (bad version, zero-length field) — caller
 * rejects; -1 when incomplete (caller waits for more bytes). */
int pp_socks_auth_frame(const uint8_t *d, size_t n, char *user,
                        size_t usz, const uint8_t **pass, size_t *plen);

/* SOCKS5 CONNECT request [5, CMD, RSV, ATYP, addr..., port]: returns 0
 * with *cmd and *rep filled (rep = 7 for unsupported command, 8 for
 * unsupported/empty address type) and *out = target; -1 when the
 * frame is incomplete. */
int pp_socks_request(const uint8_t *d, size_t n, uint8_t *cmd,
                     uint8_t *rep, pp_target *out);

#endif /* IWAN_PROTO_PARSE_H */
