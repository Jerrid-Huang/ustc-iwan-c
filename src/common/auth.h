#ifndef IWAN_AUTH_H
#define IWAN_AUTH_H

#include <stdbool.h>
#include <stdint.h>
#include "common.h"

typedef struct {
    uint16_t sid;
    uint32_t tok;
    char     tun[16];
    char     gw[16];
    char     dns[16];
    /* OPEN_ACK's IPv6 trio: 0x0b inner v6 address, 0x0c v6 DNS, 0x0d v6 gateway.
     * Each TLV's length byte is 0x12 (2-byte TLV header + 16-byte address); the value is
     * a 128-bit address in network order. Empty string = not issued by the server (an all-zero address is treated as
     * not issued, matching client behavior). This repository's server does not send these three TLVs yet. */
    char     tun6[46];
    char     gw6[46];
    char     dns6[46];
    uint16_t mtu;
    uint8_t  enc;   /* data-plane encryption flag from OPEN_ACK T_ENCRYPT (R23-F2) */
    /* Minimal ACK of the new protocol: the server replies only with the authentication echo (username + our own nonce),
     * without issuing tun/gw/dns/mtu. In that case sid/tok are valid, tun/gw/dns are empty strings,
     * and mtu is the default value. Set only when IWAN_ALLOW_MINIMAL_ACK=1. */
    bool     unissued;
} AuthResult;

/* build OPEN packet (appends to out). Returns 0 on success, -1 when the
 * username exceeds 255 bytes (it would corrupt the TLV framing). */
int build_open(buf_t *out, const char *user, const uint8_t ct[16],
               uint16_t mtu, uint8_t enc, uint32_t nonce);

/* connected IPv4 UDP socket with recv timeout. Returns fd or -1. */
int udp_connect(const char *host, uint16_t port, int timeout_ms);

/* derive the 16-byte encrypted password (uses ct_pass_hex if given).
 * Returns 0 on success, -1 when ct_pass_hex is malformed (not exactly
 * 32 hex digits after an optional 0x prefix). */
int get_ct(const char *user, const char *pass, const char *ct_pass_hex,
           uint8_t out[16]);

/* full OPEN/ACK handshake with retries. Returns fd (>=0) and fills r, or -1. */
enum do_auth_style {
    DO_AUTH_AUTH = 0, /* iwan-client auth: "[i] -> OPEN (61B) nonce=...", "  err:", "  timeout:" */
    DO_AUTH_PUMP = 1, /* iwan-client socks/proxy: "[i] -> OPEN", "[i] invalid reply:", "[i] timeout:" */
    DO_AUTH_OIDC = 2, /* iwan-client-oidc: no OPEN line, "  [i] err:", "  [i] timeout:" */
};
int do_auth(const char *server, uint16_t port, const uint8_t *open_pkt, size_t open_len,
            uint32_t nonce, int style, AuthResult *r);

#endif
