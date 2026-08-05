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
    uint16_t mtu;
} AuthResult;

/* build OPEN packet (appends to out). */
void build_open(buf_t *out, const char *user, const uint8_t ct[16],
                uint16_t mtu, uint8_t enc, uint32_t nonce);

/* parse OPEN_ACK. On success fills r and returns true; errmsg (if set) on failure. */
bool parse_ack(const uint8_t *buf, size_t len, uint32_t expect_nonce,
               AuthResult *r, char *errmsg, size_t errmsg_sz);

/* connected IPv4 UDP socket with recv timeout. Returns fd or -1. */
int udp_connect(const char *host, uint16_t port, int timeout_ms);

/* derive the 16-byte encrypted password (uses ct_pass_hex if given). */
void get_ct(const char *user, const char *pass, const char *ct_pass_hex,
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
