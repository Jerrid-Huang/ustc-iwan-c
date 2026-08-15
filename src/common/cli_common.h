#ifndef IWAN_CLI_COMMON_H
#define IWAN_CLI_COMMON_H

#include <stdbool.h>
#include <stddef.h>

#include "auth.h"     /* AuthResult, get_ct/build_open/do_auth */
#include "common.h"   /* slist_t */
#include "socks.h"    /* SocksConfig */

/* Helpers shared verbatim between the iwan-client and iwan-client-oidc
 * CLIs (formerly static copies in src/iwan_client.c, src/oidc/oidc_connect.c
 * and src/oidc/oidc_cli.c). Keep the implementations line-identical with
 * those originals: do not change log text, return values or semantics. */

/* F8: cross-check the server-issued gateway against the server the client
 * actually connected to. Both are dotted-quads; when the server is a
 * hostname (or any non-IPv4 literal) the check is skipped silently. A
 * mismatch is legal in NAT setups, so this is a warning only — but an
 * unexpected mismatch may indicate a forged OPEN_ACK. */
void check_gw_server(const char *server, const char *gw);

/* push the --proxy-cidr / --proxy-ip / --proxy-domain entries onto
 * `routes`, and the --proxy-cidr6 entries onto `routes6` (caller owns and
 * frees the destination lists). Same loop order as the original copies. */
void collect_routes(slist_t *routes, const slist_t *cidr,
                    const slist_t *ips, const slist_t *domains);
void collect_routes6(slist_t *routes6, const slist_t *cidr6);

/* cli_opt.validate callbacks shared by both CLIs (see cli.h) */
bool valid_listen(const char *val, char *err, size_t errsz);
bool validate_token_len(const char *val, char *err, size_t errsz);

/* OPEN/ACK authentication sequence shared by the iwan-client and
 * iwan-client-oidc auth paths (get_ct -> build_open -> do_auth). Returns
 * the connected fd on success (res filled). On failure returns a negative
 * stage code and the caller picks its own message and cleanup:
 *  -1  get_ct failed (malformed --ct-pass hex)
 *  -2  build_open failed (username longer than 255 bytes)
 *  -3  do_auth failed
 * The password string is owned by the caller in every case (iwan-client
 * passes the plain argv pass, the oidc client a freshly decrypted one);
 * it is never freed or scrubbed here. */
int authenticate_ex(const char *user, const char *password,
                    const char *ct_pass, uint16_t mtu,
                    const char *server, uint16_t port, int style,
                    AuthResult *res);

/* Fill the session-derived SocksConfig fields shared by every
 * construction site (iwan-client socks mode + its re-auth callback,
 * iwan-client-oidc socks mode + its re-auth callback): inner_ip/gateway
 * (already parsed and validated by the caller), the mtu min, the xor_key,
 * sid/token, encryption and the dns string. The listen address, the
 * auth_token/open_proxy/allow_remote/ipv6 flags and the reauth wiring are
 * caller-specific and stay at the call sites. */
void socks_cfg_from_auth(SocksConfig *cfg, const AuthResult *res,
                         uint32_t inner_ip, uint32_t gateway,
                         const uint8_t sk[16], int mtu);

#endif
