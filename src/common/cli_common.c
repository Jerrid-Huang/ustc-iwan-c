#include "cli_common.h"
#include "addr.h"
#include "auth.h"
#include "common.h"
#include "protocol.h"
#include "socks.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

/* This file holds the helper functions that used to be duplicated
 * verbatim between the iwan-client and iwan-client-oidc CLIs. The
 * implementations are byte-identical to the originals (src/iwan_client.c,
 * src/oidc/oidc_connect.c, src/oidc/oidc_cli.c); only collect_routes /
 * collect_routes6 had their opaque struct parameter (CmdOpts/Opts) turned
 * into the four slist_t members it actually reads. */

void check_gw_server(const char *server, const char *gw)
{
    uint8_t sb[4], gb[4];

    if (!s2ip4(server, sb) || !s2ip4(gw, gb))
        return;
    if (memcmp(sb, gb, sizeof sb) != 0) {
        log_err("WARNING: server-issued gateway %s differs from the "
                "connected server %s (NAT setups are normal; an "
                "unexpected mismatch may indicate a forged OPEN_ACK)",
                gw, server);
    }
}

void collect_routes(slist_t *routes, const slist_t *cidr,
                    const slist_t *ips, const slist_t *domains)
{
    for (size_t i = 0; i < cidr->n; i++)
        slist_push(routes, cidr->v[i]);
    for (size_t i = 0; i < ips->n; i++)
        slist_push(routes, ips->v[i]);
    for (size_t i = 0; i < domains->n; i++)
        slist_push(routes, domains->v[i]);
}

void collect_routes6(slist_t *routes6, const slist_t *cidr6)
{
    for (size_t i = 0; i < cidr6->n; i++)
        slist_push(routes6, cidr6->v[i]);
}

bool valid_listen(const char *val, char *err, size_t errsz)
{
    struct sockaddr_in tmp;
    if (parse_host_port(val, &tmp) == 0)
        return true;
    snprintf(err, errsz, "invalid socket address syntax");
    return false;
}

/* RFC1929 (SOCKS5 username/password) carries the password in a
 * one-byte length field: longer tokens can never authenticate and
 * would silently deny every peer. Reject at parse time. */
bool validate_token_len(const char *val, char *err, size_t errsz)
{
    if (strlen(val) <= 255)
        return true;
    snprintf(err, errsz, "must be at most 255 bytes (RFC1929 limit)");
    return false;
}

/* Shared auth sequence: formerly inline copies in src/iwan_client.c
 * (authenticate) and src/oidc/oidc_connect.c (connect loop + SOCKS
 * re-auth callback). The callers keep their own error messages and
 * password cleanup; see the header for the stage-code contract. */
int authenticate_ex(const char *user, const char *password,
                    const char *ct_pass, uint16_t mtu,
                    const char *server, uint16_t port, int style,
                    AuthResult *res)
{
    uint8_t ct[16];
    if (get_ct(user, password, ct_pass, ct) != 0)
        return -1;   /* malformed --ct-pass hex */
    uint32_t nonce = rand_u32();
    buf_t open;
    buf_init(&open);
    if (build_open(&open, user, ct, mtu, 1, nonce) != 0) {
        buf_free(&open);
        return -2;   /* username too long */
    }
    int fd = do_auth(server, port, open.data, open.len, nonce, style, res);
    buf_free(&open);
    if (fd < 0)
        return -3;   /* handshake failed */
    return fd;
}

/* Session-derived SocksConfig fill shared by the four construction sites
 * (see the header). Callers keep their s2ip4 checks/error paths, the sk
 * scrub and the listen/socks-auth/reauth wiring. */
void socks_cfg_from_auth(SocksConfig *cfg, const AuthResult *res,
                         uint32_t inner_ip, uint32_t gateway,
                         const uint8_t sk[16], int mtu)
{
    cfg->inner_ip = inner_ip;
    cfg->gateway = gateway;
    cfg->mtu = mtu;
    memcpy(cfg->xor_key, sk, sizeof cfg->xor_key);
    cfg->sid = res->sid;
    cfg->token = res->tok;
    cfg->encryption = 1;
    snprintf(cfg->dns, sizeof cfg->dns, "%s", res->dns);
}
