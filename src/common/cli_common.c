#include "cli_common.h"
#include "addr.h"
#include "common.h"
#include "protocol.h"
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
