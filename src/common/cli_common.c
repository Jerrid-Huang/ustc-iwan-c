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
 * would silently deny every peer. Reject at parse time.
 *
 * R14 H-1: an EMPTY token is equally dangerous in the opposite
 * direction. Callers key "is auth configured?" off the option being
 * non-NULL, and both --socks-token= and --socks-token "" arrive here as
 * a non-NULL "" — so an empty value used to "pass" this check, get stored
 * as a set token, and silently turn --allow-remote into an open
 * (passwordless) proxy. Empty must be rejected outright. */
bool validate_token_len(const char *val, char *err, size_t errsz)
{
    if (val == NULL || val[0] == '\0') {
        snprintf(err, errsz,
                 "must not be empty (empty value would silently disable auth)");
        return false;
    }
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
    /* L8 (bughunt): --mtu 0 / --socks-mtu 0 reach here as 0 (min(0, o.mtu)
     * with no lower bound), which made socks.c's `plen > cfg->mtu`
     * filter drop EVERY downlink datagram silently. Clamp to the
     * protocol's valid range instead of accepting 0. */
    cfg->mtu = mtu < IWAN_MTU_MIN ? IWAN_MTU_MIN
             : mtu > IWAN_MTU_MAX ? IWAN_MTU_MAX : mtu;
    memcpy(cfg->xor_key, sk, sizeof cfg->xor_key);
    cfg->sid = res->sid;
    cfg->token = res->tok;
    cfg->encryption = res->enc;   /* R23-F2: honor OPEN_ACK T_ENCRYPT */
    snprintf(cfg->dns, sizeof cfg->dns, "%s", res->dns);
}

bool check_server_ip(const char *server, char *errmsg, size_t errsz)
{
    char buf[64];
    const char *ip = server;
    struct in_addr a4;
    struct in6_addr a6;
    if (ip[0] == '[') {
        ip = unbracket_ipv6(server, buf, sizeof buf);
    } else if (strchr(ip, ':') != NULL) {
        /* Rust SocketAddr rejects unbracketed IPv6 ("::1:6001" is
         * ambiguous) */
        snprintf(errmsg, errsz, "%s", "invalid socket address syntax");
        return false;
    }
    if (inet_pton(AF_INET, ip, &a4) != 1 &&
        inet_pton(AF_INET6, ip, &a6) != 1) {
        snprintf(errmsg, errsz, "%s", "invalid socket address syntax");
        return false;
    }
    return true;
}

int auth_result_addrs(const AuthResult *res, uint32_t *inner_ip,
                      uint32_t *gateway)
{
    uint8_t b[4];
    if (!s2ip4(res->tun, b))
        return 0;
    *inner_ip = ip4_u32(b);
    if (!s2ip4(res->gw, b))
        return -1;
    *gateway = ip4_u32(b);
    return 1;
}

/* ---- --data-plane （见 cli_common.h 的契约） ---- */

bool validate_data_plane(const char *val, char *err, size_t errsz)
{
    if (strcmp(val, IWAN_DATA_PLANE_TUN) == 0)
        return true;
    if (strcmp(val, IWAN_DATA_PLANE_AUTO) == 0)
        return true;
    if (strcmp(val, IWAN_DATA_PLANE_KERNEL) == 0) {
#if defined(__linux__) || defined(_WIN32)
        /* Linux = 内核模块 iwan；Windows = WFP callout 驱动 iwan.sys。
         * 两者语义相同（内核态数据面、报文不进用户态），所以共用同一个取值。
         * 驱动没装时由运行期决定：auto 会回退 TUN，显式 kernel 报错退出。 */
        return true;
#else
        /* 其余平台（macOS 等）显式传 kernel 必须是用法错误，不能静默降级：
         * 那台机器上根本不存在这条路径 */
        snprintf(err, errsz,
                 "内核数据面（--data-plane kernel）只在 Linux 与 Windows 上可用："
                 "当前平台没有内核数据面，请用 --data-plane tun（默认的 auto 在本平台就是 tun）");
        return false;
#endif
    }
    if (strcmp(val, IWAN_DATA_PLANE_KERNEL_MP) == 0) {
#if defined(_WIN32)
        /* 第二个内核数据面（NDIS 微型端口 + 协议驱动 iwanmp.sys）。它不是
         * 默认选择，只在显式点名时使用 —— 新平面还在验证阶段。 */
        return true;
#else
        snprintf(err, errsz,
                 "内核数据面（--data-plane kernel-mp）只在 Windows 上可用："
                 "它是 NDIS 微型端口 + 协议驱动那一版（iwanmp.sys），"
                 "Linux 侧的内核面就叫 kernel");
        return false;
#endif
    }
    snprintf(err, errsz,
             "只能是 auto、tun、kernel 或 kernel-mp"
             "（auto = 默认，Linux 与 Windows 上先试内核面、不可用则回退 tun；"
             "kernel = 内核数据面，仅 Linux 与 Windows 可用；"
             "kernel-mp = Windows 的 NDIS 内核数据面），实际是 \"%s\"", val);
    return false;
}

bool data_plane_is_kernel(const char *val)
{
    return val != NULL &&
           (strcmp(val, IWAN_DATA_PLANE_KERNEL) == 0 ||
            strcmp(val, IWAN_DATA_PLANE_KERNEL_MP) == 0);
}

bool data_plane_is_kernel_mp(const char *val)
{
    return val != NULL && strcmp(val, IWAN_DATA_PLANE_KERNEL_MP) == 0;
}

bool data_plane_is_auto(const char *val)
{
    return val == NULL || strcmp(val, IWAN_DATA_PLANE_AUTO) == 0;
}

const char *data_plane_resolve(const char *val, bool *out_auto)
{
    if (val == NULL || strcmp(val, IWAN_DATA_PLANE_AUTO) == 0) {
        if (out_auto != NULL)
            *out_auto = true;
#if defined(__linux__) || defined(_WIN32)
        return IWAN_DATA_PLANE_KERNEL;
#else
        return IWAN_DATA_PLANE_TUN;
#endif
    }
    if (out_auto != NULL)
        *out_auto = false;
    return val;
}
