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

/* --data-plane <auto|tun|kernel> (iwan-client proxy / iwan-client-oidc).
 *
 *   auto   : **默认值**。Linux 与 Windows 上先选内核数据面：Linux 是内核模块
 *            iwan（模块未加载、/dev/iwan 缺失或布局版本不符、iwan0 被非 iwan
 *            设备占用则回退），Windows 是 WFP callout 驱动 iwan.sys（设备打不开
 *            则回退），两边都起不来才退出；其余平台直接是 tun。
 *   tun    : 现有的 TUN 用户态数据面，行为逐位不变；
 *   kernel : 把数据面交给内核（Linux 内核模块 iwan / Windows WFP 驱动
 *            iwan.sys，客户端不再需要 TUN）。这两个平台之外显式传 kernel 是
 *            用法错误（清晰的错误文本，绝不静默降级成 tun）。
 *
 * 显式指定 tun/kernel 都**不回退**：那是用户点名的平面，失败即失败。
 * 回退只覆盖"内核面在本机根本起不来"这一类启动失败；命中"本 netns 已有
 * 内核会话"（kdp_plane_precheck 的 busy 出参）时不回退 —— 回退过去会用同
 * 一账号把那条会话顶掉（服务端对同源 IP 的第二次 OPEN 按合法重连处理），
 * 比直接失败更糟。
 *
 * 校验放进 cli_opt.validate，取值错误因此由共享 CLI 解析器按用法错误处理
 * （打印 usage 并以 2 退出）。 */
#define IWAN_DATA_PLANE_TUN    "tun"
#define IWAN_DATA_PLANE_KERNEL "kernel"
/* Windows 专有：第二个内核数据面（NDIS 小型端口 + 协议驱动 iwanmp.sys）。
 * 语义与 kernel 相同（报文不进用户态），差别只在设备与实现：kernel 是 WFP
 * callout 注入，kernel-mp 是自成一张虚拟网卡的微型端口。留着它就能在同一台
 * 机器上把两个平面做 A/B（设备名见 iwan_win_abi.h 的 IWAN_WIN_USER_PATH_MP）。
 * 只由用户显式指定：auto 在 Windows 上仍然落在 kernel。 */
#define IWAN_DATA_PLANE_KERNEL_MP "kernel-mp"
#define IWAN_DATA_PLANE_AUTO   "auto"
bool validate_data_plane(const char *val, char *err, size_t errsz);
/* true 表示已校验通过的内核面取值（Linux 内核模块 / Windows 的两个驱动）。 */
bool data_plane_is_kernel(const char *val);
/* true 表示取值是 "kernel-mp"（只有 Windows 上有这个平面）。 */
bool data_plane_is_kernel_mp(const char *val);
/* true 表示取值是 NULL 或 "auto"：调用者还没选定平面，允许自动回退。 */
bool data_plane_is_auto(const char *val);
/* 把 --data-plane 的取值解析成实际使用的平面（返回值是上面的宏之一）。
 * *out_auto = true 表示这是"默认选择"（内核面不可用时可以回退 TUN）；显式
 * 取值时写 false。auto 在 Linux 上解析成 kernel、其余平台解析成 tun。 */
const char *data_plane_resolve(const char *val, bool *out_auto);

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

/* validate a server address literal (uses common.h's unbracket_ipv6).
 * On false, errmsg carries the reason (NUL-terminated) for the caller's
 * own error style. shared by iwan-client (die_invalid_address) and
 * iwan-client-oidc (oidc_die_with_cause("invalid address", ...)). */
bool check_server_ip(const char *server, char *errmsg, size_t errsz);

/* parse and validate res->tun/res->gw into uint32 host order.
 * Returns 1 on success, 0 when the tunnel address is invalid, -1 when
 * the gateway address is invalid (each caller keeps its own error
 * message). Shared by the four construction/re-auth sites. */
int auth_result_addrs(const AuthResult *res, uint32_t *inner_ip,
                      uint32_t *gateway);

#endif
