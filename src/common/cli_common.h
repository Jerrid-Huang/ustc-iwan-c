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
 * mismatch is legal in NAT setups, so this is a warning only -- but an
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
 *   auto   : **default**. On Linux and Windows, try the kernel data plane first: on Linux the kernel module
 *            iwan (fall back if the module is not loaded, /dev/iwan is missing, the layout version does not match, or iwan0 is held by a non-iwan
 *            device); on Windows the WFP callout driver iwan.sys (fall back if the device cannot be opened);
 *            exit only if neither comes up; on other platforms it is tun directly.
 *   tun    : the existing TUN userspace data plane, behavior bit-for-bit unchanged;
 *   kernel : hand the data plane to the kernel (Linux kernel module iwan / Windows WFP driver
 *            iwan.sys; the client no longer needs a TUN). Explicitly passing kernel outside these two platforms is
 *            a usage error (clear error text, never a silent fallback to tun).
 *
 * Explicitly specifying tun/kernel both **do not fall back**: that is the plane the user named, failure is failure.
 * Fallback covers only the class of startup failures where "the kernel plane cannot come up on this machine at all"; on hitting "this netns already has
 * a kernel session" (the busy output of kdp_plane_precheck) there is no fallback -- falling back would use the same
 * account to displace that session (the server treats a second OPEN from the same source IP as a legitimate reconnect),
 * which is worse than failing outright.
 *
 * Validation lives in cli_opt.validate, so an invalid value is handled by the shared CLI parser as a usage error
 * (print usage and exit with 2). */
#define IWAN_DATA_PLANE_TUN    "tun"
#define IWAN_DATA_PLANE_KERNEL "kernel"
/* Windows-specific: the second kernel data plane (NDIS miniport + protocol driver iwanmp.sys).
 * Semantics are the same as kernel (packets do not enter userspace); only the device and implementation differ: kernel is WFP
 * callout injection, kernel-mp is a miniport that forms a virtual NIC of its own. Keeping it allows A/B comparison of the two planes
 * on the same machine (device names: see IWAN_WIN_USER_PATH_MP in iwan_win_abi.h).
 * Only explicitly selected by the user: auto still resolves to kernel on Windows. */
#define IWAN_DATA_PLANE_KERNEL_MP "kernel-mp"
#define IWAN_DATA_PLANE_AUTO   "auto"
bool validate_data_plane(const char *val, char *err, size_t errsz);
/* true if this is a validated kernel-plane value (Linux kernel module / the two Windows drivers). */
bool data_plane_is_kernel(const char *val);
/* true if the value is "kernel-mp" (this plane exists only on Windows). */
bool data_plane_is_kernel_mp(const char *val);
/* true if the value is NULL or "auto": the caller has not chosen a plane yet, automatic fallback is allowed. */
bool data_plane_is_auto(const char *val);
/* Resolve the --data-plane value into the plane actually used (the return value is one of the macros above).
 * *out_auto = true means this is the "default choice" (fallback to TUN is allowed when the kernel plane is unavailable); an explicit
 * value writes false. auto resolves to kernel on Linux and to tun on other platforms. */
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
