#ifndef IWAN_OIDC_H
#define IWAN_OIDC_H

#ifdef _WIN32
#  include <winsock2.h>
#else
#  include <netinet/in.h>
#endif
#include <stdbool.h>
#include <stdint.h>

#include "cli.h"
#include "common.h"
#include "json.h"
#include "util.h"   /* err_printf (oidc_eprintf alias below) */

#define OIDC_VERSION "0.1.0"

#define OIDC_DOMAIN          "iwan.ustc"
#define OIDC_APP_SECRET      "ca6a3532abd2986a03b86b3a"
#define OIDC_CONTROLLER_HOST "crtl.ivpn.ustc.edu.cn"
#define OIDC_AUTH_HOST       "auth.ivpn.ustc.edu.cn"
#define OIDC_AUTH_PATH       "/login/oauth/authorize"
#define OIDC_TOKEN_PATH      "/api/login/oauth/access_token"
#define OIDC_CLIENT_ID       "afc6479ffb531d71daef"
#define OIDC_REDIRECT        "com.panabit.mobile://oauth2redirect"
#define OIDC_SCOPE           "openid profile email offline_access"
#define OIDC_APP_ID          "controller-ustc"
#define OIDC_DEFAULT_PORT    6001

typedef struct {
    char *domain;   /* owned */
    Json *root;     /* owned parsed tree; servers points inside */
    Json *servers;  /* into root */
    char *pretty;   /* owned pretty JSON text for saving (NULL when loaded) */
} Config;

/* program options parsed from argv */
typedef struct {
    const char *config_dir;
    bool        fetch;
    bool        list;
    bool        connect;
    bool        all;
    const char *server;
    const char *tun;
    slist_t     proxy_cidr;
    slist_t     proxy_ip;
    slist_t     proxy_domain;
    slist_t     proxy_cidr6;    /* IPv6: CIDRs, addresses or domains */
    bool        ustc;   /* route USTC campus networks through the tunnel */
    bool        socks;
    const char *socks_listen;
    uint16_t    socks_mtu;
    const char *socks_token;   /* RFC1929 password; NULL = no auth */
    bool        socks_no_token;/* explicit opt-out for --allow-remote */
    bool        allow_remote;
    bool        socks_ipv6;    /* assume the server relays IPv6 (opt-in) */
} Opts;

/* oidc_util.c */
/* IWAN_PRINTF_LIKE comes from util.h (included above): R37-F3 puts the
 * OIDC CLI's fatal-error printer under the same compile-time format
 * checking as the core loggers. oidc_die_with_cause takes a plain
 * message + cause pair (no variadic format), so it stays unannotated. */
_Noreturn void oidc_die(const char *fmt, ...) IWAN_PRINTF_LIKE(1, 2);
_Noreturn void oidc_die_with_cause(const char *msg, const char *cause);
void oidc_pause_if_relaunched(void);
/* oidc_eprintf is the raw-stderr printer (no newline, no flush) shared
 * with the core CLI helpers: err_printf (util.h) has the identical
 * contract, so this is a plain alias — a function wrapper could not
 * forward the variadic args anyway. */
#define oidc_eprintf err_printf
void oidc_rand_bytes(uint8_t *out, size_t n);
void oidc_hex_upper(const uint8_t *b, size_t n, char *out);
void oidc_urlenc(const char *s, buf_t *out);
void oidc_buf_cstr(buf_t *b);
char *oidc_buf_to_cstr(buf_t *b);
void oidc_esc_put(buf_t *b, const char *s);
/* pull a named query parameter out of a URL/query string; returns a
 * newly allocated URL-decoded value (caller frees) or NULL when absent */
char *oidc_url_param(const char *s, const char *name);
char *oidc_id_token_username(const char *jwt);

/* oidc_cli.c */
void oidc_parse_cli(int argc, char **argv, Opts *o, Cli *usage);
const char *oidc_usage(const Cli *c);

/* oidc_config.c */
void oidc_fetch_config(Config *cf);
void oidc_save_config(const char *path, const Config *cf);
void oidc_load_config(const char *path, Config *cf);
void oidc_config_free(Config *cf);
/* R37-FIX-A2 / A2b (R3-L18): the ONE root-write guard and the ONE
 * canonical spelling of the config path. Both live in oidc_config.c next
 * to normalize_path() and are shared by the three call sites that MUST
 * agree — the --config-dir CLI gate, iwan-client-oidc's early gate and
 * the oidc_save_config() backstop. Declared here so the prototype cannot
 * drift from the definition; the file-local normalization helper and its
 * NormPath scratch type deliberately do NOT appear: neither is exported. */
bool oidc_config_dir_resolves_to_root(const char *dir);
char *oidc_config_canon_path(const char *path);

/* oidc_flow.c */
void oidc_login(char **kp_out, char **user_out);
int  oidc_ctrl_post(const char *path, const char *body, const char *kp,
                    char **resp_out);
char *oidc_build_dev_body(const char *type, const char *device_id,
                          const char *username);

/* oidc_jwt.c */
/* verify an id_token JWT (signature against the issuer's JWKS plus
 * aud/iss/exp claim validation and, when expected_nonce is non-NULL,
 * the OIDC nonce echo — OIDC Core 3.1.3.7); returns 0 when valid,
 * non-zero otherwise (reason on stderr). Fail-closed on network/parse
 * errors. expected_nonce = the nonce sent in the authorization request
 * (NULL skips the nonce check). */
int oidc_jwt_verify(const char *jwt, const char *aud, const char *iss,
                    const char *expected_nonce);
/* extract one base64url segment of a JWT (0=header, 1=payload, 2=sig),
 * decoded to a NUL-terminated string; NULL on malformed input or
 * allocation failure */
char *oidc_jwt_segment(const char *jwt, int idx);

/* oidc_select.c */
void oidc_print_servers(Json *servers);
Json *oidc_find_server(Json *servers, const char *spec);
Json *oidc_select_server(Json *servers);
/* R37-WG-E1 (L28/L39): a terminal-safe copy of a remote-controlled string
 * — C0/C1 control bytes, stray/invalid UTF-8 and non-shortest (overlong),
 * surrogate or >U+10FFFF sequences each become '?'. DISPLAY ONLY: the
 * raw value must keep being used for matching, comparison and storage.
 * Caller owns the result (free it; oidc_die paths may rely on _Noreturn). */
char *oidc_printable_dup(const char *s);

/* oidc_connect.c */
void oidc_connect_server(const Opts *o, const Config *cf);
void oidc_elevate_root(int argc, char **argv);
/* server "port" value from a server entry: 1 = valid (out set),
 * 0 = absent (caller uses OIDC_DEFAULT_PORT), -1 = not an integer in
 * 1..65535 (raw receives the offending value). */
int oidc_server_port(const Json *srv, uint16_t *out, double *raw);

#endif
