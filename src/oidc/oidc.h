#ifndef IWAN_OIDC_H
#define IWAN_OIDC_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include "cli.h"
#include "common.h"
#include "json.h"

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
    bool        ustc;   /* route USTC campus networks through the tunnel */
    uint8_t     encrypt;
    bool        socks;
    const char *socks_listen;
    uint16_t    socks_mtu;
} Opts;

/* oidc_util.c */
void oidc_die(const char *fmt, ...);
void oidc_die_with_cause(const char *msg, const char *cause);
void oidc_eprintf(const char *fmt, ...);
void oidc_rand_bytes(uint8_t *out, size_t n);
void oidc_check_server_ip(const char *server);
void oidc_hex_upper(const uint8_t *b, size_t n, char *out);
void oidc_urlenc(const char *s, buf_t *out);
char *oidc_urldec(const char *s, size_t n);
void oidc_buf_cstr(buf_t *b);
char *oidc_buf_to_cstr(buf_t *b);
void oidc_esc_put(buf_t *b, const char *s);
char *oidc_extract_code(const char *s);
char *oidc_id_token_username(Json *tok);

/* oidc_cli.c */
void oidc_parse_cli(int argc, char **argv, Opts *o, Cli *usage);
const char *oidc_usage(const Cli *c);

/* oidc_config.c */
void oidc_fetch_config(Config *cf);
void oidc_save_config(const char *path, const Config *cf);
void oidc_load_config(const char *path, Config *cf);
void oidc_config_free(Config *cf);

/* oidc_flow.c */
void oidc_login(char **kp_out, char **user_out);
int  oidc_ctrl_post(const char *path, const char *body, const char *kp,
                    char **resp_out);
char *oidc_build_dev_body(const char *type, const char *device_id,
                          const char *username);

/* oidc_select.c */
void oidc_print_servers(Json *servers);
Json *oidc_find_server(Json *servers, const char *spec);
Json *oidc_select_server(Json *servers);

/* oidc_connect.c */
void oidc_connect_server(const Opts *o, const Config *cf);
void oidc_elevate_root(int argc, char **argv);

#endif