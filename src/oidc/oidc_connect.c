/* Server connect: SOCKS userspace mode or TUN pump (with sudo re-exec). */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "addr.h"
#include "auth.h"
#include "common.h"
#include "crypto.h"
#include "gcm.h"
#include "oidc.h"
#include "protocol.h"
#include "proxy.h"
#include "socks.h"
#include "tun.h"
#include "util.h"

static int run_socks_mode(const Opts *o, int fd, const uint8_t sk[16],
                          const AuthResult *res)
{
    uint8_t b[4];
    if (!s2ip4(res->tun, b)) {
        log_err("server returned invalid tunnel IPv4 address");
        return -1;
    }
    uint32_t inner_ip = ip4_u32(b);
    if (!s2ip4(res->gw, b)) {
        log_err("server returned invalid gateway IPv4 address");
        return -1;
    }
    uint32_t gateway = ip4_u32(b);

    struct sockaddr_in listen;
    if (parse_host_port(o->socks_listen, &listen) != 0)
        oidc_die("invalid listen address");

    SocksConfig cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.listen_addr = listen;
    cfg.listen_str = o->socks_listen;
    cfg.inner_ip = inner_ip;
    cfg.gateway = gateway;
    cfg.mtu = res->mtu < o->socks_mtu ? res->mtu : o->socks_mtu;
    memcpy(cfg.xor_key, sk, sizeof cfg.xor_key);
    cfg.sid = res->sid;
    cfg.token = res->tok;
    cfg.encryption = o->encrypt;
    snprintf(cfg.dns, sizeof cfg.dns, "%s", res->dns);

    run_socks(fd, &cfg);
    return 0;
}

/* TUN mode needs root: re-exec the whole invocation via sudo when not root */
void oidc_elevate_root(int argc, char **argv)
{
#ifdef _WIN32
    /* TUN mode needs an administrator: relaunch via a UAC prompt
     * (ShellExecuteW runas) instead of failing. The elevated instance
     * passes port_is_admin() and proceeds. --socks paths never call
     * this. */
    if (!port_is_admin()) {
        if (port_elevate_self(argc, argv) == 0)
            exit(0);   /* UAC accepted: the new instance owns the work */
        fprintf(stderr,
                "Error: TUN mode requires administrator privileges "
                "(elevation declined)\n");
        exit(1);
    }
#else
    char self[4096];
    const char *exe = argv[0];
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n > 0) {
        self[n] = '\0';
        exe = self;
    }
    char **args = malloc(((size_t)argc + 2) * sizeof(char *));
    if (!args)
        oidc_die("out of memory");
    args[0] = "sudo";
    args[1] = (char *)exe;
    for (int i = 1; i < argc; i++)
        args[i + 1] = argv[i];
    args[argc + 1] = NULL;
    oidc_eprintf("TUN mode requires root; re-running via sudo...\n");
    exec_sanitize();
    execve("/usr/bin/sudo", args, environ);
    if (errno == ENOENT)
        execve("/bin/sudo", args, environ);
    fprintf(stderr, "Error: cannot run sudo: %s\n", strerror(errno));
    exit(1);
#endif
}

static void collect_routes(const Opts *o, slist_t *routes)
{
    for (size_t i = 0; i < o->proxy_cidr.n; i++)
        slist_push(routes, o->proxy_cidr.v[i]);
    for (size_t i = 0; i < o->proxy_ip.n; i++)
        slist_push(routes, o->proxy_ip.v[i]);
    for (size_t i = 0; i < o->proxy_domain.n; i++)
        slist_push(routes, o->proxy_domain.v[i]);
}

/* server "port" value from a server entry: 1 = valid (out set),
 * 0 = absent (caller uses OIDC_DEFAULT_PORT), -1 = not an integer in
 * 1..65535 (raw receives the offending value). */
int oidc_server_port(const Json *srv, uint16_t *out, double *raw)
{
    Json *p = json_get((Json *)srv, "port");
    if (!p)
        return 0;
    double v = json_num(p);
    if (raw)
        *raw = v;
    if (json_type(p) != JSON_NUM || v != v || v < 1.0 || v > 65535.0 ||
        (double)(long)v != v)
        return -1;
    *out = (uint16_t)v;
    return 1;
}

void oidc_connect_server(const Opts *o, const Config *cf)
{
    Json *servers = cf->servers;
    if (json_arr_len(servers) == 0)
        oidc_die("no servers in config");
    Json *srv;
    if (o->server) {
        srv = oidc_find_server(servers, o->server);
        if (!srv)
            oidc_die("no server matching \"%s\"", o->server);
    } else {
        srv = oidc_select_server(servers);
    }

    const char *name = json_get_str(srv, "name");
    const char *host = json_get_str(srv, "host");
    if (!host || !*host)
        oidc_die("missing host");
    uint16_t port;
    double pv;
    int pr = oidc_server_port(srv, &port, &pv);
    if (pr < 0)
        oidc_die("invalid port %g for server \"%s\" "
                 "(must be an integer in 1..65535)",
                 pv, name ? name : host);
    if (pr == 0)
        port = OIDC_DEFAULT_PORT;
    const char *srv_user = json_get_str(srv, "username");
    const char *encrypted_pw = json_get_str(srv, "passWord");

    char *password = decrypt_password(encrypted_pw ? encrypted_pw : "",
                                      OIDC_APP_SECRET, cf->domain,
                                      srv_user ? srv_user : "");
    if (!password)
        oidc_die("cannot decrypt password");

    oidc_eprintf("  Connecting to %s (%s:%u)...\n", name ? name : "", host,
                 (unsigned)port);

    oidc_check_server_ip(host);

    const char *user = srv_user ? srv_user : "";
    uint8_t ct[16];
    if (get_ct(user, password, NULL, ct) != 0)
        oidc_die("cannot derive password");
    uint32_t nonce = rand_u32();
    buf_t open;
    buf_init(&open);
    if (build_open(&open, user, ct, IWAN_DEFAULT_MTU, o->encrypt, nonce) != 0) {
        buf_free(&open);
        oidc_die("username too long (max 255 bytes)");
    }
    AuthResult res;
    int fd = do_auth(host, port, open.data, open.len, nonce, DO_AUTH_OIDC,
                     &res);
    buf_free(&open);
    if (fd < 0)
        oidc_die("auth failed");
    oidc_eprintf("  OK  tun=%s gw=%s dns=%s mtu=%u\n", res.tun, res.gw,
                 res.dns, (unsigned)res.mtu);

    uint8_t sk[16];
    session_key(user, password, sk);
    OPENSSL_cleanse(password, strlen(password)); /* plaintext credential */
    free(password);

    if (o->socks) {
        int rc = run_socks_mode(o, fd, sk, &res);
        port_close(fd);
        if (rc != 0)
            exit(1);
        return;
    }

    if (!tun_name_valid(o->tun)) {
        port_close(fd);
        oidc_die("invalid TUN device name '%s'", o->tun);
    }

#ifndef _WIN32
    /* Linux: pre-delete a stale tun device by name. Windows: wintun's
     * open_tun (tun_win.c) deletes an existing adapter with the same
     * name as part of open-or-create, so nothing to do here. */
    char *const del[] = { "link", "del", (char *)o->tun, NULL };
    ip_run_quiet(del);
#endif
    int tun_fd = open_tun(o->tun);
    if (tun_fd < 0) {
        port_close(fd);
        oidc_die("open tun (must be root or CAP_NET_ADMIN)");
    }
    set_nonblock(tun_fd);
    if (debug_enabled())
        oidc_eprintf("  tun %s fd=%d\n", o->tun, tun_fd);

    slist_t routes;
    slist_init(&routes);
    collect_routes(o, &routes);

    int rc = run_pump(tun_fd, o->tun, fd, sk, res.sid, res.tok, o->encrypt,
                      host, &routes, res.tun, res.mtu);
    tun_close(tun_fd);
    port_close(fd);
    slist_free(&routes);
    if (rc != 0)
        exit(1);
}