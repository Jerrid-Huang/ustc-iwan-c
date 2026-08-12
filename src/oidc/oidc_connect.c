/* Server connect: SOCKS userspace mode or TUN pump (with sudo re-exec). */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>   /* _NSGetExecutablePath */
extern char **environ;     /* macOS unistd.h does not declare it */
#endif

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

/* F8: cross-check the server-issued gateway against the server actually
 * connected to (same check as iwan_client's proxy/socks paths; the OIDC
 * entry missed it). A mismatch is legal in NAT setups, so this is a
 * warning only — but an unexpected mismatch may indicate a forged
 * OPEN_ACK. Skipped when either side is not an IPv4 literal. */
static void check_gw_server(const char *server, const char *gw)
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
    cfg.allow_remote = o->allow_remote;
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
#ifdef __APPLE__
    /* macOS has no /proc/self/exe; _NSGetExecutablePath gives the
     * absolute path of the running image (may contain symlinks, which
     * sudo resolves fine). */
    {
        uint32_t sz = (uint32_t)sizeof self - 1;
        if (_NSGetExecutablePath(self, &sz) == 0) {
            self[sz] = '\0';
            exe = self;
        }
    }
#else
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n > 0) {
        self[n] = '\0';
        exe = self;
    }
#endif
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
    uint16_t port = 0;
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

    oidc_eprintf("  Connecting to %s (%s:%u)...\n", name ? name : "", host,
                 (unsigned)port);

    oidc_check_server_ip(host);

    const char *user = srv_user ? srv_user : "";

    /* TUN device and route prep are session-independent: prepared once,
     * reused across reconnects (the server keeps the assigned IP on a
     * re-OPEN, so routing stays valid). */
    int tun_fd = -1;
    if (!o->socks) {
        if (!tun_name_valid(o->tun))
            oidc_die("invalid TUN device name '%s'", o->tun);
#ifndef _WIN32
        /* Linux: pre-delete a stale tun device by name. Windows: wintun's
         * open_tun (tun_win.c) deletes an existing adapter with the same
         * name as part of open-or-create, so nothing to do here. */
        char *const del[] = { "link", "del", (char *)o->tun, NULL };
        ip_run_quiet(del);
#endif
        tun_fd = open_tun(o->tun);
        if (tun_fd < 0)
            oidc_die("open tun (must be root or CAP_NET_ADMIN)");
        set_nonblock(tun_fd);
        if (debug_enabled())
            oidc_eprintf("  tun %s fd=%d\n", o->tun, tun_fd);
    }

    slist_t routes;
    slist_init(&routes);
    collect_routes(o, &routes);

    /* authenticate/run loop: a lost session (keepalive failure, no
     * downlink) re-authenticates and re-runs the pump instead of
     * silently dying. The plaintext password is re-decrypted per
     * iteration and scrubbed right after use. */
    for (;;) {
        char *password = decrypt_password(encrypted_pw ? encrypted_pw : "",
                                          OIDC_APP_SECRET, cf->domain,
                                          srv_user ? srv_user : "");
        if (!password)
            oidc_die("cannot decrypt password");
        uint8_t ct[16];
        if (get_ct(user, password, NULL, ct) != 0) {
            OPENSSL_cleanse(password, strlen(password));
            free(password);
            oidc_die("cannot derive password");
        }
        uint32_t nonce = rand_u32();
        buf_t open;
        buf_init(&open);
        if (build_open(&open, user, ct, IWAN_DEFAULT_MTU, o->encrypt,
                       nonce) != 0) {
            buf_free(&open);
            OPENSSL_cleanse(password, strlen(password));
            free(password);
            oidc_die("username too long (max 255 bytes)");
        }
        AuthResult res;
        int fd = do_auth(host, port, open.data, open.len, nonce, DO_AUTH_OIDC,
                         &res);
        buf_free(&open);
        if (fd < 0) {
            OPENSSL_cleanse(password, strlen(password));
            free(password);
            oidc_die("auth failed");
        }
        oidc_eprintf("  OK  tun=%s gw=%s dns=%s mtu=%u\n", res.tun, res.gw,
                     res.dns, (unsigned)res.mtu);
        check_gw_server(host, res.gw);   /* F8 */

        uint8_t sk[16];
        session_key(user, password, sk);
        OPENSSL_cleanse(password, strlen(password));
        free(password);

        int rc;
        if (o->socks) {
            rc = run_socks_mode(o, fd, sk, &res);
            port_close(fd);
        } else {
            rc = run_pump(tun_fd, o->tun, fd, sk, res.sid, res.tok,
                          o->encrypt, host, &routes, res.tun, res.mtu);
            port_close(fd);
        }
        OPENSSL_cleanse(sk, sizeof sk);   /* session key scrub */
        if (rc == 0)
            break;   /* user stopped it (pump returns 0 when the exit
                      * was not a detected session loss); run_pump
                      * resets g_stop on entry, so a lost session
                      * (rc == 1, g_stop set by the pump's detection)
                      * falls through to reconnect */
        if (rc < 0) {
#ifdef _WIN32
            oidc_pause_if_relaunched();
#endif
            exit(1);   /* config/startup failure: retrying cannot help */
        }
        oidc_eprintf("  tunnel session lost; reconnecting...\n");
        port_sleep_ms(1000);
        if (g_user_stop)
            break;   /* Ctrl-C during the reconnect wait */
    }

    if (tun_fd >= 0)
        tun_close(tun_fd);
    slist_free(&routes);
}