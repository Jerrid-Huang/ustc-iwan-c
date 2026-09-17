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
#include "cli_common.h"
#include "common.h"
#include "crypto.h"
#include "gcm.h"
#include "oidc.h"
#include "oidc_pwsecret.h"
#include "protocol.h"
#include "proxy.h"
#include "relay_proxy.h"
#include "socks.h"
#include "socks_internal.h"   /* R36-L01: on_sig for the loop-level stop
                               * handler (see the reconnect loop below) */
#include "tun.h"
#include "util.h"

/* in-place tunnel re-auth (socks.h): re-run the OIDC auth and refresh
 * the session fields of cfg. The SOCKS listener, flows and lwIP inner
 * TCP state are kept by run_socks; only the carrier switches. */
struct oidc_reauth_ctx {
    const Opts *o;
    const char *host;
    uint16_t port;
    const char *user;
    const char *srv_user;
    const char *encrypted_pw;
    const Config *cf;
};

/* R49-L4: does `blob` have the SHAPE of a legacy GCM ciphertext — i.e.
 * is it base64url-decodable to at least the fixed GCM overhead (12-byte
 * nonce + 16-byte tag)? This mirrors exactly the structural gate inside
 * decrypt_password (gcm.c:94-96), which refuses anything decoding to
 * fewer than GCM_NONCE_LEN + GCM_TAG_LEN bytes before it even attempts
 * GCM. A blob that fails this shape test cannot be legacy ciphertext
 * UNLESS it was corrupted in a way that destroyed its decodability;
 * such a corrupted legacy blob is indistinguishable by shape from a
 * plaintext password and would fall back as plaintext with no
 * corruption alert — the irreducible residual of the markerless format
 * (frozen: the format carries no marker that could separate "corrupted
 * ciphertext" from a "legit short plaintext", so this ambiguity is
 * information-theoretically unavoidable and is deliberately not chased).
 * The other irreducible residual: a plaintext password that
 * independently happens to decode to >= 28 bytes of base64url is
 * indistinguishable from ciphertext by shape; it also logged under the
 * old unconditional rule, so nothing regresses.
 * FROZEN BOUNDARY: decrypt_password, oidc_wrap_password and every write
 * format are untouched; this only classifies the DIAGNOSTIC TRIGGER in
 * stored_password(). */
static bool blob_looks_encrypted(const char *blob)
{
    size_t len = 0;
    uint8_t *raw = b64url_decode(blob, &len);
    if (!raw)
        return false;
    free(raw);
    return len >= GCM_NONCE_LEN + GCM_TAG_LEN;
}

/* Recover the plaintext server password from the stored value:
 * unwrap the platform protection (DPAPI / Keychain), then GCM-decrypt
 * the LEGACY ciphertext format (pre-plaintext servers.json files).
 * The current --fetch format stores the plaintext password itself, so
 * the GCM check fails and the unwrapped blob IS the password — that
 * fallback is also what makes this tolerant of a server that someday
 * stops encrypting. Returns a malloc'd password or NULL (unwrap
 * failed, e.g. locked Keychain). */
static char *stored_password(const char *stored, const char *domain,
                             const char *user)
{
    char *blob = oidc_unwrap_password(stored ? stored : "", domain,
                                      user ? user : "");
    if (!blob)
        return NULL;
    /* same NULL guard as the unwrap call above: a servers.json entry
     * without "username" leaves user NULL, and decrypt_password
     * strlen()s it (SUMMARY-2 M2) */
    char *pw = decrypt_password(blob, OIDC_APP_SECRET, domain,
                                user ? user : "");
    if (pw) {
        OPENSSL_cleanse(blob, strlen(blob));
        free(blob);
        return pw;
    }
    /* R13 B-3 (M-3 hardening, minimal): decrypt_password failed. The
     * blob is the legacy PLAINTEXT password only if the server actually
     * stored it that way — but the identical failure mode also covers a
     * corrupt/tampered blob or a changed app secret, which would then be
     * fed to the auth stack as if it were the real password. We keep the
     * tolerant legacy fallback (no contract change), but it must no
     * longer be silent. A fuller fix (blob format marker etc.) is a
     * design change, deliberately out of scope here.
     * R49-L4: the alert must only fire when the blob actually HAS the
     * legacy ciphertext shape — the modern --fetch flow stores plaintext,
     * and decrypt_password can never GCM-decode a plaintext blob, so its
     * failure there is the EXPECTED path on every connection/reconnect
     * (dynamically proven in R49: 34-byte plaintext blob -> decrypt NULL
     * every time). Unconditional log_err diluted the real corruption
     * signal into wallpaper. Now only a ciphertext-shaped blob that fails
     * to decrypt raises the corruption/tampering/secret-change alert;
     * a non-ciphertext-shaped blob falls back as plaintext with a debug
     * note instead. */
    if (blob_looks_encrypted(blob))
        log_err("stored password decrypt failed; falling back to treating "
                "the stored blob as a legacy plaintext password — this may "
                "indicate corruption/tampering or a secret change");
    else
        log_debug("stored password fell back as a plaintext password: it "
                  "is not legacy-ciphertext shaped (undecodable as "
                  "base64url or shorter than the GCM nonce+tag overhead). "
                  "Note the ambiguity: if this value was SUPPOSED to be "
                  "legacy ciphertext, it has been damaged past "
                  "recognizability and will be used as plaintext — the "
                  "markerless format (frozen) cannot tell that apart from "
                  "a genuine short plaintext");
    return blob;   /* plaintext format: the blob is the password */
}

static int oidc_socks_reauth_cb(void *ud, SocksConfig *cfg, int *out_fd)
{
    const struct oidc_reauth_ctx *rc = ud;
    char *password = stored_password(rc->encrypted_pw, rc->cf->domain,
                                     rc->srv_user);
    if (!password) {
        log_err("SOCKS re-auth: cannot recover password (Keychain)");
        return -1;
    }
    AuthResult res;
    /* R25-f3 F1: the OPEN MTU must match the userspace stack's negotiated
     * size (--socks-mtu, default 1380) — advertising IWAN_DEFAULT_MTU(1400)
     * made the server size 1400 while socks.c:565 drops 1381-1400B downlink. */
    int fd = authenticate_ex(rc->user, password, NULL, rc->o->socks_mtu,
                             rc->host, rc->port, DO_AUTH_OIDC, &res);
    if (fd < 0) {
        OPENSSL_cleanse(password, strlen(password));
        free(password);
        if (fd == -1)
            log_err("SOCKS re-auth: cannot derive password");
        else if (fd == -2)
            log_err("SOCKS re-auth: username too long");
        else
            log_err("SOCKS re-auth: auth failed");
        return -1;
    }
    uint8_t sk[16];
    session_key(rc->user, password, sk);
    OPENSSL_cleanse(password, strlen(password));
    free(password);
    uint32_t inner_ip_v, gateway_v;
    int sar = auth_result_addrs(&res, &inner_ip_v, &gateway_v);
    if (sar == 0)
        log_err("SOCKS re-auth: server returned invalid tun");
    else if (sar < 0)
        log_err("SOCKS re-auth: server returned invalid gw");
    if (sar != 1) {
        OPENSSL_cleanse(sk, sizeof sk);
        port_close(fd);
        return -1;
    }
    socks_cfg_from_auth(cfg, &res, inner_ip_v, gateway_v, sk,
                        res.mtu < rc->o->socks_mtu ? res.mtu : rc->o->socks_mtu);
    OPENSSL_cleanse(sk, sizeof sk);
    *out_fd = fd;
    return 0;
}

static int run_socks_mode(const Opts *o, int fd, const uint8_t sk[16],
                          const AuthResult *res,
                          const struct oidc_reauth_ctx *rc)
{
    uint32_t inner_ip, gateway;
    int sar = auth_result_addrs(res, &inner_ip, &gateway);
    if (sar == 0)
        log_err("server returned invalid tunnel IPv4 address");
    else if (sar < 0)
        log_err("server returned invalid gateway IPv4 address");
    if (sar != 1) {
        /* R24-f2 F2: run_pump/run_socks do not own fd on this failure path
         * (the caller expects to hand it to the runner); the sole caller
         * exits on rc<0 today, but close here to match the A-1 contract. */
        port_close(fd);
        return -1;
    }

    struct sockaddr_in listen;
    if (parse_host_port(o->socks_listen, &listen) != 0)
        oidc_die("invalid listen address");

    SocksConfig cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.listen_addr = listen;
    cfg.listen_str = o->socks_listen;
    socks_cfg_from_auth(&cfg, res, inner_ip, gateway, sk,
                        res->mtu < o->socks_mtu ? res->mtu : o->socks_mtu);
    cfg.auth_token = o->socks_token;
    cfg.open_proxy = o->socks_no_token;
    cfg.allow_remote = o->allow_remote;
    cfg.ipv6 = o->socks_ipv6;
    cfg.reauth = oidc_socks_reauth_cb;   /* in-place tunnel re-auth */
    cfg.reauth_ud = (void *)rc;

    /* propagate run_socks's return unchanged — three states
     * (0 = clean user stop, 1 = session lost / reconnect, -1 = startup
     * failure): the -1 from the invalid-address check above is already a
     * pre-startup failure, and run_socks now reports a failed
     * socket/bind/listen as -1 (R13-M-1) instead of masking it as a
     * clean stop. The hardcoded 0 here used to make every lost session
     * look like a clean user stop — the process exited silently instead
     * of reconnecting. Every early return in this function is -1
     * (failure) or aborts (oidc_die); nothing here can mis-report an
     * error as "stopped". */
    return run_socks(fd, &cfg);
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
    /* already root: nothing to re-exec (mirrors the _WIN32 guard above;
     * the oidc main calls this unconditionally for --connect) */
    if (geteuid() == 0)
        return;
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
        /* R37-WG-E1 (L28): the name/host of an entry are remote controlled
         * (controller /m/config; a hand-edited servers.json decodes \u001b
         * back to a raw ESC). Every terminal copy below is neutralized;
         * the raw pointers keep feeding matching and the auth stack. */
        oidc_die("invalid port %g for server \"%s\" "
                 "(must be an integer in 1..65535)",
                 pv, oidc_printable_dup(name ? name : host));
    if (pr == 0)
        port = OIDC_DEFAULT_PORT;
    const char *srv_user = json_get_str(srv, "username");
    const char *encrypted_pw = json_get_str(srv, "passWord");

    {
        /* L28: printed on every connection attempt — the most likely
         * sink for a hostile server name to reach the terminal */
        char *name_s = oidc_printable_dup(name ? name : "");
        char *host_s = oidc_printable_dup(host);
        oidc_eprintf("  Connecting to %s (%s:%u)...\n", name_s, host_s,
                     (unsigned)port);
        free(name_s);
        free(host_s);
    }

    {
        char eb[64];
        if (!check_server_ip(host, eb, sizeof eb))
            oidc_die_with_cause("invalid address", eb);
    }

    /* R25-f3 F3: an absent username would silently fail with "invalid
     * credentials" (empty T_USERNAME never matches a server user); surface
     * it as a config error instead. */
    if (!srv_user || !srv_user[0])
        oidc_die("server \"%s\" has no username in servers.json; add "
                 "\"username\" (iwan-client defaults to _rev_m_1)",
                 oidc_printable_dup(name ? name : host));
    const char *user = srv_user;

    /* TUN device and route prep are session-independent: prepared once,
     * reused across reconnects (the server keeps the assigned IP on a
     * re-OPEN, so routing stays valid). */
    int tun_fd = -1;
    struct RelayProxy *rp = NULL;
    if (!o->socks) {
        /* Validate the name shape up front. We deliberately do NOT
         * pre-delete: the TUN devices we create are non-persistent
         * (open_tun never sets TUNSETPERSIST), so the kernel removes
         * them when the fd closes — at shutdown and on any crash. If
         * `o->tun` is occupied by an interface we do not own, TUNSETIFF
         * fails below and we abort instead of deleting it. */
        if (!tun_name_valid(o->tun))
            oidc_die("invalid TUN device name '%s'", o->tun);
        tun_fd = open_tun(o->tun);
        if (tun_fd < 0)
            oidc_die("open tun (must be root)");
        set_nonblock(tun_fd);
        if (debug_enabled())
            oidc_eprintf("  tun %s fd=%d\n", o->tun, tun_fd);
        /* optional SOCKS5+HTTP proxy sharing the TUN routes.
         * R38-L02: a failed listener start (most commonly 127.0.0.1:1080
         * already in use) must NOT kill the whole tunnel — the side-car
         * is a convenience on top of the TUN, so degrade to "no local
         * proxy" and keep going. rp is left NULL (relay_proxy_start sets
         * *out = NULL before returning -1 on every failure arm) and
         * relay_proxy_stop(NULL) at teardown is a no-op. The OIDC SOCKS
         * MODE (--socks) never reaches this branch — it is guarded by
         * !o->socks above — and keeps the proxy as the tunnel itself. */
        if (o->socks_listen &&
            relay_proxy_start(o->socks_listen, o->socks_token,
                              o->socks_no_token, o->allow_remote,
                              &rp) != 0)
            log_err("cannot start the SOCKS5+HTTP side-car proxy on %s; "
                    "continuing without it (tunnel unaffected)",
                    o->socks_listen);
    }

    slist_t routes;
    slist_init(&routes);
    collect_routes(&routes, &o->proxy_cidr, &o->proxy_ip,
                   &o->proxy_domain);
    slist_t routes6;
    slist_init(&routes6);
    collect_routes6(&routes6, &o->proxy_cidr6);

    /* authenticate/run loop: a lost session (keepalive failure, no
     * downlink) re-authenticates and re-runs the pump instead of
     * silently dying. The plaintext password is re-decrypted per
     * iteration and scrubbed right after use. */
    struct oidc_reauth_ctx reauth_ctx = {
        .o = o, .host = host, .port = port, .user = user,
        .srv_user = srv_user, .encrypted_pw = encrypted_pw, .cf = cf,
    };
    bool reconnecting = false;
#ifndef _WIN32
    /* R36-L01: hold the stop handler across the WHOLE reconnect loop in
     * SOCKS mode. run_socks installs on_sig when it enters and restores
     * the PREVIOUS disposition when it leaves; without a loop-level
     * install that previous disposition in the reconnect wait window
     * after run_socks_mode returned was the DEFAULT, so a Ctrl-C there
     * took the default action (abrupt rc=130 in the foreground, or
     * swallowed by an inherited SIG_IGN in the background) and the
     * g_user_stop check below could never fire. Holding on_sig for the
     * loop makes run_socks's save/restore preserve it, the wait-window
     * Ctrl-C lands in g_user_stop, and the loop breaks cleanly. The TUN
     * path (run_pump) already keeps its own handler for the process
     * lifetime (proxy.c install_signals) and is unchanged; we only cover
     * the shared wait window once. Restored after the loop so nothing
     * persists. Windows: run_socks uses the process-lifetime
     * port_set_stop_handler there, so the window was never unprotected —
     * nothing to add. */
    struct sigaction sa_stop, old_stop_int, old_stop_term;
    memset(&sa_stop, 0, sizeof sa_stop);
    sa_stop.sa_handler = on_sig;
    sigaction(SIGINT, &sa_stop, &old_stop_int);
    sigaction(SIGTERM, &sa_stop, &old_stop_term);
#endif
    for (;;) {
        char *password = stored_password(encrypted_pw, cf->domain,
                                         srv_user);
        if (!password) {
#if defined(__APPLE__)
            oidc_die("cannot read password from the login Keychain "
                     "(locked keychain or SSH session? run "
                     "`security unlock-keychain`, then retry; or "
                     "re-run --fetch)");
#else
            oidc_die("cannot decrypt password");
#endif
        }
        AuthResult res;
        /* R25-f3 F1: advertise the socks-mode MTU, not the 1400 default */
        int fd = authenticate_ex(user, password, NULL, o->socks_mtu,
                                 host, port, DO_AUTH_OIDC, &res);
        if (fd < 0) {
            OPENSSL_cleanse(password, strlen(password));
            free(password);
            if (fd == -1)
                oidc_die("cannot derive password");
            else if (fd == -2)
                oidc_die("username too long (max 255 bytes)");
            if (!reconnecting)
                oidc_die("auth failed");
            /* a reconnect hit the same loss window that killed the
             * session: the OPEN is just as likely to be eaten, so
             * retry with a backoff instead of dying */
            oidc_eprintf("  auth failed during reconnect; retrying in "
                         "3s...\n");
            port_sleep_ms(3000);
            if (g_user_stop)
                break;
            continue;
        }
        /* R37-WG-E1 (L28) ruling: res.tun/gw/dns are the only
         * server-supplied strings on this line, and they cannot carry a
         * control byte: auth.c fills them exclusively through
         * ip_to_string() ("%d.%d.%d.%d", auth.c:93/101/109) or leaves
         * them empty, and the ACK fields are frozen wire values that must
         * stay raw for check_gw_server()/run_pump() below. Deliberately
         * not filtered. */
        oidc_eprintf("  OK  tun=%s gw=%s dns=%s mtu=%u\n", res.tun, res.gw,
                     res.dns, (unsigned)res.mtu);
        check_gw_server(host, res.gw);   /* F8 */

        uint8_t sk[16];
        session_key(user, password, sk);
        OPENSSL_cleanse(password, strlen(password));
        free(password);

        int rc;
        if (o->socks) {
            /* H-1: OIDC mode always sets cfg.reauth (oidc_socks_reauth_cb),
             * so run_socks may swap in a fresh session fd mid-run via
             * socks_reauth_swap. run_socks/run_socks_mode now OWN and close
             * the current sockfd in their teardown (including any
             * swapped-in replacement); the caller MUST NOT port_close(fd)
             * afterwards — closing the stale pre-swap fd would be a double
             * close (and could clobber an unrelated descriptor reusing
             * that number) and would leak every replaced session socket.
             * run_socks_mode itself only forwards fd to run_socks and does
             * not close it, so ownership passes straight through. */
            rc = run_socks_mode(o, fd, sk, &res, &reauth_ctx);
        } else {
#ifdef _WIN32
            /* M1: Windows sockets default to BLOCKING; the pump paths
             * expect a nonblocking datagram socket. A blocking socket
             * makes pump_win_single_pkt's WSASend block, bypassing the
             * 5ms EAGAIN budget and ending in ETIMEDOUT after 3s, which
             * fatally kills the session. On Linux the pump sets this
             * itself (same alignment as iwan_client.c cmd_proxy). */
            if (port_set_nonblock(fd, true) != 0)
                log_err("Error: set nonblock: %s", strerror(errno));
#endif
            /* run_pump does NOT own fd: the caller closes it here */
            rc = run_pump(tun_fd, o->tun, fd, sk, res.sid, res.tok,
                          res.enc, host, &routes, &routes6,
                          res.tun, res.mtu);
            port_close(fd);
        }
        OPENSSL_cleanse(sk, sizeof sk);   /* session key scrub */
        /* R13-M-1 three-state return from run_socks_mode / run_pump:
         *   rc == 0 -> clean user stop (break out of the reconnect loop
         *              and exit: the process exit code stays a normal 0)
         *   rc == 1 -> session lost (run_pump resets g_stop on entry;
         *              run_socks sets g_stop on its lost-session
         *              detection) -> falls through to the reconnect path
         *   rc <  0 -> startup/config failure (run_socks now reports a
         *              failed socket/bind/listen as -1, NOT as a clean 0
         *              stop; run_socks_mode's invalid-address path is
         *              also -1) -> must exit non-zero here: retrying
         *              cannot help, and treating it as a user stop would
         *              silently mask a broken client with exit code 0 */
        if (rc < 0) {
            log_err("connection startup failed (rc=%d): not a clean "
                    "stop — exiting non-zero", rc);
#ifdef _WIN32
            oidc_pause_if_relaunched();
#endif
            exit(1);   /* config/startup failure: retrying cannot help */
        }
        if (rc == 0)
            break;   /* user stopped it */
        oidc_eprintf("  tunnel session lost; reconnecting...\n");
        reconnecting = true;
        port_sleep_ms(1000);
        if (g_user_stop)
            break;   /* Ctrl-C during the reconnect wait */
    }

#ifndef _WIN32
    /* R36-L01: loop-level handler no longer needed; restore the
     * dispositions that were active when the loop was entered (the TUN
     * path's own handler, if any, is left exactly as run_pump set it). */
    sigaction(SIGINT, &old_stop_int, NULL);
    sigaction(SIGTERM, &old_stop_term, NULL);
#endif
    relay_proxy_stop(rp);
    if (tun_fd >= 0)
        tun_close(tun_fd);
    slist_free(&routes);
    slist_free(&routes6);
}