/* iwan-client-oidc: fetch/list/connect OIDC client entry point. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "common.h"
#include "crypto.h"
#include "oidc.h"
#include "util.h"

/* argument-validation failure: report the error, show the usage summary,
 * and point at --help, matching the CLI framework's own errors */
static void usage_error(const Cli *usage, const char *msg)
{
    fprintf(stderr, "error: %s\n\n%s\n\nFor more information, try '--help'.\n",
            msg, oidc_usage(usage));
    exit(2);
}

/* R37-FIX-A2 / A2b: the root-write guard implementation lives in
 * oidc_config.c next to normalize_path(), and oidc_config_canon_path() is
 * the same canonicalization the save backstop uses — so the path opened by
 * --list/--connect is the one --fetch wrote. This early gate and the
 * oidc_save_config() backstop must share both; the prototypes live in
 * oidc.h (R3-L18). */

int main(int argc, char **argv)
{
#ifdef _WIN32
    port_install_crash_handler();
#endif
    util_ignore_sigpipe();
    /* WSAStartup + console UTF-8 on Windows; no-op on Linux. Without
     * this the OIDC client relied on port_socket's WSANOTINITIALISED
     * recovery for every first socket (wine: wsa 10093), and Chinese
     * output was mangled (console codepage never set to UTF-8). */
    port_socket_init();
    Opts o;
    memset(&o, 0, sizeof o);
    o.config_dir = "~/.config/iwan";
    o.tun = "iwan0";
    o.socks_listen = "127.0.0.1:1080";
    o.socks_mtu = 1380;
    slist_init(&o.proxy_cidr);
    slist_init(&o.proxy_ip);
    slist_init(&o.proxy_domain);
    slist_init(&o.proxy_cidr6);

    Cli usage;
    oidc_parse_cli(argc, argv, &o, &usage);

    if (!(o.fetch || o.list || o.connect || o.all))
        usage_error(&usage,
                    "no action chosen: pass --fetch, --list, --connect, or --all");
    bool do_fetch = o.fetch || o.all;
    bool do_list = o.list || o.all;
    bool do_connect = o.connect || o.all;
    if (o.socks && !do_connect)
        usage_error(&usage, "--socks requires --connect or --all");
    if (o.socks_token && o.socks_no_token)
        usage_error(&usage,
                    "--socks-token and --socks-no-token are mutually "
                    "exclusive");
    /* H-1 (R14): judge the token's CONTENT, not just the pointer — an
     * empty string is "no token" and must never open a remote SOCKS
     * proxy without --socks-no-token. Defence-in-depth behind
     * validate_token_len (first gate; parallel agent A): even a direct
     * config path that lands an empty token here hits this second gate. */
    if (o.socks && o.allow_remote &&
        (!o.socks_token || !*o.socks_token) && !o.socks_no_token)
        usage_error(&usage,
                    "--allow-remote requires an explicit SOCKS proxy "
                    "password: pass --socks-token <PASS>, or "
                    "--socks-no-token to confirm an open (passwordless) "
                    "proxy");
    /* oidc_elevate_root checks the privilege itself (Windows: admin ->
     * no-op; POSIX: euid 0 -> no-op) */
    if (do_connect && !o.socks)
        oidc_elevate_root(argc, argv);

    /* M-2/M-1 (R14): --config-dir is validated here at CLI level, before
     * resolve_config_dir, so NO entry path (direct call included) can
     * reach the config write with a root-only directory.
     *   - M-2: empty/whitespace degenerates to "/servers.json" (a root
     *     write). oidc_config.c already refuses that when actually saving
     *     (R13), but the rejection belongs at CLI parse time too.
     *   - M-1: a value made only of separators ("/", "//", "///")
     *     collapses to the filesystem root as well, yet keeps a
     *     strrchr()-visible leading part ("//"), so it slips past
     *     oidc_config.c's single-slash guard. Reject it here.
     * For non-rooted values, resolve_config_dir passes them through, so
     * checking the raw value covers both cases. Permissible absolute
     * paths like /home/user (a directory name follows the leading
     * separators) are unaffected, and the "~/" expansion stays untouched.
     *   - R37-FIX-A2: "/..", "/foo/..", "/tmp/../..", "C:\" and friends
     *     are not "all separators" but still RESOLVE to the root once ".."
     *     is applied, so the old text check passed them straight to
     *     oidc_save_config() (as root: /servers.json + chown of the
     *     resolved dir). oidc_config_dir_resolves_to_root() is the same
     *     normalization the save guard uses. */
    {
        const char *cd = o.config_dir;
        size_t i = 0;
        while (cd[i] == ' ' || cd[i] == '\t' || cd[i] == '\r' || cd[i] == '\n')
            i++;
        bool only_slashes = cd[0] == '/';
        size_t j;
        for (j = 1; only_slashes && cd[j]; j++)
            only_slashes = (cd[j] == '/');
        if (cd[i] == '\0')
            usage_error(&usage, "config-dir must not be empty");
        if (only_slashes || oidc_config_dir_resolves_to_root(cd))
            usage_error(&usage,
                        "config-dir must name a directory, not the "
                        "filesystem root");
    }

    char *dir = resolve_config_dir(o.config_dir);
    if (!dir)
        oidc_die("cannot determine home directory; set HOME or run via sudo");
    /* R37-FIX-A2: "~/" is expanded only here, so "~/../.." is invisible to
     * the raw-value gate above; now that the value is absolute, re-run the
     * very same guard before any path is joined, opened or saved */
    if (oidc_config_dir_resolves_to_root(dir)) {
        free(dir);
        usage_error(&usage,
                    "config-dir must name a directory, not the "
                    "filesystem root");
    }
    size_t plen = strlen(dir) + strlen("/servers.json") + 1;
    char *path = malloc(plen);
    if (!path)
        oom_abort();
    snprintf(path, plen, "%s/servers.json", dir);
    free(dir);
    /* R37-FIX-A2b (R2-B2-1): canonicalize ONCE, here at the CLI boundary,
     * so save / load / the proxy.conf sibling / every diagnostic all use
     * the SAME string. oidc_save_config() normalizes internally too, but
     * doing it only there left oidc_load_config() fopen()ing the raw
     * spelling: with a ".." (or, before this revision, a '\') component
     * the two resolved to different files, so --fetch wrote a config that
     * --list/--connect could not read. The result is already normalized,
     * so the save backstop is a no-op here. */
    {
        char *cpath = oidc_config_canon_path(path);
        free(path);
        path = cpath;
    }

    /* R39: install the never-NULL libcrypto allocator (and force init) only
     * now, immediately before the first action that can reach libcrypto:
     * oidc_fetch_config() hashes the PKCE verifier / OPENSSL_cleanse()s
     * secrets, and oidc_load_config() verifies JWTs through EVP_DigestVerify.
     * This used to run at the top of main, so pure-CLI paths (--help,
     * argument/usage errors) initialised libcrypto and could hang forever in
     * futex() on one failed internal allocation (9fef151). Everything above
     * this line is CLI parsing + pure string/path validation: oidc_cli.c,
     * oidc_util.c, common/config.c and the pre-fetch part of oidc_config.c
     * contain no libcrypto call (the only OPENSSL_* symbol in oidc_config.c
     * is inside oidc_fetch_config, below this point). */
    if (crypto_init() != 0)
        oom_abort();

    Config cf;
    memset(&cf, 0, sizeof cf);
    if (do_fetch) {
        oidc_fetch_config(&cf);
        oidc_save_config(path, &cf);
    } else {
        oidc_load_config(path, &cf);
    }

    if (do_list || (do_connect && !o.server))
        oidc_print_servers(cf.servers);
    if (do_connect && !o.socks) {
        /* TUN routes from <config-dir>/proxy.conf, merged with --proxy-cidr */
        char *slash = strrchr(path, '/');
        size_t dlen = slash ? (size_t)(slash - path) : strlen(path);
        char *ppath = malloc(dlen + sizeof "/proxy.conf");
        if (!ppath)
            oom_abort();
        memcpy(ppath, path, dlen);
        memcpy(ppath + dlen, "/proxy.conf", sizeof "/proxy.conf");
        if (load_cidr_file(ppath, &o.proxy_cidr) != 0) {
            char msg[160];
            snprintf(msg, sizeof msg, "read %s", ppath);
            oidc_die_with_cause(msg, strerror(errno));
        }
        if (o.ustc) {
            static const char *const ustc_nets[] = {
                "114.214.160.0/19",   "114.214.192.0/18",
                "202.38.64.0/19",     "210.45.64.0/20",
                "210.45.112.0/20",    "211.86.144.0/20",
                "222.195.64.0/19",    "210.72.22.0/24",
                "202.141.160.0/19",   "218.22.21.0/27",
                "218.104.71.160/28",
            };
            for (size_t i = 0; i < sizeof ustc_nets / sizeof ustc_nets[0]; i++)
                slist_push(&o.proxy_cidr, ustc_nets[i]);
        }
        free(ppath);
    }
    if (do_connect)
        oidc_connect_server(&o, &cf);

    oidc_config_free(&cf);
    free(path);
    slist_free(&o.proxy_cidr);
    slist_free(&o.proxy_ip);
    slist_free(&o.proxy_domain);
    slist_free(&o.proxy_cidr6);
    return 0;
}