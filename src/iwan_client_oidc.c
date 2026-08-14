/* iwan-client-oidc: fetch/list/connect OIDC client entry point. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "common.h"
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
    o.encrypt = 1;
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
    if (o.socks && o.allow_remote && !o.socks_token && !o.socks_no_token)
        usage_error(&usage,
                    "--allow-remote requires an explicit SOCKS proxy "
                    "password: pass --socks-token <PASS>, or "
                    "--socks-no-token to confirm an open (passwordless) "
                    "proxy");
    if (do_connect && !o.socks && !port_is_admin())
        oidc_elevate_root(argc, argv);

    char *dir = resolve_config_dir(o.config_dir);
    if (!dir)
        oidc_die("cannot determine home directory; set HOME or run via sudo");
    size_t plen = strlen(dir) + strlen("/servers.json") + 1;
    char *path = malloc(plen);
    if (!path)
        oom_abort();
    snprintf(path, plen, "%s/servers.json", dir);
    free(dir);

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