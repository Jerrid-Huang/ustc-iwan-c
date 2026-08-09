/* CLI parsing for iwan-client-oidc (help text lives here). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "addr.h"
#include "cli.h"
#include "common.h"
#include "oidc.h"
#include "util.h"

static Cli *g_usage;   /* used by ctl->usage_str; set before cli_parse */

const char *oidc_usage(const Cli *c)
{
    static char buf[512];
    if (c->usage_dup || c->nusage == 0) {
        snprintf(buf, sizeof buf, "Usage: iwan-client-oidc [OPTIONS]");
    } else {
        char *p = buf;
        size_t left = sizeof buf;
        int n = snprintf(p, left, "Usage: iwan-client-oidc");
        if (n > 0 && (size_t)n < left) {
            p += n;
            left -= (size_t)n;
        }
        for (int i = 0; i < c->nusage && left > 16; i++) {
            int k = snprintf(p, left, " %s", c->usage_args[i]);
            if (k <= 0 || (size_t)k >= left)
                break;   /* truncate rather than overflow */
            p += k;
            left -= (size_t)k;
        }
    }
    return buf;
}

static void print_help_short(void)
{
    printf(
        "Fetch, list, or connect using iWAN server config\n"
        "\n"
        "Usage: iwan-client-oidc [OPTIONS]\n"
        "\n"
        "Options:\n"
        "      --config-dir <CONFIG_DIR>      Output directory for the config file [default: ~/.config/iwan]\n"
        "      -f, --fetch                    Fetch config via OIDC and save it\n"
        "      -l, --list                     Print servers from the local config file\n"
        "      -c, --connect                  Choose a server from the local config file and connect\n"
        "      -a, --all                      Fetch config, print servers, choose one, and connect\n"
        "      --server <NAME|HOST:PORT>     Connect directly to a server by name or host:port\n"
        "      --tun <TUN>                    TUN device name [default: iwan0]\n"
        "      --proxy-cidr <PROXY_CIDR>      CIDR ranges to route through the tunnel. Can be repeated or comma-separated (also read from proxy.conf)\n"
        "      --ustc                         Route USTC campus networks through the tunnel (shortcut for the usual --proxy-cidr list)\n"
        "      --proxy-ip <PROXY_IP>          IPv4 addresses to route through the tunnel. Can be repeated or comma-separated\n"
        "      --proxy-domain <PROXY_DOMAIN>  Domains to resolve and route through the tunnel. Can be repeated or comma-separated\n"
        "      --encrypt <ENCRYPT>            Encryption method: 0=None, 1=XOR [default: 1]\n"
        "      --socks                        Use a rootless userspace SOCKS5 proxy instead of a TUN device\n"
        "      --socks-listen <SOCKS_LISTEN>  Local SOCKS5 listen address [default: 127.0.0.1:1080]\n"
        "      --socks-mtu <SOCKS_MTU>        Maximum userspace inner IP MTU [default: 1380]\n"
        "  -h, --help                         Print help (see more with '--help')\n"
        "  -V, --version                      Print version\n");
}

static void print_help_long(void)
{
    printf(
        "Fetch, list, or connect using iWAN server config.\n"
        "\n"
        "Config is stored at ~/.config/iwan/servers.json with encrypted passwords intact.\n"
        "\n"
        "Usage: iwan-client-oidc [OPTIONS]\n"
        "\n"
        "Options:\n"
        "      --config-dir <CONFIG_DIR>\n"
        "          Output directory for the config file\n"
        "          \n"
        "          [default: ~/.config/iwan]\n"
        "\n"
        "      -f, --fetch\n"
        "          Fetch config via OIDC and save it\n"
        "\n"
        "      -l, --list\n"
        "          Print servers from the local config file\n"
        "\n"
        "      -c, --connect\n"
        "          Choose a server from the local config file and connect\n"
        "\n"
        "      -a, --all\n"
        "          Fetch config, print servers, choose one, and connect\n"
        "\n"
        "      --server <NAME|HOST:PORT>\n"
        "          Connect directly to a server by name or host:port\n"
        "\n"
        "      --tun <TUN>\n"
        "          TUN device name\n"
        "          \n"
        "          [default: iwan0]\n"
        "\n"
        "      --proxy-cidr <PROXY_CIDR>\n"
        "          CIDR ranges to route through the tunnel. Can be repeated or comma-separated (also read from proxy.conf)\n"
        "\n"
        "      --ustc\n"
        "          Route USTC campus networks through the tunnel (shortcut for the usual --proxy-cidr list)\n"
        "\n"
        "      --proxy-ip <PROXY_IP>\n"
        "          IPv4 addresses to route through the tunnel. Can be repeated or comma-separated\n"
        "\n"
        "      --proxy-domain <PROXY_DOMAIN>\n"
        "          Domains to resolve and route through the tunnel. Can be repeated or comma-separated\n"
        "\n"
        "      --encrypt <ENCRYPT>\n"
        "          Encryption method: 0=None, 1=XOR\n"
        "          \n"
        "          [default: 1]\n"
        "\n"
        "      --socks\n"
        "          Use a rootless userspace SOCKS5 proxy instead of a TUN device\n"
        "\n"
        "      --socks-listen <SOCKS_LISTEN>\n"
        "          Local SOCKS5 listen address\n"
        "          \n"
        "          [default: 127.0.0.1:1080]\n"
        "\n"
        "      --socks-mtu <SOCKS_MTU>\n"
        "          Maximum userspace inner IP MTU\n"
        "          \n"
        "          [default: 1380]\n"
        "\n"
        "  -h, --help\n"
        "          Print help (see a summary with '-h')\n"
        "\n"
        "  -V, --version\n"
        "          Print version\n");
}

static bool valid_listen(const char *val, char *err, size_t errsz)
{
    struct sockaddr_in tmp;
    if (parse_host_port(val, &tmp) == 0)
        return true;
    snprintf(err, errsz, "invalid socket address syntax");
    return false;
}

static void on_help(bool long_help)
{
    if (long_help)
        print_help_long();
    else
        print_help_short();
    exit(0);
}

static void on_version(void)
{
    printf("iwan-client-oidc %s\n", OIDC_VERSION);
    exit(0);
}

static const char *on_usage(void)
{
    return oidc_usage(g_usage);
}

static const char *const short_aliases[][2] = {
    { "f", "--fetch" },
    { "l", "--list" },
    { "c", "--connect" },
    { "a", "--all" },
    { NULL, NULL },
};

void oidc_parse_cli(int argc, char **argv, Opts *o, Cli *usage)
{
    /* called first thing from main: cover the whole process before any
     * network I/O (https.c depends on EPIPE, not SIGPIPE, killing us) */
    util_ignore_sigpipe();

    cli_init(usage);
    g_usage = usage;

    cli_opt opts[] = {
        { "config-dir",   CLI_OPT_STR,  &o->config_dir,    "<CONFIG_DIR>",    NULL },
        { "fetch",        CLI_OPT_BOOL, &o->fetch,         NULL,             NULL },
        { "list",         CLI_OPT_BOOL, &o->list,          NULL,             NULL },
        { "connect",      CLI_OPT_BOOL, &o->connect,       NULL,             NULL },
        { "all",          CLI_OPT_BOOL, &o->all,           NULL,             NULL },
        { "server",       CLI_OPT_STR,  &o->server,        "<NAME|HOST:PORT>", NULL },
        { "tun",          CLI_OPT_STR,  &o->tun,           "<TUN>",          NULL },
        { "proxy-cidr",   CLI_OPT_CSV,  &o->proxy_cidr,    "<PROXY_CIDR>",   NULL },
        { "ustc",         CLI_OPT_BOOL, &o->ustc,          NULL,             NULL },
        { "proxy-ip",     CLI_OPT_CSV,  &o->proxy_ip,      "<PROXY_IP>",     NULL },
        { "proxy-domain", CLI_OPT_CSV,  &o->proxy_domain,  "<PROXY_DOMAIN>", NULL },
        { "encrypt",      CLI_OPT_U8,   &o->encrypt,       "<ENCRYPT>",      NULL },
        { "socks",        CLI_OPT_BOOL, &o->socks,         NULL,             NULL },
        { "socks-listen", CLI_OPT_STR,  &o->socks_listen,  "<SOCKS_LISTEN>", valid_listen },
        { "socks-mtu",    CLI_OPT_U16,  &o->socks_mtu,     "<SOCKS_MTU>",    NULL },
    };

    cli_ctl ctl = {
        .on_help = on_help,
        .on_version = on_version,
        .version_is_unknown = false,
        .usage_str = on_usage,
        .short_aliases = short_aliases,
        .track_usage = true,
    };
    cli_parse(usage, argc, argv, 1, opts, sizeof opts / sizeof opts[0], &ctl);
}