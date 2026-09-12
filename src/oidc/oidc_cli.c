/* CLI parsing for iwan-client-oidc (help text lives here). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "addr.h"
#include "cli.h"
#include "cli_common.h"
#include "common.h"   /* port.h: sockaddr_in on both platforms */
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

/* ---- shared help footer: repeat-option semantics + environment matrix ----
 *
 * R37 R5 (L24): "repeating an option ..." is deliberately the same opening
 * sentence as in iwan-server and iwan-client, so the documented semantics of
 * the three binaries can be compared side by side (both clap-style parsers
 * exit 2 with 'cannot be used multiple times'; iwan-server's bare
 * getopt_long takes the last value).
 * R37 R5 (L20-1): the environment matrix lists ONLY the variables this
 * binary really reads; [scope] says where each one applies. The same block
 * is printed by -h and --help, and it mirrors README.md's matrix. */
static void print_help_footer(void)
{
    printf(
        "\n"
        "Repeating an option is an error: 'cannot be used multiple times' (exit 2).\n"
        "The list options --proxy-cidr, --proxy-ip, --proxy-domain and --proxy-cidr6\n"
        "are the exception: they accumulate across repetitions.\n"
        "\n"
        "Environment (settings this binary reads; [scope] = where they apply):\n"
        "      IWAN_DEBUG=1                      debug logging (default: off; ignored by\n"
        "                                        IWAN_DEBUG_STRIP builds) [all]\n"
        "      IWAN_RX_STALE_MS=<ms>             re-authenticate after this long without\n"
        "                                        downlink, 0 disables, 30000..86400000\n"
        "                                        (default: 120000) [TUN, socks]\n"
        "      IWAN_SEND_PACING_PPS=<n>          aggregate send pacing in packets/s,\n"
        "                                        0 disables (default: 0) [TUN, socks]\n"
        "      IWAN_RXDBG=1                      log every VPN datagram received\n"
        "                                        (default: off) [socks]\n"
        "      IWAN_FLOWDBG=1                    log SOCKS flow state changes and close\n"
        "                                        reasons (default: off) [socks]\n"
        "      IWAN_NS_CONNECT_TIMEOUT_MS=<ms>   userspace TCP connect timeout,\n"
        "                                        1000..300000 (default: 30000) [socks]\n"
        "      IWAN_SOCKS_ALLOW_LOOPBACK=1       let non-loopback peers reach loopback/\n"
        "                                        link-local targets; only the exact value 1\n"
        "                                        enables it (default: off) [socks]\n"
        "      IWAN_AUTH_FAIL_MAX=<n>            failed authentications per source before\n"
        "                                        lockout, 1..100 (default: 5) [socks]\n"
        "      IWAN_AUTH_FAIL_WINDOW_MS=<ms>     lockout window, 100..86400000\n"
        "                                        (default: 60000) [socks]\n"
        "      IWAN_PUMP_PROF=1                  per-stage TUN pump profiler; any value\n"
        "                                        (even empty) enables it, never parsed by\n"
        "                                        IWAN_DEBUG_STRIP builds (default: off) [TUN]\n"
        "      IWAN_PUMP_QUEUES=<n>              TUN reader-pool queues, 1..8 (default:\n"
        "                                        number of CPUs, capped at 8; wintun is\n"
        "                                        single-queue on Windows) [TUN]\n"
        "      IWAN_RELAY_ALLOW_LOOPBACK=1       let non-loopback peers reach loopback/\n"
        "                                        link-local targets through --socks-listen;\n"
        "                                        only the exact value 1 enables it\n"
        "                                        (default: off) [TUN --socks-listen]\n"
        "      IWAN_WIN_THREAD_PIN=1             pin pump threads to CPU 1/2 (Windows\n"
        "                                        only; default: off) [TUN]\n"
        "      IWAN_ELEVATED_RELAUNCH            internal marker set by the program before\n"
        "                                        a Windows UAC relaunch; do not set\n"
        "      Flags: 0/false/no/off (case-insensitive) are off and any other non-empty\n"
        "      value is on, except IWAN_RXDBG/IWAN_FLOWDBG, which are case-sensitive.\n"
        "      Invalid numbers fall back to the default with a warning.\n"
        "      Also read: SSL_CERT_FILE, SSL_CERT_DIR (non-Windows: CA bundle for the\n"
        "      HTTPS calls, dropped before helper exec unless root-owned and not\n"
        "      group/other-writable), HOME, SUDO_USER, SUDO_UID, SUDO_GID,\n"
        "      XDG_RUNTIME_DIR, TMPDIR (Linux);\n"
        "      USERPROFILE, HOMEDRIVE, HOMEPATH, HOME, TEMP, TMP, USERNAME (Windows).\n");
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
        "      --proxy-cidr6 <PROXY_CIDR6>    IPv6 CIDRs/addresses/domains to route through the tunnel\n"
        "      --ustc                         Route USTC campus networks through the tunnel (shortcut for the usual --proxy-cidr list)\n"
        "      --proxy-ip <PROXY_IP>          IPv4 addresses to route through the tunnel. Can be repeated or comma-separated\n"
        "      --proxy-domain <PROXY_DOMAIN>  Domains to resolve and route through the tunnel. Can be repeated or comma-separated\n"
        "      --socks                        Use a rootless userspace SOCKS5 proxy instead of a TUN device\n"
        "      --socks-listen <SOCKS_LISTEN>  SOCKS5 proxy address (TUN mode: adds a SOCKS5+HTTP proxy following the TUN routes) [default: 127.0.0.1:1080]\n"
        "      --socks-mtu <SOCKS_MTU>        Maximum userspace inner IP MTU [default: 1380]\n"
        "      --socks-token <TOKEN>          Require this RFC1929 password from SOCKS5 clients\n"
        "      --socks-no-token               Explicitly allow a passwordless proxy with --allow-remote\n"
        "      --allow-remote                 Allow non-loopback SOCKS5 listen addresses\n"
        "      --socks-ipv6                   Assume the server relays IPv6: v6 DNS (AAAA) + ATYP=4 targets (off by default)\n"
        "  -h, --help                         Print help (see more with '--help')\n"
        "  -V, --version                      Print version\n");
    print_help_footer();
}

static void print_help_long(void)
{
    printf(
        "Fetch, list, or connect using iWAN server config.\n"
        "\n"
        "Config is stored at ~/.config/iwan/servers.json. Passwords are\n"
        "stored as plaintext (0600; DPAPI-sealed on Windows, in the login\n"
        "Keychain on macOS).\n"
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
        "      --proxy-cidr6 <PROXY_CIDR6>\n"
        "          IPv6 CIDRs, addresses or domains to route through the tunnel. Can be repeated or comma-separated\n"
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
        "      --socks\n"
        "          Use a rootless userspace SOCKS5 proxy instead of a TUN device\n"
        "\n"
        "      --socks-listen <SOCKS_LISTEN>\n"
        "          Local SOCKS5 listen address. In SOCKS mode (--socks)\n"
        "          this is the proxy itself; in TUN mode it adds a\n"
        "          SOCKS5+HTTP proxy whose traffic follows the TUN\n"
        "          routes (kernel-stack relay)\n"
        "          \n"
        "          [default: 127.0.0.1:1080]\n"
        "\n"
        "      --socks-mtu <SOCKS_MTU>\n"
        "          Maximum userspace inner IP MTU\n"
        "          \n"
        "          [default: 1380]\n"
        "\n"
        "      --socks-token <TOKEN>\n"
        "          Require this RFC1929 password from SOCKS5 clients\n"
        "          (HTTP proxy mode is disabled while a token is set)\n"
        "          \n"
        "          [default: no auth for loopback-only binds]\n"
        "\n"
        "      --socks-no-token\n"
        "          Explicitly allow a passwordless proxy with --allow-remote\n"
        "          (without this, --allow-remote requires --socks-token)\n"
        "\n"
        "      --allow-remote\n"
        "          Allow non-loopback SOCKS5 listen addresses\n"
        "\n"
        "      --socks-ipv6\n"
        "          Assume the server relays IPv6: enable AAAA DNS lookups\n"
        "          (v6 preferred for dual-stack domains) and accept ATYP=4\n"
        "          IPv6 targets. Off by default: the server is assumed to\n"
        "          be IPv4-only, so domains resolve A-only and ATYP=4\n"
        "          requests are rejected (rep=8)\n"
        "\n"
        "  -h, --help\n"
        "          Print help (see a summary with '-h')\n"
        "\n"
        "  -V, --version\n"
        "          Print version\n");
    print_help_footer();
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

/* R37-FIX-A2: the guard implementation lives in oidc_config.c next to
 * normalize_path(); the CLI gate here and the oidc_save_config() backstop
 * MUST share it, otherwise a spelling this gate accepts could still be a
 * root write. The prototype lives in oidc.h (R3-L18). */

/* R14-M-2: an empty or all-whitespace --config-dir joins with
 * "/servers.json" into "/servers.json" (and "--config-dir '//'" into
 * "///servers.json"), which would make oidc_save_config write into the
 * filesystem ROOT as root (sudo re-exec). This CLI parse gate is the
 * first authoritative check; oidc_config.c's save guard is the second
 * (backstop for any other caller).
 * R37-FIX-A2: also reject every spelling that RESOLVES to the root once
 * "." and ".." components are applied ("/..", "/foo/..", "/tmp/../..",
 * "C:\"): those are not "all separators", so the old check let them
 * through to the (then equally blind) save guard. "~" is expanded later
 * (see iwan_client_oidc.c), which re-checks the expanded value. */
static bool validate_config_dir(const char *val, char *err, size_t errsz)
{
    const char *p = val;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' ||
           *p == '\v' || *p == '\f')
        p++;
    if (*p == '\0') {
        snprintf(err, errsz, "must not be empty or all whitespace "
                 "(it would make the config path resolve to the "
                 "filesystem root)");
        return false;
    }
    if (oidc_config_dir_resolves_to_root(val)) {
        snprintf(err, errsz, "must not name the filesystem root "
                 "(all separators, or a \"..\"/drive-root spelling that "
                 "resolves to it)");
        return false;
    }
    return true;
}

void oidc_parse_cli(int argc, char **argv, Opts *o, Cli *usage)
{
    /* called first thing from main: cover the whole process before any
     * network I/O (https.c depends on EPIPE, not SIGPIPE, killing us) */
    util_ignore_sigpipe();

    cli_init(usage);
    g_usage = usage;

    cli_opt opts[] = {
        { "config-dir",   CLI_OPT_STR,  &o->config_dir,    "<CONFIG_DIR>",    validate_config_dir },
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
        { "proxy-cidr6",  CLI_OPT_CSV,  &o->proxy_cidr6,   "<PROXY_CIDR6>",  NULL },
        { "socks",        CLI_OPT_BOOL, &o->socks,         NULL,             NULL },
        { "socks-listen", CLI_OPT_STR,  &o->socks_listen,  "<SOCKS_LISTEN>", valid_listen },
        { "socks-mtu",    CLI_OPT_U16,  &o->socks_mtu,     "<SOCKS_MTU>",    NULL },
        { "socks-token",  CLI_OPT_STR,  &o->socks_token,   "<TOKEN>",        validate_token_len },
        { "socks-no-token", CLI_OPT_BOOL, &o->socks_no_token, NULL,          NULL },
        { "allow-remote", CLI_OPT_BOOL, &o->allow_remote,  NULL,             NULL },
        { "socks-ipv6",   CLI_OPT_BOOL, &o->socks_ipv6,   NULL,             NULL },
    };

    cli_ctl ctl = {
        .on_help = on_help,
        .on_version = on_version,
        .version_is_unknown = false,
        .usage_str = on_usage,
        .short_aliases = short_aliases,
    };
    cli_parse(usage, argc, argv, 1, opts, sizeof opts / sizeof opts[0], &ctl);
}