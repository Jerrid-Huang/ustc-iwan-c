#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <net/if.h>   /* if_nametoindex: --bind-dev name -> ifindex */
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#include "wintun_fetch.h"
#endif

#include "addr.h"
#include "auth.h"
#include "cli.h"
#include "cli_common.h"
#include "common.h"
#include "crypto.h"
#ifdef __linux__
#include "kdp.h"      /* kernel data plane (Linux only): conditionally compiled with kdp.c */
#endif
#if defined(_WIN32)
#include "kdp_win.h"   /* Windows kernel data plane (WFP driver): conditionally compiled with kdp_win.c */
#endif
#include "profile.h"
#include "protocol.h"
#include "proxy.h"
#include "relay_proxy.h"
#include "socks.h"
#include "socks_internal.h"   /* R36-L01: on_sig for the loop-level stop
                               * handler (see cmd_socks) */
#include "tun.h"
#include "util.h"

#ifdef IWAN_HEADLESS_SVC
/* the iwan-winsvc front-end (svc_win.c) owns main() for this target and
 * calls the renamed entry below; no other code changes - the service is
 * just another caller of the exact same command paths */
#define main iwan_client_main
#endif

#define VERSION     "0.8.0"
#define PING_BUF_SZ 64
/* PING round-trip bound: udp_connect's recv timeout (ms). PING has no
 * retry loop, so a single bound must cover one request/response pair. */
#define PING_TIMEOUT_MS 3000
/* token redaction: only the low 16 bits are ever logged (tok=0x****xxxx) */
#define TOK_LOG_MASK 0xFFFF

typedef struct {
    const char *server;
    uint16_t    port;
    const char *user;
    const char *pass;
    const char *ct_pass;
    const char *pass_file;
    const char *ct_pass_file;
    uint16_t    mtu;
    const char *tun;
    /* "tun" (default, TUN userspace data plane) or "kernel" (kernel data plane, Linux only;
     * see IWAN_DATA_PLANE_* in cli_common.h) */
    const char *data_plane;
    slist_t     proxy_cidr;
    slist_t     proxy_ip;
    slist_t     proxy_domain;
    slist_t     proxy_cidr6;    /* IPv6: CIDRs, addresses or domains */
    const char *listen_str;
    const char *socks_token;
    bool        socks_no_token;
    bool        allow_remote;
    bool        socks_ipv6;     /* assume the server relays IPv6 (opt-in) */
    /* Carrier NIC binding (meaningful only with --data-plane kernel; see kdp_bind in kdp.h):
     *   --bind-dev <NIC>  bind NIC: strictly use this interface
     *   --bind-ip  <IP>   bind egress IP: the kernel resolves it to the owning interface via the
     *                     address table; the address is also the outer IP header source
     * neither given = bind nothing (the kernel pins it after one FIB lookup). */
    const char *bind_dev;
    /* Reply routing (conntrack, kernel plane only): send replies of "connections arriving
     * through the tunnel" back the way they came. See docs/reply-routing.md. */
    bool        reply_via_tunnel;
    const char *bind_ip;
    uint32_t    bind_ip_host;   /* --bind-ip parse result (v4, host order) */
    /* If --bind-ip parsed as a v6 literal, family+address are here; mutually
     * exclusive with bind_ip_host (same option, family from the literal) */
    int         bind_ip_family; /* AF_UNSPEC = not given/not parsed */
    struct in6_addr bind_ip6;
} CmdOpts;

/* ---- help/usage text ---- */

static const char *usage_full(const char *sub)
{
    if (sub && strcmp(sub, "ping") == 0)
        return "Usage: iwan-client ping [OPTIONS] --server <SERVER>";
    if (sub && strcmp(sub, "auth") == 0)
        return "Usage: iwan-client auth [OPTIONS] --server <SERVER>";
    if (sub && strcmp(sub, "proxy") == 0)
        return "Usage: iwan-client proxy [OPTIONS] --server <SERVER>";
    if (sub && strcmp(sub, "socks") == 0)
        return "Usage: iwan-client socks [OPTIONS] --server <SERVER>";
    return "Usage: iwan-client <COMMAND>";
}

static const char *usage_required(const char *sub)
{
    if (sub && strcmp(sub, "ping") == 0)
        return "Usage: iwan-client ping --server <SERVER>";
    if (sub && strcmp(sub, "auth") == 0)
        return "Usage: iwan-client auth --server <SERVER> "
               "--pass <PASS> or --pass-file <FILE>";
    if (sub && strcmp(sub, "proxy") == 0)
        return "Usage: iwan-client proxy --server <SERVER> "
               "--pass <PASS> or --pass-file <FILE>";
    if (sub && strcmp(sub, "socks") == 0)
        return "Usage: iwan-client socks --server <SERVER> "
               "--pass <PASS> or --pass-file <FILE>";
    return "Usage: iwan-client <COMMAND>";
}

/* repeat-option note + environment matrix, printed at the end of every help
 * text of this binary; the definition follows print_sub_help */
static void print_help_footer(FILE *out);

static void print_top_help(FILE *out)
{
    fprintf(out,
        "iWAN client - ping, authenticate, or run a SOCKS5 proxy\n"
        "\n"
        "Usage: iwan-client <COMMAND>\n"
        "\n"
        "Commands:\n"
        "  ping   Test server connectivity (round-trip latency)\n"
        "  auth   Perform authentication handshake only (debug / credential check)\n"
        "  proxy  Open a TUN tunnel and proxy traffic through the VPN server\n"
        "  socks  Run a rootless SOCKS5 proxy using a userspace TCP/IP stack\n"
        "  help   Print this message or the help of the given subcommand(s)\n"
        "\n"
        "Options:\n"
        "  -h, --help     Print help\n"
        "  -V, --version  Print version\n");
    print_help_footer(out);
}

static void print_help_help(void)
{
    printf(
        "Print this message or the help of the given subcommand(s)\n"
        "\n"
        "Usage: iwan-client help [COMMAND]...\n"
        "\n"
        "Arguments:\n"
        "  [COMMAND]...  Print help for the subcommand(s)\n");
    print_help_footer(stdout);
}

/* ---- shared help footer: repeat-option semantics + environment matrix ----
 *
 * R37 R5 (L24): "repeating an option ..." is deliberately the same opening
 * sentence in all three binaries (iwan-server: the last value wins; the two
 * clap-style parsers: exit 2 with 'cannot be used multiple times'), so the
 * documented semantics can be compared side by side.
 * R37 R5 (L20-1): the environment matrix lists ONLY the variables this
 * binary really reads; [scope] says where each one applies. The same block
 * is printed by every help text of this binary, and it mirrors README.md's
 * matrix. */
static void print_help_footer(FILE *out)
{
    fprintf(out,
        "\n"
        "Repeating an option is an error: 'cannot be used multiple times' (exit 2).\n"
        "The list options --proxy-cidr, --proxy-ip, --proxy-domain and\n"
        "--proxy-cidr6 (proxy only) are the exception: they accumulate across\n"
        "repetitions.\n"
        "\n"
        "Environment (settings this binary reads; [scope] = where they apply):\n"
        "      IWAN_DEBUG=1                      debug logging (default: off; ignored by\n"
        "                                        IWAN_DEBUG_STRIP builds) [all]\n"
        "      IWAN_PROFILE=1                    print stage throughput at exit (default:\n"
        "                                        off; ignored by IWAN_DEBUG_STRIP builds) [all]\n"
        "      IWAN_RX_STALE_MS=<ms>             re-authenticate after this long without\n"
        "                                        downlink, 0 disables, 30000..86400000\n"
        "                                        (default: 120000) [proxy, socks, proxy --data-plane kernel]\n"
        "      IWAN_SEND_PACING_PPS=<n>          aggregate send pacing in packets/s,\n"
        "                                        0 disables; range 1..10000000\n"
        "                                        (default: 0) [proxy, socks]\n"
        "      IWAN_RXDBG=1                      log every VPN datagram received\n"
        "                                        (default: off; only the case-sensitive\n"
        "                                        exact 0/false/off switch it off) [socks]\n"
        "      IWAN_FLOWDBG=1                    log SOCKS flow state changes and close\n"
        "                                        reasons (default: off; same case-sensitive\n"
        "                                        0/false/off rule) [socks]\n"
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
        "                                        IWAN_DEBUG_STRIP builds (default: off) [proxy]\n"
        "      IWAN_PUMP_QUEUES=<n>              TUN reader-pool queues, 1..8 (default:\n"
        "                                        number of CPUs, capped at 8; wintun is\n"
        "                                        single-queue on Windows) [proxy]\n"
        "      IWAN_RELAY_ALLOW_LOOPBACK=1       let non-loopback peers reach loopback/\n"
        "                                        link-local targets through --listen; only\n"
        "                                        the exact value 1 enables it (default: off)\n"
        "                                        [proxy --listen]\n"
        "      IWAN_WIN_THREAD_PIN=1             pin pump threads to CPU 1/2 (Windows\n"
        "                                        only; default: off) [proxy]\n"
        "      IWAN_ELEVATED_RELAUNCH            internal marker set by the program before\n"
        "                                        a Windows UAC relaunch; do not set\n"
        "      Flags: 0/false/no/off (case-insensitive) are off and any other non-empty\n"
        "      value is on, except: IWAN_RXDBG/IWAN_FLOWDBG take only the case-SENSITIVE\n"
        "      exact 0/false/off as off (no/NO/False/Off/0x stay on); IWAN_PUMP_PROF is\n"
        "      on whenever the variable is SET at all (empty string and 0 included).\n"
        "      Invalid numbers fall back to the default with a warning.\n"
        "      Also read: SSL_CERT_FILE (non-Windows TUN mode; the only CA file source\n"
        "      chosen by an environment variable), SSL_CERT_DIR (never read as a CA\n"
        "      directory; before helper exec it is only kept or dropped by\n"
        "      owner/permission - a non-root-owned or group/other-writable path is\n"
        "      unset).\n");
}

static void print_sub_help(const char *sub)
{
    if (strcmp(sub, "ping") == 0) {
        printf(
            "Test server connectivity (round-trip latency)\n"
            "\n"
            "Usage: iwan-client ping [OPTIONS] --server <SERVER>\n"
            "\n"
            "Options:\n"
            "      --server <SERVER>  \n"
            "      --port <PORT>      [default: 6001]\n"
            "  -h, --help             Print help\n");
    } else if (strcmp(sub, "auth") == 0) {
        printf(
            "Perform authentication handshake only (debug / credential check)\n"
            "\n"
            "Usage: iwan-client auth [OPTIONS] --server <SERVER>\n"
            "\n"
            "Options:\n"
            "      --server <SERVER>    \n"
            "      --port <PORT>        [default: 6001]\n"
            "      --user <USER>        [default: _rev_m_1]\n"
            "      --pass <PASS>        \n"
            "      --pass-file <PASS_FILE>      \n"
            "      --ct-pass <CT_PASS>  \n"
            "      --ct-pass-file <CT_PASS_FILE>\n"
            "      --mtu <MTU>          [default: %d]\n"
            "  -h, --help               Print help\n",
            IWAN_DEFAULT_MTU);
    } else if (strcmp(sub, "proxy") == 0) {
        printf(
            "Open a TUN tunnel and proxy traffic through the VPN server\n"
            "\n"
            "Usage: iwan-client proxy [OPTIONS] --server <SERVER>\n"
            "\n"
            "Options:\n"
            "      --server <SERVER>              \n"
            "      --port <PORT>                  [default: 6001]\n"
            "      --user <USER>                  [default: _rev_m_1]\n"
            "      --pass <PASS>                  \n"
            "      --pass-file <PASS_FILE>        \n"
            "      --ct-pass <CT_PASS>            \n"
            "      --ct-pass-file <CT_PASS_FILE>  \n"
            "      --mtu <MTU>                    [default: %d]\n"
            "      --tun <TUN>                    [default: iwan0]\n"
            "      --data-plane <auto|tun|kernel>  auto = default: on Linux try the kernel module iwan first, "
            "fall back to tun if it fails to start here, exit only if neither works; tun = TUN userspace data plane only; "
            "kernel = kernel data plane only (Linux only). Explicit tun/kernel never falls back\n"
            "      --reply-via-tunnel              route replies of \"connections arriving through the tunnel\" back the way they came (--data-plane "
            "kernel only): the served address set comes from --proxy-cidr*/--proxy-ip/--proxy-domain, peer addresses need no foreknowledge; "
            "conntrack (CONNMARK) records the ingress interface on the conntrack entry, and replies select the tunnel-only routing table by fwmark. "
            "The module hook must decapsulate before conntrack (default hooknum=0/hookprio=-300, or reinject=1), "
            "otherwise startup is refused instead of silently doing nothing; see docs/reply-routing.md\n"
            "      --bind-dev <NIC>               bound carrier NIC (--data-plane kernel only): a session uses only this "
            "downstream NIC; omitted = pinned once by the FIB lookup\n"
            "      --bind-ip <IP>                 bound egress IP (--data-plane kernel only): the kernel resolves the local address table "
            "to the NIC holding that address and pins it; the address is also the outer IP header source; "
            "v4 dotted or a v6 literal both work (the family must match the session outer family: the outer family comes from --server's address family)\n"
            "      --proxy-cidr <PROXY_CIDR>      \n"
            "      --proxy-ip <PROXY_IP>          \n"
            "      --proxy-domain <PROXY_DOMAIN>  \n"
            "      --proxy-cidr6 <PROXY_CIDR6>    inner IPv6 routes: supported by both the kernel and TUN planes\n"
            "                                      (the module version-checks inner headers). Inner MTU must be\n"
            "                                      >= 1280 (RFC 8200 Section 5), otherwise a warning\n"
            "      --listen <LISTEN>              SOCKS5+HTTP proxy sharing the TUN routes (optional)\n"
            "      --socks-token <TOKEN>          RFC1929 password for the proxy\n"
            "      --socks-no-token               Explicit proxy password opt-out with --allow-remote\n"
            "      --allow-remote                 Allow non-loopback --listen\n"
            "  -h, --help                         Print help\n",
            IWAN_DEFAULT_MTU);
    } else if (strcmp(sub, "socks") == 0) {
        printf(
            "Run a rootless SOCKS5 proxy using a userspace TCP/IP stack\n"
            "\n"
            "Usage: iwan-client socks [OPTIONS] --server <SERVER>\n"
            "\n"
            "Options:\n"
            "      --server <SERVER>    \n"
            "      --port <PORT>        [default: 6001]\n"
            "      --user <USER>        [default: _rev_m_1]\n"
            "      --pass <PASS>        \n"
            "      --pass-file <PASS_FILE>      \n"
            "      --ct-pass <CT_PASS>  \n"
            "      --ct-pass-file <CT_PASS_FILE>\n"
            "      --mtu <MTU>          [default: 1380]\n"
            "      --listen <LISTEN>    Local SOCKS5 listen address [default: 127.0.0.1:1080]\n"
            "      --socks-token <TOKEN>\n"
            "      --socks-no-token     Explicitly allow a passwordless proxy with --allow-remote\n"
            "      --allow-remote       Allow non-loopback listen addresses\n"
            "      --socks-ipv6         Assume the server relays IPv6: AAAA DNS + ATYP=4 (off by default)\n"
            "  -h, --help               Print help\n");
    }
    print_help_footer(stdout);
}

/* ---- shared CLI glue (per-subcommand context) ---- */

static const char *g_usage_sub;

static const char *current_usage(void)
{
    return usage_full(g_usage_sub);
}

static void on_help(bool long_help)
{
    (void)long_help;
    print_sub_help(g_usage_sub);
    exit(0);
}

static void err_usage_exit(const char *usage)
{
    fprintf(stderr, "\n\n%s\n\nFor more information, try '--help'.\n", usage);
    exit(2);
}

static void err_required_msg(const char *sub, const char *detail)
{
    fprintf(stderr,
            "error: the following required arguments were not provided:\n  %s",
            detail);
    err_usage_exit(usage_required(sub));
}

static void err_required(const char *sub)
{
    err_required_msg(sub, "--server <SERVER>");
}

/* --pass has no built-in default: refuse to run without it. */
static void err_required_pass(const char *sub)
{
    err_required_msg(sub, "--pass <PASS> or --pass-file <FILE>");
}

/* --allow-remote without an explicit proxy password is an open proxy
 * waiting to happen: require an explicit --socks-token, or an explicit
 * --socks-no-token opt-out. Local (loopback) binds stay passwordless
 * by default. */
static void err_remote_token(const char *sub)
{
    fprintf(stderr,
            "error: --allow-remote requires an explicit SOCKS proxy "
            "password:\n"
            "  pass --socks-token <PASS> to require RFC1929 auth, or\n"
            "  pass --socks-no-token to confirm an open (passwordless) "
            "proxy");
    err_usage_exit(usage_required(sub));
}

/* read the first line of a pass file (O_NOFOLLOW|O_NONBLOCK, capped at
 * sz-1 bytes, trailing whitespace trimmed); returns buf. Only a regular
 * file is accepted (a FIFO with no writer would otherwise block the
 * open forever), an empty file or an over-long first line is a hard
 * error rather than a silently truncated password. Errors exit(1). */
#ifdef _WIN32
/* map a GetLastError() code to a POSIX-style errno so the pass-file
 * error messages (strerror(errno)) read the same as on Linux */
static int win_errno(void)
{
    switch (GetLastError()) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:      return ENOENT;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:   return EACCES;
    case ERROR_TOO_MANY_OPEN_FILES: return EMFILE;
    default:                        return EIO;
    }
}
#endif

static const char *read_pass_file(const char *path, char *buf, size_t sz)
{
#ifdef _WIN32
    /* CreateFileA with FILE_FLAG_OPEN_REPARSE_POINT: a symlink/junction
     * is opened as the link itself, never followed, and rejected below -
     * the O_NOFOLLOW equivalent (O_NOFOLLOW does not exist on Windows).
     * FILE_FLAG_BACKUP_SEMANTICS allows opening a directory just far
     * enough to detect and reject it. */
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING,
                           FILE_FLAG_OPEN_REPARSE_POINT |
                               FILE_FLAG_BACKUP_SEMANTICS,
                           NULL);
    if (h == INVALID_HANDLE_VALUE) {
        errno = win_errno();
        log_err("Error: cannot open pass file '%s': %s", path,
                strerror(errno));
        exit(1);
    }
    BY_HANDLE_FILE_INFORMATION fi;
    if (!GetFileInformationByHandle(h, &fi)) {
        errno = win_errno();
        log_err("Error: cannot stat pass file '%s': %s", path,
                strerror(errno));
        CloseHandle(h);
        exit(1);
    }
    if ((fi.dwFileAttributes &
         (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY |
          FILE_ATTRIBUTE_DEVICE)) != 0) {
        log_err("Error: pass file '%s' is not a regular file", path);
        CloseHandle(h);
        exit(1);
    }
    DWORD n = 0;
    if (!ReadFile(h, buf, (DWORD)(sz - 1), &n, NULL)) {
        errno = win_errno();
        log_err("Error: cannot read pass file '%s': %s", path,
                strerror(errno));
        CloseHandle(h);
        exit(1);
    }
    CloseHandle(h);
#else
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        log_err("Error: cannot open pass file '%s': %s", path,
                strerror(errno));
        exit(1);
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        log_err("Error: cannot stat pass file '%s': %s", path,
                strerror(errno));
        close(fd);
        exit(1);
    }
    if (!S_ISREG(st.st_mode)) {
        log_err("Error: pass file '%s' is not a regular file", path);
        close(fd);
        exit(1);
    }
    ssize_t n = read(fd, buf, sz - 1);
    close(fd);
    if (n < 0) {
        log_err("Error: cannot read pass file '%s': %s", path,
                strerror(errno));
        exit(1);
    }
#endif
    if (n == 0) {
        log_err("Error: pass file '%s' is empty", path);
        exit(1);
    }
    if ((size_t)n == sz - 1 && memchr(buf, '\n', (size_t)n) == NULL) {
        /* %llu not %zu: msvcrt printf (Windows) lacks %zu */
        log_err("Error: pass file '%s' first line too long (max %llu "
                "bytes)", path, (unsigned long long)(sz - 2));
        exit(1);
    }
    buf[n] = '\0';
    /* keep only the first line */
    char *eol = strchr(buf, '\n');
    if (eol)
        *eol = '\0';
    eol = strchr(buf, '\r');
    if (eol)
        *eol = '\0';
    /* strip trailing whitespace */
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == ' ' || buf[len - 1] == '\t'))
        buf[--len] = '\0';
    return buf;
}

/* scrub a secret string (an argv slot or a pass-file buffer) from memory;
 * NULL-safe, immune to optimizer elision */
static void cleanse_str(const char *s)
{
    volatile unsigned char *v = (volatile unsigned char *)s;
    if (!s)
        return;
    while (*v)
        *v++ = 0;
}

static void die_invalid_address(const char *ctx)
{
    fprintf(stderr,
            "Error: %s\n\nCaused by:\n    invalid socket address syntax\n",
            ctx);
    exit(2);   /* argument-validation error: same code as the CLI parser */
}


/* parse subcommand args; on -h/--help/errors the shared parser exits */
static void parse_cmd(int argc, char **argv, int start, const char *sub,
                      const cli_opt *opts, size_t nopts)
{
    g_usage_sub = sub;
    Cli u;
    memset(&u, 0, sizeof u);
    cli_ctl ctl = {
        .on_help = on_help,
        .version_is_unknown = true,
        .usage_str = current_usage,
    };
    cli_parse(&u, argc, argv, start, opts, nopts, &ctl);
}

/* ---- shared auth glue (auth/proxy/socks subcommands) ---- */

/* pass-file scratch buffers; the subcommands run one at a time */
static char g_pass_buf[512];
static char g_ct_buf[512];

/* fill the 8 credential/connection options shared by auth/proxy/socks
 * into opts[0..7]; each command appends its private options after */
static void add_auth_opts(cli_opt *opts, CmdOpts *o)
{
    opts[0] = (cli_opt){ "server",       CLI_OPT_STR, &o->server,
                         "<SERVER>", NULL };
    opts[1] = (cli_opt){ "port",         CLI_OPT_U16, &o->port,
                         "<PORT>", NULL };
    opts[2] = (cli_opt){ "user",         CLI_OPT_STR, &o->user,
                         "<USER>", NULL };
    opts[3] = (cli_opt){ "pass",         CLI_OPT_STR, &o->pass,
                         "<PASS>", NULL };
    opts[4] = (cli_opt){ "pass-file",    CLI_OPT_STR, &o->pass_file,
                         "<PASS_FILE>", NULL };
    opts[5] = (cli_opt){ "ct-pass",      CLI_OPT_STR, &o->ct_pass,
                         "<CT_PASS>", NULL };
    opts[6] = (cli_opt){ "ct-pass-file", CLI_OPT_STR, &o->ct_pass_file,
                         "<CT_PASS_FILE>", NULL };
    opts[7] = (cli_opt){ "mtu",          CLI_OPT_U16, &o->mtu,
                         "<MTU>", NULL };
}

/* resolve --pass/--pass-file and --ct-pass/--ct-pass-file into o.pass /
 * o.ct_pass (buffers live for the process); the clap-style required
 * error exits when neither pass form is given.
 *
 * Explicit --pass deliberately wins over --pass-file: a secret typed
 * on the command line is a higher-trust override of the file default,
 * so supplying both is accepted (not an error), never the reverse.
 * The same rule applies to --ct-pass over --ct-pass-file. */
static void resolve_credentials(CmdOpts *o, const char *sub)
{
    if (!o->pass) {
        if (o->pass_file)
            o->pass = read_pass_file(o->pass_file, g_pass_buf,
                                     sizeof g_pass_buf);
        else
            err_required_pass(sub);
    }
    if (!o->ct_pass && o->ct_pass_file)
        o->ct_pass = read_pass_file(o->ct_pass_file, g_ct_buf,
                                    sizeof g_ct_buf);
}

/* OPEN/ACK handshake with the VPN server; returns fd or -1 */
static int authenticate(const CmdOpts *o, int style, AuthResult *res)
{
    int r = authenticate_ex(o->user, o->pass, o->ct_pass, o->mtu,
                            o->server, o->port, style, res);
    if (r == -1) {
        log_err("Error: invalid --ct-pass hex (want exactly 32 hex digits)");
        cleanse_str(o->ct_pass);   /* error path: ct pass can never be
                                    * reused, wipe it now */
        return -1;
    }
    /* success: keep ct_pass so reconnect/re-auth can reuse the credential;
     * the terminal caller (cmd_proxy / cmd_socks) wipes it at session end */
    if (r == -2) {
        fprintf(stderr, "Error: username too long (max %d bytes)\n",
                IWAN_TLV_VLEN_MAX);
        return -1;
    }
    return r;
}

static void free_route_opts(CmdOpts *o)
{
    slist_free(&o->proxy_cidr);
    slist_free(&o->proxy_ip);
    slist_free(&o->proxy_domain);
    slist_free(&o->proxy_cidr6);
}

/* ---- commands ---- */

static void fmt_duration(char *out, size_t sz, uint64_t ns)
{
    /* Rust std::time::Duration Debug format, e.g. 159.044us / 1.5ms / 2s */
    uint64_t unit;
    const char *suf;
    if (ns >= 1000000000ull) {
        unit = 1000000000ull;
        suf = "s";
    } else if (ns >= 1000000ull) {
        unit = 1000000ull;
        suf = "ms";
    } else if (ns >= 1000ull) {
        unit = 1000ull;
        suf = "us";
    } else {
        unit = 1ull;
        suf = "ns";
    }
    uint64_t whole = ns / unit;
    uint64_t frac = ns % unit;
    if (frac == 0) {
        snprintf(out, sz, "%llu%s", (unsigned long long)whole, suf);
        return;
    }
    uint64_t f3 = frac * 1000ull / unit;
    char tmp[4];
    tmp[0] = (char)('0' + f3 / 100);
    tmp[1] = (char)('0' + (f3 / 10) % 10);
    tmp[2] = (char)('0' + f3 % 10);
    tmp[3] = '\0';
    int len = 3;
    while (len > 0 && tmp[len - 1] == '0')
        len--;
    if (len == 0)
        snprintf(out, sz, "%llu%s", (unsigned long long)whole, suf);
    else
        snprintf(out, sz, "%llu.%.*s%s", (unsigned long long)whole, len, tmp,
                 suf);
}

/* R10 (F1-8): install libcrypto's never-NULL allocator as LATE as possible.
 *
 * R39 put the single crypto_init() call in main() before the subcommand
 * dispatch, which made every usage error of an *already recognised*
 * subcommand ("iwan-client ping" without --server) initialise libcrypto:
 * under an injected allocation failure that turned a plain rc=2 usage error
 * into an "out of memory" abort, and with the allocator wrapper removed it
 * hung in futex() (e07fe75 did zero libcrypto work on those paths). The
 * contract in crypto.h is explicit: --help, --version and argument errors
 * must stay libcrypto-free.
 *
 * Every cmd_* below therefore calls this immediately after its last
 * argument/usage check and strictly BEFORE its first libcrypto call:
 *   cmd_ping  -> ctrl_hdr()      -> protocol.c pkt_sig()  -> md5()
 *   cmd_auth  -> authenticate()  -> cli_common.c authenticate_ex()
 *                                 -> protocol.c build_open() -> md5()
 *   cmd_proxy -> wintun_ensure() -> wintun_pin.c sha256()  (_WIN32 only)
 *                authenticate()  (Linux: the first one on this path)
 *   cmd_socks -> authenticate()
 * Installing it later than the first libcrypto call would reintroduce the
 * R39 hang (CRYPTO_set_mem_functions() only has an effect while libcrypto
 * is still uninitialised), so the position is load-bearing: keep it after
 * the validation, never after the crypto. */
static void crypto_init_or_die(void)
{
    if (crypto_init() != 0)
        oom_abort();
}

static int cmd_ping(int argc, char **argv, int start)
{
    CmdOpts o;
    memset(&o, 0, sizeof o);
    o.port = 6001;

    cli_opt opts[] = {
        { "server", CLI_OPT_STR, &o.server, "<SERVER>", NULL },
        { "port",   CLI_OPT_U16, &o.port,   "<PORT>",   NULL },
    };
    parse_cmd(argc, argv, start, "ping", opts, sizeof opts / sizeof opts[0]);
    if (!o.server)
        err_required("ping");
    char eb[64];
    if (!check_server_ip(o.server, eb, sizeof eb))
        die_invalid_address("invalid server address");
    /* last usage check passed; next stop is ctrl_hdr() -> md5() */
    crypto_init_or_die();

    int fd = udp_connect(o.server, o.port, PING_TIMEOUT_MS);
    if (fd < 0) {
        log_err("Error: connect UDP: %s", strerror(errno));
        return 1;
    }

    buf_t pkt;
    buf_init(&pkt);
    ctrl_hdr(&pkt, PT_PING_REQ, 0, IWAN_PING_SID, IWAN_PING_TOK);
    if (port_send(fd, pkt.data, pkt.len, 0) != (ssize_t)pkt.len) {
        log_err("Error: send PING: %s", strerror(errno));
        buf_free(&pkt);
        port_close(fd);
        return 1;
    }
    /* %llu not %zu: msvcrt printf (Windows) lacks %zu */
    log_info("-> PING (%lluB) to %s:%u", (unsigned long long)pkt.len,
             o.server, (unsigned)o.port);
    buf_free(&pkt);

    uint8_t rbuf[PING_BUF_SZ] = { 0 };
    /* port_now_us is the monotonic clock (QPC on Windows); convert the
     * us delta back to ns so fmt_duration keeps its existing units */
    uint64_t t0 = port_now_us();
    ssize_t n = port_recv(fd, rbuf, sizeof rbuf, 0);
    if (n == IWAN_CTRL_LEN && rbuf[0] == PT_PING_RSP &&
        verify_sig(rbuf, (size_t)n)) {
        uint64_t t1 = port_now_us();
        uint64_t ns = (t1 - t0) * 1000ull;
        char dbuf[48];
        fmt_duration(dbuf, sizeof dbuf, ns);
        log_info("<- PONG  RTT=%s", dbuf);
        port_close(fd);
        return 0;
    }
    if (n < 0) {
        log_err("Error: timeout: %s (os error %d)", strerror(errno), errno);
    } else {
        char hex[2 * PING_BUF_SZ + 1];
        hex_encode(rbuf, (size_t)n, hex);
        log_err("Error: <- %dB type=0x%02x %s", (int)n, rbuf[0], hex);
    }
    port_close(fd);
    return 1;
}

static int cmd_auth(int argc, char **argv, int start)
{
    CmdOpts o;
    memset(&o, 0, sizeof o);
    o.port = 6001;
    o.user = "_rev_m_1";
    o.mtu = IWAN_DEFAULT_MTU;
    /* must match the 8 options add_auth_opts fills (opts[0..7]):
     * any extra slot would be left uninitialized and parse_cmd would
     * call strlen() on it when an unknown --long option is scanned */
    cli_opt opts[8];

    add_auth_opts(opts, &o);
    parse_cmd(argc, argv, start, "auth", opts, sizeof opts / sizeof opts[0]);
    if (!o.server)
        err_required("auth");
    resolve_credentials(&o, "auth");
    char eb[64];
    if (!check_server_ip(o.server, eb, sizeof eb))
        die_invalid_address("invalid server address");

    /* last usage check passed; next stop is authenticate() -> md5() */
    crypto_init_or_die();

    AuthResult res;
    int fd = authenticate(&o, DO_AUTH_AUTH, &res);
    cleanse_str(o.pass);     /* last use of the pass */
    cleanse_str(o.ct_pass);  /* last use of the client-token pass */
    if (fd < 0) {
        log_err("Error: auth failed");
        return 1;
    }

    log_info("OK sid=0x%04x tok=0x****%04x tun=%s gw=%s dns=%s mtu=%u",
             res.sid, res.tok & TOK_LOG_MASK, res.tun, res.gw, res.dns,
             (unsigned)res.mtu);
    if (res.tun6[0])
        log_info("   IPv6 tun=%s gw=%s dns=%s", res.tun6, res.gw6, res.dns6);

    buf_t cl;
    buf_init(&cl);
    ctrl_hdr(&cl, PT_CLOSE, 1, res.sid, res.tok);
    (void)port_send(fd, cl.data, cl.len, 0);
    log_info("-> CLOSE");
    buf_free(&cl);
    port_close(fd);
    return 0;
}

/* Which kernel device --data-plane selects on Windows: kernel uses the WFP
 * callout driver (iwan.sys, device \\.\iwan), kernel-mp uses the NDIS
 * miniport + protocol driver (iwanmp.sys, device \\.\iwanmp). NULL = default. */
#if defined(_WIN32)
static const wchar_t *win_device_path(const char *plane)
{
    return data_plane_is_kernel_mp(plane) ? IWAN_WIN_USER_PATH_MP : NULL;
}

/* Which adapter carries the inner address: WFP-plane packets are injected by
 * the kernel and need an existing adapter that carries the inner address
 * (KM-TEST loopback, renamed iWAN after install); the NDIS plane's adapter is
 * the driver's own (named by the INF DeviceDesc, installed as iwanmp), so the
 * name follows the plane. NULL = kdp_win.c's default name. */
static const char *win_inner_dev(const char *plane)
{
    return data_plane_is_kernel_mp(plane) ? IWAN_WIN_DEF_DEV_MP : NULL;
}
#endif

/* TUN plane resource preparation: open the device (nonblocking) + optional
 * SOCKS5/HTTP side-car (kernel-stack forwarding sharing the TUN routes).
 * Extracted because the TUN device is now opened on demand: the default auto
 * tries the kernel plane first, and the device is opened only when the kernel
 * plane fails to start and we fall back (or TUN was chosen anyway). The
 * kernel plane must not have iwan0 open beforehand - that makes the module's
 * SESSION_UP report -EBUSY (device taken) and the kernel plane fails instead.
 *
 * Returns fd on success (>=0, rp filled by relay_proxy_start, NULL on
 * failure); returns -1 on failure with the reason already printed by errno
 * class (EBUSY = name taken is the most common; the old catch-all "must be
 * root" text was misleading). */
static int proxy_tun_prepare(const CmdOpts *o, struct RelayProxy **rp)
{
    int fd;
    int e;

    *rp = NULL;
    errno = 0;
    fd = open_tun(o->tun);
    if (fd < 0) {
        e = errno;
#ifdef _WIN32
        /* errno values on Windows have no actionable distinction (see the
         * classification in the Linux branch below), so just print it. */
        log_err("Error: open tun failed (errno=%d, %s; see earlier log; "
                "wintun.dll must sit next to the executable and the wintun "
                "driver must be installed)", e, strerror(e));
#else
        if (e == EBUSY || e == EEXIST || e == EINVAL)
            log_err("Error: failed to open TUN device %s: the kernel rejected this name (%s)\n"
                    "  Only one virtual-NIC client can hold this device name in a netns "
                    "at a time. The owner may be another client (stop it, Ctrl-C), "
                    "or the %s created by the kernel module (a leftover --data-plane kernel "
                    "session; clear it with sudo iwan_ctl session-down).\n"
                    "  Stop the owner and retry; or use --tun <another name>"
                    " (note that routes will overwrite each other)",
                    o->tun, strerror(e), o->tun);
        else if (e == EACCES || e == EPERM)
            log_err("Error: failed to open TUN device %s: permission denied (%s) - the TUN "
                    "data plane requires root (or CAP_NET_ADMIN)", o->tun,
                    strerror(e));
        else if (e != 0)
            log_err("Error: failed to open TUN device %s: %s", o->tun, strerror(e));
        else
            log_err("Error: failed to open TUN device %s", o->tun);
#endif
        return -1;
    }
    set_nonblock(fd);
    log_info("tun %s fd=%d", o->tun, fd);
    if (o->listen_str &&
        relay_proxy_start(o->listen_str, o->socks_token, o->socks_no_token,
                          o->allow_remote, rp) != 0) {
        tun_close(fd);
        return -1;
    }
    return fd;
}

static int cmd_proxy(int argc, char **argv, int start)
{
    CmdOpts o;
    memset(&o, 0, sizeof o);
    o.port = 6001;
    o.user = "_rev_m_1";
    o.mtu = IWAN_DEFAULT_MTU;
    o.tun = "iwan0";
    o.data_plane = IWAN_DATA_PLANE_AUTO;   /* default: kernel plane, fall back to TUN if it fails */
    cli_opt opts[21];

    add_auth_opts(opts, &o);
    opts[8] = (cli_opt){ "tun",          CLI_OPT_STR, &o.tun,
                         "<TUN>", NULL };
    opts[9] = (cli_opt){ "proxy-cidr",  CLI_OPT_CSV, &o.proxy_cidr,
                         "<PROXY_CIDR>", NULL };
    opts[10] = (cli_opt){ "proxy-ip",    CLI_OPT_CSV, &o.proxy_ip,
                          "<PROXY_IP>", NULL };
    opts[11] = (cli_opt){ "proxy-domain", CLI_OPT_CSV, &o.proxy_domain,
                          "<PROXY_DOMAIN>", NULL };
    opts[12] = (cli_opt){ "proxy-cidr6", CLI_OPT_CSV, &o.proxy_cidr6,
                          "<PROXY_CIDR6>", NULL };
    opts[13] = (cli_opt){ "listen",      CLI_OPT_STR, &o.listen_str,
                          "<LISTEN>", valid_listen };
    opts[14] = (cli_opt){ "socks-token", CLI_OPT_STR, &o.socks_token,
                          "<TOKEN>", validate_token_len };
    opts[15] = (cli_opt){ "socks-no-token", CLI_OPT_BOOL, &o.socks_no_token,
                          NULL, NULL };
    opts[16] = (cli_opt){ "allow-remote", CLI_OPT_BOOL, &o.allow_remote,
                          NULL, NULL };
    opts[17] = (cli_opt){ "data-plane",  CLI_OPT_STR, &o.data_plane,
                          "<auto|tun|kernel>", validate_data_plane };
    opts[20] = (cli_opt){ "reply-via-tunnel", CLI_OPT_BOOL, &o.reply_via_tunnel,
                          NULL, NULL };
    opts[18] = (cli_opt){ "bind-dev",    CLI_OPT_STR, &o.bind_dev,
                          "<NIC>", NULL };
    opts[19] = (cli_opt){ "bind-ip",     CLI_OPT_STR, &o.bind_ip,
                          "<IP>", NULL };
    parse_cmd(argc, argv, start, "proxy", opts, sizeof opts / sizeof opts[0]);

    /* Data-plane selection (--data-plane auto = default):
     *   - auto => kernel plane on Linux, TUN elsewhere, and allows "fall back to
     *     TUN if the kernel plane fails to start" (exit only if both fail);
     *   - bind NIC / bind egress IP are kernel-plane-only (the TUN path has no
     *     equivalent binding) => auto picks the kernel plane and **disables
     *     fallback**: fallback cannot satisfy the binding anyway, so report an
     *     explicit error instead;
     *   - --listen/--socks-* are TUN-plane userspace proxy features, mutually
     *     exclusive with the kernel plane => auto picks TUN (the mutual-exclusion
     *     check below therefore applies only to an explicit --data-plane kernel).
     * Explicit tun/kernel never falls back (see the contract in cli_common.h). */
    bool plane_auto = false;
    const char *plane = data_plane_resolve(o.data_plane, &plane_auto);
    /* Inner IPv4/IPv6 are supported on both planes (since slice 1 the kernel
     * module also decapsulates inner v6), so --proxy-cidr6 no longer affects
     * plane selection:
     *   - kernel plane: the module version-checks inner headers; v6 in v4 is
     *     re-injected via netif_rx;
     *   - TUN plane: the userspace pump already passes inner packets through
     *     as payload.
     * The two planes' **policies** differ (deliberately; see
     * docs/kernel-data-plane.md): the TUN plane filters admission by session
     * inner IP and derived ULA, the kernel plane only checks header sanity
     * (policy in the kernel would need an inner-address ABI item). The only
     * gate is the inner MTU: IPv6 requires a link MTU >= 1280 (RFC 8200
     * Section 5), below which v6 cannot work - checked after the effective
     * MTU is known, see the want_v6 warning below. */
    const bool want_v6 = o.proxy_cidr6.n > 0;
    const bool need_bind = (o.bind_dev != NULL || o.bind_ip != NULL);
    if (plane_auto && need_bind) {
        plane = IWAN_DATA_PLANE_KERNEL;
        plane_auto = false;
        log_info("data plane: --bind-dev/--bind-ip are kernel-plane-only, "
                 "selecting --data-plane kernel (no automatic fallback)");
    }
    if (plane_auto && (o.listen_str || o.socks_token || o.socks_no_token ||
                       o.allow_remote)) {
        plane = IWAN_DATA_PLANE_TUN;
        plane_auto = false;
        log_info("data plane: --listen/--socks-* are TUN-plane userspace proxy features, "
                 "selecting --data-plane tun");
    }
    bool kernel_plane = data_plane_is_kernel(plane);
    if (plane_auto)
        log_info("data plane: default %s (falls back to TUN when the kernel plane is unavailable)", plane);
    if (!o.server)
        err_required("proxy");
    resolve_credentials(&o, "proxy");
    char eb[64];
    if (!check_server_ip(o.server, eb, sizeof eb))
        die_invalid_address("invalid server address");
    if (o.socks_token && o.socks_no_token) {
        fprintf(stderr,
                "error: --socks-token and --socks-no-token are "
                "mutually exclusive");
        err_usage_exit(usage_required("proxy"));
    }
    /* H-1 (R14): judge the token's CONTENT, not just the pointer - an
     * empty string is "no token" too and must never open a remote proxy
     * without --socks-no-token. Defence-in-depth: even if
     * validate_token_len misses an empty value or the option is set by a
     * direct/config path, empty != a configured password. --socks-no-token
     * (explicit open) and its mutual-exclusion check above are unchanged. */
    if (o.allow_remote && (!o.socks_token || !*o.socks_token) &&
        !o.socks_no_token && o.listen_str)
        err_remote_token("proxy");

    /* --data-plane kernel is mutually exclusive with --listen/--socks*: --listen
     * starts a userspace SOCKS5+HTTP proxy (lwIP terminates TCP and builds
     * inner packets itself), while the kernel data-plane hook would compete
     * for/consume packets on the same outer socket - a bad configuration, so
     * reject it as a usage error instead of leaving it half-working. */
    if (kernel_plane &&
        (o.listen_str || o.socks_token || o.socks_no_token ||
         o.allow_remote)) {
        fprintf(stderr,
                "error: --data-plane kernel is mutually exclusive with --listen/"
                "--socks-token/--socks-no-token/--allow-remote\n"
                "  reason: the userspace SOCKS proxy and the kernel data plane "
                "would compete for packets on the same outer socket;\n"
                "  the kernel data plane uses the kernel stack and needs no userspace proxy");
        err_usage_exit(usage_required("proxy"));
    }
#if !defined(__linux__) && !defined(_WIN32)
    /* Other platforms (macOS etc.): validate_data_plane already rejected
     * kernel as an invalid value, this is only a safety net. Windows has the
     * WFP callout driver iwan.sys, equivalent to Linux's kernel module, so it
     * is not covered here - kdp_win_run handles it. */
    if (kernel_plane) {
        fprintf(stderr,
                "error: --data-plane kernel is only available on Linux and Windows "
                "(this platform has no kernel data plane)");
        err_usage_exit(usage_required("proxy"));
    }
#endif
    if (kernel_plane && strcmp(o.tun, "iwan0") != 0)
        log_err("--data-plane kernel always uses iwan0 (the kernel module owns the device name), "
                "ignoring --tun %s", o.tun);

#ifdef __linux__
    /* Three carrier binding modes (none / bind NIC / bind egress IP): only
     * startup validation and parsing here; values go to the kernel via kdp_run
     * (SESSION_UP's OIF/IP attributes). The TUN path's outer socket is the
     * app's own UDP socket and binding a NIC needs SO_BINDTODEVICE, which is
     * not implemented - report an error instead of silently ignoring it. */
    kdp_bind kbind;
    memset(&kbind, 0, sizeof(kbind));
    kbind.reply_via_tunnel = o.reply_via_tunnel;
    if (o.reply_via_tunnel && !kernel_plane) {
        fprintf(stderr,
                "error: --reply-via-tunnel is currently wired only on the kernel data plane"
                "\n  reason: the two data planes differ in ingress-interface semantics -"
                " after decapsulation the kernel plane's skb->dev is still the carrier NIC"
                " (replies leave via iwan0), while TUN-plane inner packets are re-injected"
                " by iwan0; the TUN plane is not wired yet, not silently ignored\n");
        err_usage_exit(usage_required("proxy"));
    }
    if ((o.bind_dev || o.bind_ip) && !kernel_plane) {
        fprintf(stderr,
                "error: --bind-dev/--bind-ip are valid only with --data-plane kernel"
                "\n  reason: binding is done by the kernel module in SESSION_UP (a session uses"
                " one downstream NIC); the TUN path's outer socket is held by userspace, and an"
                " equivalent binding is not implemented\n");
        err_usage_exit(usage_required("proxy"));
    }
    if (o.bind_dev) {
        kbind.oif = if_nametoindex(o.bind_dev);
        kbind.dev = o.bind_dev;
        if (kbind.oif == 0) {
            fprintf(stderr, "error: --bind-dev %s: no such NIC\n",
                    o.bind_dev);
            cleanse_str(o.pass);
            cleanse_str(o.ct_pass);
            free_route_opts(&o);
            return 1;
        }
    }
    if (o.bind_ip) {
        /* Family from the literal: v4 dotted -> bind the v4 egress IP; v6 ->
         * bind the v6 egress IP (the outer version comes from the session
         * socket's family; the kernel requires "bound IP == outer source
         * address", so a wrong family is rejected with -EINVAL after the
         * handshake - parsing either family is enough here; exact consistency
         * is left to kdp_socket_params). */
        struct in_addr a4;
        struct in6_addr a6;

        if (inet_pton(AF_INET, o.bind_ip, &a4) == 1) {
            o.bind_ip_family = AF_INET;
            o.bind_ip_host = ntohl(a4.s_addr);
            kbind.bind_ip = o.bind_ip_host;
        } else if (inet_pton(AF_INET6, o.bind_ip, &a6) == 1) {
            o.bind_ip_family = AF_INET6;
            o.bind_ip6 = a6;
            kbind.bind_v6 = true;
            kbind.bind_ip6 = a6;
        } else {
            fprintf(stderr,
                    "error: --bind-ip %s: not an IPv4 dotted address or an IPv6 "
                    "literal\n  (link-local addresses are unsupported: the kernel "
                    "outer v6 attribute carries no scope_id)\n",
                    o.bind_ip);
            err_usage_exit(usage_required("proxy"));
        }
    }
    if (kbind.oif != 0 || kbind.bind_ip != 0 || kbind.bind_v6) {
        char why[256];

        /* Validate at startup: the NIC exists, is UP and has carrier; the egress
         * IP belongs to a local interface, and must be the same one as --bind-dev
         * (if given together). Addresses and link state are always read live
         * (getifaddrs), never cached. */
        if (!kdp_bind_ok(&kbind, why, sizeof(why))) {
            fprintf(stderr, "error: bind unavailable: %s\n", why);
            cleanse_str(o.pass);
            cleanse_str(o.ct_pass);
            free_route_opts(&o);
            return 1;
        }
        char bdesc[128] = "";

        if (kbind.bind_ip != 0 || kbind.bind_v6)
            snprintf(bdesc, sizeof(bdesc), "egress IP %s", o.bind_ip);
        if (kbind.oif != 0) {
            size_t n = strlen(bdesc);

            snprintf(bdesc + n, sizeof(bdesc) - n, "%sbind NIC %s(ifindex=%u)",
                     n != 0 ? " + " : "", o.bind_dev,
                     (unsigned)kbind.oif);
        }
        log_info("kernel data plane: bind mode=%s (one session uses one downstream NIC)", bdesc);
    }
#else
    /* The non-Linux kernel plane (Windows kdp_win_run) does not wire these
     * three switches yet: SESSION_OPEN reserves oif_index/bind_ip/bind_ip6 and
     * the BIND_* flags, but the client fills none of them, and the kernel plane
     * picks the egress by route. Reject explicitly, never silently ignore
     * (same rule as the Linux TUN path). */
    if (o.bind_dev || o.bind_ip) {
        fprintf(stderr,
                "error: --bind-dev/--bind-ip are available only on the Linux kernel plane"
                "\n  reason: this platform's kernel plane does not wire binding attributes yet"
                " (Windows SESSION_OPEN leaves oif_index/bind_ip unset), and the TUN path has"
                " no equivalent binding\n");
        err_usage_exit(usage_required("proxy"));
    }
    if (o.reply_via_tunnel) {
        fprintf(stderr,
                "error: --reply-via-tunnel is available only on the Linux kernel plane"
                "\n  reason: reply-through-tunnel on this platform's kernel plane is not wired yet\n");
        err_usage_exit(usage_required("proxy"));
    }
#endif /* __linux__ */

#ifdef _WIN32
    /* TUN mode requires an administrator (wintun driver + routing):
     * relaunch via a UAC prompt instead of failing. Must happen before
     * any network/session work - the elevated instance re-runs the
     * whole command. */
    if (!port_is_admin()) {
        if (port_elevate_self(argc, argv) == 0) {
            log_info("TUN mode needs administrator; relaunching elevated...");
            cleanse_str(o.pass);
            cleanse_str(o.ct_pass);
            return 0;
        }
        log_err("Error: TUN mode requires administrator privileges "
                "(elevation declined)");
        cleanse_str(o.pass);
        cleanse_str(o.ct_pass);
        return 1;
    }
#endif

    slist_t routes;
    slist_init(&routes);
    collect_routes(&routes, &o.proxy_cidr, &o.proxy_ip,
                   &o.proxy_domain);

    if (!tun_name_valid(o.tun)) {
        log_err("Error: invalid TUN device name '%s'", o.tun);
        slist_free(&routes);
        free_route_opts(&o);
        cleanse_str(o.pass);
        cleanse_str(o.ct_pass);
        return 1;
    }

    /* All argument/usage checks of this subcommand are done (parse_cmd
     * validators, --server/--pass requirements, --socks-token checks and
     * tun_name_valid above). Everything from here on is real work, and the
     * first libcrypto call on this path is wintun_ensure() -> sha256()
     * (_WIN32) or authenticate() -> md5() (Linux). */
    crypto_init_or_die();

    /* No pre-delete here: the TUN devices we create are non-persistent
     * (open_tun never sets TUNSETPERSIST), so the kernel removes them
     * when the owning fd closes - at shutdown and on any crash. If the
     * name is already taken (any interface type), TUNSETIFF fails with
     * EBUSY/EEXIST below and we report the error instead of touching a
     * device we do not own. */

#ifdef _WIN32
    /* wintun.dll missing? ask (interactive) and auto-download the latest
     * wintun build before open_tun so the first run just works.
     * The kernel plane creates no TUN device (the driver and kdp path own the
     * device and addresses), so it does not need wintun.dll: previously this
     * demanded it unconditionally, and the result was "data plane fully handled
     * by the driver, yet it cannot start for lack of a userspace DLL". */
    if (!kernel_plane && wintun_ensure() != 0) {
        slist_free(&routes);
        free_route_opts(&o);
        cleanse_str(o.pass);
        cleanse_str(o.ct_pass);
        return 1;
    }
#endif

    /* No TUN under --data-plane kernel: the device (fixed iwan0) is created,
     * brought UP and MTU-set on demand by the kernel module at SESSION_UP;
     * addresses and routes still come from userspace per the DEVNAME in the
     * reply (done inside kdp_run, same code as route_setup). tun_fd stays -1,
     * and every use below checks >= 0.
     *
     * When the default auto selects the kernel plane, **no device is opened**
     * here: the device is opened on demand (proxy_tun_prepare at the fallback
     * point if the kernel plane fails), since opening it early makes
     * SESSION_UP -EBUSY. */
    int tun_fd = -1;
    struct RelayProxy *rp = NULL;
    if (!kernel_plane) {
        tun_fd = proxy_tun_prepare(&o, &rp);
        if (tun_fd < 0) {
            slist_free(&routes);
            free_route_opts(&o);
            cleanse_str(o.pass);
            cleanse_str(o.ct_pass);
            return 1;
        }
    }

    /* keep the plaintext pass until the session ends: reconnects need
     * it to re-derive the session key (server re-OPEN keeps the IP) */
    int rc = 0;
    bool reconnecting = false;
    /* kdp_run startup-failure classification: true = this netns already has
     * a kernel session/device taken; such a failure does **not** fall back
     * to TUN (fallback would evict that session with the same account). */
    bool kdp_busy = false;
    for (;;) {
        AuthResult res;

#ifdef __linux__
        /* Do not handshake while the binding is down: the kernel part has been
         * disabled (kdp_run's 1s tick tears it down on failure), the route via
         * iwan0 also dies with the device, and inner traffic falls to the next
         * routing-table entry. Wait for the bound NIC/egress IP to return, then
         * re-handshake and reopen the data plane - same semantics as "re-handshake
         * when the bound IP returns". The Windows kernel plane does no binding, so
         * there is no "wait for binding" state. */
        if (reconnecting)
            kdp_bind_wait(&kbind);
#endif

        /* Kernel-plane precheck before the handshake (only before the first
         * handshake): whether the local kernel plane is available and whether
         * this netns already has a live session. Placed here to **not handshake
         * with the server first** - otherwise a "no local module" failure would
         * waste a server-side session, and worse, when "this netns already has a
         * live session" it would evict that session (the server treats a second
         * OPEN from the same source IP as a legitimate reconnect). Must not run
         * on reconnect: this process's own session may still be alive. */
        if (!reconnecting && kernel_plane) {
            char perr[512];
            bool busy = false;

#if defined(_WIN32)
            if (!kdp_win_plane_precheck(win_device_path(plane),
                                        perr, sizeof(perr), &busy)) {
#elif defined(__linux__)
            if (!kdp_plane_precheck(perr, sizeof(perr), &busy)) {
#else
            /* Other platforms have no kernel data plane (cli_common's
             * validate_data_plane already rejects --data-plane kernel, and auto
             * never lands on it); this section only keeps all three platforms
             * compiling. */
            (void)busy;
            snprintf(perr, sizeof perr, "this platform has no kernel data plane");
            if (true) {
#endif
                log_err("kernel data plane: %s", perr);
                if (plane_auto && !busy) {
                    log_err("kernel data plane unavailable on this host, falling back to the TUN data plane");
                    plane_auto = false;   /* fall back only once */
                    kernel_plane = false;
                    tun_fd = proxy_tun_prepare(&o, &rp);
                    if (tun_fd < 0) {
                        log_err("TUN data plane also unavailable, exiting "
                                "(kernel-plane reason above)");
                        rc = -1;
                        break;
                    }
                    continue;   /* run another round: TUN plane this time */
                }
                /* busy: this netns already has a live session/device taken.
                 * The only way out is to stop the owner first - falling back
                 * to TUN is not a way out: the server treats a second OPEN from
                 * the same source IP as a legitimate reconnect, so the TUN
                 * plane would evict that live session (kick the other user
                 * offline with the same account). */
                if (busy)
                    log_err("kernel data plane: this netns already has a kernel session/device taken, "
                            "not falling back to TUN (fallback would evict that session with the same account); "
                            "stop it first and retry");
                else if (!plane_auto)
                    log_err("kernel data plane: this run does not accept automatic fallback "
                            "(explicit --data-plane, or a kernel-plane-only binding), exiting now");
                rc = -1;
                break;
            }
        }
        int sockfd = authenticate(&o, DO_AUTH_PUMP, &res);
        if (sockfd < 0) {
            if (!reconnecting) {
                log_err("Error: auth failed");
                rc = 1;
                break;
            }
            /* a reconnect hit the same loss window that killed the
             * session: the OPEN is just as likely to be eaten, so
             * retry with a backoff instead of dying */
            log_err("auth failed during reconnect; retrying in 3s...");
            port_sleep_ms(3000);
            if (g_user_stop) {
                rc = 1;
                break;
            }
            continue;
        }

        check_gw_server(o.server, res.gw);   /* F8 */
        {
            /* L17: pre-validate what route_setup turns into kernel
             * configuration; a malformed response dies with a clear
             * error instead of a baffling netsh failure */
            uint8_t b4[4];
            if (res.unissued) {
                log_err("Error: server did not issue an inner address (minimal ACK); "
                        "TUN/route mode requires an address, use socks mode instead");
                port_close(sockfd);
                rc = 1;
                break;
            }
            if (!s2ip4(res.tun, b4) || !s2ip4(res.gw, b4)) {
                log_err("Error: server returned invalid tunnel/gateway "
                        "IPv4 address");
                port_close(sockfd);
                rc = 1;
                break;
            }
        }
        /* Inner IPv6 needs a link MTU >= 1280 (RFC 8200 Section 5): IPv6
         * routers do not fragment, so below 1280 v6 cannot work (it shows up
         * as "routes installed but no connectivity", the silent blackhole to
         * avoid). The effective MTU is known only now (the server may lower
         * it), so the check is here, shared by both data planes. */
        if (want_v6 && res.mtu < 1280)
            log_err("warning: --proxy-cidr6 (inner IPv6) requires an inner MTU >= 1280 "
                    "(RFC 8200 Section 5); effective MTU=%u this time: IPv6 packets will be "
                    "dropped by the peer or an intermediate device; raise --mtu or drop --proxy-cidr6",
                    (unsigned)res.mtu);

#ifdef _WIN32
        /* Windows sockets default to blocking; the pump paths expect a
         * nonblocking datagram socket. On Linux the pump sets this
         * itself. */
        if (port_set_nonblock(sockfd, true) != 0)
            log_err("Error: set nonblock: %s", strerror(errno));
#endif


        uint8_t sk[16];
        session_key(o.user, o.pass, sk);

        slist_t routes6;
        slist_init(&routes6);
        collect_routes6(&routes6, &o.proxy_cidr6);
#ifdef __linux__
        if (kernel_plane)
            /* Kernel data plane: the handshake (OPEN/OPEN_ACK/verification/key
             * derivation) already completed in authenticate() above - at that
             * moment there was no kernel session yet, the hook did not
             * intercept, so the app's own UDP socket received OPEN_ACK normally.
             * Only now is the data plane handed to the kernel: data frames,
             * keepalive receive and disconnect receive belong to the module;
             * keepalive send and liveness decisions stay in userspace (kdp_run).
             * The return value means the same as run_pump, and the reconnect
             * loop below is unchanged. */
            rc = kdp_run(sockfd, sk, res.sid, res.tok, res.enc, o.server,
                         &routes, &routes6, res.tun, res.mtu, &kbind,
                         &kdp_busy);
        else
#elif defined(_WIN32)
        if (kernel_plane)
            rc = kdp_win_run(sockfd, sk, res.sid, res.tok,
                             res.enc, o.server, win_inner_dev(plane),
                             win_device_path(plane), &routes,
                             &routes6, res.tun, res.mtu,
                             &kdp_busy);
        else
#endif
            rc = run_pump(tun_fd, o.tun, sockfd, sk, res.sid, res.tok,
                          res.enc, o.server, &routes, &routes6,
                          res.tun, res.mtu);
        slist_free(&routes6);
        wipe(sk, sizeof sk);
        port_close(sockfd);
        /* user stopped it (Ctrl-C): run_pump returns 0 when the exit
         * was not a detected session loss; a lost session (rc == 1)
         * reconnects (run_pump resets g_stop on entry). rc < 0 is a
         * deterministic setup failure (route_setup already rolled back):
         * retrying cannot help and would churn server sessions. */
        if (rc == 0)
            break;
        if (rc < 0) {
            /* Kernel plane failed to start and it was the default choice => retry
             * with TUN ("fail again, then exit"). Exception at kdp_busy: this netns
             * already has a kernel session/device taken, and falling back would
             * evict that session with the same account (the server treats a second
             * OPEN from the same source IP as a legitimate reconnect), worse than
             * failing outright. */
            if (kernel_plane && plane_auto && !kdp_busy) {
                log_err("kernel data plane failed to start, falling back to the TUN data plane");
                plane_auto = false;   /* fall back only once */
                kernel_plane = false;
                if (tun_fd < 0)
                    tun_fd = proxy_tun_prepare(&o, &rp);
                if (tun_fd < 0) {
                    log_err("TUN data plane also unavailable, exiting (kernel-plane reason above)");
                    break;
                }
                continue;
            }
            if (kernel_plane && kdp_busy)
                log_err("this netns already has a kernel session/device taken, not falling back to TUN "
                        "(fallback would evict that session); stop it first and retry");
            log_err("tunnel setup failed; giving up");
            break;
        }
        reconnecting = true;
        log_err("tunnel session lost; reconnecting in 1s...");
        port_sleep_ms(1000);
        if (g_user_stop)
            break;   /* Ctrl-C during the reconnect wait */
    }
    cleanse_str(o.pass);
    cleanse_str(o.ct_pass);
    relay_proxy_stop(rp);
    if (tun_fd >= 0)
        tun_close(tun_fd);   /* --data-plane kernel: no TUN fd */
    log_info("done.");

    slist_free(&routes);
    free_route_opts(&o);
    return rc == 0 ? 0 : 1;
}

/* (R4-01-2: in-place tunnel re-auth was removed from cmd_socks - the
 * reconnect loop owns session recovery now, so the old re-auth callback
 * was deleted; see git history. Nothing else used it.) */

static int cmd_socks(int argc, char **argv, int start)
{
    CmdOpts o;
    memset(&o, 0, sizeof o);
    o.port = 6001;
    o.user = "_rev_m_1";
    o.mtu = 1380;
    o.listen_str = "127.0.0.1:1080";
    cli_opt opts[13];

    add_auth_opts(opts, &o);
    opts[8] = (cli_opt){ "listen",       CLI_OPT_STR, &o.listen_str,
                         "<LISTEN>",  valid_listen };
    opts[9] = (cli_opt){ "socks-token", CLI_OPT_STR, &o.socks_token,
                          "<TOKEN>", validate_token_len };
    opts[10] = (cli_opt){ "socks-no-token", CLI_OPT_BOOL, &o.socks_no_token,
                          NULL, NULL };
    opts[11] = (cli_opt){ "allow-remote", CLI_OPT_BOOL, &o.allow_remote,
                          NULL, NULL };
    opts[12] = (cli_opt){ "socks-ipv6", CLI_OPT_BOOL, &o.socks_ipv6,
                          NULL, NULL };
    parse_cmd(argc, argv, start, "socks", opts, sizeof opts / sizeof opts[0]);
    if (!o.server)
        err_required("socks");
    resolve_credentials(&o, "socks");
    char eb[64];
    if (!check_server_ip(o.server, eb, sizeof eb))
        die_invalid_address("invalid server address");
    if (o.socks_token && o.socks_no_token) {
        fprintf(stderr,
                "error: --socks-token and --socks-no-token are "
                "mutually exclusive");
        err_usage_exit(usage_required("socks"));
    }
    /* H-1 (R14): same as the proxy command - judge the token's CONTENT.
     * `--socks-token ""` is "no token", so an empty value must never
     * unlock a remote bind without --socks-no-token. */
    if (o.allow_remote && (!o.socks_token || !*o.socks_token) &&
        !o.socks_no_token)
        err_remote_token("socks");
    /* last usage check passed; next stop is authenticate() -> md5() */
    crypto_init_or_die();

    /* keep the plaintext pass until the session ends: reconnects need
     * it to re-derive the session key (server re-OPEN keeps the IP) */
    bool reconnecting = false;
    /* M-3 (R14): distinguish "at least one session actually ran" from
     * "every attempt failed at startup". A startup-only failure must
     * exit non-zero instead of masquerading as a clean user-stopped run
     * (Ctrl-C during the retry loop used to end with return 0 even when
     * run_socks never succeeded once). */
    bool ran_session = false;
    bool saw_startup_fail = false;
#ifndef _WIN32
    /* R36-L01: hold the stop handler across the WHOLE reconnect loop,
     * not just inside run_socks. run_socks installs on_sig when it
     * enters and restores the PREVIOUS disposition when it leaves; with
     * no loop-level install, that "previous disposition" during the
     * between-attempt wait window was the DEFAULT, so a Ctrl-C in the
     * port_sleep_ms(1000) window took the default action - abrupt rc=130
     * death in the foreground, or a silently swallowed signal (a
     * background job inherits SIG_IGN) that left the startup-fail retry
     * loop running forever - and the g_user_stop check right after the
     * sleep could never fire. With the loop-level handler, run_socks's
     * save/restore now preserves on_sig, the wait-window Ctrl-C lands in
     * g_user_stop, and the loop breaks cleanly when the sleep returns.
     * Restored after the loop so nothing persists for a later run_socks
     * call (the early `return 1` paths below exit the process right
     * away, so their handler state is unobservable). Windows: run_socks
     * uses the process-lifetime port_set_stop_handler there, so the wait
     * window was never unprotected on Windows - nothing to add. */
    struct sigaction sa_stop, old_stop_int, old_stop_term;
    memset(&sa_stop, 0, sizeof sa_stop);
    sa_stop.sa_handler = on_sig;
    sigaction(SIGINT, &sa_stop, &old_stop_int);
    sigaction(SIGTERM, &sa_stop, &old_stop_term);
#endif
    for (;;) {
        AuthResult res;
        int sockfd = authenticate(&o, DO_AUTH_PUMP, &res);
        if (sockfd < 0) {
            if (!reconnecting) {
                log_err("Error: auth failed");
                cleanse_str(o.pass);
                cleanse_str(o.ct_pass);
                return 1;
            }
            /* a reconnect hit the same loss window that killed the
             * session: the OPEN is just as likely to be eaten, so
             * retry with a backoff instead of dying */
            log_err("auth failed during reconnect; retrying in 3s...");
            port_sleep_ms(3000);
            if (g_user_stop) {
                cleanse_str(o.pass);
                cleanse_str(o.ct_pass);
                return 1;
            }
            continue;
        }
#ifdef _WIN32
        /* Windows sockets default to blocking; run_socks expects a
         * nonblocking datagram socket. On Linux run_socks sets this
         * itself. */
        if (port_set_nonblock(sockfd, true) != 0)
            log_err("Error: set nonblock: %s", strerror(errno));
#endif

        uint8_t sk[16];
        session_key(o.user, o.pass, sk);

        uint32_t inner_ip, gateway;
        int sar = auth_result_addrs(&res, &inner_ip, &gateway);
        if (sar == 0)
            log_err("Error: server returned invalid tunnel IPv4 address");
        else if (sar < 0)
            log_err("Error: server returned invalid gateway IPv4 address");
        if (sar != 1) {
            wipe(sk, sizeof sk);
            port_close(sockfd);
            cleanse_str(o.pass);
            cleanse_str(o.ct_pass);
            return 1;
        }
        if (res.unissued) {
            log_err("WARNING: server did not issue an address (minimal ACK): the inner address is locally derived, "
                     "available in socks mode only");
        }
        check_gw_server(o.server, res.gw);   /* F8 */

        /* valid_listen already validated the syntax at parse time; this
         * parse only fills the sockaddr for run_socks */
        struct sockaddr_in listen;
        parse_host_port(o.listen_str, &listen);

        SocksConfig cfg;
        memset(&cfg, 0, sizeof cfg);
        cfg.listen_addr = listen;
        cfg.listen_str = o.listen_str;
        socks_cfg_from_auth(&cfg, &res, inner_ip, gateway, sk,
                            (int)(res.mtu < o.mtu ? res.mtu : o.mtu));
        wipe(sk, sizeof sk);
        cfg.auth_token = o.socks_token;
        cfg.open_proxy = o.socks_no_token;
        cfg.allow_remote = o.allow_remote;
        cfg.ipv6 = o.socks_ipv6;
        /* H-1 contract: run_socks now OWNS sockfd from entry and closes
         * it in its teardown on every return path, so the caller must NOT
         * port_close(sockfd) after run_socks returns - closing again
         * would be a double close (and, if the number was meanwhile
         * reused, would clobber an unrelated descriptor). This path has
         * no in-place re-auth callback (socks_reauth_tunnel bails on
         * !cfg->reauth), so run_socks never even swaps the fd, but the
         * ownership rule still applies uniformly. Session recovery is
         * owned by this outer reconnect loop (the same way cmd_proxy does
         * it): on session loss run_socks closes the socket, returns 1,
         * and we re-run authenticate() (which allocates a fresh sockfd)
         * + run_socks() above. */
        int rc = run_socks(sockfd, &cfg);
        /* run_socks tri-state contract (R13-FIND M-1, adapted with the
         * -1 semantics landed by parallel agent A):
         *   0  user stopped it  -> clean break, no retry
         *   1  session lost     -> reconnect (re-auth runs via the
         *                          caller's loop) with the message below
         *  -1  startup failed   -> e.g. SOCKS5 listener bind failed / port
         *                          in use; NOT a lost tunnel, so it gets
         *                          its own diagnostic below. It still goes
         *                          through the same 1s retry loop (bounded
         *                          by g_user_stop), matching the task's
         *                          "keep current retry behaviour, only add
         *                          the distinguishing log". */
        /* M-3: rc>0 (session lost) and rc==0 (user stopped a live
         * tunnel) both prove a session really ran at least once.
         * rc<0 is a startup failure only and records the opposite. */
        if (rc > 0)
            ran_session = true;
        if (rc == 0) {
            ran_session = true;   /* user stopped an actually-running tunnel */
            break;                /* user stopped it */
        }
        if (rc < 0) {
            saw_startup_fail = true;
            log_err("SOCKS startup failed (rc=%d); will retry in 1s...", rc);
        }
        reconnecting = true;
        if (rc > 0)
            log_err("tunnel session lost; reconnecting in 1s...");
        port_sleep_ms(1000);
        if (g_user_stop)
            break;   /* Ctrl-C during the reconnect wait */
    }
#ifndef _WIN32
    /* R36-L01: loop-level handler no longer needed; restore the
     * dispositions that were active when cmd_socks was entered. */
    sigaction(SIGINT, &old_stop_int, NULL);
    sigaction(SIGTERM, &old_stop_term, NULL);
#endif
    cleanse_str(o.pass);
    cleanse_str(o.ct_pass);
    /* M-3: if every single attempt died at startup and no session ever
     * ran, a non-zero exit is the honest signal (a Ctrl-C'd retry loop
     * must not look like a success). Otherwise keep the existing
     * semantics: user-stopped (rc==0) or reconnect path returns 0. */
    if (saw_startup_fail && !ran_session)
        return 1;
    return 0;
}

int main(int argc, char **argv)
{
#ifdef _WIN32
    port_install_crash_handler();
#endif
    port_socket_init();   /* WSAStartup on Windows; no-op on Linux */
    util_ignore_sigpipe();
    prof_init();          /* IWAN_PROFILE=1: stage throughput prints */
    if (argc < 2) {
        /* clap arg_required_else_help: help on stderr, exit 2 */
        print_top_help(stderr);
        return 2;
    }
    const char *sub = argv[1];
    if (strcmp(sub, "-h") == 0 || strcmp(sub, "--help") == 0) {
        print_top_help(stdout);
        return 0;
    }
    if (strcmp(sub, "-V") == 0 || strcmp(sub, "--version") == 0) {
        printf("iwan-client %s\n", VERSION);
        return 0;
    }
    if (strcmp(sub, "help") == 0) {
        if (argc == 2) {
            print_top_help(stdout);
            return 0;
        }
        if (argc > 3) {
            fprintf(stderr, "error: unrecognized subcommand '%s'", argv[3]);
            err_usage_exit(usage_full(argv[2]));
        }
        const char *t = argv[2];
        if (strcmp(t, "ping") == 0 || strcmp(t, "auth") == 0 ||
            strcmp(t, "proxy") == 0 || strcmp(t, "socks") == 0) {
            print_sub_help(t);
            return 0;
        }
        if (strcmp(t, "help") == 0) {
            print_help_help();
            return 0;
        }
        fprintf(stderr, "error: unrecognized subcommand '%s'", t);
        err_usage_exit(usage_full(NULL));
    }
    if (sub[0] == '-') {
        fprintf(stderr, "error: unexpected argument '%s' found", sub);
        err_usage_exit(usage_full(NULL));
    }

    /* R39: reject an unknown subcommand BEFORE touching libcrypto. The final
     * `else` of the dispatch below is the historical place for this error, but
     * it sits after crypto_init(), so a plain usage error would depend on
     * libcrypto's allocation succeeding (visible OOM fatal instead of the rc=2
     * usage error); on e07fe75 this path allocated nothing at all. The
     * dispatch's own else is kept as an unreachable safety net. */
    if (strcmp(sub, "ping") != 0 && strcmp(sub, "auth") != 0 &&
        strcmp(sub, "proxy") != 0 && strcmp(sub, "socks") != 0) {
        fprintf(stderr, "error: unrecognized subcommand '%s'", sub);
        err_usage_exit(usage_full(NULL));
    }

    /* R10 (F1-8): libcrypto is NO LONGER initialised here. R39 put the
     * crypto_init() call at this point, i.e. before the dispatch, which
     * covers the unrecognised-subcommand error above but not the usage
     * errors *inside* an already recognised subcommand: "iwan-client ping"
     * without --server initialised libcrypto and then exited rc=2, so one
     * failed internal allocation reported "out of memory" instead (and the
     * un-wrapped negative control hung). Each cmd_* now calls
     * crypto_init_or_die() itself, immediately after its last argument
     * check and immediately before its first libcrypto call; the checks
     * above (argc, --help/-V/help, dash-argument, unknown subcommand) stay
     * libcrypto-free exactly as on e07fe75. */

    int rc = 0;
    if (strcmp(sub, "ping") == 0)
        rc = cmd_ping(argc, argv, 2);
    else if (strcmp(sub, "auth") == 0)
        rc = cmd_auth(argc, argv, 2);
    else if (strcmp(sub, "proxy") == 0)
        rc = cmd_proxy(argc, argv, 2);
    else if (strcmp(sub, "socks") == 0)
        rc = cmd_socks(argc, argv, 2);
    else {
        fprintf(stderr, "error: unrecognized subcommand '%s'", sub);
        err_usage_exit(usage_full(NULL));
    }
    return rc;
}
