#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <net/if.h>   /* if_nametoindex：--bind-dev 的名字 -> ifindex */
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
#include "kdp.h"      /* 内核数据面（Linux only）：与 kdp.c 同处条件编译 */
#endif
#if defined(_WIN32)
#include "kdp_win.h"   /* Windows 内核数据面（WFP 驱动）：与 kdp_win.c 同处条件编译 */
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
 * calls the renamed entry below; no other code changes — the service is
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
    /* "tun"（默认，TUN 用户态数据面）或 "kernel"（内核数据面，仅 Linux；
     * 见 cli_common.h 的 IWAN_DATA_PLANE_*） */
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
    /* 承载网卡绑定（仅 --data-plane kernel 有意义，见 kdp.h 的 kdp_bind）：
     *   --bind-dev <NIC>  绑网卡：严格用这张接口
     *   --bind-ip  <IP>   绑出口 IP：内核按地址表把它解析成所属接口，
     *                     该地址同时是外层 IP 头的源地址
     * 都不给 = 什么都不绑（内核按 FIB 解析一次后钉住）。 */
    const char *bind_dev;
    /* 回程路由（conntrack，仅内核面）：让"从隧道进来的连接"的回包按来路回去。
     * 见 docs/reply-routing.md。 */
    bool        reply_via_tunnel;
    const char *bind_ip;
    uint32_t    bind_ip_host;   /* --bind-ip 解析结果（v4，主机序） */
    /* --bind-ip 若按 v6 字面量解析成功，则族与地址在这里；与
     * bind_ip_host 互斥（同一个选项按字面量判族，不给族开关） */
    int         bind_ip_family; /* AF_UNSPEC = 未给/未解析 */
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
        "iWAN client — ping, authenticate, or run a SOCKS5 proxy\n"
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
            "      --data-plane <auto|tun|kernel>  auto = 默认：Linux 上先试内核模块 iwan，"
            "本机起不来自动回退 tun，两边都不行才退出；tun = 只用 TUN 用户态数据面；"
            "kernel = 只用内核数据面（仅 Linux）。显式指定 tun/kernel 不回退\n"
            "      --reply-via-tunnel              让\"从隧道进来的连接\"的回包按来路回去（仅 --data-plane "
            "kernel）：被服务地址集合来自 --proxy-cidr*/--proxy-ip/--proxy-domain，对端地址不需要预知；"
            "用 conntrack（CONNMARK）把入接口记在连接表项上，回包按 fwmark 选隧道专用路由表。"
            "模块钩子必须在 conntrack 之前解封（默认 hooknum=0/hookprio=-300，或 reinject=1），"
            "否则拒绝启动而不是静默不生效；见 docs/reply-routing.md\n"
            "      --bind-dev <NIC>               绑定的承载网卡（仅 --data-plane kernel）：一条会话只用这张"
            "下游网卡；不给 = 由 FIB 解析一次后钉住\n"
            "      --bind-ip <IP>                 绑定的出口 IP（仅 --data-plane kernel）：内核按本机地址表"
            "解析出持有该地址的网卡并钉住，该地址同时是外层 IP 头的源地址；"
            "v4 点分地址或 v6 字面量都行（族要与会话外层一致：外层族由 --server 的地址族决定）\n"
            "      --proxy-cidr <PROXY_CIDR>      \n"
            "      --proxy-ip <PROXY_IP>          \n"
            "      --proxy-domain <PROXY_DOMAIN>  \n"
            "      --proxy-cidr6 <PROXY_CIDR6>    内层 IPv6 路由：内核面与 TUN 面都支持\n"
            "                                      （模块按版本校验内层头）。内层 MTU 必须\n"
            "                                      ≥ 1280（RFC 8200 §5），否则警告\n"
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
     * is opened as the link itself, never followed, and rejected below —
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
    /* Rust std::time::Duration Debug format, e.g. 159.044µs / 1.5ms / 2s */
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
        suf = "µs";
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

    buf_t cl;
    buf_init(&cl);
    ctrl_hdr(&cl, PT_CLOSE, 1, res.sid, res.tok);
    (void)port_send(fd, cl.data, cl.len, 0);
    log_info("-> CLOSE");
    buf_free(&cl);
    port_close(fd);
    return 0;
}

/* Windows 上 --data-plane 选定的是哪个内核设备：kernel 走 WFP callout 驱动
 * （iwan.sys，设备 \\.\iwan），kernel-mp 走 NDIS 微型端口 + 协议驱动
 * （iwanmp.sys，设备 \\.\iwanmp）。返回 NULL 表示用默认设备。 */
#if defined(_WIN32)
static const wchar_t *win_device_path(const char *plane)
{
    return data_plane_is_kernel_mp(plane) ? IWAN_WIN_USER_PATH_MP : NULL;
}
#endif

/* TUN 面的资源准备：开设备（非阻塞）+ 可选的 SOCKS5/HTTP side-car（共享
 * TUN 路由的内核栈转发）。抽出来是因为 TUN 设备现在是**按需打开**的：
 * 默认的 auto 先试内核面，只有内核面起不来回退 TUN 时（或本来就选 TUN 时）
 * 才开设备。内核面下不能预先开着 iwan0 —— 那会让模块的 SESSION_UP 报
 * -EBUSY（设备被别人占了），内核面反而起不来。
 *
 * 成功返回 fd（>=0，rp 由 relay_proxy_start 填，失败时保持 NULL）；
 * 失败返回 -1，原因已经按 errno 分类打印（EBUSY = 名字被占是最常见的一种，
 * 旧文本统一说成 "must be root" 会把人带偏）。 */
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
        log_err("Error: open tun failed (see earlier log; wintun.dll must "
                "sit next to the executable and the wintun driver must be "
                "installed)");
#else
        if (e == EBUSY || e == EEXIST || e == EINVAL)
            log_err("Error: 打开 TUN 设备 %s 失败：内核拒绝了这个名字（%s）\n"
                    "  同一个 netns 里同一时刻只能有一个虚拟网卡客户端持有"
                    "这个设备名。占用者可能是另一个客户端（停掉它，Ctrl-C），"
                    "也可能是内核模块建的 %s（--data-plane kernel 的会话残留，"
                    "用 sudo iwan_ctl session-down 清掉）。\n"
                    "  先停掉占用者再重试；也可以用 --tun <别的名字>"
                    "（注意路由会互相覆盖）",
                    o->tun, strerror(e), o->tun);
        else if (e == EACCES || e == EPERM)
            log_err("Error: 打开 TUN 设备 %s 失败：权限不足（%s）—— TUN "
                    "数据面需要 root（或 CAP_NET_ADMIN）", o->tun,
                    strerror(e));
        else if (e != 0)
            log_err("Error: 打开 TUN 设备 %s 失败: %s", o->tun, strerror(e));
        else
            log_err("Error: 打开 TUN 设备 %s 失败", o->tun);
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
    o.data_plane = IWAN_DATA_PLANE_AUTO;   /* 默认：内核面，起不来则回退 TUN */
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

    /* 数据面选面（--data-plane auto = 默认）：
     *   · auto ⇒ Linux 选内核面、其余平台选 TUN，并允许"内核面起不来就回退
     *     TUN"（两边都起不来才退出）；
     *   · 绑网卡/绑出口 IP 只有内核面能实现（TUN 路径没有等价绑定）⇒ auto
     *     直接选内核面并**关掉回退**：回退过去也满足不了绑定，宁可明确报错；
     *   · --listen/--socks-* 是 TUN 面的用户态代理特性，与内核面互斥 ⇒ auto
     *     直接选 TUN（下面的互斥检查因此只对显式 --data-plane kernel 生效）。
     * 显式指定 tun/kernel 时不回退（见 cli_common.h 的契约）。 */
    bool plane_auto = false;
    const char *plane = data_plane_resolve(o.data_plane, &plane_auto);
    /* 内层 IPv4/IPv6 两个面都支持（切片 1 起内核模块同样解封内层 v6），
     * --proxy-cidr6 因此不再影响选面：
     *   · 内核面：模块按版本校验内层头，v6 in v4 走 netif_rx 重新入栈；
     *   · TUN 面：用户态泵本来就把内层分组当载荷透传。
     * 两个面的**策略**不同（这是刻意的，见 docs/kernel-data-plane.md）：
     * TUN 面按会话内层 IP 与派生 ULA 做准入过滤，内核面只做头部自洽
     * （策略要进内核得先给 ABI 加内层地址项）。唯一要拦的是内层 MTU：
     * IPv6 要求链路 MTU ≥ 1280（RFC 8200 §5），小于它 v6 必然不通 ——
     * 拿到生效 MTU 后检查，见下面的 want_v6 警告。 */
    const bool want_v6 = o.proxy_cidr6.n > 0;
    const bool need_bind = (o.bind_dev != NULL || o.bind_ip != NULL);
    if (plane_auto && need_bind) {
        plane = IWAN_DATA_PLANE_KERNEL;
        plane_auto = false;
        log_info("数据面: --bind-dev/--bind-ip 只有内核面能实现，"
                 "选定 --data-plane kernel（不自动回退）");
    }
    if (plane_auto && (o.listen_str || o.socks_token || o.socks_no_token ||
                       o.allow_remote)) {
        plane = IWAN_DATA_PLANE_TUN;
        plane_auto = false;
        log_info("数据面: --listen/--socks-* 是 TUN 面的用户态代理特性，"
                 "选定 --data-plane tun");
    }
    bool kernel_plane = data_plane_is_kernel(plane);
    if (plane_auto)
        log_info("数据面: 默认 %s（内核面不可用时自动回退 TUN）", plane);
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
    /* H-1 (R14): judge the token's CONTENT, not just the pointer — an
     * empty string is "no token" too and must never open a remote proxy
     * without --socks-no-token. Defence-in-depth: even if
     * validate_token_len misses an empty value or the option is set by a
     * direct/config path, empty != a configured password. --socks-no-token
     * (explicit open) and its mutual-exclusion check above are unchanged. */
    if (o.allow_remote && (!o.socks_token || !*o.socks_token) &&
        !o.socks_no_token && o.listen_str)
        err_remote_token("proxy");

    /* --data-plane kernel 与 --listen/--socks* 互斥：--listen 起的是用户态
     * SOCKS5+HTTP 代理（lwIP 终结 TCP，自己造内层包），而内核数据面的钩子
     * 会在同一个外层套接字上抢包/吞包 —— 两者组合是坏配置，按用法错误拒绝
     * 而不是让它半死不活。 */
    if (kernel_plane &&
        (o.listen_str || o.socks_token || o.socks_no_token ||
         o.allow_remote)) {
        fprintf(stderr,
                "error: --data-plane kernel 与 --listen/--socks-token/"
                "--socks-no-token/--allow-remote 互斥\n"
                "  原因: 用户态 SOCKS 代理与内核数据面会在同一条外层套接字上"
                "抢包；\n"
                "  内核数据面本身走内核栈，不需要用户态代理");
        err_usage_exit(usage_required("proxy"));
    }
#if !defined(__linux__) && !defined(_WIN32)
    /* 其余平台（macOS 等）validate_data_plane 已经按取值错误拒过 kernel，
     * 这里只是兜底。Windows 有 WFP callout 驱动 iwan.sys，与 Linux 的内核
     * 模块同义，不在兜底之列 —— 它由 kdp_win_run 接管。 */
    if (kernel_plane) {
        fprintf(stderr,
                "error: --data-plane kernel 只在 Linux 与 Windows 上可用"
                "（当前平台没有内核数据面）");
        err_usage_exit(usage_required("proxy"));
    }
#endif
    if (kernel_plane && strcmp(o.tun, "iwan0") != 0)
        log_err("--data-plane kernel 固定使用 iwan0（内核模块决定设备名），"
                "忽略 --tun %s", o.tun);

#ifdef __linux__
    /* 承载网卡绑定的三种模式（不绑 / 绑网卡 / 绑出口 IP）：这里只做启动
     * 校验与解析，值随 kdp_run 交给内核（SESSION_UP 的 OIF/IP 属性）。
     * TUN 路径的外层是应用自己的 UDP socket，绑网卡要靠 SO_BINDTODEVICE，
     * 目前没有实现 —— 直接报错，不静默忽略。 */
    kdp_bind kbind;
    memset(&kbind, 0, sizeof(kbind));
    kbind.reply_via_tunnel = o.reply_via_tunnel;
    if (o.reply_via_tunnel && !kernel_plane) {
        fprintf(stderr,
                "error: --reply-via-tunnel 目前只接在内核数据面上"
                "\n  原因: 两个数据面的入接口口径不同 —— 内核面解封后"
                "skb->dev 仍是承载网卡（回包从 iwan0 出去），TUN 面的内层包"
                "由 iwan0 重新入栈；TUN 面尚未接线，不静默忽略\n");
        err_usage_exit(usage_required("proxy"));
    }
    if ((o.bind_dev || o.bind_ip) && !kernel_plane) {
        fprintf(stderr,
                "error: --bind-dev/--bind-ip 只在 --data-plane kernel 下有效"
                "\n  原因: 绑定由内核模块在 SESSION_UP 里执行（一条会话只用"
                "一张下游网卡）；TUN 路径的外层套接字由用户态持有，"
                "尚未实现等价绑定\n");
        err_usage_exit(usage_required("proxy"));
    }
    if (o.bind_dev) {
        kbind.oif = if_nametoindex(o.bind_dev);
        kbind.dev = o.bind_dev;
        if (kbind.oif == 0) {
            fprintf(stderr, "error: --bind-dev %s: 没有这张网卡\n",
                    o.bind_dev);
            cleanse_str(o.pass);
            cleanse_str(o.ct_pass);
            free_route_opts(&o);
            return 1;
        }
    }
    if (o.bind_ip) {
        /* 按字面量判族：v4 点分 -> 绑 v4 出口 IP；v6 -> 绑 v6 出口 IP
         * （外层版本由会话套接字的族决定，内核侧要求"绑的 IP == 外层源
         * 地址"，所以给错族会在握手后被内核 -EINVAL 拒掉 —— 这里只要
         * 能解析成任一族就行，具体一致性交给 kdp_socket_params）。 */
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
                    "error: --bind-ip %s: 不是 IPv4 点分地址，也不是 IPv6 "
                    "字面量\n  （链路本地地址不支持：内核外层 v6 属性不带 "
                    "scope_id）\n",
                    o.bind_ip);
            err_usage_exit(usage_required("proxy"));
        }
    }
    if (kbind.oif != 0 || kbind.bind_ip != 0 || kbind.bind_v6) {
        char why[256];

        /* 启动即校验：网卡存在且 UP 有载波；出口 IP 属于本机某张接口，
         * 且与 --bind-dev（若同时给了）必须是同一张。地址与链路状态一律
         * 现读（getifaddrs），不缓存。 */
        if (!kdp_bind_ok(&kbind, why, sizeof(why))) {
            fprintf(stderr, "error: 绑定不可用: %s\n", why);
            cleanse_str(o.pass);
            cleanse_str(o.ct_pass);
            free_route_opts(&o);
            return 1;
        }
        char bdesc[128] = "";

        if (kbind.bind_ip != 0 || kbind.bind_v6)
            snprintf(bdesc, sizeof(bdesc), "绑出口 IP %s", o.bind_ip);
        if (kbind.oif != 0) {
            size_t n = strlen(bdesc);

            snprintf(bdesc + n, sizeof(bdesc) - n, "%s绑网卡 %s(ifindex=%u)",
                     n != 0 ? " + " : "", o.bind_dev,
                     (unsigned)kbind.oif);
        }
        log_info("内核数据面: 绑定方式=%s（一条会话只用一张下游网卡）", bdesc);
    }
#else
    /* 非 Linux 的内核面（Windows 的 kdp_win_run）还没接这三个开关：
     * SESSION_OPEN 里虽然留了 oif_index/bind_ip/bind_ip6 与 BIND_* 标志位，
     * 但客户端侧一个都没填，内核面按路由选出口。显式拒绝，不静默忽略
     * （与 Linux 的 TUN 路径同规矩）。 */
    if (o.bind_dev || o.bind_ip) {
        fprintf(stderr,
                "error: --bind-dev/--bind-ip 只在 Linux 内核面上可用"
                "\n  原因: 本平台内核面还没接绑定属性（Windows 的 SESSION_OPEN"
                "未填 oif_index/bind_ip），TUN 路径也没有等价绑定\n");
        err_usage_exit(usage_required("proxy"));
    }
    if (o.reply_via_tunnel) {
        fprintf(stderr,
                "error: --reply-via-tunnel 只在 Linux 内核面上可用"
                "\n  原因: 本平台内核面的回包走隧道尚未接线\n");
        err_usage_exit(usage_required("proxy"));
    }
#endif /* __linux__ */

#ifdef _WIN32
    /* TUN mode requires an administrator (wintun driver + routing):
     * relaunch via a UAC prompt instead of failing. Must happen before
     * any network/session work — the elevated instance re-runs the
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
     * when the owning fd closes — at shutdown and on any crash. If the
     * name is already taken (any interface type), TUNSETIFF fails with
     * EBUSY/EEXIST below and we report the error instead of touching a
     * device we do not own. */

#ifdef _WIN32
    /* wintun.dll missing? ask (interactive) and auto-download the latest
     * wintun build before open_tun so the first run just works */
    if (wintun_ensure() != 0) {
        slist_free(&routes);
        free_route_opts(&o);
        cleanse_str(o.pass);
        cleanse_str(o.ct_pass);
        return 1;
    }
#endif

    /* --data-plane kernel 下不建 TUN：设备（固定 iwan0）由内核模块在
     * SESSION_UP 时按需创建/UP/设 MTU，地址与路由仍由用户态按回执里的
     * DEVNAME 配置（kdp_run 内部做，与 route_setup 同一套代码）。
     * tun_fd 保持 -1，下面的所有使用点都按 >= 0 判定。
     *
     * 默认的 auto 选到内核面时这里**不开设备**：设备按需打开（内核面起不
     * 来时在回退处调 proxy_tun_prepare），预先开着会让 SESSION_UP -EBUSY。 */
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
    /* kdp_run 的启动失败分类：true = 本 netns 已有内核会话/设备被占，
     * 这种失败**不回退** TUN（回退会用同一账号把那条会话顶掉）。 */
    bool kdp_busy = false;
    for (;;) {
        AuthResult res;

#ifdef __linux__
        /* 绑定失效期间不握手：内核部分已被停用（kdp_run 的 1s 节拍发现失效
         * 即 teardown），经 iwan0 的那条路由也随设备失效，内层流量改由路由
         * 表的下一条目承担。等绑定的网卡/出口 IP 回来再重新握手、重新打开数据
         * —— 与"绑 IP 时 IP 回来则重新握手"的语义一致。
         * Windows 内核面不做绑定，没有"等绑定回来"这一态。 */
        if (reconnecting)
            kdp_bind_wait(&kbind);
#endif

        /* 握手前的内核面预检（只在首次握手之前跑）：本机内核面是否可用、
         * 本 netns 是否已有活会话。放在这里是为了**不先跟服务器握手**——
         * 否则一次"本机没模块"的失败会白占一条服务端会话，更糟的是"本 netns
         * 已有活会话"时会把那条会话顶掉（服务端对同源 IP 的第二次 OPEN 按
         * 合法重连处理）。重连时不能跑：本进程自己的会话可能还在。 */
        if (!reconnecting && kernel_plane) {
            char perr[512];
            bool busy = false;

#if defined(_WIN32)
            if (!kdp_win_plane_precheck(win_device_path(plane),
                                        perr, sizeof(perr), &busy)) {
#else
            if (!kdp_plane_precheck(perr, sizeof(perr), &busy)) {
#endif
                log_err("内核数据面: %s", perr);
                if (plane_auto && !busy) {
                    log_err("内核数据面在本机不可用，自动回退到 TUN 数据面");
                    plane_auto = false;   /* 只回退一次 */
                    kernel_plane = false;
                    tun_fd = proxy_tun_prepare(&o, &rp);
                    if (tun_fd < 0) {
                        log_err("TUN 数据面也不可用，退出"
                                "（内核面原因见上）");
                        rc = -1;
                        break;
                    }
                    continue;   /* 重新走一轮：这次是 TUN 面 */
                }
                /* busy：本 netns 已有活会话/设备被占。这一类的唯一出路是
                 * 先停掉占用者 —— 回退 TUN 不是出路：服务端对同源 IP 的
                 * 第二次 OPEN 按合法重连处理，于是 TUN 面会把那条活会话
                 * 顶掉（就是用同一个账号把别人踢下线）。 */
                if (busy)
                    log_err("内核数据面: 本 netns 已有内核会话/设备被占，"
                            "不回退 TUN（回退会拿同一账号把那条会话顶掉）；"
                            "先停掉它再试");
                else if (!plane_auto)
                    log_err("内核数据面: 本次运行不接受自动回退"
                            "（显式指定了 --data-plane，或用了只有内核面"
                            "支持的绑定），直接退出");
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
            if (!s2ip4(res.tun, b4) || !s2ip4(res.gw, b4)) {
                log_err("Error: server returned invalid tunnel/gateway "
                        "IPv4 address");
                port_close(sockfd);
                rc = 1;
                break;
            }
        }
        /* 内层 IPv6 需要链路 MTU ≥ 1280（RFC 8200 §5）：IPv6 路由器不做
         * 分片，链路小于 1280 时 v6 必然不通（表现为"路由装上了但不通"，
         * 正是要避免的静默黑洞）。生效 MTU 现在才知道（服务端可能下调），
         * 所以检查放在这里，两期数据面共用。 */
        if (want_v6 && res.mtu < 1280)
            log_err("警告: --proxy-cidr6（内层 IPv6）要求内层 MTU ≥ 1280"
                    "（RFC 8200 §5），本次生效 MTU=%u：IPv6 分组会被对端"
                    "或中间设备丢弃，请调大 --mtu 或去掉 --proxy-cidr6",
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
            /* 内核数据面：握手（OPEN/OPEN_ACK/验签/密钥派生）已经在上面的
             * authenticate() 里完成 —— 那一刻还没有内核会话，钩子不拦，
             * 所以应用自己的 UDP socket 正常收到了 OPEN_ACK。这里才把数据面
             * 交给内核：数据帧、keepalive 接收、断开接收都归模块，keepalive
             * 发送与存活判定仍在用户态（kdp_run）。返回值与 run_pump 同义，
             * 下面的重连循环零改动。 */
            rc = kdp_run(sockfd, sk, res.sid, res.tok, res.enc, o.server,
                         &routes, &routes6, res.tun, res.mtu, &kbind,
                         &kdp_busy);
        else
#elif defined(_WIN32)
        if (kernel_plane)
            rc = kdp_win_run(sockfd, sk, res.sid, res.tok,
                             res.enc, o.server, NULL,
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
            /* 内核面启动失败且这是默认选的面 ⇒ 回退 TUN 再试一次（"再失败就
             * 退出"）。kdp_busy 时例外：本 netns 已有内核会话/设备被占，回退
             * 过去会用同一账号把那条会话顶掉（服务端对同源 IP 的第二次 OPEN
             * 按合法重连处理），比直接失败更糟。 */
            if (kernel_plane && plane_auto && !kdp_busy) {
                log_err("内核数据面启动失败，自动回退到 TUN 数据面");
                plane_auto = false;   /* 只回退一次 */
                kernel_plane = false;
                if (tun_fd < 0)
                    tun_fd = proxy_tun_prepare(&o, &rp);
                if (tun_fd < 0) {
                    log_err("TUN 数据面也不可用，退出（内核面原因见上）");
                    break;
                }
                continue;
            }
            if (kernel_plane && kdp_busy)
                log_err("本 netns 已有内核会话/设备被占，不回退 TUN"
                        "（回退会把那条会话顶掉）；先停掉它再试");
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
        tun_close(tun_fd);   /* --data-plane kernel: 没有 TUN fd */
    log_info("done.");

    slist_free(&routes);
    free_route_opts(&o);
    return rc == 0 ? 0 : 1;
}

/* (R4-01-2: in-place tunnel re-auth was removed from cmd_socks — the
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
    /* H-1 (R14): same as the proxy command — judge the token's CONTENT.
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
     * port_sleep_ms(1000) window took the default action — abrupt rc=130
     * death in the foreground, or a silently swallowed signal (a
     * background job inherits SIG_IGN) that left the startup-fail retry
     * loop running forever — and the g_user_stop check right after the
     * sleep could never fire. With the loop-level handler, run_socks's
     * save/restore now preserves on_sig, the wait-window Ctrl-C lands in
     * g_user_stop, and the loop breaks cleanly when the sleep returns.
     * Restored after the loop so nothing persists for a later run_socks
     * call (the early `return 1` paths below exit the process right
     * away, so their handler state is unobservable). Windows: run_socks
     * uses the process-lifetime port_set_stop_handler there, so the wait
     * window was never unprotected on Windows — nothing to add. */
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
         * port_close(sockfd) after run_socks returns — closing again
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
