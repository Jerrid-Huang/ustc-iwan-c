#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "addr.h"
#include "auth.h"
#include "cli.h"
#include "common.h"
#include "crypto.h"
#include "protocol.h"
#include "proxy.h"
#include "socks.h"
#include "tun.h"
#include "util.h"

#define VERSION     "0.1.0"
#define PING_BUF_SZ 64

typedef struct {
    const char *server;
    uint16_t    port;
    const char *user;
    const char *pass;
    const char *ct_pass;
    const char *pass_file;
    const char *ct_pass_file;
    uint8_t     encrypt;
    uint16_t    mtu;
    const char *tun;
    slist_t     proxy_cidr;
    slist_t     proxy_ip;
    slist_t     proxy_domain;
    const char *listen_str;
    const char *socks_token;
    bool        allow_remote;
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
        return "Usage: iwan-client auth --server <SERVER> --pass <PASS>";
    if (sub && strcmp(sub, "proxy") == 0)
        return "Usage: iwan-client proxy --server <SERVER> --pass <PASS>";
    if (sub && strcmp(sub, "socks") == 0)
        return "Usage: iwan-client socks --server <SERVER> --pass <PASS>";
    return "Usage: iwan-client <COMMAND>";
}

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
            "      --encrypt <ENCRYPT>  [default: 1]\n"
            "      --mtu <MTU>          [default: 1400]\n"
            "  -h, --help               Print help\n");
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
            "      --encrypt <ENCRYPT>            [default: 1]\n"
            "      --mtu <MTU>                    [default: 1400]\n"
            "      --tun <TUN>                    [default: iwan0]\n"
            "      --proxy-cidr <PROXY_CIDR>      \n"
            "      --proxy-ip <PROXY_IP>          \n"
            "      --proxy-domain <PROXY_DOMAIN>  \n"
            "  -h, --help                         Print help\n");
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
            "      --encrypt <ENCRYPT>  [default: 1]\n"
            "      --mtu <MTU>          [default: 1380]\n"
            "      --listen <LISTEN>    Local SOCKS5 listen address [default: 127.0.0.1:1080]\n"
            "      --socks-token <TOKEN>\n"
            "      --allow-remote       Allow non-loopback listen addresses\n"
            "  -h, --help               Print help\n");
    }
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

static void err_required(const char *sub)
{
    fprintf(stderr,
            "error: the following required arguments were not provided:\n"
            "  --server <SERVER>");
    err_usage_exit(usage_required(sub));
}

/* --pass has no built-in default: refuse to run without it. */
static void err_required_pass(const char *sub)
{
    fprintf(stderr,
            "error: the following required arguments were not provided:\n"
            "  --pass <PASS> or --pass-file <FILE>");
    err_usage_exit(usage_required(sub));
}

/* read the first line of a pass file (O_NOFOLLOW, capped at sz-1 bytes,
 * trailing whitespace trimmed); returns buf. Errors exit(1). */
static const char *read_pass_file(const char *path, char *buf, size_t sz)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        log_err("cannot open pass file '%s': %s", path, strerror(errno));
        exit(1);
    }
    ssize_t n = read(fd, buf, sz - 1);
    close(fd);
    if (n < 0) {
        log_err("cannot read pass file '%s': %s", path, strerror(errno));
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

/* best-effort scrub of a fixed-size secret, immune to optimizer elision */
static void wipe(void *p, size_t n)
{
    volatile unsigned char *v = p;
    while (n--)
        *v++ = 0;
}

static bool valid_listen(const char *val, char *err, size_t errsz)
{
    struct sockaddr_in tmp;
    if (parse_host_port(val, &tmp) == 0)
        return true;
    snprintf(err, errsz, "invalid socket address syntax");
    return false;
}

static void die_invalid_address(const char *ctx)
{
    fprintf(stderr,
            "Error: %s\n\nCaused by:\n    invalid socket address syntax\n",
            ctx);
    exit(1);
}

static void check_server_ip(const char *server, const char *ctx)
{
    char buf[64];
    const char *ip = server;
    struct in_addr a4;
    struct in6_addr a6;
    if (ip[0] == '[') {
        ip = unbracket_ipv6(server, buf, sizeof buf);
    } else if (strchr(ip, ':') != NULL) {
        /* Rust SocketAddr rejects unbracketed IPv6 ("::1:6001" is ambiguous) */
        die_invalid_address(ctx);
    }
    if (inet_pton(AF_INET, ip, &a4) != 1 &&
        inet_pton(AF_INET6, ip, &a6) != 1)
        die_invalid_address(ctx);
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
        .track_usage = false,
    };
    cli_parse(&u, argc, argv, start, opts, nopts, &ctl);
}

/* ---- shared auth glue (auth/proxy/socks subcommands) ---- */

/* pass-file scratch buffers; the subcommands run one at a time */
static char g_pass_buf[512];
static char g_ct_buf[512];

/* fill the 9 credential/connection options shared by auth/proxy/socks
 * into opts[0..8]; each command appends its private options after */
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
    opts[7] = (cli_opt){ "encrypt",      CLI_OPT_U8,  &o->encrypt,
                         "<ENCRYPT>", NULL };
    opts[8] = (cli_opt){ "mtu",          CLI_OPT_U16, &o->mtu,
                         "<MTU>", NULL };
}

/* resolve --pass/--pass-file and --ct-pass/--ct-pass-file into o.pass /
 * o.ct_pass (buffers live for the process); the clap-style required
 * error exits when neither pass form is given */
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
    uint8_t ct[16];
    if (get_ct(o->user, o->pass, o->ct_pass, ct) != 0) {
        log_err("invalid --ct-pass hex (want exactly 32 hex digits)");
        return -1;
    }
    cleanse_str(o->ct_pass);   /* last use of the ct pass */
    uint32_t nonce = rand_u32();
    buf_t open;
    buf_init(&open);
    if (build_open(&open, o->user, ct, o->mtu, o->encrypt, nonce) != 0) {
        buf_free(&open);
        fprintf(stderr, "Error: username too long (max 255 bytes)\n");
        return -1;
    }
    int fd = do_auth(o->server, o->port, open.data, open.len, nonce, style,
                     res);
    buf_free(&open);
    return fd;
}

static void collect_routes(const CmdOpts *o, slist_t *routes)
{
    for (size_t i = 0; i < o->proxy_cidr.n; i++)
        slist_push(routes, o->proxy_cidr.v[i]);
    for (size_t i = 0; i < o->proxy_ip.n; i++)
        slist_push(routes, o->proxy_ip.v[i]);
    for (size_t i = 0; i < o->proxy_domain.n; i++)
        slist_push(routes, o->proxy_domain.v[i]);
}

static void free_route_opts(CmdOpts *o)
{
    slist_free(&o->proxy_cidr);
    slist_free(&o->proxy_ip);
    slist_free(&o->proxy_domain);
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
    check_server_ip(o.server, "invalid server address");

    int fd = udp_connect(o.server, o.port, 3000);
    if (fd < 0) {
        log_err("connect UDP: %s", strerror(errno));
        return 1;
    }

    buf_t pkt;
    buf_init(&pkt);
    ctrl_hdr(&pkt, PT_PING_REQ, 0, 0xFFFF, 0xFFFFFFFFu);
    if (send(fd, pkt.data, pkt.len, 0) != (ssize_t)pkt.len) {
        log_err("send PING: %s", strerror(errno));
        buf_free(&pkt);
        close(fd);
        return 1;
    }
    log_info("-> PING (%zuB) to %s:%u", pkt.len, o.server, (unsigned)o.port);
    buf_free(&pkt);

    uint8_t rbuf[PING_BUF_SZ] = { 0 };
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    ssize_t n = recv(fd, rbuf, sizeof rbuf, 0);
    if (n == 24 && rbuf[0] == PT_PING_RSP && verify_sig(rbuf, (size_t)n)) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        uint64_t ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ull +
                      (uint64_t)(t1.tv_nsec - t0.tv_nsec);
        char dbuf[48];
        fmt_duration(dbuf, sizeof dbuf, ns);
        log_info("<- PONG  RTT=%s", dbuf);
        close(fd);
        return 0;
    }
    if (n < 0) {
        log_err("Error: timeout: %s (os error %d)", strerror(errno), errno);
    } else {
        char hex[2 * PING_BUF_SZ + 1];
        hex_encode(rbuf, (size_t)n, hex);
        log_err("Error: <- %dB type=0x%02x %s", (int)n, rbuf[0], hex);
    }
    close(fd);
    return 1;
}

static int cmd_auth(int argc, char **argv, int start)
{
    CmdOpts o;
    memset(&o, 0, sizeof o);
    o.port = 6001;
    o.user = "_rev_m_1";
    o.encrypt = 1;
    o.mtu = 1400;
    cli_opt opts[9];

    add_auth_opts(opts, &o);
    parse_cmd(argc, argv, start, "auth", opts, sizeof opts / sizeof opts[0]);
    if (!o.server)
        err_required("auth");
    resolve_credentials(&o, "auth");
    check_server_ip(o.server, "invalid server address");

    AuthResult res;
    int fd = authenticate(&o, DO_AUTH_AUTH, &res);
    cleanse_str(o.pass);   /* last use of the pass */
    if (fd < 0) {
        log_err("Error: auth failed");
        return 1;
    }

    log_info("OK sid=0x%04x tok=0x****%04x tun=%s gw=%s dns=%s mtu=%u",
             res.sid, res.tok & 0xFFFF, res.tun, res.gw, res.dns,
             (unsigned)res.mtu);

    buf_t cl;
    buf_init(&cl);
    ctrl_hdr(&cl, PT_CLOSE, o.encrypt, res.sid, res.tok);
    (void)send(fd, cl.data, cl.len, 0);
    log_info("-> CLOSE");
    buf_free(&cl);
    close(fd);
    return 0;
}

static int cmd_proxy(int argc, char **argv, int start)
{
    CmdOpts o;
    memset(&o, 0, sizeof o);
    o.port = 6001;
    o.user = "_rev_m_1";
    o.encrypt = 1;
    o.mtu = 1400;
    o.tun = "iwan0";
    cli_opt opts[13];

    add_auth_opts(opts, &o);
    opts[9] = (cli_opt){ "tun",          CLI_OPT_STR, &o.tun,
                         "<TUN>", NULL };
    opts[10] = (cli_opt){ "proxy-cidr",  CLI_OPT_CSV, &o.proxy_cidr,
                          "<PROXY_CIDR>", NULL };
    opts[11] = (cli_opt){ "proxy-ip",    CLI_OPT_CSV, &o.proxy_ip,
                          "<PROXY_IP>", NULL };
    opts[12] = (cli_opt){ "proxy-domain", CLI_OPT_CSV, &o.proxy_domain,
                          "<PROXY_DOMAIN>", NULL };
    parse_cmd(argc, argv, start, "proxy", opts, sizeof opts / sizeof opts[0]);
    if (!o.server)
        err_required("proxy");
    resolve_credentials(&o, "proxy");
    check_server_ip(o.server, "invalid server address");

    AuthResult res;
    int sockfd = authenticate(&o, DO_AUTH_PUMP, &res);
    if (sockfd < 0) {
        log_err("Error: auth failed");
        cleanse_str(o.pass);
        free_route_opts(&o);
        return 1;
    }

    if (o.encrypt != 1)
        log_err("WARN: data-plane only XOR(1), got %d", o.encrypt);

    uint8_t sk[16];
    session_key(o.user, o.pass, sk);
    cleanse_str(o.pass);   /* last use of the pass */

    if (!tun_name_valid(o.tun)) {
        log_err("invalid TUN device name '%s'", o.tun);
        wipe(sk, sizeof sk);
        close(sockfd);
        free_route_opts(&o);
        return 1;
    }

    slist_t routes;
    slist_init(&routes);
    collect_routes(&o, &routes);

    char *const del[] = { "link", "del", (char *)o.tun, NULL };
    ip_run_quiet(del);

    int tun_fd = open_tun(o.tun);
    if (tun_fd < 0) {
        log_err("open tun (must be root)");
        wipe(sk, sizeof sk);
        close(sockfd);
        slist_free(&routes);
        free_route_opts(&o);
        return 1;
    }
    set_nonblock(tun_fd);
    log_info("tun %s fd=%d", o.tun, tun_fd);

    int rc = run_pump(tun_fd, o.tun, sockfd, sk, res.sid, res.tok, o.encrypt,
                      o.server, &routes, res.tun, res.mtu);
    wipe(sk, sizeof sk);   /* last use of the derived key */
    tun_close(tun_fd);
    log_info("done.");

    close(sockfd);
    slist_free(&routes);
    free_route_opts(&o);
    return rc == 0 ? 0 : 1;
}

static int cmd_socks(int argc, char **argv, int start)
{
    CmdOpts o;
    memset(&o, 0, sizeof o);
    o.port = 6001;
    o.user = "_rev_m_1";
    o.encrypt = 1;
    o.mtu = 1380;
    o.listen_str = "127.0.0.1:1080";
    cli_opt opts[12];

    add_auth_opts(opts, &o);
    opts[9] = (cli_opt){ "listen",       CLI_OPT_STR, &o.listen_str,
                         "<LISTEN>",  valid_listen };
    opts[10] = (cli_opt){ "socks-token", CLI_OPT_STR, &o.socks_token,
                          "<TOKEN>", NULL };
    opts[11] = (cli_opt){ "allow-remote", CLI_OPT_BOOL, &o.allow_remote,
                          NULL, NULL };
    parse_cmd(argc, argv, start, "socks", opts, sizeof opts / sizeof opts[0]);
    if (!o.server)
        err_required("socks");
    resolve_credentials(&o, "socks");
    check_server_ip(o.server, "invalid server address");

    AuthResult res;
    int sockfd = authenticate(&o, DO_AUTH_PUMP, &res);
    if (sockfd < 0) {
        log_err("Error: auth failed");
        cleanse_str(o.pass);
        return 1;
    }
    if (o.encrypt != 1)
        log_err("WARN: data-plane only XOR(1), got %d", o.encrypt);

    uint8_t sk[16];
    session_key(o.user, o.pass, sk);
    cleanse_str(o.pass);   /* last use of the pass */

    uint8_t b[4];
    if (!s2ip4(res.tun, b)) {
        log_err("server returned invalid tunnel IPv4 address");
        wipe(sk, sizeof sk);
        close(sockfd);
        return 1;
    }
    uint32_t inner_ip = ip4_u32(b);
    if (!s2ip4(res.gw, b)) {
        log_err("server returned invalid gateway IPv4 address");
        wipe(sk, sizeof sk);
        close(sockfd);
        return 1;
    }
    uint32_t gateway = ip4_u32(b);

    /* valid_listen already validated the syntax at parse time; this
     * parse only fills the sockaddr for run_socks */
    struct sockaddr_in listen;
    parse_host_port(o.listen_str, &listen);

    SocksConfig cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.listen_addr = listen;
    cfg.listen_str = o.listen_str;
    cfg.inner_ip = inner_ip;
    cfg.gateway = gateway;
    cfg.mtu = (int)(res.mtu < o.mtu ? res.mtu : o.mtu);
    memcpy(cfg.xor_key, sk, sizeof cfg.xor_key);
    wipe(sk, sizeof sk);   /* last use of the derived key */
    cfg.sid = res.sid;
    cfg.token = res.tok;
    cfg.encryption = o.encrypt;
    cfg.auth_token = o.socks_token;
    cfg.allow_remote = o.allow_remote;
    snprintf(cfg.dns, sizeof cfg.dns, "%s", res.dns);

    run_socks(sockfd, &cfg);
    close(sockfd);
    return 0;
}

int main(int argc, char **argv)
{
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