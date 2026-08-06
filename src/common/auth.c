#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>

#include "auth.h"
#include "common.h"
#include "crypto.h"
#include "protocol.h"

static void eprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void set_err(char *errmsg, size_t sz, const char *fmt, ...)
{
    if (!errmsg || sz == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errmsg, sz, fmt, ap);
    va_end(ap);
}

static size_t utf8_seq(const uint8_t *s, size_t remain, size_t *seq_len)
{
    size_t need;
    if (s[0] < 0x80)
        need = 1;
    else if ((s[0] & 0xE0) == 0xC0)
        need = 2;
    else if ((s[0] & 0xF0) == 0xE0)
        need = 3;
    else if ((s[0] & 0xF8) == 0xF0)
        need = 4;
    else
        return 0;

    if (need > remain)
        return 0;
    for (size_t i = 1; i < need; i++)
        if ((s[i] & 0xC0) != 0x80)
            return 0;
    if (need == 2 && s[0] < 0xC2)
        return 0;
    if (need == 3 && s[0] == 0xE0 && s[1] < 0xA0)
        return 0;
    if (need == 3 && s[0] == 0xED && s[1] >= 0xA0)
        return 0;
    if (need == 4 && s[0] == 0xF0 && s[1] < 0x90)
        return 0;
    if (need == 4 && s[0] == 0xF4 && s[1] >= 0x90)
        return 0;
    *seq_len = need;
    return need;
}

static size_t utf8_lossy(const uint8_t *in, size_t n, char *out)
{
    size_t o = 0;
    size_t i = 0;
    while (i < n) {
        size_t seq = 0;
        if (utf8_seq(in + i, n - i, &seq)) {
            memcpy(out + o, in + i, seq);
            i += seq;
            o += seq;
        } else {
            memcpy(out + o, "\xEF\xBF\xBD", 3);
            i += 1;
            o += 3;
        }
    }
    out[o] = '\0';
    return o;
}

static void hexl(const uint8_t *b, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = d[b[i] >> 4];
        out[i * 2 + 1] = d[b[i] & 0xF];
    }
    out[n * 2] = '\0';
}

void build_open(buf_t *out, const char *user, const uint8_t ct[16],
                uint16_t mtu, uint8_t enc, uint32_t nonce)
{
    buf_t pl;
    uint8_t mb[2];
    uint8_t nb[4];

    mb[0] = (uint8_t)(mtu >> 8);
    mb[1] = (uint8_t)(mtu & 0xFF);
    nb[0] = (uint8_t)(nonce >> 24);
    nb[1] = (uint8_t)(nonce >> 16);
    nb[2] = (uint8_t)(nonce >> 8);
    nb[3] = (uint8_t)nonce;

    buf_init(&pl);
    tlv_put(&pl, T_MTU, mb, sizeof mb);
    tlv_put(&pl, T_USERNAME, user, (uint8_t)strlen(user));
    tlv_put(&pl, T_PASSWORD, ct, 16);
    tlv_put(&pl, T_ENCRYPT, &enc, 1);
    tlv_put(&pl, T_AUTH_VERIFY, nb, sizeof nb);

    ctrl_hdr(out, PT_OPEN, enc, 0, 0);
    buf_put(out, pl.data, pl.len);
    buf_free(&pl);
}

struct ack_ctx {
    AuthResult *r;
    uint32_t    expect;
    int         err;      /* 0 = none, 1 = AV wrong len, 2 = AV echo mismatch,
                            * 3 = short IP TLV */
    int         seen_av;
    uint32_t    echo;
};

static bool ack_tlv(uint8_t typ, const uint8_t *val, uint8_t vlen, void *ud)
{
    struct ack_ctx *c = ud;
    AuthResult *r = c->r;

    switch (typ) {
    case T_IP:
        if (vlen < 4) {
            c->err = 3;
            return false;
        }
        ip_to_string(val, r->tun);
        break;
    case T_GATEWAY:
        if (vlen < 4) {
            c->err = 3;
            return false;
        }
        ip_to_string(val, r->gw);
        break;
    case T_DNS:
        if (vlen < 4) {
            c->err = 3;
            return false;
        }
        ip_to_string(val, r->dns);
        break;
    case T_MTU:
        if (vlen >= 2) {
            uint16_t m = (uint16_t)((val[0] << 8) | val[1]);
            /* the ACK is only header-signed, so never trust a huge MTU:
             * clamp to the IPv4-over-UDP sane range */
            r->mtu = m < 576 ? 576 : (m > 1500 ? 1500 : m);
        }
        break;
    case T_AUTH_VERIFY:
        c->seen_av = 1;
        if (vlen != 4) {
            c->err = 1;
            return false;
        }
        c->echo = ((uint32_t)val[0] << 24) | ((uint32_t)val[1] << 16) |
                  ((uint32_t)val[2] << 8) | (uint32_t)val[3];
        if (c->echo != c->expect) {
            c->err = 2;
            return false;
        }
        break;
    default:
        break;
    }
    return true;
}

bool parse_ack(const uint8_t *buf, size_t len, uint32_t expect_nonce,
               AuthResult *r, char *errmsg, size_t errmsg_sz)
{
    uint8_t t;
    struct ack_ctx ctx;

    if (len < 24) {
        set_err(errmsg, errmsg_sz, "too short");
        return false;
    }
    t = buf[0];
    r->sid = (uint16_t)((buf[2] << 8) | buf[3]);
    r->tok = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
             ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];

    if (t == PT_OPEN_REJECT) {
        char *lossy = malloc(3 * (len - 24) + 1);
        utf8_lossy(buf + 24, len - 24, lossy);
        set_err(errmsg, errmsg_sz, "OPEN_REJECT: %s", lossy);
        free(lossy);
        return false;
    }
    if (t != PT_OPEN_ACK) {
        char *hex = malloc(2 * (len - 24) + 1);
        hexl(buf + 24, len - 24, hex);
        set_err(errmsg, errmsg_sz, "unexpected type 0x%02x tlvs=%s", t, hex);
        free(hex);
        return false;
    }
    if (!verify_sig(buf, len)) {
        set_err(errmsg, errmsg_sz, "bad sig");
        return false;
    }

    memset(r->tun, 0, sizeof r->tun);
    memset(r->gw, 0, sizeof r->gw);
    memset(r->dns, 0, sizeof r->dns);
    r->mtu = 1400;

    memset(&ctx, 0, sizeof ctx);
    ctx.r = r;
    ctx.expect = expect_nonce;
    parse_tlvs(buf + 24, len - 24, ack_tlv, &ctx);
    if (!ctx.seen_av)
        set_err(errmsg, errmsg_sz, "missing AV");
    else if (ctx.err == 1)
        set_err(errmsg, errmsg_sz, "AV wrong len");
    else if (ctx.err == 2)
        set_err(errmsg, errmsg_sz, "AV mismatch %08x", ctx.echo);
    else if (ctx.err == 3)
        set_err(errmsg, errmsg_sz, "short IP TLV");
    if (ctx.err || !ctx.seen_av)
        return false;
    return true;
}

int udp_connect(const char *host, uint16_t port, int timeout_ms)
{
    struct addrinfo hints, *res = NULL;
    struct timeval tv;
    char svc[16], hostbuf[64];
    int g, fd;

    host = unbracket_ipv6(host, hostbuf, sizeof hostbuf);
    snprintf(svc, sizeof svc, "%u", (unsigned)port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    g = getaddrinfo(host, svc, &hints, &res);
    if (g != 0) {
        errno = EINVAL;
        return -1;
    }

    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    struct sockaddr_storage any;
    socklen_t anylen;
    memset(&any, 0, sizeof any);
    if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&any;
        a6->sin6_family = AF_INET6;
        anylen = sizeof *a6;
    } else {
        struct sockaddr_in *a4 = (struct sockaddr_in *)&any;
        a4->sin_family = AF_INET;
        a4->sin_addr.s_addr = htonl(INADDR_ANY);
        anylen = sizeof *a4;
    }
    if (bind(fd, (struct sockaddr *)&any, anylen) < 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    /* large UDP buffers: burst drops on the tunnel path collapse the inner
     * TCP cwnd; default rcvbuf/sndbuf (~208KB) is too small for a VPN */
    int bufsz = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof bufsz);
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof bufsz);
    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    freeaddrinfo(res);
    return fd;
}

static int hexnib(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

void get_ct(const char *user, const char *pass, const char *ct_pass_hex,
            uint8_t out[16])
{
    if (ct_pass_hex && ct_pass_hex[0]) {
        const char *h = ct_pass_hex;
        uint8_t tmp[16] = {0};
        size_t i;

        if (h[0] == '0' && (h[1] == 'x' || h[1] == 'X'))
            h += 2;
        for (i = 0; i < 16; i++) {
            int hi = hexnib((unsigned char)h[2 * i]);
            int lo = hexnib((unsigned char)h[2 * i + 1]);
            if (hi < 0 || lo < 0)
                break;
            tmp[i] = (uint8_t)((hi << 4) | lo);
        }
        memcpy(out, tmp, 16);
    } else {
        encrypt_password(pass, user, out);
    }
}

int do_auth(const char *server, uint16_t port, const uint8_t *open_pkt, size_t open_len,
            uint32_t nonce, int style, AuthResult *r)
{
    int fd = udp_connect(server, port, 3000);
    uint8_t buf[4096];

    if (fd < 0)
        return -1;

    for (int i = 0; i < 4; i++) {
        if (send(fd, open_pkt, open_len, 0) < 0) {
            fprintf(stderr,
                    "Error: send OPEN\n\nCaused by:\n    %s (os error %d)\n",
                    strerror(errno), errno);
            close(fd);
            return -1;
        }
        if (style == DO_AUTH_AUTH)
            eprintf("[%d] -> OPEN (%zuB) nonce=%08x\n", i, open_len, nonce);
        else if (style == DO_AUTH_PUMP)
            eprintf("[%d] -> OPEN\n", i);

        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n >= 0) {
            char errmsg[256];
            if (parse_ack(buf, (size_t)n, nonce, r, errmsg, sizeof errmsg))
                return fd;
            if (style == DO_AUTH_AUTH)
                eprintf("  err: %s\n", errmsg);
            else if (style == DO_AUTH_PUMP)
                eprintf("[%d] invalid reply: %s\n", i, errmsg);
            else
                eprintf("  [%d] err: %s\n", i, errmsg);
        } else {
            if (style == DO_AUTH_AUTH)
                eprintf("  timeout: %s (os error %d)\n", strerror(errno), errno);
            else
                eprintf("  [%d] timeout: %s (os error %d)\n", i, strerror(errno),
                        errno);
        }
        if (i < 3)
            usleep(1000000);
    }

    close(fd);
    return -1;
}