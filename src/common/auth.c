#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include "auth.h"
#include "common.h"   /* port.h: winsock2.h + windows.h first */
#ifdef _WIN32
#include <mswsock.h>   /* SIO_UDP_CONNRESET (mingw keeps it here, not mstcpip.h) */
#endif
#include "crypto.h"
#include "protocol.h"
#include "util.h"   /* err_printf: the shared stderr printf (replaces the
                     * per-module eprintf this file used to carry) */

static void set_err(char *errmsg, size_t sz, const char *fmt, ...)
{
    if (!errmsg || sz == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errmsg, sz, fmt, ap);
    va_end(ap);
}

int build_open(buf_t *out, const char *user, const uint8_t ct[16],
               uint16_t mtu, uint8_t enc, uint32_t nonce)
{
    buf_t pl;
    uint8_t mb[2];
    uint8_t nb[4];
    size_t ulen;

    /* the username rides in a single TLV whose length byte stores
     * vlen+2, so the value is capped at 253 bytes (254/255 would wrap
     * the length byte to 0/1 and shift every subsequent TLV out of
     * alignment); refuse to build the frame for longer strings */
    ulen = strlen(user);
    if (ulen > IWAN_TLV_VLEN_MAX)
        return -1;

    mb[0] = (uint8_t)(mtu >> 8);
    mb[1] = (uint8_t)(mtu & 0xFF);
    nb[0] = (uint8_t)(nonce >> 24);
    nb[1] = (uint8_t)(nonce >> 16);
    nb[2] = (uint8_t)(nonce >> 8);
    nb[3] = (uint8_t)nonce;

    buf_init(&pl);
    tlv_put(&pl, T_MTU, mb, sizeof mb);
    tlv_put(&pl, T_USERNAME, user, (uint8_t)ulen);
    tlv_put(&pl, T_PASSWORD, ct, 16);
    tlv_put(&pl, T_ENCRYPT, &enc, 1);
    tlv_put(&pl, T_AUTH_VERIFY, nb, sizeof nb);

    ctrl_hdr(out, PT_OPEN, enc, 0, 0);
    buf_put(out, pl.data, pl.len);
    buf_free(&pl);
    return 0;
}

struct ack_ctx {
    AuthResult *r;
    uint32_t    expect;
    int         err;      /* 0 = none, 1 = AV wrong len, 2 = AV echo mismatch,
                            * 3 = short TLV */
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
        if (vlen < 2) {
            c->err = 3;
            return false;
        }
        {
            uint16_t m = (uint16_t)((val[0] << 8) | val[1]);
            /* the ACK is only header-signed, so never trust a huge MTU:
             * clamp to the IPv4-over-UDP sane range */
            r->mtu = m < IWAN_MTU_MIN ? IWAN_MTU_MIN
                                      : (m > IWAN_MTU_MAX ? IWAN_MTU_MAX : m);
        }
        break;
    case T_AUTH_VERIFY:
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

    if (len < IWAN_CTRL_LEN) {
        set_err(errmsg, errmsg_sz, "too short");
        return false;
    }
    t = buf[0];
    /* sid/tok are only filled after the signature check below: an
     * attacker-forged frame must not leave half-populated results */
    if (t == PT_OPEN_REJECT) {
        /* F5: require the same header signature as the ACK branch below;
         * an unsigned or truncated reject must fail with "bad sig"
         * instead of rendering attacker-chosen T_ERR_MSG text. The sig
         * key is public, so this only stops accidental/naive forgeries,
         * not determined attackers — the real server signs its rejects
         * (server.c builds them with ctrl_hdr). len < IWAN_CTRL_LEN was
         * already rejected above. */
        if (!verify_sig(buf, len)) {
            set_err(errmsg, errmsg_sz, "bad sig");
            return false;
        }
        /* the reason rides in a T_ERR_MSG TLV; render only its value.
         * (Rendering the raw TLV bytes used to mangle the type/length
         * prefix into the message.) Sanitize control bytes in place. */
        const uint8_t *p = buf + IWAN_CTRL_LEN;
        size_t remain = len - IWAN_CTRL_LEN;
        char reason[128];
        size_t rlen = 0;

        while (remain >= 2) {
            uint8_t lt = p[0], ll = p[1];
            if (ll < 2 || ll > remain)
                break;
            if (lt == T_ERR_MSG && (size_t)(ll - 2) < sizeof reason) {
                rlen = ll - 2;
                memcpy(reason, p + 2, rlen);
            }
            p += ll;
            remain -= ll;
        }
        reason[rlen] = '\0';
        for (size_t i = 0; i < rlen; i++)
            if ((uint8_t)reason[i] < 0x20 || (uint8_t)reason[i] == 0x7f)
                reason[i] = '?';
        if (rlen > 0)
            set_err(errmsg, errmsg_sz, "OPEN_REJECT: %s", reason);
        else
            set_err(errmsg, errmsg_sz, "OPEN_REJECT");
        return false;
    }
    if (t != PT_OPEN_ACK) {
        char *hex = malloc(2 * (len - IWAN_CTRL_LEN) + 1);
        hex_encode(buf + IWAN_CTRL_LEN, len - IWAN_CTRL_LEN, hex);
        set_err(errmsg, errmsg_sz, "unexpected type 0x%02x tlvs=%s", t, hex);
        free(hex);
        return false;
    }
    if (!verify_sig(buf, len)) {
        set_err(errmsg, errmsg_sz, "bad sig");
        return false;
    }
    r->sid = (uint16_t)((buf[2] << 8) | buf[3]);
    r->tok = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
             ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];

    memset(r->tun, 0, sizeof r->tun);
    memset(r->gw, 0, sizeof r->gw);
    memset(r->dns, 0, sizeof r->dns);
    r->mtu = IWAN_DEFAULT_MTU;

    memset(&ctx, 0, sizeof ctx);
    ctx.r = r;
    ctx.expect = expect_nonce;
    if (parse_tlvs(buf + IWAN_CTRL_LEN, len - IWAN_CTRL_LEN, ack_tlv,
                   &ctx) != 0) {
        set_err(errmsg, errmsg_sz, "malformed TLVs");
        return false;
    }
    /* T_AUTH_VERIFY is optional on the wire: the reference server's
     * OPEN_ACK omits it, so requiring it breaks production interop.
     * When present it is still strictly verified (len + nonce echo). */
    if (ctx.err == 1)
        set_err(errmsg, errmsg_sz, "AV wrong len");
    else if (ctx.err == 2)
        set_err(errmsg, errmsg_sz, "AV mismatch %08x", ctx.echo);
    else if (ctx.err == 3)
        set_err(errmsg, errmsg_sz, "short TLV");
    if (ctx.err)
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

    fd = port_socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

#ifdef _WIN32
    /* Connected UDP sockets on Windows surface any ICMP unreachable as
     * WSAECONNRESET on the NEXT recv (the infamous behavior) — a single
     * stray ICMP (server restart, middlebox, spoofed probe) would then
     * kill the tunnel. Disable it: the protocol has its own
     * keepalive/session-loss detection. */
    {
        DWORD b = FALSE;
        DWORD br = 0;   /* WSAIoctl requires a valid lpcbBytesReturned */

        if (WSAIoctl((SOCKET)fd, SIO_UDP_CONNRESET, &b, sizeof b, NULL, 0,
                     &br, NULL, NULL) != 0)
            log_debug("SIO_UDP_CONNRESET: winsock error %d",
                      WSAGetLastError());
    }
#endif

    /* large UDP buffers: burst drops on the tunnel path collapse the inner
     * TCP cwnd; default rcvbuf/sndbuf (~208KB) is too small for a VPN.
     * The kernel may clamp SO_RCVBUF to rmem_max — nonfatal, but note it
     * for diagnostics. (No explicit bind needed: connect() binds the
     * local address implicitly.) */
    int bufsz = 4 * 1024 * 1024;
    if (port_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof bufsz) < 0)
        log_debug("SO_RCVBUF: %s", strerror(errno));
    if (port_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof bufsz) < 0)
        log_debug("SO_SNDBUF: %s", strerror(errno));
    if (port_connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        port_close(fd);
        freeaddrinfo(res);
        return -1;
    }

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (port_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0)
        log_debug("SO_RCVTIMEO: %s", strerror(errno));
    if (port_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) < 0)
        log_debug("SO_SNDTIMEO: %s", strerror(errno));

    freeaddrinfo(res);
    return fd;
}

int get_ct(const char *user, const char *pass, const char *ct_pass_hex,
           uint8_t out[16])
{
    if (ct_pass_hex && ct_pass_hex[0]) {
        const char *h = ct_pass_hex;

        if (h[0] == '0' && (h[1] == 'x' || h[1] == 'X'))
            h += 2;
        /* an optional 0x prefix followed by exactly 32 hex digits */
        if (strlen(h) != 32)
            return -1;
        if (hex_decode(h, 32, out, 16) != 16)
            return -1;
        return 0;
    }
    encrypt_password(pass, user, out);
    return 0;
}

/* OPEN retry policy: the reference server answers within ~1s, so the 3s
 * recv timeout covers one round trip plus jitter; up to 4 sends spaced
 * ~4s apart (3s recv timeout + 1s sleep) survive a lost or dropped OPEN
 * without flooding the server. A received-but-invalid reply (reject,
 * bad sig, malformed TLVs) is deterministic: the server is up and has
 * answered, so retrying cannot change the outcome — stop early. */
#define AUTH_TIMEOUT_MS     3000
#define AUTH_SEND_MAX       4
#define AUTH_RETRY_DELAY_US 1000000

int do_auth(const char *server, uint16_t port, const uint8_t *open_pkt, size_t open_len,
            uint32_t nonce, int style, AuthResult *r)
{
    int fd = udp_connect(server, port, AUTH_TIMEOUT_MS);
    uint8_t buf[4096];

    if (fd < 0)
        return -1;

    for (int i = 0; i < AUTH_SEND_MAX; i++) {
        if (port_send(fd, open_pkt, open_len, 0) < 0) {
            fprintf(stderr,
                    "Error: send OPEN\n\nCaused by:\n    %s (os error %d)\n",
                    strerror(errno), errno);
            port_close(fd);
            return -1;
        }
        if (style == DO_AUTH_AUTH)
            err_printf("[%d] -> OPEN (%zuB) nonce=%08x\n", i, open_len, nonce);
        else if (style == DO_AUTH_PUMP)
            err_printf("[%d] -> OPEN\n", i);

        ssize_t n = port_recv(fd, buf, sizeof buf, 0);
        if (n >= 0) {
            char errmsg[256];
            if (parse_ack(buf, (size_t)n, nonce, r, errmsg, sizeof errmsg))
                return fd;
            if (style == DO_AUTH_AUTH)
                err_printf("  err: %s\n", errmsg);
            else if (style == DO_AUTH_PUMP)
                err_printf("[%d] invalid reply: %s\n", i, errmsg);
            else
                err_printf("  [%d] err: %s\n", i, errmsg);
            break;   /* deterministic reject: do not retry */
        } else {
            if (style == DO_AUTH_AUTH)
                err_printf("  timeout: %s (os error %d)\n", strerror(errno), errno);
            else
                err_printf("  [%d] timeout: %s (os error %d)\n", i, strerror(errno),
                        errno);
        }
        if (i < AUTH_SEND_MAX - 1)
            port_sleep_us(AUTH_RETRY_DELAY_US);
    }

    port_close(fd);
    return -1;
}