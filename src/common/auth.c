#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
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

/* R37-F3 (R3-M5): variadic printf wrapper (vsnprintf into errmsg) -- the
 * message buffer this file hands back to its callers is now format-
 * checked like the shared loggers (errmsg=1, sz=2, fmt=3). On a function
 * *definition* GCC wants the attribute before the declarator. */
static void IWAN_PRINTF_LIKE(3, 4)
set_err(char *errmsg, size_t sz, const char *fmt, ...)
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
    /* T_AUTH_VERIFY (TLV 0x0F) is optional: the production server (measured 2026-11)
     * replies to an OPEN carrying 0x0F with only a "minimal ACK" (username + nonce echo,
     * no 0x03/0x04/0x05/0x06, sid=0), issuing no session at all; the official Panabit
     * client never sends this item. Off by default; when needed, enable it with
     * IWAN_OPEN_NONCE=1 (a self-hosted server can still echo and verify). */
    if (env_bool("IWAN_OPEN_NONCE", false))
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
    uint8_t     got;      /* R23-F1: bitmask of mandatory TLVs seen
                            * (1=T_IP 2=T_GATEWAY 4=T_DNS 8=T_MTU) */
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
        c->got |= 1u;
        break;
    case T_GATEWAY:
        if (vlen < 4) {
            c->err = 3;
            return false;
        }
        ip_to_string(val, r->gw);
        c->got |= 2u;
        break;
    case T_DNS:
        if (vlen < 4) {
            c->err = 3;
            return false;
        }
        ip_to_string(val, r->dns);
        c->got |= 4u;
        break;
    /* IPv6 trio (0x0b/0x0c/0x0d): the official client accepts only length byte == 0x12
     * (2-byte TLV header + 16-byte address); any other length is ignored entirely, and an all-zero address means
     * "the server did not issue v6", matching the client's "skip all-zero" behavior. */
    case T_IPV6:
    case T_DNS6:
    case T_GATEWAY6: {
        char *dst = typ == T_IPV6 ? r->tun6
                 : typ == T_DNS6 ? r->dns6
                                 : r->gw6;
        static const uint8_t zero6[16];
        if (vlen != 16)
            break;
        if (memcmp(val, zero6, 16) == 0) {
            dst[0] = '\0';
            break;
        }
        if (!inet_ntop(AF_INET6, val, dst, 46))
            dst[0] = '\0';
        break;
    }
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
        c->got |= 8u;
        break;
    case T_ENCRYPT:
        /* R23-F2: honor the server's negotiated data-plane encryption flag;
         * absent means 1 (the reference server always sends it) */
        if (vlen < 1) {
            c->err = 3;
            return false;
        }
        r->enc = val[0] ? 1 : 0;
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

static bool parse_ack(const uint8_t *buf, size_t len, uint32_t expect_nonce,
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
         * not determined attackers -- the real server signs its rejects
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
        /* L3 (bughunt): also blank the C1 control range (0x80-0x9F) the
         * old filter missed; it is terminal garbage at worst, but blank
         * it for defense-in-depth like the classic C0 range + DEL. */
        for (size_t i = 0; i < rlen; i++) {
            uint8_t c = (uint8_t)reason[i];
            if (c < 0x20 || (c >= 0x7f && c <= 0x9f))
                reason[i] = '?';
        }
        if (rlen > 0)
            set_err(errmsg, errmsg_sz, "OPEN_REJECT: %s", reason);
        else
            set_err(errmsg, errmsg_sz, "OPEN_REJECT");
        return false;
    }
    if (t != PT_OPEN_ACK) {
        size_t tl = len > IWAN_CTRL_LEN ? (size_t)(len - IWAN_CTRL_LEN) : 0;
        char *hex = malloc(2 * tl + 1);
        if (!hex)
            oom_abort();
        hex_encode(buf + IWAN_CTRL_LEN, tl, hex);
        set_err(errmsg, errmsg_sz, "unexpected type 0x%02x tlvs=%s", t, hex);
        free(hex);
        return false;
    }
    /* The ACK TLV area is extensible: this repository's own ACK has 25-31 bytes of TLVs,
     * while the official Panabit client requires the DNS TLV to be 8 bytes (TLV area +4) and with IPv6
     * also sends three more TLVs, 0x0b/0x0c/0x0d. The historical limit of 31 was "this repository's own
     * ACK shape", which judged both classes of legal ACK oversized (measured: interop with the official client
     * failed with auth failed directly). Relaxed to 200 bytes -- far larger than any known ACK
     * and still far below the 1500 path MTU; malformed short frames are rejected by the TLV parsing below. */
    if (len > IWAN_CTRL_LEN + 200) {
        set_err(errmsg, errmsg_sz, "oversized ACK");
        return false;
    }
    if (!verify_sig(buf, len)) {
        set_err(errmsg, errmsg_sz, "bad sig");
        return false;
    }
    r->sid = (uint16_t)((buf[2] << 8) | buf[3]);
    r->tok = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
             ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
    /* M2 (bughunt): degenerate-credential guard -- an ACK with a zero
     * session token would reduce blind 2^32 guessing to a 2^16 sid
     * search (tok is the whole data-plane credential); tok==0 alone is
     * degenerate even when sid!=0. Real servers issue random nonzero
     * tokens; refuse it before parse_ack can report success. */
    if (r->tok == 0) {
        set_err(errmsg, errmsg_sz, "degenerate zero token");
        return false;
    }

    memset(r->tun, 0, sizeof r->tun);
    memset(r->gw, 0, sizeof r->gw);
    memset(r->dns, 0, sizeof r->dns);
    r->unissued = false;   /* the caller's AuthResult is a stack variable, must be cleared explicitly */
    memset(r->tun6, 0, sizeof r->tun6);
    memset(r->gw6, 0, sizeof r->gw6);
    memset(r->dns6, 0, sizeof r->dns6);
    r->mtu = IWAN_DEFAULT_MTU;
    r->enc = 1;   /* default when the ACK omits T_ENCRYPT (R23-F2) */

    memset(&ctx, 0, sizeof ctx);
    ctx.r = r;
    ctx.expect = expect_nonce;
    if (parse_tlvs(buf + IWAN_CTRL_LEN, len - IWAN_CTRL_LEN, ack_tlv,
                   &ctx) != 0) {
        set_err(errmsg, errmsg_sz, "malformed TLVs");
        return false;
    }
    /* Debug aid: decode and print each ACK TLV entry (IWAN_DEBUG=1). Release builds
     * compile log_debug out; to see it, switch the build to Debug. */
    if (debug_enabled()) {
        const uint8_t *p = buf + IWAN_CTRL_LEN;
        size_t remain = len - IWAN_CTRL_LEN;

        while (remain >= 2) {
            uint8_t lt = p[0], ll = p[1];
            /* 3 bytes per input byte plus NUL, and 3 more for the "..." ellipsis in the
             * truncated case: the ellipsis is a 3-character string written at hex + 3 * 32,
             * so the old 3 * 32 + 1 buffer left it writing past the end (clang reports
             * 'strcpy will always overflow'). */
            char hex[3 * 32 + 1 + 3];
            size_t vn;

            if (ll < 2 || (size_t)ll > remain)
                break;
            vn = (size_t)ll - 2;
            if (vn > 32) {
                hex_encode(p + 2, 32, hex);
                strcpy(hex + 3 * 32, "...");
            } else {
                hex_encode(p + 2, vn, hex);
            }
            switch (lt) {
            case T_MTU:
                log_debug("  TLV 0x03 mtu=%u", (unsigned)((p[2] << 8) | p[3]));
                break;
            case T_IP:
            case T_GATEWAY:
            case T_DNS: {
                char a[64] = "";
                size_t n = 0;
                while (n + 4 <= vn && n < 8) {
                    char one[16];
                    snprintf(one, sizeof one, "%s%u.%u.%u.%u",
                             n ? "/" : "", p[2 + n], p[3 + n],
                             p[4 + n], p[5 + n]);
                    strncat(a, one, sizeof a - strlen(a) - 1);
                    n += 4;
                }
                log_debug("  TLV 0x%02x %s len=%llu", lt,
                          lt == T_IP ? "tun" :
                          lt == T_GATEWAY ? "gw" : "dns",
                          (unsigned long long)vn, a);
                break;
            }
            case T_ENCRYPT:
                log_debug("  TLV 0x08 enc=%u", vn ? p[2] : 0);
                break;
            case T_IPV6:
            case T_DNS6:
            case T_GATEWAY6: {
                char a6[64] = "";

                if (vn == 16)
                    (void)inet_ntop(AF_INET6, p + 2, a6, sizeof a6);
                log_debug("  TLV 0x%02x %s len=%llu %s", lt,
                          lt == T_IPV6 ? "tun6" :
                          lt == T_DNS6 ? "dns6" : "gw6",
                          (unsigned long long)vn, a6);
                break;
            }
            default:
                log_debug("  TLV 0x%02x len=%llu hex=%s", lt,
                          (unsigned long long)vn, hex);
                break;
            }
            p += ll;
            remain -= ll;
        }
    }

    /* R23-F1: the reference server always sends these four; accepting a
     * bare/partial ACK as success would let a forged (header-sig-only)
     * frame report a bogus "auth OK" with no tun/gw/dns/mtu at all. */
    if ((ctx.got & 0x0F) != 0x0F && env_bool("IWAN_ALLOW_MINIMAL_ACK", false)) {
        /* Minimal-ACK semantics after a server upgrade: both the signature and the nonce echo hold, proving the peer
         * really received our OPEN and verified the password (a wrong password replies OPEN_REJECT),
         * but it no longer issues tun/gw/dns/mtu. By default we still hard-fail per the old semantics -- the ACK signing
         * key is a public constant, so any man-in-the-middle can forge a "bare ACK"; requiring the four TLVs
         * is the only remaining barrier against forgery; only explicitly enabling the env var relaxes it. */
        log_err("WARNING: ACK carried no address (got=0x%02x): continuing as minimal ACK "
                 "(IWAN_ALLOW_MINIMAL_ACK=1)", ctx.got);
        r->unissued = true;
    } else if ((ctx.got & 0x0F) != 0x0F) {
        if (debug_enabled()) {
            char hex[3 * 128 + 1];
            size_t tl = len > IWAN_CTRL_LEN ? (size_t)(len - IWAN_CTRL_LEN) : 0;
            if (tl > 128)
                tl = 128;
            hex_encode(buf + IWAN_CTRL_LEN, tl, hex);
            log_debug("ACK hdr type=0x%02x enc=%u sid=0x%02x%02x tok=%08x "
                      "got=0x%02x len=%llu: %s",
                      buf[0], buf[1], buf[2], buf[3],
                      ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                          ((uint32_t)buf[6] << 8) | (uint32_t)buf[7],
                      ctx.got, (unsigned long long)len, hex);
        }
        set_err(errmsg, errmsg_sz, "ACK missing mandatory TLVs");
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
        /* R37-A2: five distinct EAI_* codes used to collapse into a bare
         * EINVAL, so the caller could only print "auth failed" -- an OOM
         * (EAI_MEMORY) or a resolver system failure looked exactly like a
         * bad server address. Report the resolver's own text, the same
         * way https.c:725-730 does for its connect diag, and keep errno
         * meaningful for the caller.
         *
         * Control flow is deliberately unchanged: both callers reach
         * udp_connect() only after check_server_ip() (cli_common.c:130)
         * has validated an IP literal, so EAI_NONAME/EAI_AGAIN/EAI_FAIL
         * are unreachable here and only EAI_MEMORY/EAI_SYSTEM can fire.
         * EAI_SYSTEM is guarded: it is a POSIX spelling that MinGW-w64
         * does not define (its getaddrinfo reports no errno-backed
         * failure), and referencing it unguarded re-breaks win-cross. */
        errno = (g == EAI_MEMORY) ? ENOMEM :
#ifdef EAI_SYSTEM
                (g == EAI_SYSTEM) ? errno :   /* errno already holds it */
#endif
                EINVAL;
        err_printf("Error: resolve %s: %s (os error %d)\n", host,
                   gai_strerror(g), errno);
        return -1;
    }

    fd = port_socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

#ifdef _WIN32
    /* Connected UDP sockets on Windows surface any ICMP unreachable as
     * WSAECONNRESET on the NEXT recv (the infamous behavior) -- a single
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
     * The kernel may clamp SO_RCVBUF to rmem_max -- nonfatal, but note it
     * for diagnostics. (No explicit bind needed: connect() binds the
     * local address implicitly.) */
    int bufsz = 16 * 1024 * 1024;
    if (port_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof bufsz) < 0)
        log_debug("SO_RCVBUF: %s", strerror(errno));
    if (port_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof bufsz) < 0)
        log_debug("SO_SNDBUF: %s", strerror(errno));
    if (port_connect(fd, res->ai_addr, (socklen_t)res->ai_addrlen) < 0) {
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
    /* M-2: propagate OOM/failure instead of returning success with
     * (previously possibly-uninitialized) bytes in out. encrypt_password
     * zeroes out on failure, but ignoring the code would still push an
     * all-zero ct onto the wire as if it were valid. */
    if (encrypt_password(pass, user, out) != 0)
        return -1;
    return 0;
}

/* OPEN retry policy, aligned with the official client's state machine
 * (docs/sdwan-protocol.md section 6): it re-sends OPEN every 2 s and declares
 * "AUTH timeout" when 6 s pass without an OPEN_ACK. Three sends spaced 2 s
 * therefore reproduce that budget (6 s from the first OPEN), still covering
 * one round trip plus jitter on a slow mobile link. A received-but-invalid
 * reply (reject, bad sig, malformed TLVs) is deterministic: the server is up
 * and has answered, so retrying cannot change the outcome -- stop early. */
#define AUTH_TIMEOUT_MS     2000
#define AUTH_SEND_MAX       3
#define AUTH_RETRY_DELAY_US 0

/* M7/R2-B5-1: port_send() returns a byte count and can perform a short
 * write. The old loop only looked for `< 0` and then went straight to
 * recv(), so a truncated OPEN (a forced 1-byte send reproduces this:
 * only 1 byte of the frame left the host) was followed by the whole
 * ~16s retry cycle and a bare "auth failed", while the server never saw
 * a complete request. Send the entire frame, resuming on short writes
 * and EINTR. A zero-byte send means the peer closed without accepting
 * the frame, and a permanent error is reported with the byte counts so
 * the failure is diagnosable instead of silent. */
static int auth_send_open(int fd, const uint8_t *pkt, size_t len) {
    size_t off = 0;
    uint64_t t0 = port_now_ms();

    while (off < len) {
        ssize_t w = port_send(fd, pkt + off, len - off, 0);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR)
            continue;   /* interrupted before any byte: retry */
        /* the AUTH socket is blocking with SO_SNDTIMEO=3s (udp_connect),
         * so EAGAIN means the send timed out or the buffer is full; give
         * it the same bounded window as one auth round trip */
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
            port_now_ms() - t0 < AUTH_TIMEOUT_MS) {
            port_sleep_us(1000);
            continue;
        }
        if (w == 0)
            errno = EPIPE;   /* peer closed without taking the frame */
        /* R37-A1: %llu, never %zu -- msvcrt printf (Windows) lacks %zu and
         * MinGW-w64 rejects it under -Werror=format= (see json.c:55,
         * relay_proxy.c:1328 for the same rule). The two size_t args need
         * the explicit cast because %llu is not size_t on every ABI. */
        fprintf(stderr,
                "Error: send OPEN (%llu of %llu bytes)\n\nCaused by:\n    %s (os error %d)\n",
                (unsigned long long)off, (unsigned long long)len,
                strerror(errno), errno);
        return -1;
    }
    return 0;
}

int do_auth(const char *server, uint16_t port, const uint8_t *open_pkt, size_t open_len,
            uint32_t nonce, int style, AuthResult *r)
{
    int fd = udp_connect(server, port, AUTH_TIMEOUT_MS);
    uint8_t buf[4096];

    if (fd < 0)
        return -1;

    for (int i = 0; i < AUTH_SEND_MAX; i++) {
        if (auth_send_open(fd, open_pkt, open_len) != 0) {
            port_close(fd);
            return -1;
        }
        if (style == DO_AUTH_AUTH)
            err_printf("[%d] -> OPEN (%lluB) nonce=%08x\n", i,
                       (unsigned long long)open_len, nonce);
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
