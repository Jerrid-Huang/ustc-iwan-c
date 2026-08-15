/* Shared protocol parsing (SOCKS5 + HTTP proxy handshakes).
 *
 * Used by both proxy data planes:
 *   - socks_flow.c  (lwIP userspace stack, SOCKS mode)
 *   - relay_proxy.c (kernel-stack relay, TUN-mode --listen)
 * Pure functions: no state, no I/O. See proto_parse.h.
 */

#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "port.h"
#include "proto_parse.h"

/* ---- HTTP method probe ---- */

int pp_http_probe(const uint8_t *d, size_t n)
{
    static const char *const methods[] = {
        "CONNECT", "GET", "POST", "HEAD", "PUT", "DELETE",
        "OPTIONS", "TRACE", "PATCH",
    };
    static const size_t lens[] = {7, 3, 4, 4, 3, 6, 7, 5, 5};

    if (n == 0)
        return -1;
    for (int i = 0; i < (int)(sizeof lens / sizeof lens[0]); i++) {
        if (n >= lens[i] && memcmp(d, methods[i], lens[i]) == 0) {
            if (n > lens[i] && d[lens[i]] == ' ')
                return 1;
            return n == lens[i] ? -1 : 0;   /* wait / wrong delimiter */
        }
    }
    /* first byte could still start a method whose token is incomplete */
    if (d[0] == 'C' || d[0] == 'O' || d[0] == 'D' ||
        (n < 3 && (d[0] == 'G' || d[0] == 'P' || d[0] == 'T')) ||
        (n < 4 && d[0] == 'H'))
        return -1;
    return 0;
}

/* ---- HTTP request target ---- */

static int pp_parse_port(const char *s, size_t n, uint16_t *port_out)
{
    unsigned long v = 0;
    if (n == 0)
        return -1;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        v = v * 10 + (unsigned long)(s[i] - '0');
        if (v > 65535)
            return -1;
    }
    *port_out = (uint16_t)v;
    return 0;
}

int pp_http_target(const char *s, size_t n, bool is_connect,
                   pp_target *out)
{
    uint16_t port = is_connect ? 443 : 80;
    size_t i;

    memset(out, 0, sizeof *out);
    out->af = 0;

    if (n == 0)
        return -1;
    if (!is_connect) {
        /* strip scheme for absolute-URI requests */
        if (n >= 7 && port_strncasecmp(s, "http://", 7) == 0) {
            s += 7;
            n -= 7;
        } else if (n >= 8 && port_strncasecmp(s, "https://", 8) == 0) {
            s += 8;
            n -= 8;
        }
        if (n == 0)
            return -1;
        /* host part ends at '/', '?' or '#' */
        for (i = 0; i < n; i++) {
            char c = s[i];
            if (c == '/' || c == '?' || c == '#') {
                n = i;
                break;
            }
        }
    }
    if (n == 0)
        return -1;
    /* CONNECT: the authority is followed by a space and the HTTP
     * version (CONNECT host:443 HTTP/1.1); cut at the space too */
    for (i = 0; i < n; i++) {
        if (s[i] == ' ') {
            n = i;
            break;
        }
    }
    if (n == 0)
        return -1;
    if (s[0] == '[') {
        /* bracketed IPv6 literal: [addr]:port (RFC 7230 authority) */
        size_t close = 0;
        while (close < n && s[close] != ']')
            close++;
        if (close == n || close < 3 || close > 45)
            return -1;          /* ] must exist, addr 3..45 chars */
        size_t hn6 = close - 1;
        char buf[48];
        if (hn6 >= sizeof buf)
            return -1;
        memcpy(buf, s + 1, hn6);
        buf[hn6] = 0;
        if (inet_pton(AF_INET6, buf, out->ip6) != 1)
            return -1;
        if (close + 1 < n) {
            if (s[close + 1] != ':')
                return -1;
            if (pp_parse_port(s + close + 2, n - (close + 2), &port) != 0)
                return -1;
        }
        out->af = 6;
        out->port = port;
        return 0;
    }
    /* split host:port at the (single) colon */
    {
        const char *colon = NULL;
        for (i = 0; i < n; i++) {
            if (s[i] == ':') {
                if (i == n - 1 || colon)
                    return -1;
                colon = s + i;
            }
        }
        if (colon) {
            if (pp_parse_port(colon + 1, n - (size_t)(colon + 1 - s),
                              &port) != 0)
                return -1;
            n = (size_t)(colon - s);
        }
    }
    if (n == 0 || n > sizeof out->host - 1)
        return -1;
    /* host charset: letters, digits, '.', '-', '_' */
    for (i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'))
            return -1;
    }
    memcpy(out->host, s, n);
    out->host[n] = 0;
    out->port = port;
    if (inet_pton(AF_INET, out->host, &out->ip4) == 1)
        out->af = 4;            /* IPv4 literal: host kept for display */
    return 0;
}

/* ---- SOCKS5 greeting ---- */

int pp_socks_greeting(const uint8_t *d, size_t n, bool have_token,
                      uint8_t *method)
{
    size_t nmethods;
    int want = have_token ? 2 : 0;

    if (n < 2)
        return -1;
    if (d[0] != 5)
        return -1;
    nmethods = d[1];
    if (n < 2 + nmethods)
        return -1;
    *method = 0xff;
    for (size_t i = 0; i < nmethods; i++) {
        if (d[2 + i] == want) {
            *method = (uint8_t)want;
            break;
        }
    }
    return 0;
}

/* ---- RFC1929 auth frame ---- */

int pp_socks_auth_frame(const uint8_t *d, size_t n, char *user,
                        size_t usz, const uint8_t **pass, size_t *plen)
{
    size_t ulen;

    if (n < 2)
        return -1;
    if (d[0] != 1 || d[1] == 0)
        return 0;
    ulen = d[1];
    if (n < 2 + ulen + 1)
        return -1;
    if (d[2 + ulen] == 0)
        return 0;
    if (n < 2 + ulen + 1 + d[2 + ulen])
        return -1;
    if (ulen >= usz)
        return 0;
    memcpy(user, d + 2, ulen);
    user[ulen] = 0;
    *pass = d + 2 + ulen + 1;
    *plen = d[2 + ulen];
    return 1;
}

/* ---- SOCKS5 CONNECT request ---- */

int pp_socks_request(const uint8_t *d, size_t n, uint8_t *cmd,
                     uint8_t *rep, pp_target *out)
{
    uint8_t atyp;

    if (n < 4)
        return -1;
    if (d[0] != 5)
        return -1;
    *cmd = d[1];
    *rep = 0;
    if (d[1] != 1) {            /* only CONNECT is implemented */
        *rep = 7;
        return 0;
    }
    if (d[2] != 0) {            /* RSV must be zero */
        *rep = 7;
        return 0;
    }
    atyp = d[3];
    memset(out, 0, sizeof *out);
    out->af = 0;
    if (atyp == 1) {
        if (n < 10)
            return -1;
        memcpy(&out->ip4, d + 4, 4);
        out->port = (uint16_t)((d[8] << 8) | d[9]);
        out->af = 4;
    } else if (atyp == 4) {
        if (n < 22)
            return -1;
        memcpy(out->ip6, d + 4, 16);
        out->port = (uint16_t)((d[20] << 8) | d[21]);
        out->af = 6;
    } else if (atyp == 3) {
        uint8_t l = d[4];
        /* l is a u8 (<=255) and host[] holds 255 + NUL: l==0 is the
         * only invalid length */
        if (l == 0) {
            *rep = 8;
            return 0;
        }
        if (n < 5 + (size_t)l + 2)
            return -1;
        memcpy(out->host, d + 5, l);
        out->host[l] = 0;
        out->port = (uint16_t)((d[5 + l] << 8) | d[6 + l]);
    } else {
        *rep = 8;
        return 0;
    }
    return 0;
}
