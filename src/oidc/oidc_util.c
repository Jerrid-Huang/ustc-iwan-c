/* Small shared helpers for the OIDC client (errors, entropy, URL/hex/JSON). */

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "crypto.h"
#include "json.h"
#include "oidc.h"

void oidc_die(const char *fmt, ...)
{
    va_list ap;
    fputs("Error: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

void oidc_die_with_cause(const char *msg, const char *cause)
{
    fprintf(stderr, "Error: %s\n\nCaused by:\n    %s\n", msg, cause);
    exit(1);
}

void oidc_eprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void oidc_rand_bytes(uint8_t *out, size_t n)
{
    while (n > 0) {
        uint32_t r = rand_u32();
        size_t m = n > sizeof r ? sizeof r : n;
        memcpy(out, &r, m);
        out += m;
        n -= m;
    }
}

void oidc_check_server_ip(const char *server)
{
    char buf[64];
    const char *ip = server;
    struct in_addr a4;
    struct in6_addr a6;
    if (ip[0] == '[') {
        ip = unbracket_ipv6(server, buf, sizeof buf);
    } else if (strchr(ip, ':') != NULL) {
        fprintf(stderr,
                "Error: invalid address\n\nCaused by:\n    invalid socket address syntax\n");
        exit(1);
    }
    if (inet_pton(AF_INET, ip, &a4) != 1 &&
        inet_pton(AF_INET6, ip, &a6) != 1) {
        fprintf(stderr,
                "Error: invalid address\n\nCaused by:\n    invalid socket address syntax\n");
        exit(1);
    }
}

void oidc_hex_upper(const uint8_t *b, size_t n, char *out)
{
    static const char d[] = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = d[b[i] >> 4];
        out[i * 2 + 1] = d[b[i] & 0xF];
    }
    out[n * 2] = '\0';
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

void oidc_urlenc(const char *s, buf_t *out)
{
    static const char hex[] = "0123456789ABCDEF";
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
            c == '~') {
            buf_put_u8(out, c);
        } else {
            char tmp[3];
            tmp[0] = '%';
            tmp[1] = hex[c >> 4];
            tmp[2] = hex[c & 0xF];
            buf_put(out, tmp, 3);
        }
    }
}

char *oidc_urldec(const char *s, size_t n)
{
    char *out = malloc(n + 1);
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '%' && i + 2 < n) {
            int hi = hexval((unsigned char)s[i + 1]);
            int lo = hexval((unsigned char)s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out[o++] = (char)((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        out[o++] = s[i] == '+' ? ' ' : s[i];
    }
    out[o] = '\0';
    return out;
}

void oidc_buf_cstr(buf_t *b)
{
    buf_ensure(b, 1);
    b->data[b->len] = '\0';
}

char *oidc_buf_to_cstr(buf_t *b)
{
    oidc_buf_cstr(b);
    char *s = xstrdup((char *)b->data);
    buf_free(b);
    return s;
}

void oidc_esc_put(buf_t *b, const char *s)
{
    char *e = json_escape(s ? s : "");
    buf_put_str(b, e);
    free(e);
}

/* pull "code=..." out of an OAuth redirect URL/query string */
char *oidc_extract_code(const char *s)
{
    const char *q = strchr(s, '?');
    if (!q)
        return NULL;
    const char *p = q + 1;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        const char *kv = memchr(p, '=', seg);
        if (kv) {
            size_t kl = (size_t)(kv - p);
            if (kl == 4 && strncmp(p, "code", 4) == 0)
                return oidc_urldec(kv + 1, seg - kl - 1);
        }
        if (!amp)
            break;
        p = amp + 1;
    }
    return NULL;
}

/* decode the "name"/"preferred_username"/"sub" claim from the id_token JWT */
char *oidc_id_token_username(Json *tok)
{
    const char *jwt = json_get_str(tok, "id_token");
    if (!jwt)
        return NULL;
    const char *d1 = strchr(jwt, '.');
    if (!d1)
        return NULL;
    const char *d2 = strchr(d1 + 1, '.');
    if (!d2 || d2 == d1 + 1)
        return NULL;
    size_t seglen = (size_t)(d2 - d1 - 1);
    char *seg = malloc(seglen + 1);
    memcpy(seg, d1 + 1, seglen);
    seg[seglen] = '\0';
    size_t plen = 0;
    uint8_t *raw = b64url_decode(seg, &plen);
    free(seg);
    if (!raw)
        return NULL;
    char *txt = malloc(plen + 1);
    memcpy(txt, raw, plen);
    txt[plen] = '\0';
    free(raw);
    Json *claims = json_parse(txt);
    free(txt);
    if (!claims)
        return NULL;
    const char *nm = json_get_str(claims, "name");
    if (!nm)
        nm = json_get_str(claims, "preferred_username");
    if (!nm)
        nm = json_get_str(claims, "sub");
    char *out = nm ? xstrdup(nm) : NULL;
    json_free(claims);
    return out;
}