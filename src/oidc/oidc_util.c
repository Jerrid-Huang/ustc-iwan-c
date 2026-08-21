/* Small shared helpers for the OIDC client (errors, entropy, URL/hex/JSON). */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "common.h"
#include "crypto.h"
#include "json.h"
#include "oidc.h"
#include "util.h"   /* hex_nibble; oidc_eprintf is err_printf (oidc.h) */

#ifdef _WIN32
#include <conio.h>   /* _getch: hold the UAC-relaunched window open */
#endif

/* A UAC-relaunched console app (port_elevate_self sets
 * IWAN_ELEVATED_RELAUNCH) owns a console window that Windows closes
 * the moment the process exits — taking any error message with it.
 * Hold the window open on failure so the user can read the error. */
void oidc_pause_if_relaunched(void)
{
#ifdef _WIN32
    if (getenv("IWAN_ELEVATED_RELAUNCH")) {
        fputs("\nPress any key to close this window...", stderr);
        fflush(stderr);
        _getch();
    }
#endif
}

void oidc_die(const char *fmt, ...)
{
    va_list ap;
    fputs("Error: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
#ifdef _WIN32
    oidc_pause_if_relaunched();
#endif
    exit(1);
}

void oidc_die_with_cause(const char *msg, const char *cause)
{
    fprintf(stderr, "Error: %s\n\nCaused by:\n    %s\n", msg, cause);
#ifdef _WIN32
    oidc_pause_if_relaunched();
#endif
    exit(1);
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

void oidc_hex_upper(const uint8_t *b, size_t n, char *out)
{
    hex_encode(b, n, out);
    for (size_t i = 0; i < n * 2; i++) {
        if (out[i] >= 'a' && out[i] <= 'f')
            out[i] -= 'a' - 'A';
    }
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

static char *oidc_urldec(const char *s, size_t n)
{
    char *out = malloc(n + 1);
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '%' && i + 2 < n) {
            int hi = hex_nibble(s[i + 1]);
            int lo = hex_nibble(s[i + 2]);
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

/* pull a named query parameter out of a URL/query string; returns a
 * newly allocated URL-decoded value (caller frees) or NULL when absent */
char *oidc_url_param(const char *s, const char *name)
{
    const char *q = strchr(s, '?');
    if (!q)
        return NULL;
    size_t nlen = strlen(name);
    const char *p = q + 1;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        const char *kv = memchr(p, '=', seg);
        if (kv && (size_t)(kv - p) == nlen && strncmp(p, name, nlen) == 0)
            return oidc_urldec(kv + 1, seg - nlen - 1);
        if (!amp)
            break;
        p = amp + 1;
    }
    return NULL;
}

/* decode the "name"/"preferred_username"/"sub" claim from the id_token
 * JWT (the caller supplies the token string; the only caller,
 * oidc_login, passes the string verify_id_token already fetched) */
char *oidc_id_token_username(const char *jwt)
{
    char *txt, *out;
    Json *claims;
    const char *nm;

    if (!jwt)
        return NULL;
    txt = oidc_jwt_segment(jwt, 1);
    if (!txt)
        return NULL;
    claims = json_parse(txt);
    free(txt);
    if (!claims)
        return NULL;
    nm = json_get_str(claims, "name");
    if (!nm)
        nm = json_get_str(claims, "preferred_username");
    if (!nm)
        nm = json_get_str(claims, "sub");
    out = nm ? xstrdup(nm) : NULL;
    json_free(claims);
    return out;
}