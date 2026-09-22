/* Server listing, matching, and interactive selection. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "json.h"
#include "oidc.h"
#include "util.h"   /* oidc_eprintf is err_printf (oidc.h) */

/* display width: East Asian wide/fullwidth codepoints count as 2 columns */
static int utf8_width(const char *s)
{
    int w = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p;) {
        uint32_t cp;
        if (*p < 0x80) {
            cp = *p++;
        } else if ((*p & 0xE0) == 0xC0) {
            if (!p[1])
                break;
            cp = ((uint32_t)(*p & 0x1F) << 6) | (p[1] & 0x3F);
            p += 2;
        } else if ((*p & 0xF0) == 0xE0) {
            if (!p[1] || !p[2])
                break;
            cp = ((uint32_t)(*p & 0x0F) << 12) |
                 ((uint32_t)(p[1] & 0x3F) << 6) | (p[2] & 0x3F);
            p += 3;
        } else {
            if (!p[1] || !p[2] || !p[3])
                break;
            cp = ((uint32_t)(*p & 0x07) << 18) |
                 ((uint32_t)(p[1] & 0x3F) << 12) |
                 ((uint32_t)(p[2] & 0x3F) << 6) | (p[3] & 0x3F);
            p += 4;
        }
        int wide = (cp >= 0x1100 && cp <= 0x115F) ||
                   (cp >= 0x2E80 && cp <= 0xA4CF) ||
                   (cp >= 0xAC00 && cp <= 0xD7A3) ||
                   (cp >= 0xF900 && cp <= 0xFAFF) ||
                   (cp >= 0xFE30 && cp <= 0xFE4F) ||
                   (cp >= 0xFF00 && cp <= 0xFF60) ||
                   (cp >= 0xFFE0 && cp <= 0xFFE6);
        w += wide ? 2 : 1;
    }
    return w;
}

/* R37-FIX-B1 (R1-D-a-2 / R1-D-5): the server name/host are remote
 * controlled (controller /m/config, or a hand-edited servers.json where
 * \u001b etc. is decoded back to raw bytes) and were printf()d verbatim:
 * ESC/BEL/CR/LF/OSC sequences let a name retitle the terminal, clear the
 * screen or forge extra "server" lines in the --all selection list.
 * Replace every control byte with '?' like auth.c does for peer-supplied
 * text — but unlike that byte-wise filter, walk valid UTF-8 sequences as
 * units: U+0080..U+009F (C1, still an 8-bit CSI on some terminals) is
 * neutralized whether it arrives raw or as a legal 2-byte sequence, while
 * ordinary multi-byte text (Chinese names included) is copied untouched.
 * Only the display path uses this; matching/storage keep the raw value.
 *
 * R37-WG-E1 (L28): promoted from a file-static helper to the shared one
 * declared in oidc.h — every remote-controlled string that can reach a
 * terminal must go through the same filter, not just the --list rows.
 * R37-WG-E1 (L39): the sequence walk now also rejects non-shortest forms,
 * UTF-16 surrogates and codepoints above U+10FFFF. A lenient decoder
 * maps e0 81 9b back to ESC (3-byte overlong) and f0 80 81 9b back to
 * ESC (4-byte overlong), so without these checks the byte-wise control
 * filter below could be bypassed by re-encoding the control character.
 * The codepoint is already accumulated when the checks run, so they are
 * pure range tests, and a rejected sequence falls through to the
 * existing byte-wise '?' path exactly like a stray lead byte. */
char *oidc_printable_dup(const char *s)
{
    size_t n = strlen(s);
    char *out = malloc(n + 1);
    if (!out)
        oom_abort();
    size_t o = 0;
    for (size_t i = 0; i < n;) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x80) {
            out[o++] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
            i++;
            continue;
        }
        /* valid UTF-8 lead? 0xC0/0xC1 and 0xF5.. can only start an
         * overlong/out-of-range sequence, so they are not text either */
        size_t need = (c >= 0xC2 && c <= 0xDF) ? 2 :
                      (c >= 0xE0 && c <= 0xEF) ? 3 :
                      (c >= 0xF0 && c <= 0xF4) ? 4 : 0;
        uint32_t cp = 0;
        if (need) {
            if (need > n - i) {
                need = 0;            /* truncated sequence at the end */
            } else {
                cp = (uint32_t)(c & (0xFFu >> (need + 1)));
                size_t k = 1;
                while (k < need && ((unsigned char)s[i + k] & 0xC0) == 0x80) {
                    cp = (cp << 6) |
                         (uint32_t)((unsigned char)s[i + k] & 0x3F);
                    k++;
                }
                if (k != need)
                    need = 0;        /* bad continuation byte */
            }
        }
        if (need) {
            /* L39: a well-formed-looking sequence is still not text when
             * it decodes to something other than a scalar value. A 2-byte
             * overlong is already impossible (the lead must be >= 0xC2,
             * so cp >= 0x80), the other three widths are not. */
            if ((need == 3 && cp < 0x800) ||        /* overlong 3-byte */
                (need == 4 && cp < 0x10000) ||      /* overlong 4-byte */
                (cp >= 0xD800 && cp <= 0xDFFF) ||   /* UTF-16 surrogate */
                cp > 0x10FFFF)                      /* not a codepoint */
                need = 0;
        }
        if (need) {
            if (cp >= 0x80 && cp <= 0x9F) {
                out[o++] = '?';      /* C1 control, whatever its encoding */
            } else {
                memcpy(out + o, s + i, need);
                o += need;
            }
            i += need;
        } else {
            out[o++] = '?';          /* stray lead/continuation byte */
            i++;
        }
    }
    out[o] = '\0';
    return out;
}

void oidc_print_servers(Json *servers)
{
    size_t n = json_arr_len(servers);
    for (size_t i = 0; i < n; i++) {
        Json *s = json_arr_at(servers, i);
        const char *name = json_get_str(s, "name");
        const char *host = json_get_str(s, "host");
        Json *portj = json_get(s, "port");
        /* L9 (bughunt, #7): never cast a raw double -> unsigned long —
         * a local servers.json "port":1e19 would be UB. Validate in the
         * numeric domain; a broken/missing value prints the default. */
        long port = OIDC_DEFAULT_PORT;
        if (portj && json_type(portj) == JSON_NUM) {
            double dv = json_num(portj);
            if (dv >= 1.0 && dv <= 65535.0 &&
                dv == (double)(long)dv)
                port = (long)dv;
        } else if (portj && json_type(portj) == JSON_STR) {
            char *end = NULL;
            errno = 0;
            long pv = strtol(json_str(portj), &end, 10);
            if (errno == 0 && end != json_str(portj) && *end == '\0' &&
                pv >= 1 && pv <= 65535)
                port = pv;
        }
        const char *nm = name ? name : "";
        char *nm_s = oidc_printable_dup(nm);
        char *host_s = oidc_printable_dup(host ? host : "");
        int w = utf8_width(nm_s);
        int pad = w < 30 ? 30 - w : 0;
        printf("%2llu. %s%*s %s:%lu\n", (unsigned long long)(i + 1),
               nm_s, pad, "", host_s, (unsigned long)port);
        free(nm_s);
        free(host_s);
    }
}

/* structured match of one server entry against a "host:port" spec
 * (unbracketed, case-insensitive host, numeric port); the entry on
 * match, NULL otherwise. A broken port value dies only when the spec
 * actually addresses this entry by host. */
static Json *match_host_port(Json *s, const char *spec, const char *last,
                             const char *name, const char *host)
{
    char sb[64], s2[64], hb[64];
    uint16_t sport;
    size_t hlen = (size_t)(last - spec);
    if (hlen >= sizeof sb)
        return NULL;
    if (str_to_u16(last + 1, &sport) != 0)
        return NULL;   /* non-numeric port: no structured match */
    memcpy(sb, spec, hlen);
    sb[hlen] = '\0';
    const char *shost = unbracket_ipv6(sb, s2, sizeof s2);
    const char *hhost = unbracket_ipv6(host, hb, sizeof hb);
    uint16_t hport;
    double pv;
    int pr = oidc_server_port(s, &hport, &pv);
    if (pr < 0) {
        /* a broken port only matters if this entry is the one
         * the spec addresses by host */
        if (strcasecmp(shost, hhost) == 0) {
            /* R37-FIX-B1: the same remote-controlled name reaches the
             * terminal here through oidc_die (which exits, so the
             * printable copy needs no free) */
            oidc_die("invalid port %g for server \"%s\" "
                     "(must be an integer in 1..65535)",
                     pv, oidc_printable_dup(name ? name : host));
        }
        return NULL;
    }
    if (pr == 0)
        hport = OIDC_DEFAULT_PORT;
    if (sport == hport && strcasecmp(shost, hhost) == 0)
        return s;
    return NULL;
}

/* match a line by exact name, or structurally by host:port */
Json *oidc_find_server(Json *servers, const char *spec)
{
    size_t n = json_arr_len(servers);
    const char *last = strrchr(spec, ':');
    for (size_t i = 0; i < n; i++) {
        Json *s = json_arr_at(servers, i);
        const char *name = json_get_str(s, "name");
        const char *host = json_get_str(s, "host");
        if (name && strcmp(name, spec) == 0)
            return s;
        if (last && host) {
            Json *m = match_host_port(s, spec, last, name, host);
            if (m)
                return m;
        }
    }
    return NULL;
}

Json *oidc_select_server(Json *servers)
{
    size_t n = json_arr_len(servers);
    for (;;) {
        printf("  Select server [1-%llu]: ", (unsigned long long)n);
        fflush(stdout);
        char buf[32];
        if (!fgets(buf, sizeof buf, stdin))
            oidc_die("read server selection");
        char *end;
        long v = strtol(buf, &end, 10);
        if (end != buf && v >= 1 && (size_t)v <= n)
            return json_arr_at(servers, (size_t)(v - 1));
        oidc_eprintf("  invalid selection\n");
    }
}
