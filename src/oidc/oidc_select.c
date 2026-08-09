/* Server listing, matching, and interactive selection. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "json.h"
#include "oidc.h"

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

void oidc_print_servers(Json *servers)
{
    size_t n = json_arr_len(servers);
    for (size_t i = 0; i < n; i++) {
        Json *s = json_arr_at(servers, i);
        const char *name = json_get_str(s, "name");
        const char *host = json_get_str(s, "host");
        Json *portj = json_get(s, "port");
        unsigned long port = portj ? (unsigned long)json_num(portj) : 0;
        const char *nm = name ? name : "";
        int w = utf8_width(nm);
        int pad = w < 30 ? 30 - w : 0;
        printf("%2zu. %s%*s %s:%lu\n", i + 1, nm, pad, "",
               host ? host : "", port);
    }
}

/* match a line by exact name, or structurally by host:port
 * (unbracketed, case-insensitive host, numeric port) */
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
            char sb[64], s2[64], hb[64];
            uint16_t sport;
            size_t hlen = (size_t)(last - spec);
            if (hlen >= sizeof sb)
                continue;
            if (str_to_u16(last + 1, &sport) != 0)
                continue;   /* non-numeric port: no structured match */
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
                if (strcasecmp(shost, hhost) == 0)
                    oidc_die("invalid port %g for server \"%s\" "
                             "(must be an integer in 1..65535)",
                             pv, name ? name : host);
                continue;
            }
            if (pr == 0)
                hport = OIDC_DEFAULT_PORT;
            if (sport == hport && strcasecmp(shost, hhost) == 0)
                return s;
        }
    }
    return NULL;
}

Json *oidc_select_server(Json *servers)
{
    size_t n = json_arr_len(servers);
    for (;;) {
        printf("  Select server [1-%zu]: ", n);
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