#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"
#include "route.h"
#include "util.h"

static void copy_token(char *dst, size_t cap, const char *tok) {
    size_t n = strlen(tok);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, tok, n);
    dst[n] = '\0';
}

bool capture_default(char gw[16], char dev[16]) {
    char *args[] = { "-4", "route", "show", "default", NULL };
    char *out = cmd_capture(args);
    if (out == NULL)
        return false;
    bool got_gw = false, got_dev = false;
    char *save = NULL;
    for (char *tok = strtok_r(out, " \t\r\n", &save); tok != NULL;
         tok = strtok_r(NULL, " \t\r\n", &save)) {
        if (strcmp(tok, "via") == 0) {
            char *nt = strtok_r(NULL, " \t\r\n", &save);
            if (nt != NULL) {
                copy_token(gw, 16, nt);
                got_gw = true;
            }
        } else if (strcmp(tok, "dev") == 0) {
            char *nt = strtok_r(NULL, " \t\r\n", &save);
            if (nt != NULL) {
                copy_token(dev, 16, nt);
                got_dev = true;
            }
        }
    }
    free(out);
    return got_gw && got_dev;
}

bool local_subnet(const char *dev, char out[24]) {
    char *args[] = { "-4", "addr", "show", "dev", (char *)dev, NULL };
    char *cap = cmd_capture(args);
    if (cap == NULL)
        return false;
    bool ok = false;
    char *lsave = NULL;
    for (char *line = strtok_r(cap, "\n", &lsave); line != NULL;
         line = strtok_r(NULL, "\n", &lsave)) {
        char *save = NULL;
        for (char *tok = strtok_r(line, " \t\r\n", &save); tok != NULL;
             tok = strtok_r(NULL, " \t\r\n", &save)) {
            if (strcmp(tok, "inet") != 0)
                continue;
            char *cidr = NULL;
            for (char *nt = strtok_r(NULL, " \t\r\n", &save); nt != NULL;
                 nt = strtok_r(NULL, " \t\r\n", &save)) {
                if (strchr(nt, '/') != NULL) {
                    cidr = nt;
                    break;
                }
            }
            if (cidr == NULL)
                break;
            char *slash = strchr(cidr, '/');
            *slash = '\0';
            uint8_t b[4];
            if (!s2ip4(cidr, b)) {
                *slash = '/';
                break;
            }
            char *pend;
            long p = strtol(slash + 1, &pend, 10);
            *slash = '/';
            uint32_t plen;
            if (pend == slash + 1 || *pend != '\0' || p < 0)
                plen = 24;
            else if (p > 32)
                plen = 32;
            else
                plen = (uint32_t)p;
            uint32_t mask = plen == 0 ? 0 : ~((1u << (32 - plen)) - 1);
            uint32_t net = ip4_u32(b) & mask;
            uint8_t nb[4];
            u32_ip4(net, nb);
            snprintf(out, 24, "%u.%u.%u.%u/%u", nb[0], nb[1], nb[2], nb[3],
                     (unsigned)plen);
            ok = true;
            goto done;
        }
    }
done:
    free(cap);
    return ok;
}

void route_setup(const char *tun, const char *tun_ip, uint16_t mtu,
                 const char *srv, const char *ogw, const char *odev,
                 const slist_t *routes_with_default) {
    char mtu_s[8], ip24[64], srv32[64];
    snprintf(mtu_s, sizeof mtu_s, "%u", (unsigned)mtu);
    snprintf(ip24, sizeof ip24, "%s/24", tun_ip);
    snprintf(srv32, sizeof srv32, "%s/32", srv);

    char *a1[] = { "addr", "flush", "dev", (char *)tun, NULL };
    ip_run(a1);
    char *a2[] = { "link", "set", (char *)tun, "up", NULL };
    ip_run(a2);
    char *a3[] = { "link", "set", "dev", (char *)tun, "mtu", mtu_s, NULL };
    ip_run(a3);
    char *a4[] = { "addr", "add", ip24, "dev", (char *)tun, NULL };
    ip_run(a4);
    char *a5[] = { "route", "add", srv32, "via", (char *)ogw, "dev",
                   (char *)odev, NULL };
    ip_run(a5);
    char *fc[] = { "route", "flush", "cache", NULL };
    ip_run(fc);

    for (size_t i = 0; i < routes_with_default->n; i++) {
        const char *c = routes_with_default->v[i];
        if (strcmp(c, "default") == 0 || strcmp(c, "0.0.0.0/0") == 0) {
            char loc[24];
            if (local_subnet(odev, loc)) {
                char *r1[] = { "route", "replace", loc, "dev", (char *)odev,
                               NULL };
                ip_run(r1);
                log_info("preserved local subnet %s", loc);
            }
            char *r2[] = { "route", "replace", "default", "dev", (char *)tun,
                           NULL };
            ip_run(r2);
        } else {
            char *r3[] = { "route", "replace", (char *)c, "dev", (char *)tun,
                           NULL };
            ip_run(r3);
        }
        ip_run(fc);
    }
}

void route_teardown(const char *tun, const char *srv, const char *ogw,
                    const char *odev, const slist_t *routes) {
    for (size_t i = 0; i < routes->n; i++) {
        const char *c = routes->v[i];
        if (strcmp(c, "default") == 0 || strcmp(c, "0.0.0.0/0") == 0) {
            char *d1[] = { "route", "del", "default", NULL };
            ip_run(d1);
            char *d2[] = { "route", "add", "default", "via", (char *)ogw,
                           "dev", (char *)odev, NULL };
            ip_run(d2);
        } else {
            char *d3[] = { "route", "del", (char *)c, NULL };
            ip_run(d3);
        }
    }
    char srv32[64];
    snprintf(srv32, sizeof srv32, "%s/32", srv);
    char *d4[] = { "route", "del", srv32, NULL };
    ip_run(d4);
    char *d5[] = { "addr", "flush", "dev", (char *)tun, NULL };
    ip_run(d5);
    char *d6[] = { "link", "set", (char *)tun, "down", NULL };
    ip_run(d6);
    char *fc[] = { "route", "flush", "cache", NULL };
    ip_run(fc);
}
