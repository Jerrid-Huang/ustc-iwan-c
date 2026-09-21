#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"
#include "route_common.h"
#include "util.h"

/* Strict "A.B.C.D/n" parser: exact dotted-quad, 0 <= n <= 32, no
 * trailing garbage. net is filled in host byte order (unmasked).
 * Pure string parsing (s2ip4/strtol): shared across all platforms. */
int cidr_parse(const char *s, uint32_t *net, int *prefix)
{
    const char *slash = strchr(s, '/');
    if (slash == NULL || slash == s || strchr(slash + 1, '/') != NULL)
        return -1;
    size_t ilen = (size_t)(slash - s);
    if (ilen == 0 || ilen >= 16)
        return -1;
    char ip[16];
    memcpy(ip, s, ilen);
    ip[ilen] = '\0';
    uint8_t b[4];
    if (!s2ip4(ip, b))
        return -1;
    char *pend;
    if (slash[1] < '0' || slash[1] > '9')
        return -1;   /* strict: reject "/ 8" and "/+8" */
    long p = strtol(slash + 1, &pend, 10);
    if (pend == slash + 1 || *pend != '\0' || p < 0 || p > 32)
        return -1;
    *net = ip4_u32(b);
    /* R23-F3 F2: a /0 that is not 0.0.0.0/0 is a typo, not a route — the
     * canonicalization later turns ANY /0 into a default route on all
     * three backends, so accepting "1.2.3.4/0" would silently replace the
     * real default with one via the tunnel. Only the true 0.0.0.0/0 is
     * legal. */
    if (p == 0 && *net != 0)
        return -1;
    *prefix = (int)p;
    return 0;
}

bool canon_v4_cidr(const char *c, char out[24])
{
    uint32_t net;
    int prefix;
    if (cidr_parse(c, &net, &prefix) != 0)
        return false;
    uint32_t mask = prefix == 0 ? 0 : ~((1u << (32 - prefix)) - 1);
    uint32_t canon = net & mask;
    snprintf(out, 24, "%u.%u.%u.%u/%d", (canon >> 24) & 0xFF,
             (canon >> 16) & 0xFF, (canon >> 8) & 0xFF, canon & 0xFF,
             prefix);
    return true;
}

bool tun_ula_str(const char *tun_ip, char out[64])
{
    uint8_t v4[4], b6[16];
    if (!s2ip4(tun_ip, v4))
        return false;
    ip6_derive_ula(ip4_u32(v4), b6);
    snprintf(out, 64,
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             b6[0], b6[1], b6[2], b6[3], b6[4], b6[5], b6[6], b6[7],
             b6[8], b6[9], b6[10], b6[11], b6[12], b6[13], b6[14], b6[15]);
    return true;
}

bool is_default_v4(const char *c)
{
    return strcmp(c, "default") == 0 || strcmp(c, "0.0.0.0/0") == 0;
}

void copy_token(char *dst, size_t cap, const char *tok)
{
    size_t n = strlen(tok);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, tok, n);
    dst[n] = '\0';
}
