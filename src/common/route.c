#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"
#include "route.h"
#include "util.h"

#ifdef _WIN32
/* Windows backend: winsock2 (via port.h, included above) must precede
 * iphlpapi.h. Route/address changes go through netsh (port_run_cmd);
 * default-route and adapter discovery use the IP Helper API. */
#  include <iphlpapi.h>
#  include <windows.h>
#else
#  include <arpa/inet.h>
#endif

#ifdef _WIN32
/* ------------------------- Windows helpers ------------------------ */

/* Run netsh with NULL-terminated argv (argv[0] = "netsh"). Returns true
 * when netsh exited 0; logs the exit code otherwise. */
static bool netsh_run(char *const argv[], const char *what)
{
    int rc = port_run_cmd(argv);
    if (rc != 0) {
        log_err("%s failed (netsh exit %d)", what, rc);
        return false;
    }
    return true;
}

/* canonical "a.b.c.d/plen" prefix string (net masked to the network) */
static void prefix_str(uint32_t net, int prefix, char out[24])
{
    uint8_t b[4];
    u32_ip4(net, b);
    snprintf(out, 24, "%u.%u.%u.%u/%d", b[0], b[1], b[2], b[3], prefix);
}

#endif /* _WIN32 */

/* bring the tunnel interface up with an address and MTU (no routes):
 * addr flush / link up / mtu / addr add. Shared by route_setup (which
 * then installs routes) and the no-route-hijack pump path in proxy.c.
 * Returns false when a step failed (state partially applied). */
#ifdef _WIN32
bool route_iface_up(const char *tun, const char *tun_ip, uint16_t mtu)
{
    char namea[32], mtu_s[8], mtuarg[24];
    snprintf(namea, sizeof namea, "name=%s", tun);
    snprintf(mtu_s, sizeof mtu_s, "%u", (unsigned)mtu);
    snprintf(mtuarg, sizeof mtuarg, "mtu=%s", mtu_s);
    char *a1[] = { "netsh", "interface", "ipv4", "set", "address", namea,
                   "static", (char *)tun_ip, "255.255.255.0", NULL };
    if (!netsh_run(a1, "iface up: set address"))
        return false;
    char *a2[] = { "netsh", "interface", "ipv4", "set", "subinterface",
                   namea, mtuarg, NULL };
    if (!netsh_run(a2, "iface up: set mtu"))
        return false;
    return true;
}
#else
bool route_iface_up(const char *tun, const char *tun_ip, uint16_t mtu)
{
    char mtu_s[8], ip24[64];
    snprintf(mtu_s, sizeof mtu_s, "%u", (unsigned)mtu);
    snprintf(ip24, sizeof ip24, "%s/24", tun_ip);
    char *a1[] = { "addr", "flush", "dev", (char *)tun, NULL };
    if (!ip_run(a1)) {
        log_err("iface up: addr flush dev %s failed", tun);
        return false;
    }
    char *a2[] = { "link", "set", (char *)tun, "up", NULL };
    if (!ip_run(a2)) {
        log_err("iface up: link set %s up failed", tun);
        return false;
    }
    char *a3[] = { "link", "set", "dev", (char *)tun, "mtu", mtu_s, NULL };
    if (!ip_run(a3)) {
        log_err("iface up: mtu %s on %s failed", mtu_s, tun);
        return false;
    }
    char *a4[] = { "addr", "add", ip24, "dev", (char *)tun, NULL };
    if (!ip_run(a4)) {
        log_err("iface up: addr add %s dev %s failed", ip24, tun);
        return false;
    }
    return true;
}
#endif /* _WIN32 */

/* take the tunnel interface down and flush its addresses (no routes).
 * Shared by route_teardown's tail and the no-route-hijack pump path. */
#ifdef _WIN32
void route_iface_down(const char *tun)
{
    char namea[32];
    snprintf(namea, sizeof namea, "name=%s", tun);
    char *d1[] = { "netsh", "interface", "ipv4", "delete", "address",
                   namea, NULL };
    port_run_cmd(d1);   /* best-effort: no address left, or iface gone */
}
#else
void route_iface_down(const char *tun)
{
    char *d5[] = { "addr", "flush", "dev", (char *)tun, NULL };
    ip_run(d5);
    char *d6[] = { "link", "set", (char *)tun, "down", NULL };
    ip_run(d6);
}
#endif /* _WIN32 */

/* strict "A.B.C.D/n" parser: exact dotted-quad, 0 <= n <= 32, no
 * trailing garbage. net is filled in host byte order (unmasked).
 * Pure string parsing (s2ip4/strtol): shared by both backends. */
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
    long p = strtol(slash + 1, &pend, 10);
    if (pend == slash + 1 || *pend != '\0' || p < 0 || p > 32)
        return -1;
    *net = ip4_u32(b);
    *prefix = (int)p;
    return 0;
}

#ifndef _WIN32
static void copy_token(char *dst, size_t cap, const char *tok) {
    size_t n = strlen(tok);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, tok, n);
    dst[n] = '\0';
}
#endif

#ifdef _WIN32
bool capture_default(char gw[16], char dev[16], char metric[16])
{
    MIB_IPFORWARDROW best;
    IP_ADAPTER_ADDRESSES *aa = NULL;
    ULONG buflen = 0;
    DWORD rc;
    bool found = false;

    gw[0] = dev[0] = metric[0] = '\0';   /* metric: "" when absent */
    memset(&best, 0, sizeof best);
    /* best route to 0.0.0.0 == the default route; the returned row's
     * address fields are in network byte order (the adapter-index-map
     * parameter only exists on newer SDKs and is never needed) */
    if (GetBestRoute(0, 0, &best) != NO_ERROR)
        return false;

    rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL,
                              &buflen);
    if (rc != NO_ERROR && rc != ERROR_BUFFER_OVERFLOW)
        return false;
    if (buflen == 0)
        return false;
    aa = malloc(buflen);
    if (aa == NULL)
        oom_abort();
    rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, aa,
                              &buflen);
    if (rc != NO_ERROR) {
        free(aa);
        return false;
    }

    if (best.dwForwardNextHop != 0) {
        inet_ntop(AF_INET, &best.dwForwardNextHop, gw, 16);
    }
    for (IP_ADAPTER_ADDRESSES *p = aa; p != NULL; p = p->Next) {
        if (p->IfIndex != best.dwForwardIfIndex)
            continue;
        found = true;
        /* friendly name -> UTF-8; names longer than 15 bytes fall back
         * to a stable if<index> handle (still usable with netsh) */
        if (!WideCharToMultiByte(CP_UTF8, 0, p->FriendlyName, -1, dev, 16,
                                 NULL, NULL) || dev[0] == '\0')
            snprintf(dev, 16, "if%lu", (unsigned long)p->IfIndex);
        if (gw[0] == '\0') {
            /* on-link default (nexthop 0.0.0.0): the gateway is the
             * interface's own address */
            for (IP_ADAPTER_UNICAST_ADDRESS *u = p->FirstUnicastAddress;
                 u != NULL; u = u->Next) {
                if (u->Address.lpSockaddr->sa_family != AF_INET)
                    continue;
                const struct sockaddr_in *sin =
                    (const struct sockaddr_in *)u->Address.lpSockaddr;
                inet_ntop(AF_INET, &sin->sin_addr, gw, 16);
                break;
            }
        }
        break;
    }
    if (!found) {
        free(aa);
        return false;
    }

    /* metric: total of the default row's metrics in the IPv4 forwarding
     * table (matching ifindex; the smallest total is the one in use) */
    ULONG tsz = 0;
    if (GetIpForwardTable(NULL, &tsz, FALSE) == ERROR_INSUFFICIENT_BUFFER &&
        tsz > 0) {
        MIB_IPFORWARDTABLE *tab = malloc(tsz);
        if (tab != NULL) {
            if (GetIpForwardTable(tab, &tsz, FALSE) == NO_ERROR) {
                uint64_t bestm = UINT64_MAX;
                for (DWORD i = 0; i < tab->dwNumEntries; i++) {
                    MIB_IPFORWARDROW *r = &tab->table[i];
                    if (r->dwForwardDest != 0 || r->dwForwardMask != 0)
                        continue;
                    if (r->dwForwardIfIndex != best.dwForwardIfIndex)
                        continue;
                    uint64_t m = (uint64_t)r->dwForwardMetric1 +
                                 r->dwForwardMetric2 + r->dwForwardMetric3 +
                                 r->dwForwardMetric4 + r->dwForwardMetric5;
                    if (m < bestm)
                        bestm = m;
                }
                if (bestm != UINT64_MAX) {
                    /* real route metrics are small; cap so the value
                     * always fits the 16-byte metric buffer */
                    if (bestm > UINT32_MAX)
                        bestm = UINT32_MAX;
                    snprintf(metric, 16, "%u", (unsigned)bestm);
                }
            }
            free(tab);
        }
    }
    free(aa);
    return gw[0] != '\0';
}
#else
bool capture_default(char gw[16], char dev[16], char metric[16]) {
    char *args[] = { "-4", "route", "show", "default", NULL };
    char *out = cmd_capture(args);
    if (out == NULL)
        return false;
    gw[0] = dev[0] = metric[0] = '\0';   /* metric: "" when absent */
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
        } else if (strcmp(tok, "metric") == 0) {
            char *nt = strtok_r(NULL, " \t\r\n", &save);
            if (nt != NULL)
                copy_token(metric, 16, nt);
        }
    }
    free(out);
    return got_gw && got_dev;
}
#endif /* _WIN32 */

#ifdef _WIN32
bool local_subnet(const char *dev, char out[24])
{
    ULONG buflen = 0;
    IP_ADAPTER_ADDRESSES *aa = NULL;
    DWORD rc;
    bool found = false;

    out[0] = '\0';
    rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL,
                              &buflen);
    if (rc != NO_ERROR && rc != ERROR_BUFFER_OVERFLOW)
        return false;
    if (buflen == 0)
        return false;
    aa = malloc(buflen);
    if (aa == NULL)
        oom_abort();
    rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, aa,
                              &buflen);
    if (rc != NO_ERROR) {
        free(aa);
        return false;
    }
    for (IP_ADAPTER_ADDRESSES *p = aa; p != NULL; p = p->Next) {
        char d16[16];
        d16[0] = '\0';
        WideCharToMultiByte(CP_UTF8, 0, p->FriendlyName, -1, d16,
                            sizeof d16, NULL, NULL);
        if (strcmp(d16, dev) != 0)
            continue;
        for (IP_ADAPTER_UNICAST_ADDRESS *u = p->FirstUnicastAddress;
             u != NULL; u = u->Next) {
            if (u->Address.lpSockaddr->sa_family != AF_INET)
                continue;
            const struct sockaddr_in *sin =
                (const struct sockaddr_in *)u->Address.lpSockaddr;
            char ip[16];
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip);
            unsigned plen = u->OnLinkPrefixLength;
            if (plen > 32)
                plen = 32;
            snprintf(out, 24, "%s/%u", ip, plen);
            found = true;
            goto done;
        }
    }
done:
    free(aa);
    return found;
}
#else
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
            /* parse "ip/plen" without mutating the cmd_capture buffer:
             * strndup the address part, then free it on every exit */
            char *slash = strchr(cidr, '/');
            if (slash == NULL)
                break;
            char *ip = strndup(cidr, (size_t)(slash - cidr));
            if (ip == NULL) {
                oom_abort();
                break;
            }
            uint8_t b[4];
            if (!s2ip4(ip, b)) {
                free(ip);
                break;
            }
            char *pend;
            long p = strtol(slash + 1, &pend, 10);
            free(ip);
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
#endif /* _WIN32 */

#ifdef _WIN32
bool route_setup(const char *tun, const char *tun_ip, uint16_t mtu,
                 const char *srv, const char *ogw, const char *odev,
                 const char *metric, const slist_t *routes_with_default)
{
    char tun_if[32], nh[40];
    struct in_addr s4;

    (void)metric;   /* Windows keeps the physical default in the table;
                     * teardown deletes only our own route, so there is
                     * nothing to restore (see route_teardown) */
    snprintf(tun_if, sizeof tun_if, "interface=%s", tun);
    snprintf(nh, sizeof nh, "nexthop=%s", tun_ip);

    /* every step mutates system state, so a failure must stop the
     * sequence and undo what was applied (mirror the Linux sequence) */
    if (!route_iface_up(tun, tun_ip, mtu)) {
        route_iface_down(tun);   /* undo any partial bring-up */
        return false;            /* nothing applied yet */
    }

    /* the server-pinned /32 only exists in the IPv4 table; an IPv6
     * server address cannot be pinned via the (IPv4) default gateway */
    if (inet_pton(AF_INET, srv, &s4) == 1 &&
        (ntohl(s4.s_addr) >> 24) != 127) {
        char srv32[40], odev_if[32], pin_nh[40];
        snprintf(srv32, sizeof srv32, "%s/32", srv);
        snprintf(odev_if, sizeof odev_if, "interface=%s", odev);
        char *del[] = { "netsh", "interface", "ipv4", "delete", "route",
                        srv32, odev_if, NULL };
        port_run_cmd(del);   /* idempotent setup: drop any stale pin */
        char *pin[10];
        int pi = 0;
        pin[pi++] = "netsh";
        pin[pi++] = "interface";
        pin[pi++] = "ipv4";
        pin[pi++] = "add";
        pin[pi++] = "route";
        pin[pi++] = srv32;
        pin[pi++] = odev_if;
        if (strcmp(ogw, "0.0.0.0") != 0) {
            snprintf(pin_nh, sizeof pin_nh, "nexthop=%s", ogw);
            pin[pi++] = pin_nh;
        }
        pin[pi] = NULL;
        if (!netsh_run(pin, "route_setup: pin server route")) {
            route_iface_down(tun);
            return false;
        }
    }

    for (size_t i = 0; i < routes_with_default->n; i++) {
        const char *c = routes_with_default->v[i];
        if (strcmp(c, "default") == 0 || strcmp(c, "0.0.0.0/0") == 0) {
            /* replace the default: a metric-0 route via the tunnel
             * outranks the physical default, which is never removed */
            char *del[] = { "netsh", "interface", "ipv4", "delete",
                            "route", "0.0.0.0/0", tun_if, NULL };
            port_run_cmd(del);   /* idempotent replace */
            char *add[] = { "netsh", "interface", "ipv4", "add", "route",
                            "0.0.0.0/0", tun_if, nh, "metric=0", NULL };
            if (!netsh_run(add, "route_setup: default via tun"))
                goto rollback;
        } else {
            uint32_t net;
            int prefix;
            if (cidr_parse(c, &net, &prefix) != 0) {
                log_err("route_setup: invalid route target '%s'", c);
                goto rollback;
            }
            /* canonical network address (host bits cleared) */
            uint32_t mask = prefix == 0
                                ? 0
                                : ~((1u << (32 - prefix)) - 1);
            char prefix_s[24];
            prefix_str(net & mask, prefix, prefix_s);
            /* netsh has no "replace" verb: delete-then-add makes setup
             * idempotent and clears routes a crashed run left behind */
            char *del[] = { "netsh", "interface", "ipv4", "delete",
                            "route", prefix_s, tun_if, NULL };
            port_run_cmd(del);
            char *add[] = { "netsh", "interface", "ipv4", "add", "route",
                            prefix_s, tun_if, nh, NULL };
            if (!netsh_run(add, "route_setup: add route"))
                goto rollback;
        }
    }
    return true;

rollback:
    /* the loop applied at least one route: drop every entry it may have
     * installed (route_teardown tolerates entries never applied), then
     * tear the device down below */
    log_err("route_setup: rolling back applied routes");
    route_teardown(tun, srv, ogw, odev, metric, routes_with_default);
    return false;
}
#else
bool route_setup(const char *tun, const char *tun_ip, uint16_t mtu,
                 const char *srv, const char *ogw, const char *odev,
                 const char *metric, const slist_t *routes_with_default) {
    char srv32[64];
    struct in_addr s4;
    bool srv_v4 = inet_pton(AF_INET, srv, &s4) == 1;
    /* loopback servers (e.g. --server 127.0.0.1 when client and server
     * share a host) are local: no /32 pin is needed, and the kernel
     * rejects `ip route add 127.0.0.1/32 via <gw>` (EEXIST against the
     * local table), which would roll back the whole setup */
    bool srv_lo = srv_v4 && (ntohl(s4.s_addr) >> 24) == 127;
    snprintf(srv32, sizeof srv32, "%s/32", srv);
    char *fc[] = { "route", "flush", "cache", NULL };

    /* every step mutates system state, so a failure must stop the
     * sequence and undo what was applied; a half-configured tunnel
     * (e.g. routes replaced but no srv route) would otherwise claim to
     * be up while the machine has no working path to the server */
    if (!route_iface_up(tun, tun_ip, mtu)) {
        route_iface_down(tun);   /* undo any partial bring-up */
        return false;            /* nothing applied yet */
    }
    /* the server-pinned /32 only exists in the IPv4 table; an IPv6
     * server address cannot be routed via the (IPv4) default gateway
     * and would fail every `ip route add` attempt, so skip it */
    if (srv_v4 && !srv_lo) {
        char *a5[] = { "route", "add", srv32, "via", (char *)ogw, "dev",
                       (char *)odev, NULL };
        if (!ip_run(a5)) {
            log_err("route_setup: route add %s via %s dev %s failed",
                    srv32, ogw, odev);
            route_iface_down(tun);
            return false;
        }
    }

    for (size_t i = 0; i < routes_with_default->n; i++) {
        const char *c = routes_with_default->v[i];
        if (strcmp(c, "default") == 0 || strcmp(c, "0.0.0.0/0") == 0) {
            char loc[24];
            if (local_subnet(odev, loc)) {
                char *r1[] = { "route", "replace", loc, "dev", (char *)odev,
                               NULL };
                if (!ip_run(r1)) {
                    log_err("route_setup: route replace %s dev %s failed "
                            "(local subnet must not route via the tunnel)",
                            loc, odev);
                    goto rollback_routes;
                }
                log_info("preserved local subnet %s", loc);
            } else {
                log_debug("route_setup: no local subnet on %s to preserve",
                          odev);
            }
            char *r2[] = { "route", "replace", "default", "dev",
                           (char *)tun, NULL };
            if (!ip_run(r2)) {
                log_err("route_setup: route replace default dev %s failed",
                        tun);
                goto rollback_routes;
            }
        } else {
            char *r3[] = { "route", "replace", (char *)c, "dev",
                           (char *)tun, NULL };
            if (!ip_run(r3)) {
                log_err("route_setup: route replace %s dev %s failed", c,
                        tun);
                goto rollback_routes;
            }
        }
    }
    /* flush the route cache once, after every route is in place (the
     * per-route flush in the old code restarted the cache 1..N times
     * for no observable benefit) */
    ip_run(fc);
    return true;

rollback_routes:
    /* the loop replaced at least one route: restore the pre-VPN default
     * and drop every entry the loop may have installed (route_teardown
     * tolerates entries that were never applied), then tear the device
     * down below */
    log_err("route_setup: rolling back applied routes");
    route_teardown(tun, srv, ogw, odev, metric, routes_with_default);
    return false;
}
#endif /* _WIN32 */

#ifdef _WIN32
void route_teardown(const char *tun, const char *srv, const char *ogw,
                    const char *odev, const char *metric,
                    const slist_t *routes)
{
    char tun_if[32];

    (void)ogw;
    (void)metric;
    snprintf(tun_if, sizeof tun_if, "interface=%s", tun);
    for (size_t i = 0; i < routes->n; i++) {
        const char *c = routes->v[i];
        if (strcmp(c, "default") == 0 || strcmp(c, "0.0.0.0/0") == 0) {
            /* the physical default was never removed, so deleting our
             * own 0.0.0.0/0 restores the pre-VPN routing automatically */
            char *d1[] = { "netsh", "interface", "ipv4", "delete",
                           "route", "0.0.0.0/0", tun_if, NULL };
            port_run_cmd(d1);   /* best-effort: ours may never have applied */
        } else {
            uint32_t net;
            int prefix;
            if (cidr_parse(c, &net, &prefix) != 0)
                continue;
            uint32_t mask = prefix == 0
                                ? 0
                                : ~((1u << (32 - prefix)) - 1);
            char prefix_s[24];
            prefix_str(net & mask, prefix, prefix_s);
            char *d2[] = { "netsh", "interface", "ipv4", "delete",
                           "route", prefix_s, tun_if, NULL };
            port_run_cmd(d2);   /* best-effort */
        }
    }
    /* drop the server pin installed on the physical NIC by route_setup */
    struct in_addr s4;
    if (inet_pton(AF_INET, srv, &s4) == 1 &&
        (ntohl(s4.s_addr) >> 24) != 127) {
        char srv32[40], odev_if[32];
        snprintf(srv32, sizeof srv32, "%s/32", srv);
        snprintf(odev_if, sizeof odev_if, "interface=%s", odev);
        char *d3[] = { "netsh", "interface", "ipv4", "delete", "route",
                       srv32, odev_if, NULL };
        port_run_cmd(d3);
    }
    route_iface_down(tun);
}
#else
void route_teardown(const char *tun, const char *srv, const char *ogw,
                    const char *odev, const char *metric,
                    const slist_t *routes) {
    for (size_t i = 0; i < routes->n; i++) {
        const char *c = routes->v[i];
        if (strcmp(c, "default") == 0 || strcmp(c, "0.0.0.0/0") == 0) {
            char *d1[] = { "route", "del", "default", NULL };
            if (!ip_run(d1)) {
                /* the default route was not ours to remove (never
                 * replaced, or already gone): leave whatever is there
                 * alone — deleting it here would strand the machine */
                continue;
            }
            /* we removed it: restore the original via-gateway route,
             * keeping its metric (captured by capture_default) so route
             * precedence matches the pre-VPN state — a metric-less
             * restore would install a priority-0 default that shadows
             * (or is shadowed by) other defaults */
            char *d2[10];
            int di = 0;
            d2[di++] = "route";
            d2[di++] = "add";
            d2[di++] = "default";
            d2[di++] = "via";
            d2[di++] = (char *)ogw;
            d2[di++] = "dev";
            d2[di++] = (char *)odev;
            if (metric[0] != '\0') {
                d2[di++] = "metric";
                d2[di++] = (char *)metric;
            }
            d2[di] = NULL;
            if (!ip_run(d2)) {
                /* the original gateway may have vanished while the VPN
                 * was up (wifi switch, NIC down): fall back to a
                 * device-only default route so the machine is never
                 * left with NO default route at all */
                log_err("route_teardown: restore default via %s dev %s "
                        "failed — trying device-only default",
                        ogw, odev);
                char *d2b[] = { "route", "replace", "default", "dev",
                                (char *)odev, NULL };
                if (!ip_run(d2b))
                    log_err("route_teardown: NO default route after "
                            "teardown; fix manually: ip route add "
                            "default via %s dev %s", ogw, odev);
            }
        } else {
            char *d3[] = { "route", "del", (char *)c, NULL };
            if (!ip_run(d3))
                log_debug("route_teardown: route del %s: not present", c);
        }
    }
    char srv32[64];
    struct in_addr s4;
    snprintf(srv32, sizeof srv32, "%s/32", srv);
    if (inet_pton(AF_INET, srv, &s4) == 1 &&
        (ntohl(s4.s_addr) >> 24) != 127) {
        char *d4[] = { "route", "del", srv32, NULL };
        if (!ip_run(d4))
            log_debug("route_teardown: route del %s: not present", srv32);
    }
    route_iface_down(tun);
    char *fc[] = { "route", "flush", "cache", NULL };
    ip_run(fc);
}
#endif /* _WIN32 */
