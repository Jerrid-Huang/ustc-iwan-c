#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"
#include "route.h"
#include "route_common.h"
#include "tun.h"
#include "util.h"

/* Linux/POSIX session state: whether THIS process actually installed the
 * tunnel default route and/or the server /32 pin during route_setup.
 * route_teardown must never remove a route this process did not install;
 * in particular, when route_setup fails BEFORE replacing the default, the
 * rollback must leave the pre-existing physical default(s) completely
 * untouched (an unqualified `route del default` would delete the real
 * default and strand the machine). Each flag is set only after the
 * matching install command succeeds and cleared by route_teardown, so a
 * later session starts clean. */
static bool srv_default_installed;
static bool srv_pin_installed;

/* best-effort: give the tunnel interface its IPv6 side (the derived
 * ULA/96). The /96 makes the whole client pool on-link, so the kernel
 * routes v6 return traffic into the tunnel without extra routes. */
static void tun_iface_up6(const char *tun, const char *tun_ip)
{
    char ula[64], ula96[72];
    if (!tun_ula_str(tun_ip, ula))
        return;
    snprintf(ula96, sizeof ula96, "%s/96", ula);
    (void)ip_run((char *[]){"-6", "addr", "add", ula96,
                            "dev", (char *)tun, NULL});
}

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
    tun_iface_up6(tun, tun_ip);   /* best-effort IPv6 side */
    return true;
}

void route_iface_down(const char *tun)
{
    char *d5[] = { "addr", "flush", "dev", (char *)tun, NULL };
    ip_run(d5);
    char *d6[] = { "link", "set", (char *)tun, "down", NULL };
    ip_run(d6);
}

bool capture_default(char gw[16], char dev[16], char metric[16]) {
    char *args[] = { "-4", "route", "show", "default", NULL };
    char *out = cmd_capture(args);
    if (out == NULL)
        return false;
    gw[0] = dev[0] = metric[0] = '\0';   /* metric: "" when absent */
    bool got_gw = false, got_dev = false;
    char *lsave = NULL;
    /* One default route per line ("default via 10.0.2.2 dev enp0s3
     * proto dhcp metric 100"). Parse LINE BY LINE and take the first
     * line carrying both via and dev: the old token-stream parse could
     * mix via/dev/metric from different default routes on multi-homed
     * hosts, yielding a wrong gateway for the server pin or a bogus
     * restore route at teardown. */
    for (char *line = strtok_r(out, "\n", &lsave); line != NULL;
         line = strtok_r(NULL, "\n", &lsave)) {
        char *save = NULL;
        char *line_gw = NULL, *line_dev = NULL, *line_metric = NULL;
        for (char *tok = strtok_r(line, " \t\r", &save); tok != NULL;
             tok = strtok_r(NULL, " \t\r", &save)) {
            if (strcmp(tok, "via") == 0) {
                line_gw = strtok_r(NULL, " \t\r", &save);
            } else if (strcmp(tok, "dev") == 0) {
                line_dev = strtok_r(NULL, " \t\r", &save);
            } else if (strcmp(tok, "metric") == 0) {
                line_metric = strtok_r(NULL, " \t\r", &save);
            }
        }
        if (line_gw != NULL && line_dev != NULL) {
            copy_token(gw, 16, line_gw);
            copy_token(dev, 16, line_dev);
            if (line_metric != NULL)
                copy_token(metric, 16, line_metric);
            got_gw = true;
            got_dev = true;
            break;
        }
    }
    free(out);
    return got_gw && got_dev;
}

static bool local_subnet(const char *dev, char out[24]) {
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

bool route_setup(const char *tun, const char *tun_ip, uint16_t mtu,
                 const char *srv, const char *ogw, const char *odev,
                 const char *metric, const slist_t *routes_with_default,
                 const slist_t *routes6) {
    char srv32[64];
    struct in_addr s4;
    (void)routes6;   /* IPv6 policy routes are handled by route_setup6 */
    bool srv_v4 = inet_pton(AF_INET, srv, &s4) == 1;
    /* loopback servers (e.g. --server 127.0.0.1 when client and server
     * share a host) are local: no /32 pin is needed, and the kernel
     * rejects `ip route add 127.0.0.1/32 via <gw>` (EEXIST against the
     * local table), which would roll back the whole setup */
    bool srv_lo = srv_v4 && (ntohl(s4.s_addr) >> 24) == 127;
    snprintf(srv32, sizeof srv32, "%s/32", srv);
    char *fc[] = { "route", "flush", "cache", NULL };

    /* B-1/B-2: start a fresh session — neither the tunnel default nor
     * the server pin is installed yet, so if anything below fails before
     * we install them, the rollback (route_teardown) must not touch the
     * pre-existing routes (it only acts when the matching flag is set) */
    srv_default_installed = false;
    srv_pin_installed = false;

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
     * and would fail every `ip route add` attempt, so skip it.
     * M4 (SUMMARY-2): `replace` not `add` — a pin left behind by a
     * crashed client would make every later connection fail with
     * EEXIST (and the stale pin blackholes server traffic) */
    if (srv_v4 && !srv_lo) {
        char *a5[] = { "route", "replace", srv32, "via", (char *)ogw, "dev",
                       (char *)odev, NULL };
        if (!ip_run(a5)) {
            log_err("route_setup: route replace %s via %s dev %s failed",
                    srv32, ogw, odev);
            route_iface_down(tun);
            return false;
        }
        /* B-2: remember that WE now own this /32 — teardown may only
         * remove it (and only via the same via/dev attributes) when this
         * flag is set, so a pre-existing /32 that we never replaced is
         * never deleted by us */
        srv_pin_installed = true;
    }

    for (size_t i = 0; i < routes_with_default->n; i++) {
        const char *c = routes_with_default->v[i];
        if (is_default_v4(c)) {
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
            /* R1-C-C-1: deliberately NOT carrying `metric` here. A
             * metric-less replace installs a priority-0 tunnel default
             * that beats every metric>0 default (the hijack always
             * works) while the pre-VPN default stays in the table; if
             * the process dies the TUN device unregisters and takes its
             * route with it, so the untouched physical default
             * self-heals. Replacing the physical default at its own
             * metric instead would (a) lose it for good on a crash and
             * (b) fail to hijack when another lower-metric default
             * exists. The restore path below owns the pre-VPN entry. */
            char *r2[] = { "route", "replace", "default", "dev",
                           (char *)tun, NULL };
            if (!ip_run(r2)) {
                log_err("route_setup: route replace default dev %s failed",
                        tun);
                goto rollback_routes;
            }
            /* B-1: remember that we replaced the default with a tunnel
             * route (dev <tun>, no via). route_teardown may only delete
             * the default (and then restore the pre-VPN one) when this
             * flag is set, so a setup that fails before this point never
             * tears the pre-existing physical default away. */
            srv_default_installed = true;
        } else {
            char netstr[24];
            const char *target = c;
            if (canon_v4_cidr(c, netstr))
                target = netstr;
            char *r3[] = { "route", "replace", (char *)target, "dev",
                           (char *)tun, NULL };
            if (!ip_run(r3)) {
                log_err("route_setup: route replace %s dev %s failed", target,
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

void route_rollback_v6(const char *tun, const char *tun_ip,
                       const slist_t *routes6)
{
    (void)tun;
    (void)tun_ip;
    (void)routes6;
}

void route_teardown(const char *tun, const char *srv, const char *ogw,
                    const char *odev, const char *metric,
                    const slist_t *routes) {
    for (size_t i = 0; i < routes->n; i++) {
        const char *c = routes->v[i];
        if (is_default_v4(c)) {
            /* B-1: only ever remove a default that THIS process really
             * installed. route_setup sets srv_default_installed only
             * after `route replace default dev <tun>` succeeded, so when
             * setup failed before that step (rollback path) — or there
             * is simply no tunnel default from this session — the
             * pre-existing physical default(s) are left completely
             * untouched; the old unqualified `route del default` would
             * have deleted the real default and stranded the machine. */
            if (!srv_default_installed)
                continue;
            /* we did replace the default: clear the flag up front —
             * whether or not the delete below succeeds we no longer own
             * a tunnel default afterwards, so a later teardown (or a
             * fresh session) cannot act on stale state. */
            srv_default_installed = false;
            /* delete ONLY the tunnel default we installed, mirroring
             * setup's `route replace default dev <tun>`: qualifying with
             * `dev <tun>` means a multi-default host loses only our
             * entry (the old unqualified del was ambiguous there and
             * could remove an unrelated default on a single-default host
             * during a failed-setup rollback). */
            char *d1[] = { "route", "del", "default", "dev",
                           (char *)tun, NULL };
            if (!ip_run(d1)) {
                /* our tunnel default is already gone (crash cleanup, or
                 * the replace never took effect): leave whatever default
                 * is there alone */
                log_debug("route_teardown: no tunnel default on %s to "
                          "delete", tun);
                continue;
            }
            /* we removed it: restore the original via-gateway route,
             * keeping its metric (captured by capture_default) so route
             * precedence matches the pre-VPN state — a metric-less
             * restore would install a priority-0 default that shadows
             * (or is shadowed by) other defaults.
             *
             * R1-C-C-1: `replace`, NOT `add`. The kernel matches route
             * aliases by (prefix, dscp, fib_priority), so setup's
             * metric-less `replace default dev <tun>` does not replace a
             * DHCP default carrying e.g. metric 100 — both coexist and
             * the physical one is still in the table here. `add` would
             * then fail EEXIST and the device-only fallback below would
             * install a priority-0 on-link default that shadows the real
             * one: the host kept "a" default route but every off-link
             * packet went to ARP on the physical NIC (silent, host-wide
             * outage after a clean exit). `replace` is idempotent when
             * the original route is still present (rc=0, no change) and
             * re-creates it when it is genuinely gone, so the
             * destructive fallback is only reached when the kernel
             * really refuses the restore. */
            char *d2[10];
            int di = 0;
            d2[di++] = "route";
            d2[di++] = "replace";
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
            /* only remove the entry we installed on the tunnel dev; an
             * unqualified del could clobber a same-prefix route on
             * another device. The target is canonicalized exactly like
             * route_setup installs it (R1-C-C-2), so the delete always
             * addresses the key the kernel actually stored */
            char netstr[24];
            const char *target = c;
            if (canon_v4_cidr(c, netstr))
                target = netstr;
            char *d3[] = { "route", "del", (char *)target, "dev",
                           (char *)tun, NULL };
            if (!ip_run(d3))
                log_debug("route_teardown: route del %s: not present",
                          target);
        }
    }
    char srv32[64];
    struct in_addr s4;
    snprintf(srv32, sizeof srv32, "%s/32", srv);
    /* B-2: only remove the server /32 pin this process actually
     * installed — srv_pin_installed is set by route_setup right after
     * `route replace <srv>/32 via <ogw> dev <odev>` succeeds. The delete
     * mirrors setup's via/dev attributes, so a pre-existing /32 that is
     * not ours (or one pinned via another gateway/device) is never
     * touched by the teardown. */
    if (inet_pton(AF_INET, srv, &s4) == 1 &&
        (ntohl(s4.s_addr) >> 24) != 127 && srv_pin_installed) {
        char *d4[] = { "route", "del", srv32, "via", (char *)ogw, "dev",
                       (char *)odev, NULL };
        if (!ip_run(d4))
            log_debug("route_teardown: route del %s: not present", srv32);
        srv_pin_installed = false;
    }
    route_iface_down(tun);
    char *fc[] = { "route", "flush", "cache", NULL };
    ip_run(fc);
}

void route_setup6(const char *tun, const slist_t *routes6)
{
    if (routes6 == NULL)
        return;
    /* R49-L2: `replace`, not `add`, mirroring the v4 arm's metric-less
     * `route replace ... dev <tun>` (see the R1-C-C-1 note in route_setup,
     * route.c ~line 1096). `add` was broken in two ways on any dual-stack
     * host that already has a physical IPv6 default: the kernel applies
     * IP6_RT_PRIO_USER (1024) to a v6 netlink route whose RTA_PRIORITY is
     * absent (inet6_rtm_newroute), so (a) a `add ::/0` collided with an
     * RA default at the same 1024 and rtnetlink answered EEXIST — the
     * tunnel ::/0 was never installed, and (b) even when the metrics
     * differed, the 1024 tunnel default lost to any lower-metric physical
     * default. The metric below is therefore written EXPLICITLY as
     * `metric 0`: on IPv6 an absent metric is 1024, NOT the priority-0 an
     * absent metric means on IPv4, so the v4 tradeoff (a priority-0
     * tunnel default that outranks every physical default while the
     * physical default stays in the table and self-heals when the TUN
     * unregisters) is only reproducible on v6 by naming metric 0. The
     * v4/v6 replace tradeoffs are otherwise shared: replace is idempotent
     * (a leftover from an old run — at any metric — is superseded in its
     * slot if identical or re-created), and neither side ever removes the
     * physical default because independent metrics keep both entries in
     * the table; the only shared edge is a pre-existing physical route AT
     * priority 0, which replace takes over exactly as the v4 arm does.
     * route_teardown6's `-6 route del <c> dev <tun>` already deletes the
     * priority-0 dev-<tun> entry and leaves any other default alone. */
    for (size_t i = 0; i < routes6->n; i++) {
        const char *c = routes6->v[i];
        char *a[] = { "-6", "route", "replace", (char *)c,
                      "dev", (char *)tun, "metric", "0", NULL };
        if (!ip_run(a))
            log_err("route_setup6: ip -6 route replace %s dev %s failed",
                    c, tun);
    }
}

void route_teardown6(const char *tun, const char *tun_ip,
                     const slist_t *routes6)
{
    (void)tun_ip;
    if (routes6 == NULL)
        return;
    for (size_t i = 0; i < routes6->n; i++) {
        const char *c = routes6->v[i];
        char *d[] = { "-6", "route", "del", (char *)c,
                      "dev", (char *)tun, NULL };
        if (!ip_run(d))
            log_debug("route_teardown6: ip -6 route del %s: not present", c);
    }
}
