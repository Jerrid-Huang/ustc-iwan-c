#ifndef IWAN_ROUTE_H
#define IWAN_ROUTE_H

#include <stdbool.h>
#include <stdint.h>
#include "common.h"

/* Parse "A.B.C.D/n" (0 <= n <= 32) into host-order net + prefix length.
 * Returns 0 on success, -1 on malformed input. */
int cidr_parse(const char *s, uint32_t *net, int *prefix);
/* detect default route. Returns true and fills gw/dev and the route's
 * metric ("" when the default has none; all buffers >= 16 bytes). */
bool capture_default(char gw[16], char dev[16], char metric[16]);
/* first IPv4 subnet on dev as "a.b.c.d/plen", or false. */
bool local_subnet(const char *dev, char out[24]);

/* Apply the VPN routes: flush/up/mtu/addr on tun, then install the
 * proxy routes (default replaced onto tun). Returns true on success;
 * on failure, rolls back everything applied so far (restoring the
 * pre-VPN default route) and returns false — the caller must not
 * start the pump on failure. metric is the pre-VPN default's metric
 * ("" when none) and is carried into the teardown restore. */
bool route_setup(const char *tun, const char *tun_ip, uint16_t mtu,
                 const char *srv, const char *ogw, const char *odev,
                 const char *metric, const slist_t *routes_with_default);
void route_teardown(const char *tun, const char *srv, const char *ogw,
                    const char *odev, const char *metric,
                    const slist_t *routes);

/* IPv6 proxy routes ("<v6-cidr>" entries) through the tunnel, installed
 * alongside the IPv4 route_setup. Best-effort: IPv6 routing must never
 * take the tunnel down (the IPv4 path is the load-bearing one), so
 * failures are logged and skipped, never fatal. */
bool route_setup6(const char *tun, const slist_t *routes6);
void route_teardown6(const char *tun, const slist_t *routes6);

/* bring the tunnel interface up with an address and MTU (no routes);
 * shared by route_setup and the no-route-hijack pump path. Returns
 * false when a step failed (state partially applied). */
bool route_iface_up(const char *tun, const char *tun_ip, uint16_t mtu);
/* take the tunnel interface down and flush its addresses (no routes) */
void route_iface_down(const char *tun);

#endif
