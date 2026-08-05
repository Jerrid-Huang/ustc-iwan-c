#ifndef IWAN_ROUTE_H
#define IWAN_ROUTE_H

#include <stdbool.h>
#include <stdint.h>
#include "common.h"

/* detect default route. Returns true and fills gw/dev (>=16 bytes each). */
bool capture_default(char gw[16], char dev[16]);
/* first IPv4 subnet on dev as "a.b.c.d/plen", or false. */
bool local_subnet(const char *dev, char out[24]);

void route_setup(const char *tun, const char *tun_ip, uint16_t mtu,
                 const char *srv, const char *ogw, const char *odev,
                 const slist_t *routes_with_default);
void route_teardown(const char *tun, const char *srv, const char *ogw,
                    const char *odev, const slist_t *routes);

#endif
