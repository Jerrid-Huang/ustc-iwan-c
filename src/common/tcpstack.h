#ifndef IWAN_TCPSTACK_H
#define IWAN_TCPSTACK_H

/*
 * Dispatch header for the SOCKS-mode userspace TCP stack. The SOCKS layer
 * (socks.c / socks_flow.c) talks to it through the ns_* API. The vendored
 * lwIP bridge is the only implementation (the native netstack.c rollback
 * was removed). Inner IPv6 is a RUNTIME choice — the client's
 * --socks-ipv6 flag (socks_flow.c g_socks_cfg->ipv6) — not a compile-time
 * switch: there is no IWAN_NS_IPV6 macro and no IPv4-only fallback build.
 */

#include "lwip_bridge.h"

#endif /* IWAN_TCPSTACK_H */
