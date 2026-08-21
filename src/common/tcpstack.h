#ifndef IWAN_TCPSTACK_H
#define IWAN_TCPSTACK_H

/*
 * Dispatch header for the SOCKS-mode userspace TCP stack. The SOCKS layer
 * (socks.c / socks_flow.c) talks to it through the ns_* API. The vendored
 * lwIP bridge is the only implementation (the native netstack.c rollback
 * was removed); IWAN_NS_IPV6 stays a compile-time switch so the IPv4-only
 * fallback branch in socks_flow.c remains visible and testable.
 */

#define IWAN_NS_IPV6 1   /* the lwIP bridge speaks inner IPv6 */
#include "lwip_bridge.h"

#endif /* IWAN_TCPSTACK_H */
