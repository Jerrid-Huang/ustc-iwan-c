#ifndef IWAN_TCPSTACK_H
#define IWAN_TCPSTACK_H

/*
 * Dispatch header: the SOCKS layer (socks.c / socks_flow.c) talks to the
 * userspace TCP stack through the ns_* API, which both implementations
 * expose with identical signatures and public types. CMake's IWAN_TCP_STACK
 * option (lwip | native) selects the backing header; the compile definition
 * IWAN_TCP_STACK_LWIP drives this include.
 */

#if defined(IWAN_TCP_STACK_LWIP)
#  define IWAN_NS_IPV6 1   /* the lwIP bridge speaks inner IPv6 */
#  include "lwip_bridge.h"
#else
#  define IWAN_NS_IPV6 0   /* the native rollback stack is IPv4-only */
#  include "netstack.h"
#endif

#endif /* IWAN_TCPSTACK_H */
