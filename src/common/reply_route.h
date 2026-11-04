#ifndef IWAN_REPLY_ROUTE_H
#define IWAN_REPLY_ROUTE_H

/*
 * Reply route: return packets of connections arriving via the tunnel go back the way they came.
 *
 * Why conntrack is required: Linux looks up the FIB for locally originated packets by destination only; the ingress interface does not participate in
 * the decision, and there is no "remember the path back" mechanism. The peer address is unknown in advance (reverse access, the remote initiating from an arbitrary
 * address), so the ingress interface can only be recorded on the connection tracking entry (CONNMARK); reply packets then restore it into
 * fwmark handed to `ip rule` to select a table holding only the tunnel default route. Full design in
 * docs/reply-routing.md.
 *
 * Discriminator = `-i <tunnel ingress interface> -d <served address set>`: the served address set is known
 * (from --proxy-cidr*); only the peer is unknown. Do not mark by ingress interface alone, otherwise normal
 * service connections on the same carrier NIC would also be pushed into the tunnel.
 *
 * The ingress interface differs between the two data planes:
 *   - TUN plane    -> iwan0 (userspace writes inner packets into the TUN; the kernel treats them as received from iwan0);
 *   - kernel plane -> carrier NIC (the module, after decapsulating in PRE_ROUTING, calls NF_ACCEPT in place without changing
 *                 skb->dev; the carrier NIC name comes from the carrier parsing in the SESSION_UP reply/log).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"

typedef struct {
	const char *tun;	     /* tunnel netdev: dev of the reply route, always iwan0 */
	const char *in_if;	     /* interface name matched on ingress; NULL = use tun (TUN plane).
			      * the kernel plane must supply the carrier NIC name: after decapsulation skb->dev is still
			      * the physical port, but reply packets must leave via iwan0 -- they are not the same */
	const char *srv;	     /* server outer address (used only for logs/hints) */
	const slist_t *served4;	     /* served address set v4 (CIDR/address/domain; may be NULL) */
	const slist_t *served6;	     /* served address set v6 (may be NULL). Both lists must remain
			      * valid throughout setup/teardown (held by the caller) */
	uint32_t    mark;	     /* fwmark value; 0 = default 0x1 */
	uint32_t    table;	     /* routing table number; 0 = default 100 */
	bool	    kernel_plane;    /* true = kernel data plane (module hook parameters must be queried) */
} reply_route_opts;

typedef struct {
	reply_route_opts o;	     /* value copy: the caller may free its opts after setup returns */
	bool	installed;
	bool	nft;		     /* true = use nft, false = fall back to iptables */
	bool	v6;		     /* whether v6 rules/tables were installed too */
	uint32_t mark;
	uint32_t table;
} reply_route_state;

/*
 * Precheck. **This is the guard against "silent failure"**: the kernel plane module hook must decapsulate
 * before conntrack(-200) (default hooknum=0/PRE_ROUTING + hookprio=-300), or reinject=1 must
 * make inner packets re-enter the stack; otherwise inner connections never enter the conntrack table, reply packets --restore-mark
 * get 0, and the rules never match -- no error, no effect. Returns false if unmet and writes a directly
 * executable fix command into why.
 */
bool reply_route_precheck(const reply_route_opts *o, char *why, size_t whysz);

/* Install rules: nft (preferred) or iptables + ip rule/ip route. On failure, cleanly roll back
 * whatever it installed and write the reason into err. Idempotent: clear same-named leftovers before starting. */
bool reply_route_setup(const reply_route_opts *o, reply_route_state *st,
		       char *err, size_t errsz);

/* Roll back only what it installed itself (same criteria as route_teardown). Safe to call repeatedly. */
void reply_route_teardown(reply_route_state *st);

#endif /* IWAN_REPLY_ROUTE_H */
