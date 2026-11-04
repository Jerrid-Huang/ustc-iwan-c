#ifndef IWAN_KDP_H
#define IWAN_KDP_H

/*
 * kdp = kernel data plane. Kernel data plane supervisor for the iWAN client (Linux only).
 *
 * Design (step 2 of the three-step plan approved by the user; see docs/kernel-data-plane.md):
 *   - handshake (OPEN/OPEN_ACK/signature verification/key derivation) still entirely in userspace -- at that point there is no kernel
 *     session yet, the hook does not intercept, and the app's own UDP socket can receive OPEN_ACK normally;
 *   - only after the handshake completes does SESSION_UP hand the data plane to the kernel: data frame exchange, keepalive
 *     reception and disconnect reception are all handled by the kernel;
 *   - keepalive is all in userspace: **sending** (still one PT_ECHO_REQ every 10s), the reply
 *     (server side), the failure budget and silent death detection are all userspace business; the kernel only does data transport,
 *     plus one bookkeeping item, "on receiving a gated frame write the current timestamp into shared memory" -- no timers,
 *     no keepalive sending, no death detection (see docs/kernel-data-plane.md);
 *   - the liveness/disconnect criterion is last_rx_ms in the /dev/iwan shared memory (1s polling):
 *     zero = peer PT_CLOSE / session cleared, above IWAN_RX_STALE_MS = silent link loss;
 *   - address/route/MTU are still configured by userspace; the module only creates the NIC, sets it UP and sets the MTU.
 *
 * Return values are exactly the same as run_pump(), so the reconnect loops of cmd_proxy / oidc need no semantic change:
 *   0 = user stopped (Ctrl-C etc.), 1 = session lost (should reconnect), -1 = startup failed.
 * On -1, `ns_busy` (may be NULL) distinguishes two kinds of startup failure: true = this netns already has a kernel
 * session or the device is occupied (the caller **must not** fall back to another data plane), false = the local kernel plane cannot
 * start up (if the caller uses the default auto, it may fall back to TUN, see cli_common.h).
 *
 * Calling contract:
 *   - sockfd must be a session socket already connected to the server (the product of authenticate()),
 *     and **still in the post-handshake state**: this function owns the whole data plane lifecycle on top of it, but it does not
 *     close it (same as run_pump, the caller is responsible for port_close);
 *   - reconnecting must first let this function return 1 (it has already executed SESSION_DOWN), then handshake again --
 *     while the session still exists the hook swallows OPEN_ACK, so inverting the order means the handshake never succeeds;
 *   - never call it in the init netns with a real server's five-tuple (it would swallow the user's real tunnel
 *     inbound packets); always do validation in a separate netns + veth topology.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>   /* struct in6_addr (outer v6 binding) */

#include "common.h"   /* slist_t */

#if defined(__linux__)

/* Carrier NIC binding (three modes, one-to-one with the kernel ABI; see docs/kernel-data-plane.md):
 *   oif=0, bind_ip=0   bind nothing: the kernel resolves once via FIB and pins it, and a dead path self-heals;
 *   oif!=0             bind NIC ("bind NIC"): strictly use this interface, per-packet rejection on failure;
 *   bind_ip!=0         bind egress IP ("bind IP"): the kernel resolves via the address table the
 *                      interface that holds that address, which is then equivalent to binding the NIC; that address is also the outer header's source address.
 * dev has a value only when binding a NIC (for logging); bind_ip is in host order.
 *
 * Why bind validity must be judged by userspace: the kernel only reacts on an **outer lookup failure** (a correctness
 * fallback, not a timeliness mechanism). Measured (tests/vm_bind_probe.sh):
 *   - carrier NIC set down / deleted => per-packet rejection (tx_err grows); the data plane does not switch
 *     NICs by itself (the semantics of an explicit bind is that drift is not allowed);
 *   - bound egress IP deleted => **the kernel keeps sending** (a synthesized scope link route only requires the device
 *     to be UP, not that it holds the address; tx_pkts and the peer's received packets both grow normally).
 * So "disable the data plane when the binding is invalid" can only be judged here. */
typedef struct {
    uint32_t    oif;
    uint32_t    bind_ip;      /* v4 egress IP (host order), 0 = no IP bind */
    const char *dev;
    /* Outer v6 "bind IP": semantics correspond item by item to bind_ip (must equal the outer source address,
     * must belong to a local interface, and when given together with oif must be the same interface). When bind_v6=true only
     * bind_ip6 is consulted, and bind_ip must be 0 (the two families are never bound at the same time). */
    bool             bind_v6;
    struct in6_addr  bind_ip6;
    /* Reply route (conntrack): make replies for "connections coming in through the tunnel" go back the way they came. The peer address
     * is not known in advance, so CONNMARK can only record the ingress interface on the conntrack entry, and replies are then restored
     * to an fwmark that selects a table containing only the tunnel default route. See docs/reply-routing.md.
     * The kernel plane installs this after SESSION_UP (only then is the carrier NIC name known); when the preconditions are not met it
     * **rejects this session**, and does not "warn and continue" (that would silently have no effect). */
    bool             reply_via_tunnel;
} kdp_bind;

/* Whether the binding is currently valid (reads getifaddrs from the kernel every time, never caches "the address I assumed").
 * Always true when not binding. Returns true when the interface state cannot be read, writing the reason into why -- when the state
 * is unknown it does not act, and correctness is still covered by the kernel side. On failure why receives a Chinese reason. */
bool kdp_bind_ok(const kdp_bind *b, char *why, size_t whysz);

/* Wait until the binding is valid (once every 1s, Ctrl-C can interrupt). The reconnect loop, **before re-handshaking**,
 * calls it: it does not handshake before the bound egress IP comes back, and only after it returns does it handshake and reopen the data plane. */
void kdp_bind_wait(const kdp_bind *b);

/* Startup precheck before the handshake (**called before authenticate()**): it lets "the local kernel plane cannot start"
 * and "this netns already has a live session" fail without first handshaking with the server and without first occupying a server-side
 * session (today both happen inside kdp_run, i.e. after the handshake):
 *   - /dev/iwan exists and the shared memory layout version matches;
 *   - this netns has no live session (enabled=1 and a peer frame was received within the last 2 x keepalive);
 *   - if iwan0 already exists, it must have been created by the kernel module iwan.
 * Returns true = may continue; false = the reason is written into err (Chinese, printable directly).
 * *busy = true means the failure is "this netns already has a live session": the caller must not fall back to the TUN
 * plane -- falling back would use the same account to kick that session out (the server treats a second OPEN from the same source IP as a legitimate
 * reconnect), which is worse than failing outright.
 *
 * The liveness window is 2 x keepalive (10s -> 20s); it can only prove "someone used this session recently":
 * when the peer is silent (the outer link is blackholed) last_rx_ms is equally old, and such a session cannot be detected by the precheck --
 * it is still covered by the SESSION_UP conflict check -- which is exactly why a SIGKILL leftover must be able to be taken over by a new
 * client (otherwise the client could never start again after one crash).
 *
 * Should only be called "before the first handshake": on reconnect this process's own session may well still exist, and then
 * the precheck would misjudge a normal reconnect as a conflict. */
bool kdp_plane_precheck(char *err, size_t errsz, bool *busy);

/* ns_busy may be NULL; for semantics see the file header (on -1 it distinguishes "existing session/device occupied" from "the local
 * kernel plane cannot start"). */
int kdp_run(int sockfd, const uint8_t xor_key[8], uint16_t sid, uint32_t tok,
            uint8_t enc, const char *server, const slist_t *route_targets,
            const slist_t *route_targets6, const char *auth_tun_ip,
            uint16_t auth_mtu, const kdp_bind *bind, bool *ns_busy);

#endif /* __linux__ */

#endif /* IWAN_KDP_H */
