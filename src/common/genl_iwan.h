#ifndef IWAN_GENL_IWAN_H
#define IWAN_GENL_IWAN_H

/*
 * genetlink control-plane client for the iWAN kernel data plane (Linux only).
 *
 * The sole ABI authority is kernel/iwan_genl.h (frozen); this file includes it directly and does not copy
 * constants; for the design see kernel/CONTROL-PLANE.md. The implementation follows
 * kernel/tests/iwan_ctl.c: plain libc + hand-built netlink messages, no
 * libnl/libmnl dependency.
 *
 * Byte order: input structs in this file always use **host byte order** (addresses too); conversion is done only
 * once at the attribute packing site in genl_iwan.c -- matching kernel/iwan_genl.h's rule that "conversion happens only
 * once at the netlink boundary".
 *
 * For the Linux-only reason and wiring see CMakeLists.txt: this file, together with genl_iwan.c and
 * kdp.c, is built only in the Linux branch; the file body is additionally wrapped in __linux__ because
 * src/iwan_client.c is also compiled into the Windows iwan-winsvc.exe, so on non-Linux
 * including it must still compile (only declarations disappear; there is no half-finished stub).
 */

#if defined(__linux__)

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>		/* struct in6_addr (outer v6 endpoint) */

#include "../../kernel/iwan_genl.h"

/* Session parameters for IWAN_CMD_SESSION_UP (host byte order).
 *
 * sport must be **given explicitly from the very first call** and stay identical every time: the module stores the sport of the first SESSION_UP
 * for idempotent comparison; if omitted on the first call it stores 0, and explicitly supplying it later returns -EINVAL
 * (see CONTROL-PLANE.md section 10.2). The caller uses getsockname() to get the actual local port,
 * so "reconnect changed the ephemeral port" requires SESSION_DOWN first (that is what kdp.c does). */
typedef struct {
    uint16_t sid;
    uint32_t tok;
    uint8_t  enc;                    /* 1 = PT_DATA_ENC + XOR, 0 = plaintext */
    uint8_t  key[IWAN_KEY_LEN];      /* MD5(user||pass)[0..8) */
    uint32_t outer_src;              /* local outer address (v4, host byte order) */
    uint32_t outer_dst;              /* peer outer address (v4, host byte order) */
    /* Outer version (slice 2): decided by **the caller according to the session socket family**, mutually
     * exclusive with outer_src/outer_dst -- when outer_v6=true only the two 16-byte fields below are
     * used and the v4 fields are left 0 (the kernel decides the family by "which pair was given"; giving both pairs
     * returns -EINVAL). v4 sessions must explicitly pass outer_v6=false. */
    bool     outer_v6;
    struct in6_addr outer_src6;      /* local outer address (v6) */
    struct in6_addr outer_dst6;      /* peer outer address (v6) */
    uint16_t dport;                  /* server port, host byte order */
    uint16_t sport;                  /* actual local port, host byte order */
    uint32_t mtu;                    /* 0 = omit IWAN_A_MTU (use module default) */
    /* Carrier NIC binding (three modes, see docs/kernel-data-plane.md):
     *   oif=0, bind_ip=0   bind nothing: the kernel resolves once via FIB and pins it; a broken path self-heals
     *   oif!=0             bind NIC: strictly use this interface; failure rejects packets individually (no drift)
     *   bind_ip!=0         bind IP: the kernel resolves via the address table the interface holding that address,
     *                      equivalent to binding that interface; the address is also the outer header source address,
     *                      so it must equal outer_src (the kernel rejects a mismatch with -EINVAL)
     * When both are given they must point to the same interface (otherwise the kernel returns -EINVAL). */
    uint32_t oif;                    /* bound carrier NIC ifindex, 0 = unbound */
    uint32_t bind_ip;                /* bound egress IP (v4, host byte order), 0 = unbound */
    /* Bound egress v6 address: all zero = unbound (semantics mirror bind_ip item by item: it must equal
     * outer_src6, must be a local address, and must use the same interface when given together with oif) */
    struct in6_addr bind_ip6;
} genl_iwan_session;

/* GET_STATS snapshot (for diagnostics; to decide "is there a session" check sid==0 && tok==0,
 * not whether dev is empty -- without a session DEVNAME is "-", not an empty string). */
typedef struct {
    uint16_t sid;
    uint32_t tok;
    char     dev[16];
    uint32_t mtu;
    uint64_t last_keepalive_ms;
    uint8_t  peer_state;             /* enum iwan_peer_state */
    uint64_t rx_frames;
    uint64_t rx_ctrl_frame;
    uint64_t rx_delivered;
    uint64_t tx_pkts;
    uint64_t tx_err;                 /* number of packets dropped by the data plane during outer lookup
                                      * (this counter only grows when explicit binding is unavailable) */
    /* Binding state (read-only export, for reconciliation): requested binding spec + actual effective carrier NIC */
    uint32_t oif;                    /* requested binding NIC, 0 = unspecified */
    uint32_t bind_ip;                /* requested binding egress IP (v4), 0 = unspecified */
    uint32_t carrier;                /* actual carrier NIC ifindex, 0 = not resolved yet */
    /* Three items valid only for outer v6 sessions: "is the attribute present" in the reply is the family criterion
     * (a v4 session sends none of these three attributes) */
    bool     outer_v6;
    struct in6_addr outer_src6;
    struct in6_addr outer_dst6;
    struct in6_addr bind_ip6;
} genl_iwan_stats;

/* Event callback (the events group is an optional/diagnostic channel; see usage in kdp.c).
 * ev = enum iwan_genl_event, frame = raw IWAN_EVA_FRAME bytes (may be NULL). */
typedef void (*genl_iwan_ev_cb)(void *ud, uint8_t ev, const uint8_t *frame,
                                size_t len);

typedef struct genl_iwan genl_iwan;

/* Open a genetlink socket. Returns NULL on failure and writes the reason into err. */
genl_iwan *genl_iwan_open(char *err, size_t errsz);
void genl_iwan_close(genl_iwan *g);

/* Resolve the family id (+ optional events group id), idempotent; 0 on success, negative errno on failure. */
int genl_iwan_resolve(genl_iwan *g, char *err, size_t errsz);

/* IWAN_CMD_SESSION_UP (idempotent replay). 0 on success; negative errno on failure.
 *
 * On success dev/devsz receives IWAN_A_DEVNAME from the reply (if the attribute is missing, empty, or the kernel returned
 * the no-session placeholder "-", it falls back to "iwan0" and logs a log_err), and mtu_out receives the measured
 * MTU (may be NULL).
 *
 * Device ownership is handled only within the reply contract here: values of new optional attributes such as IWAN_A_DEV_OWNED are not
 * echoed back (enum constants cannot be probed with #ifdef, and hard references would clash with the "frozen ABI"
 * build order); "iwan0 is already taken by a non-iwan device" is covered by two legs: kdp.c's pre-startup
 * `ip -d link show dev iwan0` precheck + SESSION_UP returning -EBUSY. */
int genl_iwan_session_up(genl_iwan *g, const genl_iwan_session *s,
                         char *dev, size_t devsz, uint32_t *mtu_out,
                         char *err, size_t errsz);

/* IWAN_CMD_SESSION_DOWN: zero the credentials and delete the NIC created by the module. */
int genl_iwan_session_down(genl_iwan *g, char *err, size_t errsz);

/* IWAN_CMD_GET_STATS (view of this netns). */
int genl_iwan_get_stats(genl_iwan *g, genl_iwan_stats *st, char *err,
                        size_t errsz);

/* Optional: join the "events" multicast group. If the family has no such group or the join fails, it only returns -1; the caller treats
 * it as a diagnostic channel and must never conclude that the data plane is unavailable because of it. */
int genl_iwan_events_subscribe(genl_iwan *g, char *err, size_t errsz);

/* Non-blocking drain of ready events, invoking the callback for each. Returns the number processed; -1 means a socket error. */
int genl_iwan_events_drain(genl_iwan *g, genl_iwan_ev_cb cb, void *ud);

#endif /* __linux__ */

#endif /* IWAN_GENL_IWAN_H */
