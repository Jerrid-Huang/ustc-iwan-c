#ifndef IWAN_PROXY_H
#define IWAN_PROXY_H

#include <stdint.h>
#include "common.h"

/* TUN <-> UDP pump. Blocks until Ctrl-C/error. sockfd already authenticated.
 * route_targets: list of CIDR/"default"/IPv4/domain strings (may be empty);
 * route_targets6: IPv6 CIDRs/addresses/domains (may be NULL). */
int run_pump(int tun_fd, const char *tun_name, int sockfd,
             const uint8_t xor_key[8], uint16_t sid, uint32_t tok, uint8_t enc,
             const char *server, const slist_t *route_targets,
             const slist_t *route_targets6,
             const char *auth_tun_ip, uint16_t auth_mtu);

/* ---------------------------------------------------------------------------
 * Shared with the kernel data plane supervisor (src/common/kdp.c, Linux-only).
 * run_pump stays the only other user and its behavior is unchanged (the
 * definitions were un-static'ed / extracted verbatim).
 * ------------------------------------------------------------------------- */

/* IWAN_RX_STALE_MS watchdog in ms: default 120000, 0 disables the watchdog,
 * parsed once per process with the 30s..24h range (util.c env_ms_range).
 * kdp_run() uses the same value so both data planes declare a session lost
 * under identical conditions. */
unsigned pump_rx_stale_ms(void);
/* Keepalive cadence (ms) and the "peer not answering" budget that declares
 * the session lost, i.e. PUMP_KEEPALIVE_MS / PUMP_KA_FAIL_MAX.
 *
 * Semantics (both data planes agree; corrected after 2026-10-10 field tests): this budget counts
 * **unanswered failures**, cleared only by a "valid frame that passed the gate" --
 *   - A successful send does **not** clear it: a connected UDP socket reports ICMP port unreachable
 *     every other time and the send in between succeeds; clearing on send success would keep the
 *     3-failure budget from ever being reached (measured: after the server vanished the log repeated
 *     "retry 1/3"; only the IWAN_RX_STALE_MS watchdog declared death).
 *   - Charged events: keepalive send failure (kernel data plane) and hard transport errors
 *     seen by the receive side: ECONNREFUSED/EHOSTUNREACH/ENETUNREACH/ECONNRESET (TUN
 *     pump path: recvmmsg consumes the error first, so the send side never sees it).
 *   - The TUN pump clears it per frame in the inner loop at the same place as last_rx
 *     (after the sid/token gate), so forged frames cannot hold a reconnect; the kernel
 *     data plane clears on /dev/iwan's last_rx_ms change, written only on gated frames.
 *     The watchdog (IWAN_RX_STALE_MS, default 120s) remains the outer fallback: a peer that receives but answers nothing (e.g. blackholed) never grows this budget, so only the watchdog can declare death. */
unsigned pump_keepalive_ms(void);
unsigned pump_ka_fail_max(void);

/* Expand route targets into the concrete CIDR list handed to the platform
 * router (fam = AF_INET / AF_INET6). Returns 0 on success, -1 on a malformed
 * target. Used by run_pump and kdp_run for identical route semantics. */
int expand_route_targets(const slist_t *targets, slist_t *out);
int expand_route_targets6(const slist_t *targets, slist_t *out);

#endif
