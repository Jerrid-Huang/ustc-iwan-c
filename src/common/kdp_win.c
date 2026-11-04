/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdp_win.c -- see kdp_win.h. Corresponds item by item to the loop in kdp.c on Linux:
 *
 *   kdp.c (Linux)                        kdp_win.c (Windows)
 *   -----------------------------------  ------------------------------------
 *   kdp_plane_precheck()                 kdp_win_plane_precheck()
 *   genl SESSION_UP + oif/bind attrs     IOCTL_IWAN_SESSION_OPEN (outer four-tuple +
 *                                        carrier MTU + target set)
 *   mmap(/dev/iwan)                      read-only mapping from IOCTL_IWAN_SHM_QUERY
 *   1s tick reads last_rx_ms             windev_shm_last_rx_ms()
 *   10s PT_ECHO_REQ (userspace socket)   the same ctrl_hdr() + port_send()
 *   IWAN_RX_STALE_MS watchdog            pump_rx_stale_ms(), same default value
 *   SESSION_DOWN + route rollback        route_teardown/route_iface_down +
 *                                        IOCTL_IWAN_SESSION_CLOSE
 *
 * Deliberately not done (consistent with the M1 boundary): no egress IP binding (that is the --bind-ip capability on linux,
 * to be added on Windows when needed); --reply-via-tunnel on Windows would rely on WFP flow context,
 * not yet implemented; when the user explicitly requests it we must report an error rather than silently ignore it (judged by the caller).
 */
#if defined(_WIN32)

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>      /* wcscmp: tell which kernel plane from the device path */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <netioapi.h>

#include "kdp_win.h"

#include "protocol.h"   /* PT_ECHO_REQ/PT_CLOSE, ctrl_hdr */
#include "echo.h"        /* 60-byte ECHOREQ payload */
#include "proxy.h"      /* expand_route_targets(_6), pump_keepalive_ms etc. */
#include "route.h"      /* capture_default, route_setup/teardown, route_iface_up */
#include "util.h"       /* now_ms, ms_since, logging */
#include "windev.h"     /* device layer */

#define KDP_WIN_POLL_MS  1000u
#define KDP_WIN_SLEEP_MS 100u

/* Same meaning as ms_since in kdp.c: monotonic millisecond difference, returns 0 when now is behind then */
static uint64_t kdp_win_ms_since(uint64_t now, uint64_t then)
{
    return now > then ? now - then : 0;
}

/* ---- outer four-tuple and carrier MTU -------------------------------- */

/* Read the outer four-tuple (network order) from the already-connected session socket; same
 * intent as kdp_outer_tuple in kdp.c: the driver uses it to claim inbound data frames and build the outer header. */
static bool kdp_win_outer_tuple(int fd, IWAN_WIN_SESSION_OPEN *req,
                                char *err, size_t errsz)
{
    struct sockaddr_storage local, peer;
    socklen_t ll = sizeof(local), pl = sizeof(peer);
    struct sockaddr_in *l4, *p4;

    if (getsockname(fd, (struct sockaddr *)&local, &ll) != 0 ||
        getpeername(fd, (struct sockaddr *)&peer, &pl) != 0) {
        snprintf(err, errsz, "failed to read session socket address: %s", strerror(errno));
        return false;
    }
    if (local.ss_family != peer.ss_family) {
        snprintf(err, errsz, "session socket endpoint address families differ");
        return false;
    }
    if (local.ss_family == AF_INET) {
        l4 = (struct sockaddr_in *)&local;
        p4 = (struct sockaddr_in *)&peer;
        req->sport = l4->sin_port;
        req->dport = p4->sin_port;
        req->outer_src = l4->sin_addr.s_addr;
        req->outer_dst = p4->sin_addr.s_addr;
        /* The v6 fields must be zeroed: the driver decides outer v6 by "both v6 fields non-zero" */
        memset(req->outer_src6, 0, sizeof(req->outer_src6));
        memset(req->outer_dst6, 0, sizeof(req->outer_dst6));
        return true;
    }
    if (local.ss_family == AF_INET6) {
        struct sockaddr_in6 *l6 = (struct sockaddr_in6 *)&local;
        struct sockaddr_in6 *p6 = (struct sockaddr_in6 *)&peer;

        req->sport = l6->sin6_port;
        req->dport = p6->sin6_port;
        memcpy(req->outer_src6, &l6->sin6_addr, sizeof(req->outer_src6));
        memcpy(req->outer_dst6, &p6->sin6_addr, sizeof(req->outer_dst6));
        req->outer_src = 0;
        req->outer_dst = 0;
        return true;
    }
    snprintf(err, errsz, "unsupported outer address family %d", (int)local.ss_family);
    return false;
}

/* Carrier route to the hop toward the server: gives the carrier interface MTU (the driver uses it to compute the usable inner MTU),
 * the next-hop address (the driver uses it to resolve the carrier NIC's neighbor address), and the carrier interface index (the NDIS plane
 * uses it to pin the session to "exactly one downstream NIC").
 * If it cannot be obtained, fall back to 1500 / 0 / 0: better to be conservative than to let the driver compute an absurd MTU from 0,
 * and still worse to let it ARP for a made-up next hop. */
/* Carrier route to the hop toward the server: gives the carrier interface MTU (the driver uses it to compute the usable inner MTU),
 * the next-hop address (the driver uses it to resolve the carrier NIC's neighbor address), and the carrier interface index (the NDIS plane
 * uses it to pin the session to "exactly one downstream NIC").
 *
 * The implementation deliberately avoids GetBestRoute2: on this machine (a mingw cross-compiled client, guest Windows
 * 11 24H2) it reliably returns 87 ERROR_INVALID_PARAMETER (in the same code
 * GetIpForwardTable2 and ConvertInterfaceLuids both work fine), and both two-argument source-address forms
 * fail the same way -- rather than bet on a struct layout, just use one table and pick ourselves.
 *
 * The criterion follows the same order as the kernel's FIB lookup: **longest prefix wins**, ties go to the smallest metric, further ties
 * to the smallest interface index. For a directly connected route NextHop is all zero; the peer is then on-link, so per the driver's
 * convention write 0 (meaning "peer is on-link"); do not invent a next hop.
 *
 * Returning 0 means "no usable carrier found"; the caller must make session setup fail: silently giving index 0 would
 * be rejected by the driver as "no carrier specified", but the error reported is Win32 87, giving no hint that it is a routing problem. */
static uint32_t kdp_win_carrier_route(uint32_t dst_be, uint32_t *hop_be,
                                      uint32_t *oif_out, uint8_t *guid_out)
{
    MIB_IPFORWARD_TABLE2 *ft = NULL;
    MIB_IPFORWARD_ROW2 *best = NULL;
    MIB_IPINTERFACE_ROW ifrow;
    NET_LUID luid;
    ULONG i, best_plen = 0;
    ULONG best_metric = 0;
    ULONG mtu = 0;

    *hop_be = 0;
    *oif_out = 0;
    memset(guid_out, 0, 16);

    if (GetIpForwardTable2(AF_INET, &ft) != NO_ERROR || ft == NULL)
        return 0;

    for (i = 0; i < ft->NumEntries; i++) {
        MIB_IPFORWARD_ROW2 *r = &ft->Table[i];
        const uint8_t *pfx;
        uint8_t d[4];
        ULONG plen, bit;
        BOOLEAN hit = TRUE;

        if (r->DestinationPrefix.Prefix.si_family != AF_INET)
            continue;
        plen = r->DestinationPrefix.PrefixLength;
        if (plen > 32)
            continue;
        pfx = (const uint8_t *)&r->DestinationPrefix.Prefix.Ipv4.sin_addr;
        d[0] = (uint8_t)(dst_be >> 24);
        d[1] = (uint8_t)(dst_be >> 16);
        d[2] = (uint8_t)(dst_be >> 8);
        d[3] = (uint8_t)dst_be;
        for (bit = 0; bit < plen; bit++) {
            uint8_t mask = (uint8_t)(0x80u >> (bit & 7u));

            if ((pfx[bit >> 3] & mask) != (d[bit >> 3] & mask)) {
                hit = FALSE;
                break;
            }
        }
        if (!hit)
            continue;
        if (best == NULL || plen > best_plen ||
            (plen == best_plen && r->Metric < best_metric) ||
            (plen == best_plen && r->Metric == best_metric &&
             r->InterfaceIndex < best->InterfaceIndex)) {
            best = r;
            best_plen = plen;
            best_metric = r->Metric;
        }
    }
    if (best == NULL) {
        FreeMibTable(ft);
        return 0;
    }
    *oif_out = (uint32_t)best->InterfaceIndex;
    if (best->NextHop.si_family == AF_INET)
        *hop_be = best->NextHop.Ipv4.sin_addr.s_addr;
    luid = best->InterfaceLuid;
    FreeMibTable(ft);

    if (*oif_out == 0)
        return 0;

    /* The interface GUID is the only thing that matches across the two index conventions. Measured on the guest: Ethernet's
     * netio index is 7, while the BoundIfIndex reported by the protocol driver's bind callback is 23/26 --
     * the two numbering schemes do not agree, so picking the carrier by index is guessing (the symptom of a wrong guess is "the bind clearly exists but
     * OPEN always returns DEVICE_NOT_READY", which is completely invisible in the counters). The protocol side resolves
     * the same GUID out of NDIS_BIND_PARAMETERS.AdapterName, and the driver matches by
     * GUID; only when the GUID cannot be obtained does it fall back to the index convention. */
    {
        GUID g;

        memset(&g, 0, sizeof(g));
        if (ConvertInterfaceLuidToGuid(&luid, &g) == NO_ERROR)
            memcpy(guid_out, &g, 16);
    }

    memset(&ifrow, 0, sizeof(ifrow));
    ifrow.Family = AF_INET;
    ifrow.InterfaceLuid = luid;
    if (GetIpInterfaceEntry(&ifrow) != NO_ERROR)
        return 0;
    mtu = ifrow.NlMtu;
    if (mtu < 576 || mtu > 65535)
        return 0;
    return (uint32_t)mtu;
}

/* ---- target set ------------------------------------------------------- */

/* "<cidr>" or a bare host address -> IWAN_WIN_TARGET. For v4 only the first 4 bytes of addr are filled
 * (consistent with the ABI convention: the remaining bytes must be 0; the driver also verifies this). */
static bool kdp_win_target_parse(const char *s, IWAN_WIN_TARGET *out,
                                 char *err, size_t errsz)
{
    char buf[128];
    char *slash;
    long plen = -1;

    if (strlen(s) >= sizeof(buf)) {
        snprintf(err, errsz, "route target too long: %s", s);
        return false;
    }
    snprintf(buf, sizeof(buf), "%s", s);
    slash = strchr(buf, '/');
    if (slash != NULL) {
        char *end = NULL;

        *slash = '\0';
        plen = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end != '\0' || plen < 0) {
            snprintf(err, errsz, "route target prefix invalid: %s", s);
            return false;
        }
    }

    memset(out, 0, sizeof(*out));
    if (strchr(buf, ':') != NULL) {
        struct in6_addr a6;

        if (inet_pton(AF_INET6, buf, &a6) != 1) {
            snprintf(err, errsz, "route target invalid: %s", s);
            return false;
        }
        if (plen < 0)
            plen = 128;
        if (plen > 128) {
            snprintf(err, errsz, "route target prefix out of range: %s", s);
            return false;
        }
        out->family = IWAN_WIN_AF_V6;
        out->prefix_len = (uint32_t)plen;
        memcpy(out->addr, &a6, 16);
        return true;
    }

    {
        struct in_addr a4;

        if (inet_pton(AF_INET, buf, &a4) != 1) {
            snprintf(err, errsz, "route target invalid: %s", s);
            return false;
        }
        if (plen < 0)
            plen = 32;
        if (plen > 32) {
            snprintf(err, errsz, "route target prefix out of range: %s", s);
            return false;
        }
        out->family = IWAN_WIN_AF_V4;
        out->prefix_len = (uint32_t)plen;
        memcpy(out->addr, &a4, 4);
    }
    return true;
}

static int kdp_win_targets_build(const slist_t *v4, const slist_t *v6,
                                 IWAN_WIN_TARGET **out, size_t *nout,
                                 char *err, size_t errsz)
{
    size_t n = (v4 != NULL ? v4->n : 0) + (v6 != NULL ? v6->n : 0);
    IWAN_WIN_TARGET *t;
    size_t i, k = 0;

    *out = NULL;
    *nout = 0;
    if (n == 0)
        return 0;
    if (n > IWAN_WIN_MAX_TARGETS) {
        snprintf(err, errsz, "too many target set entries (%llu > %u)",
                 (unsigned long long)n, (unsigned)IWAN_WIN_MAX_TARGETS);
        return -1;
    }
    t = (IWAN_WIN_TARGET *)calloc(n, sizeof(*t));
    if (t == NULL) {
        snprintf(err, errsz, "out of memory (%llu target set entries)",
                 (unsigned long long)n);
        return -1;
    }
    for (i = 0; i < (v4 != NULL ? v4->n : 0); i++, k++)
        if (!kdp_win_target_parse(v4->v[i], &t[k], err, errsz)) {
            free(t);
            return -1;
        }
    for (i = 0; i < (v6 != NULL ? v6->n : 0); i++, k++)
        if (!kdp_win_target_parse(v6->v[i], &t[k], err, errsz)) {
            free(t);
            return -1;
        }
    *out = t;
    *nout = k;
    return 0;
}

/* ---- startup precheck ------------------------------------------------- */

bool kdp_win_plane_precheck(const wchar_t *device_path, char *err, size_t errsz,
                            bool *busy)
{
    windev_t *d = NULL;
    IWAN_WIN_SESSION_INFO info;
    int rc;

    if (busy != NULL)
        *busy = false;

    rc = windev_open_named(&d, device_path, err, errsz);
    if (rc != WINDEV_OK) {
        /* Driver not installed -> the caller may fall back to the TUN plane; the rest (version mismatch, permissions) are
         * explained by windev's Chinese reason, and likewise do not fall back. */
        return false;
    }

    rc = windev_session_get(d, &info, err, errsz);
    if (rc == WINDEV_OK && info.enabled != 0 && info.last_rx_ms != 0) {
        uint64_t window = (uint64_t)pump_keepalive_ms() * 10u;

        if (window == 0)
            window = 20000;
        if (kdp_win_ms_since(now_ms(), (uint64_t)info.last_rx_ms) < window) {
            if (busy != NULL)
                *busy = true;
            snprintf(err, errsz,
                     "a live session already exists locally (sid=%u, last peer frame %llu ms ago):"
                     " opening another with the same account would kick that one out; stop it first and retry",
                     (unsigned)info.sid,
                     (unsigned long long)kdp_win_ms_since(now_ms(),
                                                  (uint64_t)info.last_rx_ms));
            windev_close(d);
            return false;
        }
    }
    /* Device present, no live session: may continue (abi_version in the session info has already been
     * validated by windev_session_get). */
    windev_close(d);
    return true;
}

/* ---- main loop -------------------------------------------------------- */

int kdp_win_run(int sockfd, const uint8_t xor_key[8], uint16_t sid, uint32_t tok,
                uint8_t enc, const char *server, const char *dev,
                const wchar_t *device_path,
                const slist_t *route_targets, const slist_t *route_targets6,
                const char *auth_tun_ip, uint16_t auth_mtu, bool *ns_busy)
{
    IWAN_WIN_SESSION_OPEN req;
    IWAN_WIN_SESSION_INFO info;
    IWAN_WIN_TARGET *targets = NULL;
    size_t ntargets = 0;
    const IWAN_WIN_SHM *shm = NULL;
    windev_t *d = NULL;
    char err[512];
    const char *tun = (dev != NULL && dev[0] != '\0') ? dev : IWAN_WIN_DEF_DEV;

    slist_t routes, routes6, empty;
    char ogw[16] = "", odev[16] = "", ometric[16] = "";
    bool iface_up = false, session_up = false, routes_up = false;
    bool seen_rx = false, session_lost = false;
    uint64_t last_seen = 0;
    uint64_t t_up = 0;
    unsigned ka_ms, ka_fail_max, stale;
    unsigned ka_fail = 0;
    uint64_t last_ka, next_tick;
    int rc = 0;

    if (ns_busy != NULL)
        *ns_busy = false;
    slist_init(&routes);
    slist_init(&routes6);
    err[0] = '\0';

    /* 0) Target set: uses the same expansion as kdp.c (bare IP, CIDR, dedup and normalization are all
     *    in expand_route_targets); the driver only does longest prefix matching. */
    slist_init(&empty);
    if (expand_route_targets(route_targets != NULL ? route_targets : &empty,
                            &routes) != 0 ||
        expand_route_targets6(route_targets6 != NULL ? route_targets6 : &empty,
                              &routes6) != 0) {
        log_err("Windows kernel data plane: target set expansion failed");
        rc = -1;
        goto out;
    }
    if (kdp_win_targets_build(&routes, &routes6, &targets, &ntargets,
                              err, sizeof(err)) != 0) {
        log_err("Windows kernel data plane: %s", err);
        rc = -1;
        goto out;
    }

    /* 1) Open the driver device. Failure here = the local kernel plane cannot start; the caller may fall back to TUN. */
    if (windev_open_named(&d, device_path, err, sizeof(err)) != WINDEV_OK) {
        log_err("Windows kernel data plane: %s", err);
        rc = -1;
        goto out;
    }

    /* 2) Session socket five-tuple + carrier MTU + inner MTU */
    memset(&req, 0, sizeof(req));
    if (!kdp_win_outer_tuple(sockfd, &req, err, sizeof(err))) {
        log_err("Windows kernel data plane: %s", err);
        rc = -1;
        goto out;
    }
    req.carrier_mtu = kdp_win_carrier_route(req.outer_dst, &req.outer_hop,
                                            &req.oif_index,
                                            req.outer_if_guid);
    if (req.carrier_mtu == 0) {
        /* No carrier found means no outer egress: the NDIS plane rejects the session with oif_index=0,
         * and the WFP plane would set up a session that can never send a packet. Neither may happen silently. */
        log_err("Windows kernel data plane: no carrier route to %s (no default route?)",
                server);
        rc = -1;
        goto out;
    }
    {
        /* Inner MTU = min(server-negotiated value, carrier NIC MTU - encapsulation overhead). The carrier MTU is the
         * hard upper bound (if it does not fit, not a single byte can be sent); the negotiated value is the server's receive capability;
         * trusting only the negotiated value would emit oversized outer frames on links whose carrier is under 1500, and trusting only the NIC would,
         * when the server is more conservative, get dropped by the peer. The value declared to the driver and the value netsh writes into the adapter must be
         * the same -- otherwise it is a PMTU black hole where "the upper layer thinks it can send and the driver silently drops". */
        uint32_t overhead = (req.outer_dst != 0) ? IWAN_WIN_OVERHEAD_V4
                                                 : IWAN_WIN_OVERHEAD_V6;
        uint32_t cap, mtu;

        if (req.carrier_mtu <= overhead + IWAN_WIN_MTU_MIN) {
            log_err("Windows kernel data plane: carrier MTU %u cannot fit the tunnel"
                    " (encapsulation overhead %u, inner minimum %u)",
                    (unsigned)req.carrier_mtu, (unsigned)overhead,
                    (unsigned)IWAN_WIN_MTU_MIN);
            rc = -1;
            goto out;
        }
        cap = req.carrier_mtu - overhead;
        mtu = (auth_mtu == 0 || (uint32_t)auth_mtu > cap) ? cap
                                                         : (uint32_t)auth_mtu;
        req.inner_mtu = (uint16_t)mtu;
        if (mtu != (uint32_t)auth_mtu)
            log_info("Windows kernel data plane: inner MTU lowered from %u to %u"
                     " (carrier MTU %u, encapsulation overhead %u)",
                     (unsigned)auth_mtu, (unsigned)mtu,
                     (unsigned)req.carrier_mtu, (unsigned)overhead);
        auth_mtu = (uint16_t)mtu;
    }
    memcpy(req.key, xor_key, sizeof(req.key));
    req.sid = sid;
    req.tok = tok;
    req.enc = enc;
    req.flags = 0;

    /* The inner address must be given to the driver. Outbound classification uses it as the "session usable" guard
     * (iwan_win_wfp.c: with inner_ip == 0 it passes through in place and encapsulates nothing); if left unset, the
     * consequence is that the kernel plane looks set up successfully while in fact no packet enters the tunnel.
     * The addresses in the outer four-tuple are all in network order; inner_ip stays consistent (ABI comment: be32). */
    {
        struct in_addr a4;
        uint8_t b4[4];

        if (inet_pton(AF_INET, auth_tun_ip, &a4) != 1) {
            log_err("Windows kernel data plane: inner address %s is not a valid IPv4",
                    auth_tun_ip);
            rc = -1;
            goto out;
        }
        memcpy(b4, &a4.s_addr, sizeof(b4));
        req.inner_ip = a4.s_addr;
        /* Inner v6 is a ULA derived from the same inner address: the driver currently only stores it without using it,
         * but filling it in is what matches the ABI semantics (proxy/socks derive it the same way). */
        ip6_derive_ula(ip4_u32(b4), req.inner_ip6);
    }

    /* 3) Addresses and routes (before the session: on failure no established session needs to be torn down).
     *    Same order as kdp.c: with a target set, "hijack" the routes for these prefixes; without one, just bring
     *    the adapter up with the inner address. */
    if (capture_default(ogw, odev, ometric) && odev[0] != '\0') {
        log_debug("Windows kernel data plane: default route %s dev %s metric %s",
                  ogw, odev, ometric);
    }
    /* NDIS plane: the inner adapter is this driver's own, and the connection name Windows gives it is chosen by the system
     * ("Local Area Connection", possibly with a number after reinstall), while route_setup and netsh
     * only know names -- so first match it to our agreed alias. The WFP plane's inner adapter is created by the user with
     * KM-TEST and named by --dev, and does not go through this step. */
    if (device_path != NULL && wcscmp(device_path, IWAN_WIN_USER_PATH_MP) == 0 &&
        !route_iface_ensure_name(tun, IWAN_WIN_MP_ADAPTER_DESC)) {
        log_err("Windows kernel data plane: no inner adapter described as \"%s\""
                " (--dev %s)", IWAN_WIN_MP_ADAPTER_DESC, tun);
        rc = -1;
        goto out;
    }

    if (routes.n > 0 || routes6.n > 0) {
        if (!route_setup(tun, auth_tun_ip, auth_mtu, server, ogw, odev,
                         ometric, &routes, &routes6)) {
            log_err("Windows kernel data plane: address/route configuration failed (route_setup rolled back)");
            rc = -1;
            goto out;
        }
        routes_up = true;
        iface_up = true;
        log_info("tun %s ready: %llu route%s", tun,
                 (unsigned long long)routes.n, routes.n == 1 ? "" : "s");
    } else {
        if (!route_iface_up(tun, auth_tun_ip, auth_mtu)) {
            route_rollback_v6(tun, auth_tun_ip, &routes6);
            route_iface_down(tun);
            log_err("Windows kernel data plane: adapter %s cannot come up", tun);
            rc = -1;
            goto out;
        }
        iface_up = true;
        log_info("tun %s up with IP %s (no route hijack)", tun, auth_tun_ip);
    }

    /* 4) Establish the kernel session: the data plane is handed to the driver from here on */
    if (windev_session_open(d, &req, targets, ntargets, &info,
                            err, sizeof(err)) != WINDEV_OK) {
        log_err("Windows kernel data plane: session setup failed: %s", err);
        rc = -1;
        goto out;
    }
    session_up = true;
    log_info("kernel data plane: session established dev=%s mtu=%u carrier_mtu=%u sid=%u",
             tun, (unsigned)info.effective_mtu, (unsigned)req.carrier_mtu,
             (unsigned)info.sid);

    /* 5) Liveness shared memory page (already mapped by the driver when it set up the session; here we only get the pointer) */
    if (windev_shm_map(d, &shm, err, sizeof(err)) != WINDEV_OK) {
        log_err("Windows kernel data plane: %s", err);
        rc = -1;
        goto out;
    }

    ka_ms = pump_keepalive_ms();
    ka_fail_max = pump_ka_fail_max();
    stale = pump_rx_stale_ms();
    t_up = now_ms();
    last_ka = t_up;
    next_tick = t_up;

    /* 6) Main loop: same cadence as kdp.c (100ms sleep, 1s decision, 10s keepalive) */
    while (!g_stop && !g_user_stop) {
        uint64_t now, lr;

        port_sleep_ms(KDP_WIN_SLEEP_MS);
        now = now_ms();
        if (now < next_tick)
            continue;
        next_tick = now + KDP_WIN_POLL_MS;

        /* 6a) Is the session still there (unloading the driver or takeover by another client both invalidate it) */
        if (windev_session_get(d, &info, err, sizeof(err)) != WINDEV_OK ||
            info.enabled == 0) {
            log_err("Windows kernel data plane: session invalid (%s), session lost",
                    err[0] != '\0' ? err : "driver reports enabled bit is 0");
            session_lost = true;
            break;
        }

        /* 6b) Liveness: timestamp 0 = peer PT_CLOSE / session cleared; new timestamp = peer alive */
        lr = windev_shm_last_rx_ms(shm);
        if (lr != 0) {
            if (!seen_rx) {
                seen_rx = true;
                log_info("kernel data plane: received the peer's first valid frame (shared memory timestamp is now non-zero)");
            }
            /* Only "a new frame received" clears the failure budget: one successful send does not prove the peer exists;
             * a connected UDP socket reports ICMP port unreachable every other time. */
            if (lr != last_seen)
                ka_fail = 0;
            last_seen = lr;
        } else if (seen_rx) {
            log_err("kernel data plane: shared memory timestamp went to zero"
                    " (peer PT_CLOSE / session cleared), session lost");
            session_lost = true;
            break;
        }
        if (stale != 0) {
            /* Count from "session setup time" when no frame has ever been received (same meaning as t_up in kdp.c) */
            uint64_t quiet = seen_rx ? kdp_win_ms_since(now, last_seen)
                                     : kdp_win_ms_since(now, t_up);
            if (quiet > stale) {
                log_err("kernel data plane: no valid frame received for %llu ms"
                        " (IWAN_RX_STALE_MS=%u), session lost",
                        (unsigned long long)quiet, stale);
                session_lost = true;
                break;
            }
        }

        /* 6c) keepalive is still in userspace (10s PT_ECHO_REQ, over the client's own socket) */
        if (ka_ms != 0 && kdp_win_ms_since(now, last_ka) >= ka_ms) {
            buf_t pkt;

            buf_init(&pkt);
            /* Same as the Linux kernel plane: 60-byte ECHOREQ, tick filled from the local clock */
            iwan_echo_build(&pkt, PT_ECHO_REQ, enc, sid, tok, NULL, now_us());
            {
                ssize_t w = port_send(sockfd, pkt.data, pkt.len, 0);

                if (w < 0 || (size_t)w != pkt.len) {
                    int e = errno;

                    buf_free(&pkt);
                    if (++ka_fail >= ka_fail_max) {
                        log_err("kernel data plane: keepalive failed %u times with no downlink frames"
                                " (last error: %s); session lost", ka_fail,
                                strerror(e));
                        session_lost = true;
                        break;
                    }
                    err_printf("kernel data plane: keepalive send failed: %s"
                               " (%u/%u accumulated with no downlink frames)\n", strerror(e),
                               ka_fail, ka_fail_max);
                }
            }
            buf_free(&pkt);
            /* Advance the cadence whether or not it succeeded: a failure must be retried every ka_ms */
            last_ka = now_ms();
        }
    }

    /* 7) Exit: courtesy first, then force -- PT_CLOSE, stats, tear down the session, tear down address routes */
    if (session_up) {
        buf_t pkt;

        buf_init(&pkt);
        ctrl_hdr(&pkt, PT_CLOSE, enc, sid, tok);
        if (port_send(sockfd, pkt.data, pkt.len, 0) < 0)
            log_debug("kernel data plane: PT_CLOSE send failed: %s", strerror(errno));
        else
            err_printf("CLOSE sent\n");
        buf_free(&pkt);
    }

    if (session_up) {
        /* Same convention as on Linux: tx_bytes counts outer bytes (including encapsulation overhead).
         * M1 only has outbound encapsulation, so rx_delivered being 0 is normal (inbound decapsulation is M2). */
        log_info("kernel data plane: stats: received outer %llu frames (delivered %llu),"
                 " sent %llu frames / %llu bytes, dropped %llu, errors %llu",
                 (unsigned long long)info.stats.rx_outer,
                 (unsigned long long)info.stats.rx_delivered,
                 (unsigned long long)info.stats.tx_pkts,
                 (unsigned long long)info.stats.tx_bytes,
                 (unsigned long long)info.stats.ev_dropped,
                 (unsigned long long)info.stats.tx_err);
    }

out:
    if (routes_up)
        route_teardown(tun, server, ogw, odev, ometric, &routes);
    else if (iface_up)
        route_iface_down(tun);
    if (session_up)
        (void)windev_session_close(d, err, sizeof(err));
    if (d != NULL)
        windev_close(d);
    free(targets);
    slist_free(&routes);
    slist_free(&routes6);
    slist_free(&empty);

    if (rc == 0 && session_lost)
        rc = 1;         /* session lost: the caller should reconnect (same meaning as kdp_run) */
    return rc;
}

#endif /* _WIN32 */
