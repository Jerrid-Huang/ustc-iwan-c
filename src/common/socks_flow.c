#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* POSIX-only headers: on Windows getaddrinfo/inet_ntop/iovec come from
 * port.h (winsock2/ws2tcpip). */
#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

/* winsock2 names the shutdown how-values SD_SEND etc.; the numeric
 * values match the POSIX SHUT_* constants, and port_shutdown passes
 * them straight through, so alias SHUT_WR for the call below. */
#ifdef _WIN32
#ifndef SHUT_WR
#define SHUT_WR 1
#endif
#endif

#include "common.h"
#include "crypto.h"
#include "ipv4.h"
#include "proto_parse.h"
#include "tcpstack.h"
#include "protocol.h"
#include "lockout.h"
#include "socks_internal.h"
#include "socks_auth_guard.h"
#include "socks_dns.h"
#include "util.h"

/* R37 R1E-1: ns_flow_ref/ns_flow_unref maintain the per-slot flow-reference
 * counter this layer must bump at every f->ns_idx assignment/detach, and
 * ns_port_tw_held reports whether lwIP's TIME_WAIT list still holds an
 * ephemeral port. They run on the single event-loop thread that also drives
 * lwIP, so they need no locking. All three are declared in the bridge header
 * (they used to be hand-written prototypes here, which let the signature
 * drift silently between the two TUs). */

#define LOCAL_WRITE_LIMIT   262144
#define LOCAL_IOV_MAX       45     /* zero-copy readv feed: reserve slots
                                    * (== NS_SCRATCH_SLOTS, lwip_bridge.c;
                                    * the iov array must hold every slot
                                    * ns_send_reservev can return) */
#define HANDSHAKE_TIMEOUT_MS 30000u /* ms: greeting/request/resolve/connect */
#define HANDSHAKE_INPUT_MAX (64 * 1024) /* handshake-phase input cap */
#define IWAN_RESOLV_INPUT_CAP (1024 * 1024) /* ST_RESOLVING input cap (M1):
                             * pipelined bytes with nowhere to go while DNS
                             * runs; over the cap the flow stops reading and
                             * the kernel buffers (backpressure) */
#define TCP_RX_CHUNK        16384
#define ST_CLOSING_TIMEOUT_MS 30000u /* R4-09-F1: bound a stuck closing flow
                             * (client never drains the queued reply) so a
                             * dead-connection flow is force-reaped instead
                             * of pinning its fd/slot forever */

static const char *flow_state_name(FlowState st)
{
    /* indexed by the FlowState enum in socks_internal.h */
    static const char *const names[] = {
        "GREETING", "REQUEST", "RESOLVING", "CONNECTING",
        "ESTABLISHED", "CLOSING",
    };
    return (size_t)st < sizeof names / sizeof names[0] ? names[st] : "?";
}

/* IPv6 relay assumption (--socks-ipv6): off by default — the server is
 * assumed to be IPv4-only, so domains resolve A-only and ATYP=4
 * CONNECTs are rejected rep=8. With the flag, v6 is preferred for
 * dual-stack domains (AAAA-first, RFC 8305-style). */
static bool socks_v6_ok(void)
{
    return g_socks_cfg && g_socks_cfg->ipv6;
}

/* diagnostic (IWAN_FLOWDBG=1): flow close triggers */
static void flowdbg(const Flow *f, const char *why)
{
    TcpConn *c;
    if (!dbg_env("IWAN_FLOWDBG"))
        return;
    c = f->ns_idx >= 0 ? ns_conn(&g_ns, f->ns_idx) : NULL;
    fprintf(stderr, "FLOWDBG: flow=%d fd=%d state=%s ns=%d conn_state=%d "
            "rxq=%llu out=%llu why=%s\n",
            (int)(f - g_flows), f->fd, flow_state_name(f->state),
            f->ns_idx, c ? (int)c->state : -1,
            c ? (unsigned long long)c->rxq.len : 0ULL,
            (unsigned long long)f->output.len, why);
}

uint64_t g_next_id = 1;
int g_flow_len;         /* active count */

void queue_flow_output(Flow *f, const uint8_t *data, size_t n) {
    buf_put(&f->output, data, n);
}

/* SOCKS5 reply frame: ver=5, rep, rsv, atyp=1 (IPv4), bound addr+port.
 * Shared by the error path (zeroed bind) and the CONNECT success path.
 * bnd_ip is host-order MSB-first (same convention as g_ns.ip). */
void socks_reply(Flow *f, uint8_t rep, uint32_t bnd_ip,
                 uint16_t bnd_port)
{
    uint8_t r[10] = {5, rep, 0, 1, 0, 0, 0, 0, 0, 0};
    r[4] = (uint8_t)(bnd_ip >> 24);
    r[5] = (uint8_t)(bnd_ip >> 16);
    r[6] = (uint8_t)(bnd_ip >> 8);
    r[7] = (uint8_t)bnd_ip;
    r[8] = (uint8_t)(bnd_port >> 8);
    r[9] = (uint8_t)bnd_port;
    queue_flow_output(f, r, sizeof r);
}

/* SOCKS5 reply with an IPv6 bound address: ver=5, rep, rsv, atyp=4,
 * 16-byte addr, port. bnd6 is raw wire bytes. */
void socks_reply6(Flow *f, uint8_t rep, const uint8_t bnd6[16],
                  uint16_t bnd_port)
{
    uint8_t r[22] = {5, rep, 0, 4};
    memcpy(r + 4, bnd6, 16);
    r[20] = (uint8_t)(bnd_port >> 8);
    r[21] = (uint8_t)bnd_port;
    queue_flow_output(f, r, sizeof r);
}

void queue_socks_error(Flow *f, uint8_t rep) {
    if (debug_enabled())
        log_debug("[flow %lu] socks error rep=%u (state %d)",
                  (unsigned long)f->id, rep, f->state);
    if (f->reply_sent) {
        /* R37 R1-A-2: the CONNECT success reply is already on the wire, so
         * every byte after it belongs to the tunnelled stream — appending a
         * second SOCKS5/HTTP reply here would inject protocol bytes into the
         * client's data (TLS/HTTP corruption) and then close the flow. This
         * is reachable from the re-auth re-establish path (open_tcp_conn_af,
         * via socks_reauth_flows) when the rebuilt stack has no free slot:
         * tear the flow down silently, no protocol-level reply. Mirrors
         * update_tcp_states, which already reports a post-reply failure as
         * ST_CLOSING only. */
        set_flow_state(f, ST_CLOSING);
        return;
    }
    if (f->http_mode) {
        /* HTTP proxy clients expect an HTTP status, not a SOCKS5 frame */
        static const char bad[] = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        queue_flow_output(f, (const uint8_t *)bad, sizeof bad - 1);
    } else {
        socks_reply(f, rep, 0, 0);
    }
    /* M-2 (R06): refresh state_ms via set_flow_state instead of writing
     * the state directly — a direct write leaves an old state_ms, so a
     * flow whose stored timestamp is already > ST_CLOSING_TIMEOUT_MS
     * gets force-reaped by reap_flows the same/next round, buf_clear()-ing
     * the error reply we just queued before it reaches the client. */
    set_flow_state(f, ST_CLOSING);
}

void set_flow_state(Flow *f, FlowState st) {
    f->state = st;
    f->state_ms = now_ms();
}

Flow *flow_alloc(struct sockaddr_in *peer) {
    Flow *f = NULL;
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (!g_flows[i].active) {
            f = &g_flows[i];
            break;
        }
    }
    if (!f) {
        /* accept_connections closes the new socket silently on NULL; make
         * the exhausted table visible instead of dropping in silence.
         *
         * R37 R6-WG2 (K-2): that visibility had no rate bound — every
         * accepted client while the table is full emits a line, so ONE
         * persistent condition (a saturated proxy) produced unbounded
         * stderr: measured at HEAD, 20 rejected connections -> 64 lines.
         * Rate-limit to one line per second, reusing the 1-line/s idiom of
         * the accept backoff (socks.c:244-250) and the relay spawn warning
         * (relay_proxy.c:1931).
         *
         * Counter type: `_Atomic uint64_t` + relaxed load/store — the
         * relay_proxy.c spelling, chosen over a plain static because the
         * condition is a process-wide singleton (`g_flows`/`g_flow_len`)
         * rather than per-flow state and this function is exported through
         * socks_internal.h: today only the single socks event-loop thread
         * reaches it (accept_connections is called once per round at
         * socks.c:1379), but the file already owns a second thread (the
         * detached tunnel-DNS worker) and a future caller must not have to
         * re-audit this site. memory_order_relaxed is sufficient and
         * deliberate: this is a best-effort diagnostic throttle, so a lost
         * update costs at most one extra line and never correctness.
         *
         * Deliberately a SEPARATE counter from greet_reject()'s below: a
         * saturated flow table and a client with no acceptable auth method
         * are different conditions, and a shared counter would let either
         * one silence the other's diagnosis for up to a second. */
        static _Atomic uint64_t last_flow_full_ms;
        uint64_t ff_now = now_ms();
        if (ff_now - atomic_load_explicit(&last_flow_full_ms,
                                         memory_order_relaxed) >= 1000) {
            atomic_store_explicit(&last_flow_full_ms, ff_now,
                                  memory_order_relaxed);
            log_err("flow table full (%d active): dropping new SOCKS5 client",
                    g_flow_len);
        }
        return NULL;
    }
    memset(f, 0, sizeof *f);
    f->active = 1;
    f->id = g_next_id++;
    f->ns_idx = -1;
    f->state = ST_GREETING;
    f->state_ms = now_ms();
    f->last_progress_ms = now_ms();   /* R07 M-1/M-3 no-progress watchdog:
                                       * explicit after memset */
    f->peer_ip = peer->sin_addr.s_addr;   /* network byte order */
    f->peer_port = ntohs(peer->sin_port); /* host order */
    if (debug_enabled()) {
        char peer_s[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &peer->sin_addr, peer_s, sizeof peer_s);
        log_debug("[flow %lu] local client %s:%u", (unsigned long)f->id,
                  peer_s, ntohs(peer->sin_port));
    }
    g_flow_len++;
    return f;
}

void flow_free(Flow *f) {
    if (!f->active)
        return;   /* never-allocated or already-freed slot: closing a
                   * zeroed fd would hit WSAENOTSOCK on Windows and
                   * g_flow_len would underflow */
    if (f->fd >= 0) {
        port_close(f->fd);   /* local client stream: a socket */
        f->fd = -1;
    }
    if (f->ns_idx >= 0) {
        TcpConn *c = ns_conn(&g_ns, f->ns_idx);
        if (c != NULL && c->pcb != NULL &&
            (c->state == NS_CLOSED || c->state == NS_FIN_WAIT)) {
            /* FIND-F5-1 / FIND-F03-5: graceful shutdown with a live pcb
             * (LAST_ACK / TIME_WAIT, or CLOSE_WAIT already answered with
             * our FIN). Do NOT abort here: aborting a TIME_WAIT pcb both
             * leaves a dangling c->pcb and, on LAST_ACK, fires a
             * gratuitous RST at the peer. The trailing rxq has already
             * been drained (reap only frees with rxq empty), so this
             * flow just drops its slot reference and closes the local fd;
             * lwIP's close state machine (LAST_ACK RTO / TIME_WAIT 2*MSL,
             * both bounded by ns_tick) and conn_reap_if_dead reclaim the
             * slot afterwards (FIND-R2-3). */
            /* no abort */
        } else {
            /* connection truly gone (pcb==NULL / slot invalid) or an
             * active-but-unfinished close (SYN_SENT / ESTABLISHED /
             * CLOSE_WAIT with a live pcb): abandon it with a RST so the
             * peer side and the slot are both freed. ns_abort is a no-op
             * when the pcb is already gone. */
            ns_abort(&g_ns, f->ns_idx);
        }
        ns_flow_unref(f->ns_idx);
    }
    buf_free(&f->input);
    buf_free(&f->output);
    f->active = 0;
    f->ns_idx = -1;
    g_flow_len--;
    if (debug_enabled())
        log_debug("[flow %lu] closed", (unsigned long)f->id);
}

/* ---- port allocation (shared alloc_ephemeral above) ---- */

/* shared connect implementation behind open_tcp_connection /
 * open_tcp_connection6: family dispatch on the parsed target. The two
 * public entry points stay as thin wrappers (both are called by name
 * from socks.c's re-auth re-establish path and the handshake code), so
 * the bridge connect / non-blocking / EINPROGRESS handling is
 * unchanged — only the surrounding bookkeeping is unified. Per-
 * connection, but still data plane. */
#define PORT_BASE 49152u
#define PORT_TOP  65535u

static uint16_t alloc_ephemeral(int (*in_use)(uint16_t p))
{
    unsigned p0 = PORT_BASE +
                  (unsigned)(rand_u32() % (PORT_TOP - PORT_BASE));
    for (int tries = 0; tries < 2048; tries++) {
        uint16_t p = (uint16_t)(PORT_BASE +
                                ((p0 - PORT_BASE + (unsigned)tries) %
                                 (PORT_TOP - PORT_BASE + 1u)));
        if (!in_use(p))
            return p;
    }
    return 0;
}

static int tcp_port_in_use(uint16_t p)
{
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (g_flows[i].active && g_flows[i].ns_idx >= 0 &&
            g_flows[i].lport == p)
            return 1;
    }
    if (ns_port_tw_held(p))
        return 1;
    return 0;
}

static uint16_t alloc_port(void)
{
    return alloc_ephemeral(tcp_port_in_use);
}

/* F4b: capacity pressure, not idleness, decides when a flow may be evicted.
 *
 * The netstack connection table has only NS_MAX_CONN (64) slots and no
 * eviction of its own: a flow pins its slot while f->ns_idx >= 0, i.e.
 * until its connection really dies. An ESTABLISHED-but-idle flow never
 * dies on its own — lwIP's keepalive probes are echoed back by the peer,
 * so the pcb stays healthy and reap_flows' no-progress watchdog (which
 * deliberately requires ST_CLOSING, or CLOSE_WAIT/NS_CLOSED) never fires
 * on it. After 64 idle-but-alive flows, every later open_tcp_conn_af
 * finds conn_slot_alloc refusing, ns_connect returns -1, and the CONNECT
 * is answered rep=0x01 forever.
 *
 * The fix is eviction UNDER PRESSURE, not a standing idle timeout: an
 * idle-but-healthy session must NOT be killed while capacity is free (a
 * quiet SOCKS session is legitimate — an idle timeout would break it for
 * no reason). Only an allocation that cannot get a slot may retire the
 * stalest idle candidate, and only then does the new flow take its place.
 *
 * Only the slot is reclaimed: the new flow keeps its own fresh local port.
 * Reusing the victim's just-released source port would hand a server or
 * stateful hop still holding 4-tuple state for the retired connection a
 * look-alike replacement it could misattribute.
 */
static bool evict_stalest_idle_flow(const Flow *self)
{
    Flow *victim = NULL;
    uint64_t now = now_ms();

    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &g_flows[i];
        TcpConn *c;
        if (!f->active || f == self || f->state != ST_ESTABLISHED ||
            f->ns_idx < 0)
            continue;
        /* Freeing a flow that still holds undelivered data would close()
         * the local client fd with bytes unread -> RST, and drop the
         * payload. Only a fully drained flow may be evicted. */
        if (f->output.len > 0 || f->rxq_waiting)
            continue;
        c = ns_conn(&g_ns, f->ns_idx);
        if (c != NULL && c->rxq.len > 0)
            continue;
        /* Not actually idle: a healthy flow in the middle of an
         * allocation burst (handshake/relay) must keep its slot. */
        if (now - f->last_progress_ms < 1000)
            continue;
        if (victim == NULL || f->last_progress_ms < victim->last_progress_ms)
            victim = f;   /* stalest last_progress_ms wins */
    }
    if (victim == NULL)
        return false;

    log_err("[flow %lu] netstack conn table full (%d slots): evicting stalest "
            "idle flow %lu (idle %llu ms)",
            (unsigned long)self->id, (int)NS_MAX_CONN,
            (unsigned long)victim->id,
            (unsigned long long)(now - victim->last_progress_ms));

    /* Retire the victim exactly like reap_flows' force-kill arm for a
     * live-pcb wedge: ns_abort is TIME_WAIT-safe (clears c->pcb), then
     * the slot reference is released and f->ns_idx detached IN THE SAME
     * ROUND — so the caller's retried ns_connect can allocate the slot
     * immediately. ST_CLOSING + the drained output above make the
     * existing reap arms collect the flow on their normal rules. */
    int vidx = victim->ns_idx;
    /* conns[] lives at a fixed address: this pointer survives the detach. */
    TcpConn *vc = ns_conn(&g_ns, vidx);

    ns_abort(&g_ns, vidx);
    ns_flow_unref(vidx);
    victim->ns_idx = -1;
    victim->local_eof = true;          /* stops POLLIN being armed */
    set_flow_state(victim, ST_CLOSING);

    /* bridge_err set reap_pending so a ST_CONNECTING flow could still read
     * term_reason, but the victim was ESTABLISHED with its reply already
     * sent and is now fully detached, so nobody needs that reason: clear
     * the guard directly and the slot is allocatable for this round's
     * retry. This replaces a mid-round ns_tick(), which would run the
     * whole bridge tick (lwIP timers) a second time in one round and let
     * flows see mixed pre-/post-tick conn state. */
    if (vc != NULL)
        vc->reap_pending = false;
    return true;
}

static void open_tcp_conn_af(Flow *f, uint8_t af, uint32_t rip,
                             const uint8_t rip6[16], uint16_t rport)
{
    uint16_t lport;
    int idx;

    lport = alloc_port();
    if (lport == 0) {
        queue_socks_error(f, 1);
        return;
    }
    idx = (af == 6) ? ns_connect6(&g_ns, lport, rip6, rport)
                    : ns_connect(&g_ns, lport, rip, rport);
    if (idx < 0) {
        /* F4b: the table was full of idle-but-alive flows. The eviction
         * released one slot in this same round, so retry ONCE with the
         * fresh port alloc_port already picked. Only a second failure is
         * a real capacity rejection. */
        if (evict_stalest_idle_flow(f)) {
            idx = (af == 6) ? ns_connect6(&g_ns, lport, rip6, rport)
                            : ns_connect(&g_ns, lport, rip, rport);
        }
    }
    if (idx < 0) {
        queue_socks_error(f, 1);
        return;
    }
    f->ns_idx = idx;
    /* FIND-R2-5: this is the ONE place a flow takes a slot reference;
     * mark it so conn_slot_alloc refuses the slot while the flow lives.
     * All f->ns_idx = -1 detach points pair with ns_flow_unref below. */
    ns_flow_ref(idx);
    f->lport = lport;
    f->tgt_af = af;
    if (af == 6)
        memcpy(f->tgt_ip6, rip6, 16);
    else
        f->tgt_ip4 = rip;
    f->tgt_port = rport;
    set_flow_state(f, ST_CONNECTING);
    if (debug_enabled()) {
        if (af == 6) {
            uint8_t b6[16];
            ip6_derive_ula(g_ns.ip, b6);
            log_debug("[flow %lu] [%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                      "%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u -> "
                      "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                      "%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u",
                      (unsigned long)f->id, b6[0], b6[1], b6[2], b6[3], b6[4],
                      b6[5], b6[6], b6[7], b6[8], b6[9], b6[10], b6[11], b6[12],
                      b6[13], b6[14], b6[15], lport, rip6[0], rip6[1], rip6[2],
                      rip6[3], rip6[4], rip6[5], rip6[6], rip6[7], rip6[8],
                      rip6[9], rip6[10], rip6[11], rip6[12], rip6[13], rip6[14],
                      rip6[15], rport);
        } else {
            uint8_t b[4];
            u32_ip4(rip, b);
            log_debug("[flow %lu] %d.%d.%d.%d:%u -> %d.%d.%d.%d:%u",
                      (unsigned long)f->id, (g_ns.ip >> 24) & 0xff,
                      (g_ns.ip >> 16) & 0xff, (g_ns.ip >> 8) & 0xff,
                      g_ns.ip & 0xff, lport, b[0], b[1], b[2], b[3], rport);
        }
    }
}

void open_tcp_connection(Flow *f, uint32_t rip, uint16_t rport) {
    open_tcp_conn_af(f, 4, rip, NULL, rport);
}

void open_tcp_connection6(Flow *f, const uint8_t rip6[16], uint16_t rport) {
    open_tcp_conn_af(f, 6, 0, rip6, rport);
}

/* ---- SSRF gate for the standalone SOCKS5/HTTP proxy ----
 * Mirrors the TUN-mode relay gate (relay_proxy.c M7): a non-loopback
 * peer must not use this proxy to reach the host's own loopback or
 * link-local services. Loopback peers keep today's local usage, and
 * IWAN_SOCKS_ALLOW_LOOPBACK=1 is an explicit operator opt-out. */
static bool socks_ssrf_off(void)
{
    static int loaded, off;
    if (!loaded) {
        loaded = 1;
        const char *v = getenv("IWAN_SOCKS_ALLOW_LOOPBACK");
        off = v && strcmp(v, "1") == 0;
    }
    return off;
}

static bool socks_peer_is_loopback(const Flow *f)
{
    /* peer_ip is sin_addr.s_addr (network byte order) */
    return (f->peer_ip & htonl(0xFF000000u)) == htonl(0x7F000000u);
}

static bool socks_target_blocked(const Flow *f, int af, const uint8_t *p)
{
    if (socks_ssrf_off() || socks_peer_is_loopback(f))
        return false;
    if (af == 4)
        return p[0] == 0 ||                          /* 0.0.0.0/8: Linux
                                                        connect() routes it
                                                        to loopback -> SSRF */
               p[0] == 127 ||                        /* 127.0.0.0/8 */
               (p[0] == 169 && p[1] == 254);         /* 169.254.0.0/16 */
    if (af == 6) {
        static const uint8_t lo[16] = {
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1 };
        static const uint8_t unspec[16] = { 0 };   /* :: */
        static const uint8_t v4map[12] = {
            0,0,0,0,0,0,0,0, 0,0,0xff,0xff };
        if (memcmp(p, lo, 16) == 0)
            return true;                              /* ::1 */
        /* R2-L33: :: — same rationale as the v4 0.0.0.0 check (Linux
         * connect(AF_INET6,[::]) routes to loopback, so it is an alternate
         * spelling of ::1 that would bypass the gate) and the same 4-line
         * branch relay_proxy.c's rp_target_blocked already carries. Keep
         * the two gates identical: this is the socks side's only loopback
         * defence. Currently unreachable (the lwIP stack has no loopback
         * netif), fixed for parity/defence in depth. */
        if (memcmp(p, unspec, 16) == 0)
            return true;                              /* :: */
        if (p[0] == 0xfe && (p[1] & 0xc0) == 0x80)
            return true;                              /* fe80::/10 */
        /* ::ffff:a.b.c.d: the mapped v4 address obeys the v4 rules,
         * else a crafted AAAA would bypass the gate; 0.0.0.0 is never a
         * legitimate proxy target (Linux routes it to loopback). */
        if (memcmp(p, v4map, 12) == 0)
            return p[12] == 0 ||                      /* ::ffff:0.0.0.0 */
                   p[12] == 127 ||                    /* ::ffff:127/8 */
                   (p[12] == 169 && p[13] == 254);    /* ::ffff:169.254 */
    }
    return false;
}

/* gate, then open. rip is host-order MSB-first (open_tcp_connection's
 * own contract); rip6 is network byte order. Returns false when the
 * gate refused the target and queued a SOCKS error reply. */
bool flow_open_gated(Flow *f, int af, uint32_t rip,
                     const uint8_t rip6[16], uint16_t port)
{
    uint8_t b4[4];
    if (af == 6) {
        if (socks_target_blocked(f, 6, rip6)) {
            queue_socks_error(f, 2);   /* connection not allowed by ruleset */
            return false;
        }
        open_tcp_connection6(f, rip6, port);
    } else {
        u32_ip4(rip, b4);
        if (socks_target_blocked(f, 4, b4)) {
            queue_socks_error(f, 2);
            return false;
        }
        open_tcp_connection(f, rip, port);
    }
    return true;
}

/* constant-time equality: the shared implementation from crypto.h
 * (ct_eq, same comparison shape) replaced the local copy */

/* RFC 1929 sub-negotiation failure: reply (ver=1, status=1) and close */
static void auth_reject(Flow *f)
{
    uint8_t r[2] = {1, 1};
    queue_flow_output(f, r, 2);
    set_flow_state(f, ST_CLOSING);
}

/* SOCKS5 greeting failure: reply (ver=5, method=0xff) and close */
static void greet_reject(Flow *f)
{
    uint8_t r[2] = {5, 0xff};
    char ipbuf[INET_ADDRSTRLEN] = "";
    if (g_socks_cfg && g_socks_cfg->auth_token) {
        /* auth is required: a client offering no acceptable method is
         * worth an error log (likely a misconfigured client or an
         * unauthenticated probe against a token-protected proxy).
         *
         * R37 R6-WG2 (K-2): one greeting per connection means one line per
         * connection, and this branch is the token-protected default an
         * unauthenticated prober drives directly (send `\x05\x01\x02` with
         * no 0x00/0x02 method and close) — measured at HEAD, 20 such
         * connections -> 64 stderr lines. Rate-limited to one line per
         * second with its own counter, independent of flow_alloc()'s
         * (different condition, neither may swallow the other); the
         * limiter also gates inet_ntop() so a rejected storm does no
         * per-connection formatting work. See flow_alloc() for why the
         * counter is `_Atomic` + relaxed. */
        static _Atomic uint64_t last_greet_reject_ms;
        uint64_t gr_now = now_ms();
        if (gr_now - atomic_load_explicit(&last_greet_reject_ms,
                                          memory_order_relaxed) >= 1000) {
            atomic_store_explicit(&last_greet_reject_ms, gr_now,
                                  memory_order_relaxed);
            inet_ntop(AF_INET, &(struct in_addr){ .s_addr = f->peer_ip },
                      ipbuf, sizeof ipbuf);
            log_err("[flow %lu] SOCKS5 client %s:%u offered no acceptable "
                    "method while auth is required",
                    (unsigned long)f->id, ipbuf, f->peer_port);
        }
    } else if (debug_enabled()) {
        /* R37 R6-WG2 (K-2): log_debug is compiled OUT in Release, but
         * Debug is exactly the diagnostic scenario this round is about
         * (same shape as R6-5 in socks.c), and this branch is the DEFAULT
         * when no token is configured — a client looping on a bad greeting
         * would flood it. Same 1-line/s treatment, own counter (it is not
         * the "auth is required" condition, so it must not share that
         * counter). */
        static _Atomic uint64_t last_greet_reject_dbg_ms;
        uint64_t grd_now = now_ms();
        if (grd_now - atomic_load_explicit(&last_greet_reject_dbg_ms,
                                           memory_order_relaxed) >= 1000) {
            atomic_store_explicit(&last_greet_reject_dbg_ms, grd_now,
                                  memory_order_relaxed);
            inet_ntop(AF_INET, &(struct in_addr){ .s_addr = f->peer_ip },
                      ipbuf, sizeof ipbuf);
            log_debug("[flow %lu] SOCKS5 client %s:%u offered no acceptable "
                      "method", (unsigned long)f->id, ipbuf, f->peer_port);
        }
    }
    queue_flow_output(f, r, 2);
    set_flow_state(f, ST_CLOSING);
}

/* CONNECT target dispatch shared by the HTTP and SOCKS5 handshakes: an
 * IPv4 literal goes straight to open_tcp_connection, an IPv6 literal is
 * relayed only under the IPv6 relay assumption (--socks-ipv6), a domain
 * goes through the async tunnel-DNS path (family decided by the result).
 * The SOCKS5 caller consumes its request frame from f->input BEFORE
 * calling this (the per-branch lengths differ — 10/22/req_len — and a
 * zero-length domain errors without consuming), so the shared part is
 * exactly this family dispatch; error handling is identical at both
 * call sites (rep=8 for an unrelayable IPv6 target). */
void flow_start_target(Flow *f, const pp_target *t)
{
    if (t->af == 4) {
        f->target_af = 4;
        /* pp stores ip4 in network byte order; the netstack wants
         * host-order MSB-first */
        flow_open_gated(f, 4, ntohl(t->ip4), NULL, t->port);
    } else if (t->af == 6) {
        if (!socks_v6_ok()) {
            /* IPv4-only relay assumption (--socks-ipv6 off): an IPv6
             * literal target cannot be relayed, so reject it like any
             * other unsupported address type instead of blackholing the
             * SYN for ~6.5s */
            queue_socks_error(f, 8);
            return;
        }
        f->target_af = 6;
        flow_open_gated(f, 6, 0, t->ip6, t->port);
    } else {
        f->target_af = 0;   /* domain: family decided by the DNS result */
        set_flow_state(f, ST_RESOLVING);
        spawn_dns((int)f->id, t->host, t->port);
    }
}

/* ST_GREETING + http_mode: parse the HTTP request header block. For
 * CONNECT the header is consumed (post-header bytes stay in f->input
 * as tunnel data); absolute-URI methods forward the entire request
 * verbatim, so nothing is consumed. Target parsing is delegated to
 * proto_parse.c (shared with the TUN-mode relay proxy). */
static void http_handshake(Flow *f)
{
    uint8_t *d = f->input.data;
    size_t n = f->input.len;
    size_t hdr, eol, mn, ts;
    pp_target t;

    /* header block ends at \r\n\r\n (real clients always send CRLF).
     * Resume the scan where the previous round stopped: input only grows
     * during the handshake, and the re-checked 3-byte overlap makes the
     * window boundaries safe, so a trickled large header (64KB of cookies)
     * costs O(n) total instead of O(n^2). */
    {
        size_t start = f->http_scan_off;
        if (start < 3 || start > n)
            start = 3;
        for (hdr = start; hdr < n; hdr++) {
            if (d[hdr - 3] == '\r' && d[hdr - 2] == '\n' &&
                d[hdr - 1] == '\r' && d[hdr] == '\n')
                break;
        }
    }
    if (hdr >= n) {
        f->http_scan_off = n >= 3 ? n - 3 : 0;
        return;                  /* header not complete: wait for more */
    }
    hdr += 1;                    /* index past the final \n */
    for (eol = 0; eol < n && d[eol] != '\r' && d[eol] != '\n'; eol++)
        ;
    for (mn = 0; mn < eol && d[mn] != ' '; mn++)
        ;
    if (mn == 0 || mn >= eol)
        goto bad;                /* no method token / no target */
    f->http_connect = (mn == 7 && memcmp(d, "CONNECT", 7) == 0);
    for (ts = mn + 1; ts < eol && d[ts] == ' '; ts++)
        ;
    if (ts >= eol)
        goto bad;
    if (pp_http_target((const char *)d + ts, eol - ts, f->http_connect,
                       &t) != 0)
        goto bad;
    if (f->http_connect)
        buf_consume(&f->input, hdr);
    flow_start_target(f, &t);   /* IPv4 / IPv6 (gate) / domain dispatch */
    return;
bad:
    queue_socks_error(f, 5);     /* http_mode -> 502 Bad Gateway */
}

/* ST_GREETING: version/method negotiation plus the RFC1929 sub-
 * negotiation when a token is configured; returns true when a CONNECT
 * request may already be buffered and should be parsed this round.
 * Frame parsing is delegated to proto_parse.c (shared with the
 * TUN-mode relay proxy). */
static bool handshake_greeting(Flow *f)
{
    if (!f->auth_pending) {
        const char *tok = g_socks_cfg ? g_socks_cfg->auth_token : NULL;
        if (f->input.len < 2)
            return false;
        /* HTTP proxy fallback: browsers and the Windows system proxy
         * speak HTTP to a plain proxy port. Only without a SOCKS5 token
         * (a token-requiring proxy must not silently accept unauthenti-
         * cated HTTP traffic, and HTTP clients cannot do RFC1929). */
        if (f->input.data[0] != 5 &&
            (!g_socks_cfg || !g_socks_cfg->auth_token)) {
            int pr = pp_http_probe(f->input.data, f->input.len);
            if (pr == 1) {
                f->http_mode = true;
                http_handshake(f);
                return false;
            }
            if (pr == -1)
                return false;    /* incomplete method token: wait */
            /* not HTTP and not SOCKS5: reject below */
        }
        uint8_t method = 0;
        if (f->input.data[0] != 5) {
            greet_reject(f);     /* not HTTP and not SOCKS5 */
            return false;
        }
        if (pp_socks_greeting(f->input.data, f->input.len, tok != NULL,
                              &method) != 0)
            return false;        /* incomplete greeting: wait */
        method = pp_socks_pick_method(tok != NULL, method);
        if (method == 0xff) {
            greet_reject(f);
            return false;
        }
        /* R24-f1 F1: snap the frame length before consuming — reading
         * f->input.data[1] inside the buf_consume argument is safe today
         * (argument evaluation precedes the memmove) but fragile. */
        {
            size_t nm = 2 + (size_t)f->input.data[1];
            buf_consume(&f->input, nm);
        }
        if (method == 2) {
            /* token mode: real RFC1929. Token-less mode with a client
             * that offered only 0x02: accept the flow and validate
             * nothing (courtesy — curl -U against a passwordless
             * proxy). */
            uint8_t ok[2] = {5, 2};
            queue_flow_output(f, ok, 2);
            f->auth_pending = true;
            return false;   /* the next round is RFC1929 */
        }
        uint8_t ok[2] = {5, 0};
        queue_flow_output(f, ok, 2);
        set_flow_state(f, ST_REQUEST);
        return true;
    }

    /* RFC1929 user/password sub-negotiation, frame
     * [0x01, ulen, user..., plen, pass...]. Like the greeting, the
     * frame is only judged once its declared length has fully arrived
     * (the 30s HANDSHAKE_TIMEOUT_MS bounds a client that stalls mid-
     * frame; the HANDSHAKE_INPUT_MAX cap bounds a lying length). A
     * partial frame waits for the next read. Zero-length fields, a
     * wrong version, or a complete frame that fails the check are
     * rejected. */
    char ipbuf[INET_ADDRSTRLEN] = "";
    char user[64];
    const uint8_t *pass;
    size_t plen;
    int pr = pp_socks_auth_frame(f->input.data, f->input.len, user,
                                 sizeof user, &pass, &plen);
    if (pr < 0)
        return false;              /* frame incomplete: wait */
    if (pr == 0 || pr == 2) {
        /* R46-L4: the parser now reports an oversized-username frame
         * (well-shaped, but ulen >= 64) as 2, distinct from "malformed"
         * (0). For THIS path both are rejects that never count toward
         * the source's lockout (M6c: only well-formed wrong passes
         * count), so they share the auth_reject — behavior is unchanged
         * from before the split. */
        inet_ntop(AF_INET, &(struct in_addr){ .s_addr = f->peer_ip },
                  ipbuf, sizeof ipbuf);
        log_debug("[flow %lu] RFC1929 auth frame malformed "
                  "from %s:%u", (unsigned long)f->id, ipbuf, f->peer_port);
        auth_reject(f);
        return false;
    }
    const char *tok = g_socks_cfg ? g_socks_cfg->auth_token : NULL;
    /* token-less mode validates nothing (the greeting already accepted
     * the flow as a courtesy) */
    bool ok = pp_socks_auth_ok(pass, plen, tok);
    /* R24-f1 F2: same fragility — pass was borrowed from f->input.data;
     * finish all reads of the buffer (incl. data[1]) before consuming. */
    {
        size_t nm = 2 + (size_t)f->input.data[1] + 1 + plen;
        buf_consume(&f->input, nm);
    }
    f->auth_pending = false;
    if (!ok) {
        /* well-formed frame, wrong password: counts toward the source's
         * brute-force lockout */
        auth_fail_note(f->peer_ip, false);
        inet_ntop(AF_INET, &(struct in_addr){ .s_addr = f->peer_ip },
                  ipbuf, sizeof ipbuf);
        log_err("[flow %lu] SOCKS5 RFC1929 auth failed (wrong password) "
                "from %s:%u", (unsigned long)f->id, ipbuf, f->peer_port);
        auth_reject(f);
        return false;
    }
    auth_fail_note(f->peer_ip, true);   /* success clears the source */
    uint8_t okr[2] = {1, 0};
    queue_flow_output(f, okr, 2);
    set_flow_state(f, ST_REQUEST);
    /* a CONNECT request may already be buffered in the same write */
    return true;
}

/* ST_REQUEST: parse the CONNECT frame (IPv4, IPv6 or domain); domains
 * go through the async tunnel-DNS path. Frame parsing is delegated to
 * proto_parse.c (shared with the TUN-mode relay proxy). */
static void handshake_request(Flow *f)
{
    uint8_t cmd, rep;
    pp_target t;

    if (pp_socks_request(f->input.data, f->input.len, &cmd, &rep, &t) != 0)
        return;                  /* frame incomplete: wait */
    if (rep != 0) {
        /* VER is 5 here: pp_socks_request already returned rep=1 for
         * any other VER. unsupported command / bad RSV -> rep 7;
         * unsupported or empty address type -> rep 8 */
        queue_socks_error(f, rep);
        return;
    }
    if (t.af == 4) {
        buf_consume(&f->input, 10);
        flow_start_target(f, &t);
        return;
    }
    if (t.af == 6) {
        /* consume the frame first: the reply must not be raced by a
         * re-parse of the same request on the next round */
        buf_consume(&f->input, 22);
        flow_start_target(f, &t);   /* gates IPv6 on --socks-ipv6 */
        return;
    }
    /* domain */
    {
        size_t dlen = (size_t)f->input.data[4];
        size_t req_len = 5 + dlen + 2;
        /* R37 R1-A-6: no zero-length-domain case here — pp_socks_request
         * already maps l == 0 to rep=8 and returned above (:1554), so this
         * code only ever sees 1..255. */
        buf_consume(&f->input, req_len);
        flow_start_target(f, &t);
        return;
    }
}

void process_socks_handshake(Flow *f)
{
    /* R37-R5 (R3-L12): a client that coalesces the greeting and its
     * RFC1929 auth frame into one write (curl -U) leaves the auth frame
     * buffered while handshake_greeting() returns false right after
     * queueing {5,2}. The old single-pass version then fell out and the
     * buffered frame waited for the NEXT event-loop round to parse it;
     * with no fd event and no lwIP timer pending that round is only
     * reached at the 1000ms poll ceiling (socks.c POLL_CEIL_MS,
     * socks.c:1354), measured 1001ms end to end. Advance every frame
     * that is already buffered, in this round.
     *
     * Bounded: every `continue` below is preceded by a strict decrease
     * of f->input.len (buf_consume of a frame the parser certified as
     * complete), and the loop refuses to continue when nothing was
     * consumed (`len >= before`), so it can never spin. At most three
     * frames can belong to the handshake (greeting -> RFC1929 ->
     * CONNECT), hence the pass cap; anything beyond CONNECT is tunnel
     * payload that ST_CONNECTING/ST_RESOLVING spills into the netstack
     * (see the state guard in service_local_inputs), not handshake
     * input. */
    for (int pass = 0; pass < 3; pass++) {
        if (f->state != ST_GREETING && f->state != ST_REQUEST)
            return;
        if (f->state == ST_GREETING) {
            if (f->http_mode) {
                http_handshake(f);
                return;
            }
            size_t before = f->input.len;
            if (handshake_greeting(f)) {
                /* method 0 (or a verified RFC1929 frame) already moved
                 * the flow to ST_REQUEST: parse CONNECT this round too
                 * when it is buffered. With no buffered byte the old
                 * code's handshake_request() call was a no-op
                 * (pp_socks_request needs >= 4 bytes), so returning here
                 * is behaviour-preserving. */
                if (f->state == ST_REQUEST && f->input.len > 0)
                    continue;
                return;
            }
            if (f->input.len >= before)
                return;      /* frame incomplete: wait for the next read */
            /* a complete frame was consumed ({5,2} may have been queued
             * for method 2, {1,0}/{1,1} for RFC1929, or nothing on the
             * reject paths, which leave ST_CLOSING and exit at the top):
             * parse whatever else came in the same write */
            continue;
        }
        handshake_request(f);   /* ST_REQUEST */
        return;
    }
}

void handle_dns_results(void) {
    DnsResult q[DNS_DRAIN_MAX];
    int n = dns_drain(q, DNS_DRAIN_MAX);
    for (int k = 0; k < n; k++) {
        for (int i = 0; i < MAX_FLOWS; i++) {
            Flow *f = &g_flows[i];
            if (!f->active || f->state != ST_RESOLVING)
                continue;
            if ((uint64_t)q[k].flow_id != f->id)
                continue;
            if (q[k].ok) {
                if (q[k].af == 6) {
                    if (debug_enabled())
                        log_debug("[flow %lu] DNS -> [IPv6] %02x%02x:%02x%02x:"
                                  "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                                  "%02x%02x:%02x%02x",
                                  (unsigned long)f->id, q[k].ip6[0],
                                  q[k].ip6[1], q[k].ip6[2], q[k].ip6[3],
                                  q[k].ip6[4], q[k].ip6[5], q[k].ip6[6],
                                  q[k].ip6[7], q[k].ip6[8], q[k].ip6[9],
                                  q[k].ip6[10], q[k].ip6[11], q[k].ip6[12],
                                  q[k].ip6[13], q[k].ip6[14], q[k].ip6[15]);
                    /* must stay consistent with flow_start_target: the
                     * reply dispatch (update_tcp_states) keys on
                     * f->target_af == 6 for a v6-format (atyp=4) reply */
                    f->target_af = 6;
                    flow_open_gated(f, 6, 0, q[k].ip6, q[k].port);
                } else {
                    if (debug_enabled())
                        log_debug("[flow %lu] DNS -> %d.%d.%d.%d",
                                  (unsigned long)f->id, (q[k].ip >> 24) & 0xff,
                                  (q[k].ip >> 16) & 0xff,
                                  (q[k].ip >> 8) & 0xff, q[k].ip & 0xff);
                    flow_open_gated(f, 4, q[k].ip, NULL, q[k].port);
                }
            } else {
                /* A dual query (AAAA+A) may still be pending: fail the
                 * flow only after the last outstanding result arrived */
                if (f->dns_pending > 0)
                    f->dns_pending--;
                if (f->dns_pending <= 0) {
                    log_err("[flow %lu] DNS failed via %s",
                            (unsigned long)f->id,
                            dns_server_name());
                    queue_socks_error(f, 4);
                }
            }
            break;
        }
    }
}

/* ms until the earliest handshake/connect flow times out, INT64_MAX if none */
int64_t next_conn_timeout_ms(void)
{
    int64_t d = INT64_MAX;
    uint64_t now = now_ms();
    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &g_flows[i];
        if (f->active && (f->state == ST_GREETING ||
                          f->state == ST_REQUEST ||
                          f->state == ST_RESOLVING ||
                          f->state == ST_CONNECTING)) {
            int64_t dd = (int64_t)(f->state_ms + HANDSHAKE_TIMEOUT_MS - now);
            if (dd < d)
                d = dd;
        }
    }
    return d;
}

void update_tcp_states(void) {
    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &g_flows[i];
        if (!f->active)
            continue;
        /* handshake states (greeting/request/DNS-resolve) time out exactly
         * like ST_CONNECTING: same window, same cleanup path. The failure
         * is the client's own silence, so a SOCKS5 client gets NO reply
         * (rep=4 would claim a connect error, and the proxy never wrote
         * a greeting it could pair the failure with): just close. HTTP-
         * mode flows get an HTTP 502, because an HTTP client expects a
         * status line for every request. */
        if (f->state == ST_GREETING || f->state == ST_REQUEST ||
            f->state == ST_RESOLVING) {
            if (now_ms() - f->state_ms >= HANDSHAKE_TIMEOUT_MS) {
                if (f->http_mode) {
                    /* HTTP clients expect a status for every request */
                    queue_socks_error(f, 5);
                } else {
                    if (debug_enabled())
                        log_debug("[flow %lu] handshake timed out (no reply)",
                                  (unsigned long)f->id);
                    set_flow_state(f, ST_CLOSING);
                }
            }
            continue;
        }
        if (f->state != ST_CONNECTING)
            continue;
        TcpConn *c = ns_conn(&g_ns, f->ns_idx);
        NsState st = c ? c->state : NS_CLOSED;
        /* R25-f1 F2: a peer that FINs immediately after our SYN-ACK leaves
         * the bridge in NS_CLOSE_WAIT (never seen as NS_ESTABLISHED). The
         * connection still established — send the success reply exactly as
         * for ESTABLISHED so the accept-then-close server works. */
        if (st == NS_ESTABLISHED || st == NS_CLOSE_WAIT) {
            if (!f->reply_sent) {
                if (f->http_connect) {
                    /* HTTP CONNECT tunnel: confirm after the tunnel is up */
                    static const char okhdr[] =
                        "HTTP/1.1 200 Connection Established\r\n\r\n";
                    queue_flow_output(f, (const uint8_t *)okhdr,
                                      sizeof okhdr - 1);
                } else if (!f->http_mode) {
                    if (f->target_af == 6) {
                        uint8_t b6[16];
                        ip6_derive_ula(g_ns.ip, b6);
                        socks_reply6(f, 0, b6, f->lport);
                    } else {
                        socks_reply(f, 0, g_ns.ip, f->lport);
                    }
                }
                f->reply_sent = true;
            }
            set_flow_state(f, ST_ESTABLISHED);
            if (debug_enabled())
                log_debug("[flow %lu] TCP established", (unsigned long)f->id);
        } else if (st == NS_CLOSED) {
            uint8_t why = c ? c->term_reason : NS_TERM_NONE;
            if (debug_enabled())
                log_debug("[flow %lu] TCP connect closed (term=%u)",
                          (unsigned long)f->id, why);
            /* NS_TERM_TIMEOUT -> rep 4 (host unreachable); RST/other ->
             * rep 5 (connection refused). Same-iteration slot reuse can
             * reset the reason before this read; worst case the flow
             * reports rep=5. A re-established flow already got its
             * success reply: close without a second reply. */
            /* R4-09-F1: detach the dead slot index BEFORE the flow leaves
             * ST_CONNECTING — term_reason was read above, and from the
             * next round on the slot may be reused for a new flow, in
             * which case a stale ns_idx would make this flow read or
             * write another flow's connection. */
            ns_flow_unref(f->ns_idx);   /* FIND-R2-5: release the slot ref */
            f->ns_idx = -1;
            if (f->reply_sent) {
                set_flow_state(f, ST_CLOSING);
            } else {
                queue_socks_error(f, why == NS_TERM_TIMEOUT ? 4 : 5);
            }
        } else if (now_ms() - f->state_ms >= HANDSHAKE_TIMEOUT_MS) {
            if (debug_enabled())
                log_debug("[flow %lu] TCP connect timed out",
                          (unsigned long)f->id);
            ns_abort(&g_ns, f->ns_idx);
            if (f->reply_sent) {
                set_flow_state(f, ST_CLOSING);
            } else {
                queue_socks_error(f, 4);
            }
        }
    }
}

/* R4-09-F1: has the netstack connection this flow references died?
 * bridge_err() marks the slot NS_CLOSED with pcb==NULL; ns_tick clears
 * reap_pending on the very next tick, after which conn_slot_alloc may
 * hand the slot to a NEW flow. While the flow still holds the index it
 * must not touch the slot — otherwise its input/output servicing reads
 * or writes another flow's connection. */
static bool flow_conn_dead(const Flow *f)
{
    TcpConn *c;
    if (f->ns_idx < 0)
        return false;
    c = ns_conn(&g_ns, f->ns_idx);
    /* FIND-F03-1: "dead" = the pcb is GONE (slot reusable, a stale
     * ns_idx would read/write another flow's conn). A graceful shutdown
     * (state==NS_CLOSED but pcb still alive in TIME_WAIT/LAST_ACK) is
     * NOT dead: the slot cannot be reused while pcb != NULL, and the
     * rxq may still hold undrained trailing response bytes that
     * service_local_outputs must deliver before the fd closes. */
    return c == NULL || c->pcb == NULL;
}

#if defined(__linux__) /* R56-001: this is called ONLY from wait_events
                        * (socks.c), whose POLLERR|POLLHUP flow convergence
                        * is Linux-gated. On Windows/macOS WSAPoll/poll
                        * report POLLHUP on a half-open socket (peer FIN
                        * read, write still open), so the ERR|HUP logic is
                        * not compiled there and this symbol must not be
                        * emitted (no undefined/dead reference). */
/* R55-SK-1: converge a flow whose local client fd just poll-reported
 * POLLERR/POLLHUP in wait_events (socks.c). Probe-verified on Linux: those
 * two bits are reported by poll() UNCONDITIONALLY (ignoring the events
 * mask), and only ever on a truly dead client socket — a clean FIN /
 * half-close never sets them while our write side is still open (a socket
 * in that state wakes only with POLLIN/POLLOUT; the events=0 control
 * returns 0), and only a pure POLLHUP (no POLLERR) appears once BOTH sides
 * have fully closed. ERR therefore means the client is gone (RST / hard
 * error): nothing more will ever be read (readv/recv would return
 * -1/ECONNRESET) and nothing more can be delivered (writes fail
 * EPIPE/ECONNRESET).
 *
 * wait_events calls this ONLY when nothing is left to deliver (output
 * empty, no rxq waiting) or after the FLOW_ERR_ROUNDS_MAX cap (whose
 * caller-side branch clears the undeliverable output first), so no queued
 * data is dropped by the transition itself.
 *
 * The transition mirrors the readv-EOF / readv-hard-error paths below
 * (local_eof, ns_close for a graceful tunnel half-close so the remote side
 * still gets its FIN, ST_CLOSING), then closes the local fd and sets
 * f->fd = -1. That fd close is the actual R55-SK-1 fix: wait_events' flow
 * registration skips fd < 0, so the dead fd leaves the poll set and can no
 * longer force port_poll() to return instantly every round — an events=0
 * slot on a POLLERR|POLLHUP fd measured 1000 rounds in 0.287 ms, i.e. the
 * zero-wait busy spin (held until reap_flows finally collected the flow,
 * ST_CLOSING_TIMEOUT_MS later, or same-round when removable). reap_flows
 * then collects the flow on its normal rules (ST_CLOSING + output empty,
 * or the 30s no-progress watchdog), and flow_free's `if (f->fd >= 0)`
 * guard skips the already-closed descriptor, so g_flow_len and the
 * fd-close ownership stay exactly as before. */
void flow_kill_dead_client(Flow *f)
{
    flowdbg(f, "poll ERR/HUP -> ns_close");
    f->local_eof = true;
    if (f->ns_idx >= 0)
        ns_close(&g_ns, f->ns_idx);
    set_flow_state(f, ST_CLOSING);
    if (f->fd >= 0) {
        port_close(f->fd);
        f->fd = -1;
    }
}
#endif /* defined(__linux__) */

void service_local_inputs(Flow *fs) {
    /* R4-09-F1: detach every flow from a dead netstack connection before
     * any handshake this round can allocate the freed slot (conn_slot_alloc
     * reuses pcb==NULL slots; a stale ns_idx would make this flow read or
     * write another flow's connection). ST_CONNECTING is handled by
     * update_tcp_states later this round (it needs term_reason for the
     * reply), and its dead slot is still reap_pending-protected today. */
    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &fs[i];
        if (f->active && f->state != ST_CONNECTING && flow_conn_dead(f)) {
            ns_flow_unref(f->ns_idx);   /* FIND-R2-5: release the slot ref */
            f->ns_idx = -1;
            set_flow_state(f, ST_CLOSING);
        }
    }
    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &fs[i];
        if (!f->active || f->local_eof)
            continue;
        /* every tick/event re-attempts the feed; if the ring is still
         * full the reserve below re-pauses for another cycle */
        f->rx_paused = false;
        if (f->ns_idx >= 0 && f->state != ST_GREETING &&
            f->state != ST_REQUEST && f->state != ST_RESOLVING &&
            f->input.len > 0) {
            /* spill leftover input into the stack's pending segment
             * slots. Also during ST_CONNECTING (SYN_SENT): a slow
             * tunnel connect (DNS + SYN over the mobile line) lets the
             * client pile up body bytes in input while the handshake
             * parser waits; the netstack accepts payload from SYN_SENT
             * on, so feed it instead of letting HANDSHAKE_INPUT_MAX
             * kill the upload. Fill up to LOCAL_IOV_MAX slots per
             * round (a one-slot spill drained 64KB in ~45 rounds,
             * collapsing buffered uploads to MSS/RTT). */
            for (;;) {
                struct iovec iov[LOCAL_IOV_MAX];
                int nv = ns_send_reservev(&g_ns, f->ns_idx, iov,
                                          LOCAL_IOV_MAX);
                if (nv == 0) {
                    f->rx_paused = true;   /* ring full: stop POLLIN */
                    break;
                }
                size_t used = 0;
                int k;
                for (k = 0; k < nv && used < f->input.len; k++) {
                    size_t take = f->input.len - used < iov[k].iov_len
                                      ? f->input.len - used
                                      : iov[k].iov_len;
                    memcpy(iov[k].iov_base, f->input.data + used, take);
                    /* R4-09-F2: ns_send_commit returns what tcp_write
                     * actually accepted; it can be 0/short on ERR_MEM
                     * (pbuf / MEMP_TCP_SEG pool exhaustion, independent
                     * of snd_buf). Only count what lwIP took — anything
                     * else must stay in f->input for a later retry. */
                    int w = ns_send_commit(&g_ns, f->ns_idx, take);
                    if (w <= 0)
                        break;   /* nothing accepted: keep take in input */
                    /* R37 R1-A-3: uplink consumption is progress too. The
                     * no-progress watchdog used to key on downlink drains
                     * only, so a healthy long upload on a half-closed
                     * (CLOSE_WAIT) connection was force-killed after 30s
                     * while every byte was still being ACKed. */
                    f->last_progress_ms = now_ms();
                    used += (size_t)w;
                    if ((size_t)w < take)
                        break;   /* partial commit: keep the remainder */
                    if (take < iov[k].iov_len)
                        break;   /* input exhausted mid-slot */
                }
                buf_consume(&f->input, used);
                if (f->input.len == 0)
                    break;
                if (k < nv)
                    break;   /* partial slot: reserve again next round */
            }
            if (f->input.len > 0) {
                f->rx_paused = true;   /* ring full: stop polling POLLIN */
                continue;
            }
        }

        if (f->ns_idx >= 0 && f->state == ST_ESTABLISHED) {
            /* zero-copy feed: one readv() fills up to 4 pending segment
             * slots (reserve never commits, so the slot pointers stay
             * stable across the batch) */
            for (;;) {
                struct iovec iov[LOCAL_IOV_MAX];
                int nv = ns_send_reservev(&g_ns, f->ns_idx, iov,
                                          LOCAL_IOV_MAX);
                if (nv == 0) {
                    /* backpressure: ring/window full. Dump the conn
                     * state at most once per second per flow so a stuck
                     * upload is diagnosable without flooding an upload
                     * that is merely running at ring capacity */
                    TcpConn *dc = ns_conn(&g_ns, f->ns_idx);
                    uint64_t nowd = now_ms();
                    if (dc && nowd - dc->last_dump_ms >= 1000) {
                        dc->last_dump_ms = nowd;
                        ns_dump_conn(&g_ns, f->ns_idx);
                    }
                    f->rx_paused = true;   /* stop polling POLLIN until
                                            * the next tick frees room */
                    break;       /* stack full: backpressure */
                }
                ssize_t r2 = port_readv(f->fd, iov, nv);
                /* R37 R3-L5 / R5-WG-B: EINTR is a retry, not a dead client.
                 * It is caught by the EAGAIN arm of the chain below, not by
                 * the hard-error arm: nothing was read and ns_send_commit was
                 * never called, so this batch's reservation is simply dropped
                 * and the next event-loop round reads again (rx_paused stays
                 * false, so POLLIN is still registered). ns_close/ns_abort
                 * here would RST the client and discard f->output. This guard
                 * therefore only logs genuinely fatal errno values. */
                if (r2 < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                    errno != EINTR) {
                    log_debug("[flow %lu] readv fd=%d nv=%d err=%s "
                              "iov0=%p/%llu",
                              (unsigned long)f->id, f->fd, nv,
                              strerror(errno), iov[0].iov_base,
                              (unsigned long long)iov[0].iov_len);
                }
                if (r2 > 0) {
                    size_t left = (size_t)r2;
                    for (int k = 0; k < nv && left > 0; k++) {
                        size_t take = left < iov[k].iov_len ? left
                                                             : iov[k].iov_len;
                        /* R4-09-F2: only count bytes lwIP actually
                         * accepted (ns_send_commit can return 0/short on
                         * ERR_MEM, independent of snd_buf). */
                        int w = ns_send_commit(&g_ns, f->ns_idx, take);
                        if (w > 0) {
                            left -= (size_t)w;
                            /* R37 R1-A-3: same as the spill path above —
                             * bytes accepted by the stack are uplink
                             * progress for the no-progress watchdog. */
                            f->last_progress_ms = now_ms();
                        }
                        if (w < (int)take)
                            break;
                    }
                    if (left > 0) {
                        /* R4-09-F2: readv already pulled these bytes out
                         * of the client socket's kernel buffer, but lwIP
                         * did not accept them — copy the uncommitted tail
                         * (contiguous in the netstack scratch) back into
                         * f->input so the spill path retries next tick
                         * instead of silently dropping the upload. */
                        TcpConn *dc = ns_conn(&g_ns, f->ns_idx);
                        if (dc) {
                            size_t tail = (size_t)r2 - left;
                            buf_put(&f->input, dc->scratch + tail, left);
                        } else {
                            /* R54-WG4-4 (C4): DEAD-ZONE DEFENSE — if the
                             * netstack connection were already gone, the
                             * tail cannot be re-linked (dc->scratch is its
                             * only copy) and these `left` bytes would be
                             * silently dropped. Under today's single-
                             * threaded event loop this branch is
                             * UNREACHABLE: ns_conn() only returns NULL for
                             * ns_idx < 0 / out of range (lwip_bridge.c),
                             * the guard above guarantees ns_idx >= 0, and
                             * nothing in the readv/ns_send_commit window
                             * detaches the flow; bridge_err() requires an
                             * lwIP callback entry that cannot interleave
                             * here. It is kept as armed dead code: a future
                             * multithreaded rewrite that can race bridge_err
                             * into this window MUST preserve the tail before
                             * touching anything — log_debug is the tripwire
                             * so the loss is never silent. rx_paused stays
                             * set (harmless: service_local_inputs clears it
                             * at the top of every round). */
                            if (debug_enabled())
                                log_debug("[flow %lu] ns_conn() NULL: "
                                          "dropping %llu uncommitted readv "
                                          "tail bytes (dead-zone defense)",
                                          (unsigned long)f->id,
                                          (unsigned long long)left);
                        }
                        f->rx_paused = true;
                        /* stop this round's readv loop: further batches
                         * would place newer bytes after the preserved tail
                         * in f->input and break stream ordering; the spill
                         * path retries the tail on a later round */
                        break;
                    }
                } else if (r2 == 0) {
#ifndef _WIN32
                    /* diagnostic: why did readv return EOF while the app
                     * is still connected? dump fd state. fstat on a
                     * socket is POSIX-only; this block is debug-only. */
                    if (dbg_env("IWAN_FLOWDBG")) {
                        struct stat st;
                        int soerr = 0;
                        socklen_t sl = sizeof soerr;
                        fprintf(stderr,
                                "FLOWDBG: readv EOF fd=%d fstat=%d "
                                "mode=%o soerr=", f->fd,
                                fstat(f->fd, &st), st.st_mode);
                        if (port_getsockopt(f->fd, SOL_SOCKET, SO_ERROR,
                                            &soerr, &sl) == 0)
                            fprintf(stderr, "%d (%s)\n", soerr,
                                    strerror(soerr));
                        else
                            fprintf(stderr, "getsockopt fail\n");
                    }
#endif
                    f->local_eof = true;
                    flowdbg(f, "readv EOF -> ns_close");
                    ns_close(&g_ns, f->ns_idx);
                    set_flow_state(f, ST_CLOSING);
                    break;
                } else if (errno == EAGAIN || errno == EWOULDBLOCK ||
                           errno == EINTR) {
                    break;             /* drained for now — EINTR retried
                                        * next round: nothing was read and no
                                        * reserved slot was committed */
                } else {
                    /* hard read error (ECONNRESET when the local app
                     * RSTs, e.g. a cancelled browser tab): treat it as
                     * client EOF — close the netstack conn and move to
                     * ST_CLOSING.
                     *
                     * R55-SK-1: the OLD argument said leaving
                     * ST_ESTABLISHED "would keep the fd in the poll set
                     * with the kernel reporting POLLERR forever (the
                     * error is not cleared by read), busy-spinning one
                     * core and leaking the fd/conn/flow triple" — i.e.
                     * that moving to ST_CLOSING was enough to stop the
                     * spin. That is FALSE on Linux: poll() reports
                     * POLLERR/POLLHUP unconditionally, ignoring the
                     * events mask, so the events=0 slot wait_events
                     * registers for this ST_CLOSING flow STILL wakes
                     * every round (measured: poll(events=0) on an
                     * RST'd fd returns revents=0x18 in ~0.287 ms/1000
                     * rounds), holding the zero-wait busy spin until
                     * reap_flows finally collects the flow. The move to
                     * ST_CLOSING (plus the feed-stop below) is still
                     * REQUIRED — it stops POLLIN/POLLOUT wakes and the
                     * unbounded buffering — but the spin is actually
                     * broken by wait_events (socks.c) now detecting the
                     * unconditional ERR/HUP wake and calling
                     * flow_kill_dead_client() to close the dead fd, so
                     * it leaves the poll set entirely. */
                    flowdbg(f, "readv err -> ns_close");
                    f->local_eof = true;
                    ns_close(&g_ns, f->ns_idx);
                    set_flow_state(f, ST_CLOSING);
                    break;
                }
            }
        } else if (f->state != ST_ESTABLISHED) {
            /* M-1 (R06): a CLOSING flow must stop reading entirely. It
             * has no parser to consume the bytes, and input has no cap
             * here (the HANDSHAKE_INPUT_MAX guard above only covers
             * ST_GREETING/ST_REQUEST), so a client that keeps writing
             * during the 30s close window would inflate f->input until
             * buf_ensure hits oom_abort and kills the whole process. The
             * peer no longer needs the reads anyway (we already sent our
             * close). socks.c wait_events drops the POLLIN registration
             * for ST_CLOSING in lockstep (parallel agent C), so this
             * branch is not re-entered with buffered-but-unread data.
             * R55-SK-1: that events=0 registration alone does NOT stop
             * the wakeup on a dead client — poll reports ERR/HUP
             * unconditionally — so wait_events additionally closes the
             * dead fd (flow_kill_dead_client); until that happens this
             * branch has no data to lose and simply skips. */
            if (f->state == ST_CLOSING)
                continue;
            /* greeting/request (or CONNECTING): read into rbuf for the
             * handshake parser. An ESTABLISHED flow whose conn vanished
             * (dead tunnel, in-place re-auth pending) is NOT read: the
             * kernel socket buffers the client's bytes (backpressure)
             * until the re-established connection drains them. */
            /* M1 (SUMMARY-2): a RESOLVING flow's pipelined bytes have
             * nowhere to go (the ST_CONNECTING spill needs ns_idx >= 0,
             * and ns_idx stays -1 until DNS completes), so bound them:
             * stop reading once input reaches IWAN_RESOLV_INPUT_CAP —
             * the kernel socket buffers the rest (backpressure), and
             * this branch re-enters every event-loop round, so reading
             * resumes as soon as the resolution lands and the spill
             * drains input below the cap. A CONNECT header plus a
             * normal pipelined request is far below 1MB; previously the
             * input grew unboundedly for up to the 30s DNS window and
             * buf_ensure failure aborted the whole process. */
            if (f->state == ST_RESOLVING &&
                f->input.len >= IWAN_RESOLV_INPUT_CAP) {
                /* R37 R1-A-4: skip the flow but ALSO arm the backpressure
                 * flag. Without it wait_events kept POLLIN registered, the
                 * socket stayed readable and poll() returned instantly for
                 * the whole DNS window (measured 620k rounds / 1.5s CPU).
                 * The flag must be set HERE (after the per-round reset at
                 * the top of this loop) because wait_events — its only
                 * consumer — runs later in the same round. The flow is not
                 * wedged: the flag only suppresses POLLIN until the next
                 * round, DNS completion moves the flow to ST_CONNECTING and
                 * the spill path drains input below the cap. */
                f->rx_paused = true;
                continue;   /* over the cap: skip this flow this round */
            }
            uint8_t rbuf[TCP_RX_CHUNK];
            ssize_t n = port_recv(f->fd, rbuf, sizeof rbuf, 0);
            if (n == 0) {
                /* client gone before the handshake finished: close the
                 * flow so reap_flows collects it (previously the slot
                 * and fd leaked forever and poll busy-spun on the EOF) */
                f->local_eof = true;
                set_flow_state(f, ST_CLOSING);
            } else if (n > 0) {
                buf_put(&f->input, rbuf, (size_t)n);
                /* Handshake-phase unbounded-input guard: bound only the
                 * frame parsing states (greeting/request). Once the
                 * connect is in flight (ST_CONNECTING) or DNS is running
                 * (ST_RESOLVING, M4/bughunt), buffered bytes are tunnel
                 * payload the client pipelined before the SOCKS reply —
                 * the ST_CONNECTING spill in service_local_inputs feeds
                 * them into the netstack, and ST_RESOLVING lands there
                 * right after DNS completes, so a large HTTP upload
                 * during a slow connect/DNS must NOT be killed by this
                 * cap (previously ST_RESOLVING was still listed here and
                 * a >HANDSHAKE_INPUT_MAX body killed the flow while its
                 * ns_idx was still -1). */
                if (f->input.len > HANDSHAKE_INPUT_MAX &&
                    (f->state == ST_GREETING ||
                     f->state == ST_REQUEST)) {
                    f->local_eof = true;
                    set_flow_state(f, ST_CLOSING);
                }
            } else if (errno != EAGAIN && errno != EWOULDBLOCK &&
                       errno != EINTR) {
                /* hard read error during the handshake (R37 R3-L5: EINTR
                 * is retried next round, not treated as hard): the flow has no
                 * netstack conn, so close it unconditionally — leaving
                 * ST_GREETING would hold the fd/slot until the 30s
                 * timeout while poll busy-spins on the dead fd */
                f->local_eof = true;
                if (f->ns_idx >= 0)
                    ns_abort(&g_ns, f->ns_idx);
                set_flow_state(f, ST_CLOSING);
            }
            /* run the parser whenever bytes are buffered, not only after
             * a fresh read: a client that sends greeting+CONNECT in one
             * write (or one segment) leaves CONNECT stranded in input
             * otherwise and the handshake stalls forever */
            if (f->input.len > 0)
                process_socks_handshake(f);
        }
    }
}

void service_local_outputs(void) {
    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &g_flows[i];
        if (!f->active)
            continue;

        while (f->output.len > 0) {
            ssize_t n = port_send(f->fd, f->output.data, f->output.len, 0);
            if (n > 0) {
                if ((size_t)n == f->output.len)
                    buf_clear(&f->output);   /* full drain: no memmove */
                else
                    buf_consume(&f->output, (size_t)n);
                /* R07 M-1/M-3: any actual byte written to the client is
                 * progress — resets the no-progress watchdog */
                f->last_progress_ms = now_ms();
            } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                                 errno == EINTR || errno == ENOBUFS ||
                                 errno == ENOMEM)) {
                /* R37 R3-L5: EINTR keeps the queued output for the next
                 * round; the old code fell into the hard-error branch and
                 * buf_clear()ed replies the client never got. R23
                 * (R22-B1-1): ENOBUFS/ENOMEM are the same transient
                 * send-pressure class the relay and UDP pump already
                 * retry — the local client's buffer stays intact and the
                 * next POLLOUT drains it, instead of dropping bytes and
                 * closing the flow.
                 * R25 (R24-A3-1): with ENOBUFS/ENOMEM the socket can stay
                 * POLLOUT-armed/ready while the kernel keeps refusing the
                 * write — without a backoff the event loop re-enters this
                 * arm every round (hot spin on one core; the no-progress
                 * watchdog excludes ESTABLISHED flows). Back off 1 ms for
                 * that pair, same as relay rp_send_full_payload. */
                if (errno == ENOBUFS || errno == ENOMEM)
                    port_sleep_ms(1);
                break;
            } else {
                f->local_eof = true;
                if (f->ns_idx >= 0)
                    ns_abort(&g_ns, f->ns_idx);
                buf_clear(&f->output);
                f->rxq_waiting = false;   /* dead client: no POLLOUT wake */
                set_flow_state(f, ST_CLOSING);
                break;
            }
        }

        /* R37 R1-A-1: never hand inner payload to the client before the
         * CONNECT success reply. update_tcp_states queues that reply only at
         * the END of the round (it runs after this function), so a peer that
         * sends data together with its SYN-ACK (SMTP/FTP/SSH/MySQL banners,
         * early HTTP error pages) would otherwise deliver the payload first
         * and desynchronize the client's protocol parser. reply_sent is the
         * "the client may receive inner bytes now" flag; output.len == 0
         * additionally waits until the queued reply has been written out.
         * Buffering instead of sending cannot wedge the flow: the reply is
         * queued in the same round the connection establishes (ESTABLISHED
         * or CLOSE_WAIT), so the drain starts one round later, and a flow
         * whose reply never appears is an error/close path whose rxq is
         * discarded by the bounded reap (ST_CLOSING_TIMEOUT_MS). */
        if (f->ns_idx >= 0 && f->output.len == 0 && f->reply_sent) {
            TcpConn *c = ns_conn(&g_ns, f->ns_idx);
            if (c && c->rxq.len > 0) {
                size_t want = c->rxq.len > LOCAL_WRITE_LIMIT
                                  ? LOCAL_WRITE_LIMIT
                                  : c->rxq.len;
                struct iovec io = { .iov_base = c->rxq.data,
                                    .iov_len = want };
                ssize_t n = port_writev(f->fd, &io, 1);
                if (n > 0) {
                    /* R21 (F1-A): "full drain" must compare against the
                     * ACTUAL buffered length, not the capped `want`: when
                     * rxq.len > LOCAL_WRITE_LIMIT (in-flight overrun past a
                     * full TCP window), n == want only means the cap was
                     * written — buf_clear here would silently drop the
                     * unsent tail while conn_reconcile_rxq tcp_recved()s
                     * those bytes upstream (permanent stream corruption).
                     * The ==len case is the common lossless path and still
                     * takes the O(1) reset. */
                    if ((size_t)n == c->rxq.len) {
                        /* full drain (the common case): the payload is
                         * already on the local socket, so reset the
                         * buffer without the O(n) memmove — with a
                         * 256KB rxq the per-round shift used to cost
                         * ~4x of the 64KB-era and dominated the loop
                         * at 4+ conns (socks-down collapsed to
                         * ~1800 Mbit/s aggregate) */
                        buf_clear(&c->rxq);
                        f->rxq_waiting = false;
                    } else {
                        buf_consume(&c->rxq, (size_t)n);  /* partial */
                        f->rxq_waiting = true;
                    }
                    /* R07 M-1/M-3: rxq -> client drain is the key
                     * progress signal — even a partial write resets the
                     * no-progress watchdog */
                    f->last_progress_ms = now_ms();
                } else if (n < 0 && errno != EAGAIN &&
                           errno != EWOULDBLOCK && errno != EINTR &&
                           /* R23 (R22-B1-1): ENOBUFS/ENOMEM are transient
                            * send pressure (local socket buffer/memory), the
                            * same class the relay and UDP pump retry — keep
                            * the rxq tail and wait for the next POLLOUT
                            * rather than aborting the flow and dropping it */
                           errno != ENOBUFS && errno != ENOMEM) {
                    f->local_eof = true;
                    ns_abort(&g_ns, f->ns_idx);
                    f->rxq_waiting = false; /* dead client: no POLLOUT wake */
                    set_flow_state(f, ST_CLOSING);
                    continue;
                } else {
                    /* R25 (R24-A3-1): same 1 ms backoff as the main drain
                     * — ENOBUFS/ENOMEM with POLLOUT ready would otherwise
                     * re-enter every round and hot-spin one core (relay
                     * rp_send_full_payload precedent) */
                    if (n < 0 && (errno == ENOBUFS || errno == ENOMEM))
                        port_sleep_ms(1);
                    f->rxq_waiting = true;
                }
            } else {
                /* nothing pending toward the client: cancel the POLLOUT
                 * wake, otherwise a stale flag would spin the loop */
                f->rxq_waiting = false;
            }
        }

        if (f->ns_idx >= 0) {
            TcpConn *c = ns_conn(&g_ns, f->ns_idx);
            /* R25-f1 F2: an accepted-then-closed server can deliver the
             * peer FIN in the same round the connect completes, moving the
             * bridge to NS_CLOSE_WAIT BEFORE update_tcp_states has sent the
             * SOCKS/HTTP success reply (service_local_outputs runs first).
             * Only close when the flow is ESTABLISHED and already replied
             * (reply_sent) — otherwise the reply would be silently dropped
             * and the client's CONNECT lost.
             * R37 R1-A-3: and only when no uplink data is still queued for
             * the connection. A peer FIN closes the peer's SEND direction
             * only: a client that is still uploading must keep going, and
             * propagating the FIN now would close our send side (and stop
             * reading the client) while f->input still holds bytes to
             * deliver — a healthy long upload on a half-closed connection
             * was cut off and then reaped as "stuck". The shortcut still
             * fires as soon as that queue drains. */
            if (c && c->state == NS_CLOSE_WAIT && f->reply_sent &&
                c->rxq.len == 0 && f->output.len == 0 && f->input.len == 0) {
                /* R37 R1-A-3 (WG3): deliver the peer's EOF first and our own
                 * FIN only when the local client has really stopped
                 * uploading. A peer FIN closes the peer's SEND direction
                 * only; the local client may still be uploading on this
                 * half-closed connection. The previous code sent our FIN in
                 * the same breath, which was reachable even for an actively
                 * uploading flow: service_local_inputs (which runs just
                 * before this function) can absorb the whole f->input into
                 * the stack, so input.len was transiently 0 here and the
                 * upload's send direction was cut off (lwIP LAST_ACK) and
                 * then reaped as "dead" with its buffered bytes dropped.
                 * Now: EOF to the client is immediate and idempotent
                 * (shutdown(SHUT_WR) on an already-shut socket returns 0 on
                 * Linux), and last_progress_ms — refreshed by every uplink
                 * byte accepted in service_local_inputs (R1-A-3) — decides
                 * when our FIN may go out. A client that keeps uploading
                 * keeps the flow alive; one that went idle for a full close
                 * timeout is closed exactly as the old code did, still
                 * bounded, and still with a clean FIN rather than a RST. */
                port_shutdown(f->fd, SHUT_WR);
                if (now_ms() - f->last_progress_ms >=
                        ST_CLOSING_TIMEOUT_MS) {
                    flowdbg(f, "CLOSE_WAIT drained + idle -> ns_close");
                    ns_close(&g_ns, f->ns_idx);
                    set_flow_state(f, ST_CLOSING);
                }
            }
        }
    }
}

void reap_flows(void) {
    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &g_flows[i];
        int removable = 0;
        if (!f->active)
            continue;
        if (f->state == ST_ESTABLISHED && f->ns_idx < 0) {
            log_err("[flow %lu] ESTABLISHED with no netstack conn: converging "
                    "(invariant repair)", (unsigned long)f->id);
            f->local_eof = true;            /* stops POLLIN being armed */
            set_flow_state(f, ST_CLOSING);  /* existing arms then reap it */
        }
        if (f->ns_idx >= 0) {
            TcpConn *c = ns_conn(&g_ns, f->ns_idx);
            if (c == NULL || c->pcb == NULL) {
                /* R4-09-F1 / FIND-F03-1: connection DIED (pcb gone, slot
                 * reusable) — detach the slot index so it can be reused
                 * safely; the flow is drained and reaped as a closing
                 * flow below. Note: a graceful shutdown (state==NS_CLOSED
                 * but pcb alive in TIME_WAIT/LAST_ACK) falls through to
                 * the removable branch — it may still hold trailing rxq
                 * bytes, and "don't free while undelivered data remains"
                 * must keep the slot until they are drained. */
                ns_flow_unref(f->ns_idx);   /* FIND-R2-5: release the slot ref */
                f->ns_idx = -1;
                set_flow_state(f, ST_CLOSING);
            } else {
                /* the netstack rxq is the flow's receive buffer: a flow
                 * must not be freed while it still holds undelivered data
                 * — the close(fd) would reset the client socket (RST on
                 * unread data) and the rxq payload would be lost.
                 * R07 M-1/M-3: that "keep until drained" grace is now a
                 * NO-PROGRESS watchdog keyed on last_progress_ms, not a
                 * pure wall-clock from ST_CLOSING entry (state_ms). Every
                 * actual drain of rxq/output to the client refreshes
                 * last_progress_ms (service_local_outputs) and so does every
                 * byte accepted from the local client into the netstack
                 * (service_local_inputs, R37 R1-A-3), so a client that IS
                 * slowly reading (peer already FIN'd, trailing
                 * rxq still being drained) is never killed while it makes
                 * progress — that wall-clock regression (R6 H-1's 30s
                 * pure-timeout killing a legitimately slow-draining
                 * TIME_WAIT tail) is M-3. But a client that makes NO
                 * progress for a full close timeout while the pcb is
                 * still alive is force-terminated, which closes both:
                 *   - H-1: stuck graceful close (TIME_WAIT/LAST_ACK, pcb
                 *     alive). lwIP frees a TIME_WAIT pcb silently after
                 *     2*MSL with no callback, leaving c->pcb dangling ->
                 *     UAF in ns_tick. Force-terminate (ns_abort is
                 *     TW-safe: tcp_abort + unconditional c->pcb clear,
                 *     R2-1) and release the slot ref so the ns_idx<0
                 *     path force-reaps this flow (same round when the
                 *     old state_ms is likewise overdue).
                 *   - M-1: passive CLOSE_WAIT deadlock. Peer FIN'd
                 *     (c->state == NS_CLOSE_WAIT) but the local client
                 *     never reads, so rxq stays non-empty and the
                 *     graceful ns_close path never fires; the flow sits
                 *     in ST_ESTABLISHED forever (ns_tick's SYN_SENT /
                 *     FIN_WAIT / LAST_ACK timeouts all miss) and the
                 *     64-slot table / fd / flow entry is pinned
                 *     permanently. No progress for 30s -> force-kill it
                 *     here too.
                 *   - R22-B/C: attached graceful flow in NS_CLOSED
                 *     (peer already FIN'd, we are in LAST_ACK/TIME_WAIT)
                 *     whose trailing rxq is stuck (local client stopped
                 *     reading). It is NOT removable (rxq.len > 0) and
                 *     NOT covered by ns_tick's FIN_WAIT/LAST_ACK/SYN_SENT
                 *     timeouts, and conn_reap_if_dead cannot reclaim it
                 *     while this flow still holds the slot ref -> the
                 *     slot+pcb+flow would be pinned forever. Treat it
                 *     like CLOSE_WAIT: no progress for 30s -> force-kill
                 *     (ns_abort is TW-safe and clears c->pcb, so the
                 *     later silent lwIP TW free can never dangle).
                 * Semantics: state_ms = when the flow *state* last
                 * changed (wall clock); last_progress_ms = when the flow
                 * last moved bytes in EITHER direction (progress clock).
                 * The watchdog keys off progress, so a healthy
                 * long-lived flow is never at risk while a wedged one is
                 * hard-bounded at ST_CLOSING_TIMEOUT_MS. */
                if (now_ms() - f->last_progress_ms >=
                        ST_CLOSING_TIMEOUT_MS &&
                    (f->state == ST_CLOSING ||
                     /* R37 R1-A-3 + R2-L1: an ESTABLISHED flow in
                      * CLOSE_WAIT/NS_CLOSED is "stuck" when the progress
                      * clock has not moved for a full window.
                      * last_progress_ms is a BIDIRECTIONAL clock: every
                      * uplink byte the stack accepts refreshes it in
                      * service_local_inputs (R1-A-3) and every downlink
                      * drain refreshes it in service_local_outputs. A
                      * continuously-uploading half-closed flow therefore
                      * stays alive on its own (measured: since_progress
                      * 1 ms while 16 MB were ACKed) — the A-3 protection
                      * does NOT depend on the rxq/output requirement that
                      * used to be here.
                      * R2-L1: that requirement is exactly what removed the
                      * 30s upper bound. With rxq and output empty and the
                      * peer no longer ACKing, ns_send_commit stops accepting
                      * bytes (no refresh), f->input stays non-empty (so the
                      * CLOSE_WAIT shortcut in service_local_outputs never
                      * closes it) and rxq/output stay empty (so the old
                      * clause never matched): the flow pinned its fd, flow
                      * slot and conn slot forever. Dropping the clause
                      * restores a bounded "no progress at all" window while
                      * keeping the uplink-aware clock — this is NOT the old
                      * downlink-only criterion. A genuinely idle half-closed
                      * flow (f->input empty too) is still finished by the
                      * CLOSE_WAIT shortcut's clean ns_close on the same
                      * timeout, and a healthy ESTABLISHED conn is untouched
                      * (requires NS_CLOSE_WAIT/NS_CLOSED). */
                     (f->state == ST_ESTABLISHED &&
                      (c->state == NS_CLOSE_WAIT ||
                       c->state == NS_CLOSED)))) {
                    ns_abort(&g_ns, f->ns_idx);
                    ns_flow_unref(f->ns_idx);
                    f->ns_idx = -1;
                    if (f->state != ST_CLOSING) {
                        /* M-1: ST_ESTABLISHED + CLOSE_WAIT wedge. Jump
                         * straight to ST_CLOSING WITHOUT set_flow_state —
                         * keep the old state_ms/last_progress_ms so the
                         * ns_idx < 0 block below (state==ST_CLOSING &&
                         * timed out) force-reaps this flow the same
                         * round (buf_clear + removable = 1), dropping
                         * the undelivered rxq/data. This deliberate
                         * force-reap is exactly the "kill the stuck flow,
                         * discard undelivered data" semantic — it is NOT
                         * the M-2 case where an error reply must not be
                         * cleared before delivery (there we use
                         * set_flow_state to refresh the clock instead). */
                        f->state = ST_CLOSING;
                    }
                    /* H-1 already ST_CLOSING: keep ST_CLOSING + old
                     * state_ms/last_progress_ms (do not refresh the
                     * clock) — the ns_idx < 0 block below
                     * (state==ST_CLOSING && timed out) force-reaps it,
                     * immediately when the old state_ms is overdue too,
                     * else once that ages out. */
                } else {
                    removable = c->state == NS_CLOSED && c->rxq.len == 0 &&
                                f->output.len == 0;
                }
            }
        }
        if (f->ns_idx < 0) {
            if (f->state == ST_CLOSING &&
                now_ms() - f->state_ms >= ST_CLOSING_TIMEOUT_MS) {
                /* client never drained the reply: force-reap the flow */
                buf_clear(&f->output);
                removable = 1;
            } else {
                removable = f->state == ST_CLOSING && f->output.len == 0;
            }
        }
        if (removable) {
            flow_free(f);
        }
    }
}
