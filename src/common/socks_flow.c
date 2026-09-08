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
#include "util.h"

/* FIND-R2-4 / FIND-R2-5: bridge extensions that live in lwip_bridge.c but
 * are not declared in lwip_bridge.h (that header is outside this round's
 * editable set). ns_flow_ref/ns_flow_unref maintain the per-slot
 * flow-reference counter this layer must bump at every f->ns_idx
 * assignment/detach; ns_port_tw_held reports whether lwIP's TIME_WAIT list
 * still holds an ephemeral port. Both run on the single event-loop thread
 * that also drives lwIP, so they need no locking. */
int  ns_flow_ref(int idx);
void ns_flow_unref(int idx);
bool ns_port_tw_held(uint16_t p);

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

/* ---- brute-force auth lockout ----
 * Tracks wrong-password RFC1929 failures per source IPv4 so a brute-
 * forcing client cannot hammer the token check. Only WELL-FORMED
 * RFC1929 frames that fail the password check count: broken clients
 * (ulen=0/plen=0/bad version) and greeting-method probes are protocol
 * violations, not auth attempts, so they can neither lock a source out
 * nor be used to DoS it (a probe flood must not be able to trip the
 * lockout of the real user). After auth_fail_max() counted failures
 * within auth_fail_window_ms() the source is blocked until now+window;
 * blocked connections are dropped silently at accept() time (no bytes
 * written). A successful auth clears the source's counter. The table
 * is a fixed-size linear scan (AUTH_FAIL_TRACK_MAX entries) with
 * oldest-first eviction when full, and everything runs on the single-
 * threaded event loop, so no locking is needed. The env overrides
 * (IWAN_AUTH_FAIL_MAX / IWAN_AUTH_FAIL_WINDOW_MS) let tests shrink the
 * threshold and window without recompiling. */
#define AUTH_FAIL_MAX_DEFAULT 5
#define AUTH_FAIL_WINDOW_MS_DEFAULT 60000u
#define AUTH_FAIL_TRACK_MAX 16
static unsigned auth_fail_max(void)
{
    static int cached = -1;

    if (cached < 0)
        cached = (int)env_ms_range("IWAN_AUTH_FAIL_MAX",
                                   AUTH_FAIL_MAX_DEFAULT, 1, 100, 0,
                                   "1..100");
    return (unsigned)cached;
}

static unsigned auth_fail_window_ms(void)
{
    static int cached = -1;

    if (cached < 0)
        cached = (int)env_ms_range("IWAN_AUTH_FAIL_WINDOW_MS",
                                   AUTH_FAIL_WINDOW_MS_DEFAULT, 100,
                                   86400000, 0, "100..86400000");
    return (unsigned)cached;
}

/* Auth-failure lockout: fixed-slot table, key = peer IPv4. Params via
 * IWAN_AUTH_FAIL_MAX / IWAN_AUTH_FAIL_WINDOW_MS (tests shrink them);
 * the algorithm lives in lockout.c, shared with relay_proxy. */
static lockout_rec g_auth_fail[AUTH_FAIL_TRACK_MAX];

void auth_fail_note(uint32_t ip, bool success)
{
    lockout_note(g_auth_fail, AUTH_FAIL_TRACK_MAX, &ip, sizeof ip,
                 success, auth_fail_max(), auth_fail_window_ms(), NULL);
}

bool auth_fail_blocked(uint32_t ip)
{
    return lockout_blocked(g_auth_fail, AUTH_FAIL_TRACK_MAX, &ip,
                           sizeof ip, NULL);
}

/* ---- DNS result queue ---- */
static pthread_mutex_t g_dns_mu = PTHREAD_MUTEX_INITIALIZER;
static DnsResult g_dns_q[DNS_RESULT_Q_LEN];
static int g_dns_hd, g_dns_tl; /* ring */

/* session generation: bumped by dns_reset()/dns_stop() (run_socks).
 * Workers capture it at spawn and stop registering/sending once it
 * changes, so a worker can never touch the session socket after it was
 * closed (and possibly reused by another open()); dns_drain also drops
 * results whose generation is stale (H3). Declared before the result
 * queue: dns_drain reads it. */
static atomic_uint g_dns_gen = 1;

void dns_push_g(unsigned gen, int flow_id, bool ok, uint8_t af,
                uint32_t ip, const uint8_t ip6[16], uint16_t port) {
    pthread_mutex_lock(&g_dns_mu);
    g_dns_q[g_dns_tl].gen = gen;
    g_dns_q[g_dns_tl].flow_id = flow_id;
    g_dns_q[g_dns_tl].ok = ok;
    g_dns_q[g_dns_tl].af = af;
    g_dns_q[g_dns_tl].ip = ip;
    if (ip6)
        memcpy(g_dns_q[g_dns_tl].ip6, ip6, 16);
    g_dns_q[g_dns_tl].port = port;
    g_dns_tl = (g_dns_tl + 1) % DNS_RESULT_Q_LEN;
    if (g_dns_tl == g_dns_hd)
        g_dns_hd = (g_dns_hd + 1) % DNS_RESULT_Q_LEN; /* drop oldest */
    pthread_mutex_unlock(&g_dns_mu);
}

int dns_drain(DnsResult *out, int max) {
    int n = 0;
    /* session generation NOW: entries pushed by a torn-down session's
     * workers are dropped here, not delivered — their flow ids are
     * indistinguishable from a fresh session's (g_next_id resets to 1
     * every session), so a stale result would inject the wrong IP
     * into a new flow (SUMMARY-2 H3). Relaxed load: a torn-down
     * entry is merely discarded, and dns_reset() clears the ring
     * under this same mutex anyway. */
    unsigned cur = atomic_load_explicit(&g_dns_gen, memory_order_relaxed);
    pthread_mutex_lock(&g_dns_mu);
    while (g_dns_hd != g_dns_tl && n < max) {
        if (g_dns_q[g_dns_hd].gen == cur)
            out[n++] = g_dns_q[g_dns_hd];
        /* stale-generation entries are dropped, not delivered */
        g_dns_hd = (g_dns_hd + 1) % DNS_RESULT_Q_LEN;
    }
    pthread_mutex_unlock(&g_dns_mu);
    return n;
}

/* ---- M1 tunnel DNS: queries travel inside the VPN as inner UDP/53
 * packets; the server's kernel routes them (MASQUERADE + conntrack
 * bring the reply back). The client never emits plaintext DNS, so the
 * resolver address and every query stay inside the encrypted session. */
/* DNS_WAIT_MAX / DNS_POLL_MS / DNS_TIMEOUT_MS live in socks_internal.h */
#define DNS_MAX_RESEND  3

/* one ephemeral-port allocator for both TCP flows and tunnel DNS:
 * random start in [PORT_BASE, PORT_TOP), up to 2048 tries, collision
 * scan against the caller's predicate. Randomness matters: a sequential
 * ephemeral port would let an observer predict the inner 4-tuple and
 * forge RST/ACK segments. */
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

/* TCP-flow variant: collision scan over the active flows' local ports.
 * FIND-F03-3 / FIND-R2-4: also avoid ports lwIP still holds in TIME_WAIT
 * (2*MSL, no free callback). A slot may have been reclaimed (c->pcb=NULL)
 * while lwIP's tcp_tw_pcbs list still owns the lport; handing that port to
 * a new flow would make tcp_bind fail with ERR_USE and the connect fail
 * spuriously. ns_port_tw_held walks the bridge-side list on the same
 * single event-loop thread. */
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

typedef struct {
    int      flow_id;
    uint16_t port;
    char    *domain;
    unsigned gen;        /* session generation at spawn (see g_dns_gen) */
    uint8_t  qtype;      /* DNS query type: 1 = A, 28 = AAAA, 0 = local
                          * fallback (system resolver, AF_UNSPEC) */
} DnsJob;

/* Process-level singletons: g_dns_server_ip4 here and g_sockfd (declared
 * in socks.c, consumed by the tunnel-DNS workers below) are shared across
 * all flows. That is a deliberate single-instance design — the process
 * runs exactly one proxy, so one session socket and one resolver address
 * suffice and avoid passing them through every flow API. If the proxy is
 * ever instantiated more than once per process, both must be turned into
 * explicit parameters instead of globals. */
static char     g_dns_server_ip[16] = "system resolver";
static uint32_t g_dns_server_ip4;    /* host-order, MSB-first */
static uint16_t g_dns_ip_id;         /* inner IP ID (bumped under the lock) */
static uint64_t g_dns_ignored;       /* responses dropped by validation */

/* one pending DNS query: the response handler matches on the inner UDP
 * dst port (our random source port), then validates id + question echo */
typedef struct {
    bool     in_use;
    uint16_t dns_id;     /* DNS transaction id */
    uint16_t sport;      /* inner UDP source port (dst port on the reply) */
    uint16_t ipid;       /* inner IPv4 ID */
    uint64_t deadline;   /* absolute final timeout (ms) */
    int      resends;    /* retransmissions still allowed */
    char     domain[256];
    int      flow_id;
    uint16_t port;       /* requested remote port, replayed by dns_push */
    uint8_t  qtype;      /* query type this wait entry is for (1 / 28) */
} DnsWait;

static DnsWait g_dns_wait[DNS_WAIT_MAX];
static pthread_mutex_t g_dns_wait_mu = PTHREAD_MUTEX_INITIALIZER;
/* number of in_use wait slots (fast path for dns_try_handle_response:
 * the downlink must not take the wait-table lock for every UDP packet
 * when no tunnel-DNS query is pending). Incremented after in_use=true,
 * decremented after in_use=false, both under g_dns_wait_mu. */
static atomic_int g_dns_wait_n;

/* true when the session generation changed since this job was spawned,
 * i.e. the tunnel session was torn down and workers must stop (see
 * g_dns_gen above) */
static bool dns_stale(const DnsJob *j)
{
    return atomic_load(&g_dns_gen) != j->gen;
}

/* tunnel-DNS variant of alloc_ephemeral: collision scan over the
 * pending-query wait table (under its lock) */
static int dns_sport_in_use(uint16_t p)
{
    int used = 0;
    pthread_mutex_lock(&g_dns_wait_mu);
    for (int i = 0; i < DNS_WAIT_MAX; i++) {
        if (g_dns_wait[i].in_use && g_dns_wait[i].sport == p) {
            used = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_dns_wait_mu);
    return used;
}

static uint16_t dns_alloc_sport(void)
{
    return alloc_ephemeral(dns_sport_in_use);
}

/* checksums come from ipv4.h: ip_csum_accum/ip_csum_fold (plain IP
 * header) and ip_udp_csum (UDP + pseudo-header), shared with
 * netstack.c — no local copies. */

/* encode `domain` as a DNS qname; returns length or -1 (invalid name) */
static int dns_encode_qname(const char *domain, uint8_t *out, size_t outsz)
{
    size_t len = strlen(domain);
    size_t i, o = 0, llen = 0, lstart = 0;

    while (len > 0 && domain[len - 1] == '.')
        len--;
    if (len == 0 || len > 253)
        return -1;
    for (i = 0; i < len; i++) {
        if (domain[i] == '.') {
            if (llen == 0 || llen > 63)
                return -1;
            llen = 0;
        } else {
            llen++;
        }
    }
    if (llen == 0 || llen > 63)
        return -1;
    for (i = 0; i <= len; i++) {
        if (i == len || domain[i] == '.') {
            size_t lab = i - lstart;
            if (o + 1 + lab + 1 > outsz)
                return -1;
            if (lab > 0) {
                out[o++] = (uint8_t)lab;
                memcpy(out + o, domain + lstart, lab);
                o += lab;
            }
            lstart = i + 1;
        }
    }
    if (o + 1 > outsz)
        return -1;
    out[o++] = 0;
    return (int)o;
}

/* build a DNS query payload: header + question (qname, qtype, class IN) */
static size_t dns_build_query(uint16_t id, const char *domain, uint8_t qtype,
                              uint8_t *out, size_t outsz)
{
    int qn;
    if (outsz < 12 + 5)
        return 0;
    qn = dns_encode_qname(domain, out + 12, outsz - 12);
    if (qn < 0)
        return 0;
    out[0] = (uint8_t)(id >> 8);
    out[1] = (uint8_t)id;
    out[2] = 0x01;               /* RD */
    out[3] = 0x00;
    out[4] = 0x00;               /* QDCOUNT = 1 */
    out[5] = 0x01;
    out[6] = out[7] = out[8] = out[9] = out[10] = out[11] = 0;
    out[12 + qn]     = 0x00;     /* QTYPE = A / AAAA */
    out[12 + qn + 1] = qtype;
    out[12 + qn + 2] = 0x00;     /* QCLASS = IN */
    out[12 + qn + 3] = 0x01;
    return 12 + (size_t)qn + 4;
}

/* build the inner IPv4+UDP datagram (IP and UDP checksums computed).
 * sip/dip are host-order MSB-first (same convention as netstack.c). */
static size_t dns_build_inner(uint32_t sip, uint32_t dip, uint16_t sport,
                              uint16_t ipid, const uint8_t *dnsq,
                              size_t dnslen, uint8_t *out, size_t outsz)
{
    size_t udplen = 8 + dnslen, tot = 20 + udplen;
    uint16_t ipc, uc;
    uint8_t *u;

    if (tot > outsz)
        return 0;
    memset(out, 0, 20);
    out[0] = 0x45;               /* version 4, IHL 5 */
    out[2] = (uint8_t)(tot >> 8);/* total length */
    out[3] = (uint8_t)tot;
    out[4] = (uint8_t)(ipid >> 8); /* ID */
    out[5] = (uint8_t)ipid;
    out[8] = 64;                 /* TTL */
    out[9] = 17;                 /* proto UDP */
    out[12] = (uint8_t)(sip >> 24); out[13] = (uint8_t)(sip >> 16);
    out[14] = (uint8_t)(sip >> 8);  out[15] = (uint8_t)sip;
    out[16] = (uint8_t)(dip >> 24); out[17] = (uint8_t)(dip >> 16);
    out[18] = (uint8_t)(dip >> 8);  out[19] = (uint8_t)dip;
    ipc = ip_csum_fold(ip_csum_accum(0, out, 20));
    out[10] = (uint8_t)(ipc >> 8);
    out[11] = (uint8_t)ipc;

    u = out + 20;
    u[0] = (uint8_t)(sport >> 8);
    u[1] = (uint8_t)sport;
    u[2] = 0x00;
    u[3] = 53;                   /* dst port 53 */
    u[4] = (uint8_t)(udplen >> 8);
    u[5] = (uint8_t)udplen;
    u[6] = 0x00;                 /* checksum (computed over the zeroed field) */
    u[7] = 0x00;
    memcpy(u + 8, dnsq, dnslen);
    uc = ip_udp_csum(sip, dip, u, udplen);
    u[6] = (uint8_t)(uc >> 8);
    u[7] = (uint8_t)uc;
    return tot;
}

/* frame the inner packet with the 8-byte outer header + XOR payload */
static size_t dns_wrap_outer(const uint8_t *inner, size_t inlen,
                             uint8_t *out, size_t outsz)
{
    if (8 + inlen > outsz)
        return 0;
    memcpy(out, g_ns.outer_hdr, 8);
    memcpy(out + 8, inner, inlen);
    if (g_ns.outer_hdr[0] == PT_DATA_ENC)
        xor_crypt(out + 8, inlen, g_ns.xor_key, 8);
    return 8 + inlen;
}

/* claim a wait-table slot; all fields published under the lock */
static int dns_register(uint16_t id, uint16_t sport, const DnsJob *j)
{
    for (int spin = 0; spin < 200; spin++) {  /* up to 2s for a free slot */
        if (dns_stale(j))
            return -1;   /* session torn down: stop claiming slots */
        pthread_mutex_lock(&g_dns_wait_mu);
        for (int i = 0; i < DNS_WAIT_MAX; i++) {
            DnsWait *w = &g_dns_wait[i];
            if (w->in_use)
                continue;
            memset(w, 0, sizeof *w);
            w->dns_id = id;
            w->sport = sport;
            w->ipid = g_dns_ip_id++;
            w->deadline = now_ms() + DNS_TIMEOUT_MS;
            w->resends = DNS_MAX_RESEND;
            w->flow_id = j->flow_id;
            w->port = j->port;
            w->qtype = j->qtype;
            snprintf(w->domain, sizeof w->domain, "%s", j->domain);
            w->in_use = true;
            atomic_fetch_add_explicit(&g_dns_wait_n, 1, memory_order_release);
            pthread_mutex_unlock(&g_dns_wait_mu);
            return i;
        }
        pthread_mutex_unlock(&g_dns_wait_mu);
        port_sleep_us(10 * 1000);
    }
    return -1;
}

/* resolver configured by run_socks (server-assigned AuthResult.dns).
 * A missing/0.0.0.0 value leaves g_dns_server_ip4 == 0, which sends
 * domain resolution down the system-resolver fallback in dns_worker. */
void dns_set_server(const char *ip)
{
    uint8_t b[4];
    if (ip && ip[0] && s2ip4(ip, b) && ip4_u32(b) != 0) {
        snprintf(g_dns_server_ip, sizeof g_dns_server_ip, "%s", ip);
        g_dns_server_ip4 = ip4_u32(b);
    } else {
        g_dns_server_ip4 = 0;
    }
}

/* skip a (possibly compressed) DNS name; returns new offset or -1 */
static size_t dns_skip_name(const uint8_t *p, size_t n, size_t off)
{
    for (;;) {
        uint8_t l;
        if (off >= n)
            return (size_t)-1;
        l = p[off];
        if ((l & 0xc0) == 0xc0) {
            if (off + 2 > n)
                return (size_t)-1;
            return off + 2;
        }
        if (l & 0xc0)
            return (size_t)-1;
        off++;
        if (l == 0)
            return off;
        if (off + l > n)
            return (size_t)-1;
        off += l;
    }
}

/* consume a validated A/AAAA answer: the slot may have been recycled by
 * the timed-out worker, so only clear (and push) when it is still OUR
 * transaction. Lock order is identical for both families and matches
 * the original branches statement-for-statement: take g_dns_wait_mu,
 * re-validate slot ownership, clear in_use, release, then push (dns_push
 * takes g_dns_mu — never held here). */
static bool dns_consume_answer(int slot, uint16_t dport, uint16_t want_id,
                               int flow_id, uint16_t fport,
                               uint8_t af, uint32_t ip, const uint8_t *ip6)
{
    pthread_mutex_lock(&g_dns_wait_mu);
    {
        DnsWait *w = &g_dns_wait[slot];
        if (w->in_use && w->sport == dport && w->dns_id == want_id) {
            w->in_use = false;
            atomic_fetch_sub_explicit(&g_dns_wait_n, 1, memory_order_release);
            pthread_mutex_unlock(&g_dns_wait_mu);
            /* event-loop side: tag with the current generation so the
             * drain filter accepts it (H3) */
            dns_push_g(atomic_load(&g_dns_gen), flow_id, true, af, ip,
                       ip6, fport);
        } else {
            pthread_mutex_unlock(&g_dns_wait_mu);
        }
    }
    return true;
}

/* receive_vpn hook: consume inner IPv4 packets that are tunnel-DNS
 * responses. Returns true when the packet was taken (its dst port belongs
 * to a pending query). Validation failures are ignored and counted, so
 * spoofed/mismatched traffic can never inject an address — the entry
 * simply times out and the flow fails with rep=4. */
bool dns_try_handle_response(const uint8_t *pkt, size_t n)
{
    size_t ihl, ulen, dnslen, off;
    uint16_t dport, an, want_id, fport;
    uint8_t want_qtype;
    int slot = -1, flow_id;
    char want_domain[256];
    uint8_t q[300];
    int qn;
    const uint8_t *udp, *dns;

    if (n < 20 + 8 + 12 || pkt[9] != 17)
        return false;
    if (atomic_load_explicit(&g_dns_wait_n, memory_order_acquire) == 0)
        return false;   /* no pending tunnel-DNS query: skip lock + scan */
    ihl = (size_t)(pkt[0] & 0x0f) * 4;
    if (ihl < 20 || n < ihl + 8 + 12)
        return false;
    udp = pkt + ihl;
    dport = (uint16_t)((udp[2] << 8) | udp[3]);
    ulen = (size_t)((udp[4] << 8) | udp[5]);
    if (ulen < 8 + 12 || ihl + ulen > n)
        return false;

    pthread_mutex_lock(&g_dns_wait_mu);
    for (int i = 0; i < DNS_WAIT_MAX; i++) {
        DnsWait *w = &g_dns_wait[i];
        if (w->in_use && w->sport == dport) {
            slot = i;
            want_id = w->dns_id;
            want_qtype = w->qtype;
            flow_id = w->flow_id;
            fport = w->port;
            memcpy(want_domain, w->domain, sizeof want_domain);
            break;
        }
    }
    pthread_mutex_unlock(&g_dns_wait_mu);
    if (slot < 0)
        return false;   /* not ours: leave it for the TCP stack */

    /* ---- validation (any failure: ignore + count, never inject) ---- */
    if (udp[0] != 0 || udp[1] != 53)           /* src port must be 53 */
        goto bad;
    if (ip4_u32(pkt + 12) != g_dns_server_ip4) /* from our resolver */
        goto bad;
    if (ip4_u32(pkt + 16) != g_ns.ip)          /* addressed to our inner IP */
        goto bad;
    dns = udp + 8;
    dnslen = ulen - 8;   /* >= 12: the ulen >= 8+12 guard above */
    if (((dns[0] << 8) | dns[1]) != want_id)   /* transaction id */
        goto bad;
    {
        uint16_t flags = (uint16_t)((dns[2] << 8) | dns[3]);
        if (!(flags & 0x8000) || (flags & 0x000f) != 0) /* QR + rcode 0 */
            goto bad;
    }
    if (dns[4] != 0 || dns[5] < 1)             /* QDCOUNT >= 1 */
        goto bad;
    /* question echo: the response must repeat our exact question bytes
     * (qname + QTYPE + QCLASS IN) — a blind injector that guesses the
     * ID is still rejected */
    qn = dns_encode_qname(want_domain, q, sizeof q - 4);
    if (qn < 0)
        goto bad;
    q[qn] = 0x00; q[qn + 1] = want_qtype;
    q[qn + 2] = 0x00; q[qn + 3] = 0x01;
    qn += 4;
    if (12 + (size_t)qn > dnslen ||
        memcmp(dns + 12, q, (size_t)qn) != 0)
        goto bad;
    off = 12 + (size_t)qn;
    /* skip any extra question records (we always send exactly one) */
    for (uint16_t qd = (uint16_t)((dns[4] << 8) | dns[5]); qd > 1; qd--) {
        off = dns_skip_name(dns, dnslen, off);
        if (off == (size_t)-1 || off + 4 > dnslen)
            goto bad;
        off += 4;
    }
    an = (uint16_t)((dns[6] << 8) | dns[7]);
    for (uint16_t k = 0; k < an; k++) {
        uint16_t typ, cls, rdlen;
        off = dns_skip_name(dns, dnslen, off);
        if (off == (size_t)-1)
            goto bad;
        if (off + 10 > dnslen)
            goto bad;
        typ = (uint16_t)((dns[off] << 8) | dns[off + 1]);
        cls = (uint16_t)((dns[off + 2] << 8) | dns[off + 3]);
        rdlen = (uint16_t)((dns[off + 8] << 8) | dns[off + 9]);
        off += 10;
        if (off + rdlen > dnslen)
            goto bad;
        if (typ == want_qtype && cls == 1) {
            if (want_qtype == 1 && rdlen == 4) {
                uint32_t ip = ip4_u32(dns + off);
                return dns_consume_answer(slot, dport, want_id, flow_id,
                                          fport, 4, ip, NULL);
            }
            if (want_qtype == 28 && rdlen == 16) {
                return dns_consume_answer(slot, dport, want_id, flow_id,
                                          fport, 6, 0, dns + off);
            }
        }
        off += rdlen;
    }
bad:
    g_dns_ignored++;
    if (debug_enabled())
        log_debug("tunnel DNS: dropped invalid response (total %llu)",
                  (unsigned long long)g_dns_ignored);
    return true;   /* consumed: dst port belongs to a pending query */
}

/* retire the worker's wait-table slot if it is still ours (caller holds
 * g_dns_wait_mu) */
static void dns_retire_slot_locked(int slot, uint16_t sport, uint16_t id)
{
    if (slot < 0)
        return;
    DnsWait *w = &g_dns_wait[slot];
    if (w->in_use && w->sport == sport && w->dns_id == id) {
        w->in_use = false;
        atomic_fetch_sub_explicit(&g_dns_wait_n, 1, memory_order_release);
    }
}

/* run_socks setup: clear any state a previous session left behind —
 * result ring and wait table — so stale entries can never match a fresh
 * session's flows or queries. Also bumps the generation, retiring
 * workers that outlived the previous teardown. */
void dns_reset(void)
{
    pthread_mutex_lock(&g_dns_mu);
    g_dns_hd = g_dns_tl = 0;
    pthread_mutex_unlock(&g_dns_mu);
    pthread_mutex_lock(&g_dns_wait_mu);
    for (int i = 0; i < DNS_WAIT_MAX; i++)
        g_dns_wait[i].in_use = false;
    atomic_store_explicit(&g_dns_wait_n, 0, memory_order_release);
    atomic_fetch_add(&g_dns_gen, 1);
    pthread_mutex_unlock(&g_dns_wait_mu);
}

/* run_socks teardown: bump the generation under the wait-table lock.
 * Worker sends hold the same lock, so no worker can be mid-send when
 * this returns — the caller may close the session socket and the DNS
 * eventfd immediately after. */
void dns_stop(void)
{
    pthread_mutex_lock(&g_dns_wait_mu);
    atomic_fetch_add(&g_dns_gen, 1);
    pthread_mutex_unlock(&g_dns_wait_mu);
}

/* --- local fallback resolver -----------------------------------------
 * When the server hands out no tunnel DNS (dns=0.0.0.0 — observed on
 * the real USTC service), the SOCKS5 domain path falls back to the
 * system resolver via getaddrinfo(): whatever /etc/resolv.conf (or
 * NSS) is configured to use, no hardcoded server. Tunnel DNS stays the
 * preferred path when the server does advertise one. */

/* one-shot A/AAAA query via the system resolver. Blocks the worker
 * thread for the resolver's own timeout at worst, which only delays
 * this flow's rep=4; other flows are unaffected. */
static bool dns_query_local(const char *domain, uint8_t *af_out,
                            uint32_t *ip_out, uint8_t ip6_out[16])
{
    struct addrinfo hints, *res = NULL, *r;
    int rc;

    memset(&hints, 0, sizeof hints);
    /* dual-stack (prefer IPv6 when present) only when the server is
     * assumed to relay IPv6 (--socks-ipv6); the default assumes a
     * v4-only relay and resolves A records only — a v6-first choice
     * would blackhole dual-stack domains there (~6.5s SYN retries with
     * the 1s RTO, then rep=4). */
    hints.ai_family = socks_v6_ok() ? AF_UNSPEC : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(domain, NULL, &hints, &res);
    if (rc != 0 || !res)
        return false;
    /* prefer an IPv6 answer; fall back to IPv4 (RFC 8305-style order) */
    r = NULL;
    for (struct addrinfo *a = res; a != NULL; a = a->ai_next) {
        if (a->ai_family == AF_INET6 && a->ai_addrlen >= 16) {
            r = a;
            break;
        }
    }
    if (r == NULL) {
        for (struct addrinfo *a = res; a != NULL; a = a->ai_next) {
            if (a->ai_family == AF_INET) {
                r = a;
                break;
            }
        }
    }
    if (r == NULL) {
        freeaddrinfo(res);
        return false;
    }
    if (r->ai_family == AF_INET6) {
        /* raw wire bytes, same convention as ns_connect6 / ip6_derive_ula */
        memcpy(ip6_out,
               &((const struct sockaddr_in6 *)r->ai_addr)->sin6_addr, 16);
        *af_out = 6;
    } else {
        /* host-order MSB-first, same convention as the tunnel path's
         * dns_push()/open_tcp_connection() */
        *ip_out = ntohl(((const struct sockaddr_in *)r->ai_addr)->sin_addr.s_addr);
        *af_out = 4;
    }
    freeaddrinfo(res);
    return true;
}

static void *dns_worker(void *arg) {
    DnsJob *j = (DnsJob *)arg;
    uint8_t q[512];
    uint8_t inner[20 + 8 + 512];
    uint8_t out[8 + 20 + 8 + 512];
    uint16_t id, sport, ipid;
    size_t qlen, inlen, outlen;
    uint64_t last_send;
    int slot = -1;

    /* generation gate: a worker that started under a previous session
     * (or whose session was torn down) must not register, send, or
     * push — the flow table is gone and the socket may be closed and
     * reused by another open() */
    if (dns_stale(j))
        goto done;
    if (g_dns_server_ip4 == 0 || j->qtype == 0) {
        /* no tunnel DNS (dns=0.0.0.0) or a local-fallback worker:
         * resolve via the system resolver — no session socket involved,
         * so the socket-safety generation gate above suffices there.
         * dns_query_local BLOCKS in getaddrinfo for up to ~30s, and the
         * session can be torn down and rebuilt meanwhile: the gate must
         * be re-checked after the call, or the stale worker injects an
         * old IP into a new session's same-numbered flow (SUMMARY-2 H3;
         * dns_drain's generation filter is the second layer). */
        uint32_t lip = 0;
        uint8_t lip6[16] = {0}, af = 4;
        bool resolved = dns_query_local(j->domain, &af, &lip, lip6);
        if (dns_stale(j))
            goto done;   /* session torn down while we resolved */
        if (resolved)
            dns_push_g(j->gen, j->flow_id, true, af, lip, lip6, j->port);
        else
            dns_push_g(j->gen, j->flow_id, false, 4, 0, NULL, j->port);
        goto done;
    }
    if (g_sockfd < 0)
        goto fail;
    id = (uint16_t)rand_u32();
    qlen = dns_build_query(id, j->domain, j->qtype, q, sizeof q);
    if (qlen == 0)
        goto fail;                       /* invalid domain */
    sport = dns_alloc_sport();
    if (sport == 0)
        goto fail;
    slot = dns_register(id, sport, j);
    if (slot < 0)
        goto fail;

    /* registered BEFORE the first send: a reply that races the send can
     * never be dropped as unclaimed (the handler matches the dst port) */
    pthread_mutex_lock(&g_dns_wait_mu);
    {
        DnsWait *w = &g_dns_wait[slot];
        if (!w->in_use || w->sport != sport || w->dns_id != id) {
            pthread_mutex_unlock(&g_dns_wait_mu);
            /* consumed before our first send: the response already
             * cleared (and pushed) this slot, so this path retires
             * nothing on the way out — the index is not read again */
            goto done;
        }
        ipid = w->ipid;
        if (dns_stale(j)) {
            /* session torn down while we registered: retire the slot */
            dns_retire_slot_locked(slot, sport, id);
            pthread_mutex_unlock(&g_dns_wait_mu);
            goto done;
        }
    }
    pthread_mutex_unlock(&g_dns_wait_mu);

    inlen = dns_build_inner(g_ns.ip, g_dns_server_ip4, sport, ipid, q,
                            qlen, inner, sizeof inner);
    if (inlen == 0)
        goto fail;
    outlen = dns_wrap_outer(inner, inlen, out, sizeof out);
    if (outlen == 0)
        goto fail;
    /* first send, gated on the generation under the wait-table lock:
     * dns_stop() takes the same lock before closing the socket, so a
     * send can never race a close — and a reused fd can never receive
     * tunnel-DNS bytes from a retired session */
    pthread_mutex_lock(&g_dns_wait_mu);
    if (dns_stale(j)) {
        dns_retire_slot_locked(slot, sport, id);
        pthread_mutex_unlock(&g_dns_wait_mu);
        goto done;
    }
    if (port_send(g_sockfd, out, (int)outlen, 0) < 0 && errno != EAGAIN &&
        errno != EWOULDBLOCK) {
        /* hard send error (ENETUNREACH, EPERM, ...): fail fast — a
         * retry loop cannot succeed, and the flow would only see its
         * rep=4 after the full 1.5s deadline */
        pthread_mutex_unlock(&g_dns_wait_mu);
        log_err("tunnel DNS send failed: %s", strerror(errno));
        goto fail;
    }
    pthread_mutex_unlock(&g_dns_wait_mu);
    last_send = now_ms();

    for (;;) {
        int act = 0;             /* 0 wait, 1 resend, 2 fail, 3 done */
        uint64_t now;
        port_sleep_us(DNS_POLL_MS * 1000);
        now = now_ms();
        pthread_mutex_lock(&g_dns_wait_mu);
        if (dns_stale(j)) {
            /* session over: stop polling and resending */
            dns_retire_slot_locked(slot, sport, id);
            pthread_mutex_unlock(&g_dns_wait_mu);
            break;
        }
        {
            DnsWait *w = &g_dns_wait[slot];
            /* a recycled slot (consumed + re-registered) is not ours */
            if (!w->in_use || w->sport != sport || w->dns_id != id)
                act = 3;         /* response already handled */
            else if (now >= w->deadline) {
                w->in_use = false;
                atomic_fetch_sub_explicit(&g_dns_wait_n, 1, memory_order_release);
                act = 2;
            } else if (now - last_send >= DNS_POLL_MS && w->resends > 0) {
                w->resends--;
                /* resend under the lock: dns_stop() (generation bump +
                 * socket close) can only run between these critical
                 * sections, never mid-send */
                if (port_send(g_sockfd, out, (int)outlen, 0) >= 0)
                    last_send = now;
                /* EAGAIN/short send: last_send stays, the next 250ms
                 * tick retries */
            }
        }
        pthread_mutex_unlock(&g_dns_wait_mu);
        if (act == 3)
            break;
        if (act == 2) {
            dns_push_g(j->gen, j->flow_id, false, 4, 0, NULL, j->port);
            break;
        }
    }
    goto done;

fail:
    if (slot >= 0) {
        pthread_mutex_lock(&g_dns_wait_mu);
        dns_retire_slot_locked(slot, sport, id);
        pthread_mutex_unlock(&g_dns_wait_mu);
    }
    dns_push_g(j->gen, j->flow_id, false, 4, 0, NULL, j->port);
done:
    /* wake the event loop, unless the session is gone: its eventfd may
     * already be closed (and reused), and the loop is not waiting.
     * Same lock serializes this write against the evfd close. */
    pthread_mutex_lock(&g_dns_wait_mu);
    if (atomic_load(&g_dns_gen) == j->gen && g_dns_evfd >= 0) {
        /* EAGAIN means the eventfd counter is already non-zero: the loop
         * is (or will be) awake, so a failed wake is not an error.
         * port_evfd_wake returns -1 with errno == EAGAIN on Linux when
         * the counter is already set; on Windows the UDP-pair wake send
         * always succeeds, so this branch is inert there. */
        if (port_evfd_wake(g_dns_evfd) != 0 && errno != EAGAIN)
            log_debug("dns evfd wake: %s", strerror(errno));
    }
    pthread_mutex_unlock(&g_dns_wait_mu);
    free(j->domain);
    free(j);
    return NULL;
}

/* spawn detached threads resolving `domain` then pushing a result for
 * flow id. With tunnel DNS active, two workers run concurrently — one
 * AAAA (preferred when the server relays IPv6, --socks-ipv6), one A —
 * so dual-stack domains resolve with the latency of the faster answer;
 * the flow fails (rep=4) only after ALL its outstanding queries failed
 * (Flow.dns_pending). Without the flag (default: IPv4-only relay) only
 * the A worker runs. Without tunnel DNS a single worker uses the
 * system resolver (AF_UNSPEC, v6-preferred only when flagged). */
void spawn_dns(int flow_id, const char *domain, uint16_t port) {
    uint8_t qtypes[2] = {28, 1};   /* AAAA first, then A */
    int nq = (g_dns_server_ip4 != 0) ? 2 : 1;
    if (!socks_v6_ok()) {
        qtypes[0] = 1;             /* A only */
        nq = 1;
    }
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (g_flows[i].active && (uint64_t)flow_id == g_flows[i].id) {
            g_flows[i].dns_pending = nq;
            break;
        }
    }
    for (int k = 0; k < nq; k++) {
        pthread_t th;
        DnsJob *j = malloc(sizeof *j);
        if (!j) {
            dns_push_g(atomic_load(&g_dns_gen), flow_id, false, 4, 0,
                       NULL, port);
            continue;
        }
        j->flow_id = flow_id;
        j->port = port;
        j->domain = xstrdup(domain);
        j->gen = atomic_load(&g_dns_gen);
        j->qtype = qtypes[k];
        if (pthread_create(&th, NULL, dns_worker, j) != 0) {
            free(j->domain);
            free(j);
            dns_push_g(atomic_load(&g_dns_gen), flow_id, false, 4, 0,
                       NULL, port);
            continue;
        }
        pthread_detach(th);
    }
}

void queue_flow_output(Flow *f, const uint8_t *data, size_t n) {
    buf_put(&f->output, data, n);
}

/* SOCKS5 reply frame: ver=5, rep, rsv, atyp=1 (IPv4), bound addr+port.
 * Shared by the error path (zeroed bind) and the CONNECT success path.
 * bnd_ip is host-order MSB-first (same convention as g_ns.ip). */
static void socks_reply(Flow *f, uint8_t rep, uint32_t bnd_ip,
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
static void socks_reply6(Flow *f, uint8_t rep, const uint8_t bnd6[16],
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
         * the exhausted table visible instead of dropping in silence */
        log_err("flow table full (%d active): dropping new SOCKS5 client",
                g_flow_len);
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
        static const uint8_t v4map[12] = {
            0,0,0,0,0,0,0,0, 0,0,0xff,0xff };
        if (memcmp(p, lo, 16) == 0)
            return true;                              /* ::1 */
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
static bool flow_open_gated(Flow *f, int af, uint32_t rip,
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
         * unauthenticated probe against a token-protected proxy) */
        inet_ntop(AF_INET, &(struct in_addr){ .s_addr = f->peer_ip },
                  ipbuf, sizeof ipbuf);
        log_err("[flow %lu] SOCKS5 client %s:%u offered no acceptable "
                "method while auth is required",
                (unsigned long)f->id, ipbuf, f->peer_port);
    } else if (debug_enabled()) {
        inet_ntop(AF_INET, &(struct in_addr){ .s_addr = f->peer_ip },
                  ipbuf, sizeof ipbuf);
        log_debug("[flow %lu] SOCKS5 client %s:%u offered no acceptable "
                  "method", (unsigned long)f->id, ipbuf, f->peer_port);
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
static void flow_start_target(Flow *f, const pp_target *t)
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
        buf_consume(&f->input, 2 + (size_t)f->input.data[1]);
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
    if (pr == 0) {
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
    buf_consume(&f->input, 2 + (size_t)f->input.data[1] + 1 + plen);
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
        /* VER is 5 here: pp_socks_request rejects anything else.
         * unsupported command / bad RSV -> rep 7; unsupported or
         * empty address type -> rep 8 */
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
        if (dlen == 0) {
            /* RFC 1928: a zero-length domain is an address-type error
             * (rep=8). The frame is 5 + 0 + 2 = 7 bytes; wait until the
             * full frame has arrived so the reply is not raced. */
            if (f->input.len < req_len)
                return;
            queue_socks_error(f, 8);
            return;
        }
        buf_consume(&f->input, req_len);
        flow_start_target(f, &t);
        return;
    }
}

void process_socks_handshake(Flow *f)
{
    if (f->state == ST_GREETING) {
        if (f->http_mode) {
            http_handshake(f);
            return;
        }
        if (!handshake_greeting(f))
            return;
    }
    if (f->state == ST_REQUEST)
        handshake_request(f);
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
                            g_dns_server_ip4 == 0
                                ? "system resolver"
                                : g_dns_server_ip);
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
        if (st == NS_ESTABLISHED) {
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
                if (r2 < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    log_debug("[flow %lu] readv fd=%d nv=%d err=%s "
                              "iov0=%p/%zu",
                              (unsigned long)f->id, f->fd, nv,
                              strerror(errno), iov[0].iov_base,
                              iov[0].iov_len);
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
                        if (w > 0)
                            left -= (size_t)w;
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
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;             /* drained for now */
                } else {
                    /* hard read error (ECONNRESET when the local app
                     * RSTs, e.g. a cancelled browser tab): treat it as
                     * client EOF — close the netstack conn and move to
                     * ST_CLOSING. Leaving ST_ESTABLISHED would keep the
                     * fd in the poll set with the kernel reporting
                     * POLLERR forever (the error is not cleared by
                     * read), busy-spinning one core and leaking the
                     * fd/conn/flow triple. */
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
             * branch is not re-entered with buffered-but-unread data —
             * no busy-spin. */
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
                f->input.len >= IWAN_RESOLV_INPUT_CAP)
                continue;   /* over the cap: skip this flow this round */
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
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                /* hard read error during the handshake: the flow has no
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
            } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
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

        if (f->ns_idx >= 0 && f->output.len == 0) {
            TcpConn *c = ns_conn(&g_ns, f->ns_idx);
            if (c && c->rxq.len > 0) {
                size_t want = c->rxq.len > LOCAL_WRITE_LIMIT
                                  ? LOCAL_WRITE_LIMIT
                                  : c->rxq.len;
                struct iovec io = { .iov_base = c->rxq.data,
                                    .iov_len = want };
                ssize_t n = port_writev(f->fd, &io, 1);
                if (n > 0) {
                    if ((size_t)n == want) {
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
                           errno != EWOULDBLOCK) {
                    f->local_eof = true;
                    ns_abort(&g_ns, f->ns_idx);
                    f->rxq_waiting = false; /* dead client: no POLLOUT wake */
                    set_flow_state(f, ST_CLOSING);
                    continue;
                } else {
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
            if (c && c->state == NS_CLOSE_WAIT && c->rxq.len == 0 &&
                f->output.len == 0) {
                flowdbg(f, "CLOSE_WAIT rxq-empty -> ns_close");
                port_shutdown(f->fd, SHUT_WR);
                ns_close(&g_ns, f->ns_idx);
                set_flow_state(f, ST_CLOSING);
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
                 * last_progress_ms (service_local_outputs), so a client
                 * that IS slowly reading (peer already FIN'd, trailing
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
                 * Semantics: state_ms = when the flow *state* last
                 * changed (wall clock); last_progress_ms = when we last
                 * actually *drained* bytes to the client (progress
                 * clock). The watchdog keys off progress, so a healthy
                 * long-lived flow is never at risk while a wedged one is
                 * hard-bounded at ST_CLOSING_TIMEOUT_MS. */
                if (now_ms() - f->last_progress_ms >=
                        ST_CLOSING_TIMEOUT_MS &&
                    (f->state == ST_CLOSING ||
                     (f->state == ST_ESTABLISHED &&
                      c->state == NS_CLOSE_WAIT))) {
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
