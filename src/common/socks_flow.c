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
#include "netstack.h"
#include "protocol.h"
#include "socks_internal.h"
#include "util.h"

#define LOCAL_WRITE_LIMIT   262144
#define LOCAL_IOV_MAX       4      /* zero-copy readv feed: reserve slots */
#define HANDSHAKE_TIMEOUT_MS 30000u /* ms: greeting/request/resolve/connect */
#define HANDSHAKE_INPUT_MAX (64 * 1024) /* handshake-phase input cap */
#define TCP_RX_CHUNK        16384

static const char *flow_state_name(FlowState st)
{
    /* indexed by the FlowState enum in socks_internal.h */
    static const char *const names[] = {
        "GREETING", "REQUEST", "RESOLVING", "CONNECTING",
        "ESTABLISHED", "CLOSING",
    };
    return (size_t)st < sizeof names / sizeof names[0] ? names[st] : "?";
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
typedef struct {
    uint32_t ip;               /* peer IPv4, network byte order */
    int      fail;
    uint64_t first_fail_ms;
    uint64_t blocked_until_ms; /* 0 = not blocked */
} AuthFailRec;
static AuthFailRec g_auth_fail[AUTH_FAIL_TRACK_MAX];

static unsigned auth_fail_max(void)
{
    const char *v = getenv("IWAN_AUTH_FAIL_MAX");
    char *end;
    unsigned long n;
    static int cached = -1;

    if (cached >= 0)
        return (unsigned)cached;
    if (!v || !v[0]) {
        cached = (int)AUTH_FAIL_MAX_DEFAULT;
        return AUTH_FAIL_MAX_DEFAULT;
    }
    n = strtoul(v, &end, 10);
    if (end == v || *end != '\0' || n < 1 || n > 100) {
        log_err("IWAN_AUTH_FAIL_MAX: invalid value '%s' (1..100); "
                "using default", v);
        cached = (int)AUTH_FAIL_MAX_DEFAULT;
        return AUTH_FAIL_MAX_DEFAULT;
    }
    cached = (int)n;
    return (unsigned)n;
}

static unsigned auth_fail_window_ms(void)
{
    const char *v = getenv("IWAN_AUTH_FAIL_WINDOW_MS");
    char *end;
    unsigned long n;
    static int cached = -1;

    if (cached >= 0)
        return (unsigned)cached;
    if (!v || !v[0]) {
        cached = (int)AUTH_FAIL_WINDOW_MS_DEFAULT;
        return AUTH_FAIL_WINDOW_MS_DEFAULT;
    }
    n = strtoul(v, &end, 10);
    if (end == v || *end != '\0' || n < 100 || n > 86400000) {
        log_err("IWAN_AUTH_FAIL_WINDOW_MS: invalid value '%s' "
                "(100..86400000); using default", v);
        cached = (int)AUTH_FAIL_WINDOW_MS_DEFAULT;
        return AUTH_FAIL_WINDOW_MS_DEFAULT;
    }
    cached = (int)n;
    return (unsigned)n;
}

void auth_fail_note(uint32_t ip, bool success)
{
    uint64_t now = now_ms();
    AuthFailRec *e = NULL;
    AuthFailRec *oldest = &g_auth_fail[0];

    if (success) {
        for (int i = 0; i < AUTH_FAIL_TRACK_MAX; i++) {
            if (g_auth_fail[i].ip == ip) {
                memset(&g_auth_fail[i], 0, sizeof g_auth_fail[i]);
                return;
            }
        }
        return;
    }
    for (int i = 0; i < AUTH_FAIL_TRACK_MAX; i++) {
        AuthFailRec *r = &g_auth_fail[i];
        if (r->ip == ip) {
            e = r;
            break;
        }
        /* empty slot wins; otherwise keep the oldest first_fail_ms
         * (the entry that would age out first) */
        if (r->ip == 0 || r->first_fail_ms < oldest->first_fail_ms)
            oldest = r;
    }
    if (!e)
        e = oldest;
    /* fresh entry, or the previous burst aged out of the window */
    if (e->first_fail_ms == 0 ||
        now - e->first_fail_ms > auth_fail_window_ms()) {
        e->ip = ip;
        e->fail = 1;
        e->first_fail_ms = now;
        e->blocked_until_ms = 0;
        return;
    }
    e->ip = ip;
    e->fail++;
    if (e->fail >= (int)auth_fail_max())
        e->blocked_until_ms = now + auth_fail_window_ms();
}

bool auth_fail_blocked(uint32_t ip)
{
    for (int i = 0; i < AUTH_FAIL_TRACK_MAX; i++) {
        if (g_auth_fail[i].ip == ip && g_auth_fail[i].blocked_until_ms != 0)
            return g_auth_fail[i].blocked_until_ms > now_ms();
    }
    return false;
}

/* ---- DNS result queue ---- */
static pthread_mutex_t g_dns_mu = PTHREAD_MUTEX_INITIALIZER;
static DnsResult g_dns_q[DNS_RESULT_Q_LEN];
static int g_dns_hd, g_dns_tl; /* ring */

void dns_push(int flow_id, bool ok, uint32_t ip, uint16_t port) {
    pthread_mutex_lock(&g_dns_mu);
    g_dns_q[g_dns_tl].flow_id = flow_id;
    g_dns_q[g_dns_tl].ok = ok;
    g_dns_q[g_dns_tl].ip = ip;
    g_dns_q[g_dns_tl].port = port;
    g_dns_tl = (g_dns_tl + 1) % DNS_RESULT_Q_LEN;
    if (g_dns_tl == g_dns_hd)
        g_dns_hd = (g_dns_hd + 1) % DNS_RESULT_Q_LEN; /* drop oldest */
    pthread_mutex_unlock(&g_dns_mu);
}

int dns_drain(DnsResult *out, int max) {
    int n = 0;
    pthread_mutex_lock(&g_dns_mu);
    while (g_dns_hd != g_dns_tl && n < max) {
        out[n++] = g_dns_q[g_dns_hd];
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

/* TCP-flow variant: collision scan over the active flows' local ports */
static int tcp_port_in_use(uint16_t p)
{
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (g_flows[i].active && g_flows[i].ns_idx >= 0 &&
            g_flows[i].lport == p)
            return 1;
    }
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
} DnsWait;

static DnsWait g_dns_wait[DNS_WAIT_MAX];
static pthread_mutex_t g_dns_wait_mu = PTHREAD_MUTEX_INITIALIZER;

/* session generation: bumped by dns_reset()/dns_stop() (run_socks).
 * Workers capture it at spawn and stop registering/sending once it
 * changes, so a worker can never touch the session socket after it was
 * closed (and possibly reused by another open()). */
static atomic_uint g_dns_gen = 1;

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

/* build a DNS query payload: header + question (qname, type A, class IN) */
static size_t dns_build_query(uint16_t id, const char *domain,
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
    out[12 + qn]     = 0x00;     /* QTYPE = A */
    out[12 + qn + 1] = 0x01;
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
        if (atomic_load(&g_dns_gen) != j->gen)
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
            snprintf(w->domain, sizeof w->domain, "%s", j->domain);
            w->in_use = true;
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

/* receive_vpn hook: consume inner IPv4 packets that are tunnel-DNS
 * responses. Returns true when the packet was taken (its dst port belongs
 * to a pending query). Validation failures are ignored and counted, so
 * spoofed/mismatched traffic can never inject an address — the entry
 * simply times out and the flow fails with rep=4. */
bool dns_try_handle_response(const uint8_t *pkt, size_t n)
{
    size_t ihl, ulen, dnslen, off;
    uint16_t dport, an, want_id, fport;
    int slot = -1, flow_id;
    char want_domain[256];
    uint8_t q[300];
    int qn;
    const uint8_t *udp, *dns;

    if (n < 20 + 8 + 12 || pkt[9] != 17)
        return false;
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
    dnslen = ulen - 8;
    if (dnslen < 12)
        goto bad;
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
     * (qname + QTYPE A + QCLASS IN) — a blind injector that guesses the
     * ID is still rejected */
    qn = dns_encode_qname(want_domain, q, sizeof q - 4);
    if (qn < 0)
        goto bad;
    q[qn] = 0x00; q[qn + 1] = 0x01;
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
        if (typ == 1 && cls == 1 && rdlen == 4) {
            uint32_t ip = ip4_u32(dns + off);
            /* slot may have been recycled by the timed-out worker: only
             * consume (and push) when it is still OUR transaction */
            pthread_mutex_lock(&g_dns_wait_mu);
            {
                DnsWait *w = &g_dns_wait[slot];
                if (w->in_use && w->sport == dport &&
                    w->dns_id == want_id) {
                    w->in_use = false;
                    pthread_mutex_unlock(&g_dns_wait_mu);
                    dns_push(flow_id, true, ip, fport);
                } else {
                    pthread_mutex_unlock(&g_dns_wait_mu);
                }
            }
            return true;
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
    if (w->in_use && w->sport == sport && w->dns_id == id)
        w->in_use = false;
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

/* one-shot local A query via the system resolver. Blocks the worker
 * thread for the resolver's own timeout at worst, which only delays
 * this flow's rep=4; other flows are unaffected. */
static bool dns_query_local(const char *domain, uint32_t *ip_out)
{
    struct addrinfo hints, *res = NULL;
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;      /* the tunnel stack is IPv4-only */
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(domain, NULL, &hints, &res);
    if (rc != 0 || !res)
        return false;
    /* host-order MSB-first, same convention as the tunnel path's
     * dns_push()/open_tcp_connection() */
    *ip_out = ntohl(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr);
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
    if (atomic_load(&g_dns_gen) != j->gen)
        goto done;
    if (g_dns_server_ip4 == 0) {
        /* server handed out no tunnel DNS (dns=0.0.0.0): resolve via
         * the system resolver — no session socket involved, so the
         * generation gate above is sufficient */
        uint32_t lip;
        if (dns_query_local(j->domain, &lip))
            dns_push(j->flow_id, true, lip, j->port);
        else
            dns_push(j->flow_id, false, 0, j->port);
        goto done;
    }
    if (g_sockfd < 0)
        goto fail;
    id = (uint16_t)rand_u32();
    qlen = dns_build_query(id, j->domain, q, sizeof q);
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
            slot = -1;                   /* consumed before our first send */
            goto done;
        }
        ipid = w->ipid;
        if (atomic_load(&g_dns_gen) != j->gen) {
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
    if (atomic_load(&g_dns_gen) != j->gen) {
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
        if (atomic_load(&g_dns_gen) != j->gen) {
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
            dns_push(j->flow_id, false, 0, j->port);
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
    dns_push(j->flow_id, false, 0, j->port);
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

/* spawn detached thread resolving `domain` then pushing a result for flow id. */
void spawn_dns(int flow_id, const char *domain, uint16_t port) {
    pthread_t th;
    DnsJob *j = malloc(sizeof *j);
    if (!j) {
        dns_push(flow_id, false, 0, port);
        return;
    }
    j->flow_id = flow_id;
    j->port = port;
    j->domain = xstrdup(domain);
    j->gen = atomic_load(&g_dns_gen);
    if (pthread_create(&th, NULL, dns_worker, j) != 0) {
        free(j->domain);
        free(j);
        dns_push(flow_id, false, 0, port);
        return;
    }
    pthread_detach(th);
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
    f->state = ST_CLOSING;
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
    if (f->ns_idx >= 0)
        ns_abort(&g_ns, f->ns_idx);
    buf_free(&f->input);
    buf_free(&f->output);
    f->active = 0;
    f->ns_idx = -1;
    g_flow_len--;
    if (debug_enabled())
        log_debug("[flow %lu] closed", (unsigned long)f->id);
}

/* ---- port allocation (shared alloc_ephemeral above) ---- */

void open_tcp_connection(Flow *f, uint32_t rip, uint16_t rport) {
    uint16_t lport = alloc_port();
    if (lport == 0) {
        queue_socks_error(f, 1);
        return;
    }
    int idx = ns_connect(&g_ns, lport, rip, rport);
    if (idx < 0) {
        queue_socks_error(f, 1);
        return;
    }
    f->ns_idx = idx;
    f->lport = lport;
    set_flow_state(f, ST_CONNECTING);
    if (debug_enabled()) {
        uint8_t b[4];
        u32_ip4(rip, b);
        log_debug("[flow %lu] %d.%d.%d.%d:%u -> %d.%d.%d.%d:%u",
                  (unsigned long)f->id, (g_ns.ip >> 24) & 0xff,
                  (g_ns.ip >> 16) & 0xff, (g_ns.ip >> 8) & 0xff,
                  g_ns.ip & 0xff, lport, b[0], b[1], b[2], b[3], rport);
    }
}

/* constant-time equality: both buffers are exactly n bytes (the caller
 * rejects length mismatches first), so the loop hides the comparison
 * shape from timing */
static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= a[i] ^ b[i];
    return d == 0;
}

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

/* ---- HTTP proxy fallback ----
 * Browsers and the Windows system proxy speak HTTP CONNECT (and
 * absolute-URI GET/POST) to a plain proxy port; the SOCKS5-only
 * handshake rejected them with greet_reject. Detect an HTTP method
 * line in the greeting buffer and switch the flow into HTTP mode.
 */

/* Probe the buffered greeting for an HTTP method line. Returns 1 when
 * the buffer starts with a known method token followed by a space, -1
 * when the first byte could still begin a method but the token is
 * incomplete (wait for more data), 0 otherwise (not HTTP). */
static int greeting_http_probe(const uint8_t *d, size_t n)
{
    static const char *const methods[] = {
        "CONNECT", "GET", "POST", "HEAD", "PUT", "DELETE",
        "OPTIONS", "TRACE", "PATCH",
    };
    static const size_t lens[] = {7, 3, 4, 4, 3, 6, 7, 5, 5};

    if (n == 0)
        return -1;
    for (int i = 0; i < (int)(sizeof lens / sizeof lens[0]); i++) {
        if (n >= lens[i] && memcmp(d, methods[i], lens[i]) == 0) {
            if (n > lens[i] && d[lens[i]] == ' ')
                return 1;
            return n == lens[i] ? -1 : 0;   /* wait / wrong delimiter */
        }
    }
    /* first byte could still start a method whose token is incomplete */
    if (d[0] == 'C' || d[0] == 'O' || d[0] == 'D' ||
        (n < 3 && (d[0] == 'G' || d[0] == 'P' || d[0] == 'T')) ||
        (n < 4 && d[0] == 'H'))
        return -1;
    return 0;
}

/* Parse an HTTP request target: for CONNECT an authority "host:port",
 * for other methods an absolute URI "http://host[:port]/path". IPv4
 * literals return 1 (ip4 filled), domains return 0 (domain filled),
 * anything malformed returns -1. */
static int http_parse_target(const char *s, size_t n, bool is_connect,
                             uint32_t *ip4_out, char *domain, size_t dsz,
                             uint16_t *port_out)
{
    size_t i;
    const char *host;
    size_t hn;
    uint16_t port = is_connect ? 443 : 80;

    if (n == 0)
        return -1;
    if (!is_connect) {
        /* strip scheme for absolute-URI requests */
        if (n >= 7 && strncasecmp(s, "http://", 7) == 0) {
            s += 7;
            n -= 7;
        } else if (n >= 8 && strncasecmp(s, "https://", 8) == 0) {
            s += 8;
            n -= 8;
        }
        if (n == 0)
            return -1;
        /* host part ends at '/', '?' or '#' */
        for (i = 0; i < n; i++) {
            char c = s[i];
            if (c == '/' || c == '?' || c == '#') {
                n = i;
                break;
            }
        }
    }
    if (n == 0)
        return -1;
    /* CONNECT: the authority is followed by a space and the HTTP
     * version (CONNECT host:443 HTTP/1.1); cut at the space too */
    for (i = 0; i < n; i++) {
        if (s[i] == ' ') {
            n = i;
            break;
        }
    }
    if (n == 0)
        return -1;
    if (s[0] == '[')
        return -1;              /* IPv6 literal: netstack is IPv4-only */
    /* split host:port at the (single) colon */
    {
        const char *colon = NULL;
        for (i = 0; i < n; i++) {
            if (s[i] == ':') {
                if (i == n - 1 || colon)
                    return -1;
                colon = s + i;
            }
        }
        if (colon) {
            const char *ps = colon + 1;
            size_t pn = n - (size_t)(colon + 1 - s);
            unsigned long v = 0;
            for (i = 0; i < pn; i++) {
                if (ps[i] < '0' || ps[i] > '9')
                    return -1;
                v = v * 10 + (unsigned long)(ps[i] - '0');
                if (v > 65535)
                    return -1;
            }
            if (pn == 0)
                return -1;
            port = (uint16_t)v;
            host = s;
            hn = (size_t)(colon - s);
        } else {
            host = s;
            hn = n;
        }
    }
    if (hn == 0 || hn > dsz - 1)
        return -1;
    /* host charset: letters, digits, '.', '-', '_' */
    for (i = 0; i < hn; i++) {
        char c = host[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'))
            return -1;
    }
    memcpy(domain, host, hn);
    domain[hn] = 0;
    *port_out = port;
    if (inet_pton(AF_INET, domain, ip4_out) == 1)
        return 1;               /* IPv4 literal */
    return 0;                   /* domain: async tunnel DNS */
}

/* ST_GREETING + http_mode: parse the HTTP request header block. For
 * CONNECT the header is consumed (post-header bytes stay in f->input
 * as tunnel data); absolute-URI methods forward the entire request
 * verbatim, so nothing is consumed. */
static void http_handshake(Flow *f)
{
    uint8_t *d = f->input.data;
    size_t n = f->input.len;
    size_t hdr, eol, mn, ts;
    char domain[256];
    uint32_t ip4 = 0;
    uint16_t port;
    int r;

    /* header block ends at \r\n\r\n (real clients always send CRLF) */
    for (hdr = 3; hdr < n; hdr++) {
        if (d[hdr - 3] == '\r' && d[hdr - 2] == '\n' &&
            d[hdr - 1] == '\r' && d[hdr] == '\n')
            break;
    }
    if (hdr >= n)
        return;                  /* header not complete: wait for more */
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
    r = http_parse_target((const char *)d + ts, eol - ts, f->http_connect,
                          &ip4, domain, sizeof domain, &port);
    if (r < 0)
        goto bad;
    if (f->http_connect)
        buf_consume(&f->input, hdr);
    if (r == 1)
        open_tcp_connection(f, ip4, port);
    else {
        set_flow_state(f, ST_RESOLVING);
        spawn_dns((int)f->id, domain, port);
    }
    return;
bad:
    queue_socks_error(f, 5);     /* http_mode -> 502 Bad Gateway */
}

/* ST_GREETING: version/method negotiation plus the RFC1929 sub-
 * negotiation when a token is configured; returns true when a CONNECT
 * request may already be buffered and should be parsed this round */
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
            int pr = greeting_http_probe(f->input.data, f->input.len);
            if (pr == 1) {
                f->http_mode = true;
                http_handshake(f);
                return false;
            }
            if (pr == -1)
                return false;    /* incomplete method token: wait */
            /* not HTTP and not SOCKS5: reject below */
        }
        size_t nmethods = f->input.data[1];
        if (f->input.len < 2 + nmethods)
            return false;
        int want = tok ? 2 : 0;   /* RFC1929 when a token is set */
        int has = 0;
        for (size_t i = 0; i < nmethods; i++) {
            if (f->input.data[2 + i] == want)
                has = 1;
        }
        if (f->input.data[0] != 5 || !has) {
            greet_reject(f);
            return false;
        }
        buf_consume(&f->input, 2 + nmethods);
        if (tok) {
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
    if (f->input.len < 2)
        return false;              /* ulen not delivered yet: wait */
    char ipbuf[INET_ADDRSTRLEN] = "";
    size_t ulen = f->input.data[1];
    if (ulen == 0) {
        inet_ntop(AF_INET, &(struct in_addr){ .s_addr = f->peer_ip },
                  ipbuf, sizeof ipbuf);
        log_debug("[flow %lu] RFC1929 auth frame malformed (ulen=0) "
                  "from %s:%u", (unsigned long)f->id, ipbuf, f->peer_port);
        auth_reject(f);            /* complete header, invalid length */
        return false;
    }
    if (f->input.len < 2 + ulen + 1)
        return false;              /* plen byte not delivered yet: wait */
    size_t plen = f->input.data[2 + ulen];
    if (plen == 0) {
        inet_ntop(AF_INET, &(struct in_addr){ .s_addr = f->peer_ip },
                  ipbuf, sizeof ipbuf);
        log_debug("[flow %lu] RFC1929 auth frame malformed (plen=0) "
                  "from %s:%u", (unsigned long)f->id, ipbuf, f->peer_port);
        auth_reject(f);            /* complete frame, invalid length */
        return false;
    }
    if (f->input.len < 2 + ulen + 1 + plen)
        return false;              /* password not fully delivered: wait */
    if (f->input.data[0] != 1) {
        inet_ntop(AF_INET, &(struct in_addr){ .s_addr = f->peer_ip },
                  ipbuf, sizeof ipbuf);
        log_debug("[flow %lu] RFC1929 auth frame malformed (bad version) "
                  "from %s:%u", (unsigned long)f->id, ipbuf, f->peer_port);
        auth_reject(f);
        return false;
    }
    const char *tok = g_socks_cfg ? g_socks_cfg->auth_token : NULL;
    size_t tlen = tok ? strlen(tok) : 0;
    const uint8_t *pass = f->input.data + 2 + ulen + 1;
    int ok = tok && plen == tlen &&
             ct_eq(pass, (const uint8_t *)tok, tlen);
    buf_consume(&f->input, 2 + ulen + 1 + plen);
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

/* ST_REQUEST: parse the CONNECT frame (IPv4 or domain); domains go
 * through the async tunnel-DNS path */
static void handshake_request(Flow *f)
{
    if (f->input.len < 4)
        return;
    /* RFC 1928: the request header is [VER, CMD, RSV, ATYP]; VER must
     * be 5 (any other version is a general failure, rep=1) */
    if (f->input.data[0] != 5) {
        queue_socks_error(f, 1);
        return;
    }
    /* RFC 1928: only CONNECT(1) is implemented; other commands (BIND=2,
     * UDP ASSOCIATE=3) are rejected with rep=7 (command not supported) */
    if (f->input.data[1] != 1) {
        queue_socks_error(f, 7);
        return;
    }
    /* RFC 1928: RSV must be zero; a nonzero reserved byte is a malformed
     * frame and gets the same rep=7 as an unsupported command */
    if (f->input.data[2] != 0) {
        queue_socks_error(f, 7);
        return;
    }
    uint8_t atyp = f->input.data[3];
    switch (atyp) {
    case 1: { /* IPv4 */
        if (f->input.len < 10)
            return;
        uint32_t rip =
            ((uint32_t)f->input.data[4] << 24) |
            ((uint32_t)f->input.data[5] << 16) |
            ((uint32_t)f->input.data[6] << 8) | f->input.data[7];
        uint16_t rport = (uint16_t)((f->input.data[8] << 8) | f->input.data[9]);
        buf_consume(&f->input, 10);
        open_tcp_connection(f, rip, rport);
        return;
    }
    case 3: { /* domain */
        if (f->input.len < 5)
            return;
        size_t dlen = f->input.data[4];
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
        if (f->input.len < req_len)
            return;
        char domain[256];
        size_t n = dlen;
        if (n > sizeof domain - 1)
            n = sizeof domain - 1;
        memcpy(domain, f->input.data + 5, n);
        domain[n] = 0;
        uint16_t rport = (uint16_t)((f->input.data[5 + dlen] << 8) |
                                    f->input.data[6 + dlen]);
        buf_consume(&f->input, req_len);
        set_flow_state(f, ST_RESOLVING);
        spawn_dns((int)f->id, domain, rport);
        return;
    }
    default:
        queue_socks_error(f, 8);
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
                if (debug_enabled())
                    log_debug("[flow %lu] DNS -> %d.%d.%d.%d",
                              (unsigned long)f->id, (q[k].ip >> 24) & 0xff,
                              (q[k].ip >> 16) & 0xff, (q[k].ip >> 8) & 0xff,
                              q[k].ip & 0xff);
                open_tcp_connection(f, q[k].ip, q[k].port);
            } else {
                log_err("[flow %lu] DNS failed via %s", (unsigned long)f->id,
                        g_dns_server_ip4 == 0
                            ? "system resolver"
                            : g_dns_server_ip);
                queue_socks_error(f, 4);
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
            if (f->http_connect) {
                /* HTTP CONNECT tunnel: confirm after the tunnel is up */
                static const char okhdr[] =
                    "HTTP/1.1 200 Connection Established\r\n\r\n";
                queue_flow_output(f, (const uint8_t *)okhdr,
                                  sizeof okhdr - 1);
            } else if (!f->http_mode) {
                socks_reply(f, 0, g_ns.ip, f->lport);
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
             * reports rep=5. */
            queue_socks_error(f, why == NS_TERM_TIMEOUT ? 4 : 5);
        } else if (now_ms() - f->state_ms >= HANDSHAKE_TIMEOUT_MS) {
            if (debug_enabled())
                log_debug("[flow %lu] TCP connect timed out",
                          (unsigned long)f->id);
            ns_abort(&g_ns, f->ns_idx);
            queue_socks_error(f, 4);
        }
    }
}

void service_local_inputs(Flow *fs) {
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
            /* spill leftover input into the stack's pending segment slot.
             * Also during ST_CONNECTING (SYN_SENT): a slow tunnel connect
             * (DNS + SYN over the mobile line) lets the client pile up
             * body bytes in input while the handshake parser waits; the
             * netstack accepts payload from SYN_SENT on, so feed it
             * instead of letting HANDSHAKE_INPUT_MAX kill the upload. */
            size_t room = 0;
            uint8_t *dst = ns_send_reserve(&g_ns, f->ns_idx, &room);
            if (dst && room > 0) {
                size_t n = f->input.len > room ? room : f->input.len;
                memcpy(dst, f->input.data, n);
                ns_send_commit(&g_ns, f->ns_idx, n);
                buf_consume(&f->input, n);
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
                        ns_send_commit(&g_ns, f->ns_idx, take);
                        left -= take;
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
        } else {
            /* greeting/request: read into rbuf for the handshake parser */
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
                 * frame parsing states (greeting/request/DNS). Once the
                 * connect is in flight (ST_CONNECTING) the buffered
                 * bytes are tunnel payload — the ST_CONNECTING spill in
                 * service_local_inputs feeds them into the netstack
                 * (and pauses reads when the ring is full), so a large
                 * HTTP upload during a slow connect must NOT be killed
                 * by this cap. */
                if (f->input.len > HANDSHAKE_INPUT_MAX &&
                    (f->state == ST_GREETING ||
                     f->state == ST_REQUEST ||
                     f->state == ST_RESOLVING)) {
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
            } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            } else {
                f->local_eof = true;
                if (f->ns_idx >= 0)
                    ns_abort(&g_ns, f->ns_idx);
                buf_clear(&f->output);
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
                    } else {
                        buf_consume(&c->rxq, (size_t)n);  /* partial */
                    }
                } else if (n < 0 && errno != EAGAIN &&
                           errno != EWOULDBLOCK) {
                    f->local_eof = true;
                    ns_abort(&g_ns, f->ns_idx);
                    set_flow_state(f, ST_CLOSING);
                    continue;
                }
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
        if (!f->active)
            continue;
        int removable;
        if (f->ns_idx >= 0) {
            TcpConn *c = ns_conn(&g_ns, f->ns_idx);
            /* the netstack rxq is the flow's receive buffer: a flow must
             * not be freed while it still holds undelivered data — the
             * close(fd) would reset the client socket (RST on unread
             * data) and the rxq payload would be lost */
            removable = c && c->state == NS_CLOSED && c->rxq.len == 0 &&
                        f->output.len == 0;
        } else {
            removable = f->state == ST_CLOSING && f->output.len == 0;
        }
        if (removable) {
            flow_free(f);
        }
    }
}
