#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <netdb.h>
#include <sys/socket.h>
#endif

#include "socks_dns.h"
#include "addr.h"
#include "crypto.h"
#include "ipv4.h"
#include "port.h"
#include "protocol.h"
#include "util.h"

static pthread_mutex_t g_dns_mu = PTHREAD_MUTEX_INITIALIZER;
static DnsResult g_dns_q[DNS_RESULT_Q_LEN];
static int g_dns_hd, g_dns_tl; /* ring */

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
    unsigned cur = atomic_load_explicit(&g_dns_gen, memory_order_relaxed);
    pthread_mutex_lock(&g_dns_mu);
    while (g_dns_hd != g_dns_tl && n < max) {
        if (g_dns_q[g_dns_hd].gen == cur)
            out[n++] = g_dns_q[g_dns_hd];
        g_dns_hd = (g_dns_hd + 1) % DNS_RESULT_Q_LEN;
    }
    pthread_mutex_unlock(&g_dns_mu);
    return n;
}

#define DNS_MAX_RESEND  3
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

typedef struct {
    int      flow_id;
    uint16_t port;
    char    *domain;
    unsigned gen;        /* session generation at spawn */
    uint8_t  qtype;      /* 1 = A, 28 = AAAA, 0 = local fallback */
} DnsJob;

static char     g_dns_server_ip[16] = "system resolver";
static uint32_t g_dns_server_ip4;    /* host-order, MSB-first */
static uint16_t g_dns_ip_id;         /* inner IP ID (bumped under the lock) */
static uint64_t g_dns_ignored;       /* responses dropped by validation */

typedef struct {
    bool     in_use;
    uint16_t dns_id;     /* DNS transaction id */
    uint16_t sport;      /* inner UDP source port */
    uint16_t ipid;       /* inner IPv4 ID */
    uint64_t deadline;   /* absolute final timeout (ms) */
    int      resends;    /* retransmissions still allowed */
    char     domain[256];
    int      flow_id;
    uint16_t port;       /* requested remote port */
    uint8_t  qtype;      /* query type this wait entry is for (1 / 28) */
} DnsWait;

static DnsWait g_dns_wait[DNS_WAIT_MAX];
static pthread_mutex_t g_dns_wait_mu = PTHREAD_MUTEX_INITIALIZER;
static atomic_int g_dns_wait_n;

void dns_session_lock(void) { pthread_mutex_lock(&g_dns_wait_mu); }
void dns_session_unlock(void) { pthread_mutex_unlock(&g_dns_wait_mu); }

static bool dns_stale(const DnsJob *j)
{
    return atomic_load(&g_dns_gen) != j->gen;
}

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
    u[6] = 0x00;
    u[7] = 0x00;
    memcpy(u + 8, dnsq, dnslen);
    uc = ip_udp_csum(sip, dip, u, udplen);
    u[6] = (uint8_t)(uc >> 8);
    u[7] = (uint8_t)uc;
    return tot;
}

static size_t dns_wrap_outer(const uint8_t *inner, size_t inlen,
                             uint8_t *out, size_t outsz,
                             const uint8_t outer[8], const uint8_t xkey[8])
{
    if (8 + inlen > outsz)
        return 0;
    memcpy(out, outer, 8);
    memcpy(out + 8, inner, inlen);
    if (outer[0] == PT_DATA_ENC)
        xor_crypt(out + 8, inlen, xkey, 8);
    return 8 + inlen;
}

static int dns_register(uint16_t id, uint16_t sport, const DnsJob *j)
{
    for (int spin = 0; spin < 200; spin++) {  /* up to 2s for a free slot */
        if (dns_stale(j))
            return -1;
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
            dns_push_g(atomic_load(&g_dns_gen), flow_id, true, af, ip,
                       ip6, fport);
        } else {
            pthread_mutex_unlock(&g_dns_wait_mu);
        }
    }
    return true;
}

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

    if (n < 20 + 8 + 12 || pkt[9] != 17 || (pkt[0] >> 4) != 4)
        return false;
    if (atomic_load_explicit(&g_dns_wait_n, memory_order_acquire) == 0)
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
            want_qtype = w->qtype;
            flow_id = w->flow_id;
            fport = w->port;
            memcpy(want_domain, w->domain, sizeof want_domain);
            break;
        }
    }
    pthread_mutex_unlock(&g_dns_wait_mu);
    if (slot < 0)
        return false;

    if (udp[0] != 0 || udp[1] != 53)
        goto bad;
    if (ip4_u32(pkt + 12) != g_dns_server_ip4)
        goto bad;
    if (ip4_u32(pkt + 16) != g_ns.ip)
        goto bad;
    dns = udp + 8;
    dnslen = ulen - 8;
    if (((dns[0] << 8) | dns[1]) != want_id)
        goto bad;
    {
        uint16_t flags = (uint16_t)((dns[2] << 8) | dns[3]);
        if (!(flags & 0x8000) || (flags & 0x000f) != 0)
            goto bad;
    }
    if (dns[4] != 0 || dns[5] < 1)
        goto bad;
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
    return true;
}

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

void dns_stop(void)
{
    pthread_mutex_lock(&g_dns_wait_mu);
    atomic_fetch_add(&g_dns_gen, 1);
    pthread_mutex_unlock(&g_dns_wait_mu);
}

static bool socks_v6_ok_dns(void)
{
    return g_socks_cfg && g_socks_cfg->ipv6;
}

static bool dns_query_local(const char *domain, uint8_t *af_out,
                            uint32_t *ip_out, uint8_t ip6_out[16])
{
    struct addrinfo hints, *res = NULL, *r;
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = socks_v6_ok_dns() ? AF_UNSPEC : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(domain, NULL, &hints, &res);
    if (rc != 0 || !res)
        return false;
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
        memcpy(ip6_out,
               &((const struct sockaddr_in6 *)r->ai_addr)->sin6_addr, 16);
        *af_out = 6;
    } else {
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
    uint32_t lip, srv4;
    uint8_t outer_snap[8], xkey_snap[8];

    if (dns_stale(j))
        goto done;
    pthread_mutex_lock(&g_dns_wait_mu);
    srv4 = g_dns_server_ip4;
    pthread_mutex_unlock(&g_dns_wait_mu);
    if (srv4 == 0 || j->qtype == 0) {
        uint32_t lip4 = 0;
        uint8_t lip6[16] = {0}, af = 4;
        bool resolved = dns_query_local(j->domain, &af, &lip4, lip6);
        if (dns_stale(j))
            goto done;
        if (resolved)
            dns_push_g(j->gen, j->flow_id, true, af, lip4, lip6, j->port);
        else
            dns_push_g(j->gen, j->flow_id, false, 4, 0, NULL, j->port);
        goto done;
    }
    if (g_sockfd < 0)
        goto fail;
    id = (uint16_t)rand_u32();
    qlen = dns_build_query(id, j->domain, j->qtype, q, sizeof q);
    if (qlen == 0)
        goto fail;
    sport = dns_alloc_sport();
    if (sport == 0)
        goto fail;
    slot = dns_register(id, sport, j);
    if (slot < 0)
        goto fail;

    pthread_mutex_lock(&g_dns_wait_mu);
    {
        DnsWait *w = &g_dns_wait[slot];
        if (!w->in_use || w->sport != sport || w->dns_id != id) {
            pthread_mutex_unlock(&g_dns_wait_mu);
            goto done;
        }
        ipid = w->ipid;
        lip = g_ns.ip;
        srv4 = g_dns_server_ip4;
        memcpy(outer_snap, g_ns.outer_hdr, 8);
        memcpy(xkey_snap, g_ns.xor_key, 8);
        if (dns_stale(j)) {
            dns_retire_slot_locked(slot, sport, id);
            pthread_mutex_unlock(&g_dns_wait_mu);
            goto done;
        }
    }
    pthread_mutex_unlock(&g_dns_wait_mu);

    inlen = dns_build_inner(lip, srv4, sport, ipid, q,
                            qlen, inner, sizeof inner);
    if (inlen == 0)
        goto fail;
    outlen = dns_wrap_outer(inner, inlen, out, sizeof out,
                            outer_snap, xkey_snap);
    if (outlen == 0)
        goto fail;

    pthread_mutex_lock(&g_dns_wait_mu);
    if (dns_stale(j)) {
        dns_retire_slot_locked(slot, sport, id);
        pthread_mutex_unlock(&g_dns_wait_mu);
        goto done;
    }

    enum { DNS_SEND_EINTR_MAX = 8 };
    ssize_t sres = -1;
    int serr = 0;
    for (int attempt = 0; attempt < DNS_SEND_EINTR_MAX; attempt++) {
        sres = port_send(g_sockfd, out, outlen, 0);
        if (sres >= 0)
            break;
        serr = errno;
        if (serr != EINTR)
            break;
    }
    if (sres < 0 && serr != EAGAIN && serr != EWOULDBLOCK) {
        pthread_mutex_unlock(&g_dns_wait_mu);
        log_err("tunnel DNS send failed: %s", strerror(serr));
        goto fail;
    }
    pthread_mutex_unlock(&g_dns_wait_mu);
    last_send = now_ms();

    for (;;) {
        int act = 0;
        uint64_t now;
        port_sleep_us(DNS_POLL_MS * 1000);
        now = now_ms();
        pthread_mutex_lock(&g_dns_wait_mu);
        if (dns_stale(j)) {
            dns_retire_slot_locked(slot, sport, id);
            pthread_mutex_unlock(&g_dns_wait_mu);
            break;
        }
        {
            DnsWait *w = &g_dns_wait[slot];
            if (!w->in_use || w->sport != sport || w->dns_id != id)
                act = 3;
            else if (now >= w->deadline) {
                w->in_use = false;
                atomic_fetch_sub_explicit(&g_dns_wait_n, 1, memory_order_release);
                act = 2;
            } else if (now - last_send >= DNS_POLL_MS && w->resends > 0) {
                w->resends--;
                if (port_send(g_sockfd, out, outlen, 0) >= 0)
                    last_send = now;
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
    pthread_mutex_lock(&g_dns_wait_mu);
    if (atomic_load(&g_dns_gen) == j->gen &&
        atomic_load_explicit(&g_dns_evfd, memory_order_acquire) >= 0) {
        int evfd = atomic_load_explicit(&g_dns_evfd, memory_order_acquire);
        if (port_evfd_wake(evfd) != 0 && errno != EAGAIN)
            log_debug("dns evfd wake: %s", strerror(errno));
    }
    pthread_mutex_unlock(&g_dns_wait_mu);
    free(j->domain);
    free(j);
    return NULL;
}

void spawn_dns(int flow_id, const char *domain, uint16_t port) {
    uint8_t qtypes[2] = {28, 1};
    int nq = (g_dns_server_ip4 != 0) ? 2 : 1;
    if (!socks_v6_ok_dns()) {
        qtypes[0] = 1;
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

const char *dns_server_name(void) {
    return g_dns_server_ip;
}
