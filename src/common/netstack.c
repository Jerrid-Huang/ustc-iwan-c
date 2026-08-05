#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "crypto.h"
#include "netstack.h"
#include "protocol.h"
#include "util.h"

#define NS_WINDOW         65535u
#define NS_WSCALE         6u      /* our advertised window shift */
#define NS_RTO_INIT       1000u
#define NS_RTO_MAX        8000u
#define NS_MAX_OUTSTANDING 128
#define NS_MAX_SYN_TRIES  6
#define NS_IDLE_TIMEOUT   120000u
#define NS_CONNECT_TIMEOUT 30000u
#define NS_SEND_CAP       (64u * 1024u)
#define NS_SEG_CAP        1408u

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

/* one TCP segment. The payload lives here from the moment the app data
 * is read (ns_send_reserve) until it is ACKed — it is never copied.
 * hdr = [8B outer VPN header][40B inner IP+TCP header]; the inner TCP
 * header's ack/win/checksum are refreshed on every (re)transmission. */
#define SEG_HDR_LEN 48
typedef struct {
    uint32_t seq;
    uint16_t len;              uint16_t rto;
    uint8_t  cnt;
    uint8_t  fin;
    uint8_t  sent;             uint64_t last_sent_ms;
    uint8_t  hdr[SEG_HDR_LEN];
    _Alignas(16) uint8_t data[NS_SEG_CAP];
} Seg;

typedef struct {
    Seg      segs[NS_MAX_OUTSTANDING];
    Seg      fill;            int      nsegs;
    int      seg_head;       uint8_t  fin_sent;
} NsPriv;

static NsPriv priv[NS_MAX_CONN];
static uint16_t g_ip_id;

static uint16_t rd_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void wr_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t csum_buf(uint32_t sum, const uint8_t *p, size_t n) {
    /* 16-bit big-endian accumulation: gcc auto-vectorizes this loop
     * (benchmarked 57ns/1340B @ -O2, faster than 32/64-bit variants) */
    while (n >= 2) {
        sum += ((uint32_t)p[0] << 8) | p[1];
        p += 2;
        n -= 2;
    }
    if (n)
        sum += (uint32_t)p[0] << 8;
    return sum;
}

static uint16_t csum_fold(uint32_t sum) {
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

/* advertised receive window = remaining rxq space (TCP flow control:
 * the peer must stop sending when we cannot buffer) */
static uint16_t conn_win(const TcpConn *c)
{
    uint32_t free = NS_WINDOW - (uint32_t)c->rxq.len;
    return free > 0xFFFF ? 0xFFFF : (uint16_t)free;
}

/* window field on the wire: actual bytes >> our shift */
static uint16_t conn_win_field(const TcpConn *c)
{
    return (uint16_t)(conn_win(c) >> NS_WSCALE);
}

/* Incremental 16-bit one's-complement checksum update for ack/win
 * changes (the stored field is the COMPLEMENTED sum, so removing a word
 * adds it back and adding a word adds its complement). Validated against
 * full recompute over 200k random segments. */
static void seg_csum_inc(uint8_t *csum_p, uint32_t new_ack, uint32_t old_ack,
                         uint16_t new_win, uint16_t old_win)
{
    uint32_t s = rd_be16(csum_p);
    s += (old_ack >> 16) & 0xffff;
    s += old_ack & 0xffff;
    s += old_win;
    s += (uint32_t)(~((new_ack >> 16) & 0xffff)) & 0xffff;
    s += (uint32_t)(~(new_ack & 0xffff)) & 0xffff;
    s += (uint32_t)(~new_win) & 0xffff;
    while (s >> 16)
        s = (s & 0xffffu) + (s >> 16);
    wr_be16(csum_p, (uint16_t)s);
}

static uint16_t tcp_checksum(uint32_t sip, uint32_t dip,
                             const uint8_t *tcp, size_t n) {
    uint8_t ph[12];
    uint32_t sum;
    wr_be32(ph, sip);
    wr_be32(ph + 4, dip);
    ph[8] = 0;
    ph[9] = 6;
    wr_be16(ph + 10, (uint16_t)n);
    sum = csum_buf(0, ph, sizeof ph);
    sum = csum_buf(sum, tcp, n);
    return csum_fold(sum);
}

static void b_reserve(buf_t *b, size_t extra) {
    size_t ncap;
    uint8_t *nd;
    if (b->len + extra <= b->cap)
        return;
    ncap = b->cap ? b->cap : 256;
    while (ncap < b->len + extra)
        ncap *= 2;
    nd = realloc(b->data, ncap);
    if (!nd)
        return;
    b->data = nd;
    b->cap = ncap;
}

static void b_put(buf_t *b, const void *p, size_t n) {
    if (n == 0)
        return;
    b_reserve(b, n);
    if (b->cap - b->len < n)
        return;
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

static void b_consume(buf_t *b, size_t n) {
    if (n >= b->len) {
        b->len = 0;
        return;
    }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
}

static void b_reset(buf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}







static void conn_clear(TcpConn *c, int idx) {
    NsPriv *p = &priv[idx];
    b_reset(&c->rxq);
    memset(c, 0, sizeof *c);
    memset(p, 0, sizeof *p);
}

static void tx_enqueue(Netstack *ns, const Seg *seg, const uint8_t *pkt,
                       size_t n) {
    int pos;
    TxItem *it;
    if (ns->tx_count >= NS_TX_MAX) {
        ns->tx_head = (ns->tx_head + 1) % NS_TX_MAX;
    } else
        ns->tx_count++;
    pos = (ns->tx_head + ns->tx_count - 1) % NS_TX_MAX;
    it = &ns->tx_queue[pos];
    it->seg = seg;
    it->clen = 0;
    if (!seg) {
        it->clen = (uint16_t)n;
        memcpy(it->ctl, pkt, n);
    }
}

static void emit_tcp(Netstack *ns, TcpConn *c, uint8_t flags, uint32_t seq,
                     uint32_t ack, const uint8_t *data, uint16_t dlen,
                     uint16_t mss_opt) {
    /* control packet: [8B outer VPN header][IP hdr][TCP hdr][opt/data].
     * No payload on control packets, so no XOR needed. */
    uint8_t pkt[64];
    size_t olen = mss_opt ? (4 + 3 + 1) : 0;   /* MSS + WSCALE + NOP pad */
    size_t thlen = 20 + olen;
    size_t iplen = 20 + thlen + dlen;
    uint8_t *ip = pkt + 8;
    uint8_t *t = ip + 20;

    memcpy(pkt, ns->outer_hdr, 8);
    ip[0] = 0x45;
    ip[1] = 0;
    wr_be16(ip + 2, (uint16_t)iplen);
    wr_be16(ip + 4, ++g_ip_id);
    ip[6] = 0x40;
    ip[7] = 0;
    ip[8] = 64;
    ip[9] = 6;
    wr_be16(ip + 10, 0);
    u32_ip4(c->lip, ip + 12);
    u32_ip4(c->rip, ip + 16);

    wr_be16(t, c->lport);
    wr_be16(t + 2, c->rport);
    wr_be32(t + 4, seq);
    wr_be32(t + 8, ack);
    t[12] = (uint8_t)((thlen / 4) << 4);
    t[13] = flags;
    wr_be16(t + 14, conn_win_field(c));
    wr_be16(t + 16, 0);
    wr_be16(t + 18, 0);
    if (olen) {
        t[20] = 2;
        t[21] = 4;
        wr_be16(t + 22, mss_opt);
        t[24] = 3;          /* WSCALE */
        t[25] = 3;
        t[26] = (uint8_t)NS_WSCALE;
        t[27] = 1;          /* NOP pad to 4-byte alignment */
    }
    if (dlen)
        memcpy(t + thlen, data, dlen);

    wr_be16(ip + 10, csum_fold(csum_buf(0, ip, 20)));
    wr_be16(t + 16, tcp_checksum(c->lip, c->rip, t, thlen + dlen));
    if (ns->outer_hdr[1])          /* same framing as data segments:
                                    * outer header says encrypted */
        xor_crypt(ip, iplen, ns->xor_key, 8);

    tx_enqueue(ns, NULL, pkt, 8 + iplen);
}

static bool validate_inner_ipv4(const uint8_t *pkt, size_t len, size_t mtu) {
    return len != 0 && len <= mtu && (pkt[0] >> 4) == 4 && len >= 20;
}

static uint8_t parse_wscale(const uint8_t *opts, size_t olen)
{
    size_t i = 0;
    while (i < olen) {
        uint8_t k = opts[i];
        uint8_t l;
        if (k == 0)
            break;
        if (k == 1) {
            i++;
            continue;
        }
        if (i + 1 >= olen || opts[i + 1] < 2)
            break;
        l = opts[i + 1];
        if (i + l > olen)
            break;
        if (k == 3 && l == 3)
            return opts[i + 2] > 14 ? 14 : opts[i + 2];
        i += l;
    }
    return 0;
}

static uint16_t parse_mss(const uint8_t *opts, size_t olen) {
    size_t i = 0;
    while (i < olen) {
        uint8_t k = opts[i];
        uint8_t l;
        if (k == 0)
            break;
        if (k == 1) {
            i++;
            continue;
        }
        if (i + 1 >= olen || opts[i + 1] < 2)
            break;
        l = opts[i + 1];
        if (i + l > olen)
            break;
        if (k == 2 && l == 4)
            return rd_be16(opts + i + 2);
        i += l;
    }
    return 0;
}

/* segments are appended in seq order and ACKs are cumulative, so only a
 * prefix of the retransmit table can be acked. Dropping advances the ring
 * head (O(1), no per-ACK memmove of the whole table — the kernel uses a
 * list here); compaction happens when the head has walked far enough. */
static void seg_compact(NsPriv *p)
{
    if (p->seg_head == 0)
        return;
    /* move the sealed segments AND the fill slot (ring tail, where app
     * data accumulates) to the front; forgetting the fill slot would
     * leave it behind and reserve() would read a sealed segment as
     * "full", stalling the pipe forever */
    memmove(p->segs, p->segs + p->seg_head,
            (size_t)(p->nsegs + 1) * sizeof *p->segs);
    /* stale slots behind the fill would otherwise be mistaken for fill
     * data and re-sealed forever (duplicate transmission storm) */
    for (int k = p->nsegs + 1; k < NS_MAX_OUTSTANDING; k++)
        p->segs[k].len = 0;
    p->seg_head = 0;
}

static Seg *seg_at(NsPriv *p, int j)
{
    int pos = p->seg_head + j;
    if (pos >= NS_MAX_OUTSTANDING)
        pos -= NS_MAX_OUTSTANDING;
    return &p->segs[pos];
}

static bool drop_acked(TcpConn *c, NsPriv *p) {
    int i = 0;
    while (i < p->nsegs) {
        Seg *s = seg_at(p, i);
        uint32_t end = s->seq + s->len + (s->fin ? 1u : 0u);
        if ((int32_t)(c->snd_una - end) < 0)
            break;
        i++;
    }
    if (i > 0) {
        p->seg_head += i;
        if (p->seg_head >= NS_MAX_OUTSTANDING)
            p->seg_head -= NS_MAX_OUTSTANDING;
        p->nsegs -= i;
        if (p->seg_head >= (NS_MAX_OUTSTANDING >> 1))
            seg_compact(p);
    }
    return true;
}

static void handle_rx(Netstack *ns, TcpConn *c, int idx, const uint8_t *t,
                      size_t thlen, uint8_t flags, uint32_t seq, uint32_t ack,
                      const uint8_t *payload, size_t paylen, uint64_t now) {
    NsPriv *p = &priv[idx];
    uint16_t win = rd_be16(t + 14);

    if (c->state == NS_SYN_SENT) {
        uint16_t om;
        if (flags & TCP_RST) {
            conn_clear(c, idx);
            return;
        }
        if ((flags & (TCP_SYN | TCP_ACK)) != (TCP_SYN | TCP_ACK))
            return;
        if (ack != c->snd_nxt)
            return;
        om = parse_mss(t + 20, thlen - 20);
        if (om > 0 && om < c->mss)
            c->mss = om;
        c->peer_scale = parse_wscale(t + 20, thlen - 20);
        c->rcv_nxt = seq + 1;
        c->snd_una = ack;
        c->remote_win = (uint32_t)win << c->peer_scale;
        c->state = NS_ESTABLISHED;
        c->state_ms = now;
        c->last_rx_ms = now;
        c->retx_cnt = 0;
        c->retx_len = 0;
        if (paylen > 0) {
            b_put(&c->rxq, payload, paylen);
            c->rcv_nxt += (uint32_t)paylen;
        }
        emit_tcp(ns, c, TCP_ACK, c->snd_nxt, c->rcv_nxt, NULL, 0, 0);
        return;
    }

    if (flags & TCP_RST) {
        conn_clear(c, idx);
        return;
    }
    if (!(flags & TCP_ACK))
        return;
    c->last_rx_ms = now;
    c->remote_win = (uint32_t)win << c->peer_scale;
    if (paylen == 0 && ack == c->snd_una && !(flags & (TCP_SYN | TCP_FIN)) &&
        c->state != NS_SYN_SENT && c->snd_una != 0) {
        /* fast retransmit: 3 duplicate ACKs -> resend the oldest
         * unacked segment now instead of waiting for its RTO */
        if (++c->dup_acks >= 3 && p->nsegs > 0) {
            Seg *s0 = seg_at(p, 0);
            if (s0->sent) {
                uint8_t *ip = s0->hdr + 8;
                uint8_t *t = ip + 20;
                uint32_t old_ack = rd_be32(t + 8);
                uint16_t old_win = rd_be16(t + 14);
                uint16_t win = conn_win_field(c);
                if (ns->outer_hdr[1])
                    xor_crypt(ip, 40, ns->xor_key, 8);
                wr_be32(t + 8, c->rcv_nxt);
                wr_be16(t + 14, win);
                seg_csum_inc(t + 16, c->rcv_nxt, old_ack, win, old_win);
                if (ns->outer_hdr[1])
                    xor_crypt(ip, 40, ns->xor_key, 8);
                tx_enqueue(ns, s0, NULL, 0);
                s0->last_sent_ms = now;
                s0->rto = c->rto;
                s0->cnt++;
                c->dup_acks = 0;
            }
        }
    } else if ((int32_t)(ack - c->snd_una) > 0) {
        c->dup_acks = 0;
        /* RTT sample: the oldest segment this ACK covers (snd_una moves
         * to the ack'ed frontier; scan for the first covered segment) */
        for (int j = 0; j < p->nsegs; j++) {
            Seg *s2 = seg_at(p, j);
            uint32_t end = s2->seq + s2->len + (s2->fin ? 1u : 0u);
            if ((int32_t)(ack - end) < 0)
                break;
            if (s2->sent && s2->last_sent_ms > 0 &&
                (int32_t)(ack - c->snd_una) >= 0) {
                uint32_t rtt = (uint32_t)(now - s2->last_sent_ms);
                if (rtt < 10000) {
                    uint32_t sr = c->srtt ? c->srtt : rtt;
                    uint32_t var = c->rttvar ? c->rttvar : sr / 2;
                    c->srtt = (uint16_t)((sr * 7 + rtt) / 8);
                    var = (var * 3 +
                           (sr > rtt ? sr - rtt : rtt - sr)) / 4;
                    c->rttvar = (uint16_t)var;
                    uint32_t rto = c->srtt + 4u * var;
                    c->rto = (uint16_t)(rto < 200 ? 200
                                        : (rto > NS_RTO_MAX ? NS_RTO_MAX
                                                            : rto));
                }
                break;             /* oldest covered segment only */
            }
        }
        c->snd_una = ack;
    }
    drop_acked(c, p);
    if (p->fin_sent && (int32_t)(ack - c->snd_nxt) >= 0 &&
        (c->state == NS_FIN_WAIT ||
         (c->state == NS_CLOSE_WAIT && c->local_fin))) {
        c->state = NS_CLOSED;
        return;
    }
    if (seq == c->rcv_nxt) {
        if (paylen > 0 && c->state != NS_CLOSE_WAIT) {
            b_put(&c->rxq, payload, paylen);
            c->rcv_nxt += (uint32_t)paylen;
        }
        if (flags & TCP_FIN) {
            if (c->state != NS_CLOSE_WAIT) {
                if (c->state == NS_ESTABLISHED)
                    c->state = NS_CLOSE_WAIT;
                c->remote_fin = true;
                c->rcv_nxt += 1;
                emit_tcp(ns, c, TCP_ACK, c->snd_nxt, c->rcv_nxt, NULL, 0, 0);
            }
        } else if (paylen > 0) {
            if (!c->ack_pending)
                c->ack_ms = now;
            c->ack_pending = 1;
            if (++c->rx_segs >= 2) {     /* RFC 1122: ACK every 2nd seg */
                c->rx_segs = 0;
                emit_tcp(ns, c, TCP_ACK, c->snd_nxt, c->rcv_nxt, NULL, 0, 0);
                c->ack_pending = 0;
            }
        }
    } else {
        emit_tcp(ns, c, TCP_ACK, c->snd_nxt, c->rcv_nxt, NULL, 0, 0);
    }
}

void ns_init(Netstack *ns, uint32_t inner_ip, uint32_t gw, uint16_t mtu,
             uint32_t seed) {
    memset(ns, 0, sizeof *ns);
    ns->ip = inner_ip;
    ns->gw = gw;
    ns->mtu = mtu;
    ns->isn_base = seed;
}

int ns_connect(Netstack *ns, uint16_t lport, uint32_t rip, uint16_t rport) {
    int idx = -1;
    TcpConn *c;
    uint64_t now = now_ms();
    int mss;
    uint32_t isn;

    for (int i = 0; i < NS_MAX_CONN; i++) {
        if (ns->conns[i].state == NS_CLOSED) {
            idx = i;
            break;
        }
    }
    if (idx < 0)
        return -1;

    c = &ns->conns[idx];
    conn_clear(c, idx);
    isn = ns->isn_base + (uint32_t)idx * 1000u + (rand_u32() % 1000u);
    c->state = NS_SYN_SENT;
    c->lip = ns->ip;
    c->rip = rip;
    c->lport = lport;
    c->rport = rport;
    c->snd_isn = isn;
    c->snd_una = isn;
    c->snd_nxt = isn;
    c->sent_nxt = isn;
    c->rcv_nxt = 0;
    c->remote_fin = false;
    c->local_fin = false;
    c->retx_seq = isn;
    c->retx_len = 0;
    c->retx_ms = now;
    c->retx_cnt = 1;
    c->state_ms = now;
    c->last_rx_ms = now;
    c->remote_win = NS_WINDOW;
    c->rto = (uint16_t)NS_RTO_INIT;
    mss = (int)ns->mtu - 40;
    c->mss = (uint16_t)(mss < 536 ? 536 : (mss > 1460 ? 1460 : mss));

    emit_tcp(ns, c, TCP_SYN, isn, 0, NULL, 0, c->mss);
    c->snd_nxt = isn + 1u;
    c->sent_nxt = isn + 1u;       return idx;
}

TcpConn *ns_conn(Netstack *ns, int idx) {
    if (idx < 0 || idx >= NS_MAX_CONN)
        return NULL;
    return &ns->conns[idx];
}

NsState ns_state(const TcpConn *c) {
    return c->state;
}

void ns_set_outer(Netstack *ns, const uint8_t hdr[8], const uint8_t key[8])
{
    memcpy(ns->outer_hdr, hdr, 8);
    memcpy(ns->xor_key, key, 8);
}

/* the fill slot is the ring's append position; sealing it = headers +
 * in-place XOR + nsegs++ (payload never moves) */
static void seg_seal(Netstack *ns, TcpConn *c, NsPriv *p, uint8_t extra)
{
    Seg *s = &p->segs[p->seg_head + p->nsegs];
    uint8_t *ip;
    uint8_t *t;
    size_t iplen;
    if (s->len == 0 && !(extra & TCP_FIN))
        return;   /* empty seal only valid for the FIN segment */
    s->seq = c->snd_nxt;
    s->fin = (extra & TCP_FIN) ? 1 : 0;
    s->sent = 0;
    ip = s->hdr + 8;
    t = ip + 20;
    iplen = 40 + s->len;
    memcpy(s->hdr, ns->outer_hdr, 8);              ip[0] = 0x45;
    ip[1] = 0;
    wr_be16(ip + 2, (uint16_t)iplen);
    wr_be16(ip + 4, ++g_ip_id);
    ip[6] = 0x40;
    ip[7] = 0;
    ip[8] = 64;
    ip[9] = 6;
    wr_be16(ip + 10, 0);
    u32_ip4(c->lip, ip + 12);
    u32_ip4(c->rip, ip + 16);
    wr_be16(t, c->lport);
    wr_be16(t + 2, c->rport);
    wr_be32(t + 4, s->seq);
    wr_be32(t + 8, c->rcv_nxt);
    t[12] = 0x50;
    t[13] = (uint8_t)(TCP_ACK | extra);
    wr_be16(t + 14, conn_win(c));                  wr_be16(t + 16, 0);
    wr_be16(t + 18, 0);
    wr_be16(ip + 10, csum_fold(csum_buf(0, ip, 20)));
    if (ns->outer_hdr[1])   /* encrypt the whole inner packet once;
                             * same framing as the old per-packet path */
        xor_crypt(ip, iplen, ns->xor_key, 8);
    c->snd_nxt += s->len;
    p->nsegs++;
    if (extra & TCP_FIN) {
        p->fin_sent = 1;
        c->snd_nxt += 1;
    }
}

uint8_t *ns_send_reserve(Netstack *ns, int idx, size_t *room)
{
    TcpConn *c;
    NsPriv *p;
    Seg *s;
    *room = 0;
    if (idx < 0 || idx >= NS_MAX_CONN)
        return NULL;
    c = &ns->conns[idx];
    if (c->state == NS_CLOSED || c->state == NS_FIN_WAIT)
        return NULL;
    p = &priv[idx];
    if (p->nsegs >= NS_MAX_OUTSTANDING)
        return NULL;
    if (p->seg_head > 0 &&
        p->seg_head + p->nsegs >= NS_MAX_OUTSTANDING)
        seg_compact(p);
    s = &p->segs[p->seg_head + p->nsegs];
    if (s->len >= c->mss)
        return NULL;                       /* full slot not yet sealed */
    *room = c->mss - s->len;
    return s->data + s->len;
}

int ns_send_reservev(Netstack *ns, int idx, struct iovec *iov, int maxn)
{
    TcpConn *c;
    NsPriv *p;
    int pos, n = 0;

    if (idx < 0 || idx >= NS_MAX_CONN)
        return 0;
    c = &ns->conns[idx];
    if (c->state == NS_CLOSED || c->state == NS_FIN_WAIT)
        return 0;
    p = &priv[idx];
    if (p->nsegs >= NS_MAX_OUTSTANDING)
        return 0;
    if (p->seg_head > 0 &&
        p->seg_head + p->nsegs >= NS_MAX_OUTSTANDING)
        seg_compact(p);
    pos = p->seg_head + p->nsegs;
    while (n < maxn && pos < NS_MAX_OUTSTANDING) {
        Seg *s = &p->segs[pos];
        if (s->len >= c->mss)
            break;                       /* full slot not yet sealed */
        iov[n].iov_base = s->data + s->len;
        iov[n].iov_len = c->mss - s->len;
        pos++;
        n++;
    }
    return n;
}

void ns_send_commit(Netstack *ns, int idx, size_t n)
{
    TcpConn *c = &ns->conns[idx];
    NsPriv *p = &priv[idx];
    Seg *s = &p->segs[p->seg_head + p->nsegs];
    s->len += (uint16_t)n;
    if (s->len >= c->mss)
        seg_seal(ns, c, p, 0);             }

size_t ns_recv(Netstack *ns, int idx, uint8_t *out, size_t n) {
    buf_t *b;
    if (idx < 0 || idx >= NS_MAX_CONN)
        return 0;
    b = &ns->conns[idx].rxq;
    if (b->len == 0 || n == 0)
        return 0;
    if (n > b->len)
        n = b->len;
    memcpy(out, b->data, n);
    b_consume(b, n);
    return n;
}

void ns_close(Netstack *ns, int idx) {
    TcpConn *c;
    if (idx < 0 || idx >= NS_MAX_CONN)
        return;
    c = &ns->conns[idx];
    if (c->state == NS_CLOSED)
        return;
    c->local_fin = true;
    if (c->state == NS_ESTABLISHED)
        c->state = NS_FIN_WAIT;
}

void ns_abort(Netstack *ns, int idx) {
    TcpConn *c;
    if (idx < 0 || idx >= NS_MAX_CONN)
        return;
    c = &ns->conns[idx];
    if (c->state == NS_CLOSED) {
        conn_clear(c, idx);
        return;
    }
    if (c->state != NS_SYN_SENT)
        emit_tcp(ns, c, TCP_RST | TCP_ACK, c->snd_nxt, c->rcv_nxt, NULL, 0, 0);
    conn_clear(c, idx);
}

/* validate the IPv4 header (version, protocol, lengths, checksum, options)
 * and the TCP header length; fill the parse state, false = drop */
static bool rx_validate_ipv4(Netstack *ns, const uint8_t *pkt, size_t n,
                             size_t *ihl, size_t *eff, size_t *thlen,
                             const uint8_t **t) {
    uint16_t total;
    if (!validate_inner_ipv4(pkt, n, ns->mtu))
        return false;
    if (pkt[9] != 6)
        return false;
    *ihl = (size_t)(pkt[0] & 0x0f) * 4;
    if (*ihl < 20)
        return false;
    total = rd_be16(pkt + 2);
    if (total < 20 || total > n)
        return false;
    if ((pkt[6] & 0x20) || (((pkt[6] & 0x1f) << 8) | pkt[7]) != 0)
        return false;
    if (csum_fold(csum_buf(0, pkt, *ihl)) != 0) {
        log_debug("NS DROP: ip csum");
        return false;
    }
    *eff = total;
    if (*eff < *ihl + 20)
        return false;
    *t = pkt + *ihl;
    *thlen = (size_t)((*t)[12] >> 4) * 4;
    if (*thlen < 20 || *ihl + *thlen > *eff)
        return false;
    return true;
}

/* extract the TCP 4-tuple, flags, seq/ack and payload; also check dest IP
 * and TCP checksum (false = drop) */
static bool rx_parse_tcp(Netstack *ns, const uint8_t *pkt, const uint8_t *t,
                         size_t eff, size_t ihl, size_t thlen,
                         uint16_t *sport, uint16_t *dport, uint32_t *sip,
                         uint32_t *dip, uint8_t *flags, uint32_t *seq,
                         uint32_t *ack, const uint8_t **payload,
                         size_t *paylen) {
    *sport = rd_be16(t);
    *dport = rd_be16(t + 2);
    *sip = ip4_u32(pkt + 12);
    *dip = ip4_u32(pkt + 16);
    if (*dip != ns->ip) {
        log_debug("NS DROP: dip %u.%u.%u.%u != ns ip %u.%u.%u.%u",
                  (*dip >> 24) & 0xff, (*dip >> 16) & 0xff, (*dip >> 8) & 0xff,
                  *dip & 0xff, (ns->ip >> 24) & 0xff, (ns->ip >> 16) & 0xff,
                  (ns->ip >> 8) & 0xff, ns->ip & 0xff);
        return false;
    }
    if (t[16] != 0 && tcp_checksum(*sip, *dip, t, eff - ihl) != 0) {
        log_debug("NS DROP: tcp csum");
        return false;
    }
    *flags = t[13];
    *seq = rd_be32(t + 4);
    *ack = rd_be32(t + 8);
    *payload = t + thlen;
    *paylen = eff - ihl - thlen;
    return true;
}

/* find the conn matching the packet's 4-tuple; -1 when none. A one-entry
 * cache of the last matched conn covers the single-connection case (the
 * kernel's equivalent is the sk hash table) */
static int g_last_conn = -1;
static int rx_lookup_conn(const Netstack *ns, uint16_t dport, uint32_t sip,
                          uint16_t sport) {
    const TcpConn *c;
    if (g_last_conn >= 0) {
        c = &ns->conns[g_last_conn];
        if (c->state != NS_CLOSED && c->lport == dport && c->rip == sip &&
            c->rport == sport)
            return g_last_conn;
    }
    for (int i = 0; i < NS_MAX_CONN; i++) {
        c = &ns->conns[i];
        if (c->state != NS_CLOSED && c->lport == dport && c->rip == sip &&
            c->rport == sport) {
            g_last_conn = i;
            return i;
        }
    }
    g_last_conn = -1;
    return -1;
}

static void rx_reject_unknown(Netstack *ns, uint32_t dip, uint32_t sip,
                              uint16_t dport, uint16_t sport, uint8_t flags,
                              uint32_t seq, uint32_t paylen) {
    TcpConn tmp;
    uint32_t consumed;
    if (flags & TCP_RST)
        return;
    consumed = seq + ((flags & TCP_SYN) ? 1u : 0u) +
               ((flags & TCP_FIN) ? 1u : 0u) + (uint32_t)paylen;
    memset(&tmp, 0, sizeof tmp);
    tmp.lip = dip;
    tmp.rip = sip;
    tmp.lport = dport;
    tmp.rport = sport;
    emit_tcp(ns, &tmp, TCP_RST | TCP_ACK, 0, consumed, NULL, 0, 0);
}

void ns_rx_packet(Netstack *ns, const uint8_t *pkt, size_t n) {
    size_t ihl, eff, thlen, paylen;
    const uint8_t *t, *payload;
    uint16_t sport, dport;
    uint32_t sip, dip, seq, ack;
    uint8_t flags;
    int idx;
    uint64_t now;

    if (!rx_validate_ipv4(ns, pkt, n, &ihl, &eff, &thlen, &t))
        return;
    if (!rx_parse_tcp(ns, pkt, t, eff, ihl, thlen, &sport, &dport, &sip,
                      &dip, &flags, &seq, &ack, &payload, &paylen))
        return;
    idx = rx_lookup_conn(ns, dport, sip, sport);
    if (debug_enabled())
        log_debug("NS RX: sip=%u.%u.%u.%u:%u dip=%u.%u.%u.%u:%u flags=%02x seq=%08x ack=%08x conn=%d",
                  (sip >> 24) & 0xff, (sip >> 16) & 0xff, (sip >> 8) & 0xff,
                  sip & 0xff, sport, (dip >> 24) & 0xff, (dip >> 16) & 0xff,
                  (dip >> 8) & 0xff, dip & 0xff, dport, flags, seq, ack, idx);
    now = now_ms();
    if (idx < 0) {
        rx_reject_unknown(ns, dip, sip, dport, sport, flags, seq, paylen);
        return;
    }
    handle_rx(ns, &ns->conns[idx], idx, t, thlen, flags, seq, ack, payload,
              paylen, now);
}

/* retransmit the SYN on its 1s timer; return ms until this conn needs a tick
 * again, or -1 when it was aborted (tries exhausted) */
static int64_t conn_syn_retransmit(Netstack *ns, TcpConn *c, int idx,
                                   uint64_t now) {
    uint64_t deadline = c->retx_ms + 1000;
    int64_t conn_d = (int64_t)(c->state_ms + NS_CONNECT_TIMEOUT - now);

    if (now < deadline)
        return conn_d < (int64_t)(deadline - now) ? conn_d
                                                  : (int64_t)(deadline - now);
    c->retx_cnt++;
    if (c->retx_cnt > NS_MAX_SYN_TRIES) {
        ns_abort(ns, idx);
        return -1;
    }
    emit_tcp(ns, c, TCP_SYN, c->retx_seq, 0, NULL, 0, c->mss);
    c->retx_ms = now;
    return conn_d;
}

/* retransmit overdue queued segments; return true when the conn was aborted
 * (a segment exceeded its retransmit budget) */
static bool conn_retransmit_loop(Netstack *ns, TcpConn *c, NsPriv *p, int idx,
                                 uint64_t now) {
    for (int j = 0; j < p->nsegs; j++) {
        Seg *s = seg_at(p, j);
        if (!s->sent)
            continue;
        if (now < s->last_sent_ms + s->rto)
            continue;
        if ((int64_t)(c->snd_nxt - c->snd_una) > (int64_t)c->remote_win)
            continue;
                {
            uint8_t *ip = s->hdr + 8;
            uint8_t *t = ip + 20;
            uint32_t old_ack = rd_be32(t + 8);
            uint16_t old_win = rd_be16(t + 14);
            uint16_t win = conn_win_field(c);
            if (ns->outer_hdr[1])
                xor_crypt(ip, 40, ns->xor_key, 8);
            wr_be32(t + 8, c->rcv_nxt);
            wr_be16(t + 14, win);
            seg_csum_inc(t + 16, c->rcv_nxt, old_ack, win, old_win);
            if (ns->outer_hdr[1])
                xor_crypt(ip, 40, ns->xor_key, 8);
        }
        tx_enqueue(ns, s, NULL, 0);
        s->last_sent_ms = now;
        s->rto = (uint8_t)((int)s->rto * 2 > NS_RTO_MAX
                               ? NS_RTO_MAX
                               : (int)s->rto * 2);
        s->cnt++;
        if (s->cnt > 8) {
            ns_abort(ns, idx);
            return true;
        }
    }
    return false;
}

/* build and send fresh segments (pending data, then FIN) up to the
 * outstanding/window limits */
static void conn_send_new(Netstack *ns, TcpConn *c, NsPriv *p, uint64_t now) {
    /* in-flight = TRANSMITTED-but-unacked bytes (seal reserves seq space
     * in snd_nxt; counting sealed-but-unsent would fake a full window) */
    uint32_t in_flight = c->sent_nxt - c->snd_una;
    Seg *s;

        if (p->nsegs < NS_MAX_OUTSTANDING && in_flight < c->remote_win) {
        s = &p->segs[p->seg_head + p->nsegs];
        if (s->len > 0) {
            uint8_t x = (c->local_fin && !p->fin_sent) ? TCP_FIN : 0;
            seg_seal(ns, c, p, x);
        }
    }
    for (int j = 0; j < p->nsegs; j++) {
        s = seg_at(p, j);
        if (s->sent)
            continue;
        if (in_flight >= c->remote_win)
            break;
        /* refresh dynamic TCP fields (ack/win) + checksum; the slot is
         * encrypted, so decrypt the header, patch, re-encrypt */
        {
            uint8_t *ip = s->hdr + 8;
            uint8_t *t = ip + 20;
            uint32_t old_ack = rd_be32(t + 8);
            uint16_t old_win = rd_be16(t + 14);
            uint16_t win = conn_win_field(c);
            if (ns->outer_hdr[1])
                xor_crypt(ip, 40, ns->xor_key, 8);
            wr_be32(t + 8, c->rcv_nxt);
            wr_be16(t + 14, win);
            seg_csum_inc(t + 16, c->rcv_nxt, old_ack, win, old_win);
            if (ns->outer_hdr[1])
                xor_crypt(ip, 40, ns->xor_key, 8);
        }
        tx_enqueue(ns, s, NULL, 0);
        s->sent = 1;
        s->last_sent_ms = now;
        s->rto = c->rto;
        s->cnt = 1;
        c->sent_nxt = s->seq + s->len + (s->fin ? 1u : 0u);
        in_flight = c->sent_nxt - c->snd_una;
    }
        if (c->local_fin && !p->fin_sent && p->nsegs < NS_MAX_OUTSTANDING &&
        in_flight < c->remote_win) {
        emit_tcp(ns, c, TCP_ACK | TCP_FIN, c->snd_nxt, c->rcv_nxt, NULL, 0, 0);
        p->fin_sent = 1;
        c->snd_nxt += 1;
    }
}

static int64_t conn_next_deadline(const NsPriv *p, uint64_t now) {
    int64_t d = INT64_MAX;
    for (int j = 0; j < p->nsegs; j++) {
        const Seg *s = &p->segs[(p->seg_head + j) % NS_MAX_OUTSTANDING];
        int64_t dd = (int64_t)(s->last_sent_ms + s->rto - now);
        if (dd < d)
            d = dd;
    }
    return d;
}

int ns_tick(Netstack *ns, uint64_t now) {
    int64_t next = 100;
    for (int i = 0; i < NS_MAX_CONN; i++) {
        TcpConn *c = &ns->conns[i];
        NsPriv *p;
        int64_t d;

        if (c->state == NS_CLOSED)
            continue;
        if (now > c->last_rx_ms + NS_IDLE_TIMEOUT) {
            ns_abort(ns, i);
            continue;
        }
        if (c->state == NS_SYN_SENT && now > c->state_ms + NS_CONNECT_TIMEOUT) {
            ns_abort(ns, i);
            continue;
        }
        p = &priv[i];

        if (c->state == NS_SYN_SENT) {
            d = conn_syn_retransmit(ns, c, i, now);
            if (d < 0)
                continue;
        } else {
            if (c->local_fin && p->fin_sent &&
                (c->state == NS_FIN_WAIT || c->state == NS_CLOSE_WAIT) &&
                (int32_t)(c->snd_una - c->snd_nxt) >= 0) {
                c->state = NS_CLOSED;
                continue;
            }
            drop_acked(c, p);
            if (conn_retransmit_loop(ns, c, p, i, now))
                continue;
            conn_send_new(ns, c, p, now);
            /* delayed ACK: flush pending at 40ms so the peer's window
             * advances even under low/irregular traffic */
            if (c->ack_pending && now - c->ack_ms >= 40) {
                c->ack_pending = 0;
                c->rx_segs = 0;
                emit_tcp(ns, c, TCP_ACK, c->snd_nxt, c->rcv_nxt, NULL, 0, 0);
            }
            d = conn_next_deadline(p, now);
        }
        d = (int64_t)(c->last_rx_ms + NS_IDLE_TIMEOUT - now);
        if (d < next)
            next = d;
    }
    if (next < 0)
        next = 0;
    if (next > 10000)
        next = 10000;
    return (int)next;
}

const TxItem *ns_tx_peek(Netstack *ns)
{
    if (ns->tx_count == 0)
        return NULL;
    return &ns->tx_queue[ns->tx_head];
}

size_t ns_tx_item_len(const TxItem *it)
{
    return it->seg ? SEG_HDR_LEN + ((const Seg *)it->seg)->len : it->clen;
}

const uint8_t *ns_tx_item_buf(const TxItem *it)
{
    return it->seg ? ((const Seg *)it->seg)->hdr : it->ctl;
}

const TxItem *ns_tx_pop(Netstack *ns)
{
    const TxItem *it;
    if (ns->tx_count == 0)
        return NULL;
    it = &ns->tx_queue[ns->tx_head];
    ns->tx_head = (ns->tx_head + 1) % NS_TX_MAX;
    ns->tx_count--;
    return it;
}

static size_t skip_name(const uint8_t *p, size_t n, size_t off) {
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

uint32_t dns_query_a(const char *domain) {
    size_t len = strlen(domain);
    size_t i, qn = 0;
    size_t llen = 0, lstart = 0;
    uint16_t id;
    uint8_t q[512];
    int fd;
    struct timeval tv;
    struct sockaddr_in sa;
    socklen_t sl;
    ssize_t r;
    uint8_t resp[4096];
    uint16_t flags, qd, an;
    size_t off;

    while (len > 0 && domain[len - 1] == '.')
        len--;
    if (len == 0 || len > 253)
        return 0;
    for (i = 0; i < len; i++) {
        if (domain[i] == '.') {
            if (llen == 0 || llen > 63)
                return 0;
            llen = 0;
        } else {
            llen++;
        }
    }
    if (llen == 0 || llen > 63)
        return 0;

    id = (uint16_t)rand_u32();
    q[qn++] = (uint8_t)(id >> 8);
    q[qn++] = (uint8_t)id;
    q[qn++] = 0x01;
    q[qn++] = 0x00;
    q[qn++] = 0x00;
    q[qn++] = 0x01;
    q[qn++] = 0x00;
    q[qn++] = 0x00;
    q[qn++] = 0x00;
    q[qn++] = 0x00;
    q[qn++] = 0x00;
    q[qn++] = 0x00;
    llen = 0;
    lstart = 0;
    for (i = 0; i <= len; i++) {
        if (i == len || domain[i] == '.') {
            if (i < len || i > 0) {
                q[qn++] = (uint8_t)llen;
                memcpy(q + qn, domain + lstart, llen);
                qn += llen;
            }
            lstart = i + 1;
            llen = 0;
        } else {
            llen++;
        }
    }
    q[qn++] = 0x00;
    q[qn++] = 0x00;
    q[qn++] = 0x01;
    q[qn++] = 0x00;
    q[qn++] = 0x01;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    memset(&tv, 0, sizeof tv);
    tv.tv_sec = 3;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    inet_pton(AF_INET, DNS_SERVER_IP, &sa.sin_addr);
    if (sendto(fd, q, qn, 0, (struct sockaddr *)&sa, sizeof sa) < 0) {
        close(fd);
        return 0;
    }
    sl = sizeof sa;
    r = recvfrom(fd, resp, sizeof resp, 0, (struct sockaddr *)&sa, &sl);
    close(fd);
    if (r < 12)
        return 0;
    if (sa.sin_addr.s_addr != inet_addr(DNS_SERVER_IP))
        return 0;
    if (rd_be16(resp) != id)
        return 0;
    flags = rd_be16(resp + 2);
    if (!(flags & 0x8000) || (flags & 0x000f) != 0)
        return 0;
    qd = rd_be16(resp + 4);
    an = rd_be16(resp + 6);
    off = 12;
    for (i = 0; i < qd; i++) {
        off = skip_name(resp, (size_t)r, off);
        if (off == (size_t)-1)
            return 0;
        off += 4;
        if (off > (size_t)r)
            return 0;
    }
    for (i = 0; i < an; i++) {
        uint16_t typ, cls, rdlen;
        off = skip_name(resp, (size_t)r, off);
        if (off == (size_t)-1)
            return 0;
        if (off + 10 > (size_t)r)
            return 0;
        typ = rd_be16(resp + off);
        cls = rd_be16(resp + off + 2);
        rdlen = rd_be16(resp + off + 8);
        off += 10;
        if (off + rdlen > (size_t)r)
            return 0;
        if (typ == 1 && cls == 1 && rdlen == 4)
            return ip4_u32(resp + off);
        off += rdlen;
    }
    return 0;
}
