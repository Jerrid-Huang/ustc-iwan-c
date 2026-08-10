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
#include "ipv4.h"
#include "netstack.h"
#include "protocol.h"
#include "util.h"

#define NS_WINDOW         262144u  /* advertised rx window: 256KB (was
                                    * 64KB). The downlink bottleneck per
                                    * conn was window/RTT (64KB at ~1.2ms
                                    * RTT capped socks-down at ~400
                                    * Mbit/s/conn); 256KB with WSCALE=7
                                    * keeps the 16-bit wire field exact
                                    * (262144>>7 = 2048). The kernel
                                    * negotiates shift = min(ours, its
                                    * own, typically 7), so the >>7
                                    * encoding matches. */
#define NS_WSCALE         7u       /* our advertised window shift */
#define NS_RTO_INIT       250u    /* first-segment recovery: the 1000ms
                                   * RFC default makes a single dropped
                                   * segment cost a full second on the
                                   * tunnel; a premature retransmit only
                                   * duplicates (peer dedups) */
#define NS_RTO_MIN        200u
#define NS_RTO_MAX        8000u
#define NS_MAX_SYN_TRIES  6
#define NS_MAX_DATA_RETX  8       /* abort a conn after 8 retransmits of
                                   * one data segment */
#define NS_IDLE_TIMEOUT   120000u
#define NS_KEEPALIVE_MS   30000u
#define NS_KEEPALIVE_MAX  3
#define NS_CONNECT_TIMEOUT 30000u
#define NS_MSS_MIN        536u    /* RFC 879 floor for accepted MSS */
#define NS_IP_TCP_HDR     40      /* inner IPv4+TCP header (data segs) */
#define NS_TTL            64
#define NS_DF             0x40
#define NS_IPHDR_V_IHL    0x45
#define NS_RXQ_INIT       256     /* initial rxq buffer capacity */
#define NS_COMPACT_THRESH (NS_MAX_OUTSTANDING >> 1)
#define NS_SYN_RETX_MS    1000u   /* SYN retransmit interval */
#define NS_DUP_ACK_THRESH 3       /* dup ACKs before fast retransmit */
#define NS_RTT_MAX_MS     10000u  /* RTT sample clamp (bogus samples) */
#define NS_FLOWDBG_THROTTLE_MS 500u /* min gap between NSSEND dumps */
#define NS_TICK_DEFAULT_MS 100    /* ns_tick: poll interval when idle */
#define NS_TICK_MAX_MS    10000   /* ns_tick: cap on the next-tick value */

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

/* offset of the inner TCP flags byte in an inline control packet:
 * [8B outer VPN header][20B inner IP header][TCP flags at byte 13] */
#define TX_CTL_FLAGS_OFF 41

/* Seg and NsPriv are defined in netstack.h (the per-conn segment rings
 * live in the Netstack struct since the instance-state migration). */

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

/* advertised receive window = remaining rxq space (TCP flow control:
 * the peer must stop sending when we cannot buffer) */
static uint32_t conn_win(const TcpConn *c)
{
    /* never underflow: once the rxq passes NS_WINDOW the peer must be
     * told 0 (and receive-side accounting must drop, see handle_rx),
     * not a wrapped full window. NS_WINDOW is 256KB, so the return
     * needs 32 bits (the wire field, >> NS_WSCALE, still fits 16). */
    if (c->rxq.len >= NS_WINDOW)
        return 0;
    return NS_WINDOW - (uint32_t)c->rxq.len;
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

static void b_reserve(buf_t *b, size_t extra) {
    size_t ncap;
    uint8_t *nd;
    if (b->len + extra <= b->cap)
        return;
    ncap = b->cap ? b->cap : NS_RXQ_INIT;
    while (ncap < b->len + extra)
        ncap *= 2;
    nd = realloc(b->data, ncap);
    if (!nd)
        oom_abort();   /* same policy as buffer.c buf_ensure: an rxq that
                        * cannot grow would silently lose ACKed data */
    b->data = nd;
    b->cap = ncap;
}

static void b_put(buf_t *b, const void *p, size_t n) {
    if (n == 0)
        return;
    b_reserve(b, n);
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

static void b_reset(buf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}







static void conn_clear(Netstack *ns, int idx) {
    TcpConn *c = &ns->conns[idx];
    NsPriv *p = &ns->priv[idx];
    b_reset(&c->rxq);
    memset(c, 0, sizeof *c);
    memset(p, 0, sizeof *p);
}

/* Enqueue one TX item. Returns 1 when queued, 0 when the device queue is
 * full of un-droppable control packets. Callers that ignore the value:
 * a dropped segment-slot reference is recovered by the RTO retransmit
 * loop and a dropped ACK is re-generated by the next event. The send
 * paths (conn_send_new / conn_retransmit_loop) treat 0 as "not
 * transmitted": they leave the segment unsent (sent=0, no backoff) and
 * retry on the next tick. When full, the oldest pure-ACK control item
 * (seg==NULL, flags byte at ctl[8+20+13]) is overwritten instead of
 * evicting the head: ACKs are idempotent and re-issued constantly, so
 * losing one is harmless, while a FIN/RST/SYN is emitted exactly once
 * and evicting it would lose it forever (data segments live in the
 * retransmit table, so their slot references are never touched here). */
static int tx_enqueue(Netstack *ns, uint8_t conn, const Seg *seg,
                      const uint8_t *pkt, size_t n) {
    int pos = -1;
    TxItem *it;

    if (seg) {
        /* DATA item: per-conn fair-share gate. Each conn may occupy at
         * most NS_TX_CONN_CAP queue slots (kernel sch_fq per-flow
         * queues); beyond that the segment stays in its retransmit ring
         * and retries next tick — backpressure on THAT conn only, so a
         * fast conn can never starve the others of queue space
         * (measured: 8-conn upload, conn0 1494MB vs conns 4-7 ~10MB
         * before this gate). */
        if (ns->q_used[conn] >= NS_TX_CONN_CAP)
            return 0;
        if (ns->tx_count >= NS_TX_MAX)
            return 0;   /* all conns are at their share: fail, retry next
                         * tick (the caps sum to NS_TX_MAX) */
    } else if (ns->tx_count >= NS_TX_MAX) {
        /* Queue full, new packet is CONTROL (ACK/RST/SYN — never
         * droppable). Priority policy, oldest-first:
         * 1. a queued pure-ACK control item is droppable — the newest
         *    ACK supersedes the oldest;
         * 2. else evict one queued data item from the FATTEST conn —
         *    exactly the kernel's fq_codel_drop() rule ("Queue is full!
         *    Find the fat flow and drop packet(s) from it", linear
         *    max-backlog scan, sch_fq_codel.c). The evicted segment
         *    lives on in its ring with sent=0 and re-enqueues next
         *    tick. Without this the ACK stream starves behind a data
         *    burst and the peer's window never reopens (deadlock). */
        for (int i = 0; i < NS_TX_MAX; i++) {
            int p2 = (ns->tx_head + i) % NS_TX_MAX;
            it = &ns->tx_queue[p2];
            if (!it->seg &&
                !(it->ctl[TX_CTL_FLAGS_OFF] & (TCP_FIN | TCP_RST | TCP_SYN))) {
                pos = p2;          /* oldest pure-ACK control: droppable */
                break;
            }
        }
        if (pos < 0) {
            /* no pure-ACK to drop: evict from the fattest conn. The
             * linear scan over 64 conns is the same amortized shape as
             * fq_codel_drop's flow scan (one cache line per drop). */
            uint8_t fat = 0;
            unsigned maxused = 0;
            for (int i = 0; i < NS_MAX_CONN; i++)
                if (ns->q_used[i] > maxused) {
                    maxused = ns->q_used[i];
                    fat = (uint8_t)i;
                }
            if (maxused > 0) {
                for (int i = 0; i < NS_TX_MAX; i++) {
                    int p2 = (ns->tx_head + i) % NS_TX_MAX;
                    it = &ns->tx_queue[p2];
                    if (it->seg && it->conn == fat) {
                        /* the TxItem stores const void* but the ring is
                         * ours: resetting sent makes conn_send_new
                         * re-queue the segment on the next tick */
                        ((Seg *)it->seg)->sent = 0;
                        ns->q_used[fat]--;
                        pos = p2;
                        break;
                    }
                }
            }
        }
        if (pos < 0)
            return 0;              /* nothing droppable: drop the new pkt */
    }
    if (pos < 0) {
        /* empty slot at the tail (data path or a queue that was not
         * full) */
        ns->tx_count++;
        pos = (ns->tx_head + ns->tx_count - 1) % NS_TX_MAX;
    }
    it = &ns->tx_queue[pos];
    it->seg = seg;
    it->clen = 0;
    it->conn = conn;
    if (!seg) {
        it->clen = (uint16_t)n;
        memcpy(it->ctl, pkt, n);
    } else {
        ns->q_used[conn]++;
    }
    return 1;
}

/* build the inner IPv4 header of an outgoing packet (version/IHL, total
 * length, fresh IP ID, DF, TTL 64, proto 6) and checksum it in place;
 * `ip` points at the inner header start (just past the 8-byte outer VPN
 * header). Shared by the control path (emit_tcp) and the zero-copy data
 * path (seg_seal), which used to hand-write this header twice. */
static void build_ip_hdr(Netstack *ns, TcpConn *c, uint8_t *ip, size_t iplen)
{
    ip[0] = NS_IPHDR_V_IHL;
    ip[1] = 0;
    wr_be16(ip + 2, (uint16_t)iplen);
    wr_be16(ip + 4, ++ns->ip_id);
    ip[6] = NS_DF;
    ip[7] = 0;
    ip[8] = NS_TTL;
    ip[9] = 6;
    wr_be16(ip + 10, 0);
    u32_ip4(c->lip, ip + 12);
    u32_ip4(c->rip, ip + 16);
    wr_be16(ip + 10, ip_csum_fold(ip_csum_accum(0, ip, 20)));
}

/* Emit a control packet ([8B outer VPN header][IP hdr][TCP hdr][opt]).
 * No app payload ever travels on this path (data segments use the
 * zero-copy slot ring), but the packet IS XOR-encrypted whenever the
 * outer header marks the session encrypted — same framing as data
 * segments (see seg_seal). Returns 1 when enqueued, 0 when the device
 * queue dropped it (a dropped SYN is retried by conn_syn_retransmit;
 * dropped ACK/RST are re-generated by the next event). */
static int emit_tcp(Netstack *ns, TcpConn *c, uint8_t flags, uint32_t seq,
                    uint32_t ack, uint16_t mss_opt) {
    uint8_t pkt[64];
    size_t olen = mss_opt ? (4 + 3 + 1) : 0;   /* MSS + WSCALE + NOP pad */
    size_t thlen = 20 + olen;
    size_t iplen = 20 + thlen;
    uint8_t *ip = pkt + 8;
    uint8_t *t = ip + 20;

    memcpy(pkt, ns->outer_hdr, 8);
    build_ip_hdr(ns, c, ip, iplen);

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

    wr_be16(t + 16, ip_tcp_csum(c->lip, c->rip, t, thlen));
    if (ns->outer_hdr[1])          /* same framing as data segments:
                                    * outer header says encrypted */
        xor_crypt(ip, iplen, ns->xor_key, 8);

    return tx_enqueue(ns, NS_TX_CONN_CTL, NULL, pkt, 8 + iplen);
}

static bool validate_inner_ipv4(const uint8_t *pkt, size_t len, size_t mtu) {
    return len != 0 && len <= mtu && (pkt[0] >> 4) == 4 && len >= 20;
}

/* walk the TCP option list; return the offset of the first option with
 * kind `kind` and length `klen`, or -1 when absent or malformed. One
 * boundary-checking implementation for all option kinds. */
static long parse_tcp_opt(const uint8_t *opts, size_t olen, uint8_t kind,
                          uint8_t klen)
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
        if (k == kind && l == klen)
            return (long)i;
        i += l;
    }
    return -1;
}

static uint8_t parse_wscale(const uint8_t *opts, size_t olen) {
    long off = parse_tcp_opt(opts, olen, 3, 3);
    uint8_t v = off < 0 ? 0 : opts[off + 2];
    return v > 14 ? 14 : v;
}

static uint16_t parse_mss(const uint8_t *opts, size_t olen) {
    long off = parse_tcp_opt(opts, olen, 2, 4);
    return off < 0 ? 0 : rd_be16(opts + off + 2);
}

/* segments are appended in seq order and ACKs are cumulative, so only a
 * prefix of the retransmit table can be acked. Dropping advances the ring
 * head (O(1), no per-ACK memmove of the whole table — the kernel uses a
 * list here); compaction happens when the head has walked far enough.
 *
 * This memmove is also the structural reason every async/zero-copy send
 * (io_uring SENDMSG_ZC, SO_ZEROCOPY, splice) is rejected for this code:
 * an in-flight send referencing a slot goes stale the moment the table
 * moves, and retransmit re-seals slots in place while completions may
 * still be outstanding. Sends must stay synchronous with the drain. */
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
     * data and re-sealed forever (duplicate transmission storm); the
     * +1 bound also clears the tail slot segs[NS_MAX_OUTSTANDING] */
    for (int k = p->nsegs + 1; k < NS_MAX_OUTSTANDING + 1; k++)
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

/* read-only ring access (diagnostics/deadline walks) */
static const Seg *seg_at_c(const NsPriv *p, int j)
{
    int pos = p->seg_head + j;
    if (pos >= NS_MAX_OUTSTANDING)
        pos -= NS_MAX_OUTSTANDING;
    return &p->segs[pos];
}

/* the ring's append slot: the ring tail where new payload accumulates
 * (index seg_head + nsegs, in-bounds because segs[] is sized +1) */
static Seg *seg_fill_slot(NsPriv *p)
{
    return &p->segs[p->seg_head + p->nsegs];
}

/* when the ring tail would walk past the array end, shift the ring back
 * to the front (see seg_compact for why the fill slot must move too) */
static void seg_maybe_compact(NsPriv *p)
{
    if (p->seg_head > 0 && p->seg_head + p->nsegs >= NS_MAX_OUTSTANDING)
        seg_compact(p);
}

/* sequence number just past this segment (its FIN byte included) */
static uint32_t seg_end(const Seg *s)
{
    return s->seq + s->len + (s->fin ? 1u : 0u);
}

static void drop_acked(TcpConn *c, NsPriv *p) {
    int i = 0;
    while (i < p->nsegs) {
        Seg *s = seg_at(p, i);
        if (!s->sent)
            break;   /* ack for never-sent data must not free queued data */
        if ((int32_t)(c->snd_una - seg_end(s)) < 0)
            break;
        i++;
    }
    if (i > 0) {
        p->seg_head += i;
        if (p->seg_head >= NS_MAX_OUTSTANDING)
            p->seg_head -= NS_MAX_OUTSTANDING;
        p->nsegs -= i;
        if (p->seg_head >= NS_COMPACT_THRESH)
            seg_compact(p);
    }
}


/* refresh the dynamic TCP header fields (ack/win + incremental checksum)
 * of a sealed segment before (re)transmission; the slot is encrypted, so
 * the 40-byte inner header is decrypted, patched and re-encrypted */
static void seg_refresh_hdr(Netstack *ns, TcpConn *c, Seg *s)
{
    uint8_t *ip = s->hdr + 8;
    uint8_t *t = ip + 20;
    uint16_t win = conn_win_field(c);
    if (ns->outer_hdr[1])
        xor_crypt(ip, NS_IP_TCP_HDR, ns->xor_key, 8);
    {
        uint32_t old_ack = rd_be32(t + 8);
        uint16_t old_win = rd_be16(t + 14);
        wr_be32(t + 8, c->rcv_nxt);
        wr_be16(t + 14, win);
        seg_csum_inc(t + 16, c->rcv_nxt, old_ack, win, old_win);
    }
    if (ns->outer_hdr[1])
        xor_crypt(ip, NS_IP_TCP_HDR, ns->xor_key, 8);
}

/* close when our FIN is ACKed and the peer's FIN is seen; `acked` is the
 * ACK of the segment being processed (handle_rx) or snd_una (ns_tick) —
 * they are equal at the respective decision points. local_fin is always
 * set in FIN_WAIT (ns_close) and remote_fin always set in CLOSE_WAIT
 * (handle_rx), so one predicate covers both sides of the close. */
static bool conn_fin_done(const TcpConn *c, const NsPriv *p, uint32_t acked)
{
    return p->fin_sent && c->local_fin && c->remote_fin &&
           (c->state == NS_FIN_WAIT || c->state == NS_CLOSE_WAIT) &&
           (int32_t)(acked - c->snd_nxt) >= 0;
}

/* SYN-SENT: accept the peer's SYN+ACK (RFC 793 rules), enter the
 * established state and deliver any piggybacked payload */
static void handle_rx_syn_sent(Netstack *ns, TcpConn *c, int idx,
                               const uint8_t *t, size_t thlen, uint8_t flags,
                               uint32_t seq, uint32_t ack,
                               const uint8_t *payload, size_t paylen,
                               uint64_t now)
{
    uint16_t om;
    if (flags & TCP_RST) {
        /* RFC 793: in SYN-SENT an RST is acceptable only when its
         * ACK echoes our SYN (ack == snd_nxt == ISS+1); a forged
         * RST carrying the flow's 4-tuple must not abort the
         * handshake */
        if (ack != c->snd_nxt)
            return;
        conn_clear(ns, idx);
        return;
    }
    if ((flags & (TCP_SYN | TCP_ACK)) != (TCP_SYN | TCP_ACK))
        return;
    if (ack != c->snd_nxt)
        return;
    om = parse_mss(t + 20, thlen - 20);
    /* RFC 879 floor: an attacker-forged SYN+ACK must not collapse
     * segmentation below the minimum viable MSS (DoS via mss=1) */
    if (om >= NS_MSS_MIN && om < c->mss)
        c->mss = om;
    c->peer_scale = parse_wscale(t + 20, thlen - 20);
    c->rcv_nxt = seq + 1;
    c->snd_una = ack;
    c->remote_win = (uint32_t)rd_be16(t + 14) << c->peer_scale;
    c->state = NS_ESTABLISHED;
    c->state_ms = now;
    c->last_rx_ms = now;
    c->syn_retx_cnt = 0;
    if (paylen > 0) {
        if (c->rxq.len + paylen <= NS_WINDOW)
            b_put(&c->rxq, payload, paylen);
        else
            return;   /* window closed: drop, peer retransmits */
        c->rcv_nxt += (uint32_t)paylen;
    }
    emit_tcp(ns, c, TCP_ACK, c->snd_nxt, c->rcv_nxt, 0);
}

/* fold one RTT sample into the smoothed estimates (RTO = srtt +
 * 4*rttvar); samples at or above NS_RTT_MAX_MS are discarded as bogus */
static void conn_rtt_sample(TcpConn *c, const Seg *s2, uint64_t now)
{
    uint32_t rtt = (uint32_t)(now - s2->last_sent_ms);
    uint32_t sr, var, rto;
    if (rtt >= NS_RTT_MAX_MS)
        return;
    sr = c->srtt ? c->srtt : rtt;
    var = c->rttvar ? c->rttvar : sr / 2;
    c->srtt = (uint16_t)((sr * 7 + rtt) / 8);
    var = (var * 3 + (sr > rtt ? sr - rtt : rtt - sr)) / 4;
    c->rttvar = (uint16_t)var;
    rto = c->srtt + 4u * var;
    c->rto = (uint16_t)(rto < NS_RTO_MIN ? NS_RTO_MIN
                        : (rto > NS_RTO_MAX ? NS_RTO_MAX : rto));
}

/* process the ACK of an established connection: fast retransmit on
 * NS_DUP_ACK_THRESH duplicate ACKs, otherwise advance snd_una with RTT
 * sampling; returns the effective ACK (clamped to the last transmitted
 * byte) */
static uint32_t handle_rx_ack(Netstack *ns, TcpConn *c, NsPriv *p, int idx,
                              uint8_t flags, uint32_t ack, size_t paylen,
                              uint64_t now)
{
    if (paylen == 0 && ack == c->snd_una &&
        !(flags & (TCP_SYN | TCP_FIN)) && c->snd_una != 0) {
        /* fast retransmit: NS_DUP_ACK_THRESH duplicate ACKs -> resend
         * the oldest unacked segment now instead of waiting for its RTO */
        if (++c->dup_acks >= NS_DUP_ACK_THRESH && p->nsegs > 0) {
            Seg *s0 = seg_at(p, 0);
            if (s0->sent) {
                seg_refresh_hdr(ns, c, s0);
                tx_enqueue(ns, (uint8_t)idx, s0, NULL, 0);
                s0->last_sent_ms = now;
                s0->rto = c->rto;
                /* fast retransmit does NOT count toward the
                 * NS_MAX_DATA_RETX abort budget: only RTO-driven
                 * retransmits (conn_retransmit_loop) increment cnt, so
                 * a burst of dup ACKs cannot abort a healthy conn */
                c->dup_acks = 0;
            }
        }
        return ack;
    }
    if ((int32_t)(ack - c->snd_una) > 0) {
        /* a forged ACK beyond the last transmitted byte would make
         * drop_acked discard never-sent segments and freeze TX
         * (in_flight = sent_nxt - snd_una underflow); RFC 793 requires
         * ack <= SND.NXT, so clamp instead of advancing past it */
        if ((int32_t)(ack - c->sent_nxt) > 0)
            ack = c->sent_nxt;
        c->dup_acks = 0;
        /* RTT sample: the oldest segment this ACK covers (snd_una moves
         * to the ack'ed frontier; scan for the first covered segment) */
        for (int j = 0; j < p->nsegs; j++) {
            Seg *s2 = seg_at(p, j);
            if ((int32_t)(ack - seg_end(s2)) < 0)
                break;
            if (s2->sent && s2->last_sent_ms > 0 &&
                (int32_t)(ack - c->snd_una) >= 0) {
                conn_rtt_sample(c, s2, now);
                break;             /* oldest covered segment only */
            }
        }
        c->snd_una = ack;
    }
    return ack;
}

/* deliver in-order payload to the rxq, handle FIN, and ACK every data
 * segment immediately; out-of-order segments get an immediate ACK */
static void handle_rx_data(Netstack *ns, TcpConn *c, int idx, uint8_t flags,
                           uint32_t seq, const uint8_t *payload,
                           size_t paylen)
{
    if (seq == c->rcv_nxt) {
        if (paylen > 0 && c->state != NS_CLOSE_WAIT) {
            if (c->rxq.len + paylen <= NS_WINDOW) {
                b_put(&c->rxq, payload, paylen);
                c->rcv_nxt += (uint32_t)paylen;
                if (dbg_env("IWAN_RXDBG"))
                    fprintf(stderr, "RXDBG: conn=%d data->rxq pay=%zu "
                            "rxq=%zu state=%d\n", idx, paylen, c->rxq.len,
                            c->state);
            }
            /* else: receive window closed — drop without advancing
             * rcv_nxt; the peer retransmits once the window reopens */
        }
        if (flags & TCP_FIN) {
            if (c->state != NS_CLOSE_WAIT) {
                if (c->state == NS_ESTABLISHED)
                    c->state = NS_CLOSE_WAIT;
                c->remote_fin = true;
                c->rcv_nxt += 1;
                emit_tcp(ns, c, TCP_ACK, c->snd_nxt, c->rcv_nxt, 0);
            }
        } else if (paylen > 0) {
            /* ACK EVERY segment immediately: RFC 1122's every-2nd
             * delayed ACK is a bulk-transfer bandwidth optimization, but
             * on a ~2ms-RTT tunnel it is pure latency — after an RTO the
             * peer's cwnd is 1, so every single-segment burst would wait
             * the full delayed-ACK window per segment, crawling instead
             * of recovering. The extra ACK packets are negligible on the
             * tunnel. */
            emit_tcp(ns, c, TCP_ACK, c->snd_nxt, c->rcv_nxt, 0);
        }
    } else {
        emit_tcp(ns, c, TCP_ACK, c->snd_nxt, c->rcv_nxt, 0);
    }
}

static void handle_rx(Netstack *ns, TcpConn *c, int idx, const uint8_t *t,
                      size_t thlen, uint8_t flags, uint32_t seq, uint32_t ack,
                      const uint8_t *payload, size_t paylen, uint64_t now) {
    NsPriv *p = &ns->priv[idx];

    if (c->state == NS_SYN_SENT) {
        handle_rx_syn_sent(ns, c, idx, t, thlen, flags, seq, ack,
                           payload, paylen, now);
        return;
    }
    if (flags & TCP_RST) {
        /* RFC 5961: only accept an RST whose seq is inside the receive
         * window; a forged RST with the flow's 4-tuple must not kill it */
        if ((int32_t)(seq - c->rcv_nxt) < 0 ||
            (int32_t)(seq - c->rcv_nxt) > (int32_t)NS_WINDOW)
            return;
        conn_clear(ns, idx);
        return;
    }
    if (!(flags & TCP_ACK))
        return;
    /* diagnostic (IWAN_RXDBG=1): log every data/FIN segment with the
     * connection state — used to find why a segment is dropped */
    if ((paylen > 0 || (flags & TCP_FIN)) && dbg_env("IWAN_RXDBG"))
        fprintf(stderr,
                "RXDBG: conn=%d state=%d seq=%u rcv=%u ack=%u "
                "snd_una=%u flags=%02x pay=%zu\n",
                idx, c->state, seq, c->rcv_nxt, ack, c->snd_una, flags,
                paylen);
    c->last_rx_ms = now;
    c->keepalive_cnt = 0;
    c->keepalive_ms = 0;
    c->remote_win = (uint32_t)rd_be16(t + 14) << c->peer_scale;
    ack = handle_rx_ack(ns, c, p, idx, flags, ack, paylen, now);
    drop_acked(c, p);
    /* FIN_WAIT must NOT close on the FIN-ACK alone: the peer's data and
     * FIN may still be in flight (half-close, e.g. an app that shuts
     * down its write side while waiting for a reply). Closing here would
     * free the conn and let the reply be RST'd away. Stay in FIN_WAIT
     * until the peer's FIN is seen (remote_fin). */
    if (conn_fin_done(c, p, ack)) {
        /* close completed: free the rxq now — b_reset is idempotent, so
         * a later conn_clear on slot reuse frees NULL and can never
         * double-free the buffer */
        b_reset(&c->rxq);
        c->state = NS_CLOSED;
        return;
    }
    handle_rx_data(ns, c, idx, flags, seq, payload, paylen);
}

void ns_init(Netstack *ns, uint32_t inner_ip, uint32_t gw, uint16_t mtu) {
    memset(ns, 0, sizeof *ns);
    ns->ip = inner_ip;
    ns->gw = gw;
    ns->mtu = mtu;
    ns->last_conn = -1;   /* rx lookup cache starts empty (memset gave 0) */
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
    conn_clear(ns, idx);
    /* full 32-bit random ISN per connection: the old 10-bit jitter on a
     * fixed base let an observer predict sequence numbers and forge RST */
    isn = rand_u32();
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
    c->syn_retx_seq = isn;
    c->syn_retx_ms = now;
    c->syn_retx_cnt = 1;
    c->state_ms = now;
    c->last_rx_ms = now;
    c->remote_win = NS_WINDOW;
    c->rto = (uint16_t)NS_RTO_INIT;
    mss = (int)ns->mtu - (int)NS_IP_TCP_HDR;
    c->mss = (uint16_t)(mss < (int)NS_MSS_MIN ? (int)NS_MSS_MIN
                        : (mss > (int)NS_SEG_CAP ? (int)NS_SEG_CAP : mss));

    emit_tcp(ns, c, TCP_SYN, isn, 0, c->mss);
    c->snd_nxt = isn + 1u;
    c->sent_nxt = isn + 1u;
    return idx;
}

TcpConn *ns_conn(Netstack *ns, int idx) {
    if (idx < 0 || idx >= NS_MAX_CONN)
        return NULL;
    return &ns->conns[idx];
}

NsState ns_state(const TcpConn *c) {
    return c->state;
}

/* diagnostic (IWAN_FLOWDBG=1): dump one conn's full send state, used to
 * identify backpressure deadlocks (zero remote window, ring full of
 * sealed-but-unsent segments, tx-queue overflow). Cheap when disabled. */
void ns_dump_conn(const Netstack *ns, int idx)
{
    if (!dbg_env("IWAN_FLOWDBG") || idx < 0 || idx >= NS_MAX_CONN)
        return;
    const TcpConn *c = &ns->conns[idx];
    const NsPriv *p = &ns->priv[idx];
    fprintf(stderr,
            "NSDUMP: conn=%d state=%d una=%u nxt=%u sent=%u rwin=%u "
            "scale=%u inflight=%u nsegs=%u txq=%d rxq=%zu rf=%d lf=%d "
            "fs=%d rto=%u srtt=%u\n",
            idx, c->state, c->snd_una, c->snd_nxt, c->sent_nxt,
            c->remote_win, c->peer_scale,
            (unsigned)(c->sent_nxt - c->snd_una), p->nsegs, ns->tx_count,
            c->rxq.len, c->remote_fin, c->local_fin, p->fin_sent,
            c->rto, c->srtt);
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
    Seg *s = seg_fill_slot(p);
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
    iplen = NS_IP_TCP_HDR + s->len;
    memcpy(s->hdr, ns->outer_hdr, 8);
    build_ip_hdr(ns, c, ip, iplen);
    wr_be16(t, c->lport);
    wr_be16(t + 2, c->rport);
    wr_be32(t + 4, s->seq);
    wr_be32(t + 8, c->rcv_nxt);
    t[12] = (uint8_t)((20 / 4) << 4);   /* data segments carry no TCP
                                         * options (thlen 20 == 0x50),
                                         * same form as emit_tcp */
    t[13] = (uint8_t)(TCP_ACK | extra);
    wr_be16(t + 14, conn_win_field(c));   /* scaled, like every other
                                           * transmit path — the raw
                                           * window would overstate by
                                           * up to 128x with WSCALE=7 */
    wr_be16(t + 16, 0);      /* stale slot reuse would leak into csum */
    wr_be16(t + 18, 0);      /* and so would stale urg */
    wr_be16(t + 16, ip_tcp_csum(c->lip, c->rip, t, 20 + s->len));
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
    p = &ns->priv[idx];
    if (p->nsegs >= NS_MAX_OUTSTANDING)
        return NULL;
    seg_maybe_compact(p);
    s = seg_fill_slot(p);
    if (s->len >= c->mss)
        return NULL;                       /* full slot not yet sealed */
    *room = c->mss - s->len;
    return s->data + s->len;
}

int ns_send_reservev(Netstack *ns, int idx, struct iovec *iov, int maxn)
{
    TcpConn *c;
    NsPriv *p;
    int n = 0;

    if (idx < 0 || idx >= NS_MAX_CONN)
        return 0;
    c = &ns->conns[idx];
    if (c->state == NS_CLOSED || c->state == NS_FIN_WAIT)
        return 0;
    p = &ns->priv[idx];
    if (p->nsegs >= NS_MAX_OUTSTANDING)
        return 0;
    seg_maybe_compact(p);
    {
        /* walk consecutive slots from the fill position forward (linear,
         * no wrap — the tail slot segs[NS_MAX_OUTSTANDING] is excluded,
         * matching the old pos < NS_MAX_OUTSTANDING bound) */
        Seg *s = seg_fill_slot(p);
        while (n < maxn && s < p->segs + NS_MAX_OUTSTANDING) {
            if (s->len >= c->mss)
                break;                   /* full slot not yet sealed */
            iov[n].iov_base = s->data + s->len;
            iov[n].iov_len = c->mss - s->len;
            s++;
            n++;
        }
    }
    return n;
}

int ns_send_commit(Netstack *ns, int idx, size_t n)
{
    TcpConn *c;
    NsPriv *p;
    Seg *s;
    size_t room;

    /* same bounds/state guards as every sibling entry point: a stale idx
     * after ns_abort/slot reuse must not land on an unrelated conn */
    if (idx < 0 || idx >= NS_MAX_CONN)
        return 0;
    c = &ns->conns[idx];
    if (c->state == NS_CLOSED || c->state == NS_FIN_WAIT)
        return 0;
    p = &ns->priv[idx];
    if (p->nsegs >= NS_MAX_OUTSTANDING)
        return 0;
    s = seg_fill_slot(p);
    room = c->mss - s->len;
    if (n > room)            /* commit must never exceed the reserved room */
        n = room;
    s->len += (uint16_t)n;
    if (s->len >= c->mss)
        seg_seal(ns, c, p, 0);
    return (int)n;
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
        conn_clear(ns, idx);
        return;
    }
    if (c->state != NS_SYN_SENT)
        emit_tcp(ns, c, TCP_RST | TCP_ACK, c->snd_nxt, c->rcv_nxt, 0);
    conn_clear(ns, idx);
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
    /* a header longer than the whole datagram is bogus; reject it before
     * spending a checksum pass over the (claimed) header bytes */
    if (total < *ihl + 20)
        return false;
    /* policy: fragments are silently dropped — the VPN MTU (1400) with
     * MSS clamped below it keeps the peer's TCP from ever fragmenting,
     * reassembly would need a per-conn fragment cache, and a lost piece
     * is recovered by the peer's retransmit of the whole segment */
    if ((pkt[6] & 0x20) || (((pkt[6] & 0x1f) << 8) | pkt[7]) != 0)
        return false;
    if (ip_csum_fold(ip_csum_accum(0, pkt, *ihl)) != 0) {
        log_debug("NS DROP: ip csum");
        return false;
    }
    *eff = total;
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
    /* a zero checksum field is illegal for IPv4 TCP (no offload here) and
     * must not bypass verification — an attacker setting csum=0 would
     * otherwise skip the only integrity gate on forged segments */
    if (ip_tcp_csum(*sip, *dip, t, eff - ihl) != 0) {
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
static int rx_lookup_conn(Netstack *ns, uint16_t dport, uint32_t sip,
                          uint16_t sport) {
    const TcpConn *c;
    if (ns->last_conn >= 0) {
        c = &ns->conns[ns->last_conn];
        if (c->state != NS_CLOSED && c->lport == dport && c->rip == sip &&
            c->rport == sport)
            return ns->last_conn;
    }
    for (int i = 0; i < NS_MAX_CONN; i++) {
        c = &ns->conns[i];
        if (c->state != NS_CLOSED && c->lport == dport && c->rip == sip &&
            c->rport == sport) {
            ns->last_conn = i;
            return i;
        }
    }
    ns->last_conn = -1;
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
    emit_tcp(ns, &tmp, TCP_RST | TCP_ACK, 0, consumed, 0);
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

/* retransmit the SYN on its NS_SYN_RETX_MS timer; return ms until this
 * conn needs a tick again, or -1 when it was aborted (tries exhausted) */
static int64_t conn_syn_retransmit(Netstack *ns, TcpConn *c, int idx,
                                   uint64_t now) {
    uint64_t deadline = c->syn_retx_ms + NS_SYN_RETX_MS;
    int64_t conn_d = (int64_t)(c->state_ms + NS_CONNECT_TIMEOUT - now);

    if (now < deadline)
        return conn_d < (int64_t)(deadline - now) ? conn_d
                                                  : (int64_t)(deadline - now);
    c->syn_retx_cnt++;
    if (c->syn_retx_cnt > NS_MAX_SYN_TRIES) {
        ns_abort(ns, idx);
        return -1;
    }
    /* only re-arm the retransmit timer when the SYN actually made it
     * into the device queue: on a full queue syn_retx_ms stays in the
     * past so the next tick retries immediately (the count above still
     * bounds a permanently stuck queue) */
    if (!emit_tcp(ns, c, TCP_SYN, c->syn_retx_seq, 0, c->mss))
        return conn_d;
    c->syn_retx_ms = now;
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
        /* no window check here on purpose: the guard that used
         * snd_nxt - snd_una > remote_win counted SEALED-but-unsent
         * bytes, so once the ring filled (128 segs) it blocked every
         * retransmission forever — a single dropped segment (UDP rcvbuf
         * overflow, GSO partial delivery) then froze the connection
         * permanently even though in-flight was well within the window.
         * Retransmissions are never window-limited in TCP: the data was
         * already sent within the window when first transmitted. */
        seg_refresh_hdr(ns, c, s);
        /* queue full: defer the retransmit without advancing the
         * backoff or retransmit count — nothing was transmitted this
         * tick, so counting it would double the RTO for a segment the
         * peer never even saw repeated */
        if (!tx_enqueue(ns, (uint8_t)idx, s, NULL, 0))
            continue;
        s->last_sent_ms = now;
        s->rto = (uint16_t)((int)s->rto * 2 > (int)NS_RTO_MAX
                               ? (int)NS_RTO_MAX
                               : (int)s->rto * 2);
        s->cnt++;
        /* diagnostic (IWAN_RETX=1, independent of IWAN_DEBUG which slows
         * the data path): first retransmit of each segment (cnt starts
         * at 1 on the initial send, so the first retransmit is cnt==2) */
        if (s->cnt == 2 && dbg_env("IWAN_RETX"))
            fprintf(stderr, "NS RETX: conn=%d seq=%u len=%u rto=%u "
                    "win=%u inflight=%u\n", idx, s->seq, s->len, s->rto,
                    c->remote_win,
                    (unsigned)(c->sent_nxt - c->snd_una));
        if (s->cnt > NS_MAX_DATA_RETX) {
            ns_abort(ns, idx);
            return true;
        }
    }
    return false;
}

/* diagnostic (IWAN_FLOWDBG=1): nothing sent while data is queued —
 * either the window is closed (in_flight >= remote_win) or every slot
 * is marked sent with in-flight 0 (state corruption). Throttled to
 * NS_FLOWDBG_THROTTLE_MS so a stuck upload prints the reason without
 * flooding. */
static void conn_send_diag(const TcpConn *c, const NsPriv *p, int idx,
                           uint64_t now, bool sent_any, uint32_t in_flight)
{
    static uint64_t last_print[NS_MAX_CONN];
    if (!sent_any && p->nsegs > 0 && dbg_env("IWAN_FLOWDBG") &&
        now - last_print[idx] >= NS_FLOWDBG_THROTTLE_MS) {
        last_print[idx] = now;
        const Seg *s0 = seg_at_c(p, 0);
        fprintf(stderr,
                "NSSEND: conn=%d nsegs=%u sent0=%d inflight=%u "
                "rwin=%u scale=%u una=%u nxt=%u sent=%u srtt=%u "
                "rto=%u\n",
                idx, p->nsegs, s0->sent, in_flight, c->remote_win,
                c->peer_scale, c->snd_una, c->snd_nxt, c->sent_nxt,
                c->srtt, c->rto);
    }
}

/* independent FIN: enter it into the retransmit table as a zero-length
 * segment (seg_seal) instead of a fire-and-forget control packet, so a
 * lost FIN is retransmitted on RTO and a zero advertised window cannot
 * strand it. fin_sent is set at seal time — safe because the segment is
 * retried until ACKed or the conn aborts. If the fill slot still holds
 * data the FIN must not overtake it in seq space; that data seals
 * (carrying the FIN) once the window reopens. */
static void conn_send_fin(Netstack *ns, TcpConn *c, NsPriv *p)
{
    if (!c->local_fin || p->fin_sent || p->nsegs >= NS_MAX_OUTSTANDING)
        return;
    /* ACKs may have advanced seg_head without triggering compaction,
     * making the ring tail alias the out-of-ring fill slot; compact so
     * the FIN lands in a slot seg_at can actually reach */
    seg_maybe_compact(p);
    Seg *fs = seg_fill_slot(p);
    if (fs->len == 0)
        seg_seal(ns, c, p, TCP_FIN);
}

/* build and send fresh segments (pending data, then FIN) up to the
 * outstanding/window limits; a pending FIN goes out even at zero window */
static void conn_send_new(Netstack *ns, TcpConn *c, NsPriv *p, int idx,
                          uint64_t now) {
    /* in-flight = TRANSMITTED-but-unacked bytes (seal reserves seq space
     * in snd_nxt; counting sealed-but-unsent would fake a full window) */
    uint32_t in_flight = c->sent_nxt - c->snd_una;
    Seg *s;
    bool sent_any = false;

    if (p->nsegs < NS_MAX_OUTSTANDING && in_flight < c->remote_win &&
        in_flight < NS_SND_INFLIGHT_MAX) {
        s = seg_fill_slot(p);
        if (s->len > 0) {
            uint8_t x = (c->local_fin && !p->fin_sent) ? TCP_FIN : 0;
            seg_seal(ns, c, p, x);
        }
    }
    for (int j = 0; j < p->nsegs; j++) {
        s = seg_at(p, j);
        if (s->sent)
            continue;
        if (in_flight >= c->remote_win && !s->fin)
            continue;   /* zero window: hold data, but a FIN still goes
                         * out — RFC 9293 permits the FIN even when the
                         * advertised window is exhausted (it consumes
                         * one byte of sequence space beyond the window);
                         * scanning on lets a trailing FIN past queued
                         * data that must wait for the window */
        if (in_flight >= NS_SND_INFLIGHT_MAX && !s->fin)
            continue;   /* per-conn in-flight cap (see netstack.h): keep
                         * the aggregate inside the UDP sndbuf so the
                         * ACK stream can never be starved by a burst */
        seg_refresh_hdr(ns, c, s);
        /* device queue full: leave the segment unsent (sent stays 0) and
         * retry on the next tick. Marking it sent unconditionally was
         * the ul-4 stall: with 4 conns x 128 segments against a
         * 128-slot device queue, conns 2..4 lost their enqueue (the
         * first conn had filled the queue), yet the loop still set
         * sent=1 and advanced sent_nxt — the send loop then skipped the
         * segment forever (sent is sticky) and only the initial-RTO
         * retransmit (250ms per ring) flushed it, serializing the four
         * flows and capping the upload at ~170 Mbit/s. */
        if (!tx_enqueue(ns, (uint8_t)idx, s, NULL, 0))
            continue;
        s->sent = 1;
        s->last_sent_ms = now;
        s->rto = c->rto;
        s->cnt = 1;
        c->sent_nxt = seg_end(s);
        in_flight = c->sent_nxt - c->snd_una;
        sent_any = true;
    }
    conn_send_diag(c, p, idx, now, sent_any, in_flight);
    conn_send_fin(ns, c, p);
}

static int64_t conn_next_deadline(const NsPriv *p, uint64_t now) {
    int64_t d = INT64_MAX;
    for (int j = 0; j < p->nsegs; j++) {
        const Seg *s = seg_at_c(p, j);
        int64_t dd = (int64_t)(s->last_sent_ms + s->rto - now);
        if (dd < d)
            d = dd;
    }
    return d;
}

/* one conn's per-tick work: idle/keepalive handling, SYN retransmit or
 * established retransmit + fresh sends. Returns the ms until this conn
 * needs a tick again (<= 0 means immediately: an overdue segment whose
 * retransmit was deferred by a full device queue). A conn closed or
 * aborted this tick is left in NS_CLOSED — ns_tick detects that by
 * state and skips it. */
static int64_t conn_tick(Netstack *ns, int i, uint64_t now)
{
    TcpConn *c = &ns->conns[i];
    NsPriv *p;
    int64_t d;

    if (now > c->last_rx_ms + NS_IDLE_TIMEOUT) {
        /* idle: keepalive probe instead of dropping the conn; a probe
         * is a bare ACK with seq = snd_nxt - 1, which any peer answers
         * with an ACK for snd_nxt */
        if (c->state != NS_ESTABLISHED) {
            ns_abort(ns, i);
            return 0;
        }
        if (now >= c->keepalive_ms) {
            emit_tcp(ns, c, TCP_ACK, c->snd_nxt - 1u, c->rcv_nxt, 0);
            c->keepalive_ms = now + NS_KEEPALIVE_MS;
            if (++c->keepalive_cnt > NS_KEEPALIVE_MAX) {
                ns_abort(ns, i);
                return 0;
            }
        }
    }
    if (c->state == NS_SYN_SENT && now > c->state_ms + NS_CONNECT_TIMEOUT) {
        ns_abort(ns, i);
        return 0;
    }
    p = &ns->priv[i];

    if (c->state == NS_SYN_SENT) {
        d = conn_syn_retransmit(ns, c, i, now);
        if (d < 0)
            return 0;       /* tries exhausted: conn was aborted */
    } else {
        if (conn_fin_done(c, p, c->snd_una)) {
            /* close completed: free the rxq now — b_reset is idempotent,
             * so a later conn_clear on slot reuse frees NULL and can
             * never double-free the buffer */
            b_reset(&c->rxq);
            c->state = NS_CLOSED;
            return 0;
        }
        drop_acked(c, p);
        if (conn_retransmit_loop(ns, c, p, i, now))
            return 0;       /* retransmit budget exhausted: aborted */
        conn_send_new(ns, c, p, i, now);
        d = conn_next_deadline(p, now);
    }
    /* precise deadlines for a scheduled keepalive probe and idle timeout */
    if (c->keepalive_ms && (int64_t)(c->keepalive_ms - now) < d)
        d = (int64_t)(c->keepalive_ms - now);
    if ((int64_t)(c->last_rx_ms + NS_IDLE_TIMEOUT - now) < d)
        d = (int64_t)(c->last_rx_ms + NS_IDLE_TIMEOUT - now);
    return d;
}

int ns_tick(Netstack *ns, uint64_t now) {
    int64_t next = NS_TICK_DEFAULT_MS;
    for (int i = 0; i < NS_MAX_CONN; i++) {
        if (ns->conns[i].state == NS_CLOSED)
            continue;
        int64_t d = conn_tick(ns, i, now);
        if (ns->conns[i].state == NS_CLOSED)   /* closed/aborted this tick */
            continue;
        if (d < next)
            next = d;
    }
    if (next < 0)
        next = 0;
    if (next > NS_TICK_MAX_MS)
        next = NS_TICK_MAX_MS;
    return (int)next;
}

const TxItem *ns_tx_peek(Netstack *ns)
{
    if (ns->tx_count == 0)
        return NULL;
    return &ns->tx_queue[ns->tx_head];
}

const TxItem *ns_tx_pop(Netstack *ns)
{
    const TxItem *it;
    if (ns->tx_count == 0)
        return NULL;
    it = &ns->tx_queue[ns->tx_head];
    ns->tx_head = (ns->tx_head + 1) % NS_TX_MAX;
    ns->tx_count--;
    if (it->seg && it->conn != NS_TX_CONN_CTL)
        ns->q_used[it->conn]--;
    return it;
}

void ns_tx_rearm_seg(Netstack *ns, const void *seg, uint8_t conn)
{
    tx_enqueue(ns, conn, (const Seg *)seg, NULL, 0);
}

size_t ns_tx_item_len(const TxItem *it)
{
    return it->seg ? NS_SEG_HDR_LEN + ((const Seg *)it->seg)->len : it->clen;
}

const uint8_t *ns_tx_item_buf(const TxItem *it)
{
    return it->seg ? ((const Seg *)it->seg)->hdr : it->ctl;
}


