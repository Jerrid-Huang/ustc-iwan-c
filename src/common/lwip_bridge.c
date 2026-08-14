/*
 * lwIP bridge: the ns_* API from lwip_bridge.h backed by the vendored lwIP
 * (NO_SYS=1 raw API, single event-loop thread). The socks layer keeps its
 * poll-based connection model unchanged: lwIP's asynchronous callbacks
 * (connected / recv / err / poll) only update the per-slot state that
 * update_tcp_states / service_local_outputs already read.
 *
 * Close/reap model (the one non-obvious part):
 *   - abrupt close (RST / timeout): lwIP frees the pcb and fires err_cb; we
 *     mark the slot NS_CLOSED + term_reason and defer its reuse by one
 *     iteration (reap_pending) so update_tcp_states still reads the reason.
 *   - graceful close: after both FINs the slot is NS_CLOSED with a live pcb
 *     (in TIME_WAIT, or LAST_ACK about to be freed). The pcb is kept (so the
 *     slot is not reused while lwIP could still fire err_cb on a late RST),
 *     and ns_tick frees the slot once tcp_poll stops firing (the pcb left
 *     the active list => lwIP owns it no more).
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "lwip_bridge.h"
#include "util.h"

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"

#define NS_CONNECT_TIMEOUT 30000u
#define NS_MSS             1460u
#define NS_TICK_MAX_MS     10000
#define NS_POLL_DEAD_MS    1000u           /* poll stopped => pcb in TIME_WAIT
                                             * or freed; safe to reclaim */

/* ------------------------------------------------------------------ */
/* lwIP port glue                                                      */
/* ------------------------------------------------------------------ */

/* lwIP timeouts.c uses sys_now() (ms) as its timer base; the project's
 * now_ms() (util.h) is the same clock used everywhere else. */
u32_t sys_now(void)
{
    return (u32_t)now_ms();
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static void conn_slot_clear(TcpConn *c)
{
    buf_free(&c->rxq);
    c->pcb = NULL;
    c->state = NS_CLOSED;
    c->reap_pending = 0;
    c->last_poll_ms = 0;
    c->rxq_unrecved = 0;
    c->scratch_commit = 0;
}

/* call tcp_recved() for the bytes the socks layer drained from rxq since the
 * last reconciliation. This is how the downlink window reopens: recv_cb
 * appends to rxq WITHOUT tcp_recved (window shrinks -> peer stops), and the
 * drain (service_local_outputs) is acknowledged here, before any tcp_close
 * so a graceful close never sees a reduced rcv_wnd (which would force an
 * RST). */
static void conn_reconcile_rxq(TcpConn *c)
{
    if (c->pcb == NULL)
        return;
    size_t to_recved = c->rxq_unrecved - c->rxq.len;
    if (to_recved == 0)
        return;
    c->rxq_unrecved = c->rxq.len;
    while (to_recved > 0) {
        u16_t chunk = to_recved > 0xFFFF ? 0xFFFF : (u16_t)to_recved;
        tcp_recved(c->pcb, chunk);
        to_recved -= chunk;
    }
}

/* ------------------------------------------------------------------ */
/* netif output: frame [8B outer][inner IP] into a tx slot             */
/* ------------------------------------------------------------------ */

static FramedPkt *tx_find_free_slot(Netstack *ns)
{
    for (int i = 0; i < NS_TX_MAX; i++) {
        if (ns->pkt_refs[i] == 0)
            return &ns->pkt[i];
    }
    return NULL;
}

static int tx_enqueue(Netstack *ns, FramedPkt *fp, uint8_t conn)
{
    if (ns->tx_count >= NS_TX_MAX)
        return 0;
    int pos = (ns->tx_head + ns->tx_count) % NS_TX_MAX;
    TxItem *it = &ns->tx_queue[pos];
    it->seg = fp;
    it->clen = fp->len;
    it->conn = conn;
    ns->tx_count++;
    ns->pkt_refs[(int)(fp - ns->pkt)]++;
    if (conn != NS_TX_CONN_CTL)
        ns->q_used[conn]++;
    return 1;
}

/* parse the inner IPv4+TCP header of an outgoing packet: return the owning
 * conn index (matched by local/remote port) and whether it carries payload.
 * Returns -1 when the header cannot be parsed (chained pbuf is handled via
 * pbuf_copy_partial, so this is robust). */
static int bridge_output_parse(Netstack *ns, const struct pbuf *p,
                               int *has_payload)
{
    uint8_t h[40];
    const uint8_t *t;
    uint16_t sport, dport;
    size_t ihl, thlen, tot;

    *has_payload = 0;
    if (pbuf_copy_partial(p, h, sizeof h, 0) != sizeof h)
        return -1;
    ihl = (size_t)(h[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > sizeof h - 20)
        return -1;
    t = h + ihl;
    thlen = (size_t)(t[12] >> 4) * 4;
    if (thlen < 20 || ihl + thlen > sizeof h)
        return -1;
    tot = ((size_t)h[2] << 8) | h[3];
    if (tot < ihl + thlen)
        return -1;
    *has_payload = tot > ihl + thlen;
    sport = (uint16_t)((t[0] << 8) | t[1]);
    dport = (uint16_t)((t[2] << 8) | t[3]);
    for (int i = 0; i < NS_MAX_CONN; i++) {
        TcpConn *c = &ns->conns[i];
        if (c->pcb != NULL && c->lport == sport && c->rport == dport)
            return i;
    }
    return -1;
}

static err_t bridge_output(struct netif *netif, struct pbuf *p,
                           const ip4_addr_t *ipaddr)
{
    Netstack *ns = (Netstack *)netif->state;
    (void)ipaddr;

    if (p->tot_len > 1500)
        return ERR_MEM;   /* should never happen (netif MTU <= 1500) */

    /* per-conn fair-share on DATA segments: one conn may occupy at most
     * NS_TX_CONN_CAP slots so it cannot starve the others of device-queue
     * space (native netstack's sch_fq-style gate; without it an 8-conn
     * upload lets one conn fill the whole 128-slot queue and RTO-starve the
     * rest). Control (SYN/ACK/FIN, no payload) is exempt. */
    int has_payload = 0;
    int conn = bridge_output_parse(ns, p, &has_payload);
    if (conn >= 0 && has_payload && ns->q_used[conn] >= NS_TX_CONN_CAP)
        return ERR_MEM;   /* backpressure on THIS conn only */

    FramedPkt *fp = tx_find_free_slot(ns);
    if (fp == NULL)
        return ERR_MEM;   /* tx queue full: lwIP retransmits later (RTO) */

    memcpy(fp->buf, ns->outer_hdr, 8);
    if (pbuf_copy_partial(p, fp->buf + 8, p->tot_len, 0) != p->tot_len)
        return ERR_MEM;
    if (ns->outer_hdr[1])
        xor_crypt(fp->buf + 8, p->tot_len, ns->xor_key, 8);
    fp->len = (uint16_t)(8 + p->tot_len);

    tx_enqueue(ns, fp, (uint8_t)(conn >= 0 ? conn : NS_TX_CONN_CTL));
    return ERR_OK;
}

static err_t bridge_netif_init(struct netif *netif)
{
    netif->output = bridge_output;
    return ERR_OK;
}

/* ------------------------------------------------------------------ */
/* lwIP callbacks                                                      */
/* ------------------------------------------------------------------ */

static err_t bridge_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
    TcpConn *c = (TcpConn *)arg;
    if (c->pcb != pcb || err != ERR_OK)
        return ERR_OK;
    c->state = NS_ESTABLISHED;
    c->state_ms = now_ms();
    return ERR_OK;
}

static err_t bridge_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p,
                         err_t err)
{
    TcpConn *c = (TcpConn *)arg;
    if (c->pcb != pcb)
        return ERR_OK;   /* stale: slot was reused */

    if (p == NULL) {
        /* remote FIN (EOF). Active close: we already sent our FIN, so after
         * this callback lwIP moves the pcb to TIME_WAIT (no more callbacks)
         * and the slot can be reclaimed by ns_tick. */
        if (c->state == NS_ESTABLISHED)
            c->state = NS_CLOSE_WAIT;
        else if (c->state == NS_FIN_WAIT)
            c->state = NS_CLOSED;
        return ERR_OK;
    }

    if (err != ERR_OK) {
        pbuf_free(p);
        return ERR_OK;
    }

    /* copy the (possibly chained) payload into the downlink buffer. Do NOT
     * tcp_recved here: the window reopens only when the socks layer drains
     * rxq (conn_reconcile_rxq). Track the delivered-but-unrecved count. */
    for (struct pbuf *q = p; q != NULL; q = q->next)
        buf_put(&c->rxq, q->payload, q->len);
    c->rxq_unrecved += p->tot_len;
    pbuf_free(p);
    return ERR_OK;
}

static void bridge_err(void *arg, err_t err)
{
    TcpConn *c = (TcpConn *)arg;
    if (c->pcb == NULL)
        return;   /* already reclaimed */
    c->term_reason = (err == ERR_RST) ? NS_TERM_RST : NS_TERM_TIMEOUT;
    c->state = NS_CLOSED;
    c->pcb = NULL;        /* lwIP freed the pcb just before firing err_cb */
    c->reap_pending = 1;  /* defer reuse until update_tcp_states has read it */
    buf_free(&c->rxq);    /* discard undrained data, like native conn_clear */
}

static err_t bridge_poll(void *arg, struct tcp_pcb *pcb)
{
    TcpConn *c = (TcpConn *)arg;
    if (c->pcb != pcb)
        return ERR_OK;   /* stale */
    c->last_poll_ms = now_ms();
    return ERR_OK;
}

/* ------------------------------------------------------------------ */
/* public ns_* API                                                     */
/* ------------------------------------------------------------------ */

void ns_init(Netstack *ns, uint32_t inner_ip, uint32_t gw, uint16_t mtu)
{
    struct netif *old_netif = ns->netif;   /* save before the memset */

    memset(ns, 0, sizeof *ns);
    ns->ip = inner_ip;
    ns->gw = gw;
    ns->mtu = mtu;

    ns->connect_timeout_ms = NS_CONNECT_TIMEOUT;
    {
        const char *v = getenv("IWAN_NS_CONNECT_TIMEOUT_MS");
        char *end;
        unsigned long n;
        if (v && v[0]) {
            n = strtoul(v, &end, 10);
            if (end != v && *end == '\0' && n >= 1000 && n <= 300000)
                ns->connect_timeout_ms = (uint32_t)n;
            else
                log_err("IWAN_NS_CONNECT_TIMEOUT_MS: invalid value '%s' "
                        "(1000..300000); using default", v);
        }
    }

    lwip_init();

    /* a previous session's netif is still in lwIP's netif_list (netif_init
     * does not reset it); detach and free it so re-auths cannot accumulate
     * stale netifs that confuse ip_route. */
    if (old_netif != NULL) {
        netif_remove(old_netif);
        free(old_netif);
    }

    ip4_addr_t ip, mask, g;
    ip4_addr_set_u32(&ip, lwip_htonl(inner_ip));
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_u32(&g, lwip_htonl(gw));

    struct netif *n = malloc(sizeof *n);
    if (n == NULL)
        oom_abort();
    ns->netif = n;
    if (netif_add(n, &ip, &mask, &g, ns, bridge_netif_init, ip4_input) == NULL)
        return;
    n->mtu = (mtu > 1500) ? 1500 : mtu;
    n->state = ns;
    netif_set_link_up(n);
    netif_set_up(n);
    netif_set_default(n);
}

void ns_set_outer(Netstack *ns, const uint8_t hdr[8], const uint8_t key[8])
{
    memcpy(ns->outer_hdr, hdr, 8);
    memcpy(ns->xor_key, key, 8);
}

int ns_connect(Netstack *ns, uint16_t lport, uint32_t rip, uint16_t rport)
{
    int idx = -1;
    for (int i = 0; i < NS_MAX_CONN; i++) {
        if (ns->conns[i].pcb == NULL && !ns->conns[i].reap_pending) {
            idx = i;
            break;
        }
    }
    if (idx < 0)
        return -1;

    TcpConn *c = &ns->conns[idx];
    conn_slot_clear(c);
    c->ns = ns;
    c->rip = rip;
    c->lport = lport;
    c->rport = rport;
    c->term_reason = NS_TERM_NONE;
    c->state_ms = now_ms();
    c->last_poll_ms = c->state_ms;

    struct tcp_pcb *pcb = tcp_new();
    if (pcb == NULL)
        return -1;
    tcp_arg(pcb, c);
    tcp_recv(pcb, bridge_recv);
    tcp_err(pcb, bridge_err);
    tcp_poll(pcb, bridge_poll, 1);   /* 500ms liveness heartbeat */
    ip_set_option(pcb, SOF_KEEPALIVE);  /* lwIP built-in idle/keepalive */

    ip_addr_t ip;
    ip_addr_set_ip4_u32(&ip, lwip_htonl(rip));

    if (tcp_bind(pcb, IP_ADDR_ANY, lport) != ERR_OK)
        goto fail;
    if (tcp_connect(pcb, &ip, rport, bridge_connected) != ERR_OK)
        goto fail;
    tcp_nagle_disable(pcb);

    c->pcb = pcb;
    c->state = NS_SYN_SENT;
    return idx;

fail:
    tcp_arg(pcb, NULL);
    tcp_abort(pcb);
    c->pcb = NULL;
    return -1;
}

TcpConn *ns_conn(Netstack *ns, int idx)
{
    if (idx < 0 || idx >= NS_MAX_CONN)
        return NULL;
    return &ns->conns[idx];
}

NsState ns_state(const TcpConn *c)
{
    return c->state;
}

void ns_dump_conn(const Netstack *ns, int idx)
{
    if (!dbg_env("IWAN_FLOWDBG") || idx < 0 || idx >= NS_MAX_CONN)
        return;
    const TcpConn *c = &ns->conns[idx];
    const struct tcp_pcb *pcb = c->pcb;
    fprintf(stderr,
            "NSDUMP: conn=%d state=%d pcb=%p rxq=%llu term=%u "
            "pcbstate=%d snd_buf=%u rcv_wnd=%u cwnd=%u snd_wnd=%u q_used=%u\n",
            idx, c->state, (void *)pcb, (unsigned long long)c->rxq.len,
            c->term_reason,
            pcb ? (int)pcb->state : -1,
            pcb ? (unsigned)pcb->snd_buf : 0,
            pcb ? (unsigned)pcb->rcv_wnd : 0,
            pcb ? (unsigned)pcb->cwnd : 0,
            pcb ? (unsigned)pcb->snd_wnd : 0,
            ns->q_used[idx]);
}

uint8_t *ns_send_reserve(Netstack *ns, int idx, size_t *room)
{
    struct iovec iov[1];
    int n = ns_send_reservev(ns, idx, iov, 1);
    *room = n ? iov[0].iov_len : 0;
    return n ? (uint8_t *)iov[0].iov_base : NULL;
}

int ns_send_reservev(Netstack *ns, int idx, struct iovec *iov, int maxn)
{
    if (idx < 0 || idx >= NS_MAX_CONN)
        return 0;
    TcpConn *c = &ns->conns[idx];
    if (c->pcb == NULL)
        return 0;
    if (c->state == NS_CLOSED || c->state == NS_FIN_WAIT)
        return 0;
    /* backpressure: cap the reserved space at the current snd_buf so that
     * every ns_send_commit's tcp_write is guaranteed to succeed — otherwise
     * the readv bytes beyond snd_buf would be silently lost. */
    size_t avail = c->pcb->snd_buf;
    if (avail < NS_MSS)
        return 0;

    if (maxn > 4)
        maxn = 4;
    c->scratch_commit = 0;
    int n = 0;
    for (int k = 0; k < maxn && avail >= NS_MSS; k++) {
        iov[k].iov_base = c->scratch + (size_t)k * NS_MSS;
        iov[k].iov_len = NS_MSS;
        avail -= NS_MSS;
        n++;
    }
    return n;
}

int ns_send_commit(Netstack *ns, int idx, size_t n)
{
    if (idx < 0 || idx >= NS_MAX_CONN)
        return 0;
    TcpConn *c = &ns->conns[idx];
    if (c->pcb == NULL)
        return 0;
    if (n == 0)
        return 0;
    if (c->scratch_commit + n > sizeof c->scratch)
        n = sizeof c->scratch - c->scratch_commit;

    /* write in MSS-sized chunks (tcp_write len is u16_t; also keeps each
     * segment <= MSS so lwIP does not need to split) */
    size_t off = c->scratch_commit;
    size_t left = n;
    int written = 0;
    while (left > 0) {
        size_t chunk = left > NS_MSS ? NS_MSS : left;
        if (tcp_write(c->pcb, c->scratch + off, (u16_t)chunk,
                      TCP_WRITE_FLAG_COPY) != ERR_OK)
            break;
        off += chunk;
        left -= chunk;
        written += (int)chunk;
    }
    c->scratch_commit += (size_t)written;
    /* push what we accepted (tcp_output is cheap when nothing is queued) */
    if (written > 0)
        tcp_output(c->pcb);
    return written;
}

void ns_close(Netstack *ns, int idx)
{
    if (idx < 0 || idx >= NS_MAX_CONN)
        return;
    TcpConn *c = &ns->conns[idx];
    if (c->pcb == NULL || c->state == NS_CLOSED)
        return;

    if (c->state == NS_SYN_SENT) {
        /* never established: no FIN to send, just drop it */
        tcp_abort(c->pcb);   /* fires bridge_err -> NS_CLOSED */
        return;
    }

    /* reconcile the downlink window BEFORE closing: a reduced rcv_wnd makes
     * tcp_close send an RST instead of a FIN */
    conn_reconcile_rxq(c);

    /* Half-close (send FIN, keep RX) matches the native stack: ns_close is
     * called when the LOCAL client EOFs its write side, and the peer may
     * still send its response afterwards. A full tcp_close() sets
     * TF_RXCLOSED, which makes lwIP ABORT (RST) on any data that arrives
     * after our FIN — that would kill every half-closed request/response
     * stream. tcp_shutdown(shut_rx=0, shut_tx=1) sends the FIN without
     * closing the receive side. */
    if (c->state == NS_ESTABLISHED) {
        c->state = NS_FIN_WAIT;
        tcp_shutdown(c->pcb, 0, 1);
    } else if (c->state == NS_CLOSE_WAIT) {
        /* peer already FIN'd: our FIN completes the close -> LAST_ACK */
        c->state = NS_CLOSED;
        tcp_shutdown(c->pcb, 0, 1);
    }
}

void ns_abort(Netstack *ns, int idx)
{
    if (idx < 0 || idx >= NS_MAX_CONN)
        return;
    TcpConn *c = &ns->conns[idx];
    if (c->pcb == NULL)
        return;
    tcp_abort(c->pcb);   /* fires bridge_err -> NS_CLOSED + reap_pending */
}

void ns_rx_packet(Netstack *ns, const uint8_t *pkt, size_t n)
{
    if (n == 0 || n > 1500)
        return;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)n, PBUF_POOL);
    if (p == NULL)
        return;
    if (pbuf_take(p, pkt, (u16_t)n) != ERR_OK) {
        pbuf_free(p);
        return;
    }
    ip4_input(p, ns->netif);
}

/* ------------------------------------------------------------------ */
/* ns_tick: drive lwIP timers + reconcile timeouts / close reaps       */
/* ------------------------------------------------------------------ */

static void conn_reap_if_dead(Netstack *ns, int idx, uint64_t now)
{
    TcpConn *c = &ns->conns[idx];
    /* graceful close: the pcb is still alive in TIME_WAIT / LAST_ACK. Once
     * tcp_poll stops firing, lwIP no longer owns the pcb (it is in TIME_WAIT
     * or freed) and no more err_cb can fire, so the slot is safe to reuse. */
    if (c->state == NS_CLOSED && c->pcb != NULL &&
        now - c->last_poll_ms > NS_POLL_DEAD_MS) {
        c->pcb = NULL;
        buf_free(&c->rxq);
    }
}

int ns_tick(Netstack *ns, uint64_t now)
{
    int64_t next = NS_TICK_MAX_MS;
    int any_active = 0;

    for (int i = 0; i < NS_MAX_CONN; i++) {
        TcpConn *c = &ns->conns[i];
        if (c->pcb == NULL) {
            if (c->reap_pending)
                c->reap_pending = 0;
            continue;
        }
        any_active = 1;
        conn_reconcile_rxq(c);

        /* connect timeout (mirrors native conn_tick's SYN_SENT abort) */
        if (c->state == NS_SYN_SENT &&
            now - c->state_ms > ns->connect_timeout_ms) {
            c->term_reason = NS_TERM_TIMEOUT;
            tcp_abort(c->pcb);   /* bridge_err -> NS_CLOSED + reap_pending */
            continue;
        }
        conn_reap_if_dead(ns, i, now);

        /* bound the sleep so lwIP's own timers (tcp_tmr 250ms) run in time */
        if (c->state == NS_SYN_SENT) {
            int64_t d = (int64_t)(c->state_ms + ns->connect_timeout_ms) - (int64_t)now;
            if (d < next)
                next = d;
        }
    }

    /* drive lwIP timers: RTO retransmit, fast timer, slow timer (poll),
     * delayed ACK. sys_timeouts_sleeptime() reports the next lwIP timeout. */
    sys_check_timeouts();
    u32_t lwip_d = sys_timeouts_sleeptime();
    if (any_active && (int64_t)lwip_d < next)
        next = (int64_t)lwip_d;

    if (next < 0)
        next = 0;
    if (next > NS_TICK_MAX_MS)
        next = NS_TICK_MAX_MS;
    return (int)next;
}

/* ------------------------------------------------------------------ */
/* tx queue (drained by socks.c sock_drain_tx)                         */
/* ------------------------------------------------------------------ */

const TxItem *ns_tx_peek(Netstack *ns)
{
    if (ns->tx_count == 0)
        return NULL;
    return &ns->tx_queue[ns->tx_head];
}

const TxItem *ns_tx_pop(Netstack *ns)
{
    if (ns->tx_count == 0)
        return NULL;
    const TxItem *it = &ns->tx_queue[ns->tx_head];
    if (it->seg != NULL) {
        ns->pkt_refs[(int)((const FramedPkt *)it->seg - ns->pkt)]--;
        if (it->conn != NS_TX_CONN_CTL)
            ns->q_used[it->conn]--;
    }
    ns->tx_head = (ns->tx_head + 1) % NS_TX_MAX;
    ns->tx_count--;
    return it;
}

void ns_tx_rearm_seg(Netstack *ns, const void *seg, uint8_t conn)
{
    if (seg == NULL)
        return;
    tx_enqueue(ns, (FramedPkt *)seg, conn);
}

size_t ns_tx_item_len(const TxItem *it)
{
    return it->seg ? ((const FramedPkt *)it->seg)->len : it->clen;
}

const uint8_t *ns_tx_item_buf(const TxItem *it)
{
    return it->seg ? ((const FramedPkt *)it->seg)->buf : it->ctl;
}
