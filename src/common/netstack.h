#ifndef IWAN_NETSTACK_H
#define IWAN_NETSTACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "common.h"

/* device-queue item: a segment slot reference (zero-copy) or a small
 * inline control packet */
typedef struct TxItem {
    const void *seg;   /* const Seg * in netstack.c */
    uint16_t    clen;  /* 0 for segment items */
    uint8_t     ctl[64];
} TxItem;

#define DNS_SERVER_IP "114.114.114.114"
#define NS_TX_MAX     128      /* device queue slots */

/* ---------------- userspace TCP connection ---------------- */
typedef struct TcpConn TcpConn;

typedef enum {
    NS_CLOSED = 0,     /* fully closed / unallocated */
    NS_SYN_SENT,       /* connect() issued, waiting for SYN+ACK */
    NS_ESTABLISHED,
    NS_CLOSE_WAIT,     /* remote FIN received; we can still send, then close */
    NS_FIN_WAIT,       /* we called close(); draining */
} NsState;

/* callbacks filled by socks.c */
typedef struct {
    /* stack wants to emit an IP packet -> enqueue to device.tx */
    void (*on_tx_pkt)(void *ud, const uint8_t *pkt, size_t n);
    void *on_tx_pkt_ud;
} NsHooks;

/* one TCP connection (indexed 0..NS_MAX_CONN-1) */
struct TcpConn {
    NsState  state;
    uint32_t lip, rip;      /* host-order IPv4 addrs */
    uint16_t lport, rport;  /* host order */
    uint32_t snd_una, snd_nxt, snd_isn;
    uint32_t sent_nxt;      /* seq after the last TRANSMITTED segment */
    uint32_t rcv_nxt;
    bool     remote_fin;
    bool     local_fin;     /* we sent our FIN */
    buf_t    rxq;           /* received data (for app) */
    /* retransmit of a single data segment */
    uint8_t  retx_buf[2048];
    uint16_t retx_len;      /* 0 = none */
    uint32_t retx_seq;
    uint64_t retx_ms;
    uint8_t  retx_cnt;
    uint64_t state_ms;      /* when state last changed */
    uint64_t last_rx_ms;
    uint16_t mss;
    uint8_t  peer_scale;    /* peer's window shift (WSCALE) */
    uint32_t remote_win;    /* last advertised window, unscaled */
    /* delayed-ACK state: pending flag, segment count (2 -> immediate
     * ACK), timestamp of the first unacked segment */
    uint8_t  ack_pending;
    uint8_t  rx_segs;
    uint64_t ack_ms;
};

#define NS_MAX_CONN 64

typedef struct {
    uint32_t ip;            /* inner tun IP (host order) */
    uint32_t gw;            /* gateway (host order) */
    uint16_t mtu;
    uint32_t isn_base;
    uint8_t  outer_hdr[8];  /* VPN outer header, filled after auth */
    uint8_t  xor_key[8];    /* payload cipher, filled after auth */
    TcpConn conns[NS_MAX_CONN];
    /* device queue: ready packets (segment-slot pointers or control) */
    struct TxItem tx_queue[NS_TX_MAX];
    int tx_head, tx_count;
    NsHooks hooks;
} Netstack;

void ns_init(Netstack *ns, uint32_t inner_ip, uint32_t gw, uint16_t mtu, uint32_t seed);

/* auth completed: record the outer VPN header and XOR key; data segments
 * are framed and encrypted in place at seal time */
void ns_set_outer(Netstack *ns, const uint8_t hdr[8], const uint8_t key[8]);

/* find/allocate a conn slot; returns index or -1 */
int  ns_connect(Netstack *ns, uint16_t lport, uint32_t rip, uint16_t rport);
TcpConn *ns_conn(Netstack *ns, int idx);
NsState ns_state(const TcpConn *c);

/* zero-copy app-data path: reserve writable space in the pending segment
 * slot (read() straight into it), then commit what was filled. Returns
 * NULL/0 when the stack is full (backpressure). */
uint8_t *ns_send_reserve(Netstack *ns, int idx, size_t *room);
void ns_send_commit(Netstack *ns, int idx, size_t n);
/* read received data into out; returns n bytes (0 = none) */
size_t ns_recv(Netstack *ns, int idx, uint8_t *out, size_t n);
/* graceful close (FIN). */
void ns_close(Netstack *ns, int idx);
/* hard close / free slot */
void ns_abort(Netstack *ns, int idx);

/* push a received IP packet into the stack */
void ns_rx_packet(Netstack *ns, const uint8_t *pkt, size_t n);

/* pump timers/retransmits; send any queued SYN/data/ACK.
 * Returns ms until next needed tick (<=0 means immediately). */
int  ns_tick(Netstack *ns, uint64_t now);

/* peek/pop one ready packet the stack wants to emit (to VPN).
 * Returns a pointer (segment slot or inline control) or NULL. */
const struct TxItem *ns_tx_peek(Netstack *ns);
const struct TxItem *ns_tx_pop(Netstack *ns);
/* TX item helpers: total packet length and send buffer (segment slot or
 * inline control) */
size_t ns_tx_item_len(const struct TxItem *it);
const uint8_t *ns_tx_item_buf(const struct TxItem *it);
#define NS_SEG_HDR_LEN 48    /* [8B outer][40B inner] before payload */

/* ---------------- DNS (hardcoded 114.114.114.114) ---------------- */
/* resolve domain to IPv4 via 114.114.114.114:53. Returns sock-order IP or 0. */
uint32_t dns_query_a(const char *domain);

#endif
