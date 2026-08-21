#ifndef IWAN_LWIP_BRIDGE_H
#define IWAN_LWIP_BRIDGE_H

/*
 * lwIP bridge: presents the SAME ns_* API as netstack.h so socks.c /
 * socks_flow.c compile unchanged, but backs it with the vendored lwIP
 * (NO_SYS=1 raw API, single event-loop thread). Selected by the
 * IWAN_TCP_STACK CMake option; see tcpstack.h.
 *
 * The public surface (types + function signatures + the 3 Netstack fields
 * and 4 TcpConn fields the socks layer reads) is kept byte-compatible with
 * netstack.h. Bridge-internal state (the lwIP netif, tx queue, scratch
 * buffers) is additional and never touched by the socks layer.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"      /* buf_t, struct iovec (via port.h) */

/* Forward declarations: lwIP types are opaque here (this header must not
 * pull lwip/opt.h + lwipopts.h into the SOCKS layer, whose system socket
 * headers define clashing macros). lwip_bridge.c includes the real headers
 * and sees the complete types. */
struct tcp_pcb;
struct netif;

/* NOTE: this header deliberately does NOT include any lwIP header. The
 * SOCKS layer (socks.c/socks_flow.c) already includes the system socket
 * headers (netinet/tcp.h defines TCP_MSS, netinet/in.h defines BYTE_ORDER),
 * and pulling lwip/opt.h + lwipopts.h in here would collide with them.
 * lwIP types are held as opaque pointers and cast inside lwip_bridge.c. */

/* ---------------- device queue ---------------- */
#define NS_TX_MAX        128
#define NS_TX_CONN_CAP   16
#define NS_TX_CONN_CTL   0xFF
#define NS_MAX_CONN      64

/* one framed outbound packet: [8B outer VPN header][inner IP packet] */
typedef struct FramedPkt {
    uint8_t  buf[8 + 1500];   /* max inner MTU 1500 */
    uint16_t len;             /* 8 + iplen */
} FramedPkt;

/* device-queue item (same layout as netstack.h TxItem) */
typedef struct TxItem {
    const void *seg;   /* const FramedPkt * for queued packets; NULL unused */
    uint16_t    clen;
    uint8_t     conn;  /* owning conn index (fair-share accounting), or
                        * NS_TX_CONN_CTL for control packets */
    uint8_t     ctl[64];
} TxItem;

/* ---------------- userspace TCP connection ---------------- */
typedef struct TcpConn TcpConn;

typedef enum {
    NS_CLOSED = 0,
    NS_SYN_SENT,
    NS_ESTABLISHED,
    NS_CLOSE_WAIT,     /* remote FIN received */
    NS_FIN_WAIT,       /* we called close(); draining */
} NsState;

#define NS_TERM_NONE    0
#define NS_TERM_RST     1
#define NS_TERM_TIMEOUT 2

struct TcpConn {
    /* ---- public fields (read by socks_flow.c) ---- */
    NsState  state;
    buf_t    rxq;           /* downlink buffer: recv_cb appends, the socks
                             * layer drains it to the local client fd */
    uint8_t  term_reason;   /* NS_TERM_*; set on failure, read by
                             * update_tcp_states to map to a reply code */
    uint64_t last_dump_ms;
    /* ---- bridge-internal ---- */
    struct tcp_pcb *pcb;    /* NULL when the slot is free */
    uint8_t  af;            /* 4 = IPv4 (rip), 6 = IPv6 (rip6) */
    uint32_t rip;
    uint8_t  rip6[16];
    uint16_t rport, lport;
    uint64_t state_ms;      /* when state last changed (connect start) */
    size_t   rxq_unrecved;   /* bytes delivered to recv_cb but not yet
                              * tcp_recved() (= delivered - recved). The
                              * reconcile step calls tcp_recved for
                              * (rxq_unrecved - rxq.len): the part the socks
                              * layer already drained from rxq. */
    uint8_t  scratch[4 * 1460]; /* zero-copy readv target (LOCAL_IOV_MAX x
                                 * MSS) for ns_send_reservev */
    size_t   scratch_commit;    /* cursor: bytes committed from scratch */
    uint64_t last_poll_ms;      /* last tcp_poll callback (close liveness) */
    uint8_t  reap_pending;      /* abrupt close: defer slot reuse until
                                 * update_tcp_states has read term_reason */
};

typedef struct Netstack {
    /* ---- public fields (read by socks_flow.c / socks.c) ---- */
    uint32_t ip;            /* inner tun IP, host order (MSB-first) */
    uint16_t mtu;
    uint8_t  outer_hdr[8];
    uint8_t  xor_key[8];
    /* ---- bridge-internal ---- */
    struct netif *netif;        /* allocated in ns_init */
    TcpConn conns[NS_MAX_CONN];
    TxItem   tx_queue[NS_TX_MAX];
    int      tx_head, tx_count;
    FramedPkt pkt[NS_TX_MAX];       /* tx packet pool */
    uint8_t  pkt_refs[NS_TX_MAX];   /* 1 = slot referenced by a queue entry */
    uint8_t  q_used[NS_MAX_CONN];   /* per-conn tx-queue slots (fair share) */
    uint32_t connect_timeout_ms;
    int      active_count;          /* live conns (idle sleep optimization) */
} Netstack;

/* ---------------- ns_* API (signatures match netstack.h) ---------------- */
void ns_init(Netstack *ns, uint32_t inner_ip, uint32_t gw, uint16_t mtu);
void ns_set_outer(Netstack *ns, const uint8_t hdr[8], const uint8_t key[8]);
int  ns_connect(Netstack *ns, uint16_t lport, uint32_t rip, uint16_t rport);
/* IPv6 remote: rip6 is 16 raw bytes. Native (netstack.h) has no IPv6
 * and returns -1; the SOCKS layer maps that to rep=8. */
int  ns_connect6(Netstack *ns, uint16_t lport, const uint8_t rip6[16],
                 uint16_t rport);
TcpConn *ns_conn(Netstack *ns, int idx);
void ns_dump_conn(const Netstack *ns, int idx);
int  ns_send_reservev(Netstack *ns, int idx, struct iovec *iov, int maxn);
int  ns_send_commit(Netstack *ns, int idx, size_t n);
void ns_close(Netstack *ns, int idx);
void ns_abort(Netstack *ns, int idx);
void ns_rx_packet(Netstack *ns, const uint8_t *pkt, size_t n);
/* Zero-copy RX path: acquire() hands out receive buffers that the VPN
 * recv loop fills directly with a datagram (outer header first); pass the
 * buffer base + outer length to ns_rx_packet_ref, which wraps the inner
 * packet in a lwIP PBUF_REF custom pbuf and returns the buffer to the
 * pool only when lwIP frees it. Callers that drop a datagram must call
 * ns_rx_buf_release() themselves. */
int  ns_rx_buf_acquire(void **bufs, int max);
void ns_rx_buf_release(void *data);
void ns_rx_packet_ref(Netstack *ns, void *slot_data, size_t outer_len);
int  ns_tick(Netstack *ns, uint64_t now);
const struct TxItem *ns_tx_peek(Netstack *ns);
const struct TxItem *ns_tx_pop(Netstack *ns);
void ns_tx_rearm_seg(Netstack *ns, const void *seg, uint8_t conn);
size_t ns_tx_item_len(const struct TxItem *it);
const uint8_t *ns_tx_item_buf(const struct TxItem *it);
/* Call after the tx queue has been drained: lwIP may have marked
 * TF_NAGLEMEMERR when bridge_output returned ERR_MEM (queue full), and
 * tcp_txnow() retries the pending output immediately instead of waiting
 * for an ACK/timer/RTO. No-op on the native stack. */
void ns_tx_kick(Netstack *ns);

#endif /* IWAN_LWIP_BRIDGE_H */
