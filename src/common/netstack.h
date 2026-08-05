#ifndef IWAN_NETSTACK_H
#define IWAN_NETSTACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "common.h"

#define DNS_SERVER_IP "114.114.114.114"

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
    uint32_t remote_win;    /* last advertised window */
};

#define NS_MAX_CONN 64

typedef struct {
    uint32_t ip;            /* inner tun IP (host order) */
    uint32_t gw;            /* gateway (host order) */
    uint16_t mtu;
    uint32_t isn_base;
    TcpConn conns[NS_MAX_CONN];
    /* device queue: complete IP packets to send to VPN */
    buf_t tx_queue[64];
    int tx_head, tx_count;
    NsHooks hooks;
} Netstack;

void ns_init(Netstack *ns, uint32_t inner_ip, uint32_t gw, uint16_t mtu, uint32_t seed);

/* find/allocate a conn slot; returns index or -1 */
int  ns_connect(Netstack *ns, uint16_t lport, uint32_t rip, uint16_t rport);
TcpConn *ns_conn(Netstack *ns, int idx);
NsState ns_state(const TcpConn *c);

/* queue app data to send; returns bytes queued (=n, buffered internally) */
size_t ns_send(Netstack *ns, int idx, const uint8_t *data, size_t n);
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

/* pop one IP packet the stack wants to emit (to VPN). Returns len or 0. */
size_t ns_device_pop(Netstack *ns, uint8_t *out, size_t maxlen);

/* ---------------- DNS (hardcoded 114.114.114.114) ---------------- */
/* resolve domain to IPv4 via 114.114.114.114:53. Returns sock-order IP or 0. */
uint32_t dns_query_a(const char *domain);

#endif
