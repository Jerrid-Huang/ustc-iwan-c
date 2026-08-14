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
    uint8_t     conn;  /* owning conn index; NS_TX_CONN_CTL for control */
    uint8_t     ctl[64];
} TxItem;

#define NS_TX_MAX     128      /* device queue slots */
/* Per-conn cap on queued data items: the fair-share enforcer for the
 * shared device queue. Mirrors the kernel's per-flow queues (sch_fq):
 * each conn may occupy at most NS_TX_CONN_CAP slots, so N concurrent
 * conns split the queue ~evenly and one conn cannot starve the rest —
 * measured: an 8-conn upload gave conn0 1494 MB and conns 4-7 ~10 MB
 * with an unbounded queue. 16 slots x 8 conns = 128 = NS_TX_MAX. */
#define NS_TX_CONN_CAP 16
#define NS_TX_CONN_CTL 0xFF   /* TxItem.conn for inline control packets */

/* ---------------- userspace TCP connection ---------------- */
typedef struct TcpConn TcpConn;

typedef enum {
    /* fully closed / unallocated. No TIME_WAIT is kept: the tunnel peer
     * is a single trusted host, so a stale late segment cannot be
     * replayed against a reused slot (it is RST'd by rx_reject_unknown)
     * and a closing conn's rxq is freed at close completion. */
    NS_CLOSED = 0,
    NS_SYN_SENT,       /* connect() issued, waiting for SYN+ACK */
    NS_ESTABLISHED,
    NS_CLOSE_WAIT,     /* remote FIN received; we can still send, then close */
    NS_FIN_WAIT,       /* we called close(); draining */
} NsState;

/* why a connection ended: set on the acceptance/abort paths and read by
 * the SOCKS layer (socks_flow.c update_tcp_states) to map the failure to
 * a reply code (timeout -> rep 4, RST/other -> rep 5). conn_clear
 * PRESERVES the field across its memset — it must survive slot reuse
 * until the SOCKS flow has read it — and ns_connect resets it to
 * NS_TERM_NONE after conn_clear. ns_abort itself leaves it untouched
 * (local aborts keep whatever reason was set before the abort). */
#define NS_TERM_NONE    0   /* local teardown / never set */
#define NS_TERM_RST     1   /* peer RST accepted */
#define NS_TERM_TIMEOUT 2   /* retransmit/keepalive/idle timeout */

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
    /* SYN retransmit state (the data retransmit path uses the segment
     * ring in NsPriv, not this) */
    uint32_t syn_retx_seq;
    uint64_t syn_retx_ms;
    uint8_t  syn_retx_cnt;
    uint64_t state_ms;      /* when state last changed */
    uint64_t last_rx_ms;
    uint16_t mss;
    uint8_t  peer_scale;    /* peer's window shift (WSCALE) */
    uint32_t remote_win;    /* last advertised window, bytes (wire<<scale) */
    /* smoothed RTT estimates (ms): RTO = srtt + 4*rttvar */
    uint16_t srtt;
    uint16_t rttvar;
    uint16_t rto;
    uint8_t  dup_acks;      /* consecutive duplicate ACKs (fast retx) */
    uint64_t keepalive_ms;  /* next keepalive probe deadline */
    uint8_t  keepalive_cnt; /* unanswered probes before abort */
    uint64_t last_dump_ms;  /* last ns_dump_conn timestamp (diagnostic) */
    uint8_t  term_reason;   /* NS_TERM_*: why the conn ended; preserved by
                             * conn_clear, reset by ns_connect */
};

#define NS_MAX_CONN 64

/* ---------------- per-conn retransmit segment ring ---------------- */
#define NS_MAX_OUTSTANDING 128
#define NS_SEG_CAP 1460u       /* max payload per segment (MTU 1500 - 40) */
#define NS_SEG_HDR_LEN 48      /* [8B outer][40B inner] before payload */
/* per-conn cap on TRANSMITTED-but-unacked bytes (the cwnd equivalent).
 * The stack is window-driven (in_flight < remote_win), so without this
 * cap the aggregate in-flight across concurrent conns is bounded only by
 * the peer's advertised windows — a 4-conn upload against peers with
 * autotuned MB-sized windows blows past the client's UDP sndbuf, the
 * send path EAGAINs forever, the ACK stream starves and every conn
 * dies (measured: 4 x 8MiB uploads -> RST storm; the old 300k pps
 * client pacing papered over the same hole by never letting the burst
 * form). 1 MiB per conn keeps the aggregate well inside a 4-8 MiB
 * sndbuf; throughput stays window/RTT-adaptive and is not rate-capped
 * (at 2ms RTT this allows ~4 Gbit/s aggregate). */
#define NS_SND_INFLIGHT_MAX (1u << 20)

/* one TCP segment. The payload lives here from the moment the app data
 * is read (ns_send_reserve) until it is ACKed — it is never copied.
 * hdr = [8B outer VPN header][40B inner IP+TCP header]; the inner TCP
 * header's ack/win/checksum are refreshed on every (re)transmission. */
typedef struct {
    uint32_t seq;
    uint16_t len;              uint16_t rto;
    uint8_t  cnt;
    uint8_t  fin;
    uint8_t  sent;             uint64_t last_sent_ms;
    uint8_t  hdr[NS_SEG_HDR_LEN];
    _Alignas(8) uint8_t data[NS_SEG_CAP];   /* must sit at hdr+48: the
                                             * inner packet's payload is
                                             * ip+40 == hdr+48. The fields
                                             * before hdr total 24 bytes,
                                             * so data lands at 72;
                                             * _Alignas(8) keeps it there,
                                             * while 16B alignment would
                                             * push it to 80 and skew
                                             * every checksum by 8 bytes */
} Seg;

typedef struct {
    /* ring of sealed segments plus the fill slot (ring tail, where app
     * data accumulates) at segs[seg_head + nsegs]; that index reaches
     * NS_MAX_OUTSTANDING (128) when the ring is full, so the array is
     * sized +1 to keep it in-bounds — a separate `fill` field used to
     * silently alias segs[128] */
    Seg      segs[NS_MAX_OUTSTANDING + 1];
    int      nsegs;
    int      seg_head;       uint8_t  fin_sent;
} NsPriv;

typedef struct {
    uint32_t ip;            /* inner tun IP (host order) */
    uint32_t gw;            /* gateway (host order) */
    uint16_t mtu;
    uint8_t  outer_hdr[8];  /* VPN outer header, filled after auth */
    uint8_t  xor_key[8];    /* payload cipher, filled after auth */
    TcpConn conns[NS_MAX_CONN];
    NsPriv  priv[NS_MAX_CONN]; /* per-conn segment rings (parallel conns) */
    uint16_t ip_id;         /* IP ID counter for outgoing datagrams */
    int      last_conn;     /* rx 4-tuple lookup cache (last match) */
    /* device queue: ready packets (segment-slot pointers or control) */
    struct TxItem tx_queue[NS_TX_MAX];
    int tx_head, tx_count;
    /* device-queue items per conn (fair-share accounting, NS_TX_CONN_CAP) */
    uint8_t q_used[NS_MAX_CONN];
    /* connect timeout (ms) for the SYN path: IWAN_NS_CONNECT_TIMEOUT_MS
     * override for tests, default NS_CONNECT_TIMEOUT. */
    uint32_t connect_timeout_ms;
} Netstack;

void ns_init(Netstack *ns, uint32_t inner_ip, uint32_t gw, uint16_t mtu);

/* auth completed: record the outer VPN header and XOR key; data segments
 * are framed and encrypted in place at seal time */
void ns_set_outer(Netstack *ns, const uint8_t hdr[8], const uint8_t key[8]);

/* find/allocate a conn slot; returns index or -1 */
int  ns_connect(Netstack *ns, uint16_t lport, uint32_t rip, uint16_t rport);
/* IPv6 remote: the native rollback stack is IPv4-only, so this always
 * returns -1 (the SOCKS layer maps that to rep=8). Kept in the API so
 * socks_flow.c compiles against either stack. */
int  ns_connect6(Netstack *ns, uint16_t lport, const uint8_t rip6[16],
                 uint16_t rport);
TcpConn *ns_conn(Netstack *ns, int idx);
NsState ns_state(const TcpConn *c);
/* diagnostic: dump conn send state (IWAN_FLOWDBG=1) */
void ns_dump_conn(const Netstack *ns, int idx);

/* zero-copy app-data path: reserve writable space in the pending segment
 * slot (read() straight into it), then commit what was filled. Returns
 * NULL/0 when the stack is full (backpressure). */
uint8_t *ns_send_reserve(Netstack *ns, int idx, size_t *room);
/* reserve up to maxn contiguous fill slots (linear, no wrap) into iov;
 * returns the number of slots. Pointers stay valid until the matching
 * ns_send_commit calls seal them. */
int ns_send_reservev(Netstack *ns, int idx, struct iovec *iov, int maxn);
/* commit n fill bytes (clamped to the reserved room); returns the number
 * of bytes actually committed, 0 when the stack was full or idx was
 * invalid. NOTE: the return type changed from void to int — callers in
 * other modules (socks_flow.c) must adopt the return value in the
 * integration pass; ignoring it stays source-compatible. */
int  ns_send_commit(Netstack *ns, int idx, size_t n);
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
/* re-arm a segment-slot item at the tail of the device queue: used by
 * the device drain when a blocked send (ENOBUFS) must not drop the
 * segment into RTO recovery. The segment itself stays in the retransmit
 * ring, so this only re-queues the reference; if the ring compacts
 * before the next drain, the stale reference still delivers one of the
 * ring's genuine (seq, payload) pairs (payloads are immutable once
 * sealed), which the peer dedups by seq. `conn` is the item's owning
 * conn index (keeps the per-conn queue accounting in sync). */
void ns_tx_rearm_seg(Netstack *ns, const void *seg, uint8_t conn);
/* TX item helpers: total packet length and send buffer (segment slot or
 * inline control) */
size_t ns_tx_item_len(const struct TxItem *it);
const uint8_t *ns_tx_item_buf(const struct TxItem *it);

#endif
