/*
 * Root-free data-path test for the lwIP bridge.
 *
 * The 19-case socks_handshake suite only ever exercises the CONNECT
 * lifecycle (the harness never drains the tx queue, so no connection is
 * established). This harness exercises the real data plane: a minimal
 * in-process "fake TCP peer" terminates the bridge's connection and echoes
 * every uploaded segment back, while the bridge uploads a known pattern via
 * ns_send_reservev/ns_send_commit (the exact readv path socks_flow.c uses)
 * and drains ns_conn(idx)->rxq to verify the echo byte-for-byte.
 *
 * Inner topology: client 198.18.0.2 -> peer 198.18.0.1:12345, plaintext
 * (zeroed outer header, no XOR), MTU 1500.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "ipv4.h"
#include "protocol.h"
#include "tcpstack.h"
#include "util.h"

#define CLIENT_IP   0xC6120002u   /* 198.18.0.2 */
#define SERVER_IP   0xC6120001u   /* 198.18.0.1 */
#define SERVER_PORT 12345
#define CLIENT_PORT 40000
#define PATTERN_LEN (44 * 1460)   /* 44 full-MSS segments = 22 reorder pairs */

static Netstack g_ns;
static int g_conn = -1;

/* ---- fake peer state ---- */
static uint32_t g_client_seq;    /* next seq expected from the client */
static uint32_t g_server_seq;    /* next seq we (the peer) send */
static uint16_t g_client_lport;
static int g_established;
static int g_reorder;            /* IWAN_TEST_REORDER: swap adjacent echoes */
static int g_drop_once;          /* IWAN_TEST_DROP_ONCE: drop until retransmit */
static uint32_t g_drop_seq;      /* seq of the first (dropped) data segment */
static int g_drop_seen;
static size_t g_total;           /* echo size (PATTERN_LEN, or bench override) */
static int g_bench;              /* IWAN_TEST_BENCH_BYTES: skip verify, time */
/* pending echo (for out-of-order injection) */
static uint8_t g_pending[1500];
static size_t g_pending_len;
static uint32_t g_pending_seq;
static uint32_t g_pending_ack;
static int g_has_pending;

/* build a plain inner IPv4+TCP packet; returns total length. mss_opt != 0
 * adds a 4-byte MSS option, wscale != 0 adds a 4-byte WSCALE+NOP option
 * (both required in SYN+ACK: lwIP starts at the RFC 879 INITIAL_MSS of 536
 * and only raises it from the peer's MSS option, and only advertises its
 * full 256KB window once the peer echoes WSCALE). */
static size_t peer_build(uint8_t *out, uint32_t sip, uint32_t dip,
                         uint16_t sport, uint16_t dport, uint32_t seq,
                         uint32_t ack, uint8_t flags,
                         const uint8_t *payload, size_t paylen,
                         uint16_t mss_opt, uint8_t wscale)
{
    size_t optlen = (mss_opt ? 4 : 0) + (wscale ? 4 : 0);
    size_t thlen = 20 + optlen;
    size_t tot = 20 + thlen + paylen;
    memset(out, 0, 20);
    out[0] = 0x45;
    out[2] = (uint8_t)(tot >> 8);
    out[3] = (uint8_t)tot;
    out[8] = 64;                 /* TTL */
    out[9] = 6;                  /* TCP */
    u32_ip4(sip, out + 12);
    u32_ip4(dip, out + 16);
    uint16_t ipc = ip_csum_fold(ip_csum_accum(0, out, 20));
    out[10] = (uint8_t)(ipc >> 8);
    out[11] = (uint8_t)ipc;

    uint8_t *t = out + 20;
    memset(t, 0, (size_t)thlen); /* zero TCP header incl. checksum field */
    t[0] = (uint8_t)(sport >> 8); t[1] = (uint8_t)sport;
    t[2] = (uint8_t)(dport >> 8); t[3] = (uint8_t)dport;
    t[4] = (uint8_t)(seq >> 24); t[5] = (uint8_t)(seq >> 16);
    t[6] = (uint8_t)(seq >> 8);  t[7] = (uint8_t)seq;
    t[8] = (uint8_t)(ack >> 24); t[9] = (uint8_t)(ack >> 16);
    t[10] = (uint8_t)(ack >> 8); t[11] = (uint8_t)ack;
    t[12] = (uint8_t)((thlen / 4) << 4);  /* data offset */
    t[13] = flags;
    t[14] = 0xff; t[15] = 0xff;  /* window 65535 */
    if (mss_opt) {
        t[20] = 2;               /* kind = MSS */
        t[21] = 4;
        t[22] = (uint8_t)(mss_opt >> 8);
        t[23] = (uint8_t)mss_opt;
    }
    if (wscale) {
        size_t o = mss_opt ? 24 : 20;
        t[o] = 3;                /* kind = WSCALE */
        t[o + 1] = 3;
        t[o + 2] = wscale;
        t[o + 3] = 1;            /* NOP pad */
    }
    if (payload && paylen)
        memcpy(t + thlen, payload, paylen);
    uint16_t tc = ip_tcp_csum(sip, dip, t, thlen + paylen);
    t[16] = (uint8_t)(tc >> 8);
    t[17] = (uint8_t)tc;
    return tot;
}

static void peer_reply(uint32_t seq, uint32_t ack, uint8_t flags,
                       const uint8_t *payload, size_t paylen, uint16_t mss_opt,
                       uint8_t wscale)
{
    uint8_t out[2048];
    size_t n = peer_build(out, SERVER_IP, CLIENT_IP, SERVER_PORT,
                          g_client_lport, seq, ack, flags, payload, paylen,
                          mss_opt, wscale);
    ns_rx_packet(&g_ns, out, n);
}

/* consume one inner IP packet from the bridge's tx queue */
static void peer_feed(const uint8_t *pkt, size_t n)
{
    if (n < 40)
        return;
    size_t ihl = (size_t)(pkt[0] & 0x0f) * 4;
    const uint8_t *t = pkt + ihl;
    size_t thlen = (size_t)(t[12] >> 4) * 4;
    uint16_t sport = (uint16_t)((t[0] << 8) | t[1]);
    uint32_t seq = ((uint32_t)t[4] << 24) | ((uint32_t)t[5] << 16) |
                   ((uint32_t)t[6] << 8) | t[7];
    uint8_t flags = t[13];
    size_t paylen = n - ihl - thlen;
    const uint8_t *payload = t + thlen;

    if (flags & 0x02) {          /* SYN */
        g_client_lport = sport;
        g_client_seq = seq + 1;
        g_server_seq = 0x12345678u + 1;
        g_established = 1;
        peer_reply(0x12345678u, g_client_seq, 0x12 /* SYN|ACK */, NULL, 0,
                   1460, 4);
        return;
    }

    uint32_t data_end = seq + (uint32_t)paylen;

    /* process payload first: a FIN may be piggybacked with the last data */
    if (paylen > 0) {
        g_client_seq = data_end;
        if (g_drop_once && !g_drop_seen) {
            /* drop the first data segment and everything after it: the
             * client's lwIP gets no cumulative ACK, so its RTO fires and it
             * retransmits the oldest segment (same seq). On that retransmit
             * the peer resumes echoing and the stream recovers. */
            g_drop_seen = 1;
            g_drop_seq = seq;
        } else if (g_drop_once && seq == g_drop_seq) {
            /* retransmission of the dropped segment: echo it, resume normal */
            g_drop_once = 0;
            peer_reply(g_server_seq, g_client_seq, 0x18 /* PSH|ACK */,
                       payload, paylen, 0, 0);
            g_server_seq += (uint32_t)paylen;
        } else if (g_drop_once) {
            /* still dropping subsequent new segments: no echo, no ACK */
        } else if (g_reorder) {
            /* swap adjacent pairs: send segment N+1 before segment N, so the
             * client's lwIP must queue the OOS segment and reassemble. */
            if (!g_has_pending) {
                g_pending_seq = g_server_seq;
                g_pending_ack = g_client_seq;
                g_pending_len = paylen;
                memcpy(g_pending, payload, paylen);
                g_has_pending = 1;
                g_server_seq += (uint32_t)paylen;
            } else {
                peer_reply(g_server_seq, g_client_seq, 0x18 /* PSH|ACK */,
                           payload, paylen, 0, 0);      /* current (N+1) */
                peer_reply(g_pending_seq, g_pending_ack, 0x18, g_pending,
                           g_pending_len, 0, 0);        /* pending (N) */
                g_server_seq += (uint32_t)paylen;
                g_has_pending = 0;
            }
        } else {
            peer_reply(g_server_seq, g_client_seq, 0x18 /* PSH|ACK */,
                       payload, paylen, 0, 0);
            g_server_seq += (uint32_t)paylen;
        }
    }

    if (flags & 0x01) {          /* FIN */
        if (g_has_pending) {      /* odd number of segments: flush the last */
            peer_reply(g_pending_seq, g_pending_ack, 0x18 /* PSH|ACK */,
                       g_pending, g_pending_len, 0, 0);
            g_has_pending = 0;
        }
        g_client_seq = data_end + 1;
        peer_reply(g_server_seq, g_client_seq, 0x11 /* FIN|ACK */, NULL, 0,
                   0, 0);
        g_server_seq++;
    }
}

int main(void)
{
    g_reorder = getenv("IWAN_TEST_REORDER") != NULL;
    g_drop_once = getenv("IWAN_TEST_DROP_ONCE") != NULL;
    g_total = PATTERN_LEN;
    {
        const char *b = getenv("IWAN_TEST_BENCH_BYTES");
        if (b && b[0]) {
            unsigned long long n = strtoull(b, NULL, 10);
            if (n >= PATTERN_LEN) {
                g_total = (size_t)n;
                g_bench = 1;
            }
        }
    }

    uint8_t *pattern = malloc(g_total);
    if (pattern == NULL) {
        fprintf(stderr, "FAIL: malloc(%llu)\n", (unsigned long long)g_total);
        return 1;
    }
    for (size_t i = 0; i < g_total; i++)
        pattern[i] = (uint8_t)((i * 7u + 13u) & 0xffu);

    ns_init(&g_ns, CLIENT_IP, SERVER_IP, 1500);
    ns_set_outer(&g_ns, (const uint8_t[8]){0}, (const uint8_t[8]){0});

    g_conn = ns_connect(&g_ns, CLIENT_PORT, SERVER_IP, SERVER_PORT);
    if (g_conn < 0) {
        fprintf(stderr, "FAIL: ns_connect\n");
        free(pattern);
        return 1;
    }

    size_t sent = 0, received = 0;
    int upload_done = 0, fin_sent = 0;
    uint64_t t0 = now_ms();
    /* scale the deadline with the payload: the in-process echo of hundreds
     * of MB is slow (single event loop), and a fixed 15s would abort it. */
    uint64_t deadline = now_ms() + 15000 + g_total / 50000;

    while (now_ms() < deadline) {
        /* 1. drain bridge tx -> fake peer */
        const TxItem *it;
        while ((it = ns_tx_peek(&g_ns)) != NULL) {
            const uint8_t *buf = ns_tx_item_buf(it);
            size_t len = ns_tx_item_len(it);
            peer_feed(buf + 8, len - 8);
            ns_tx_pop(&g_ns);
        }

        TcpConn *c = ns_conn(&g_ns, g_conn);
        int established = c && c->state == NS_ESTABLISHED;

        /* 2. upload the pattern in reservev+commit chunks (the readv path) */
        if (established && !upload_done) {
            struct iovec iov[4];
            int nv = ns_send_reservev(&g_ns, g_conn, iov, 4);
            if (nv > 0) {
                size_t took = 0, want = g_total - sent;
                for (int k = 0; k < nv && took < want; k++) {
                    size_t take = want - took < iov[k].iov_len
                                      ? want - took : iov[k].iov_len;
                    memcpy(iov[k].iov_base, pattern + sent + took, take);
                    ns_send_commit(&g_ns, g_conn, take);
                    took += take;
                }
                sent += took;
            }
            if (sent >= g_total)
                upload_done = 1;
        }

        /* 3. drain rxq (downlink echo); verify in-order integrity (skipped in
         * bench mode, which only measures raw throughput) */
        if (c) {
            while (c->rxq.len > 0) {
                if (!g_bench &&
                    (received + c->rxq.len > g_total ||
                     memcmp(c->rxq.data, pattern + received, c->rxq.len) != 0)) {
                    size_t off = 0;
                    while (off < c->rxq.len &&
                           received + off < g_total &&
                           c->rxq.data[off] == pattern[received + off])
                        off++;
                    fprintf(stderr,
                            "FAIL: echo mismatch at offset %llu (rxq=%llu): "
                            "got %02x want %02x\n",
                            (unsigned long long)(received + off),
                            (unsigned long long)c->rxq.len,
                            off < c->rxq.len ? c->rxq.data[off] : 0,
                            received + off < g_total
                                ? pattern[received + off] : 0);
                    free(pattern);
                    return 1;
                }
                received += c->rxq.len;
                buf_clear(&c->rxq);
            }
        }

        /* 4. half-close once the upload is fully committed (mirrors the real
         * flow: the local client EOFs after writing; the FIN may race the
         * last echo segments still in flight, which the bridge must keep
         * receiving). */
        if (upload_done && !fin_sent) {
            ns_close(&g_ns, g_conn);
            fin_sent = 1;
        }

        /* 5. tick (drives tcp_recved reconciliation + lwIP timers) */
        ns_tick(&g_ns, now_ms());

        if (fin_sent && c && c->state == NS_CLOSED)
            break;
    }

    if (received != g_total) {
        fprintf(stderr, "FAIL: received %llu / %llu bytes (sent=%llu)\n",
                (unsigned long long)received, (unsigned long long)g_total,
                (unsigned long long)sent);
        free(pattern);
        return 1;
    }
    if (g_bench) {
        uint64_t dt = now_ms() - t0;
        double mbps = dt ? (double)received / (double)dt / 1000.0 : 0.0;
        printf("BENCH: %llu bytes in %llu ms = %.1f MB/s\n",
               (unsigned long long)received, (unsigned long long)dt, mbps);
    } else {
        printf("PASS: echoed %llu bytes\n", (unsigned long long)received);
    }
    free(pattern);
    return 0;
}
