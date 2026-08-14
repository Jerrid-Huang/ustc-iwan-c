/*
 * Root-free multi-connection fairness test for the lwIP bridge.
 *
 * The single-conn data harness cannot expose the device-queue starvation that
 * the per-conn fair-share gate (NS_TX_CONN_CAP) fixes: with N concurrent
 * uploads, one conn's lwIP output can fill the 128-slot tx queue and
 * RTO-starve the rest (the real bench showed conn0 at ~1156 Mbit/s and conns
 * 1..7 at 2-22 Mbit/s). This harness runs IWAN_TEST_CONNS (default 8)
 * simultaneous uploads through an in-process fake TCP peer and asserts every
 * conn completes its quota, reporting the min/max spread.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "ipv4.h"
#include "protocol.h"
#include "tcpstack.h"
#include "util.h"

#define CLIENT_IP   0xC6120002u
#define SERVER_IP   0xC6120001u
#define SERVER_PORT 12345
#define CLIENT_PORT 40000
#define MAX_CONNS   16
#define PER_CONN     (1 << 20)   /* 1 MiB per conn */

static Netstack g_ns;
static int g_conns[MAX_CONNS];
static int g_nconns;

typedef struct {
    uint16_t lport;
    uint32_t client_seq;   /* next seq expected from the client */
    uint32_t server_seq;   /* next seq the peer sends */
    int      used;
} Peer;
static Peer g_peers[MAX_CONNS];

static Peer *peer_lookup(uint16_t sport)
{
    for (int i = 0; i < g_nconns; i++)
        if (g_peers[i].used && g_peers[i].lport == sport)
            return &g_peers[i];
    for (int i = 0; i < g_nconns; i++)
        if (!g_peers[i].used) {
            g_peers[i].used = 1;
            g_peers[i].lport = sport;
            return &g_peers[i];
        }
    return NULL;
}

static void peer_send(const Peer *pp, uint32_t seq, uint32_t ack, uint8_t flags,
                      const uint8_t *payload, size_t paylen, uint16_t mss_opt,
                      uint8_t wscale)
{
    uint8_t out[2048];
    size_t optlen = (mss_opt ? 4 : 0) + (wscale ? 4 : 0);
    size_t thlen = 20 + optlen;
    size_t tot = 20 + thlen + paylen;
    memset(out, 0, 20);
    out[0] = 0x45;
    out[2] = (uint8_t)(tot >> 8);
    out[3] = (uint8_t)tot;
    out[8] = 64;
    out[9] = 6;
    u32_ip4(SERVER_IP, out + 12);
    u32_ip4(CLIENT_IP, out + 16);
    uint16_t ipc = ip_csum_fold(ip_csum_accum(0, out, 20));
    out[10] = (uint8_t)(ipc >> 8);
    out[11] = (uint8_t)ipc;

    uint8_t *t = out + 20;
    memset(t, 0, thlen);
    t[0] = (uint8_t)(SERVER_PORT >> 8); t[1] = (uint8_t)SERVER_PORT;
    t[2] = (uint8_t)(pp->lport >> 8); t[3] = (uint8_t)pp->lport;
    t[4] = (uint8_t)(seq >> 24); t[5] = (uint8_t)(seq >> 16);
    t[6] = (uint8_t)(seq >> 8);  t[7] = (uint8_t)seq;
    t[8] = (uint8_t)(ack >> 24); t[9] = (uint8_t)(ack >> 16);
    t[10] = (uint8_t)(ack >> 8); t[11] = (uint8_t)ack;
    t[12] = (uint8_t)((thlen / 4) << 4);
    t[13] = flags;
    t[14] = 0xff; t[15] = 0xff;
    if (mss_opt) {
        t[20] = 2; t[21] = 4;
        t[22] = (uint8_t)(mss_opt >> 8); t[23] = (uint8_t)mss_opt;
    }
    if (wscale) {
        size_t o = mss_opt ? 24 : 20;
        t[o] = 3; t[o + 1] = 3; t[o + 2] = wscale; t[o + 3] = 1;
    }
    if (payload && paylen)
        memcpy(t + thlen, payload, paylen);
    uint16_t tc = ip_tcp_csum(SERVER_IP, CLIENT_IP, t, thlen + paylen);
    t[16] = (uint8_t)(tc >> 8);
    t[17] = (uint8_t)tc;
    ns_rx_packet(&g_ns, out, tot);
}

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

    Peer *pp = peer_lookup(sport);
    if (pp == NULL)
        return;

    if (flags & 0x02) {          /* SYN */
        pp->client_seq = seq + 1;
        pp->server_seq = 0x12345678u + 1;
        peer_send(pp, 0x12345678u, pp->client_seq, 0x12, NULL, 0, 1460, 4);
        return;
    }
    uint32_t data_end = seq + (uint32_t)paylen;
    if (paylen > 0) {            /* data: echo */
        pp->client_seq = data_end;
        peer_send(pp, pp->server_seq, pp->client_seq, 0x18, payload, paylen,
                  0, 0);
        pp->server_seq += (uint32_t)paylen;
    }
    if (flags & 0x01) {          /* FIN */
        pp->client_seq = data_end + 1;
        peer_send(pp, pp->server_seq, pp->client_seq, 0x11, NULL, 0, 0, 0);
        pp->server_seq++;
    }
}

int main(void)
{
    g_nconns = 8;
    if (getenv("IWAN_TEST_CONNS")) {
        int v = atoi(getenv("IWAN_TEST_CONNS"));
        if (v >= 1 && v <= MAX_CONNS)
            g_nconns = v;
    }

    ns_init(&g_ns, CLIENT_IP, SERVER_IP, 1500);
    ns_set_outer(&g_ns, (const uint8_t[8]){0}, (const uint8_t[8]){0});

    for (int i = 0; i < g_nconns; i++) {
        g_conns[i] = ns_connect(&g_ns, (uint16_t)(CLIENT_PORT + i),
                                SERVER_IP, SERVER_PORT);
        if (g_conns[i] < 0) {
            fprintf(stderr, "FAIL: ns_connect[%d]\n", i);
            return 1;
        }
    }

    static uint8_t pattern[PER_CONN];
    for (size_t i = 0; i < sizeof pattern; i++)
        pattern[i] = (uint8_t)((i * 7u + 13u) & 0xffu);

    size_t sent[MAX_CONNS] = {0}, recv[MAX_CONNS] = {0};
    int done[MAX_CONNS] = {0};
    uint64_t deadline = now_ms() + 20000;

    while (now_ms() < deadline) {
        /* drain tx -> peer */
        const TxItem *it;
        while ((it = ns_tx_peek(&g_ns)) != NULL) {
            const uint8_t *buf = ns_tx_item_buf(it);
            size_t len = ns_tx_item_len(it);
            peer_feed(buf + 8, len - 8);
            ns_tx_pop(&g_ns);
        }

        int all_done = 1;
        for (int i = 0; i < g_nconns; i++) {
            if (done[i])
                continue;
            TcpConn *c = ns_conn(&g_ns, g_conns[i]);
            int est = c && c->state == NS_ESTABLISHED;
            /* upload */
            if (est && sent[i] < PER_CONN) {
                struct iovec iov[4];
                int nv = ns_send_reservev(&g_ns, g_conns[i], iov, 4);
                if (nv > 0) {
                    size_t took = 0, want = PER_CONN - sent[i];
                    for (int k = 0; k < nv && took < want; k++) {
                        size_t take = want - took < iov[k].iov_len
                                          ? want - took : iov[k].iov_len;
                        memcpy(iov[k].iov_base,
                               pattern + ((sent[i] + took) % PER_CONN), take);
                        ns_send_commit(&g_ns, g_conns[i], take);
                        took += take;
                    }
                    sent[i] += took;
                }
            }
            /* drain rxq */
            if (c)
                while (c->rxq.len > 0) {
                    recv[i] += c->rxq.len;
                    buf_clear(&c->rxq);
                }
            if (sent[i] >= PER_CONN && !done[i] && c &&
                c->state != NS_CLOSED && c->state != NS_FIN_WAIT) {
                ns_close(&g_ns, g_conns[i]);
            }
            if (recv[i] >= PER_CONN)
                done[i] = 1;
            if (!done[i])
                all_done = 0;
        }

        ns_tick(&g_ns, now_ms());
        if (all_done)
            break;
    }

    size_t mn = (size_t)-1, mx = 0;
    for (int i = 0; i < g_nconns; i++) {
        if (recv[i] < mn)
            mn = recv[i];
        if (recv[i] > mx)
            mx = recv[i];
    }
    fprintf(stderr, "fairness: conns=%d min=%llu max=%llu bytes\n",
            g_nconns, (unsigned long long)mn, (unsigned long long)mx);

    for (int i = 0; i < g_nconns; i++) {
        if (recv[i] != PER_CONN) {
            fprintf(stderr, "FAIL: conn %d received %llu / %d\n", i,
                    (unsigned long long)recv[i], PER_CONN);
            return 1;
        }
    }
    printf("PASS: %d conns x %d bytes, min=%llu max=%llu\n",
           g_nconns, PER_CONN, (unsigned long long)mn, (unsigned long long)mx);
    return 0;
}
