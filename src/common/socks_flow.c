#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "common.h"
#include "netstack.h"
#include "protocol.h"
#include "socks_internal.h"
#include "util.h"

#define LOCAL_WRITE_LIMIT 262144
#define CONNECT_TIMEOUT 30000u          /* ms */
#define TCP_RX_CHUNK     16384
#define TCP_TX_CHUNK     8192

uint64_t g_next_id = 1;
int g_flow_len;         /* active count */

/* ---- DNS result queue ---- */
static pthread_mutex_t g_dns_mu = PTHREAD_MUTEX_INITIALIZER;
static DnsResult g_dns_q[64];
static int g_dns_hd, g_dns_tl; /* ring */

uint64_t now_mono(void) {
    return now_ms();
}

void dns_push(int flow_id, bool ok, uint32_t ip, uint16_t port) {
    pthread_mutex_lock(&g_dns_mu);
    g_dns_q[g_dns_tl].flow_id = flow_id;
    g_dns_q[g_dns_tl].ok = ok;
    g_dns_q[g_dns_tl].ip = ip;
    g_dns_q[g_dns_tl].port = port;
    g_dns_tl = (g_dns_tl + 1) % 64;
    if (g_dns_tl == g_dns_hd)
        g_dns_hd = (g_dns_hd + 1) % 64; /* drop oldest */
    pthread_mutex_unlock(&g_dns_mu);
}

int dns_drain(DnsResult *out, int max) {
    int n = 0;
    pthread_mutex_lock(&g_dns_mu);
    while (g_dns_hd != g_dns_tl && n < max) {
        out[n++] = g_dns_q[g_dns_hd];
        g_dns_hd = (g_dns_hd + 1) % 64;
    }
    pthread_mutex_unlock(&g_dns_mu);
    return n;
}

typedef struct {
    int      flow_id;
    uint16_t port;
    char    *domain;
} DnsJob;

static void *dns_worker(void *arg) {
    DnsJob *j = (DnsJob *)arg;
    uint32_t ip = dns_query_a(j->domain);
    dns_push(j->flow_id, ip != 0, ip, j->port);
    if (g_dns_evfd >= 0) {
        uint64_t one = 1;
        ssize_t w = write(g_dns_evfd, &one, sizeof one);   /* wake loop */
        (void)w;
    }
    free(j->domain);
    free(j);
    return NULL;
}

/* spawn detached thread resolving `domain` then pushing a result for flow id. */
void spawn_dns(int flow_id, const char *domain, uint16_t port) {
    pthread_t th;
    DnsJob *j = malloc(sizeof *j);
    if (!j) {
        dns_push(flow_id, false, 0, port);
        return;
    }
    j->flow_id = flow_id;
    j->port = port;
    j->domain = xstrdup(domain);
    if (pthread_create(&th, NULL, dns_worker, j) != 0) {
        free(j->domain);
        free(j);
        dns_push(flow_id, false, 0, port);
        return;
    }
    pthread_detach(th);
}

void queue_flow_output(Flow *f, const uint8_t *data, size_t n) {
    buf_put(&f->output, data, n);
}

void queue_socks_error(Flow *f, uint8_t rep) {
    uint8_t r[10] = {5, rep, 0, 1, 0, 0, 0, 0, 0, 0};
    queue_flow_output(f, r, sizeof r);
    f->state = ST_CLOSING;
}

void set_flow_state(Flow *f, FlowState st) {
    f->state = st;
    f->state_ms = now_mono();
}

Flow *flow_alloc(struct sockaddr_in *peer) {
    Flow *f = NULL;
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (!g_flows[i].active) {
            f = &g_flows[i];
            break;
        }
    }
    if (!f)
        return NULL;
    memset(f, 0, sizeof *f);
    f->active = 1;
    f->id = g_next_id++;
    f->ns_idx = -1;
    f->state = ST_GREETING;
    f->state_ms = now_mono();
    if (debug_enabled()) {
        char peer_s[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &peer->sin_addr, peer_s, sizeof peer_s);
        log_debug("[flow %lu] local client %s:%u", (unsigned long)f->id,
                  peer_s, ntohs(peer->sin_port));
    }
    g_flow_len++;
    return f;
}

void flow_free(Flow *f) {
    if (f->fd >= 0) {
        close(f->fd);
        f->fd = -1;
    }
    if (f->ns_idx >= 0)
        ns_abort(&g_ns, f->ns_idx);
    buf_free(&f->input);
    buf_free(&f->output);
    f->active = 0;
    f->ns_idx = -1;
    g_flow_len--;
    if (debug_enabled())
        log_debug("[flow %lu] closed", (unsigned long)f->id);
}

/* ---- port allocation ---- */
#define PORT_BASE 49152u
#define PORT_TOP  65535u

static unsigned next_port = PORT_BASE;

static uint16_t alloc_port(void) {
    for (int tries = 0; tries < 2048; tries++) {
        uint16_t p = (uint16_t)next_port;
        next_port++;
        if (next_port > PORT_TOP)
            next_port = PORT_BASE;
        int used = 0;
        for (int i = 0; i < MAX_FLOWS; i++) {
            if (g_flows[i].active && g_flows[i].ns_idx >= 0 &&
                g_flows[i].lport == p) {
                used = 1;
                break;
            }
        }
        if (!used)
            return p;
    }
    return 0;
}

void open_tcp_connection(Flow *f, uint32_t rip, uint16_t rport) {
    uint16_t lport = alloc_port();
    if (lport == 0) {
        queue_socks_error(f, 1);
        return;
    }
    int idx = ns_connect(&g_ns, lport, rip, rport);
    if (idx < 0) {
        queue_socks_error(f, 1);
        return;
    }
    f->ns_idx = idx;
    f->lport = lport;
    set_flow_state(f, ST_CONNECTING);
    if (debug_enabled()) {
        uint8_t b[4];
        u32_ip4(rip, b);
        log_debug("[flow %lu] %d.%d.%d.%d:%u -> %d.%d.%d.%d:%u",
                  (unsigned long)f->id, (g_ns.ip >> 24) & 0xff,
                  (g_ns.ip >> 16) & 0xff, (g_ns.ip >> 8) & 0xff,
                  g_ns.ip & 0xff, lport, b[0], b[1], b[2], b[3], rport);
    }
}

void process_socks_handshake(Flow *f) {
    if (f->state == ST_GREETING) {
        if (f->input.len < 2)
            return;
        size_t nmethods = f->input.data[1];
        if (f->input.len < 2 + nmethods)
            return;
        int has0 = 0;
        for (size_t i = 0; i < nmethods; i++) {
            if (f->input.data[2 + i] == 0)
                has0 = 1;
        }
        if (f->input.data[0] != 5 || !has0) {
            uint8_t r[2] = {5, 0xff};
            queue_flow_output(f, r, 2);
            set_flow_state(f, ST_CLOSING);
            return;
        }
        buf_consume(&f->input, 2 + nmethods);
        uint8_t ok[2] = {5, 0};
        queue_flow_output(f, ok, 2);
        set_flow_state(f, ST_REQUEST);
    }

    if (f->state != ST_REQUEST || f->input.len < 4)
        return;
    if (f->input.data[0] != 5 || f->input.data[1] != 1) {
        queue_socks_error(f, 7);
        return;
    }
    uint8_t atyp = f->input.data[3];
    switch (atyp) {
    case 1: { /* IPv4 */
        if (f->input.len < 10)
            return;
        uint32_t rip =
            ((uint32_t)f->input.data[4] << 24) |
            ((uint32_t)f->input.data[5] << 16) |
            ((uint32_t)f->input.data[6] << 8) | f->input.data[7];
        uint16_t rport = (uint16_t)((f->input.data[8] << 8) | f->input.data[9]);
        buf_consume(&f->input, 10);
        open_tcp_connection(f, rip, rport);
        return;
    }
    case 3: { /* domain */
        if (f->input.len < 5)
            return;
        size_t dlen = f->input.data[4];
        size_t req_len = 5 + dlen + 2;
        if (dlen == 0 || f->input.len < req_len)
            return;
        char domain[256];
        size_t n = dlen;
        if (n > sizeof domain - 1)
            n = sizeof domain - 1;
        memcpy(domain, f->input.data + 5, n);
        domain[n] = 0;
        uint16_t rport = (uint16_t)((f->input.data[5 + dlen] << 8) |
                                    f->input.data[6 + dlen]);
        buf_consume(&f->input, req_len);
        f->req_port = rport;
        set_flow_state(f, ST_RESOLVING);
        spawn_dns((int)f->id, domain, rport);
        return;
    }
    default:
        queue_socks_error(f, 8);
        return;
    }
}

void handle_dns_results(void) {
    DnsResult q[16];
    int n = dns_drain(q, 16);
    for (int k = 0; k < n; k++) {
        for (int i = 0; i < MAX_FLOWS; i++) {
            Flow *f = &g_flows[i];
            if (!f->active || f->state != ST_RESOLVING)
                continue;
            if ((uint64_t)q[k].flow_id != f->id)
                continue;
            if (q[k].ok) {
                if (debug_enabled())
                    log_debug("[flow %lu] DNS -> %d.%d.%d.%d",
                              (unsigned long)f->id, (q[k].ip >> 24) & 0xff,
                              (q[k].ip >> 16) & 0xff, (q[k].ip >> 8) & 0xff,
                              q[k].ip & 0xff);
                open_tcp_connection(f, q[k].ip, q[k].port);
            } else {
                log_err("[flow %lu] DNS failed via %s", (unsigned long)f->id,
                        DNS_SERVER_IP);
                queue_socks_error(f, 4);
            }
            break;
        }
    }
}

/* ms until the earliest ST_CONNECTING flow times out, INT64_MAX if none */
int64_t next_conn_timeout_ms(void)
{
    int64_t d = INT64_MAX;
    uint64_t now = now_ms();
    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &g_flows[i];
        if (f->active && f->state == ST_CONNECTING) {
            int64_t dd = (int64_t)(f->state_ms + CONNECT_TIMEOUT - now);
            if (dd < d)
                d = dd;
        }
    }
    return d;
}

void update_tcp_states(void) {
    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &g_flows[i];
        if (!f->active || f->state != ST_CONNECTING)
            continue;
        TcpConn *c = ns_conn(&g_ns, f->ns_idx);
        NsState st = c ? c->state : NS_CLOSED;
        if (st == NS_ESTABLISHED) {
            uint8_t reply[10] = {5, 0, 0, 1,
                                 (uint8_t)((g_ns.ip >> 24) & 0xff),
                                 (uint8_t)((g_ns.ip >> 16) & 0xff),
                                 (uint8_t)((g_ns.ip >> 8) & 0xff),
                                 (uint8_t)(g_ns.ip & 0xff),
                                 (uint8_t)(f->lport >> 8),
                                 (uint8_t)(f->lport & 0xff)};
            queue_flow_output(f, reply, sizeof reply);
            set_flow_state(f, ST_ESTABLISHED);
            if (debug_enabled())
                log_debug("[flow %lu] TCP established", (unsigned long)f->id);
        } else if (st == NS_CLOSED) {
            if (debug_enabled())
                log_debug("[flow %lu] TCP connect failed", (unsigned long)f->id);
            queue_socks_error(f, 5);
        } else if (now_mono() - f->state_ms >= CONNECT_TIMEOUT) {
            if (debug_enabled())
                log_debug("[flow %lu] TCP connect timed out",
                          (unsigned long)f->id);
            ns_abort(&g_ns, f->ns_idx);
            queue_socks_error(f, 4);
        }
    }
}

void service_local_inputs(Flow *fs) {
    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &fs[i];
        if (!f->active || f->local_eof)
            continue;
        if (f->ns_idx >= 0 && f->state == ST_ESTABLISHED && f->input.len > 0) {
            /* spill leftover input into the stack's pending segment slot */
            size_t room = 0;
            uint8_t *dst = ns_send_reserve(&g_ns, f->ns_idx, &room);
            if (dst && room > 0) {
                size_t n = f->input.len > room ? room : f->input.len;
                memcpy(dst, f->input.data, n);
                ns_send_commit(&g_ns, f->ns_idx, n);
                buf_consume(&f->input, n);
            }
            if (f->input.len > 0)
                continue;
        }

        if (f->ns_idx >= 0 && f->state == ST_ESTABLISHED) {
            /* zero-copy feed: one readv() fills up to 4 pending segment
             * slots (reserve never commits, so the slot pointers stay
             * stable across the batch) */
            for (;;) {
                struct iovec iov[4];
                int nv = ns_send_reservev(&g_ns, f->ns_idx, iov, 4);
                if (nv == 0)
                    break;             /* stack full: backpressure */
                ssize_t r2 = readv(f->fd, iov, nv);
                if (r2 > 0) {
                    size_t left = (size_t)r2;
                    for (int k = 0; k < nv && left > 0; k++) {
                        size_t take = left < iov[k].iov_len ? left
                                                             : iov[k].iov_len;
                        ns_send_commit(&g_ns, f->ns_idx, take);
                        left -= take;
                    }
                } else if (r2 == 0) {
                    f->local_eof = true;
                    ns_close(&g_ns, f->ns_idx);
                    set_flow_state(f, ST_CLOSING);
                    break;
                } else {
                    break;             /* EAGAIN or error */
                }
            }
        } else {
            /* greeting/request: read into rbuf for the handshake parser */
            uint8_t rbuf[16 * 1024];
            ssize_t n = read(f->fd, rbuf, sizeof rbuf);
            if (n == 0) {
                /* client gone before the handshake finished: close the
                 * flow so reap_flows collects it (previously the slot
                 * and fd leaked forever and poll busy-spun on the EOF) */
                f->local_eof = true;
                set_flow_state(f, ST_CLOSING);
            } else if (n > 0) {
                buf_put(&f->input, rbuf, (size_t)n);
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                f->local_eof = true;
                if (f->ns_idx >= 0) {
                    ns_abort(&g_ns, f->ns_idx);
                    set_flow_state(f, ST_CLOSING);
                }
            }
            /* run the parser whenever bytes are buffered, not only after
             * a fresh read: a client that sends greeting+CONNECT in one
             * write (or one segment) leaves CONNECT stranded in input
             * otherwise and the handshake stalls forever */
            if (f->input.len > 0)
                process_socks_handshake(f);
        }
    }
}

void service_local_outputs(void) {
    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &g_flows[i];
        if (!f->active)
            continue;

        while (f->output.len > 0) {
            ssize_t n = write(f->fd, f->output.data, f->output.len);
            if (n > 0) {
                buf_consume(&f->output, (size_t)n);
            } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            } else {
                f->local_eof = true;
                if (f->ns_idx >= 0)
                    ns_abort(&g_ns, f->ns_idx);
                buf_clear(&f->output);
                set_flow_state(f, ST_CLOSING);
                break;
            }
        }

        if (f->ns_idx >= 0 && f->output.len == 0) {
            TcpConn *c = ns_conn(&g_ns, f->ns_idx);
            if (c && c->rxq.len > 0) {
                size_t want = c->rxq.len > LOCAL_WRITE_LIMIT
                                  ? LOCAL_WRITE_LIMIT
                                  : c->rxq.len;
                struct iovec io = { .iov_base = c->rxq.data,
                                    .iov_len = want };
                ssize_t n = writev(f->fd, &io, 1);
                if (n > 0) {
                    buf_consume(&c->rxq, (size_t)n);
                } else if (n < 0 && errno != EAGAIN &&
                           errno != EWOULDBLOCK) {
                    f->local_eof = true;
                    ns_abort(&g_ns, f->ns_idx);
                    set_flow_state(f, ST_CLOSING);
                    continue;
                }
            }
        }

        if (f->ns_idx >= 0) {
            TcpConn *c = ns_conn(&g_ns, f->ns_idx);
            if (c && c->state == NS_CLOSE_WAIT && c->rxq.len == 0 &&
                f->output.len == 0) {
                shutdown(f->fd, SHUT_WR);
                ns_close(&g_ns, f->ns_idx);
                set_flow_state(f, ST_CLOSING);
            }
        }
    }
}

void reap_flows(void) {
    for (int i = 0; i < MAX_FLOWS; i++) {
        Flow *f = &g_flows[i];
        if (!f->active)
            continue;
        int removable;
        if (f->ns_idx >= 0) {
            TcpConn *c = ns_conn(&g_ns, f->ns_idx);
            removable = c && c->state == NS_CLOSED && f->output.len == 0;
        } else {
            removable = f->state == ST_CLOSING && f->output.len == 0;
        }
        if (removable)
            flow_free(f);
    }
}
