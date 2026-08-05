#ifndef IWAN_SOCKS_INTERNAL_H
#define IWAN_SOCKS_INTERNAL_H

#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

#include "common.h"
#include "netstack.h"
#include "socks.h"

#define MAX_FLOWS       256

/* ---- SOCKS5 client flow state machine ---- */
typedef enum {
    ST_GREETING,
    ST_REQUEST,
    ST_RESOLVING,
    ST_CONNECTING,
    ST_ESTABLISHED,
    ST_CLOSING,
} FlowState;

/* One accepted SOCKS5 client connection and its netstack mapping. */
typedef struct {
    int      active;
    uint64_t id;               /* monotonically increasing flow id */
    int      fd;               /* local client stream */
    FlowState state;
    buf_t    input;
    buf_t    output;
    int      ns_idx;           /* -1 = none */
    uint16_t lport;
    bool     local_eof;
    uint64_t state_ms;         /* when state last changed */
    uint16_t req_port;         /* requested remote port while resolving */
} Flow;

/* Result of an async DNS lookup, queued for the event loop. */
typedef struct {
    int      flow_id;
    bool     ok;
    uint32_t ip;               /* host-order MSB-first */
    uint16_t port;
} DnsResult;

/* ---- shared state between socks.c (server) and socks_flow.c (flows) ---- */
extern Netstack g_ns;
extern Flow *g_flows;          /* NULL-terminated? no: MAX_FLOWS array */
extern uint64_t g_next_id;
extern int g_flow_len;         /* active count */
extern volatile sig_atomic_t g_stop;

/* ---- server lifecycle / event loop / VPN framing (socks.c) ---- */
void on_sig(int sig);
void wait_events(int listener, int sockfd, int timeout_ms);
void accept_connections(int listener);
void send_vpn_keepalive(int sockfd, const SocksConfig *cfg,
                        uint64_t *last_ka);
int  receive_vpn(int sockfd, SocksConfig *cfg);

/* ---- flow lifecycle / SOCKS5 handshake / DNS / port alloc / I/O (socks_flow.c) ---- */
uint64_t now_mono(void);
void dns_push(int flow_id, bool ok, uint32_t ip, uint16_t port);
int  dns_drain(DnsResult *out, int max);
void spawn_dns(int flow_id, const char *domain, uint16_t port);
void queue_flow_output(Flow *f, const uint8_t *data, size_t n);
void queue_socks_error(Flow *f, uint8_t rep);
void set_flow_state(Flow *f, FlowState st);
Flow *flow_alloc(struct sockaddr_in *peer);
void flow_free(Flow *f);
void open_tcp_connection(Flow *f, uint32_t rip, uint16_t rport);
void process_socks_handshake(Flow *f);
void handle_dns_results(void);
void update_tcp_states(void);
void service_local_inputs(Flow *fs);
void service_local_outputs(void);
void reap_flows(void);

#endif
