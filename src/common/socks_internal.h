#ifndef IWAN_SOCKS_INTERNAL_H
#define IWAN_SOCKS_INTERNAL_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* struct sockaddr_in comes from common.h -> port.h (netinet/in.h on
 * POSIX, winsock2 on Windows) */
#ifndef _WIN32
#include <netinet/in.h>
#endif

#include "common.h"
#include "netstack.h"
#include "socks.h"

#define MAX_FLOWS       256

/* ---- tunnel DNS (socks_flow.c) ---- */
#define DNS_RESULT_Q_LEN 64     /* DNS result ring size (dns_push/dns_drain) */
#define DNS_DRAIN_MAX    16     /* results handled per event-loop round */
#define DNS_WAIT_MAX     16     /* concurrent pending queries */
#define DNS_POLL_MS      250u   /* worker retry/poll interval */
#define DNS_TIMEOUT_MS   1500u  /* query lifetime (registration + 6 x 250ms) */

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
    uint32_t peer_ip;          /* client IPv4, network byte order (sin_addr.s_addr) */
    uint16_t peer_port;        /* client port, host order */
    FlowState state;
    buf_t    input;
    buf_t    output;
    int      ns_idx;           /* -1 = none */
    uint16_t lport;
    bool     local_eof;
    uint64_t state_ms;         /* when state last changed */
    bool     auth_pending;     /* RFC1929 auth sub-negotiation in progress */
    bool     http_mode;        /* client speaks HTTP proxy, not SOCKS5 */
    bool     http_connect;     /* HTTP mode: CONNECT tunnel (else absolute-URI
                                * forwarding: the whole request is tunneled) */
    bool     rx_paused;        /* uplink backpressure: netstack ring full,
                                * stop registering POLLIN until the next
                                * tick (wait_events reads this) */
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
extern Flow *g_flows;          /* fixed MAX_FLOWS array, never NULL-terminated */
extern uint64_t g_next_id;
extern int g_dns_evfd;         /* -1 = disabled; written by DNS workers */
extern int g_sockfd;           /* session UDP socket; set by run_socks, used by tunnel DNS */
extern SocksConfig *g_socks_cfg; /* SOCKS5 config (auth_token/allow_remote); set by run_socks */
extern int g_flow_len;         /* active count */
extern atomic_bool g_stop;     /* shared stop flag (util.h): SIGINT/SIGTERM */

/* ---- server lifecycle / event loop / VPN framing (socks.c) ---- */
void on_sig(int sig);
void wait_events(int listener, int sockfd, int dns_evfd, int timeout_ms);
void accept_connections(int listener);
void send_vpn_keepalive(int sockfd, const SocksConfig *cfg,
                        uint64_t *last_ka);
int  receive_vpn(int sockfd, SocksConfig *cfg);

/* ---- flow lifecycle / SOCKS5 handshake / DNS / port alloc / I/O (socks_flow.c) ---- */
void dns_push(int flow_id, bool ok, uint32_t ip, uint16_t port);
int  dns_drain(DnsResult *out, int max);
void spawn_dns(int flow_id, const char *domain, uint16_t port);
void dns_set_server(const char *ip);   /* tunnel DNS resolver (run_socks) */
bool dns_try_handle_response(const uint8_t *pkt, size_t n); /* consume inner DNS replies */
/* DNS worker lifecycle (run_socks): dns_reset() clears state left by a
 * previous session and retires stale workers; dns_stop() makes in-flight
 * workers stop sending before the session socket is closed. */
void dns_reset(void);
void dns_stop(void);
void queue_flow_output(Flow *f, const uint8_t *data, size_t n);
void queue_socks_error(Flow *f, uint8_t rep);
void set_flow_state(Flow *f, FlowState st);
Flow *flow_alloc(struct sockaddr_in *peer);
void flow_free(Flow *f);
void open_tcp_connection(Flow *f, uint32_t rip, uint16_t rport);
void process_socks_handshake(Flow *f);
/* brute-force auth lockout (socks_flow.c): note a wrong-password
 * failure (success=false) or a successful auth (success=true, clears
 * the source's counter); auth_fail_blocked() decides accept-time drops */
void auth_fail_note(uint32_t ip, bool success);
bool auth_fail_blocked(uint32_t ip);
void handle_dns_results(void);
void update_tcp_states(void);
int64_t next_conn_timeout_ms(void);
void service_local_inputs(Flow *fs);
void service_local_outputs(void);
void reap_flows(void);

#endif
