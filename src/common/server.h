#ifndef IWAN_SERVER_H
#define IWAN_SERVER_H

#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

#define SERVER_MAX_SESSIONS 256
#define SERVER_MAX_USERS    256
#define SERVER_USER_MAX     63

/* One authenticated client. Sessions are shared between the UDP main
 * thread (writes) and TUN reader threads (downlink lookups); every
 * mutation happens under ctx->sess_lock, readers take a snapshot under
 * the read lock. last_active_ms is atomic and updated lock-free. */
struct server_session {
    bool valid;
    uint16_t sid;
    uint32_t token;
    struct sockaddr_in peer;
    uint8_t ip[4];
    uint8_t xor_key[8];      /* session_key(user,pass)[0..7] */
    uint8_t enc;
    atomic_uint_fast64_t last_active_ms; /* monotonic ms */
    char user[SERVER_USER_MAX + 1]; /* owning account; one slot per user */
};

/* Snapshot of a session taken under the read lock; the only fields a
 * downlink thread needs to build and send a packet without holding the
 * lock during sendto(). */
struct server_sess_snap {
    struct sockaddr_in peer;
    uint8_t xor_key[8];
    uint16_t sid;
    uint32_t token;
    uint8_t enc;
};

/* Global server state, owned by main(). */
struct server_ctx {
    struct server_session sess[SERVER_MAX_SESSIONS];
    pthread_rwlock_t sess_lock;  /* guards sess[] (see above) */
    /* O(1) sid -> slot index (M-8); -1 = no live session with that sid.
     * A session's sid is unique: sid = low 16 bits of its assigned IP
     * (see handle_open), so the map is exact.  All writes happen under
     * the WRITE lock (handle_open/sess_wipe); readers take a snapshot
     * under the read lock and never mutate the map (a heal write would
     * race concurrent readers). The sess[] scan stays authoritative as a
     * read-side fallback. */
    int16_t sid_map[65536];
    uint8_t server_ip[4], dns[4];
    uint32_t next_ip;        /* BE u32; next client IP to hand out */
    uint32_t ip_base;        /* BE u32; first usable host address */
    uint32_t ip_end;         /* BE u32; last usable host address (pre-broadcast) */
    char tun_name[IFNAMSIZ];
    int tun_fd;              /* -1 when running in --no-tun mode */
    void *qpool;             /* struct tun_pool *, owned by main() */
};

/* One "user:pass" line from the users file. */
struct server_user {
    char name[SERVER_USER_MAX + 1];
    char pass[SERVER_USER_MAX + 1];
};

/* Initialize/destroy the session-table lock. */
void server_ctx_init(struct server_ctx *ctx);
void server_ctx_destroy(struct server_ctx *ctx);

/* Multithread-safe printf (server log lines). */
void srv_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Handle one UDP packet from peer. May write decrypted data to the TUN
 * (only when ctx->tun_fd >= 0, else dropped). Called from the main
 * thread only. */
void handle_udp(struct server_ctx *ctx, const struct server_user *users, int nusers,
                const uint8_t *raw, size_t len,
                const struct sockaddr_in *peer, int sockfd);

/* Send one IP packet from the TUN to the session owning dst IP.
 * Thread-safe: called from TUN reader threads. Takes a session snapshot
 * under the read lock and sends without holding the lock. */
void handle_tun_downlink(struct server_ctx *ctx, const uint8_t *ip_pkt, size_t len,
                         int tun_fd, int sockfd);

/* Drop sessions idle for more than 120s; log each. Main thread only. */
void purge_expired(struct server_ctx *ctx, uint64_t now_ms);

/* Cumulative UDP send failures (nonblocking socket: EAGAIN drops). */
uint64_t server_send_drops(void);

/* Cumulative UDP datagrams sent to clients (includes control frames
 * such as OPEN_ACK/PING_RSP, not only tunnel data). */
uint64_t server_dl_pkts(void);

/* IWAN_DEBUG=1: print per-step uplink timing averages once per second. */
void server_up_stats_print(void);

#endif
