#ifndef IWAN_SERVER_H
#define IWAN_SERVER_H

#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#define SERVER_MAX_SESSIONS 256
#define SERVER_MAX_USERS    256
#define SERVER_USER_MAX     63

/* One authenticated client. All single-threaded; no locks. */
struct server_session {
    bool valid;
    uint16_t sid;
    uint32_t token;
    struct sockaddr_in peer;
    uint8_t ip[4];
    uint8_t xor_key[8];      /* session_key(user,pass)[0..7] */
    uint8_t enc;
    uint64_t last_active_ms; /* monotonic ms */
    char user[SERVER_USER_MAX + 1]; /* owning account; one slot per user */
};

/* Global server state, owned by main(). */
struct server_ctx {
    struct server_session sess[SERVER_MAX_SESSIONS];
    uint8_t server_ip[4], dns[4];
    uint32_t next_ip;        /* BE u32; next client IP to hand out */
    uint32_t ip_base;        /* BE u32; first usable host address */
    uint32_t ip_end;         /* BE u32; last usable host address (pre-broadcast) */
    char tun_name[IFNAMSIZ];
    int tun_fd;              /* -1 when running in --no-tun mode */
};

/* One "user:pass" line from the users file. */
struct server_user {
    char name[SERVER_USER_MAX + 1];
    char pass[SERVER_USER_MAX + 1];
};

/* Handle one UDP packet from peer. May write decrypted data to ctx->tun_fd
 * (only when >= 0, else dropped). Pure logic, no main. */
void handle_udp(struct server_ctx *ctx, const struct server_user *users, int nusers,
                const uint8_t *raw, size_t len,
                const struct sockaddr_in *peer, int sockfd);

/* Send one IP packet from the TUN to the session owning dst IP. */
void handle_tun_downlink(struct server_ctx *ctx, const uint8_t *ip_pkt, size_t len,
                         int tun_fd, int sockfd);

/* Drop sessions idle for more than 120s; log each. */
void purge_expired(struct server_ctx *ctx, uint64_t now_ms);

#endif
