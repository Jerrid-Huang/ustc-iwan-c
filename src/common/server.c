#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "crypto.h"
#include "protocol.h"
#include "server.h"
#include "tun.h"

#define IDLE_TIMEOUT_MS 120000

static void peer_to_string(const struct sockaddr_in *peer, char out[INET_ADDRSTRLEN + 8])
{
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer->sin_addr, ip, sizeof ip);
    snprintf(out, INET_ADDRSTRLEN + 8, "%s:%u", ip, (unsigned)ntohs(peer->sin_port));
}

static struct server_session *find_session(struct server_ctx *ctx, uint16_t sid)
{
    for (int i = 0; i < SERVER_MAX_SESSIONS; i++)
        if (ctx->sess[i].valid && ctx->sess[i].sid == sid)
            return &ctx->sess[i];
    return NULL;
}

static struct server_session *find_session_by_ip(struct server_ctx *ctx,
                                                 const uint8_t ip[4])
{
    for (int i = 0; i < SERVER_MAX_SESSIONS; i++)
        if (ctx->sess[i].valid && memcmp(ctx->sess[i].ip, ip, 4) == 0)
            return &ctx->sess[i];
    return NULL;
}

static void send_reject(int sockfd, const struct sockaddr_in *peer, const char *msg)
{
    buf_t b;
    buf_init(&b);
    ctrl_hdr(&b, PT_OPEN_REJECT, 0, 0, 0);
    tlv_put(&b, T_ERR_MSG, msg, (uint8_t)strlen(msg));
    sendto(sockfd, b.data, b.len, 0, (const struct sockaddr *)peer, sizeof *peer);
    buf_free(&b);
}

/* 4 random bytes; getrandom(2), /dev/urandom, then clock+pid+address mix. */
static uint32_t random_token(void)
{
    uint32_t tok = 0;
    struct timespec ts;

    if (getrandom(&tok, sizeof tok, 0) == (ssize_t)sizeof tok)
        return tok;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, &tok, sizeof tok);
        close(fd);
        if (n == (ssize_t)sizeof tok)
            return tok;
    }
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)ts.tv_nsec ^ ((uint32_t)getpid() << 16) ^
           (uint32_t)(uintptr_t)&tok;
}

struct open_ctx {
    char user[SERVER_USER_MAX + 1];
    uint8_t ct[16];
    uint16_t mtu;
    uint8_t enc;
    uint32_t nonce;
    bool have_av;
};

static bool open_tlv(uint8_t typ, const uint8_t *val, uint8_t vlen, void *ud)
{
    struct open_ctx *a = ud;

    switch (typ) {
    case T_USERNAME:
        if (vlen > 0) {
            size_t n = vlen < SERVER_USER_MAX ? vlen : SERVER_USER_MAX;
            memcpy(a->user, val, n);
            a->user[n] = '\0';
        } else {
            a->user[0] = '\0';
        }
        break;
    case T_PASSWORD:
        if (vlen >= 16)
            memcpy(a->ct, val, 16);
        break;
    case T_MTU:
        if (vlen >= 2)
            a->mtu = (uint16_t)((val[0] << 8) | val[1]);
        break;
    case T_ENCRYPT:
        if (vlen >= 1)
            a->enc = val[0];
        break;
    case T_AUTH_VERIFY:
        if (vlen == 4) {
            a->nonce = ((uint32_t)val[0] << 24) | ((uint32_t)val[1] << 16) |
                       ((uint32_t)val[2] << 8) | (uint32_t)val[3];
            a->have_av = true;
        }
        break;
    default:
        break;
    }
    return true;
}

static void handle_open(struct server_ctx *ctx, const struct server_user *users,
                        int nusers, const uint8_t *raw, size_t len,
                        const struct sockaddr_in *peer, int sockfd)
{
    struct open_ctx a;
    char peerstr[INET_ADDRSTRLEN + 8];
    const char *pass = NULL;
    uint8_t sk[16], expect[16];
    buf_t b;
    uint8_t nb[4], mb[2];
    uint32_t ipu, tok;
    uint16_t sid, mtu;
    struct server_session *s;
    int slot, i;

    if (len < 24 || !verify_sig(raw, len))
        return;

    memset(&a, 0, sizeof a);
    a.mtu = 1400;
    parse_tlvs(raw + 24, len - 24, open_tlv, &a);

    if (!a.have_av) {
        peer_to_string(peer, peerstr);
        printf("[%s] OPEN reject: missing AV\n", peerstr);
        send_reject(sockfd, peer, "missing AV");
        return;
    }

    for (i = 0; i < nusers; i++) {
        if (strcmp(users[i].name, a.user) == 0) {
            pass = users[i].pass;
            break;
        }
    }
    if (!pass) {
        peer_to_string(peer, peerstr);
        printf("[%s] OPEN reject: unknown user %s\n", peerstr, a.user);
        send_reject(sockfd, peer, "unknown user");
        return;
    }

    encrypt_password(pass, a.user, expect);
    if (memcmp(expect, a.ct, 16) != 0) {
        peer_to_string(peer, peerstr);
        printf("[%s] OPEN reject: bad password for %s\n", peerstr, a.user);
        send_reject(sockfd, peer, "bad password");
        return;
    }

    /* one slot per user: a re-OPEN replaces the user's existing session
     * instead of consuming a fresh slot (prevents account-level table
     * exhaustion); fall back to any free slot */
    slot = -1;
    for (i = 0; i < SERVER_MAX_SESSIONS; i++) {
        if (ctx->sess[i].valid && strcmp(ctx->sess[i].user, a.user) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        for (i = 0; i < SERVER_MAX_SESSIONS; i++) {
            if (!ctx->sess[i].valid) {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0) {
        peer_to_string(peer, peerstr);
        printf("[%s] OPEN reject: server full\n", peerstr);
        send_reject(sockfd, peer, "server full");
        return;
    }

    /* hand out the next host address, wrapping within the subnet's usable
     * range (network+1 .. broadcast-1) instead of running past it */
    ipu = ctx->next_ip;
    if (ipu > ctx->ip_end)
        ipu = ctx->ip_base;
    ctx->next_ip = (ipu == ctx->ip_end) ? ctx->ip_base : ipu + 1;
    sid = (uint16_t)(ipu & 0xFFFF);
    tok = random_token();

    session_key(a.user, pass, sk);

    /* echo the client's nonce verbatim; this repo's client rejects ACKs
     * without a matching T_AUTH_VERIFY */
    nb[0] = (uint8_t)(a.nonce >> 24);
    nb[1] = (uint8_t)(a.nonce >> 16);
    nb[2] = (uint8_t)(a.nonce >> 8);
    nb[3] = (uint8_t)a.nonce;
    mtu = a.mtu < 576 ? 576 : (a.mtu > 1500 ? 1500 : a.mtu);
    mb[0] = (uint8_t)(mtu >> 8);
    mb[1] = (uint8_t)mtu;

    buf_init(&b);
    ctrl_hdr(&b, PT_OPEN_ACK, a.enc, sid, tok);
    tlv_put(&b, T_MTU, mb, sizeof mb);
    {
        uint8_t ipb[4];
        u32_ip4(ipu, ipb);
        tlv_put(&b, T_IP, ipb, 4);
    }
    tlv_put(&b, T_GATEWAY, ctx->server_ip, 4);
    tlv_put(&b, T_DNS, ctx->dns, 4);
    tlv_put(&b, T_ENCRYPT, &a.enc, 1);
    tlv_put(&b, T_AUTH_VERIFY, nb, sizeof nb);
    sendto(sockfd, b.data, b.len, 0, (const struct sockaddr *)peer, sizeof *peer);
    buf_free(&b);

    /* replace any existing session with the same sid */
    for (i = 0; i < SERVER_MAX_SESSIONS; i++)
        if (ctx->sess[i].valid && ctx->sess[i].sid == sid)
            ctx->sess[i].valid = false;

    s = &ctx->sess[slot];
    memset(s, 0, sizeof *s);
    s->valid = true;
    s->sid = sid;
    s->token = tok;
    s->peer = *peer;
    u32_ip4(ipu, s->ip);
    memcpy(s->xor_key, sk, 8);
    s->enc = a.enc;
    s->last_active_ms = now_ms();
    snprintf(s->user, sizeof s->user, "%s", a.user);

    peer_to_string(peer, peerstr);
    printf("[%s] OPEN_ACK -> %s sid=0x%04x ip=%u.%u.%u.%u enc=%u\n",
           peerstr, a.user, sid, s->ip[0], s->ip[1], s->ip[2], s->ip[3], s->enc);
}

void handle_udp(struct server_ctx *ctx, const struct server_user *users, int nusers,
                const uint8_t *raw, size_t len,
                const struct sockaddr_in *peer, int sockfd)
{
    struct server_session *s;
    buf_t b;
    char peerstr[INET_ADDRSTRLEN + 8];
    uint8_t typ;
    uint16_t sid;
    uint32_t tok;

    if (len < 8)
        return;
    typ = raw[0];
    sid = (uint16_t)((raw[2] << 8) | raw[3]);
    tok = ((uint32_t)raw[4] << 24) | ((uint32_t)raw[5] << 16) |
          ((uint32_t)raw[6] << 8) | (uint32_t)raw[7];

    switch (typ) {
    case PT_OPEN:
        handle_open(ctx, users, nusers, raw, len, peer, sockfd);
        break;

    case PT_DATA:
    case PT_DATA_ENC:
        s = find_session(ctx, sid);
        if (!s || s->token != tok)
            return; /* unknown session or bad token: drop */
        if (s->enc) {
            if (typ != PT_DATA_ENC)
                return; /* enc session accepts only encrypted data */
            xor_crypt((uint8_t *)raw + 8, len - 8, s->xor_key, 8);
        } else {
            if (typ != PT_DATA)
                return; /* plain session accepts only plaintext data */
        }
        if (ctx->tun_fd >= 0 && len > 8)
            tun_write(ctx->tun_fd, raw + 8, len - 8);
        s->last_active_ms = now_ms();
        break;

    case PT_CLOSE:
        if (!verify_sig(raw, len))
            return;
        s = find_session(ctx, sid);
        if (s && s->token == tok) {
            peer_to_string(peer, peerstr);
            printf("[%s] session 0x%04x (ip %u.%u.%u.%u) closed\n",
                   peerstr, s->sid, s->ip[0], s->ip[1], s->ip[2], s->ip[3]);
            s->valid = false;
        }
        break;

    case PT_PING_REQ:
        if (!verify_sig(raw, len))
            return;
        s = find_session(ctx, sid);
        if (s && s->token == tok)
            s->last_active_ms = now_ms(); /* keepalive traffic = alive */
        buf_init(&b);
        ctrl_hdr(&b, PT_PING_RSP, 0, 0xFFFF, 0xFFFFFFFF);
        sendto(sockfd, b.data, b.len, 0, (const struct sockaddr *)peer, sizeof *peer);
        buf_free(&b);
        break;

    case PT_ECHO_REQ:
        if (!verify_sig(raw, len))
            return;
        s = find_session(ctx, sid);
        if (s && s->token == tok)
            s->last_active_ms = now_ms(); /* keepalive traffic = alive */
        buf_init(&b);
        ctrl_hdr(&b, PT_ECHO_RES, raw[1], sid, tok);
        sendto(sockfd, b.data, b.len, 0, (const struct sockaddr *)peer, sizeof *peer);
        buf_free(&b);
        break;

    default:
        break; /* drop silently */
    }
}

void handle_tun_downlink(struct server_ctx *ctx, const uint8_t *ip_pkt, size_t len,
                         int tun_fd, int sockfd)
{
    struct server_session *s;
    buf_t b;

    (void)tun_fd;

    if (len < 20)
        return;
    s = find_session_by_ip(ctx, ip_pkt + 16);
    if (!s)
        return;

    buf_init(&b);
    if (s->enc) {
        data_hdr(&b, PT_DATA_ENC, 1, s->sid, s->token);
        buf_put(&b, ip_pkt, len);
        xor_crypt(b.data + 8, len, s->xor_key, 8);
    } else {
        data_hdr(&b, PT_DATA, 0, s->sid, s->token);
        buf_put(&b, ip_pkt, len);
    }
    sendto(sockfd, b.data, b.len, 0, (const struct sockaddr *)&s->peer, sizeof s->peer);
    buf_free(&b);
    s->last_active_ms = now_ms();
}

void purge_expired(struct server_ctx *ctx, uint64_t now)
{
    for (int i = 0; i < SERVER_MAX_SESSIONS; i++) {
        struct server_session *s = &ctx->sess[i];
        if (s->valid && now - s->last_active_ms > IDLE_TIMEOUT_MS) {
            printf("session 0x%04x (ip %u.%u.%u.%u) expired after 120s idle\n",
                   s->sid, s->ip[0], s->ip[1], s->ip[2], s->ip[3]);
            s->valid = false;
        }
    }
}
