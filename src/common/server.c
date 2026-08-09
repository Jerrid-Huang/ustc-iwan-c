#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>

#include "common.h"
#include "crypto.h"
#include "ipv4.h"
#include "protocol.h"
#include "server.h"
#include "tun.h"
#include "util.h"

#define IDLE_TIMEOUT_MS 120000
#define REJECT_LOG_MAX 10   /* per second, per source-independent window */
#define RATE_BUCKETS 1024   /* per-source limit table for OPEN/PING/ECHO */
#define RATE_WINDOW_MS 1000
#define RATE_OPEN_MAX 20    /* OPENs per source per window */
#define RATE_ECHO_MAX 60    /* PING/ECHO per source per window */
/* Rate-table hashing: Knuth's multiplicative hash. The constant is
 * 2^32 / golden ratio (~2654435761); multiplying by this odd number
 * scrambles the low bits of the key across the full 32-bit range, and
 * keeping the TOP bits afterwards spreads sequential client IPs evenly
 * over the table — a plain "ip % 1024" would keep only the low 10 bits,
 * so e.g. 10.0.0.1 and 10.0.4.1 would land in the same bucket. 1024
 * buckets (1<<10, so the index is a cheap shift, 32 KB of state) is the
 * tradeoff: large enough that a few hostile sources rarely collide,
 * small enough that the worst-case 8-slot probe below stays within a
 * handful of cache lines on every packet. */
#define RATE_HASH_MUL 2654435761u
#define RATE_HASH_SHIFT 22          /* keep top 10 hashed bits -> 1024 buckets */
#define RATE_PROBE_MAX 8            /* linear-probe depth before eviction */

static atomic_uint_fast64_t g_send_drops;
static atomic_ullong g_dl_pkts;   /* UDP datagrams sent (incl. control
                                   * frames like OPEN_ACK/PING_RSP — the
                                   * counter is not a pure data metric) */
static atomic_ullong g_dl_drops;  /* downlink inner-IPv4 gate drops (H1) */
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

void srv_log(const char *fmt, ...)
{
    va_list ap;

    pthread_mutex_lock(&g_log_lock);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
    pthread_mutex_unlock(&g_log_lock);
}

void server_ctx_init(struct server_ctx *ctx)
{
    pthread_rwlock_init(&ctx->sess_lock, NULL);
    memset(ctx->sid_map, 0xFF, sizeof ctx->sid_map); /* all -1: no sessions */
}

void server_ctx_destroy(struct server_ctx *ctx)
{
    pthread_rwlock_destroy(&ctx->sess_lock);
}

/* ---- uplink per-step timing (IWAN_DEBUG=1, printed once per second) ---- */
struct up_stats {
    uint64_t n;
    uint64_t parse;   /* frame parse + rate_allow + dispatch */
    uint64_t find;    /* find_session + token + rebind + enc check */
    uint64_t xor;     /* in-place decryption */
    uint64_t write;   /* tun_write syscall */
    uint64_t drop;    /* tun_write EAGAIN/failure drops */
    uint64_t h1;      /* inner-IPv4 gate drops (malformed/spoofed) */
};

static struct up_stats g_up;
static uint64_t g_up_win;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

void server_up_stats_print(void)
{
    uint64_t now;

    if (g_up.n == 0)
        return;
    now = now_ns();
    if (now - g_up_win < 1000000000ull)
        return;
    g_up_win = now;
    fprintf(stderr,
            "uplink: [t=%llu] n=%llu parse=%.0fns find=%.0fns xor=%.0fns"
            " write=%.0fns total=%.0fns drop=%llu h1=%llu dl=%llu"
            " dldrop=%llu\n",
            (unsigned long long)now_ms(), (unsigned long long)g_up.n,
            (double)g_up.parse / g_up.n, (double)g_up.find / g_up.n,
            (double)g_up.xor / g_up.n, (double)g_up.write / g_up.n,
            (double)(g_up.parse + g_up.find + g_up.xor + g_up.write) / g_up.n,
            (unsigned long long)g_up.drop,
            (unsigned long long)g_up.h1,
            (unsigned long long)server_dl_pkts(),
            (unsigned long long)atomic_load(&g_dl_drops));
    g_up.n = g_up.parse = g_up.find = g_up.xor = g_up.write = 0;
    g_up.drop = 0;
    g_up.h1 = 0;
    /* dl counter is cumulative (per-second delta is printed by the
     * caller's diff of consecutive lines); do not reset here */
}

/* best-effort scrub of secrets, immune to optimizer elision */
static void wipe(void *p, size_t n)
{
    volatile unsigned char *v = p;
    while (n--)
        *v++ = 0;
}

/* printable-only copy of an attacker-controlled string for logging */
static void log_escape(const char *in, char out[], size_t outsz)
{
    size_t i = 0;
    if (outsz == 0)
        return;
    while (*in && i + 1 < outsz) {
        unsigned char c = (unsigned char)*in;
        if (c < 0x20 || c == 0x7f)
            c = '?';
        out[i++] = (char)c;
        in++;
    }
    out[i] = '\0';
}

struct rate_bucket {
    uint32_t ip;       /* network-order source address */
    uint64_t win;      /* window start (monotonic ms) */
    uint8_t open_cnt, echo_cnt;
};

static struct rate_bucket g_rates[RATE_BUCKETS];

/* Per-source token limits on unauthenticated control paths. Over-limit
 * sources are silently dropped (no reject, no log) so a single host
 * cannot saturate the single-threaded loop with cheap forged packets. */
static bool rate_allow(const struct sockaddr_in *peer, uint8_t typ, uint64_t now)
{
    uint32_t ip = (uint32_t)peer->sin_addr.s_addr;
    struct rate_bucket *b;
    unsigned h;

    switch (typ) {
    case PT_OPEN:
    case PT_PING_REQ:
    case PT_ECHO_REQ:
        break; /* rate-limited below */
    default:
        return true; /* authenticated or negligible-cost paths */
    }
    h = (unsigned)((ip * RATE_HASH_MUL) >> RATE_HASH_SHIFT); /* top 10 bits */
    /* Linear probing: the hashed slot may belong to another source, so
     * scan up to RATE_PROBE_MAX slots for a bucket of this IP or a
     * never-used one instead of clobbering a neighbour's counters (that
     * would let one source reset another's window or dodge the limit by
     * rehashing). Only when the whole probe window is occupied by other
     * sources do we evict the slot whose window started longest ago. */
    b = NULL;
    {
        unsigned evict = 0;
        uint64_t oldest = UINT64_MAX;
        for (unsigned i = 0; i < RATE_PROBE_MAX; i++) {
            struct rate_bucket *c = &g_rates[(h + i) % RATE_BUCKETS];
            if (c->win < oldest) {
                oldest = c->win;
                evict = i;
            }
            if (c->ip == ip || (c->ip == 0 && c->win == 0)) {
                b = c;
                break;
            }
        }
        if (!b)
            b = &g_rates[(h + evict) % RATE_BUCKETS];
    }
    if (b->ip != ip || now - b->win >= RATE_WINDOW_MS) {
        b->ip = ip;
        b->win = now;
        b->open_cnt = b->echo_cnt = 0;
    }
    if (typ == PT_OPEN) {
        if (b->open_cnt >= RATE_OPEN_MAX)
            return false;
        b->open_cnt++;
    } else {
        if (b->echo_cnt >= RATE_ECHO_MAX)
            return false;
        b->echo_cnt++;
    }
    return true;
}

/* UDP send that can never block the loop; failures are counted, not
 * logged per packet (the socket is O_NONBLOCK, so EAGAIN drops).
 * Returns false when the datagram was not delivered. */
static bool udp_send(int sockfd, const struct sockaddr_in *peer,
                     const void *data, size_t len)
{
    if (sendto(sockfd, data, len, 0, (const struct sockaddr *)peer,
               sizeof *peer) < 0) {
        atomic_fetch_add(&g_send_drops, 1);
        return false;
    }
    atomic_fetch_add(&g_dl_pkts, 1);
    return true;
}

uint64_t server_send_drops(void)
{
    return atomic_load(&g_send_drops);
}

/* downlink counter: packets forwarded tun->udp (python's ACKs etc.) */
uint64_t server_dl_pkts(void)
{
    return atomic_load(&g_dl_pkts);
}

/* rate-limited reject logging: at most REJECT_LOG_MAX lines per second,
 * attacker-controlled username rendered printable-only. */
static void log_reject(const char *peerstr, const char *user, const char *reason)
{
    static uint64_t win;
    static unsigned cnt;
    uint64_t now = now_ms();
    char u[64];

    if (now - win >= 1000) {
        win = now;
        cnt = 0;
    }
    if (cnt >= REJECT_LOG_MAX)
        return;
    cnt++;
    log_escape(user, u, sizeof u);
    srv_log("[%s] OPEN reject: %s (%s)", peerstr, reason, u);
}

static void peer_to_string(const struct sockaddr_in *peer, char out[INET_ADDRSTRLEN + 8])
{
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer->sin_addr, ip, sizeof ip);
    snprintf(out, INET_ADDRSTRLEN + 8, "%s:%u", ip, (unsigned)ntohs(peer->sin_port));
}

/* caller must hold ctx->sess_lock (any mode) */
static struct server_session *find_session_unlocked(struct server_ctx *ctx,
                                                    uint16_t sid)
{
    int slot = ctx->sid_map[sid];

    if (slot >= 0 && slot < SERVER_MAX_SESSIONS &&
        ctx->sess[slot].valid && ctx->sess[slot].sid == sid)
        return &ctx->sess[slot];
    /* stale/absent map entry: the linear scan is authoritative. The map
     * is only written under the WRITE lock (handle_open/sess_wipe), so
     * this read-side fallback deliberately does NOT heal it — a write
     * here would race other read-lock holders (C11 data race). */
    for (int i = 0; i < SERVER_MAX_SESSIONS; i++)
        if (ctx->sess[i].valid && ctx->sess[i].sid == sid)
            return &ctx->sess[i];
    return NULL;
}

static struct server_session *find_session_by_ip_unlocked(struct server_ctx *ctx,
                                                          const uint8_t ip[4])
{
    /* sid = low 16 bits of the session IP (see handle_open), so the map
     * finds the slot without scanning; the full IP is still verified
     * because the map is only an index. */
    uint16_t sid = (uint16_t)(((uint32_t)ip[2] << 8) | ip[3]);
    int slot = ctx->sid_map[sid];

    if (slot >= 0 && slot < SERVER_MAX_SESSIONS &&
        ctx->sess[slot].valid && ctx->sess[slot].sid == sid &&
        memcmp(ctx->sess[slot].ip, ip, 4) == 0)
        return &ctx->sess[slot];
    /* no map write here either: see find_session_unlocked */
    for (int i = 0; i < SERVER_MAX_SESSIONS; i++)
        if (ctx->sess[i].valid && memcmp(ctx->sess[i].ip, ip, 4) == 0)
            return &ctx->sess[i];
    return NULL;
}

/* invalidate a session and scrub its secrets; caller must hold
 * ctx->sess_lock (write mode) */
static void sess_wipe(struct server_ctx *ctx, struct server_session *s)
{
    uint16_t sid = s->sid; /* still valid here: read before clearing */

    s->valid = false;
    wipe(s->xor_key, sizeof s->xor_key);
    wipe(&s->token, sizeof s->token);
    ctx->sid_map[sid] = -1; /* slot now free; map entry is stale */
}

/* All session access goes through explicit lock sections (see callers);
 * find_session_unlocked / find_session_by_ip_unlocked require the lock. */

static void send_reject(int sockfd, const struct sockaddr_in *peer, const char *msg)
{
    buf_t b;
    buf_init(&b);
    ctrl_hdr(&b, PT_OPEN_REJECT, 0, 0, 0);
    tlv_put(&b, T_ERR_MSG, msg, (uint8_t)strlen(msg));
    udp_send(sockfd, peer, b.data, b.len);
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
            a->enc = val[0] ? 1 : 0; /* clamp: boolean semantics */
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
    uint16_t sid = 0, mtu;
    struct server_session *s;
    int slot, i;

    if (len < 24 || !verify_sig(raw, len))
        return;

    memset(&a, 0, sizeof a);
    a.mtu = 1400;
    if (parse_tlvs(raw + 24, len - 24, open_tlv, &a) != 0) {
        peer_to_string(peer, peerstr);
        log_reject(peerstr, a.user, "malformed TLVs");
        send_reject(sockfd, peer, "malformed TLVs");
        return;
    }

    if (!a.have_av) {
        peer_to_string(peer, peerstr);
        log_reject(peerstr, a.user, "missing AV");
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
        log_reject(peerstr, a.user, "invalid credentials");
        send_reject(sockfd, peer, "invalid credentials");
        return;
    }

    encrypt_password(pass, a.user, expect);
    if (CRYPTO_memcmp(expect, a.ct, 16) != 0) {
        peer_to_string(peer, peerstr);
        log_reject(peerstr, a.user, "invalid credentials");
        send_reject(sockfd, peer, "invalid credentials");
        return;
    }

    session_key(a.user, pass, sk);

    /* ---- session-table section: exclusive (write) lock ---- */
    pthread_rwlock_wrlock(&ctx->sess_lock);

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
        pthread_rwlock_unlock(&ctx->sess_lock);
        peer_to_string(peer, peerstr);
        log_reject(peerstr, a.user, "server full");
        send_reject(sockfd, peer, "server full");
        return;
    }

    /* hand out an address whose sid is not in use by any live session.
     * sid = low 16 bits of the IP, so sid uniqueness implies IP
     * uniqueness: a live session whose sid collided would be silently
     * evicted by the "replace same sid" step below, killing a possibly
     * different user's session on wide subnets (mask <= 16). Probe the
     * pool forward (wrapping) until an unused sid is found. */
    if (ctx->sess[slot].valid) {
        /* re-OPEN of the same user: keep IP + sid, only refresh token */
        ipu = ip4_u32(ctx->sess[slot].ip);
        sid = ctx->sess[slot].sid;
    } else {
        uint32_t probe = ctx->next_ip;
        uint32_t pool = ctx->ip_end - ctx->ip_base + 1;
        for (i = 0; i < (int)pool && i < 65536; i++) {
            if (probe > ctx->ip_end)
                probe = ctx->ip_base;
            sid = (uint16_t)(probe & 0xFFFF);
            if (!find_session_unlocked(ctx, sid))
                break;
            probe++;
        }
        if (i == (int)pool || i == 65536) {
            pthread_rwlock_unlock(&ctx->sess_lock);
            peer_to_string(peer, peerstr);
            log_reject(peerstr, a.user, "server full");
            send_reject(sockfd, peer, "server full");
            return;
        }
        ipu = probe;
        ctx->next_ip = (ipu == ctx->ip_end) ? ctx->ip_base : ipu + 1;
    }
    tok = random_token();

    /* replace any existing session with the same sid */
    for (i = 0; i < SERVER_MAX_SESSIONS; i++)
        if (ctx->sess[i].valid && ctx->sess[i].sid == sid)
            sess_wipe(ctx, &ctx->sess[i]);

    s = &ctx->sess[slot];
    memset(s, 0, sizeof *s);
    s->valid = true;
    s->sid = sid;
    s->token = tok;
    s->peer = *peer;
    u32_ip4(ipu, s->ip);
    memcpy(s->xor_key, sk, 8);
    s->enc = a.enc;
    atomic_store(&s->last_active_ms, now_ms());
    snprintf(s->user, sizeof s->user, "%s", a.user);
    ctx->sid_map[sid] = (int16_t)slot; /* O(1) lookup index (M-8) */

    pthread_rwlock_unlock(&ctx->sess_lock);

    wipe(sk, sizeof sk);
    wipe(expect, sizeof expect);

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
    udp_send(sockfd, peer, b.data, b.len);
    buf_free(&b);

    peer_to_string(peer, peerstr);
    {
        uint8_t ipb2[4];
        char u[64];
        u32_ip4(ipu, ipb2);
        log_escape(a.user, u, sizeof u);
        srv_log("[%s] OPEN_ACK -> %s sid=0x%04x ip=%u.%u.%u.%u enc=%u",
                peerstr, u, sid, ipb2[0], ipb2[1], ipb2[2], ipb2[3], a.enc);
    }
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
    {
        uint64_t ta = 0;
        if (debug_enabled())
            ta = now_ns();
        if (!rate_allow(peer, typ, now_ms()))
            return; /* unauthenticated flood from this source: silent drop */

        switch (typ) {
        case PT_OPEN:
            handle_open(ctx, users, nusers, raw, len, peer, sockfd);
            break;

        case PT_DATA:
        case PT_DATA_ENC: {
            uint64_t tb = 0, tx0 = 0, tx1 = 0, tc = 0;
            uint8_t enc, xk[8];
            uint32_t s_ip, saddr, daddr; /* session addr + inner header */
            if (debug_enabled())
                tb = now_ns();
            pthread_rwlock_rdlock(&ctx->sess_lock);
            s = find_session_unlocked(ctx, sid);
            if (!s || s->token != tok) {
                pthread_rwlock_unlock(&ctx->sess_lock);
                return; /* unknown session or bad token: drop */
            }
            /* source binding: only the session's peer may drive the
             * session; first valid-token packet from a new source rebinds
             * it (NAT or port rebinding tolerance). Rebinds are rare, so
             * the common path holds only the read lock. */
            if (memcmp(&s->peer, peer, sizeof *peer) != 0) {
                pthread_rwlock_unlock(&ctx->sess_lock);
                pthread_rwlock_wrlock(&ctx->sess_lock);
                s = find_session_unlocked(ctx, sid);
                if (!s || s->token != tok) {
                    pthread_rwlock_unlock(&ctx->sess_lock);
                    return;
                }
                s->peer = *peer;
            }
            enc = s->enc;
            memcpy(xk, s->xor_key, sizeof xk);
            s_ip = ip4_u32(s->ip); /* BE-value order, same as the header */
            atomic_store(&s->last_active_ms, now_ms());
            pthread_rwlock_unlock(&ctx->sess_lock);
            if (debug_enabled())
                tx0 = now_ns();
            if (enc) {
                if (typ != PT_DATA_ENC)
                    return; /* enc session accepts only encrypted data */
                xor_crypt((uint8_t *)raw + 8, len - 8, xk, 8);
            } else {
                if (typ != PT_DATA)
                    return; /* plain session accepts only plaintext data */
            }
            if (debug_enabled())
                tx1 = now_ns();
            /* H1: the decrypted payload must be a sane IPv4 packet whose
             * source is the session's assigned address. Anything else is
             * a malformed or spoofed frame — drop it before it reaches
             * the TUN (counted; logged only under IWAN_DEBUG). The inner
             * header sits at raw+8, behind the 8-byte outer header. */
            if (len <= 8 ||
                ipv4_pkt_ok(raw + 8, len - 8, &saddr, &daddr) != 0 ||
                saddr != s_ip) {
                g_up.h1++;
                if (debug_enabled())
                    log_debug("uplink drop: bad inner IPv4 (sid 0x%04x)",
                              sid);
                break;
            }
            if (ctx->tun_fd >= 0 && len > 8) {
                /* device TX queue full: wait briefly for drain instead of
                 * silently dropping the segment. A dropped uplink segment
                 * makes the client RTO-retry; under a burst that can
                 * degrade into a stall. */
                if (tun_write_retry(ctx->tun_fd, raw + 8, len - 8, 1,
                                    NULL) != 0)
                    g_up.drop++;  /* still full: drop, client retransmits */
            }
            if (debug_enabled()) {
                tc = now_ns();
                g_up.parse += tb - ta;
                g_up.find += tx0 - tb;
                g_up.xor += tx1 - tx0;
                g_up.write += tc - tx1;
                g_up.n++;
            }
            break;
        }

    case PT_CLOSE:
        if (!verify_sig(raw, len))
            return;
        pthread_rwlock_wrlock(&ctx->sess_lock);
        s = find_session_unlocked(ctx, sid);
        if (s && s->token == tok) {
            /* CLOSE is terminal: never rebind to a new source, or a
             * token-holding attacker could kill the session from any
             * address */
            if (s->peer.sin_addr.s_addr != peer->sin_addr.s_addr ||
                s->peer.sin_port != peer->sin_port) {
                pthread_rwlock_unlock(&ctx->sess_lock);
                return;
            }
            peer_to_string(peer, peerstr);
            srv_log("[%s] session 0x%04x (ip %u.%u.%u.%u) closed",
                    peerstr, s->sid, s->ip[0], s->ip[1], s->ip[2], s->ip[3]);
            sess_wipe(ctx, s);
        }
        pthread_rwlock_unlock(&ctx->sess_lock);
        break;

    case PT_PING_REQ:
        if (!verify_sig(raw, len))
            return;
        pthread_rwlock_wrlock(&ctx->sess_lock);
        s = find_session_unlocked(ctx, sid);
        if (s && s->token == tok) {
            s->peer = *peer;
            atomic_store(&s->last_active_ms, now_ms()); /* keepalive */
        }
        pthread_rwlock_unlock(&ctx->sess_lock);
        buf_init(&b);
        ctrl_hdr(&b, PT_PING_RSP, 0, 0xFFFF, 0xFFFFFFFF);
        udp_send(sockfd, peer, b.data, b.len);
        buf_free(&b);
        break;

    case PT_ECHO_REQ:
        if (!verify_sig(raw, len))
            return;
        pthread_rwlock_wrlock(&ctx->sess_lock);
        s = find_session_unlocked(ctx, sid);
        if (s && s->token == tok) {
            s->peer = *peer;
            atomic_store(&s->last_active_ms, now_ms()); /* keepalive */
        }
        pthread_rwlock_unlock(&ctx->sess_lock);
        buf_init(&b);
        ctrl_hdr(&b, PT_ECHO_RES, raw[1], sid, tok);
        udp_send(sockfd, peer, b.data, b.len);
        buf_free(&b);
        break;

    default:
        break; /* drop silently */
        }
    }
}

void handle_tun_downlink(struct server_ctx *ctx, const uint8_t *ip_pkt, size_t len,
                         int tun_fd, int sockfd)
{
    struct server_sess_snap snap;
    /* fixed stack buffer: 8B outer header + max TUN datagram; avoids a
     * malloc/realloc cycle per forwarded packet */
    uint8_t out[8 + 65536];
    uint32_t saddr, daddr;

    (void)tun_fd;

    if (len < 20 || len > 65536)
        return;
    /* H1: gate the inner IPv4 header before any session lookup. dst
     * must be a client address or the server's own address; the latter
     * is the SOCKS-mode local-delivery case and must never be rejected
     * here (a session can never own it: server_ip is validated outside
     * the client pool at startup). */
    if (ipv4_pkt_ok(ip_pkt, len, &saddr, &daddr) != 0) {
        atomic_fetch_add(&g_dl_drops, 1);
        if (debug_enabled()) {
            /* len<20 already filtered above, so src/dst bytes are safe */
            log_debug("downlink drop: bad inner IPv4 (%zuB) %u.%u.%u.%u->%u.%u.%u.%u v=%u ihl=%u tot=%u",
                      len, ip_pkt[12], ip_pkt[13], ip_pkt[14], ip_pkt[15],
                      ip_pkt[16], ip_pkt[17], ip_pkt[18], ip_pkt[19],
                      ip_pkt[0] >> 4, ip_pkt[0] & 0x0F,
                      ((unsigned)ip_pkt[2] << 8) | ip_pkt[3]);
        }
        return;
    }
    if (daddr == ip4_u32(ctx->server_ip)) {
        /* server-bound packet: the gate allows it, but no client owns
         * this address — the server machine consumes it locally */
        return;
    }
    /* snapshot under the read lock; the send happens lock-free */
    pthread_rwlock_rdlock(&ctx->sess_lock);
    {
        struct server_session *s = find_session_by_ip_unlocked(ctx, ip_pkt + 16);
        if (!s) {
            pthread_rwlock_unlock(&ctx->sess_lock);
            return;
        }
        snap.peer = s->peer;
        snap.sid = s->sid;
        snap.token = s->token;
        snap.enc = s->enc;
        memcpy(snap.xor_key, s->xor_key, sizeof snap.xor_key);
    }
    pthread_rwlock_unlock(&ctx->sess_lock);

    out[0] = snap.enc ? PT_DATA_ENC : PT_DATA;
    out[1] = snap.enc;
    out[2] = (uint8_t)(snap.sid >> 8);
    out[3] = (uint8_t)snap.sid;
    out[4] = (uint8_t)(snap.token >> 24);
    out[5] = (uint8_t)(snap.token >> 16);
    out[6] = (uint8_t)(snap.token >> 8);
    out[7] = (uint8_t)snap.token;
    memcpy(out + 8, ip_pkt, len);
    if (snap.enc)
        xor_crypt(out + 8, len, snap.xor_key, 8);
    /* Deliberately NO sendto(ECONNREFUSED) teardown here: this socket is
     * unconnected, so on Linux sendto never returns ECONNREFUSED — an
     * ICMP port-unreachable is queued and surfaces on the NEXT receive
     * (which the main loop treats as EAGAIN/drained). Identifying the
     * dead peer from the error queue would need MSG_ERRQUEUE plumbing;
     * sessions of dead peers are instead reaped by purge_expired (120s
     * idle timeout) or by the client's own CLOSE. */
    (void)udp_send(sockfd, &snap.peer, out, 8 + len);
    /* deliberately NO last_active refresh here: downlink is triggered by
     * third-party traffic (other clients, inbound routing), so refreshing
     * would let anyone keep a dead session alive past the idle purge */
}

void purge_expired(struct server_ctx *ctx, uint64_t now)
{
    pthread_rwlock_wrlock(&ctx->sess_lock);
    for (int i = 0; i < SERVER_MAX_SESSIONS; i++) {
        struct server_session *s = &ctx->sess[i];
        if (s->valid &&
            now - atomic_load(&s->last_active_ms) > IDLE_TIMEOUT_MS) {
            srv_log("session 0x%04x (ip %u.%u.%u.%u) expired after %u s idle",
                    s->sid, s->ip[0], s->ip[1], s->ip[2], s->ip[3],
                    (unsigned)(IDLE_TIMEOUT_MS / 1000));
            sess_wipe(ctx, s);
        }
    }
    pthread_rwlock_unlock(&ctx->sess_lock);
}
