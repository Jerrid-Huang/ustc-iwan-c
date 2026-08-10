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
#define RATE_OPEN_MAX_DEFAULT 20    /* OPENs per source per window */
#define RATE_ECHO_MAX_DEFAULT 60    /* PING and ECHO, each per window */
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
static atomic_ullong g_rate_drops; /* per-source rate-limit drops (silent) */
static unsigned g_rate_open_max = RATE_OPEN_MAX_DEFAULT;
static unsigned g_rate_echo_max = RATE_ECHO_MAX_DEFAULT;
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

/* per-recv-thread stats (the multi-threaded uplink sums them on print) */
static struct up_stats g_up[IWAN_SRV_THREADS_MAX];
static int g_up_nthreads = 1;
static uint64_t g_up_win;

void server_up_stats_set_threads(int n)
{
    g_up_nthreads = n < 1 ? 1
                          : (n > IWAN_SRV_THREADS_MAX ? IWAN_SRV_THREADS_MAX
                                                      : n);
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

void server_up_stats_print(void)
{
    uint64_t now;
    struct up_stats sum;

    memset(&sum, 0, sizeof sum);
    for (int t = 0; t < g_up_nthreads; t++) {
        sum.n += g_up[t].n;
        sum.parse += g_up[t].parse;
        sum.find += g_up[t].find;
        sum.xor += g_up[t].xor;
        sum.write += g_up[t].write;
        sum.drop += g_up[t].drop;
        sum.h1 += g_up[t].h1;
    }
    if (sum.n == 0)
        return;
    now = now_ns();
    if (now - g_up_win < 1000000000ull)
        return;
    g_up_win = now;
    fprintf(stderr,
            "uplink: [t=%llu] n=%llu parse=%.0fns find=%.0fns xor=%.0fns"
            " write=%.0fns total=%.0fns drop=%llu h1=%llu dl=%llu"
            " dldrop=%llu ratedrop=%llu\n",
            (unsigned long long)now_ms(), (unsigned long long)sum.n,
            (double)sum.parse / sum.n, (double)sum.find / sum.n,
            (double)sum.xor / sum.n, (double)sum.write / sum.n,
            (double)(sum.parse + sum.find + sum.xor + sum.write) / sum.n,
            (unsigned long long)sum.drop,
            (unsigned long long)sum.h1,
            (unsigned long long)server_dl_pkts(),
            (unsigned long long)atomic_load(&g_dl_drops),
            (unsigned long long)atomic_load(&g_rate_drops));
    for (int t = 0; t < g_up_nthreads; t++)
        memset(&g_up[t], 0, sizeof g_up[t]);
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
    /* per-type counts in the current window. OPEN, PING and ECHO are
     * limited independently (a PING flood no longer eats the ECHO
     * budget); uint32_t so env-configured limits above 255 stay
     * representable. */
    uint32_t open_cnt, ping_cnt, echo_cnt;
};

static struct rate_bucket g_rates[RATE_BUCKETS];

/* guards g_rates: the multi-threaded uplink recv threads share the
 * rate table; the lock is only taken for unauthenticated control types
 * (see rate_allow — the DATA path returns before it) */
static pthread_mutex_t g_rate_mu = PTHREAD_MUTEX_INITIALIZER;

/* IWAN_RATE_* limits are read once at startup (server_rate_limits_init);
 * malformed or out-of-range values fall back to the defaults with a
 * logged warning. The 65535 ceiling keeps one source from claiming an
 * unbounded per-window allowance. */
static unsigned rate_limit_env(const char *name, unsigned dflt)
{
    const char *v = getenv(name);
    char *end;
    unsigned long n;

    if (!v || !*v)
        return dflt;
    errno = 0;
    n = strtoul(v, &end, 10);
    if (errno != 0 || end == v || *end != '\0' || n == 0 || n > 65535) {
        log_err("invalid %s='%s': using default %u", name, v, dflt);
        return dflt;
    }
    return (unsigned)n;
}

void server_rate_limits_init(void)
{
    g_rate_open_max = rate_limit_env("IWAN_RATE_OPEN_MAX",
                                     RATE_OPEN_MAX_DEFAULT);
    g_rate_echo_max = rate_limit_env("IWAN_RATE_ECHO_MAX",
                                     RATE_ECHO_MAX_DEFAULT);
}

/* Per-source token limits on unauthenticated control paths. Over-limit
 * sources are silently dropped (no reject, no log; each drop is counted
 * in g_rate_drops for the per-second stats line) so a single host
 * cannot saturate the single-threaded loop with cheap forged packets. */
static bool rate_allow(const struct sockaddr_in *peer, uint8_t typ, uint64_t now)
{
    uint32_t ip = (uint32_t)peer->sin_addr.s_addr;
    struct rate_bucket *b;
    uint32_t *cnt;
    unsigned limit;
    unsigned h;
    bool ok = true;

    switch (typ) {
    case PT_OPEN:
        limit = g_rate_open_max;
        break;
    case PT_PING_REQ:
    case PT_ECHO_REQ:
        limit = g_rate_echo_max;
        break;
    default:
        return true; /* authenticated or negligible-cost paths */
    }
    /* the rate table is shared by the multi-threaded uplink recv
     * threads; the mutex is only taken on the unauthenticated control
     * types above — the DATA path returns before this point, so the
     * data path never contends */
    pthread_mutex_lock(&g_rate_mu);
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
        b->open_cnt = b->ping_cnt = b->echo_cnt = 0;
    }
    /* independent per-type counters: a PING flood cannot eat the ECHO
     * budget (or vice versa); OPEN keeps its own, tighter limit */
    cnt = (typ == PT_OPEN) ? &b->open_cnt :
          (typ == PT_PING_REQ) ? &b->ping_cnt : &b->echo_cnt;
    if (*cnt >= limit)
        ok = false;
    else
        (*cnt)++;
    pthread_mutex_unlock(&g_rate_mu);
    if (!ok)
        atomic_fetch_add(&g_rate_drops, 1);
    return ok;
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
 * attacker-controlled username rendered printable-only. The throttle
 * counters are atomic: multiple recv threads may log rejects. */
static void log_reject(const char *peerstr, const char *user, const char *reason)
{
    static atomic_ullong win;
    static atomic_uint cnt;
    uint64_t now = now_ms();
    char u[64];

    if (now - atomic_load_explicit(&win, memory_order_relaxed) >= 1000) {
        atomic_store_explicit(&win, now, memory_order_relaxed);
        atomic_store_explicit(&cnt, 0, memory_order_relaxed);
    }
    if (atomic_fetch_add_explicit(&cnt, 1, memory_order_relaxed) >=
        REJECT_LOG_MAX)
        return;
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
    uint8_t ct[16];      /* 16-byte md5 digest of the encrypted password */
    uint16_t mtu;
    uint8_t enc;
    uint32_t nonce;
    bool have_av;
    bool user_too_long;  /* T_USERNAME value exceeded SERVER_USER_MAX */
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
            if (vlen > SERVER_USER_MAX)
                a->user_too_long = true; /* keep the truncated copy for
                                          * safe logging; rejected by
                                          * handle_open */
        } else {
            a->user[0] = '\0';
        }
        break;
    case T_PASSWORD:
        if (vlen >= sizeof a->ct)
            memcpy(a->ct, val, sizeof a->ct);
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

    if (len < IWAN_CTRL_LEN || !verify_sig(raw, len))
        return;

    memset(&a, 0, sizeof a);
    a.mtu = IWAN_DEFAULT_MTU;
    if (parse_tlvs(raw + IWAN_CTRL_LEN, len - IWAN_CTRL_LEN, open_tlv,
                   &a) != 0) {
        peer_to_string(peer, peerstr);
        log_reject(peerstr, a.user, "malformed TLVs");
        send_reject(sockfd, peer, "malformed TLVs");
        return;
    }

    if (a.user_too_long) {
        /* an over-long name can never match a users-file entry; reject
         * loudly instead of silently truncating to 63 bytes */
        peer_to_string(peer, peerstr);
        log_reject(peerstr, a.user, "username too long");
        send_reject(sockfd, peer, "username too long");
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
    if (CRYPTO_memcmp(expect, a.ct, sizeof a.ct) != 0) {
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
            sid = (uint16_t)probe; /* sid = low 16 bits of the IP */
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
    memcpy(s->xor_key, sk, sizeof s->xor_key);
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
    mtu = a.mtu < IWAN_MTU_MIN ? IWAN_MTU_MIN
                               : (a.mtu > IWAN_MTU_MAX ? IWAN_MTU_MAX : a.mtu);
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
                const struct sockaddr_in *peer, int sockfd, unsigned tid)
{
    struct server_session *s;
    buf_t b;
    char peerstr[INET_ADDRSTRLEN + 8];
    uint8_t typ;
    uint16_t sid;
    uint32_t tok;

    if (len < IWAN_HDR_LEN)
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
                xor_crypt((uint8_t *)raw + IWAN_HDR_LEN,
                          len - IWAN_HDR_LEN, xk, sizeof xk);
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
             * header sits at raw+IWAN_HDR_LEN, behind the outer
             * header. */
            if (len <= IWAN_HDR_LEN ||
                ipv4_pkt_ok(raw + IWAN_HDR_LEN, len - IWAN_HDR_LEN,
                            &saddr, &daddr) != 0 ||
                saddr != s_ip) {
                g_up[tid].h1++;
                if (debug_enabled())
                    log_debug("uplink drop: bad inner IPv4 (sid 0x%04x) "
                              "%u.%u.%u.%u->%u.%u.%u.%u v=%u ihl=%u tot=%u",
                              sid, raw[8 + 12], raw[8 + 13], raw[8 + 14],
                              raw[8 + 15], raw[8 + 16], raw[8 + 17],
                              raw[8 + 18], raw[8 + 19], raw[8] >> 4,
                              raw[8] & 0x0F,
                              ((unsigned)raw[8 + 2] << 8) | raw[8 + 3]);
                break;
            }
            if (ctx->tun_fd >= 0 && len > IWAN_HDR_LEN) {
                /* device TX queue full: wait briefly for drain instead of
                 * silently dropping the segment. A dropped uplink segment
                 * makes the client RTO-retry; under a burst that can
                 * degrade into a stall. */
                if (tun_write_retry(ctx->tun_fd, raw + IWAN_HDR_LEN,
                                    len - IWAN_HDR_LEN, 1, NULL) != 0)
                    g_up[tid].drop++;  /* still full: drop, client retransmits */
            }
            if (debug_enabled()) {
                tc = now_ns();
                g_up[tid].parse += tb - ta;
                g_up[tid].find += tx0 - tb;
                g_up[tid].xor += tx1 - tx0;
                g_up[tid].write += tc - tx1;
                g_up[tid].n++;
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
        ctrl_hdr(&b, PT_PING_RSP, 0, IWAN_PING_SID, IWAN_PING_TOK);
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
                         int sockfd)
{
    struct server_sess_snap snap;
    /* fixed stack buffer: outer header + max TUN datagram; avoids a
     * malloc/realloc cycle per forwarded packet */
    uint8_t out[IWAN_HDR_LEN + 65536];
    uint32_t saddr, daddr;

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

    pkt_hdr(snap.enc ? PT_DATA_ENC : PT_DATA, snap.enc, snap.sid,
            snap.token, out);
    memcpy(out + IWAN_HDR_LEN, ip_pkt, len);
    if (snap.enc)
        xor_crypt(out + IWAN_HDR_LEN, len, snap.xor_key,
                  sizeof snap.xor_key);
    /* Deliberately NO sendto(ECONNREFUSED) teardown here: this socket is
     * unconnected, so on Linux sendto never returns ECONNREFUSED — an
     * ICMP port-unreachable is queued and surfaces on the NEXT receive
     * (which the main loop treats as EAGAIN/drained). Identifying the
     * dead peer from the error queue would need MSG_ERRQUEUE plumbing;
     * sessions of dead peers are instead reaped by purge_expired (120s
     * idle timeout) or by the client's own CLOSE. */
    (void)udp_send(sockfd, &snap.peer, out, IWAN_HDR_LEN + len);
    /* deliberately NO last_active refresh here: downlink is triggered by
     * third-party traffic (other clients, inbound routing), so refreshing
     * would let anyone keep a dead session alive past the idle purge */
}

void purge_expired(struct server_ctx *ctx, uint64_t now)
{
    pthread_rwlock_wrlock(&ctx->sess_lock);
    /* Re-take the timestamp AFTER acquiring the write lock: waiting for
     * it can span DATA-path last_active updates (readers update it
     * lock-free), so a `now` sampled before the wait may be OLDER than
     * last_active — the unsigned subtraction then underflows to a huge
     * "idle time" and a live session is wiped as expired (measured:
     * last_active = now + 1ms -> diff = 2^64-1). */
    now = now_ms();
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
