#include <arpa/inet.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#include "common.h"
#include "crypto.h"
#include "ipv4.h"
#include "profile.h"
#include "protocol.h"
#include "server.h"
#include "tun.h"
#include "util.h"

/* TCP header flags (RFC 793); netstack.c keeps its own copy */
#ifndef TCP_FIN
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_ACK 0x10
#endif

/* ---- --no-tun echo mirror: per-connection mirror state ----
 * Every inner TCP packet is swapped (addresses, ports, seq/ack, flags,
 * checksums) and sent back. Two counters per 4-tuple make the mirror
 * correct under both delayed ACKs and retransmits:
 *   client_max — the highest contiguous client seq+len seen (dedup);
 *   emit_seq   — the next seq our mirrored stream will use.
 * A new segment is echoed at emit_seq and advances both counters; a
 * retransmit (client seq behind client_max) is re-echoed at the
 * position its content was originally mirrored to (emit_seq minus the
 * lag) WITHOUT advancing either counter. A pure stateless swap fails
 * under delayed ACKs (every mirror uses the client's stale ACK, so the
 * client discards almost all echoes), and a naive advance-on-seen table
 * fails on the first lost echo (the retransmit advances the table a
 * second time and every later mirror is discarded as out-of-order).
 * Locked: handle_udp runs on several SO_REUSEPORT recv threads. */
#define ECHO_MAX_CONN 64
struct echo_conn {
    uint8_t  af;                 /* 4 or 6 */
    uint32_t c_ip;               /* client inner IP (BE) — af == 4 */
    uint8_t  c6[16];             /* client inner address — af == 6 */
    uint16_t c_port;
    uint32_t t_ip;               /* target IP (BE) — af == 4 */
    uint8_t  t6[16];             /* target address — af == 6 */
    uint16_t t_port;
    uint32_t client_max;         /* highest client seq+len seen */
    uint32_t emit_seq;           /* next seq our mirrors will use */
    uint64_t last_ms;            /* idle reclamation */
};
static struct echo_conn g_echo[ECHO_MAX_CONN];
static pthread_mutex_t g_echo_mu = PTHREAD_MUTEX_INITIALIZER;

static struct echo_conn *echo_lookup(uint8_t af, const uint32_t *c4,
                                     const uint8_t c6[16], uint16_t c_port,
                                     const uint32_t *t4,
                                     const uint8_t t6[16], uint16_t t_port,
                                     bool create)
{
    uint64_t now = now_ms();
    struct echo_conn *free_slot = NULL;
    struct echo_conn *ec;
    pthread_mutex_lock(&g_echo_mu);
    for (int i = 0; i < ECHO_MAX_CONN; i++) {
        ec = &g_echo[i];
        if (ec->last_ms != 0 && ec->af == af && ec->c_port == c_port &&
            ec->t_port == t_port &&
            ((af == 4 && ec->c_ip == *c4 && ec->t_ip == *t4) ||
             (af == 6 && memcmp(ec->c6, c6, 16) == 0 &&
              memcmp(ec->t6, t6, 16) == 0))) {
            ec->last_ms = now;
            pthread_mutex_unlock(&g_echo_mu);
            return ec;
        }
        if (ec->last_ms == 0)
            free_slot = ec;
        else if (now - ec->last_ms > 60000)
            ec->last_ms = 0, free_slot = ec;   /* idle reclaim */
    }
    if (create && free_slot) {
        free_slot->af = af;
        free_slot->c_port = c_port;
        free_slot->t_port = t_port;
        if (af == 4) {
            free_slot->c_ip = *c4;
            free_slot->t_ip = *t4;
        } else {
            memcpy(free_slot->c6, c6, 16);
            memcpy(free_slot->t6, t6, 16);
        }
        free_slot->client_max = 0;
        free_slot->emit_seq = 0;
        free_slot->last_ms = now;
        pthread_mutex_unlock(&g_echo_mu);
        return free_slot;
    }
    pthread_mutex_unlock(&g_echo_mu);
    return NULL;
}

/* shared echo state machine (--no-tun mirror): locate/create the
 * per-4-tuple mirror state and compute the seq for this segment (see
 * the block comment above). Returns 0 with *seq_out set, or -1 when
 * the connection table is full. */
static int echo_seq_advance(uint8_t af, const uint32_t *c4,
                            const uint8_t c6[16], uint16_t sport,
                            const uint32_t *t4, const uint8_t t6[16],
                            uint16_t dport, uint8_t flags,
                            uint32_t s_orig, size_t paylen,
                            uint32_t *seq_out)
{
    struct echo_conn *ec = echo_lookup(af, c4, c6, sport, t4, t6, dport,
                                       (flags & TCP_SYN) != 0);
    if (!ec)
        return -1;           /* table full */
    uint32_t len = (uint32_t)paylen;
    if (flags & (TCP_SYN | TCP_FIN))
        len++;               /* SYN/FIN each consume one sequence number */
    /* unsigned subtraction: back is small when s_orig lags client_max
     * (retransmit), huge (wrapped) when s_orig is at or past it */
    uint32_t back = (uint32_t)(ec->client_max - s_orig);
    if (back != 0 && back < 0x80000000u) {
        /* retransmit: re-echo at the position this content was first
         * mirrored to; counters do not move */
        *seq_out = ec->emit_seq - back;
        return 0;
    }
    *seq_out = ec->emit_seq;
    ec->client_max = s_orig + len;
    ec->emit_seq += len;
    return 0;
}
/* shared echo ack/flags rules: the mirrored ack advances past the
 * client's bytes — SYN and FIN each consume one sequence number — and
 * SYN/FIN echoes carry the ACK flag. Returns the ack; *flags is
 * updated in place (the caller writes it to the packet). */
static uint32_t echo_mirror_ack(uint32_t s_orig, size_t paylen, uint8_t *flags)
{
    if (*flags & TCP_SYN) {
        *flags |= TCP_ACK;
        return s_orig + 1;
    } else if (*flags & TCP_FIN) {
        *flags |= TCP_ACK;
        return s_orig + (uint32_t)paylen + 1;
    } else {
        return s_orig + (uint32_t)paylen;
    }
}

static int echo_mirror(struct server_ctx *ctx, uint8_t *p, size_t len,
                       int sockfd);

#define IDLE_TIMEOUT_MS 120000
#define REJECT_LOG_MAX 10   /* per second, per source-independent window */
#define RATE_BUCKETS 1024   /* per-source limit table for OPEN/PING/ECHO */
#define RATE_WINDOW_MS 1000
#define RATE_OPEN_MAX_DEFAULT 20    /* OPENs per source per window */
#define RATE_ECHO_MAX_DEFAULT 60    /* PING and ECHO, each per window */
/* F4: per-source token-mismatch budget. At most 4 failed DATA/CLOSE
 * authentications (unknown session or wrong token) per second per source
 * address; beyond that every DATA/CLOSE packet from the source is
 * silently dropped until the window rolls. 4/s is the sweet spot: a real
 * client in transition (token refresh, idle expiry, NAT rebinding) sends
 * at most a handful of stale frames per second, while a guesser
 * brute-forcing the 32-bit token is throttled to 4 probes/s (centuries
 * at that rate). Keyed by IP only, like the other rate buckets, so NAT
 * -shared sources share one budget. */
#define RATE_TOKEN_MISMATCH_MAX 4
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
/* [prof] server-side stage counters (exported for the recv thread print) */
atomic_uint_fast64_t g_prof_srv_recv, g_prof_srv_tunw, g_prof_srv_tunr,
    g_prof_srv_dlsend;
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

/* IWAN_SRV_TUN_SINGLE=1: uplink TUN writes go to the owner fd instead
 * of the multi-queue fan-out (A/B benchmark switch; cached at startup) */
static bool srv_tun_single(void)
{
    static int v = -1;
    if (v < 0)
        v = getenv("IWAN_SRV_TUN_SINGLE") != NULL;
    return v != 0;
}
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
/* wipe: shared constant-time erasure from crypto.h */

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
    /* F4: DATA/CLOSE token mismatches in the current window (saturating
     * at RATE_TOKEN_MISMATCH_MAX). Consumed by rate_token_over /
     * rate_token_zero / rate_token_mismatch; see those. */
    uint32_t tok_mis_cnt;
};

static struct rate_bucket g_rates[RATE_BUCKETS];

/* guards g_rates: the multi-threaded uplink recv threads share the
 * rate table; the lock is taken for the unauthenticated control types
 * (rate_allow) and for the F4 DATA/CLOSE token-mismatch accounting
 * (rate_token_over/mismatch/zero). Sections are short and, per flow,
 * effectively uncontended (SO_REUSEPORT pins one client flow to one
 * recv thread). Lock order is always sess_lock (outer) -> g_rate_mu
 * (inner) when both are held; the DATA path releases sess_lock before
 * touching the rate table. */
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

/* locate (or claim) the rate bucket for ip; caller must hold g_rate_mu.
 * Linear probing: the hashed slot may belong to another source, so scan
 * up to RATE_PROBE_MAX slots for a bucket of this IP or a never-used one
 * instead of clobbering a neighbour's counters (that would let one
 * source reset another's window or dodge the limit by rehashing). Only
 * when the whole probe window is occupied by other sources do we evict
 * the slot whose window started longest ago. */
static struct rate_bucket *rate_bucket_find(uint32_t ip)
{
    unsigned h = (unsigned)((ip * RATE_HASH_MUL) >> RATE_HASH_SHIFT); /* top 10 bits */
    unsigned evict = 0;
    uint64_t oldest = UINT64_MAX;

    for (unsigned i = 0; i < RATE_PROBE_MAX; i++) {
        struct rate_bucket *c = &g_rates[(h + i) % RATE_BUCKETS];
        if (c->win < oldest) {
            oldest = c->win;
            evict = i;
        }
        if (c->ip == ip || (c->ip == 0 && c->win == 0)) {
            return c;
        }
    }
    return &g_rates[(h + evict) % RATE_BUCKETS];
}

/* (re)start the source's window when the bucket is stale or was just
 * evicted from another source; caller must hold g_rate_mu. */
static void rate_bucket_touch(struct rate_bucket *b, uint32_t ip, uint64_t now)
{
    if (b->ip != ip || now - b->win >= RATE_WINDOW_MS) {
        b->ip = ip;
        b->win = now;
        b->open_cnt = b->ping_cnt = b->echo_cnt = 0;
        b->tok_mis_cnt = 0;
    }
}

/* shared skeleton for the per-source rate paths below: lock the rate
 * table, (re)locate the source's bucket, (re)start its window, and
 * hand the bucket back with the lock STILL HELD — the caller does its
 * per-type accounting and then unlocks (the counter read-modify-write
 * must stay inside the critical section; see g_rate_mu). Small enough
 * that the compiler inlines it on the per-packet path. */
static struct rate_bucket *rate_bucket_enter(uint32_t ip, uint64_t now)
{
    pthread_mutex_lock(&g_rate_mu);
    struct rate_bucket *b = rate_bucket_find(ip);
    rate_bucket_touch(b, ip, now);
    return b;
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
     * threads; the mutex is taken on the unauthenticated control types
     * above and on the F4 DATA/CLOSE token-mismatch checks below
     * (rate_token_over/mismatch/zero) */
    b = rate_bucket_enter(ip, now);
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

/* ---- F4: per-source token-mismatch budget (DATA/CLOSE paths) ---- */

/* true when this source is at/over the mismatch budget: every DATA/CLOSE
 * packet from it is silently dropped (counted in g_rate_drops) until the
 * window rolls. Checked at the top of the DATA/CLOSE branches, before
 * any session work, so a blacklisted source cannot even probe. The OPEN/
 * PING/ECHO budgets above are NOT affected. */
static bool rate_token_over(const struct sockaddr_in *peer, uint64_t now)
{
    uint32_t ip = (uint32_t)peer->sin_addr.s_addr;
    struct rate_bucket *b;
    bool over;

    b = rate_bucket_enter(ip, now);
    over = b->tok_mis_cnt >= RATE_TOKEN_MISMATCH_MAX;
    pthread_mutex_unlock(&g_rate_mu);
    if (over)
        atomic_fetch_add(&g_rate_drops, 1);
    return over;
}

/* record one token mismatch from this source: a DATA/CLOSE frame with an
 * unknown session or a wrong token is a guess, and each guess advances
 * the source toward the blacklist. Counter saturates at the budget. */
static void rate_token_mismatch(const struct sockaddr_in *peer, uint64_t now)
{
    uint32_t ip = (uint32_t)peer->sin_addr.s_addr;
    struct rate_bucket *b;

    b = rate_bucket_enter(ip, now);
    if (b->tok_mis_cnt < RATE_TOKEN_MISMATCH_MAX)
        b->tok_mis_cnt++;
    pthread_mutex_unlock(&g_rate_mu);
}

/* true when the source has accumulated zero token mismatches in the
 * current window. Peer rebinding (DATA/PING/ECHO) is only granted to
 * such sources: this single test implements both halves of the rebind
 * gate — "under the mismatch rate limit" (an over-budget source has
 * cnt >= RATE_TOKEN_MISMATCH_MAX > 0 and fails here) and "zero recent
 * mismatches" (any sub-budget sprayer with 1..MAX-1 also fails). */
static bool rate_token_zero(const struct sockaddr_in *peer, uint64_t now)
{
    uint32_t ip = (uint32_t)peer->sin_addr.s_addr;
    struct rate_bucket *b;
    bool zero;

    b = rate_bucket_enter(ip, now);
    zero = b->tok_mis_cnt == 0;
    pthread_mutex_unlock(&g_rate_mu);
    return zero;
}

/* UDP send that can never block the loop; failures are counted, not
 * logged per packet (the socket is O_NONBLOCK, so EAGAIN drops). */
static void udp_send(int sockfd, const struct sockaddr_in *peer,
                     const void *data, size_t len)
{
    if (sendto(sockfd, data, len, 0, (const struct sockaddr *)peer,
               sizeof *peer) < 0) {
        atomic_fetch_add(&g_send_drops, 1);
        return;
    }
    atomic_fetch_add(&g_dl_pkts, 1);
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
    size_t mlen = strlen(msg);
    /* tlv_put aborts on vlen > IWAN_TLV_VLEN_MAX: clamp instead of
     * letting an over-long message crash the whole server */
    if (mlen > IWAN_TLV_VLEN_MAX)
        mlen = IWAN_TLV_VLEN_MAX;
    buf_init(&b);
    ctrl_hdr(&b, PT_OPEN_REJECT, 0, 0, 0);
    tlv_put(&b, T_ERR_MSG, msg, (uint8_t)mlen);
    udp_send(sockfd, peer, b.data, b.len);
    buf_free(&b);
}

/* shared OPEN-reject exit: peer string + rate-limited reject log +
 * reject frame, in that order — identical at every handle_open
 * rejection. The two "server full" exits unlock ctx->sess_lock BEFORE
 * calling (the reject must never run under the session-table lock). */
static void open_reject(int sockfd, const struct sockaddr_in *peer,
                        const char *user, const char *reason)
{
    char peerstr[INET_ADDRSTRLEN + 8];

    peer_to_string(peer, peerstr);
    log_reject(peerstr, user, reason);
    send_reject(sockfd, peer, reason);
}

/* 4 random bytes; cryptographically strong entropy, fail-closed (F6).
 * A guessable token is a session-hijack hole, so there is no acceptable
 * fallback: an RNG failure means the kernel entropy source is broken and
 * aborting is correct (this runs per-session at OPEN time). */
static uint32_t random_token(void)
{
    uint32_t tok;

    if (port_rand_bytes(&tok, sizeof tok) != 0) {
        log_err("random_token: cannot obtain secure randomness "
                "(port_rand_bytes failed); aborting");
        abort();
    }
    return tok;
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
        open_reject(sockfd, peer, a.user, "malformed TLVs");
        return;
    }

    if (a.user_too_long) {
        /* an over-long name can never match a users-file entry; reject
         * loudly instead of silently truncating to 63 bytes */
        open_reject(sockfd, peer, a.user, "username too long");
        return;
    }

    if (!a.have_av) {
        open_reject(sockfd, peer, a.user, "missing AV");
        return;
    }

    for (i = 0; i < nusers; i++) {
        if (strcmp(users[i].name, a.user) == 0) {
            pass = users[i].pass;
            break;
        }
    }
    if (!pass) {
        open_reject(sockfd, peer, a.user, "invalid credentials");
        return;
    }

    encrypt_password(pass, a.user, expect);
    if (CRYPTO_memcmp(expect, a.ct, sizeof a.ct) != 0) {
        open_reject(sockfd, peer, a.user, "invalid credentials");
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
        open_reject(sockfd, peer, a.user, "server full");
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
            open_reject(sockfd, peer, a.user, "server full");
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
        uint64_t now = now_ms(); /* one clock read shared by the rate checks */
        if (debug_enabled())
            ta = now_ns();
        if (!rate_allow(peer, typ, now))
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
            /* F4: a source at/over the token-mismatch budget is
             * blacklisted for the rest of the window — every DATA packet
             * from it is dropped before any session work (counted, not
             * logged, mirroring the OPEN/PING/ECHO ratedrop behavior) */
            if (rate_token_over(peer, now))
                return;
            pthread_rwlock_rdlock(&ctx->sess_lock);
            s = find_session_unlocked(ctx, sid);
            if (!s || CRYPTO_memcmp(&s->token, &tok, sizeof tok) != 0) {
                pthread_rwlock_unlock(&ctx->sess_lock);
                rate_token_mismatch(peer, now); /* F4: count the guess */
                return; /* unknown session or bad token: drop */
            }
            /* source binding: only the session's peer may drive the
             * session; first valid-token packet from a new source rebinds
             * it (NAT or port rebinding tolerance). Rebinds are rare, so
             * the common path holds only the read lock. */
            if (memcmp(&s->peer, peer, sizeof *peer) != 0) {
                pthread_rwlock_unlock(&ctx->sess_lock);
                /* F4 rebind gate: a new source may take over the session
                 * only with zero recent token mismatches AND while under
                 * the mismatch rate limit — both are one test
                 * (rate_token_zero); an address that has been spraying
                 * guesses is already blocked by rate_token_over above and
                 * never reaches this point. Honest roamers have a fresh
                 * counter and rebind on this first packet, as before. */
                if (!rate_token_zero(peer, now))
                    return;
                pthread_rwlock_wrlock(&ctx->sess_lock);
                s = find_session_unlocked(ctx, sid);
                if (!s || CRYPTO_memcmp(&s->token, &tok, sizeof tok) != 0) {
                    pthread_rwlock_unlock(&ctx->sess_lock);
                    rate_token_mismatch(peer, now); /* F4 */
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
             * source is the session's assigned address, or a sane IPv6
             * packet whose source is the session's derived ULA
             * (fd00::/96 + assigned IPv4, see protocol.h). Anything else
             * is a malformed or spoofed frame — drop it before it reaches
             * the TUN (counted; logged only under IWAN_DEBUG). The inner
             * header sits at raw+IWAN_HDR_LEN, behind the outer
             * header. */
            if (len <= IWAN_HDR_LEN) {
                g_up[tid].h1++;
                break;
            }
            {
                const uint8_t *in = raw + IWAN_HDR_LEN;
                size_t inlen = len - IWAN_HDR_LEN;
                if ((in[0] >> 4) == 6) {
                    uint8_t s6[16], d6[16], want6[16];
                    ip6_derive_ula(s_ip, want6);
                    if (ip6_pkt_ok(in, inlen, s6, d6) != 0 ||
                        memcmp(s6, want6, 16) != 0) {
                        g_up[tid].h1++;
                        if (debug_enabled())
                            log_debug("uplink drop: bad inner IPv6 "
                                      "(sid 0x%04x) v=%u nexth=%u plen=%u",
                                      sid, in[0] >> 4, in[6],
                                      ((unsigned)in[4] << 8) | in[5]);
                        break;
                    }
                } else {
                    if (ipv4_pkt_ok(in, inlen, &saddr, &daddr) != 0 ||
                        saddr != s_ip) {
                        g_up[tid].h1++;
                        if (debug_enabled())
                            log_debug("uplink drop: bad inner IPv4 "
                                      "(sid 0x%04x) %u.%u.%u.%u->%u.%u.%u.%u "
                                      "v=%u ihl=%u tot=%u",
                                      sid, raw[8 + 12], raw[8 + 13],
                                      raw[8 + 14], raw[8 + 15], raw[8 + 16],
                                      raw[8 + 17], raw[8 + 18], raw[8 + 19],
                                      raw[8] >> 4, raw[8] & 0x0F,
                                      ((unsigned)raw[8 + 2] << 8) |
                                          raw[8 + 3]);
                        break;
                    }
                }
            }
            /* len > IWAN_HDR_LEN guaranteed: the H1 guard above broke
             * out on short frames */
            if (ctx->tun_fd >= 0) {
                /* device TX queue full: wait briefly for drain instead of
                 * silently dropping the segment. A dropped uplink segment
                 * makes the client RTO-retry; under a burst that can
                 * degrade into a stall. */
                int wfd = ctx->tun_fd;
                if (ctx->qpool != NULL && !srv_tun_single()) {
                    /* spread uplink writes across the reader pool's
                     * queue fds: the device write lock is otherwise a
                     * single serialization point (measured: TUN write
                     * was 85-90% of per-frame cost at multi-client
                     * aggregate >5 Gbit/s). IWAN_SRV_TUN_SINGLE=1
                     * reverts to the owner fd for A/B benchs. */
                    int pf = tun_pool_write_fd(ctx->qpool, tid);
                    if (pf >= 0)
                        wfd = pf;
                }
                if (tun_write_retry(wfd, raw + IWAN_HDR_LEN,
                                    len - IWAN_HDR_LEN, 1, NULL) == 0)
                    PROF_ADD(g_prof_srv_tunw, len - IWAN_HDR_LEN);
                else {
                    /* still full: drop, client retransmits. Also tell
                     * the pool the device queue is congested so its
                     * AIMD keeps the write fan-out (never shrinks). */
                    tun_pool_note_stall(ctx->qpool);
                    g_up[tid].drop++;
                }
            } else {
                /* --no-tun test mode: echo the packet back (zero-latency
                 * lossless mirror) so tunnel + netstack throughput can
                 * be benchmarked without a TUN device or target network */
                if (echo_mirror(ctx, (uint8_t *)raw + IWAN_HDR_LEN,
                                len - IWAN_HDR_LEN, sockfd) != 0)
                    g_up[tid].drop++;
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
        if (rate_token_over(peer, now))
            return; /* F4: blacklisted source */
        if (!verify_sig(raw, len))
            return;
        pthread_rwlock_wrlock(&ctx->sess_lock);
        s = find_session_unlocked(ctx, sid);
        if (s && CRYPTO_memcmp(&s->token, &tok, sizeof tok) == 0) {
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
        } else {
            /* F4: a bad-token (or unknown-sid) CLOSE is a token guess:
             * count it against the source's budget */
            rate_token_mismatch(peer, now);
        }
        pthread_rwlock_unlock(&ctx->sess_lock);
        break;

    case PT_PING_REQ:
    case PT_ECHO_REQ:
        if (!verify_sig(raw, len))
            return;
        /* Common path (same peer, valid token) takes only the read
         * lock: last_active is an atomic store, so keepalives no longer
         * serialize the whole session table against every DATA reader.
         * A peer change (rebind) upgrades to the write lock — gated on
         * the source's token-mismatch history (F4) so a guessed token
         * cannot claim the session from an address that has been
         * spraying. The PING_RSP / ECHO_RES reply is still sent
         * regardless: it is a liveness oracle by design and must not
         * become a token oracle. */
        pthread_rwlock_rdlock(&ctx->sess_lock);
        s = find_session_unlocked(ctx, sid);
        if (s && CRYPTO_memcmp(&s->token, &tok, sizeof tok) == 0) {
            if (memcmp(&s->peer, peer, sizeof *peer) == 0) {
                atomic_store(&s->last_active_ms, now_ms()); /* keepalive */
                pthread_rwlock_unlock(&ctx->sess_lock);
            } else {
                pthread_rwlock_unlock(&ctx->sess_lock);
                pthread_rwlock_wrlock(&ctx->sess_lock);
                s = find_session_unlocked(ctx, sid);
                if (s && CRYPTO_memcmp(&s->token, &tok, sizeof tok) == 0 &&
                    rate_token_zero(peer, now)) {
                    s->peer = *peer;
                    atomic_store(&s->last_active_ms, now_ms());
                }
                pthread_rwlock_unlock(&ctx->sess_lock);
            }
        } else {
            pthread_rwlock_unlock(&ctx->sess_lock);
        }
        buf_init(&b);
        if (typ == PT_PING_REQ)
            ctrl_hdr(&b, PT_PING_RSP, 0, IWAN_PING_SID, IWAN_PING_TOK);
        else
            ctrl_hdr(&b, PT_ECHO_RES, raw[1], sid, tok);
        udp_send(sockfd, peer, b.data, b.len);
        buf_free(&b);
        break;

    default:
        break; /* drop silently */
        }
    }
}

/* --no-tun echo mode: mirror an inner IPv6/TCP packet back to its
 * sender (v6 sibling of echo_mirror; same stateless-ish swap, checksum
 * via the IPv6 pseudo header). */
static int echo_mirror6(struct server_ctx *ctx, uint8_t *p, size_t len,
                        int sockfd)
{
    uint32_t seq, ack, s_orig;
    uint16_t sport, dport, cs;
    uint8_t flags;
    size_t thlen, paylen;
    uint8_t tmp16[16];

    if (len < 60) {              /* 40 IPv6 + 20 TCP */
        if (debug_enabled())
            log_debug("echo6: short pkt %zu", len);
        return -1;
    }
    if (p[6] != IPPROTO_TCP) {   /* next header must be TCP (no ext hdrs) */
        if (debug_enabled())
            log_debug("echo6: nexth %u not TCP", p[6]);
        return -1;
    }
    thlen = (size_t)((p[52] >> 4) & 0x0F) * 4;
    if (len < 40 + thlen) {
        if (debug_enabled())
            log_debug("echo6: bad thlen %zu len %zu", thlen, len);
        return -1;
    }
    if (debug_enabled()) {
        char hx[160];
        size_t hn = len < 52 ? len : 52;   /* 52*3+1 = 157 < 160 */
        for (size_t k = 0; k < hn; k++)
            sprintf(hx + k * 3, "%02x ", p[k]);
        log_debug("echo6: [%02x%02x:..:%02x%02x]:%u -> [%02x%02x:..:%02x%02x]:%u "
                  "flags=%02x len=%zu [%s]",
                  p[8], p[9], p[22], p[23],
                  (unsigned)((p[40] << 8) | p[41]),
                  p[24], p[25], p[38], p[39],
                  (unsigned)((p[42] << 8) | p[43]),
                  p[53], len, hx);
    }
    sport = (uint16_t)((p[40] << 8) | p[41]);
    dport = (uint16_t)((p[42] << 8) | p[43]);
    s_orig = ((uint32_t)p[44] << 24) | ((uint32_t)p[45] << 16) |
             ((uint32_t)p[46] << 8) | p[47];
    flags = p[53];
    paylen = len - 40 - thlen;

    if (echo_seq_advance(6, NULL, p + 8, sport, NULL, p + 24, dport,
                         flags, s_orig, paylen, &seq) != 0)
        return -1;           /* table full */
    /* swap addresses byte-wise */
    memcpy(tmp16, p + 8, 16);
    memcpy(p + 8, p + 24, 16);
    memcpy(p + 24, tmp16, 16);
    /* swap TCP ports */
    p[40] = (uint8_t)(dport >> 8);
    p[41] = (uint8_t)dport;
    p[42] = (uint8_t)(sport >> 8);
    p[43] = (uint8_t)sport;
    /* mirrored ack advances past the client's bytes; seq from the table */
    ack = echo_mirror_ack(s_orig, paylen, &flags);
    p[53] = flags;
    p[44] = (uint8_t)(seq >> 24);
    p[45] = (uint8_t)(seq >> 16);
    p[46] = (uint8_t)(seq >> 8);
    p[47] = (uint8_t)seq;
    p[48] = (uint8_t)(ack >> 24);
    p[49] = (uint8_t)(ack >> 16);
    p[50] = (uint8_t)(ack >> 8);
    p[51] = (uint8_t)ack;
    /* TCP checksum over the IPv6 pseudo header (mirrored addresses) */
    p[56] = 0;
    p[57] = 0;
    cs = ip6_tcp_csum(p + 8, p + 24, p + 40, len - 40);
    p[56] = (uint8_t)(cs >> 8);
    p[57] = (uint8_t)cs;

    handle_tun_downlink(ctx, p, len, sockfd);
    return 0;
}

/* --no-tun echo mode: mirror an inner IPv4/TCP packet back to its
 * sender by swapping addresses/ports and seq/ack and turning SYN/FIN
 * into SYN+ACK/FIN+ACK (ISN 0, so no per-connection state). The client
 * netstack sees a lossless zero-RTT peer, which exercises the full
 * client<->server tunnel + netstack data path end to end — a bench
 * harness for SOCKS-mode throughput without a TUN device or a real
 * target network. */
int echo_mirror(struct server_ctx *ctx, uint8_t *p, size_t len,
                int sockfd)
{
    if (len >= 1 && (p[0] >> 4) == 6)
        return echo_mirror6(ctx, p, len, sockfd);

    uint32_t seq, ack, s_orig, nsrc, ndst;
    uint16_t sport, dport, cs;
    uint8_t ihl, flags;
    size_t thlen, paylen;
    uint8_t tmp4[4];

    if (len < 40) {              /* 20 IP + 20 TCP */
        if (debug_enabled())
            log_debug("echo: short pkt %zu", len);
        return -1;
    }
    ihl = (uint8_t)((p[0] & 0x0F) * 4);
    if (ihl < 20 || len < (size_t)ihl + 20) {
        if (debug_enabled())
            log_debug("echo: bad ihl %u len %zu", ihl, len);
        return -1;
    }
    if (p[9] != IPPROTO_TCP) {
        if (debug_enabled())
            log_debug("echo: proto %u not TCP", p[9]);
        return -1;
    }
    thlen = (size_t)((p[ihl + 12] >> 4) & 0x0F) * 4;
    if (len < (size_t)ihl + thlen) {
        if (debug_enabled())
            log_debug("echo: bad thlen %zu len %zu", thlen, len);
        return -1;
    }
    if (debug_enabled()) {
        char hx[160];
        size_t hn = len < 48 ? len : 48;
        for (size_t k = 0; k < hn; k++)
            sprintf(hx + k * 3, "%02x ", p[k]);
        log_debug("echo: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u flags=%02x len=%zu [%s]",
                  p[12], p[13], p[14], p[15],
                  (unsigned)((p[ihl] << 8) | p[ihl + 1]),
                  p[16], p[17], p[18], p[19],
                  (unsigned)((p[ihl + 2] << 8) | p[ihl + 3]),
                  p[ihl + 13], len, hx);
    }
    sport = (uint16_t)((p[ihl] << 8) | p[ihl + 1]);
    dport = (uint16_t)((p[ihl + 2] << 8) | p[ihl + 3]);
    s_orig = ((uint32_t)p[ihl + 4] << 24) | ((uint32_t)p[ihl + 5] << 16) |
             ((uint32_t)p[ihl + 6] << 8) | p[ihl + 7];
    flags = p[ihl + 13];
    paylen = len - (size_t)ihl - thlen;

    nsrc = ((uint32_t)p[12] << 24) | ((uint32_t)p[13] << 16) |
           ((uint32_t)p[14] << 8) | p[15];
    ndst = ((uint32_t)p[16] << 24) | ((uint32_t)p[17] << 16) |
           ((uint32_t)p[18] << 8) | p[19];
    /* mirrored seq from the per-connection state machine (new data
     * advances emit_seq; retransmits re-echo at their original spot) */
    if (echo_seq_advance(4, &nsrc, NULL, sport, &ndst, NULL, dport,
                         flags, s_orig, paylen, &seq) != 0)
        return -1;           /* table full */
    /* swap addresses byte-wise (never through a host-endian u32: the
     * little-endian memcpy round-trip would byte-reverse them) */
    memcpy(tmp4, p + 12, 4);
    memcpy(p + 12, p + 16, 4);
    memcpy(p + 16, tmp4, 4);
    /* swap TCP ports */
    p[ihl] = (uint8_t)(dport >> 8);
    p[ihl + 1] = (uint8_t)dport;
    p[ihl + 2] = (uint8_t)(sport >> 8);
    p[ihl + 3] = (uint8_t)sport;
    /* mirrored ack advances past the client's bytes (SYN/FIN each
     * consume one sequence number); mirrored seq from the table */
    ack = echo_mirror_ack(s_orig, paylen, &flags);
    p[ihl + 13] = flags;
    p[ihl + 4] = (uint8_t)(seq >> 24);
    p[ihl + 5] = (uint8_t)(seq >> 16);
    p[ihl + 6] = (uint8_t)(seq >> 8);
    p[ihl + 7] = (uint8_t)seq;
    p[ihl + 8] = (uint8_t)(ack >> 24);
    p[ihl + 9] = (uint8_t)(ack >> 16);
    p[ihl + 10] = (uint8_t)(ack >> 8);
    p[ihl + 11] = (uint8_t)ack;
    /* TCP checksum: pseudo header uses the mirrored addresses
     * (src = original dst, dst = original src) */
    p[ihl + 16] = 0;
    p[ihl + 17] = 0;
    cs = ip_tcp_csum(ndst, nsrc, p + ihl, len - (size_t)ihl);
    p[ihl + 16] = (uint8_t)(cs >> 8);
    p[ihl + 17] = (uint8_t)cs;
    /* IP header checksum */
    p[10] = 0;
    p[11] = 0;
    cs = ip_csum_fold(ip_csum_accum(0, p, ihl));
    p[10] = (uint8_t)(cs >> 8);
    p[11] = (uint8_t)cs;

    handle_tun_downlink(ctx, p, len, sockfd);
    return 0;
}

void handle_tun_downlink(struct server_ctx *ctx, uint8_t *ip_pkt, size_t len,
                         int sockfd)
{
    struct server_sess_snap snap;
    uint8_t hdr[IWAN_HDR_LEN];
    uint32_t saddr, daddr;

    if (len < 20 || len > 65536)
        return;
    /* H1: gate the inner header before any session lookup. dst must be a
     * client address or the server's own address; the latter is the
     * SOCKS-mode local-delivery case and must never be rejected here (a
     * session can never own it: server_ip is validated outside the client
     * pool at startup). IPv4 sessions match the assigned address; IPv6
     * sessions match the derived ULA (fd00::/96 + assigned IPv4). */
    if ((ip_pkt[0] >> 4) == 6) {
        uint8_t s6[16], d6[16];
        if (ip6_pkt_ok(ip_pkt, len, s6, d6) != 0) {   /* guards len < 40 itself */
            atomic_fetch_add(&g_dl_drops, 1);
            if (debug_enabled())
                log_debug("downlink drop: bad inner IPv6 (%zuB) v=%u "
                          "plen=%u",
                          len, ip_pkt[0] >> 4,
                          ((unsigned)ip_pkt[4] << 8) | ip_pkt[5]);
            return;
        }
        /* server-bound (its own derived ULA): consumed locally */
        {
            uint8_t srv6[16];
            ip6_derive_ula(ip4_u32(ctx->server_ip), srv6);
            if (memcmp(d6, srv6, 16) == 0)
                return;
        }
        /* session lookup: the client's ULA embeds its inner IPv4 in the
         * low 32 bits (protocol.h), so the IPv4 session table applies */
        pthread_rwlock_rdlock(&ctx->sess_lock);
        {
            struct server_session *s = find_session_by_ip_unlocked(ctx, d6 + 12);
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
    } else {
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
    }

    pkt_hdr(snap.enc ? PT_DATA_ENC : PT_DATA, snap.enc, snap.sid,
            snap.token, hdr);
    if (snap.enc)
        xor_crypt(ip_pkt, len, snap.xor_key, sizeof snap.xor_key);
    /* Zero-copy send: the payload is XORed IN PLACE (the buffer belongs
     * to the caller until this returns — the tun reader's scratch or a
     * mirror stack buffer — and UDP datagrams are never retransmitted,
     * so in-place crypto is safe) and sent as a 2-iovec message
     * [outer header, payload]. This eliminates the full-packet memcpy
     * the old sendto path did. */
    {
        struct iovec iov[2];
        struct msghdr msg;
        memset(&msg, 0, sizeof msg);
        msg.msg_name = (struct sockaddr *)&snap.peer;
        msg.msg_namelen = sizeof snap.peer;
        iov[0].iov_base = hdr;
        iov[0].iov_len = IWAN_HDR_LEN;
        iov[1].iov_base = ip_pkt;
        iov[1].iov_len = len;
        msg.msg_iov = iov;
        msg.msg_iovlen = 2;
        if (port_sendmsg(sockfd, &msg, 0) < 0)
            atomic_fetch_add(&g_send_drops, 1);
        else
            PROF_ADD(g_prof_srv_dlsend, len);
    }
    /* Deliberately NO sendmsg(ECONNREFUSED) teardown here: this socket is
     * unconnected, so on Linux sendmsg never returns ECONNREFUSED — an
     * ICMP port-unreachable is queued and surfaces on the NEXT receive
     * (which the main loop treats as EAGAIN/drained). Identifying the
     * dead peer from the error queue would need MSG_ERRQUEUE plumbing;
     * sessions of dead peers are instead reaped by purge_expired (120s
     * idle timeout) or by the client's own CLOSE. */
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
