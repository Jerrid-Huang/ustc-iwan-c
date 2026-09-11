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
#define TCP_RST 0x04
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
 * The first segment of a connection (its SYN — the only packet that
 * creates an entry) must always be treated as NEW data: the retransmit
 * heuristic reads client_max - s_orig, but with a fresh entry
 * client_max stays 0, so an initial ISN in the upper half of the seq
 * space ([2^31+1, 2^32-1]) wraps the subtraction into a small "back"
 * and is misclassified as a retransmit, wedging the counters forever.
 * The per-entry `seeded` flag marks the first-segment handoff so the
 * retransmit test only runs from the second segment onward.
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
    bool     seeded;             /* first segment already handled */
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
        free_slot->seeded = false;   /* fresh entry: first segment is
                                      * unconditionally new data */
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
    /* R20 (R09 M-3): echo_lookup released g_echo_mu, but the RMW on
     * client_max/emit_seq/seeded below is shared state (several SO_REUSEPORT
     * recv threads) — re-lock around the whole read/modify. The entry is
     * safe against mid-flight reclamation: a hit or just-created entry has
     * last_ms=now, so no other thread can idle-reclaim it for 60s. */
    pthread_mutex_lock(&g_echo_mu);
    if (!ec->seeded) {
        /* First segment for this 4-tuple (in practice its SYN, the only
         * segment that creates an entry): never a retransmit — always a
         * fresh new-data packet. The retransmit test below relies on a
         * valid client_max and would otherwise misfire for an initial
         * ISN in [2^31+1, 2^32-1] (a fresh client_max of 0 wraps
         * client_max - s_orig into a small "back"), freezing the state
         * machine. Seed the counters and skip the retransmit check. */
        ec->seeded = true;
    } else {
        /* unsigned subtraction: back is small when s_orig lags
         * client_max (retransmit), huge (wrapped) when s_orig is at or
         * past it */
        uint32_t back = (uint32_t)(ec->client_max - s_orig);
        if (back != 0 && back < 0x80000000u) {
            /* retransmit: re-echo at the position this content was
             * first mirrored to; counters do not move */
            *seq_out = ec->emit_seq - back;
            pthread_mutex_unlock(&g_echo_mu);
            return 0;
        }
    }
    *seq_out = ec->emit_seq;
    ec->client_max = s_orig + len;
    ec->emit_seq += len;
    pthread_mutex_unlock(&g_echo_mu);
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
/* F4 (R37 R1-D-1: re-keyed from "source IP" to "session + source class").
 * At most RATE_TOKEN_MISMATCH_MAX failed DATA/CLOSE token comparisons per
 * second for one session from sources that are NOT its current peer, and
 * at most RATE_TOKEN_MISMATCH_BOUND_MAX from frames that claim the
 * session's current peer address verbatim. Once a counter is at budget,
 * further DATA/CLOSE frames of that class for that session are dropped
 * BEFORE the token compare (counted in g_rate_drops, logged nowhere), so
 * the budget really caps how many guesses the server will test.
 *
 * Why 4: an honest client in transition (idle expiry, token refresh, NAT
 * rebinding) sends a handful of stale frames at most, and even a fully
 * stale ex-token device behind the same NAT is capped at 4 tested guesses
 * per second; a guesser working the 32-bit token space at that rate needs
 * ~34 years per session (2^32/4 s). It no longer matters that the old
 * key was the bare source IP: one misbehaving host behind a NAT (or the
 * same account's older device) can no longer blacklist every other
 * session sharing that address, because the budget is now the session's
 * own and is split by source class.
 *
 * Why the bound class is counted but NEVER gated (R37 R2 regression fix):
 * a pre-compare drop must key on something the attacker and the honest
 * client BOTH present, so a third party can always spend that budget on
 * the victim's behalf. An attacker able to forge the victim's exact
 * ip:port only had to sustain RATE_TOKEN_MISMATCH_BOUND_MAX forged
 * frames/s to make the server drop the victim's own (correct-token) DATA
 * before the compare; ECHO/PING keepalives do not draw on this budget,
 * so the client's stale-session watchdog never fires -> a silent,
 * permanent blackhole for any session whose peer address is spoofable.
 * The bound counter is therefore charged after a failed compare but NOT
 * consulted before one: the victim's frames are always compared and
 * always win, however many forged frames arrive. The cost is that a
 * spoofer who already knows the sid can test guesses at line rate; it
 * must still find the 32-bit token (and, blindly, the 16-bit sid), while
 * the unspoofable non-peer class stays capped at 4 tested guesses/s —
 * and that is the class every NAT neighbour / stale-token device lands
 * in. RATE_TOKEN_MISMATCH_BOUND_MAX is kept as the saturation point of
 * the observability counter (a bound-address mismatch storm is the
 * signature of source spoofing) and to document the class split. */
#define RATE_TOKEN_MISMATCH_MAX 4        /* non-peer sources, per session */
#define RATE_TOKEN_MISMATCH_BOUND_MAX 64 /* bound-peer address, per session */
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
/* F2: the per-source rate table is sharded by source-IP hash. Each shard
 * has its own lock + 64-bucket table; a given source always lands in the
 * SAME shard, so the per-source budget semantics are exactly preserved
 * (one source cannot earn N budgets by fanning flows across threads) while
 * contention on the old single global lock drops by RATE_SHARDS. The hash
 * keeps the Knuth top-bit spread: shard = top 4 hashed bits (28..31),
 * bucket = next 6 (22..27). RATE_BUCKETS must stay a multiple of
 * RATE_SHARDS. */
#define RATE_SHARDS             16
#define RATE_SHARD_BITS          6   /* log2(buckets per shard) */
#define RATE_BUCKETS_PER_SHARD  (RATE_BUCKETS / RATE_SHARDS)

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

static uint64_t server_dl_pkts(void);
/* R37-F3 (R3-M5): printf-like wrapper (vfprintf(stdout, fmt, ap)) — see
 * util.h; without the attribute its call sites were unchecked. On a
 * function definition GCC wants the attribute before the declarator. */
static void IWAN_PRINTF_LIKE(1, 2)
srv_log(const char *fmt, ...)
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
    /* R20 (F06-2): each g_up[tid] is RMW'd by recv thread tid while the
     * primary thread sums AND zeroes it in server_up_stats_print — atomic
     * fields remove the cross-thread data race on every counter. */
    _Atomic uint64_t n;
    _Atomic uint64_t parse;   /* frame parse + rate_allow + dispatch */
    _Atomic uint64_t find;    /* find_session + token + rebind + enc check */
    _Atomic uint64_t xor;     /* in-place decryption */
    _Atomic uint64_t write;   /* tun_write syscall */
    _Atomic uint64_t drop;    /* tun_write EAGAIN/failure drops */
    _Atomic uint64_t h1;      /* inner-IPv4 gate drops (malformed/spoofed) */
};

/* per-recv-thread stats (the multi-threaded uplink sums them on print) */
static struct up_stats g_up[IWAN_SRV_THREADS_MAX];

/* IWAN_SRV_TUN_SINGLE=1: uplink TUN writes go to the owner fd instead
 * of the multi-queue fan-out (A/B benchmark switch; cached at startup) */
static bool srv_tun_single(void)
{
    /* R20: called from every recv thread's handle_udp — atomic cache.
     * R37 R2: a boolean env must treat "0"/"false"/"no"/"off"/"" as OFF;
     * existence-only parsing made IWAN_SRV_TUN_SINGLE=0 mean ON, the
     * opposite of what an operator writing "=0" intends. */
    static _Atomic int v = -1;
    int c = atomic_load_explicit(&v, memory_order_relaxed);
    if (c < 0) {
        const char *e = getenv("IWAN_SRV_TUN_SINGLE");
        c = e && *e && strcmp(e, "0") != 0 && strcmp(e, "false") != 0 &&
            strcmp(e, "no") != 0 && strcmp(e, "off") != 0;
        atomic_store_explicit(&v, c, memory_order_relaxed);
    }
    return c != 0;
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
        sum.n += atomic_load_explicit(&g_up[t].n, memory_order_relaxed);
        sum.parse += atomic_load_explicit(&g_up[t].parse, memory_order_relaxed);
        sum.find += atomic_load_explicit(&g_up[t].find, memory_order_relaxed);
        sum.xor += atomic_load_explicit(&g_up[t].xor, memory_order_relaxed);
        sum.write += atomic_load_explicit(&g_up[t].write, memory_order_relaxed);
        sum.drop += atomic_load_explicit(&g_up[t].drop, memory_order_relaxed);
        sum.h1 += atomic_load_explicit(&g_up[t].h1, memory_order_relaxed);
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
            (double)sum.parse / (double)sum.n, (double)sum.find / (double)sum.n,
            (double)sum.xor / (double)sum.n, (double)sum.write / (double)sum.n,
            (double)(sum.parse + sum.find + sum.xor + sum.write) / (double)sum.n,
            (unsigned long long)sum.drop,
            (unsigned long long)sum.h1,
            (unsigned long long)server_dl_pkts(),
            (unsigned long long)atomic_load(&g_dl_drops),
            (unsigned long long)atomic_load(&g_rate_drops));
    for (int t = 0; t < g_up_nthreads; t++) {
        atomic_store_explicit(&g_up[t].n, 0, memory_order_relaxed);
        atomic_store_explicit(&g_up[t].parse, 0, memory_order_relaxed);
        atomic_store_explicit(&g_up[t].find, 0, memory_order_relaxed);
        atomic_store_explicit(&g_up[t].xor, 0, memory_order_relaxed);
        atomic_store_explicit(&g_up[t].write, 0, memory_order_relaxed);
        atomic_store_explicit(&g_up[t].drop, 0, memory_order_relaxed);
        atomic_store_explicit(&g_up[t].h1, 0, memory_order_relaxed);
    }
    /* dl counter is cumulative (per-second delta is printed by the
     * caller's diff of consecutive lines); do not reset here */
}

/* best-effort scrub of secrets, immune to optimizer elision */
/* wipe: shared constant-time erasure from crypto.h */

/* printable-only copy of an attacker-controlled string for logging.
 *
 * R3-L20: C0 + DEL alone is not enough — the C1 block (0x80..0x9F) holds
 * the 8-bit CSI (0x9B), OSC (0x9D) and the other escape introducers, so
 * a username like "\x9b31m" (8-bit SGR) or "\x9b2J" (erase display) went
 * to stdout raw and let an unauthenticated OPEN forge terminal output.
 * The C1 range is also the UTF-8 continuation-byte range, so a
 * byte-wise escape would corrupt every multi-byte character that
 * contains one (the U+20AC sign is E2 82 AC). Decode instead: a structurally
 * valid UTF-8 sequence is copied verbatim; a bare C1 byte, and the
 * two-byte UTF-8 encoding of a C1 code point (C2 80..C2 9F), are
 * neutralised. Bytes >= 0xA0 that are not a valid lead byte are left
 * alone, exactly as before. */
static size_t utf8_seq_len(unsigned char c)
{
    if (c >= 0xC2 && c <= 0xDF)
        return 2;
    if (c >= 0xE0 && c <= 0xEF)
        return 3;
    if (c >= 0xF0 && c <= 0xF4)
        return 4;
    return 0;   /* ASCII, continuation byte, overlong lead, 0xF5..0xFF */
}

static void log_escape(const char *in, char out[], size_t outsz)
{
    size_t i = 0;
    if (outsz == 0)
        return;
    while (*in && i + 1 < outsz) {
        unsigned char c = (unsigned char)*in;
        size_t seq = utf8_seq_len(c);
        if (seq >= 2) {
            size_t k;
            for (k = 1; k < seq; k++) {
                if (((unsigned char)in[k] & 0xC0) != 0x80)
                    break;
            }
            if (k == seq) {
                if (i + seq + 1 > outsz)
                    break;              /* no room for the whole char */
                /* C2 80..C2 9F is U+0080..U+009F: a C1 control, not text */
                if (seq != 2 || c != 0xC2 ||
                    (unsigned char)in[1] < 0x80 ||
                    (unsigned char)in[1] > 0x9F) {
                    memcpy(out + i, in, seq);
                    i += seq;
                    in += seq;
                    continue;
                }
            }
        }
        if (c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f))
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
    /* R1-D-1: the DATA/CLOSE token-mismatch budget is deliberately NOT a
     * field of this per-source bucket any more. Keyed by source IP it let
     * one host behind a NAT (or an ex-token device of the same account)
     * spend the budget that gated every session on that address, silently
     * dropping the neighbours' legitimate data. It now lives in
     * struct server_session as two (session, source-class) counters —
     * see tok_budget_over / tok_budget_charge / tok_rebind_allowed. */
};

struct rate_shard {
    struct rate_bucket buckets[RATE_BUCKETS_PER_SHARD];
    pthread_mutex_t mu;
};

static struct rate_shard g_rate_shards[RATE_SHARDS];

/* guards g_rate_shards: each shard has its own lock, taken for the
 * unauthenticated control types (rate_allow). The F4/R1-D-1 DATA/CLOSE
 * token-mismatch budget is NOT in this table any more: it is per
 * (session, source class), lives in struct server_session and is
 * protected by ctx->sess_lock (see tok_budget_over and friends). Sections
 * are short and, per flow, effectively uncontended (SO_REUSEPORT pins
 * one client flow to one recv thread), but independent flows now spread
 * over RATE_SHARDS locks instead of one global one. Lock order is always
 * sess_lock (outer) -> shard lock (inner) when both are held; the DATA
 * path releases sess_lock before touching the rate table. A source's
 * shard follows from its IP, so no code path holds two shard locks. */
static int g_rate_shards_init;

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
    /* one-time init of the per-shard locks (called once before the recv
     * threads are spawned; guarded so a second call is a no-op) */
    if (!g_rate_shards_init) {
        for (int i = 0; i < RATE_SHARDS; i++)
            pthread_mutex_init(&g_rate_shards[i].mu, NULL);
        g_rate_shards_init = 1;
    }
    g_rate_open_max = rate_limit_env("IWAN_RATE_OPEN_MAX",
                                     RATE_OPEN_MAX_DEFAULT);
    g_rate_echo_max = rate_limit_env("IWAN_RATE_ECHO_MAX",
                                     RATE_ECHO_MAX_DEFAULT);
}

/* source address -> owning shard. Top 4 hashed bits select the shard, so
 * sequential IPs spread evenly over all 16 shards (same Knuth hash as the
 * bucket index below). */
static inline unsigned rate_ip_shard(uint32_t ip)
{
    unsigned h = (unsigned)((ip * RATE_HASH_MUL) >> RATE_HASH_SHIFT);
    return (h >> RATE_SHARD_BITS) & (RATE_SHARDS - 1);
}

/* release the lock rate_bucket_enter took; pass the SAME ip that was
 * passed to enter (it selects the shard). */
static inline void rate_shard_unlock(uint32_t ip)
{
    pthread_mutex_unlock(&g_rate_shards[rate_ip_shard(ip)].mu);
}

/* locate (or claim) the rate bucket for ip inside its shard; caller must
 * hold that shard's lock. Linear probing: the hashed slot may belong to
 * another source, so scan up to RATE_PROBE_MAX slots for a bucket of this
 * IP or a never-used one instead of clobbering a neighbour's counters
 * (that would let one source reset another's window or dodge the limit by
 * rehashing). Only when the whole probe window is occupied by other
 * sources do we evict the slot whose window started longest ago. */
static struct rate_bucket *rate_bucket_find(struct rate_shard *sh,
                                            uint32_t ip)
{
    /* low 6 hashed bits within the shard: bits 22..27 (the shard took
     * 28..31), still evenly spread for packet-flood neighbour IPs */
    unsigned h = (unsigned)((ip * RATE_HASH_MUL) >> RATE_HASH_SHIFT) &
                 (RATE_BUCKETS_PER_SHARD - 1);
    unsigned evict = 0;
    uint64_t oldest = UINT64_MAX;

    for (unsigned i = 0; i < RATE_PROBE_MAX; i++) {
        struct rate_bucket *c = &sh->buckets[(h + i) % RATE_BUCKETS_PER_SHARD];
        if (c->win < oldest) {
            oldest = c->win;
            evict = i;
        }
        if (c->ip == ip || (c->ip == 0 && c->win == 0)) {
            return c;
        }
    }
    return &sh->buckets[(h + evict) % RATE_BUCKETS_PER_SHARD];
}

/* (re)start the source's window when the bucket is stale or was just
 * evicted from another source; caller must hold the shard lock. */
static void rate_bucket_touch(struct rate_bucket *b, uint32_t ip, uint64_t now)
{
    if (b->ip != ip || now - b->win >= RATE_WINDOW_MS) {
        b->ip = ip;
        b->win = now;
        b->open_cnt = b->ping_cnt = b->echo_cnt = 0;
    }
}

/* shared skeleton for the per-source rate paths below: lock the source's
 * shard, (re)locate its bucket, (re)start its window, and hand the bucket
 * back with the lock STILL HELD — the caller does its per-type accounting
 * and then calls rate_shard_unlock(ip) (the counter read-modify-write must
 * stay inside the critical section). Small enough that the compiler
 * inlines it on the per-packet path. */
static struct rate_bucket *rate_bucket_enter(uint32_t ip, uint64_t now)
{
    struct rate_shard *sh = &g_rate_shards[rate_ip_shard(ip)];
    pthread_mutex_lock(&sh->mu);
    struct rate_bucket *b = rate_bucket_find(sh, ip);
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
    /* the sharded rate tables are shared by the multi-threaded uplink
     * recv threads; the per-shard mutex is taken on the unauthenticated
     * control types above (the F4/R1-D-1 DATA/CLOSE budget is no longer
     * here — it is per session, under ctx->sess_lock) */
    b = rate_bucket_enter(ip, now);
    /* independent per-type counters: a PING flood cannot eat the ECHO
     * budget (or vice versa); OPEN keeps its own, tighter limit */
    cnt = (typ == PT_OPEN) ? &b->open_cnt :
          (typ == PT_PING_REQ) ? &b->ping_cnt : &b->echo_cnt;
    if (*cnt >= limit)
        ok = false;
    else
        (*cnt)++;
    rate_shard_unlock(ip);
    if (!ok)
        atomic_fetch_add(&g_rate_drops, 1);
    return ok;
}

/* ---- F4/R1-D-1: per-session token-mismatch budget (DATA/CLOSE) ----
 *
 * The budget used to be keyed by the bare source address, which let one
 * NAT neighbour (or the same account's older device) spend the budget that
 * gated every other session on that address. It is now per (session,
 * source class): tok_mis_cnt counts wrong-token frames from a source that
 * is NOT the session's current peer, tok_mis_bound counts frames that
 * claim that peer address verbatim, and tok_mis_win windows both.
 *
 * Locking: the reads below are pure and run under ctx->sess_lock in ANY
 * mode (the DATA fast path holds only the read lock, so it can still
 * pre-check before the token compare without taking the write lock);
 * tok_budget_charge mutates and therefore runs under the WRITE lock. */

/* true while the session's mismatch window is running, i.e. while the two
 * counters describe "this second". Pure. */
static bool tok_win_live(const struct server_session *s, uint64_t now)
{
    return s->tok_mis_win != 0 && now - s->tok_mis_win < RATE_WINDOW_MS;
}

/* Pre-check for the NON-PEER class only: true when this session's
 * unbound-source budget is spent. The caller must then drop the frame
 * WITHOUT comparing the token, so the budget really caps how many guesses
 * the server ever tests. Only sources that are NOT the session's current
 * peer can charge this counter, so gating on it can never starve the
 * session's legitimate (bound) client — which is exactly why the bound
 * class is NOT pre-checked (see the RATE_TOKEN_MISMATCH_* note above).
 * Pure — safe under the read lock. */
static bool tok_budget_over(const struct server_session *s, uint64_t now)
{
    return tok_win_live(s, now) && s->tok_mis_cnt >= RATE_TOKEN_MISMATCH_MAX;
}

/* Charge one wrong-token frame to this session's class counter, rolling
 * the window first. Caller holds ctx->sess_lock in WRITE mode. The bound
 * class is charged for observability only — it never gates a frame (see
 * the RATE_TOKEN_MISMATCH_* note): a third party can spend it, so using
 * it as a pre-compare budget would blackhole the session's real peer. */
static void tok_budget_charge(struct server_session *s, bool bound,
                              uint64_t now)
{
    uint32_t *cnt;
    uint32_t max;

    if (!tok_win_live(s, now)) {   /* stale or never started: new window */
        s->tok_mis_win = now;
        s->tok_mis_cnt = 0;
        s->tok_mis_bound = 0;
    }
    cnt = bound ? &s->tok_mis_bound : &s->tok_mis_cnt;
    max = bound ? (uint32_t)RATE_TOKEN_MISMATCH_BOUND_MAX
                : (uint32_t)RATE_TOKEN_MISMATCH_MAX;
    if (*cnt < max)
        (*cnt)++;
}

/* Rebind gate (the old per-source rate_token_zero, now per session): a
 * new source may take over the session only while no unbound source has
 * charged a mismatch against THIS session in the current window. That
 * keeps both halves of the original test — an over-budget sprayer has
 * cnt >= MAX > 0 and fails, and a sub-budget sprayer with 1..MAX-1 also
 * fails — while a guess aimed at a different session (or at a different
 * address behind the same NAT) no longer closes this session's door.
 * Pure. */
static bool tok_rebind_allowed(const struct server_session *s, uint64_t now)
{
    return !tok_win_live(s, now) || s->tok_mis_cnt == 0;
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
static uint64_t server_dl_pkts(void)
{
    return atomic_load(&g_dl_pkts);
}

/* count n downlink sends that failed (sendmmsg batch remainder): the
 * caller (iwan_server.c's per-queue batch) drops the rest of a batch on
 * the first error, same contract as the per-packet path */
void server_add_send_drops(unsigned long long n)
{
    atomic_fetch_add(&g_send_drops, n);
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

/* Charge a wrong-token DATA frame to the session's budget. The DATA fast
 * path holds only the READ lock, so it releases it and calls this: take
 * the write lock, re-find the session by sid, and charge the mismatch
 * only if the frame really is still a mismatch for that session — a
 * racing re-OPEN (new token, same sid) must not be charged for a guess
 * aimed at the previous token. R1-D-1. */
static void tok_charge_upgrade(struct server_ctx *ctx, uint16_t sid,
                              uint32_t tok, const struct sockaddr_in *peer,
                              uint64_t now)
{
    struct server_session *s;
    bool bound;

    pthread_rwlock_wrlock(&ctx->sess_lock);
    s = find_session_unlocked(ctx, sid);
    if (s && CRYPTO_memcmp(&s->token, &tok, sizeof tok) != 0) {
        bound = memcmp(&s->peer, peer, sizeof *peer) == 0;
        tok_budget_charge(s, bound, now);
    }
    pthread_rwlock_unlock(&ctx->sess_lock);
}

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
        /* M-4: burn an equal-cost dummy derivation so an unknown-username
         * rejection takes the same time as a known user's wrong password —
         * prevents remote account enumeration by timing (the real compare
         * is already CRYPTO_memcmp constant-time; this closes the
         * path-existence side channel). The dummy never participates in
         * an accept. */
        uint8_t dummy[16];
        static const char dummy_pass[] = "iw-no-such-account-dummy";
        encrypt_password(dummy_pass, a.user, dummy);
        (void)CRYPTO_memcmp(dummy, a.ct, sizeof a.ct);
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
        /* sid carries only the low 16 bits of the assigned IP: with a
         * pool wider than 65536, two distinct IPs share one sid and the
         * "replace same sid" step below would evict a live session that
         * is actually a different user. Reject the impossible config
         * instead of corrupting the session table. */
        if (pool > 65536) {
            pthread_rwlock_unlock(&ctx->sess_lock);
            log_err("server subnet wider than /16 (%u addresses): "
                    "session id space exhausted; use a /16 or narrower "
                    "subnet", (unsigned)pool);
            open_reject(sockfd, peer, a.user, "server full");
            return;
        }
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
    /* never mint a zero token: auth.c's parse_ack rejects tok==0 ACKs, so
     * the user could never connect on that OPEN */
    do {
        tok = rand_u32();
    } while (tok == 0);

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
    /* R1-D-1 source-class tests: "this frame claims the session's current
     * peer address verbatim" (the bound class) vs any other source. */
    bool peer_is_peer = false;  /* PT_DATA / PT_DATA_ENC */
    bool cls_bound = false;     /* PT_CLOSE */

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
            pthread_rwlock_rdlock(&ctx->sess_lock);
            s = find_session_unlocked(ctx, sid);
            if (!s) {
                /* R1-D-1: an unknown sid costs one O(1) table probe and
                 * charges NO per-source state, so a host spraying random
                 * sids can no longer blacklist the sessions behind its
                 * NAT (the old code fed those frames to a per-IP counter). */
                pthread_rwlock_unlock(&ctx->sess_lock);
                return;
            }
            /* F4 (per session, R1-D-1; R37 R2 regression fix): the
             * pre-compare budget is applied ONLY to the non-peer class —
             * a source that is not this session's peer. That class cannot
             * be presented by the session's legitimate client, so gating
             * on it caps tested guesses (4/s) without ever letting a
             * third party starve the real client. The bound class (source
             * == s->peer verbatim) is compared first and therefore never
             * blackholed by a spoofer: see tok_budget_over()'s note. */
            peer_is_peer = memcmp(&s->peer, peer, sizeof *peer) == 0;
            if (!peer_is_peer && tok_budget_over(s, now)) {
                pthread_rwlock_unlock(&ctx->sess_lock);
                atomic_fetch_add(&g_rate_drops, 1);
                return;
            }
            if (CRYPTO_memcmp(&s->token, &tok, sizeof tok) != 0) {
                pthread_rwlock_unlock(&ctx->sess_lock);
                tok_charge_upgrade(ctx, sid, tok, peer, now);
                return; /* wrong token: drop */
            }
            /* source binding: only the session's peer may drive the
             * session; first valid-token packet from a new source rebinds
             * it (NAT or port rebinding tolerance). Rebinds are rare, so
             * the common path holds only the read lock. */
            if (!peer_is_peer) {
                pthread_rwlock_unlock(&ctx->sess_lock);
                pthread_rwlock_wrlock(&ctx->sess_lock);
                s = find_session_unlocked(ctx, sid);
                if (!s || CRYPTO_memcmp(&s->token, &tok, sizeof tok) != 0) {
                    if (s)
                        tok_budget_charge(s,
                                          memcmp(&s->peer, peer,
                                                 sizeof *peer) == 0, now);
                    pthread_rwlock_unlock(&ctx->sess_lock);
                    return; /* session gone or token rotated: drop */
                }
                /* F4/R1-D-1 rebind gate: a new source may take over the
                 * session only while no unbound source has charged a
                 * mismatch against THIS session in the current window
                 * (tok_rebind_allowed). An honest roamer arrives with a
                 * clean window and rebinds on this first packet, exactly
                 * as before. This frame already carried the right token,
                 * so no guess is tested here. */
                if (memcmp(&s->peer, peer, sizeof *peer) != 0) {
                    if (!tok_rebind_allowed(s, now)) {
                        pthread_rwlock_unlock(&ctx->sess_lock);
                        return;
                    }
                    s->peer = *peer;
                }
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
                atomic_fetch_add_explicit(&g_up[tid].h1, 1, memory_order_relaxed);
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
                        atomic_fetch_add_explicit(&g_up[tid].h1, 1, memory_order_relaxed);
                        if (debug_enabled()) {
                            /* short frames can fail the sanity check
                             * before in[4..6] exist — never read past the
                             * datagram end (stale slot bytes), just log a
                             * shorter diagnosis */
                            if (inlen >= 8)
                                log_debug("uplink drop: bad inner IPv6 "
                                          "(sid 0x%04x) v=%u nexth=%u "
                                          "plen=%u",
                                          sid, in[0] >> 4, in[6],
                                          ((unsigned)in[4] << 8) | in[5]);
                            else
                                log_debug("uplink drop: bad inner IPv6 "
                                          "(sid 0x%04x) v=%u",
                                          sid, in[0] >> 4);
                        }
                        break;
                    }
                } else {
                    if (ipv4_pkt_ok(in, inlen, &saddr, &daddr) != 0 ||
                        saddr != s_ip) {
                        atomic_fetch_add_explicit(&g_up[tid].h1, 1, memory_order_relaxed);
                        if (debug_enabled()) {
                            /* short frames can fail the sanity check
                             * before the inner header bytes exist — never
                             * read past the datagram end (stale slot
                             * bytes); skip the unavailable fields */
                            if (inlen >= 20)
                                log_debug("uplink drop: bad inner IPv4 "
                                          "(sid 0x%04x) %u.%u.%u.%u->"
                                          "%u.%u.%u.%u v=%u ihl=%u tot=%u",
                                          sid, in[12], in[13], in[14],
                                          in[15], in[16], in[17], in[18],
                                          in[19], in[0] >> 4, in[0] & 0x0F,
                                          ((unsigned)in[2] << 8) | in[3]);
                            else if (inlen >= 4)
                                log_debug("uplink drop: bad inner IPv4 "
                                          "(sid 0x%04x) v=%u ihl=%u tot=%u",
                                          sid, in[0] >> 4, in[0] & 0x0F,
                                          ((unsigned)in[2] << 8) | in[3]);
                            else
                                log_debug("uplink drop: bad inner IPv4 "
                                          "(sid 0x%04x) v=%u ihl=%u",
                                          sid, in[0] >> 4, in[0] & 0x0F);
                        }
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
                    atomic_fetch_add_explicit(&g_up[tid].drop, 1, memory_order_relaxed);
                }
            } else {
                /* --no-tun test mode: echo the packet back (zero-latency
                 * lossless mirror) so tunnel + netstack throughput can
                 * be benchmarked without a TUN device or target network */
                if (echo_mirror(ctx, (uint8_t *)raw + IWAN_HDR_LEN,
                                len - IWAN_HDR_LEN, sockfd) != 0)
                    atomic_fetch_add_explicit(&g_up[tid].drop, 1, memory_order_relaxed);
            }
            if (debug_enabled()) {
                tc = now_ns();
                atomic_fetch_add_explicit(&g_up[tid].parse, (tb - ta), memory_order_relaxed);
                atomic_fetch_add_explicit(&g_up[tid].find, (tx0 - tb), memory_order_relaxed);
                atomic_fetch_add_explicit(&g_up[tid].xor, (tx1 - tx0), memory_order_relaxed);
                atomic_fetch_add_explicit(&g_up[tid].write, (tc - tx1), memory_order_relaxed);
                atomic_fetch_add_explicit(&g_up[tid].n, 1, memory_order_relaxed);
            }
            break;
        }

    case PT_CLOSE:
        if (!verify_sig(raw, len))
            return;
        pthread_rwlock_wrlock(&ctx->sess_lock);
        s = find_session_unlocked(ctx, sid);
        if (!s) {
            /* R1-D-1: unknown sid — one table probe, no per-source state */
            pthread_rwlock_unlock(&ctx->sess_lock);
            return;
        }
        /* F4/R1-D-1 + R37 R2: pre-check the token compare ONLY for the
         * non-peer class (see the DATA path / tok_budget_over note); a
         * bound-class CLOSE is always compared, so a spoofer cannot get
         * the real peer's CLOSE dropped. */
        cls_bound = memcmp(&s->peer, peer, sizeof *peer) == 0;
        if (!cls_bound && tok_budget_over(s, now)) {
            pthread_rwlock_unlock(&ctx->sess_lock);
            atomic_fetch_add(&g_rate_drops, 1);
            return;
        }
        if (CRYPTO_memcmp(&s->token, &tok, sizeof tok) == 0) {
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
            /* a bad-token CLOSE is a guess: charge this session's budget,
             * not a per-source blacklist */
            tok_budget_charge(s, cls_bound, now);
        }
        pthread_rwlock_unlock(&ctx->sess_lock);
        break;

    case PT_PING_REQ:
    case PT_ECHO_REQ: {
        int valid = 0; /* ECHO_RES only for a verified (found+tok) session */
        if (!verify_sig(raw, len))
            return;
        /* Common path (same peer, valid token) takes only the read
         * lock: last_active is an atomic store, so keepalives no longer
         * serialize the whole session table against every DATA reader.
         * A peer change (rebind) upgrades to the write lock — gated on
         * the session's own unbound-source mismatch history (F4/R1-D-1)
         * so a guessed token cannot claim the session from an address
         * that has been spraying at it. R34-1: ECHO_RES is only a per-session keepalive
         * acknowledgement — it must not be a liveness oracle, so it is
         * sent only when the session was found AND its token matched
         * (the same condition that refreshed last_active above). PING_RSP
         * stays unconditional: `iwan ping` is an unauthenticated server
         * reachability probe with the fixed wildcard IWAN_PING_SID /
         * IWAN_PING_TOK and is never read by the tunnel's stale-session
         * watchdog. */
        pthread_rwlock_rdlock(&ctx->sess_lock);
        s = find_session_unlocked(ctx, sid);
        if (s && CRYPTO_memcmp(&s->token, &tok, sizeof tok) == 0) {
            if (memcmp(&s->peer, peer, sizeof *peer) == 0) {
                atomic_store(&s->last_active_ms, now_ms()); /* keepalive */
                valid = 1;
                pthread_rwlock_unlock(&ctx->sess_lock);
            } else {
                pthread_rwlock_unlock(&ctx->sess_lock);
                pthread_rwlock_wrlock(&ctx->sess_lock);
                s = find_session_unlocked(ctx, sid);
                if (s && CRYPTO_memcmp(&s->token, &tok, sizeof tok) == 0 &&
                    tok_rebind_allowed(s, now)) {
                    s->peer = *peer;
                    atomic_store(&s->last_active_ms, now_ms());
                    valid = 1;
                }
                pthread_rwlock_unlock(&ctx->sess_lock);
            }
        } else {
            pthread_rwlock_unlock(&ctx->sess_lock);
        }
        if (typ == PT_ECHO_REQ && !valid)
            break; /* unknown session / bad token: silent drop, like the
                    * PT_DATA path — the client's watchdog then concludes
                    * the tunnel is dead and reconnects */
        buf_init(&b);
        if (typ == PT_PING_REQ)
            ctrl_hdr(&b, PT_PING_RSP, 0, IWAN_PING_SID, IWAN_PING_TOK);
        else
            ctrl_hdr(&b, PT_ECHO_RES, raw[1], sid, tok);
        udp_send(sockfd, peer, b.data, b.len);
        buf_free(&b);
        break;
    }

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
    /* Do not mirror a pure ACK (no payload, no SYN/FIN/RST). Echoing it
     * back puts the client's own ACK in front of it again; Windows
     * reacts with another ACK, the mirror echoes that too, and the two
     * sides ping-pong pure ACKs forever while data stalls. The echo
     * table is still refreshed above (ACKs keep the connection from
     * being reclaimed), and data echoes already carry the ACK that
     * advances the client's send window. */
    if (paylen == 0 && (flags & TCP_ACK) &&
        !(flags & (TCP_SYN | TCP_FIN | TCP_RST))) {
        if (debug_enabled())
            log_debug("echo6: drop pure ACK");
        return -1;
    }
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
    /* Do not mirror a pure ACK: echoing the client's ACK back makes
     * Windows send another ACK, which is echoed again — a self-
     * sustaining ACK storm that stalls data. The table lookup above
     * still refreshes the connection, and data echoes already carry
     * the ACK that advances the client's send window. */
    if (paylen == 0 && (flags & TCP_ACK) &&
        !(flags & (TCP_SYN | TCP_FIN | TCP_RST))) {
        if (debug_enabled())
            log_debug("echo: drop pure ACK");
        return -1;
    }
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

/* gate + session snapshot + outer header + in-place XOR; returns false
 * when the packet was dropped or consumed locally (nothing to send).
 * Shared by handle_tun_downlink (prep + direct send) and the TUN reader
 * pool's batching path (iwan_server.c stages the [hdr, payload] pair
 * into a per-queue sendmmsg batch instead). The in-place XOR contract
 * is unchanged: the buffer belongs to the caller until this returns. */
bool tun_prep_downlink(struct server_ctx *ctx, uint8_t *ip_pkt, size_t len,
                       struct server_sess_snap *snap_out, uint8_t *hdr_out)
{
    struct server_sess_snap snap;
    uint32_t saddr, daddr;

    if (len < 20 || len > 65536)
        return false;
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
            return false;
        }
        /* server-bound (its own derived ULA): consumed locally */
        {
            uint8_t srv6[16];
            ip6_derive_ula(ip4_u32(ctx->server_ip), srv6);
            if (memcmp(d6, srv6, 16) == 0)
                return false;
        }
        /* session lookup: the client's ULA embeds its inner IPv4 in the
         * low 32 bits (protocol.h), so the IPv4 session table applies.
         * R23-F1 (asymmetry with the uplink H1 full-16B ULA check): only a
         * genuine fd00::/96 client ULA may select a session — an arbitrary
         * v6 dest whose low 32 bits happen to match a client IP must never
         * be routed to that session (gate gap). */
        {
            bool ula_prefix = d6[0] == IWAN_IP6_ULA_BYTE0;
            for (int k = 1; k < 12; k++)
                if (d6[k] != 0)
                    ula_prefix = false;
            if (!ula_prefix)
                return false;
        }
        pthread_rwlock_rdlock(&ctx->sess_lock);
        {
            struct server_session *s = find_session_by_ip_unlocked(ctx, d6 + 12);
            if (!s) {
                pthread_rwlock_unlock(&ctx->sess_lock);
                return false;
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
            return false;
        }
        if (daddr == ip4_u32(ctx->server_ip)) {
            /* server-bound packet: the gate allows it, but no client owns
             * this address — the server machine consumes it locally */
            return false;
        }
        /* snapshot under the read lock; the send happens lock-free */
        pthread_rwlock_rdlock(&ctx->sess_lock);
        {
            struct server_session *s = find_session_by_ip_unlocked(ctx, ip_pkt + 16);
            if (!s) {
                pthread_rwlock_unlock(&ctx->sess_lock);
                return false;
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
            snap.token, hdr_out);
    if (snap.enc)
        xor_crypt(ip_pkt, len, snap.xor_key, sizeof snap.xor_key);
    *snap_out = snap;
    return true;
}

void handle_tun_downlink(struct server_ctx *ctx, uint8_t *ip_pkt, size_t len,
                         int sockfd)
{
    struct server_sess_snap snap;
    uint8_t hdr[IWAN_HDR_LEN];

    if (!tun_prep_downlink(ctx, ip_pkt, len, &snap, hdr))
        return;
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
