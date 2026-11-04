#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "protocol.h"
#include "server_rate.h"
#include "util.h"

#define RATE_BUCKETS            1024   /* per-source limit table for OPEN/PING/ECHO */
#define RATE_WINDOW_MS          1000
#define RATE_OPEN_MAX_DEFAULT   20     /* OPENs per source per window */
#define RATE_ECHO_MAX_DEFAULT   60     /* PING and ECHO, each per window */
#define RATE_MISS_MAX_DEFAULT   2000
#define RATE_TOKBAD_MAX_DEFAULT 4096
#define RATE_CLOSE_MAX_DEFAULT  4096
#define SRV_THROTTLE_DEFAULT_MS 2u

#define RATE_HASH_MUL           2654435761u
#define RATE_HASH_SHIFT         22     /* keep top 10 hashed bits -> 1024 buckets */
#define RATE_PROBE_MAX          8      /* linear-probe depth before eviction */

#define RATE_SHARDS             16
#define RATE_SHARD_BITS         6      /* log2(buckets per shard) */
#define RATE_BUCKETS_PER_SHARD  (RATE_BUCKETS / RATE_SHARDS)
#define RATE_GATE_WAYS          16

/* Family-agnostic rate-limit key. All 128 bits of a v6 address must participate (never take only the first 4 bytes: many v6 clients
 * under the same /32 prefix would be merged into one bucket, and a single client eats the whole 20/s OPEN budget);
 * v4 hashing is bit-for-bit identical to before v6 was added, so the v4 rate-limit behavior and bucket distribution are
 * completely unchanged. */
struct rate_key {
    uint8_t addr[16];   /* network byte order; AF_INET uses only addr[0..3], the rest is 0 */
    uint8_t fam;        /* AF_INET / AF_INET6 */
};

struct rate_bucket {
    /* Store the full source address (not an index hash): the v4 key is the exact 32-bit address, v6 is
     * the exact 16-byte address, so different sources never share a bucket. */
    struct rate_key key;
    /* Whether the slot is in use. An explicit valid bit replaces the old `ip != 0` empty-slot sentinel: the first
     * 4 bytes of a v6 address are often 0 (::1, ::ffff:0:x...), and the old sentinel would treat different sources as the same
     * empty slot. */
    bool valid;
    uint64_t win;      /* window start (monotonic ms) */
    uint32_t open_cnt, ping_cnt, echo_cnt;
    uint32_t miss_cnt;
    uint32_t tokbad_cnt;
    uint32_t close_cnt;
};

struct rate_shard {
    struct rate_bucket buckets[RATE_BUCKETS_PER_SHARD];
    pthread_mutex_t mu;
};

static struct rate_shard g_rate_shards[RATE_SHARDS];

struct rate_gate {
    /* Full source identity: v4 = 32-bit network-order address (bit-for-bit the ip stored by the old implementation),
     * v6 = 64-bit FNV-1a hash (collision probability 2^-64; the slot only remembers "this source is over budget",
     * it is not a counter table). */
    _Atomic uint64_t id;
    _Atomic uint8_t valid;          /* explicit occupancy bit, replaces the `ip != 0` sentinel */
    _Atomic uint64_t over_until_ms; /* budget refills at this monotonic ms */
};

struct rate_gate_set {
    struct rate_gate way[RATE_GATE_WAYS];
};

static struct rate_gate_set g_rate_gate[RATE_BUCKETS];
static struct rate_gate_set g_tokbad_gate[RATE_BUCKETS];
static struct rate_gate_set g_close_gate[RATE_BUCKETS];

static int g_rate_shards_init;
static atomic_ullong g_rate_drops;
static uint64_t g_rate_drops_reported;

static unsigned g_rate_open_max = RATE_OPEN_MAX_DEFAULT;
static unsigned g_rate_echo_max = RATE_ECHO_MAX_DEFAULT;
static unsigned g_rate_miss_max = RATE_MISS_MAX_DEFAULT;
static unsigned g_rate_tokbad_max = RATE_TOKBAD_MAX_DEFAULT;
static unsigned g_rate_close_max = RATE_CLOSE_MAX_DEFAULT;
static unsigned g_up_throttle_ms = SRV_THROTTLE_DEFAULT_MS;

unsigned server_rate_get_throttle_ms(void)
{
    return g_up_throttle_ms;
}

void server_rate_drop_inc(void)
{
    atomic_fetch_add(&g_rate_drops, 1);
}

uint64_t server_rate_drops_total(void)
{
    return (uint64_t)atomic_load_explicit(&g_rate_drops, memory_order_relaxed);
}

void server_rate_drops_mark_reported(void)
{
    g_rate_drops_reported = (uint64_t)atomic_load_explicit(&g_rate_drops, memory_order_relaxed);
}

void server_rate_drops_maybe_print(void)
{
    static uint64_t last_ms;
    uint64_t now = now_ms();
    uint64_t total = (uint64_t)atomic_load_explicit(&g_rate_drops, memory_order_relaxed);

    if (total == g_rate_drops_reported)
        return;
    if (now - last_ms < 1000)
        return;
    last_ms = now;
    fprintf(stderr,
            "[rate-limits] %llu drops this second (%llu cumulative)\n",
            (unsigned long long)(total - g_rate_drops_reported),
            (unsigned long long)total);
    g_rate_drops_reported = total;
}

static bool rate_limit_parse(const char *s, unsigned *out)
{
    uint64_t v = 0;

    if (!s || !*s)
        return false;
    for (const char *p = s; *p; p++) {
        uint64_t d;
        if (*p < '0' || *p > '9')
            return false;
        d = (uint64_t)(*p - '0');
        if (v > (65535u - d) / 10u)
            return false;
        v = v * 10 + d;
    }
    if (v == 0)
        return false;
    *out = (unsigned)v;
    return true;
}

static unsigned rate_limit_env(const char *name, unsigned dflt)
{
    const char *v = getenv(name);
    unsigned n;

    if (!v)
        return dflt;
    if (!rate_limit_parse(v, &n)) {
        log_err("invalid %s='%s': using default %u", name, v, dflt);
        return dflt;
    }
    return n;
}

void server_rate_limits_init(void)
{
    if (!g_rate_shards_init) {
        for (int i = 0; i < RATE_SHARDS; i++)
            pthread_mutex_init(&g_rate_shards[i].mu, NULL);
        g_rate_shards_init = 1;
    }
    g_rate_open_max = rate_limit_env("IWAN_RATE_OPEN_MAX", RATE_OPEN_MAX_DEFAULT);
    g_rate_echo_max = rate_limit_env("IWAN_RATE_ECHO_MAX", RATE_ECHO_MAX_DEFAULT);
    g_rate_miss_max = rate_limit_env("IWAN_RATE_MISS_MAX", RATE_MISS_MAX_DEFAULT);
    g_rate_tokbad_max = rate_limit_env("IWAN_RATE_TOKBAD_MAX", RATE_TOKBAD_MAX_DEFAULT);
    g_rate_close_max = rate_limit_env("IWAN_RATE_CLOSE_MAX", RATE_CLOSE_MAX_DEFAULT);
    g_up_throttle_ms = rate_limit_env("IWAN_SRV_THROTTLE_MS", SRV_THROTTLE_DEFAULT_MS);
}

/* Build a rate-limit key from the normalized outer peer */
static struct rate_key rate_key_from_peer(const struct iwan_peer *peer)
{
    struct rate_key k;

    memset(&k, 0, sizeof k);
    memcpy(k.addr, peer->addr, sizeof k.addr);
    k.fam = (uint8_t)peer->family;
    return k;
}

static inline bool rate_key_is_v4(const struct rate_key *k)
{
    return k->fam == (uint8_t)AF_INET;
}

/* 32-bit network-order address for AF_INET (= the value the old implementation used as the key) */
static inline uint32_t rate_key_v4(const struct rate_key *k)
{
    uint32_t ip;

    memcpy(&ip, k->addr, sizeof ip);
    return ip;
}

/* v6: 64-bit FNV-1a of the 16-byte address + family tag */
static inline uint64_t rate_key_mix6(const struct rate_key *k)
{
    uint64_t h = 1469598103934665603ull;   /* FNV-1a offset basis */

    for (size_t i = 0; i < sizeof k->addr; i++) {
        h ^= (uint64_t)k->addr[i];
        h *= 1099511628211ull;             /* FNV-1a prime */
    }
    h ^= (uint64_t)k->fam;
    h *= 1099511628211ull;
    return h;
}

static inline bool rate_key_eq(const struct rate_key *a,
                              const struct rate_key *b)
{
    return a->fam == b->fam && memcmp(a->addr, b->addr, sizeof a->addr) == 0;
}

/* Full identity value stored in a gate slot: v4 = 32-bit address (bit-for-bit the same as the old implementation),
 * v6 = 64-bit hash. */
static inline uint64_t rate_key_id(const struct rate_key *k)
{
    if (rate_key_is_v4(k))
        return (uint64_t)rate_key_v4(k);
    return rate_key_mix6(k);
}

/* 32-bit index hash for shard/bucket position: v4 matches the old implementation exactly (10 bits: the low 6 bits are
 * the in-bucket position, the next 4 bits are the shard); v6 folds the 64-bit hash. */
static inline uint32_t rate_key_hash32(const struct rate_key *k)
{
    uint64_t h;

    if (rate_key_is_v4(k))
        return (rate_key_v4(k) * RATE_HASH_MUL) >> RATE_HASH_SHIFT;
    h = rate_key_mix6(k);
    return (uint32_t)((h >> 32) ^ h);
}

static inline unsigned rate_ip_shard(const struct rate_key *k)
{
    return (rate_key_hash32(k) >> RATE_SHARD_BITS) & (RATE_SHARDS - 1);
}

static inline void rate_shard_unlock(const struct rate_key *k)
{
    pthread_mutex_unlock(&g_rate_shards[rate_ip_shard(k)].mu);
}

/* Index of the 1024 gate slots: v4 uses the old (ip * MUL) >> 22, bit-for-bit unchanged; v6 takes the top
 * 10 bits of the hash. */
static inline unsigned rate_gate_slot(const struct rate_key *k)
{
    if (rate_key_is_v4(k))
        return (unsigned)((rate_key_v4(k) * RATE_HASH_MUL) >> RATE_HASH_SHIFT);
    return (unsigned)(rate_key_mix6(k) >> 54) & (RATE_BUCKETS - 1);
}

static inline void rate_gate_claim(struct rate_gate_set *gs,
                                   const struct rate_key *k, uint64_t until,
                                   uint64_t now)
{
    uint64_t id = rate_key_id(k);

    for (unsigned w = 0; w < RATE_GATE_WAYS; w++) {
        struct rate_gate *g = &gs->way[w];
        uint8_t cur_valid = atomic_load_explicit(&g->valid, memory_order_relaxed);
        uint64_t cur_id = atomic_load_explicit(&g->id, memory_order_relaxed);
        uint64_t cur_until = atomic_load_explicit(&g->over_until_ms, memory_order_relaxed);
        if (cur_valid && cur_id != id && cur_until > now)
            continue;
        atomic_store_explicit(&g->over_until_ms, until, memory_order_relaxed);
        atomic_store_explicit(&g->id, id, memory_order_relaxed);
        atomic_store_explicit(&g->valid, 1, memory_order_relaxed);
        return;
    }
}

static inline bool rate_gate_check(const struct rate_gate_set *gs,
                                   const struct rate_key *k, uint64_t now)
{
    uint64_t id = rate_key_id(k);

    for (unsigned w = 0; w < RATE_GATE_WAYS; w++) {
        const struct rate_gate *g = &gs->way[w];
        if (atomic_load_explicit(&g->valid, memory_order_relaxed) &&
            atomic_load_explicit(&g->id, memory_order_relaxed) == id &&
            atomic_load_explicit(&g->over_until_ms, memory_order_relaxed) > now)
            return true;
    }
    return false;
}

static struct rate_bucket *rate_bucket_find(struct rate_shard *sh,
                                            const struct rate_key *k)
{
    unsigned h = (unsigned)(rate_key_hash32(k) &
                            (unsigned)(RATE_BUCKETS_PER_SHARD - 1));
    unsigned evict = 0;
    uint64_t oldest = UINT64_MAX;

    for (unsigned i = 0; i < RATE_PROBE_MAX; i++) {
        struct rate_bucket *c = &sh->buckets[(h + i) % RATE_BUCKETS_PER_SHARD];
        if (c->win < oldest) {
            oldest = c->win;
            evict = i;
        }
        if (!c->valid || rate_key_eq(&c->key, k))
            return c;
    }
    return &sh->buckets[(h + evict) % RATE_BUCKETS_PER_SHARD];
}

static void rate_evict_publish(struct rate_bucket *b, uint64_t now)
{
    uint64_t until;
    unsigned slot;

    if (!b->valid || now - b->win >= RATE_WINDOW_MS)
        return;
    if (b->open_cnt == 0 && b->ping_cnt == 0 && b->echo_cnt == 0 &&
        b->miss_cnt == 0 && b->tokbad_cnt == 0 && b->close_cnt == 0)
        return;
    until = b->win + RATE_WINDOW_MS;
    slot = rate_gate_slot(&b->key);
    rate_gate_claim(&g_rate_gate[slot], &b->key, until, now);
    rate_gate_claim(&g_tokbad_gate[slot], &b->key, until, now);
    rate_gate_claim(&g_close_gate[slot], &b->key, until, now);
}

static void rate_bucket_touch(struct rate_bucket *b, const struct rate_key *k)
{
    uint64_t now = now_ms();

    if (!b->valid || !rate_key_eq(&b->key, k) ||
        now - b->win >= RATE_WINDOW_MS) {
        rate_evict_publish(b, now);
        b->key = *k;
        b->valid = true;
        b->win = now;
        b->open_cnt = b->ping_cnt = b->echo_cnt = b->miss_cnt = 0;
        b->tokbad_cnt = 0;
        b->close_cnt = 0;
    }
}

static struct rate_bucket *rate_bucket_enter(const struct rate_key *k)
{
    struct rate_shard *sh = &g_rate_shards[rate_ip_shard(k)];
    pthread_mutex_lock(&sh->mu);
    struct rate_bucket *b = rate_bucket_find(sh, k);
    rate_bucket_touch(b, k);
    return b;
}

bool server_rate_allow_control(const struct iwan_peer *peer, uint8_t typ)
{
    struct rate_key k = rate_key_from_peer(peer);
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
        return true;
    }

    b = rate_bucket_enter(&k);
    cnt = (typ == PT_OPEN) ? &b->open_cnt :
          (typ == PT_PING_REQ) ? &b->ping_cnt : &b->echo_cnt;
    if (*cnt >= limit)
        ok = false;
    else
        (*cnt)++;
    rate_shard_unlock(&k);
    if (!ok)
        atomic_fetch_add(&g_rate_drops, 1);
    return ok;
}

bool server_rate_allow_sid_miss(const struct iwan_peer *peer, uint64_t now)
{
    struct rate_key k = rate_key_from_peer(peer);
    struct rate_gate_set *g = &g_rate_gate[rate_gate_slot(&k)];
    struct rate_bucket *b;
    bool ok;

    if (rate_gate_check(g, &k, now))
        return false;

    b = rate_bucket_enter(&k);
    ok = ++b->miss_cnt <= g_rate_miss_max;
    if (!ok) {
        rate_gate_claim(g, &k, b->win + RATE_WINDOW_MS, now);
    }
    rate_shard_unlock(&k);
    return ok;
}

bool server_rate_allow_tokbad(const struct iwan_peer *peer, uint64_t now)
{
    struct rate_key k = rate_key_from_peer(peer);
    struct rate_gate_set *g = &g_tokbad_gate[rate_gate_slot(&k)];
    struct rate_bucket *b;
    bool ok;

    if (rate_gate_check(g, &k, now))
        return false;

    b = rate_bucket_enter(&k);
    ok = ++b->tokbad_cnt <= g_rate_tokbad_max;
    if (!ok) {
        rate_gate_claim(g, &k, b->win + RATE_WINDOW_MS, now);
    }
    rate_shard_unlock(&k);
    return ok;
}

bool server_rate_allow_close(const struct iwan_peer *peer, uint64_t now)
{
    struct rate_key k = rate_key_from_peer(peer);
    struct rate_gate_set *g = &g_close_gate[rate_gate_slot(&k)];
    struct rate_bucket *b;
    bool ok;

    if (rate_gate_check(g, &k, now))
        return false;

    b = rate_bucket_enter(&k);
    ok = ++b->close_cnt <= g_rate_close_max;
    if (!ok) {
        rate_gate_claim(g, &k, b->win + RATE_WINDOW_MS, now);
    }
    rate_shard_unlock(&k);
    return ok;
}
