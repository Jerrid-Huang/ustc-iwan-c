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

/* 族无关的限速键。v6 的 128 位地址必须全部参与（绝不能只取前 4 字节：同
 * 一个 /32 前缀下一堆 v6 客户端会被并成一桶，20/s 的 OPEN 预算被单个客户
 * 端吃光）；v4 走的哈希与加 v6 之前逐位相同，所以 v4 的限速口径与桶分布
 * 完全不变。 */
struct rate_key {
    uint8_t addr[16];   /* 网络序；AF_INET 只用 addr[0..3]，其余为 0 */
    uint8_t fam;        /* AF_INET / AF_INET6 */
};

struct rate_bucket {
    /* 存完整源地址（不是索引哈希）：v4 的键就是精确的 32 位地址，v6 是
     * 精确的 16 字节地址，不同源绝不共桶。 */
    struct rate_key key;
    /* 槽位是否已被占用。显式 valid 位取代旧的 `ip != 0` 空槽哨兵：v6 地址
     * 的前 4 字节常常是 0（::1、::ffff:0:x…），旧哨兵会把不同源当成同一个
     * 空槽。 */
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
    /* 完整源身份：v4 = 32 位网络序地址（与旧实现存的 ip 逐位相同），
     * v6 = 64 位 FNV-1a 哈希（碰撞概率 2^-64，槽位只做 "该源超预算" 的
     * 记忆，不是计数表）。 */
    _Atomic uint64_t id;
    _Atomic uint8_t valid;          /* 显式占用位，取代 `ip != 0` 哨兵 */
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

/* 从规范化后的外层对端构造限速键 */
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

/* AF_INET 的 32 位网络序地址（= 旧实现里当键用的那个值） */
static inline uint32_t rate_key_v4(const struct rate_key *k)
{
    uint32_t ip;

    memcpy(&ip, k->addr, sizeof ip);
    return ip;
}

/* v6：16 字节地址 + 族标签的 64 位 FNV-1a */
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

/* gate 槽位里存的完整身份值：v4 = 32 位地址（与旧实现逐位相同），
 * v6 = 64 位哈希。 */
static inline uint64_t rate_key_id(const struct rate_key *k)
{
    if (rate_key_is_v4(k))
        return (uint64_t)rate_key_v4(k);
    return rate_key_mix6(k);
}

/* 分片/桶内位置的 32 位索引哈希：v4 与旧实现完全一致（10 位：低 6 位是桶
 * 内位置、次 4 位是分片）；v6 用 64 位哈希折叠。 */
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

/* 1024 个 gate 槽的下标：v4 走旧的 (ip * MUL) >> 22，逐位不变；v6 取哈希
 * 高 10 位。 */
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
