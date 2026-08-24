/* Lightweight throughput instrumentation for bottleneck profiling.
 *
 * IWAN_PROFILE=1 (read once at startup, prof_init) turns on byte
 * counters at instrumented hot points; each instrumented loop calls
 * prof_print() every ~1s to emit the per-second rate to stderr as
 * "[prof] tag: N Mbit/s". Counters are atomics so any thread may add;
 * the tag names which stage of the path they belong to.
 *
 * Temporary measuring aid: counters and prints are cheap when off
 * (one atomic load), and the whole thing can be dropped once the
 * bottleneck analysis is done. */
#ifndef IWAN_PROFILE_H
#define IWAN_PROFILE_H

#include <stdatomic.h>
#include <stdint.h>

struct prof_state {
    uint64_t us, cnt;
};

#ifdef IWAN_DEBUG_STRIP
/* stripped build: PROF_ADD is a no-op, g_prof_on stays 0, the
 * IWAN_PROFILE env var is never parsed and no tag strings survive */
typedef struct prof_state prof_state;
static inline void prof_init(void) { }
static inline int prof_print(const char *tag, struct prof_state *st,
                             uint64_t counter)
{
    (void)tag; (void)st; (void)counter;
    return 0;
}
static inline void prof_add_raw(prof_state *s, uint64_t n) { (void)s; (void)n; }
#define PROF_ADD(counter, n) ((void)0)
#else
extern atomic_int g_prof_on;
void prof_init(void);

/* count n payload bytes at an instrumented point */
#define PROF_ADD(counter, n)                                             \
    do {                                                                 \
        if (atomic_load_explicit(&g_prof_on, memory_order_relaxed))      \
            atomic_fetch_add(&(counter), (uint64_t)(n));                 \
    } while (0)

/* print the rate of `counter` since the previous call, at most once
 * per second; returns 1 when a line was printed */
int prof_print(const char *tag, struct prof_state *st, uint64_t counter);
#endif

#endif
