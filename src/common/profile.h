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

extern atomic_int g_prof_on;

/* count n payload bytes at an instrumented point (no-op when off) */
#define PROF_ADD(counter, n)                                             \
    do {                                                                 \
        if (atomic_load_explicit(&g_prof_on, memory_order_relaxed))      \
            atomic_fetch_add(&(counter), (uint64_t)(n));                 \
    } while (0)

/* read the IWAN_PROFILE env switch (call once at startup) */
void prof_init(void);

/* per-call state for prof_print (keep one per print site, e.g. as a
 * _Thread_local) */
struct prof_state {
    uint64_t us, cnt;
};

/* print the rate of `counter` since the previous call, at most once
 * per second; returns 1 when a line was printed */
int prof_print(const char *tag, struct prof_state *st, uint64_t counter);

#endif
