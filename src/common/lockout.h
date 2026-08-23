#ifndef IWAN_LOCKOUT_H
#define IWAN_LOCKOUT_H

/* Fixed-slot failure lockout table shared by the SOCKS and relay
 * listeners: max_fails consecutive failures from the same key within
 * window_ms trip a ban for another window_ms; a successful auth clears
 * the peer's history. Slots are reclaimed empty-first, else oldest
 * first_fail_ms (the entry that would age out soonest).
 *
 * Keys are opaque byte blobs encoded by the caller (SOCKS: the IPv4
 * address; relay: family flag + address words, v6 merged to /64).
 * mu: optional listener lock -- the relay accepts connections on several
 * threads and passes its mutex; the single-threaded SOCKS path passes
 * NULL. */

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LOCKOUT_KEY_MAX 16

typedef struct {
    uint8_t  key[LOCKOUT_KEY_MAX];
    int      fail;
    uint64_t first_fail_ms;
    uint64_t blocked_until_ms;  /* 0 = not blocked */
} lockout_rec;

void lockout_note(lockout_rec *tbl, int n, const void *key, size_t klen,
                  bool success, unsigned max_fails, unsigned window_ms,
                  pthread_mutex_t *mu);
bool lockout_blocked(const lockout_rec *tbl, int n, const void *key,
                     size_t klen, pthread_mutex_t *mu);

#endif /* IWAN_LOCKOUT_H */
