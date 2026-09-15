#ifndef IWAN_LOCKOUT_H
#define IWAN_LOCKOUT_H

/* Fixed-slot failure lockout table shared by the SOCKS and relay
 * listeners: max_fails consecutive failures from the same key within
 * window_ms trip a ban for another window_ms; a successful auth clears
 * the peer's history. Slots are reclaimed empty-first, else the oldest
 * non-blocked first_fail_ms (the entry that would age out soonest); an
 * entry under an active ban is only evicted as a last resort, when every
 * candidate is still blocked. A same-key failure that arrives after the
 * counting window while the ban is still running restarts only the count,
 * never the ban itself (M-1).
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
    /* R17 (R16-7): an independent occupancy bit.  first_fail_ms==0 used
     * to double as the empty-slot marker, which made a first failure at
     * now_ms()==0 invisible to the counter/success search and left a
     * ghost record behind; the bit is set on every entry creation and
     * cleared by memset on clear/evict.  blocked_until_ms==0 keeps its
     * own "not blocked" meaning. */
    bool     in_use;
} lockout_rec;

void lockout_note(lockout_rec *tbl, int n, const void *key, size_t klen,
                  bool success, unsigned max_fails, unsigned window_ms,
                  pthread_mutex_t *mu);
bool lockout_blocked(const lockout_rec *tbl, int n, const void *key,
                     size_t klen, pthread_mutex_t *mu);

#endif /* IWAN_LOCKOUT_H */
