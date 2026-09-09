#include "lockout.h"

#include <string.h>

#include "common.h"
#include "util.h"

void lockout_note(lockout_rec *tbl, int n, const void *key, size_t klen,
                  bool success, unsigned max_fails, unsigned window_ms,
                  pthread_mutex_t *mu)
{
    lockout_rec *e = NULL, *oldest = NULL, *earliest = &tbl[0];
    uint64_t now;

    if (!key || klen == 0 || klen > LOCKOUT_KEY_MAX)
        return;
    now = now_ms();
    if (mu)
        pthread_mutex_lock(mu);
    if (success) {
        for (int i = 0; i < n; i++) {
            if (tbl[i].first_fail_ms != 0 &&
                memcmp(tbl[i].key, key, klen) == 0) {
                memset(&tbl[i], 0, sizeof tbl[i]);
                break;
            }
        }
        if (mu)
            pthread_mutex_unlock(mu);
        return;
    }
    for (int i = 0; i < n; i++) {
        lockout_rec *r = &tbl[i];
        if (r->first_fail_ms != 0 && memcmp(r->key, key, klen) == 0) {
            e = r;
            break;
        }
        /* empty slot wins; otherwise keep the oldest first_fail_ms among
         * entries that are NOT currently blocked (L-1: never evict a live
         * ban while a non-blocked victim exists) */
        if (r->first_fail_ms == 0 ||
            (r->blocked_until_ms <= now &&
             (oldest == NULL || r->first_fail_ms < oldest->first_fail_ms)))
            oldest = r;
        /* unconditional earliest: fallback eviction target used only when
         * every remaining candidate is still blocked (L-1) */
        if (earliest == NULL || r->first_fail_ms < earliest->first_fail_ms)
            earliest = r;
    }
    if (!e)
        /* prefer a non-blocked victim; only when none exists (all slots
         * empty-or-blocked) fall back to the earliest entry, accepting
         * that its ban is lost as the last resort (L-1) */
        e = oldest != NULL ? oldest : earliest;
    /* fresh entry: an empty slot, a slot whose key changed (full-table
     * eviction taking over a different source's record — the victim's
     * fail count / blocked_until_ms must NOT be inherited by the new
     * key), or the previous burst aged out of the window (R4-06-3: the
     * window ends at exactly window_ms, hence >=). This branch respects
     * an active ban (M-1): a same-key failure that arrives after the
     * counting window but while blocked_until_ms is still in force must
     * NOT clear the ban — only the counting window restarts and the entry
     * stays blocked until blocked_until_ms expires naturally. */
    if (e->first_fail_ms == 0 ||
        memcmp(e->key, key, klen) != 0 ||
        now - e->first_fail_ms >= window_ms) {
        /* M-1: same key, previous burst aged out, ban still active — keep
         * blocked_until_ms, restart the count window only. The shortcut is
         * limited to same-key window age-outs: when the key differs this
         * is a table eviction and the new key must still take over the
         * slot. */
        if (e->first_fail_ms != 0 &&
            memcmp(e->key, key, klen) == 0 &&
            e->blocked_until_ms != 0 && e->blocked_until_ms > now) {
            e->fail = 1;
            e->first_fail_ms = now;
            if (mu)
                pthread_mutex_unlock(mu);
            return;
        }
        memset(e, 0, sizeof *e);
        memcpy(e->key, key, klen);
        e->fail = 1;
        e->first_fail_ms = now;
        if (mu)
            pthread_mutex_unlock(mu);
        return;
    }
    memcpy(e->key, key, klen);
    e->fail++;
    if (e->fail >= (int)max_fails)
        e->blocked_until_ms = now + window_ms;
    if (mu)
        pthread_mutex_unlock(mu);
}

bool lockout_blocked(const lockout_rec *tbl, int n, const void *key,
                     size_t klen, pthread_mutex_t *mu)
{
    bool hit = false;

    if (!key || klen == 0 || klen > LOCKOUT_KEY_MAX)
        return false;
    uint64_t now = now_ms();
    if (mu)
        pthread_mutex_lock(mu);
    for (int i = 0; i < n; i++) {
        const lockout_rec *r = &tbl[i];
        if (r->blocked_until_ms != 0 &&
            memcmp(r->key, key, klen) == 0) {
            hit = r->blocked_until_ms > now;
            break;
        }
    }
    if (mu)
        pthread_mutex_unlock(mu);
    return hit;
}
