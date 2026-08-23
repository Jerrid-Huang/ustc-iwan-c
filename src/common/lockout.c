#include "lockout.h"

#include <string.h>

#include "common.h"
#include "util.h"

void lockout_note(lockout_rec *tbl, int n, const void *key, size_t klen,
                  bool success, unsigned max_fails, unsigned window_ms,
                  pthread_mutex_t *mu)
{
    lockout_rec *e = NULL, *oldest = &tbl[0];
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
        /* empty slot wins; otherwise keep the oldest first_fail_ms
         * (the entry that would age out first) */
        if (r->first_fail_ms == 0 ||
            r->first_fail_ms < oldest->first_fail_ms)
            oldest = r;
    }
    if (!e)
        e = oldest;
    /* fresh entry, or the previous burst aged out of the window */
    if (e->first_fail_ms == 0 || now - e->first_fail_ms > window_ms) {
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
