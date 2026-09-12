#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "profile.h"
#include "util.h"

atomic_int g_prof_on;

#ifndef IWAN_DEBUG_STRIP
void prof_init(void)
{
    /* R37 WG6 #4 + R5 (R3-L17): "set" was not the documented contract
     * (profile.h says IWAN_PROFILE=1); the off spellings are decided by
     * env_bool() (util.h). The old comment here claimed parity with
     * debug_enabled() while the two lists actually differed ("no" was
     * off here, ON there) — that claim is now true by construction. */
    if (env_bool("IWAN_PROFILE", false))
        atomic_store(&g_prof_on, 1);
}
#endif

#ifndef IWAN_DEBUG_STRIP
int prof_print(const char *tag, struct prof_state *st, uint64_t counter)
{
    uint64_t now = now_us();
    if (st->us == 0) {
        st->us = now;
        st->cnt = counter;
        return 0;
    }
    if (now - st->us < 1000000)
        return 0;
    double dt = (double)(now - st->us) / 1e6;
    double mbps = (double)(counter - st->cnt) * 8.0 / dt / 1e6;
    st->us = now;
    st->cnt = counter;
    fprintf(stderr, "[prof] %-14s %7.1f Mbit/s (%6.2f GB)\n", tag, mbps,
            (double)counter / 1e9);
    return 1;
}
#endif
