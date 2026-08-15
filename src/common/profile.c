#include <stdio.h>
#include <stdlib.h>

#include "profile.h"
#include "util.h"

atomic_int g_prof_on;

void prof_init(void)
{
    if (getenv("IWAN_PROFILE"))
        atomic_store(&g_prof_on, 1);
}

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
