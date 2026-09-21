#include "socks_auth_guard.h"
#include "lockout.h"
#include "util.h"

#define AUTH_FAIL_MAX_DEFAULT 5
#define AUTH_FAIL_WINDOW_MS_DEFAULT 60000u
#define AUTH_FAIL_TRACK_MAX 16

static unsigned auth_fail_max(void)
{
    static int cached = -1;

    if (cached < 0)
        cached = (int)env_ms_range("IWAN_AUTH_FAIL_MAX",
                                   AUTH_FAIL_MAX_DEFAULT, 1, 100, 0,
                                   "1..100");
    return (unsigned)cached;
}

static unsigned auth_fail_window_ms(void)
{
    static int cached = -1;

    if (cached < 0)
        cached = (int)env_ms_range("IWAN_AUTH_FAIL_WINDOW_MS",
                                   AUTH_FAIL_WINDOW_MS_DEFAULT, 100,
                                   86400000, 0, "100..86400000");
    return (unsigned)cached;
}

static lockout_rec g_auth_fail[AUTH_FAIL_TRACK_MAX];

void auth_fail_note(uint32_t ip, bool success)
{
    lockout_note(g_auth_fail, AUTH_FAIL_TRACK_MAX, &ip, sizeof ip,
                 success, auth_fail_max(), auth_fail_window_ms(), NULL);
}

bool auth_fail_blocked(uint32_t ip)
{
    return lockout_blocked(g_auth_fail, AUTH_FAIL_TRACK_MAX, &ip,
                           sizeof ip, NULL);
}
