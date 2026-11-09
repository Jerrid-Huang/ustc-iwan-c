/* Live Windows regression for the production route-pin helpers.
 * Build with MinGW, -fno-asynchronous-unwind-tables -fno-unwind-tables,
 * -ffunction-sections -fdata-sections -Wl,--gc-sections,
 * -lws2_32 -liphlpapi. Run elevated: win_route_pin_test.exe LOCAL ONLINK EXISTING.
 * ONLINK and EXISTING must be unused IPv4 destinations on the test subnet.
 */
#include <stdarg.h>
#include "../src/common/route.c"

void log_err(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
}

static bool lookup(const char *ip, MIB_IPFORWARDROW *row)
{
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1 &&
           GetBestRoute(addr.s_addr, 0, row) == NO_ERROR;
}

static bool same_path(const MIB_IPFORWARDROW *a, const MIB_IPFORWARDROW *b)
{
    return a->dwForwardIfIndex == b->dwForwardIfIndex &&
           a->dwForwardNextHop == b->dwForwardNextHop;
}

int main(int argc, char **argv)
{
    WSADATA ws;
    MIB_IPFORWARDROW before, after, existing;
    struct in_addr addr;
    bool own_existing = false;
    int rc = 1;
    if (argc != 4 || WSAStartup(MAKEWORD(2, 2), &ws) != 0)
        return 2;
    if (!lookup(argv[1], &before) || before.dwForwardMask != 0xffffffffu ||
        !win_pin_server(argv[1]) || win_srv_pin_installed)
        goto done;
    win_unpin_server();
    if (!lookup(argv[1], &after) || !same_path(&before, &after) ||
        after.dwForwardMask != before.dwForwardMask)
        goto done;
    puts("ROUTEPIN local-preserved=1");

    if (!lookup(argv[2], &before) || before.dwForwardMask == 0xffffffffu ||
        before.dwForwardNextHop != 0)
        goto done;
    for (int i = 0; i < 5; i++) {
        if (!win_pin_server(argv[2]) || !win_srv_pin_installed ||
            !lookup(argv[2], &after) || after.dwForwardMask != 0xffffffffu ||
            !same_path(&before, &after))
            goto done;
        win_unpin_server();
        if (!lookup(argv[2], &after) || after.dwForwardMask != before.dwForwardMask ||
            !same_path(&before, &after))
            goto done;
    }
    printf("ROUTEPIN onlink-reconnects=5 ifindex=%lu nexthop=%lu\n",
           before.dwForwardIfIndex, before.dwForwardNextHop);

    if (!lookup(argv[3], &existing) || existing.dwForwardMask == 0xffffffffu ||
        inet_pton(AF_INET, argv[3], &addr) != 1)
        goto done;
    existing.dwForwardDest = addr.s_addr;
    existing.dwForwardMask = 0xffffffffu;
    existing.dwForwardPolicy = 0;
    existing.dwForwardProto = MIB_IPPROTO_NETMGMT;
    existing.dwForwardAge = 0;
    if (CreateIpForwardEntry(&existing) != NO_ERROR)
        goto done;
    own_existing = true;
    if (!win_pin_server(argv[3]) || win_srv_pin_installed)
        goto done;
    win_unpin_server();
    if (!lookup(argv[3], &after) || after.dwForwardMask != 0xffffffffu ||
        !same_path(&existing, &after))
        goto done;
    puts("ROUTEPIN existing-host-preserved=1");
    rc = 0;
done:
    win_unpin_server();
    if (own_existing && DeleteIpForwardEntry(&existing) != NO_ERROR)
        rc = 1;
    WSACleanup();
    printf("ROUTEPIN result=%s\n", rc == 0 ? "PASS" : "FAIL");
    return rc;
}
