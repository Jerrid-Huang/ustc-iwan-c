/* Loop-guard predicate harness: drives route_target_hits_server() — the
 * single source of truth behind expand_route_targets()'s "route target
 * covers the tunnel server → warn + ignore" rule — with a case table.
 * Literal servers only for the asserted cases (no DNS dependency); one
 * lenient name-resolution case probes the getaddrinfo path when the
 * host can resolve "localhost". Exit code = number of failures. */
#ifdef _WIN32
#  include <winsock2.h>
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <sys/socket.h>
#endif
#include <stdio.h>
#include <string.h>

#include "route_common.h"

struct case_s {
    int family;
    const char *net;    /* target network, literal */
    int prefix;
    const char *srv;    /* server spec */
    int want_hit;       /* expected coverage */
    int want_exact;     /* expected host-route equality (only if hit) */
};

static const struct case_s cases[] = {
    /* exact host routes: the direct pin-collision cases */
    { AF_INET,  "1.2.3.4",       32, "1.2.3.4",       1, 1 },
    { AF_INET,  "1.2.3.4",       32, "1.2.3.5",       0, 0 },
    { AF_INET6, "2001:db8::1",  128, "2001:db8::1",   1, 1 },
    /* broader prefixes containing the server: latent-loop cases */
    { AF_INET,  "10.0.0.0",      8, "10.255.0.1",     1, 0 },
    { AF_INET,  "10.0.0.0",      8, "11.0.0.1",       0, 0 },
    { AF_INET,  "100.64.0.0",   10, "100.100.5.5",    1, 0 },  /* rem!=0 */
    { AF_INET,  "100.64.0.0",   10, "100.128.0.1",    0, 0 },  /* its +1  */
    { AF_INET,  "203.0.113.6",  31, "203.0.113.7",    1, 0 },  /* odd base*/
    { AF_INET,  "203.0.113.6",  31, "203.0.113.8",    0, 0 },
    { AF_INET,  "192.168.0.0",  24, "192.168.1.1",    0, 0 },
    { AF_INET6, "2001:db8::",   32, "2001:db8:99::1", 1, 0 },
    { AF_INET6, "2001:db8::",   32, "2001:db9::1",    0, 0 },
    { AF_INET6, "fe80::",       10, "fe80::abcd",     1, 0 },
    /* prefix 0 is the documented full-tunnel form: NEVER a hit */
    { AF_INET,  "0.0.0.0",       0, "9.9.9.9",        0, 0 },
    { AF_INET6, "::",            0, "2001:db8::1",    0, 0 },
    /* exemption stops at prefix 0: 0/1 really does contain its half */
    { AF_INET,  "0.0.0.0",       1, "0.0.0.1",        1, 0 },
    { AF_INET,  "0.0.0.0",       1, "128.0.0.1",      0, 0 },
    /* cross-family specs can never match (v6 server vs v4 route etc.) */
    { AF_INET,  "127.0.0.0",     8, "::1",            0, 0 },
    { AF_INET6, "::1",         128, "127.0.0.1",      0, 0 },
    /* degenerate server specs: never a match, never a crash */
    { AF_INET,  "1.2.3.4",      32, NULL,             0, 0 },
    { AF_INET,  "1.2.3.4",      32, "",               0, 0 },
    { AF_INET,  "1.2.3.4",      32, "not a host",     0, 0 },
};

int main(void)
{
    int fails = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        const struct case_s *c = &cases[i];
        uint8_t net[16];
        memset(net, 0, sizeof net);
        if (inet_pton(c->family, c->net, net) != 1) {
            printf("FAIL case %zu: bad net '%s'\n", i, c->net);
            fails++;
            continue;
        }
        bool exact = false;
        bool hit = route_target_hits_server(c->family, net, c->prefix,
                                           c->srv, &exact);
        if ((int)hit != c->want_hit || (hit && exact != (bool)c->want_exact)) {
            printf("FAIL case %zu: %s %s/%d srv=%s -> hit=%d exact=%d "
                   "(want hit=%d exact=%d)\n", i,
                   c->family == AF_INET ? "v4" : "v6", c->net, c->prefix,
                   c->srv ? c->srv : "(null)", hit, exact, c->want_hit,
                   c->want_exact);
            fails++;
        }
    }

    /* lenient name path: only asserted when the host resolves localhost
     * to an IPv4 (the guard resolves non-literal servers itself) */
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo("localhost", NULL, &hints, &res) == 0) {
        freeaddrinfo(res);
        uint8_t lo8[16];
        memset(lo8, 0, sizeof lo8);
        if (inet_pton(AF_INET, "127.0.0.0", lo8) == 1 &&
            !route_target_hits_server(AF_INET, lo8, 8, "localhost", NULL)) {
            printf("FAIL name case: 127.0.0.0/8 vs srv=localhost missed\n");
            fails++;
        }
    } else {
        printf("SKIP name case: localhost unresolved\n");
    }

    printf("%s: %d case(s), %d failure(s)\n",
           fails ? "FAIL" : "PASS", (int)(sizeof cases / sizeof cases[0]),
           fails);
    return fails;
}
