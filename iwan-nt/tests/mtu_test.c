/*
 * Host unit test for driver/iwan_nt_mtu.c.
 *
 *   gcc -std=c11 -Wall -Wextra -Werror -I driver tests/mtu_test.c \
 *       driver/iwan_nt_mtu.c -o /tmp/iwan_nt_mtu_test && /tmp/iwan_nt_mtu_test
 */

#include <stdio.h>

#include "iwan_nt_mtu.h"

static unsigned gChecks;
static unsigned gFailures;

#define CHECK_EQ(a, b)                                                       \
    do {                                                                     \
        long long va = (long long)(a);                                       \
        long long vb = (long long)(b);                                       \
        gChecks++;                                                           \
        if (va != vb) {                                                      \
            gFailures++;                                                     \
            printf("FAIL %s:%d %s=%lld != %s=%lld\n", __FILE__, __LINE__,    \
                   #a, va, #b, vb);                                          \
        }                                                                    \
    } while (0)

int
main(void)
{
    /* Overhead per family. An unknown family is costed as IPv4. */
    CHECK_EQ(IwanNtMtuOverhead(4u), 36u);
    CHECK_EQ(IwanNtMtuOverhead(6u), 56u);
    CHECK_EQ(IwanNtMtuOverhead(0u), 36u);

    /* Ethernet carrier, no peer statement yet: the classic answer. */
    CHECK_EQ(IwanNtMtuEffective(1500u, 0u, 4u), 1464u);
    CHECK_EQ(IwanNtMtuEffective(1500u, 0u, 6u), 1444u);

    /* Peer MTU wins when it is smaller than what the carrier allows. */
    CHECK_EQ(IwanNtMtuEffective(1500u, 1400u, 4u), 1400u);
    CHECK_EQ(IwanNtMtuEffective(9000u, 1400u, 6u), 1400u);
    CHECK_EQ(IwanNtMtuEffective(1500u, 1200u, 4u), 1200u);

    /* Peer MTU does not raise the carrier bound: the tunnel still has to fit
     * inside the path MTU. */
    CHECK_EQ(IwanNtMtuEffective(1500u, 9000u, 4u), 1464u);

    /* Jumbo carrier is capped by the protocol ceiling, not by the carrier. */
    CHECK_EQ(IwanNtMtuEffective(9000u, 0u, 4u), IWAN_NT_MTU_MAX);
    CHECK_EQ(IwanNtMtuEffective(9000u, 9000u, 6u), IWAN_NT_MTU_MAX);

    /* Carrier too small for the inner minimum still yields the minimum. */
    CHECK_EQ(IwanNtMtuEffective(0u, 0u, 4u), IWAN_NT_MTU_MIN);
    CHECK_EQ(IwanNtMtuEffective(36u, 0u, 4u), IWAN_NT_MTU_MIN);
    CHECK_EQ(IwanNtMtuEffective(100u, 0u, 4u), IWAN_NT_MTU_MIN);
    CHECK_EQ(IwanNtMtuEffective(56u, 0u, 6u), IWAN_NT_MTU_MIN);

    /* Peer below the minimum is clamped up, never propagated as is. */
    CHECK_EQ(IwanNtMtuEffective(1500u, 40u, 4u), IWAN_NT_MTU_MIN);
    CHECK_EQ(IwanNtMtuEffective(1500u, IWAN_NT_MTU_MIN, 4u), IWAN_NT_MTU_MIN);

    /* The documented default carrier reproduces the value the adapter used to
     * hard code, which keeps existing measurements comparable. */
    CHECK_EQ(IwanNtMtuEffective(IWAN_NT_MTU_CARRIER_DEFAULT, 0u, 4u), 1464u);

    /* Boundaries of the clamp. */
    CHECK_EQ(IwanNtMtuEffective(1500u, IWAN_NT_MTU_MAX, 4u), 1464u);
    CHECK_EQ(IwanNtMtuEffective(1536u, 0u, 4u), IWAN_NT_MTU_MAX);
    CHECK_EQ(IwanNtMtuEffective(1499u, 0u, 4u), 1463u);

    if (gFailures != 0) {
        printf("mtu: %u checks, %u failures\n", gChecks, gFailures);
        return 1;
    }
    printf("mtu: %u checks, 0 failures\n", gChecks);
    return 0;
}
