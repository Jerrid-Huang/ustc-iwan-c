#include <stdio.h>
#include <string.h>

#include "iwan_nt_prefix.h"

static int Checks;
static int Failures;

static void
Check(
    int Condition,
    const char *What
    )
{
    Checks++;
    if (!Condition) {
        Failures++;
        printf("FAIL %s\n", What);
    }
}

static IWAN_NT_PREFIX
Make4(
    const char *Text,
    unsigned Length
    )
{
    IWAN_NT_PREFIX entry;

    memset(&entry, 0, sizeof(entry));
    entry.Family = 4;
    entry.Length = Length;
    if (sscanf(Text, "%hhu.%hhu.%hhu.%hhu",
            &entry.Address[0], &entry.Address[1],
            &entry.Address[2], &entry.Address[3]) != 4) {
        printf("bad test address %s\n", Text);
    }
    return entry;
}

static IWAN_NT_PREFIX
Make6(
    const char *Text,
    unsigned Length
    )
{
    IWAN_NT_PREFIX entry;
    unsigned index;

    memset(&entry, 0, sizeof(entry));
    entry.Family = 6;
    entry.Length = Length;
    for (index = 0; index < 16; index++) {
        unsigned value = 0;

        if (sscanf(Text + index * 2, "%2x", &value) != 1) {
            printf("bad test address %s\n", Text);
        }
        entry.Address[index] = (uint8_t)value;
    }
    return entry;
}

static int
Allowed4(
    const IWAN_NT_PREFIX *Table,
    unsigned Count,
    const char *Source
    )
{
    uint8_t inner[20];
    IWAN_NT_PREFIX source = Make4(Source, 32);

    memset(inner, 0, sizeof(inner));
    inner[0] = 0x45;
    memcpy(inner + 12, source.Address, 4);
    return IwanNtPrefixInnerAllowed(Table, Count, 4, inner, sizeof(inner));
}

static int
Allowed6(
    const IWAN_NT_PREFIX *Table,
    unsigned Count,
    const char *Source
    )
{
    uint8_t inner[40];
    IWAN_NT_PREFIX source = Make6(Source, 128);

    memset(inner, 0, sizeof(inner));
    inner[0] = 0x60;
    memcpy(inner + 8, source.Address, 16);
    return IwanNtPrefixInnerAllowed(Table, Count, 6, inner, sizeof(inner));
}

int
main(void)
{
    IWAN_NT_PREFIX table[IWAN_NT_MAX_PREFIXES];
    IWAN_NT_PREFIX scratch[64];
    unsigned count;
    unsigned index;

    /* An empty table means the operator has not configured anything. */
    Check(IwanNtPrefixInnerAllowed(NULL, 0, 4, NULL, 0) == 1,
        "empty table allows everything");
    Check(IwanNtPrefixInnerAllowed(table, 0, 6, NULL, 0) == 1,
        "empty table allows everything, v6");

    /* One v4 prefix. */
    table[0] = Make4("198.18.0.0", 24);
    Check(IwanNtPrefixInnerAllowed(table, 1, 4, NULL, 0) == 0,
        "configured table rejects a missing header");
    Check(Allowed4(table, 1, "198.18.0.5") == 1, "inside /24");
    Check(Allowed4(table, 1, "198.18.0.255") == 1, "last address of /24");
    Check(Allowed4(table, 1, "198.18.1.0") == 0, "next /24 rejected");
    Check(Allowed4(table, 1, "10.0.2.2") == 0, "unrelated source rejected");

    /* Prefix boundaries that are not byte aligned. */
    table[0] = Make4("192.168.4.0", 22);
    Check(Allowed4(table, 1, "192.168.4.7") == 1, "inside /22 low");
    Check(Allowed4(table, 1, "192.168.7.255") == 1, "inside /22 high");
    Check(Allowed4(table, 1, "192.168.8.0") == 0, "just outside /22");

    /* Two entries, mixed families and order independence. */
    table[0] = Make4("10.1.0.0", 16);
    table[1] = Make6("fd000000000000000000000000000002", 128);
    Check(Allowed4(table, 2, "10.1.9.9") == 1, "v4 entry matches among two");
    Check(Allowed6(table, 2, "fd000000000000000000000000000002") == 1,
        "v6 entry matches among two");
    Check(Allowed6(table, 2, "fd000000000000000000000000000003") == 0,
        "v6 neighbour rejected");

    /* A v6 /64: only the first half has to match. */
    table[0] = Make6("fd000000000000010000000000000000", 64);
    Check(Allowed6(table, 1, "fd00000000000001ffffffffffffffff") == 1,
        "inside v6 /64");
    Check(Allowed6(table, 1, "fd000000000000020000000000000000") == 0,
        "outside v6 /64");

    /* Family mismatch must not match: a v4 entry cannot cover a v6 source. */
    table[0] = Make4("0.0.0.0", 0);
    Check(Allowed6(table, 1, "fd000000000000000000000000000001") == 0,
        "v4 entry never matches a v6 source");
    Check(Allowed4(table, 1, "8.8.8.8") == 1, "a /0 covers every v4 source");

    /* Host bits set: dropped by the setter rather than silently masked. */
    scratch[0] = Make4("198.18.0.5", 24);
    count = IwanNtPrefixSetAllowed(table, IWAN_NT_MAX_PREFIXES, scratch, 1);
    Check(count == 0, "entry with host bits is rejected");

    /* A malformed entry in the middle must not take the others with it. */
    scratch[0] = Make4("10.0.0.0", 8);
    scratch[1] = Make4("10.0.0.0", 33);
    scratch[2].Family = 5;
    scratch[2].Length = 0;
    scratch[3] = Make4("172.16.0.0", 12);
    count = IwanNtPrefixSetAllowed(table, IWAN_NT_MAX_PREFIXES, scratch, 4);
    Check(count == 2, "two of four entries survive validation");
    Check(table[0].Length == 8 && table[1].Length == 12,
        "survivors keep their order");
    Check(Allowed4(table, count, "10.200.1.1") == 1, "first survivor works");
    Check(Allowed4(table, count, "172.16.0.1") == 1, "second survivor works");

    /* Capacity is respected, and the overflow is dropped not wrapped. */
    for (index = 0; index < 64; index++) {
        scratch[index] = Make4("10.0.0.0", 8);
    }
    count = IwanNtPrefixSetAllowed(table, 4, scratch, 64);
    Check(count == 4, "capacity clamps the list");
    count = IwanNtPrefixSetAllowed(table, 0, scratch, 64);
    Check(count == 0, "zero capacity stores nothing");
    count = IwanNtPrefixSetAllowed(table, IWAN_NT_MAX_PREFIXES, NULL, 8);
    Check(count == 0, "null source stores nothing");

    /* Truncated inner headers must be refused, not read past. */
    {
        uint8_t short4[19];
        uint8_t short6[39];

        memset(short4, 0, sizeof(short4));
        memset(short6, 0, sizeof(short6));
        short4[0] = 0x45;
        short6[0] = 0x60;
        table[0] = Make4("0.0.0.0", 0);
        Check(IwanNtPrefixInnerAllowed(table, 1, 4, short4, sizeof(short4)) == 0,
            "19 byte v4 header refused");
        table[0] = Make6("00000000000000000000000000000000", 0);
        Check(IwanNtPrefixInnerAllowed(table, 1, 6, short6, sizeof(short6)) == 0,
            "39 byte v6 header refused");
    }

    /* Unknown family is refused. */
    Check(IwanNtPrefixInnerAllowed(table, 1, 7, (const uint8_t *)"x", 20) == 0,
        "unknown family refused");

    /* Egress uses the destination address, which sits at a different offset. */
    {
        IWAN_NT_PREFIX table[2];
        IWAN_NT_PREFIX one;
        uint8_t packet[40];
        unsigned count;

        one = Make4("198.18.0.0", 24u);
        count = IwanNtPrefixSetAllowed(table, 2u, &one, 1u);

        memset(packet, 0, sizeof(packet));
        packet[0] = 0x45u;
        packet[16] = 198u; packet[17] = 18u; packet[18] = 0u; packet[19] = 8u;
        packet[12] = 10u;  packet[13] = 0u;  packet[14] = 0u;  packet[15] = 1u;
        Check(IwanNtPrefixInnerAllowedTarget(table, count, 4u, packet,
                                             sizeof(packet)) == 1,
              "egress target inside");
        Check(IwanNtPrefixInnerAllowed(table, count, 4u, packet,
                                       sizeof(packet)) == 0,
              "egress ignores the source, ingress sees it outside");

        packet[18] = 1u;  /* outside the /24, the last byte alone would not be */
        Check(IwanNtPrefixInnerAllowedTarget(table, count, 4u, packet,
                                             sizeof(packet)) == 0,
              "egress target outside");

        memset(packet, 0, sizeof(packet));
        one = Make6("fd000000000000000000000000000000", 16u);
        count = IwanNtPrefixSetAllowed(table, 2u, &one, 1u);
        packet[0] = 0x60u;
        packet[23] = 0x01u;
        packet[24] = 0xfdu;
        Check(IwanNtPrefixInnerAllowedTarget(table, count, 6u, packet,
                                             sizeof(packet)) == 1,
              "egress target v6 inside");
        packet[24] = 0xfeu;
        packet[25] = 0xc0u;
        Check(IwanNtPrefixInnerAllowedTarget(table, count, 6u, packet,
                                             sizeof(packet)) == 0,
              "egress target v6 outside");
    }

    printf("PREFIX checks=%d failures=%d\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
