#include "iwan_nt_inet.h"

#include <stdio.h>
#include <string.h>

static int Checks = 0;
static int Failures = 0;

static void
Expect(int Condition, const char *Text, const char *What)
{
    Checks++;
    if (!Condition) {
        Failures++;
        printf("FAIL %-24s %s\n", Text, What);
    }
}

static void
CheckIPv4(void)
{
    static const uint8_t one[4] = { 1, 2, 3, 4 };
    static const uint8_t high[4] = { 255, 255, 255, 255 };
    static const uint8_t zero[4] = { 0, 0, 0, 0 };
    uint8_t out[4];

    Expect(IwanNtParseIPv4("1.2.3.4", out) && memcmp(out, one, 4) == 0,
           "1.2.3.4", "parses");
    Expect(IwanNtParseIPv4("255.255.255.255", out) &&
               memcmp(out, high, 4) == 0,
           "255.255.255.255", "parses");
    Expect(IwanNtParseIPv4("0.0.0.0", out) && memcmp(out, zero, 4) == 0,
           "0.0.0.0", "parses");

    Expect(!IwanNtParseIPv4("1.2.3", out), "1.2.3", "rejected");
    Expect(!IwanNtParseIPv4("1.2.3.4.5", out), "1.2.3.4.5", "rejected");
    Expect(!IwanNtParseIPv4("256.1.1.1", out), "256.1.1.1", "rejected");
    Expect(!IwanNtParseIPv4("1.2.3.", out), "1.2.3.", "rejected");
    Expect(!IwanNtParseIPv4(".1.2.3", out), ".1.2.3", "rejected");
    Expect(!IwanNtParseIPv4("1..2.3", out), "1..2.3", "rejected");
    Expect(!IwanNtParseIPv4("1.2.3.4 ", out), "trailing space", "rejected");
    Expect(!IwanNtParseIPv4("", out), "empty", "rejected");
    Expect(!IwanNtParseIPv4("a.b.c.d", out), "letters", "rejected");
}

static void
CheckIPv6(void)
{
    static const uint8_t loopback[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    };
    static const uint8_t all[16] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    static const uint8_t mixed[16] = {
        0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    };
    static const uint8_t tail[16] = {
        0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01
    };
    uint8_t out[16];

    Expect(IwanNtParseIPv6("::1", out) && memcmp(out, loopback, 16) == 0,
           "::1", "parses");
    Expect(IwanNtParseIPv6("::", out) &&
               memcmp(out, (uint8_t[16]){ 0 }, 16) == 0,
           "::", "parses");
    Expect(IwanNtParseIPv6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", out) &&
               memcmp(out, all, 16) == 0,
           "all-ones", "parses");
    Expect(IwanNtParseIPv6("2001:db8::", out) &&
               memcmp(out, (uint8_t[16]){ 0x20, 0x01, 0x0d, 0xb8 }, 4) == 0,
           "2001:db8::", "parses");
    Expect(IwanNtParseIPv6("2001:db8::1", out) &&
               memcmp(out, mixed, 16) == 0,
           "2001:db8::1", "parses");
    Expect(IwanNtParseIPv6("2001:db8:0:0:0:0:0:1", out) &&
               memcmp(out, mixed, 16) == 0,
           "expanded", "parses");
    Expect(IwanNtParseIPv6("2001:db8::0:1", out) &&
               memcmp(out, tail, 16) == 0,
           "trailing group", "parses");
    Expect(IwanNtParseIPv6("::ffff:0:1", out) &&
               memcmp(out, (uint8_t[16]){ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff,
                                          0xff, 0, 0, 0, 1 }, 16) == 0,
           "::ffff:0:1", "parses");

    Expect(!IwanNtParseIPv6("", out), "empty", "rejected");
    Expect(!IwanNtParseIPv6(":", out), "single colon", "rejected");
    Expect(!IwanNtParseIPv6(":::", out), "triple colon", "rejected");
    Expect(!IwanNtParseIPv6("1:2:3:4:5:6:7", out), "seven groups", "rejected");
    Expect(!IwanNtParseIPv6("1:2:3:4:5:6:7:8:9", out), "nine groups",
           "rejected");
    Expect(!IwanNtParseIPv6("1:2:3:4:5:6:7::8", out), "run with eight",
           "rejected");
    Expect(!IwanNtParseIPv6("::1::2", out), "two runs", "rejected");
    Expect(!IwanNtParseIPv6("12345::", out), "five digits", "rejected");
    Expect(!IwanNtParseIPv6("2001:db8::g", out), "bad digit", "rejected");
    Expect(!IwanNtParseIPv6("2001:db8::1:", out), "trailing colon",
           "rejected");
    Expect(!IwanNtParseIPv6("2001::db8:", out), "trailing colon after run",
           "rejected");
    Expect(!IwanNtParseIPv6("2001:db8:::1", out), "colon before run",
           "rejected");
    Expect(!IwanNtParseIPv6("[2001:db8::1]", out), "brackets", "rejected");
    Expect(!IwanNtParseIPv6("::ffff:1.2.3.4", out), "v4 tail", "rejected");
}

static void
CheckEndpoint(void)
{
    uint8_t out[16];
    uint16_t family = 0;

    Expect(IwanNtParseEndpoint("10.0.2.2", out, &family) && family == 4 &&
               out[0] == 10 && out[3] == 2,
           "v4 endpoint", "family 4");
    Expect(IwanNtParseEndpoint("::1", out, &family) && family == 6 &&
               out[15] == 1,
           "v6 endpoint", "family 6");
    Expect(IwanNtParseEndpoint("::1", out, &family) && out[0] == 0 &&
               out[4] == 0,
           "v6 endpoint", "head zeroed");
    Expect(!IwanNtParseEndpoint("::1::2", out, &family), "bad endpoint",
           "rejected");
    Expect(!IwanNtParseEndpoint("", out, &family), "empty endpoint",
           "rejected");
}

static void
CheckFormat(void)
{
    char text[64];
    uint8_t address[16];
    uint16_t family = 0;

    Expect(strcmp(IwanNtFormatAddress((const uint8_t[4]){ 10, 0, 2, 2 }, 4,
                                      text, sizeof(text)),
                  "10.0.2.2") == 0,
           "format v4", "10.0.2.2");

    Expect(IwanNtParseEndpoint("2001:db8::1", address, &family) &&
               strcmp(IwanNtFormatAddress(address, 6, text, sizeof(text)),
                      "2001:db8:0:0:0:0:0:1") == 0,
           "format v6", "plain hextets");

    /* Whatever the formatter writes has to parse back to the same bytes. */
    {
        uint8_t again[16];
        uint16_t familyAgain = 0;

        Expect(IwanNtParseEndpoint(text, again, &familyAgain) &&
                   familyAgain == 6 && memcmp(again, address, 16) == 0,
               "format v6", "round trips");
    }
    Expect(IwanNtParseEndpoint("::", address, &family) &&
               strcmp(IwanNtFormatAddress(address, 6, text, sizeof(text)),
                      "0:0:0:0:0:0:0:0") == 0,
           "format ::", "all zeros");

    Expect(strcmp(IwanNtFormatAddress(address, 6, text, 4), "0:0") == 0,
           "short buffer", "truncated safely");
}

int
main(void)
{
    CheckIPv4();
    CheckIPv6();
    CheckEndpoint();
    CheckFormat();

    printf("inet: %d checks, %d failures\n", Checks, Failures);
    return (Failures == 0) ? 0 : 1;
}
