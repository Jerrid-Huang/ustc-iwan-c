#include "iwan_nt_inet.h"

#include <stdio.h>
#include <string.h>

static int
DigitValue(
    char Character
    )
{
    if (Character >= '0' && Character <= '9') {
        return Character - '0';
    }
    if (Character >= 'a' && Character <= 'f') {
        return (Character - 'a') + 10;
    }
    if (Character >= 'A' && Character <= 'F') {
        return (Character - 'A') + 10;
    }
    return -1;
}

int
IwanNtParseIPv4(
    _In_z_ const char *Text,
    _Out_writes_bytes_(4) uint8_t *Address
    )
{
    int part;

    if (Text == NULL || Address == NULL) {
        return 0;
    }

    for (part = 0; part < 4; part++) {
        unsigned value = 0;
        int digits = 0;

        while (*Text >= '0' && *Text <= '9') {
            value = value * 10u + (unsigned)(*Text - '0');
            if (value > 255u || ++digits > 3) {
                return 0;
            }
            Text++;
        }
        if (digits == 0) {
            return 0;
        }
        Address[part] = (uint8_t)value;

        if (part < 3) {
            if (*Text != '.') {
                return 0;
            }
            Text++;
        }
    }

    return (*Text == '\0') ? 1 : 0;
}

/*
 * One hextet: one to four hex digits. Returns the length consumed, or 0 when
 * there is no digit or the value would not fit.
 */
static int
ParseHextet(
    const char *Text,
    uint16_t *Value
    )
{
    unsigned value = 0;
    int digits = 0;

    while (digits < 4) {
        int digit = DigitValue(*Text);

        if (digit < 0) {
            break;
        }
        value = (value << 4) | (unsigned)digit;
        digits++;
        Text++;
    }

    if (digits == 0) {
        return 0;
    }
    *Value = (uint16_t)value;
    return digits;
}

int
IwanNtParseIPv6(
    _In_z_ const char *Text,
    _Out_writes_bytes_(16) uint8_t *Address
    )
{
    uint16_t head[8];
    uint16_t tail[8];
    int headCount = 0;
    int tailCount = 0;
    int compressed = 0;
    int index;

    if (Text == NULL || Address == NULL) {
        return 0;
    }
    if (*Text == '\0') {
        return 0;
    }

    /* A leading "::" means the run starts at the first hextet. */
    if (Text[0] == ':' && Text[1] == ':') {
        compressed = 1;
        Text += 2;
        if (*Text == '\0') {
            memset(Address, 0, 16);
            return 1;
        }
    } else if (*Text == ':') {
        return 0;
    }

    for (;;) {
        uint16_t value;
        int consumed = ParseHextet(Text, &value);

        if (consumed == 0) {
            return 0;
        }
        Text += consumed;

        if (compressed) {
            if (tailCount >= 8) {
                return 0;
            }
            tail[tailCount++] = value;
        } else {
            if (headCount >= 8) {
                return 0;
            }
            head[headCount++] = value;
        }

        if (*Text == '\0') {
            break;
        }
        if (*Text != ':') {
            return 0;
        }
        Text++;

        if (*Text == ':') {
            /* The second "::" would make the run ambiguous. */
            if (compressed) {
                return 0;
            }
            compressed = 1;
            Text++;
            if (*Text == '\0') {
                break;
            }
        } else if (*Text == '\0') {
            /* A single trailing ':' is not a valid address. */
            return 0;
        }
    }

    if (headCount + tailCount > 8) {
        return 0;
    }
    if (!compressed && headCount != 8) {
        return 0;
    }
    if (compressed && headCount + tailCount >= 8) {
        /* "::" has to stand for at least one zero hextet. */
        return 0;
    }

    for (index = 0; index < headCount; index++) {
        Address[index * 2] = (uint8_t)(head[index] >> 8);
        Address[index * 2 + 1] = (uint8_t)(head[index] & 0xFFu);
    }
    for (index = 0; index < tailCount; index++) {
        int slot = 8 - tailCount + index;

        Address[slot * 2] = (uint8_t)(tail[index] >> 8);
        Address[slot * 2 + 1] = (uint8_t)(tail[index] & 0xFFu);
    }
    if (compressed) {
        memset(Address + headCount * 2, 0,
               (size_t)(8 - headCount - tailCount) * 2u);
    }

    return 1;
}

int
IwanNtParseEndpoint(
    _In_z_ const char *Text,
    _Out_writes_bytes_(16) uint8_t *Address,
    _Out_ uint16_t *Family
    )
{
    if (Text == NULL || Address == NULL || Family == NULL) {
        return 0;
    }

    memset(Address, 0, 16);

    if (strchr(Text, ':') != NULL) {
        if (!IwanNtParseIPv6(Text, Address)) {
            return 0;
        }
        *Family = 6;
        return 1;
    }

    if (!IwanNtParseIPv4(Text, Address)) {
        return 0;
    }
    *Family = 4;
    return 1;
}

const char *
IwanNtFormatAddress(
    _In_reads_bytes_(16) const uint8_t *Address,
    _In_ uint16_t Family,
    _Out_writes_(Capacity) char *Buffer,
    _In_ size_t Capacity
    )
{
    size_t used;
    int index;

    if (Buffer == NULL || Capacity == 0) {
        return "";
    }
    Buffer[0] = '\0';
    if (Address == NULL) {
        return Buffer;
    }

    if (Family == 4) {
        (void)snprintf(Buffer, Capacity, "%u.%u.%u.%u", Address[0], Address[1],
                       Address[2], Address[3]);
        return Buffer;
    }

    used = 0;
    for (index = 0; index < 8; index++) {
        unsigned value = ((unsigned)Address[index * 2] << 8) |
                         (unsigned)Address[index * 2 + 1];
        int written = snprintf(Buffer + used, Capacity - used, "%s%x",
                               (index == 0) ? "" : ":", value);

        if (written <= 0 || (size_t)written >= Capacity - used) {
            Buffer[Capacity - 1] = '\0';
            return Buffer;
        }
        used += (size_t)written;
    }
    return Buffer;
}
