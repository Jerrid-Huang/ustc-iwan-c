#include "iwan_nt_crypto.h"

#include <string.h>

/*
 * MD5, following RFC 1321. The constants are the sine-derived table from the
 * specification; the shift amounts are per round.
 */

#define IWAN_NT_MD5_F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define IWAN_NT_MD5_G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define IWAN_NT_MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define IWAN_NT_MD5_I(x, y, z) ((y) ^ ((x) | ~(z)))

#define IWAN_NT_MD5_STEP(f, a, b, c, d, x, t, s) \
    do { \
        (a) += f((b), (c), (d)) + (x) + (uint32_t)(t); \
        (a) = ((a) << (s)) | ((a) >> (32u - (s))); \
        (a) += (b); \
    } while (0)

static uint32_t
IwanNtMd5Load(
    const uint8_t *Data
    )
{
    return (uint32_t)Data[0] | ((uint32_t)Data[1] << 8) |
           ((uint32_t)Data[2] << 16) | ((uint32_t)Data[3] << 24);
}

static void
IwanNtMd5Store(
    uint8_t *Data,
    uint32_t Value
    )
{
    Data[0] = (uint8_t)(Value & 0xFFu);
    Data[1] = (uint8_t)((Value >> 8) & 0xFFu);
    Data[2] = (uint8_t)((Value >> 16) & 0xFFu);
    Data[3] = (uint8_t)((Value >> 24) & 0xFFu);
}

static void
IwanNtMd5Transform(
    uint32_t State[4],
    const uint8_t Block[64]
    )
{
    uint32_t words[16];
    uint32_t a = State[0];
    uint32_t b = State[1];
    uint32_t c = State[2];
    uint32_t d = State[3];
    unsigned int index;

    for (index = 0; index < 16; index++) {
        words[index] = IwanNtMd5Load(Block + (size_t)index * 4u);
    }

    /* Round 1 */
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, a, b, c, d, words[0], 0xd76aa478, 7);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, d, a, b, c, words[1], 0xe8c7b756, 12);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, c, d, a, b, words[2], 0x242070db, 17);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, b, c, d, a, words[3], 0xc1bdceee, 22);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, a, b, c, d, words[4], 0xf57c0faf, 7);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, d, a, b, c, words[5], 0x4787c62a, 12);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, c, d, a, b, words[6], 0xa8304613, 17);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, b, c, d, a, words[7], 0xfd469501, 22);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, a, b, c, d, words[8], 0x698098d8, 7);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, d, a, b, c, words[9], 0x8b44f7af, 12);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, c, d, a, b, words[10], 0xffff5bb1, 17);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, b, c, d, a, words[11], 0x895cd7be, 22);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, a, b, c, d, words[12], 0x6b901122, 7);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, d, a, b, c, words[13], 0xfd987193, 12);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, c, d, a, b, words[14], 0xa679438e, 17);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_F, b, c, d, a, words[15], 0x49b40821, 22);

    /* Round 2 */
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, a, b, c, d, words[1], 0xf61e2562, 5);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, d, a, b, c, words[6], 0xc040b340, 9);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, c, d, a, b, words[11], 0x265e5a51, 14);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, b, c, d, a, words[0], 0xe9b6c7aa, 20);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, a, b, c, d, words[5], 0xd62f105d, 5);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, d, a, b, c, words[10], 0x02441453, 9);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, c, d, a, b, words[15], 0xd8a1e681, 14);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, b, c, d, a, words[4], 0xe7d3fbc8, 20);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, a, b, c, d, words[9], 0x21e1cde6, 5);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, d, a, b, c, words[14], 0xc33707d6, 9);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, c, d, a, b, words[3], 0xf4d50d87, 14);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, b, c, d, a, words[8], 0x455a14ed, 20);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, a, b, c, d, words[13], 0xa9e3e905, 5);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, d, a, b, c, words[2], 0xfcefa3f8, 9);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, c, d, a, b, words[7], 0x676f02d9, 14);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_G, b, c, d, a, words[12], 0x8d2a4c8a, 20);

    /* Round 3 */
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, a, b, c, d, words[5], 0xfffa3942, 4);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, d, a, b, c, words[8], 0x8771f681, 11);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, c, d, a, b, words[11], 0x6d9d6122, 16);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, b, c, d, a, words[14], 0xfde5380c, 23);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, a, b, c, d, words[1], 0xa4beea44, 4);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, d, a, b, c, words[4], 0x4bdecfa9, 11);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, c, d, a, b, words[7], 0xf6bb4b60, 16);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, b, c, d, a, words[10], 0xbebfbc70, 23);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, a, b, c, d, words[13], 0x289b7ec6, 4);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, d, a, b, c, words[0], 0xeaa127fa, 11);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, c, d, a, b, words[3], 0xd4ef3085, 16);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, b, c, d, a, words[6], 0x04881d05, 23);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, a, b, c, d, words[9], 0xd9d4d039, 4);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, d, a, b, c, words[12], 0xe6db99e5, 11);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, c, d, a, b, words[15], 0x1fa27cf8, 16);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_H, b, c, d, a, words[2], 0xc4ac5665, 23);

    /* Round 4 */
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, a, b, c, d, words[0], 0xf4292244, 6);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, d, a, b, c, words[7], 0x432aff97, 10);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, c, d, a, b, words[14], 0xab9423a7, 15);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, b, c, d, a, words[5], 0xfc93a039, 21);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, a, b, c, d, words[12], 0x655b59c3, 6);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, d, a, b, c, words[3], 0x8f0ccc92, 10);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, c, d, a, b, words[10], 0xffeff47d, 15);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, b, c, d, a, words[1], 0x85845dd1, 21);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, a, b, c, d, words[8], 0x6fa87e4f, 6);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, d, a, b, c, words[15], 0xfe2ce6e0, 10);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, c, d, a, b, words[6], 0xa3014314, 15);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, b, c, d, a, words[13], 0x4e0811a1, 21);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, a, b, c, d, words[4], 0xf7537e82, 6);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, d, a, b, c, words[11], 0xbd3af235, 10);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, c, d, a, b, words[2], 0x2ad7d2bb, 15);
    IWAN_NT_MD5_STEP(IWAN_NT_MD5_I, b, c, d, a, words[9], 0xeb86d391, 21);

    State[0] += a;
    State[1] += b;
    State[2] += c;
    State[3] += d;
}

void
IwanNtMd5Initialize(
    IWAN_NT_MD5_CTX *Context
    )
{
    Context->State[0] = 0x67452301u;
    Context->State[1] = 0xefcdab89u;
    Context->State[2] = 0x98badcfeu;
    Context->State[3] = 0x10325476u;
    Context->Bytes = 0;
    memset(Context->Buffer, 0, sizeof(Context->Buffer));
}

void
IwanNtMd5Update(
    IWAN_NT_MD5_CTX *Context,
    const void *Data,
    size_t Length
    )
{
    const uint8_t *bytes = (const uint8_t *)Data;
    size_t used = (size_t)(Context->Bytes % 64u);

    Context->Bytes += (uint64_t)Length;

    if (used != 0) {
        size_t space = 64u - used;

        if (Length < space) {
            memcpy(Context->Buffer + used, bytes, Length);
            return;
        }
        memcpy(Context->Buffer + used, bytes, space);
        IwanNtMd5Transform(Context->State, Context->Buffer);
        bytes += space;
        Length -= space;
    }

    while (Length >= 64u) {
        IwanNtMd5Transform(Context->State, bytes);
        bytes += 64u;
        Length -= 64u;
    }

    if (Length > 0) {
        memcpy(Context->Buffer, bytes, Length);
    }
}

void
IwanNtMd5Finalize(
    IWAN_NT_MD5_CTX *Context,
    uint8_t Digest[16]
    )
{
    uint8_t padding[72];
    size_t used = (size_t)(Context->Bytes % 64u);
    size_t padLength = (used < 56u) ? (56u - used) : (120u - used);
    uint64_t bits = Context->Bytes * 8u;
    unsigned int index;

    memset(padding, 0, sizeof(padding));
    padding[0] = 0x80u;
    for (index = 0; index < 8; index++) {
        padding[padLength + index] = (uint8_t)((bits >> (8u * index)) & 0xFFu);
    }
    IwanNtMd5Update(Context, padding, padLength + 8u);

    for (index = 0; index < 4; index++) {
        IwanNtMd5Store(Digest + (size_t)index * 4u, Context->State[index]);
    }
    memset(Context, 0, sizeof(*Context));
}

void
IwanNtMd5(
    const void *Data,
    size_t Length,
    uint8_t Digest[16]
    )
{
    IWAN_NT_MD5_CTX context;

    IwanNtMd5Initialize(&context);
    IwanNtMd5Update(&context, Data, Length);
    IwanNtMd5Finalize(&context, Digest);
}

/*
 * AES-128 encryption, FIPS-197. Only the forward direction is needed: the
 * protocol encrypts one password block and never decrypts in this direction.
 */

static const uint8_t IwanNtAesSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t IwanNtAesRcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint8_t
IwanNtAesMultiply(
    uint8_t Value,
    uint8_t Factor
    )
{
    uint8_t result = 0;
    uint8_t factor = Factor;

    while (factor != 0) {
        if ((factor & 1u) != 0u) {
            result ^= Value;
        }
        Value = (uint8_t)((Value << 1) ^ (((Value & 0x80u) != 0u) ? 0x1bu : 0u));
        factor >>= 1;
    }
    return result;
}

void
IwanNtAes128EncryptBlock(
    const uint8_t Key[16],
    const uint8_t Input[16],
    uint8_t Output[16]
    )
{
    uint8_t roundKeys[176];
    uint8_t state[16];
    unsigned int round;
    unsigned int index;

    memcpy(roundKeys, Key, 16);
    for (index = 16; index < 176; index += 4) {
        uint8_t temp[4];

        memcpy(temp, roundKeys + index - 4, 4);
        if ((index % 16u) == 0u) {
            uint8_t first = temp[0];

            temp[0] = (uint8_t)(IwanNtAesSbox[temp[1]] ^
                                IwanNtAesRcon[index / 16u]);
            temp[1] = IwanNtAesSbox[temp[2]];
            temp[2] = IwanNtAesSbox[temp[3]];
            temp[3] = IwanNtAesSbox[first];
        }
        roundKeys[index + 0u] =
            (uint8_t)(roundKeys[index - 16u + 0u] ^ temp[0]);
        roundKeys[index + 1u] =
            (uint8_t)(roundKeys[index - 16u + 1u] ^ temp[1]);
        roundKeys[index + 2u] =
            (uint8_t)(roundKeys[index - 16u + 2u] ^ temp[2]);
        roundKeys[index + 3u] =
            (uint8_t)(roundKeys[index - 16u + 3u] ^ temp[3]);
    }

    /*
     * A byte's position is index = row + 4 * column, the layout the standard
     * specifies for both the input block and the cipher state.
     */
    for (index = 0; index < 16; index++) {
        state[index] = (uint8_t)(Input[index] ^ roundKeys[index]);
    }

    for (round = 1; round <= 10; round++) {
        uint8_t mixed[16];

        /* SubBytes and ShiftRows in one pass: row r rotates left by r. */
        for (index = 0; index < 16; index++) {
            unsigned int row = index % 4u;
            unsigned int column = index / 4u;
            unsigned int sourceColumn = (column + row) % 4u;

            mixed[index] = IwanNtAesSbox[state[row + 4u * sourceColumn]];
        }
        memcpy(state, mixed, sizeof(state));

        if (round != 10u) {
            for (index = 0; index < 4u; index++) {
                uint8_t *column = state + (size_t)index * 4u;
                uint8_t a0 = column[0];
                uint8_t a1 = column[1];
                uint8_t a2 = column[2];
                uint8_t a3 = column[3];

                column[0] = (uint8_t)(IwanNtAesMultiply(a0, 2) ^
                                      IwanNtAesMultiply(a1, 3) ^ a2 ^ a3);
                column[1] = (uint8_t)(a0 ^ IwanNtAesMultiply(a1, 2) ^
                                      IwanNtAesMultiply(a2, 3) ^ a3);
                column[2] = (uint8_t)(a0 ^ a1 ^ IwanNtAesMultiply(a2, 2) ^
                                      IwanNtAesMultiply(a3, 3));
                column[3] = (uint8_t)(IwanNtAesMultiply(a0, 3) ^ a1 ^ a2 ^
                                      IwanNtAesMultiply(a3, 2));
            }
        }

        for (index = 0; index < 16; index++) {
            state[index] = (uint8_t)(state[index] ^
                                     roundKeys[(size_t)round * 16u + index]);
        }
    }

    memcpy(Output, state, 16);
    memset(roundKeys, 0, sizeof(roundKeys));
}
