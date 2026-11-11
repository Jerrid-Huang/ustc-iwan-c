/*
 * Known-answer tests for the two handshake primitives.
 *
 * MD5 vectors come from RFC 1321 section A.5; the AES-128 vector is the FIPS-197
 * appendix C.1 example. A protocol implementation that gets either of these wrong
 * fails against a real server in a way that looks like a credential problem, so
 * they are pinned here rather than discovered on the wire.
 */

#include <stdio.h>
#include <string.h>

#include "iwan_nt_crypto.h"

static int Failures = 0;

static void
Expect(
    const char *Name,
    const unsigned char *Actual,
    const unsigned char *Expected,
    size_t Length
    )
{
    if (memcmp(Actual, Expected, Length) != 0) {
        size_t index;

        printf("FAIL %s: got ", Name);
        for (index = 0; index < Length; index++) {
            printf("%02x", Actual[index]);
        }
        printf(", expected ");
        for (index = 0; index < Length; index++) {
            printf("%02x", Expected[index]);
        }
        printf("\n");
        Failures++;
    }
}

static void
CheckMd5(
    const char *Name,
    const void *Data,
    size_t Length,
    const unsigned char Expected[16]
    )
{
    unsigned char digest[16];

    IwanNtMd5(Data, Length, digest);
    Expect(Name, digest, Expected, sizeof(digest));
}

int
main(void)
{
    static const unsigned char Empty[16] = {
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
        0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
    };
    static const unsigned char Abc[16] = {
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
    };
    static const unsigned char MessageDigest[16] = {
        0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d,
        0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0
    };
    static const unsigned char Alphabet[16] = {
        0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00,
        0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b
    };
    static const unsigned char AesKey[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const unsigned char AesPlain[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    static const unsigned char AesCipher[16] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };
    static const char Long[] =
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
    static const unsigned char LongDigest[16] = {
        0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55,
        0xac, 0x49, 0xda, 0x2e, 0x21, 0x07, 0xb6, 0x7a
    };
    unsigned char digest[16];
    unsigned char cipher[16];
    IWAN_NT_MD5_CTX context;
    size_t index;

    CheckMd5("md5-empty", "", 0, Empty);
    CheckMd5("md5-abc", "abc", 3, Abc);
    CheckMd5("md5-message-digest", "message digest", 14, MessageDigest);
    CheckMd5("md5-alphabet", "abcdefghijklmnopqrstuvwxyz", 26, Alphabet);
    CheckMd5("md5-long", Long, strlen(Long), LongDigest);

    /*
     * The protocol hashes a header concatenated with a suffix, so streaming must
     * produce the same digest as one shot. Byte-at-a-time also exercises every
     * buffer boundary in the update path.
     */
    IwanNtMd5Initialize(&context);
    for (index = 0; index < strlen(Long); index++) {
        IwanNtMd5Update(&context, Long + index, 1);
    }
    IwanNtMd5Finalize(&context, digest);
    Expect("md5-streamed", digest, LongDigest, sizeof(digest));

    IwanNtAes128EncryptBlock(AesKey, AesPlain, cipher);
    Expect("aes-fips197", cipher, AesCipher, sizeof(cipher));

    if (Failures != 0) {
        printf("crypto: %d failures\n", Failures);
        return 1;
    }
    printf("crypto: 7 checks, 0 failures\n");
    return 0;
}
