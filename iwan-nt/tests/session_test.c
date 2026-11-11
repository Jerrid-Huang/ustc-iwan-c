/*
 * Host tests for the control-plane framing.
 *
 * Two kinds of check here. Structural ones pin the exact byte layout the server
 * expects (an off-by-one in TLV lengths makes every OPEN fail authentication, and
 * the server never says why). Vector ones parse an OPEN_ACK captured from the
 * deployment, which is the only way to know the parser agrees with a real peer.
 */

#include <stdio.h>
#include <string.h>

#include "iwan_nt_session.h"

static int Failures = 0;
static int Checks = 0;

static void
Check(
    const char *Name,
    int Condition
    )
{
    Checks++;
    if (!Condition) {
        printf("FAIL %s\n", Name);
        Failures++;
    }
}

static void
CheckBytes(
    const char *Name,
    const uint8_t *Actual,
    const uint8_t *Expected,
    size_t Length
    )
{
    Checks++;
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

/* OPEN_ACK captured from the deployment: sid 9, token 0xe4977730, 1400 MTU. */
static const uint8_t RealAck[] = {
    0x12, 0x01, 0x00, 0x09, 0xe4, 0x97, 0x77, 0x30,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x04, 0x05, 0x78,
    0x04, 0x06, 0xc6, 0x12, 0x03, 0xe9,
    0x06, 0x06, 0x64, 0x64, 0x01, 0x01,
    0x05, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x03, 0x01
};

static void
TestKey(void)
{
    uint8_t key[8];
    static const uint8_t expected[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    IwanNtSessionKey("tester", "testpass123", key);
    Check("key-not-zero", memcmp(key, expected, sizeof(key)) != 0);

    /* The same inputs must always give the same key; a drifting derivation would
     * silently produce a tunnel that carries ciphertext nobody can read. */
    {
        uint8_t again[8];
        IwanNtSessionKey("tester", "testpass123", again);
        CheckBytes("key-stable", again, key, sizeof(key));
    }
}

static void
TestOpen(void)
{
    static const uint8_t header[8] = { 0x13, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    IWAN_NT_SESSION_OPEN open;
    uint8_t frame[IWAN_NT_SESSION_CONTROL_MAX];
    size_t length = 0;
    IWAN_NT_SESSION_RESULT result;

    open.User = "_rev_m_2";
    open.Password = "testpass123";
    open.Mtu = 1400;

    result = IwanNtSessionBuildOpen(&open, frame, sizeof(frame), &length);
    Check("open-ok", result == IwanNtSessionOk);
    /* The reference client produces 59 bytes for an 8-character user. */
    /* 24 prefix + 4 mtu + 10 user + 18 password + 3 encrypt = 59. */
    Check("open-length", length == 59u);
    CheckBytes("open-header", frame, header, sizeof(header));
    CheckBytes("open-mtu-tlv", frame + 24u, (const uint8_t *)"\x03\x04\x05\x78", 4u);
    CheckBytes("open-user-tlv", frame + 28u, (const uint8_t *)"\x01\x0a_rev_m_2", 10u);
    CheckBytes("open-password-tlv", frame + 38u, (const uint8_t *)"\x02\x12", 2u);
    CheckBytes("open-encrypt-tlv", frame + 56u, (const uint8_t *)"\x08\x03\x01", 3u);

    /* Capacity must be honoured rather than overrun. */
    result = IwanNtSessionBuildOpen(&open, frame, 40u, &length);
    Check("open-too-large", result == IwanNtSessionTooLarge);

    /* NULL inputs are a caller bug, not a crash. */
    result = IwanNtSessionBuildOpen(NULL, frame, sizeof(frame), &length);
    Check("open-null", result == IwanNtSessionBadArgument);

    /*
     * The whole frame, byte for byte, against a vector built outside this code:
     * python hashlib for the signature (md5 of the header followed by "mw") and
     * the password key (md5 of "mw" + user), then openssl enc -aes-128-ecb for the
     * password block. A builder and its test that both come from the same
     * assumption agree even when both are wrong; this one cannot.
     */
    {
        static const uint8_t expected[] = {
            0x13, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x01, 0x68, 0x0d,
            0xe3, 0xa6, 0xb3, 0xdd, 0x33, 0x6a, 0xc5, 0x57, 0xc8, 0x7b, 0x50, 0x1b,
            0x03, 0x04, 0x05, 0x78, 0x01, 0x0a, 0x5f, 0x72, 0x65, 0x76, 0x5f, 0x6d,
            0x5f, 0x32, 0x02, 0x12, 0x29, 0xc3, 0x36, 0x81, 0xe8, 0xc0, 0xd8, 0xa1,
            0xd9, 0xca, 0x02, 0x74, 0x62, 0x78, 0x22, 0xa0, 0x08, 0x03, 0x01,
        };
        IWAN_NT_SESSION_OPEN wire;
        uint8_t built[128];
        size_t builtLength = 0u;

        wire.User = "_rev_m_2";
        wire.Password = "testpass123";
        wire.Mtu = 1400u;
        result = IwanNtSessionBuildOpen(&wire, built, sizeof(built), &builtLength);
        Check("wire-ok", result == IwanNtSessionOk);
        Check("wire-length", builtLength == sizeof(expected));
        CheckBytes("wire-bytes", built, expected, sizeof(expected));
    }
}

static void
TestParseAck(void)
{
    IWAN_NT_SESSION_ACK ack;
    IWAN_NT_SESSION_RESULT result;
    uint8_t frame[sizeof(RealAck)];

    memcpy(frame, RealAck, sizeof(frame));
    result = IwanNtSessionParseAck(frame, sizeof(frame), &ack);
    Check("ack-ok", result == IwanNtSessionOk);
    Check("ack-sid", ack.Sid == 9u);
    Check("ack-token", ack.Token == 0xe4977730u);
    Check("ack-mtu", ack.Mtu == 1400u);
    Check("ack-encrypted", ack.Encrypted == 1u);
    Check("ack-has-address", ack.HasAddress == 1);
    CheckBytes("ack-address", ack.Address, (const uint8_t *)"\xc6\x12\x03\xe9", 4u);
    Check("ack-has-gateway", ack.HasGateway == 1);
    CheckBytes("ack-gateway", ack.Gateway, (const uint8_t *)"\x64\x64\x01\x01", 4u);

    /* A truncated frame must be rejected before any TLV is read. */
    result = IwanNtSessionParseAck(frame, 12u, &ack);
    Check("ack-short", result == IwanNtSessionShortFrame);

    /* Wrong frame type: an ECHO response is not an ACK. */
    frame[0] = 0x16;
    result = IwanNtSessionParseAck(frame, sizeof(frame), &ack);
    Check("ack-wrong-type", result == IwanNtSessionWrongType);

    /* A TLV whose length runs past the buffer must not be trusted. */
    memcpy(frame, RealAck, sizeof(frame));
    frame[24u + 1u] = 0x40;
    result = IwanNtSessionParseAck(frame, sizeof(frame), &ack);
    Check("ack-bad-tlv", result == IwanNtSessionBadTlv);
}

static void
TestEcho(void)
{
    uint8_t frame[IWAN_NT_SESSION_ECHO_LEN];
    size_t length = 0;
    IWAN_NT_SESSION_RESULT result;

    result = IwanNtSessionBuildEchoRequest(9u, 0xe4977730u, 0x1122334455667788ull,
                                          frame, sizeof(frame), &length);
    Check("echo-ok", result == IwanNtSessionOk);
    Check("echo-length", length == IWAN_NT_SESSION_ECHO_LEN);
    CheckBytes("echo-header", frame, (const uint8_t *)"\x15\x00\x00\x09\xe4\x97\x77\x30", 8u);
    /* The tick is host order, i.e. little endian on every platform this runs on. */
    CheckBytes("echo-tick", frame + 24u, (const uint8_t *)"\x88\x77\x66\x55\x44\x33\x22\x11", 8u);
    CheckBytes("echo-cur", frame + 32u, (const uint8_t *)"\x00\x00\x00\x00", 4u);
    CheckBytes("echo-min", frame + 36u, (const uint8_t *)"\x00\x4c\x4b\x40", 4u);
    CheckBytes("echo-max", frame + 40u, (const uint8_t *)"\x00\x00\x00\x00", 4u);
    CheckBytes("echo-sdrt", frame + 48u, (const uint8_t *)"SDRT", 4u);
    CheckBytes("echo-tail", frame + 52u, (const uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8u);

    result = IwanNtSessionBuildEchoRequest(9u, 1u, 0u, frame, 40u, &length);
    Check("echo-too-large", result == IwanNtSessionTooLarge);
}

static void
TestEchoResponse(void)
{
    uint8_t frame[IWAN_NT_SESSION_ECHO_LEN];
    IWAN_NT_SESSION_ECHO echo;
    IWAN_NT_SESSION_RESULT result;
    size_t length = 0;

    /* A response is the request echoed back with the type and delays filled in. */
    result = IwanNtSessionBuildEchoRequest(9u, 0xe4977730u, 0x1122334455667788ull,
                                          frame, sizeof(frame), &length);
    Check("echo-resp-build", result == IwanNtSessionOk);
    frame[0] = 0x16;
    frame[32] = 0x00;
    frame[33] = 0x00;
    frame[34] = 0x1f;
    frame[35] = 0x40;   /* 8000 us */
    frame[36] = 0x00;
    frame[37] = 0x00;
    frame[38] = 0x0d;
    frame[39] = 0xac;   /* 3500 us */
    frame[40] = 0x00;
    frame[41] = 0x00;
    frame[42] = 0x27;
    frame[43] = 0x10;   /* 10000 us */

    result = IwanNtSessionParseEchoResponse(frame, length, &echo);
    Check("echo-resp-ok", result == IwanNtSessionOk);
    Check("echo-resp-sid", echo.Sid == 9u);
    Check("echo-resp-token", echo.Token == 0xe4977730u);
    Check("echo-resp-tick", echo.Tick == 0x1122334455667788ull);
    Check("echo-resp-current", echo.Current == 8000u);
    Check("echo-resp-minimum", echo.Minimum == 3500u);
    Check("echo-resp-maximum", echo.Maximum == 10000u);

    Check("echo-resp-short", IwanNtSessionParseEchoResponse(frame, 40u, &echo) ==
                                 IwanNtSessionShortFrame);

    /* Routing helper: an unknown type must not be mistaken for a known one. */
    Check("type-open", IwanNtSessionType(frame, length) == 0x16u);
    Check("type-null", IwanNtSessionType(NULL, 0u) == 0u);
}

int
main(void)
{
    TestKey();
    TestOpen();
    TestParseAck();
    TestEcho();
    TestEchoResponse();

    if (Failures != 0) {
        printf("session: %d failures\n", Failures);
        return 1;
    }
    printf("session: %d checks, 0 failures\n", Checks);
    return 0;
}
