#include <stdio.h>
#include <string.h>

#include "iwan_nt_peer.h"

static int Failures = 0;
static int Checks = 0;

#define CHECK(Condition)                                                       \
    do {                                                                       \
        Checks++;                                                              \
        if (!(Condition)) {                                                    \
            printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #Condition);         \
            Failures++;                                                        \
        }                                                                      \
    } while (0)

/* Build the answer the deployment sends, for a chosen sid and token. */
static size_t
BuildAck(
    uint8_t *Buffer,
    size_t Capacity,
    uint16_t Sid,
    uint32_t Token
    )
{
    static const uint8_t body[] = {
        0x03, 0x04, 0x05, 0x78,
        0x04, 0x06, 0xc6, 0x12, 0x03, 0xe9,
        0x06, 0x06, 0x64, 0x64, 0x01, 0x01,
        0x05, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x03, 0x01
    };

    if (Capacity < 24u + sizeof(body)) {
        return 0;
    }
    memset(Buffer, 0, 24u);
    Buffer[0] = IWAN_NT_SESSION_TYPE_OPEN_ACK;
    Buffer[1] = 1;
    /* Machine-order words, as the peer writes them. */
    Buffer[2] = (uint8_t)(Sid & 0xFFu);
    Buffer[3] = (uint8_t)((Sid >> 8) & 0xFFu);
    Buffer[4] = (uint8_t)(Token & 0xFFu);
    Buffer[5] = (uint8_t)((Token >> 8) & 0xFFu);
    Buffer[6] = (uint8_t)((Token >> 16) & 0xFFu);
    Buffer[7] = (uint8_t)((Token >> 24) & 0xFFu);
    memcpy(Buffer + 24u, body, sizeof(body));
    IwanNtSessionSignFrame(Buffer);
    return 24u + sizeof(body);
}

static size_t
BuildEchoAnswer(
    uint8_t *Buffer,
    size_t Capacity,
    uint16_t Sid,
    uint32_t Token,
    uint64_t Tick,
    uint32_t Current,
    uint32_t Minimum,
    uint32_t Maximum
    )
{
    size_t length = 60u;
    size_t index;

    if (Capacity < length) {
        return 0;
    }
    memset(Buffer, 0, length);
    Buffer[0] = IWAN_NT_SESSION_TYPE_ECHO_RESPONSE;
    Buffer[1] = 0;
    /* Machine-order words, as the peer writes them. */
    Buffer[2] = (uint8_t)(Sid & 0xFFu);
    Buffer[3] = (uint8_t)((Sid >> 8) & 0xFFu);
    Buffer[4] = (uint8_t)(Token & 0xFFu);
    Buffer[5] = (uint8_t)((Token >> 8) & 0xFFu);
    Buffer[6] = (uint8_t)((Token >> 16) & 0xFFu);
    Buffer[7] = (uint8_t)((Token >> 24) & 0xFFu);
    /* The tick and the three delays sit at 24, 32, 36 and 40. */
    for (index = 0u; index < 8u; index++) {
        Buffer[24u + index] = (uint8_t)((Tick >> (8u * index)) & 0xFFu);
    }
    for (index = 0u; index < 4u; index++) {
        Buffer[32u + index] = (uint8_t)((Current >> (8u * index)) & 0xFFu);
        Buffer[36u + index] = (uint8_t)((Minimum >> (8u * index)) & 0xFFu);
        Buffer[40u + index] = (uint8_t)((Maximum >> (8u * index)) & 0xFFu);
    }
    IwanNtSessionSignFrame(Buffer);
    return length;
}

/* Send the first OPEN immediately, then one every two seconds. */
static void
TestOpenRetry(void)
{
    IWAN_NT_PEER handshake;
    uint8_t frame[IWAN_NT_SESSION_CONTROL_MAX];
    size_t length = 0;
    unsigned sent = 0;
    uint64_t now;

    CHECK(IwanNtPeerInitialize(&handshake, "_rev_m_2", "secret", 1400, 0u));
    for (now = 0; now <= 7000u; now += 100u) {
        if (IwanNtPeerTick(&handshake, now, frame, sizeof(frame), &length)) {
            CHECK(length == 59u);
            CHECK(frame[0] == IWAN_NT_SESSION_TYPE_OPEN);
            sent++;
        }
    }
    /* t = 0, 2000, 4000, 6000 */
    CHECK(sent == 4u);
    CHECK(handshake.Opens == 4u);
    CHECK(handshake.State == IwanNtPeerDown);
}

/* The answer installs the session and switches the timer to keepalives. */
static void
TestEstablished(void)
{
    IWAN_NT_PEER handshake;
    uint8_t frame[IWAN_NT_SESSION_CONTROL_MAX];
    uint8_t ack[128];
    size_t length = 0;
    size_t ackLength;
    uint64_t now;
    unsigned echoes = 0;

    CHECK(IwanNtPeerInitialize(&handshake, "_rev_m_2", "secret", 1400, 0u));
    CHECK(IwanNtPeerTick(&handshake, 0u, frame, sizeof(frame), &length) == 1);
    CHECK(handshake.Opens == 1u);

    ackLength = BuildAck(ack, sizeof(ack), 9u, 0xe4977730u);
    CHECK(ackLength > 0);
    CHECK(IwanNtPeerOnFrame(&handshake, ack, ackLength, 500u) ==
          IwanNtPeerEventEstablished);
    CHECK(handshake.State == IwanNtPeerUp);
    CHECK(handshake.Sid == 9u);
    CHECK(handshake.Token == 0xe4977730u);
    CHECK(handshake.Encrypted == 1u);
    CHECK(handshake.EverEstablished == 1);

    /* The address the server assigned must survive for the caller to install. */
    CHECK(handshake.MtuFromPeer == 1400u);
    CHECK(handshake.HasAddress == 1);
    CHECK(handshake.Address[0] == 0xc6 && handshake.Address[1] == 0x12 &&
          handshake.Address[2] == 0x03 && handshake.Address[3] == 0xe9);
    CHECK(handshake.HasGateway == 1);
    CHECK(handshake.Gateway[0] == 0x64 && handshake.Gateway[3] == 0x01);

    /* The key must be the one derived from the credentials, not leftover zeros. */
    {
        uint8_t expected[8];

        IwanNtSessionKey("_rev_m_2", "secret", expected);
        CHECK(memcmp(handshake.Key, expected, sizeof(expected)) == 0);
    }

    /* No keepalive before the interval, then one, then another. */
    CHECK(IwanNtPeerTick(&handshake, 1000u, frame, sizeof(frame), &length) == 0);
    for (now = 500u; now <= 7000u; now += 100u) {
        if (IwanNtPeerTick(&handshake, now, frame, sizeof(frame), &length)) {
            CHECK(frame[0] == IWAN_NT_SESSION_TYPE_ECHO_REQUEST);
            CHECK(length == IWAN_NT_SESSION_ECHO_LEN);
            echoes++;
        }
    }
    /* t = 2500, 4500, 6500 */
    CHECK(echoes == 3u);
    CHECK(handshake.Echoes == 3u);
}

/* A duplicate answer for the session we already have changes nothing. */
static void
TestDuplicateAck(void)
{
    IWAN_NT_PEER handshake;
    uint8_t ack[128];
    size_t ackLength;

    CHECK(IwanNtPeerInitialize(&handshake, "u", "p", 1400, 0u));
    ackLength = BuildAck(ack, sizeof(ack), 9u, 0xe4977730u);
    CHECK(IwanNtPeerOnFrame(&handshake, ack, ackLength, 0u) ==
          IwanNtPeerEventEstablished);
    CHECK(handshake.NextActionMs == IWAN_NT_PEER_ECHO_MS);
    CHECK(IwanNtPeerOnFrame(&handshake, ack, ackLength, 100u) ==
          IwanNtPeerEventNone);
    CHECK(handshake.NextActionMs == IWAN_NT_PEER_ECHO_MS);
}

/* A rejection returns to OPEN after one interval rather than immediately. */
static void
TestRejected(void)
{
    IWAN_NT_PEER handshake;
    uint8_t reject[24];
    uint8_t frame[IWAN_NT_SESSION_CONTROL_MAX];
    size_t length = 0;

    CHECK(IwanNtPeerInitialize(&handshake, "u", "p", 1400, 0u));
    memset(reject, 0, sizeof(reject));
    reject[0] = IWAN_NT_SESSION_TYPE_OPEN_REJECT;

    /* An unsigned rejection is not the peer speaking: ignore, do not reset. */
    CHECK(IwanNtPeerOnFrame(&handshake, reject, sizeof(reject), 1000u) ==
          IwanNtPeerEventNone);
    CHECK(handshake.Rejects == 0u);
    CHECK(handshake.ForeignFrames == 1u);

    IwanNtSessionSignFrame(reject);

    CHECK(IwanNtPeerOnFrame(&handshake, reject, sizeof(reject), 1000u) ==
          IwanNtPeerEventRejected);
    CHECK(handshake.State == IwanNtPeerDown);
    CHECK(handshake.Rejects == 1u);
    /* Not before the interval, even though the timer had already expired. */
    CHECK(IwanNtPeerTick(&handshake, 1500u, frame, sizeof(frame), &length) == 0);
    CHECK(IwanNtPeerTick(&handshake, 3000u, frame, sizeof(frame), &length) == 1);
    CHECK(frame[0] == IWAN_NT_SESSION_TYPE_OPEN);
}

/* A CLOSE mid-session drops the key material and waits one interval. */
static void
TestClosed(void)
{
    IWAN_NT_PEER handshake;
    uint8_t ack[128];
    uint8_t closeFrame[24];
    size_t ackLength;
    size_t index;

    CHECK(IwanNtPeerInitialize(&handshake, "u", "p", 1400, 0u));
    ackLength = BuildAck(ack, sizeof(ack), 9u, 0xe4977730u);
    CHECK(IwanNtPeerOnFrame(&handshake, ack, ackLength, 0u) ==
          IwanNtPeerEventEstablished);

    memset(closeFrame, 0, sizeof(closeFrame));
    closeFrame[0] = IWAN_NT_SESSION_TYPE_CLOSE;
    IwanNtSessionSignFrame(closeFrame);
    CHECK(IwanNtPeerOnFrame(&handshake, closeFrame, sizeof(closeFrame), 500u) ==
          IwanNtPeerEventClosed);
    CHECK(handshake.Closes == 1u);
    CHECK(handshake.State == IwanNtPeerDown);
    CHECK(handshake.Sid == 0u);
    CHECK(handshake.Token == 0u);
    for (index = 0; index < sizeof(handshake.Key); index++) {
        CHECK(handshake.Key[index] == 0);
    }
    /* It still counts as having been up once, which is what callers report. */
    CHECK(handshake.EverEstablished == 1);
}

/* The peer's measured delays must survive as numbers, not be dropped. */
static void
TestEchoAnswer(void)
{
    IWAN_NT_PEER handshake;
    uint8_t ack[128];
    uint8_t echo[128];
    size_t ackLength;
    size_t echoLength;

    CHECK(IwanNtPeerInitialize(&handshake, "u", "p", 1400, 0u));
    ackLength = BuildAck(ack, sizeof(ack), 9u, 0xe4977730u);
    CHECK(IwanNtPeerOnFrame(&handshake, ack, ackLength, 0u) ==
          IwanNtPeerEventEstablished);

    echoLength = BuildEchoAnswer(echo, sizeof(echo), 9u, 0xe4977730u,
                                 123456u, 8000u, 3500u, 12000u);
    CHECK(echoLength == IWAN_NT_SESSION_ECHO_LEN);
    CHECK(IwanNtPeerOnFrame(&handshake, echo, echoLength, 100u) ==
          IwanNtPeerEventEchoAnswer);
    CHECK(handshake.DelayCurrent == 8000u);
    CHECK(handshake.DelayMinimum == 3500u);
    CHECK(handshake.DelayMaximum == 12000u);
    CHECK(handshake.EchoAnswers == 1u);

    /* While down, a stray answer is ignored rather than adopted. */
    IwanNtPeerReset(&handshake, 200u);
    CHECK(IwanNtPeerOnFrame(&handshake, echo, echoLength, 300u) ==
          IwanNtPeerEventNone);
    CHECK(handshake.EchoAnswers == 1u);
}

/* A truncated or malformed answer is a fault, not a silent retry. */
static void
TestFault(void)
{
    IWAN_NT_PEER handshake;
    uint8_t ack[128];
    size_t ackLength;

    CHECK(IwanNtPeerInitialize(&handshake, "u", "p", 1400, 0u));
    ackLength = BuildAck(ack, sizeof(ack), 9u, 0xe4977730u);
    /* A TLV whose length runs past the frame. */
    ack[25] = 0x7f;
    CHECK(IwanNtPeerOnFrame(&handshake, ack, ackLength, 0u) ==
          IwanNtPeerEventFault);
    CHECK(handshake.Fault != IwanNtSessionOk);
    CHECK(handshake.State == IwanNtPeerDown);
}

static void
TestDataTimeout(void)
{
    IWAN_NT_PEER handshake;
    uint8_t ack[IWAN_NT_SESSION_CONTROL_MAX];
    uint8_t frame[IWAN_NT_SESSION_CONTROL_MAX];
    size_t ackLength;
    size_t length = 0;

    CHECK(IwanNtPeerInitialize(&handshake, "u", "p", 1400, 0u));
    ackLength = BuildAck(ack, sizeof(ack), 9u, 0xe4977730u);
    CHECK(ackLength > 0);
    CHECK(IwanNtPeerOnFrame(&handshake, ack, ackLength, 1000u) ==
          IwanNtPeerEventEstablished);

    /* Silence up to the timeout is normal: the peer only answers every 2 s. */
    CHECK(IwanNtPeerTick(&handshake, 1000u + 14000u, frame, sizeof(frame),
                              &length) == 1);
    CHECK(handshake.State == IwanNtPeerUp);
    CHECK(handshake.Timeouts == 0u);

    /*
     * One millisecond past it the session is gone: the socket still accepts our
     * writes, so only the peer going quiet can explain no frame for this long.
     */
    (void)IwanNtPeerTick(&handshake, 1000u + 15001u, frame, sizeof(frame),
                              &length);
    CHECK(handshake.State == IwanNtPeerDown);
    CHECK(handshake.Timeouts == 1u);
    CHECK(handshake.Sid == 0u);
    CHECK(handshake.Token == 0u);

    /* And it starts over rather than staying down forever. */
    CHECK(IwanNtPeerTick(&handshake, 1000u + 15001u + 2000u, frame,
                              sizeof(frame), &length) == 1);
    CHECK(frame[0] == IWAN_NT_SESSION_TYPE_OPEN);
}

int
main(void)
{
    TestOpenRetry();
    TestEstablished();
    TestDuplicateAck();
    TestRejected();
    TestDataTimeout();
    TestClosed();
    TestEchoAnswer();
    TestFault();

    if (Failures != 0) {
        printf("handshake: %d failures\n", Failures);
        return 1;
    }
    printf("handshake: %d checks, 0 failures\n", Checks);
    return 0;
}
