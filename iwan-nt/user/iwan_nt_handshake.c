#include "iwan_nt_handshake.h"

#include <string.h>

static int
CopyName(
    char *Destination,
    size_t Capacity,
    const char *Source
    )
{
    size_t length;

    if (Destination == NULL || Capacity == 0u) {
        return 0;
    }
    if (Source == NULL) {
        Destination[0] = '\0';
        return 1;
    }

    length = strlen(Source);
    if (length >= Capacity) {
        return 0;
    }
    memcpy(Destination, Source, length + 1u);
    return 1;
}

int
IwanNtHandshakeInitialize(
    IWAN_NT_HANDSHAKE *Handshake,
    const char *User,
    const char *Password,
    uint16_t Mtu,
    uint64_t NowMs
    )
{
    if (Handshake == NULL) {
        return 0;
    }

    memset(Handshake, 0, sizeof(*Handshake));
    if (!CopyName(Handshake->User, sizeof(Handshake->User), User)) {
        return 0;
    }
    if (!CopyName(Handshake->Password, sizeof(Handshake->Password), Password)) {
        return 0;
    }

    Handshake->Mtu = Mtu;
    Handshake->State = IwanNtHandshakeDown;
    /* Send the first OPEN on the first tick rather than a full interval later. */
    Handshake->NextActionMs = NowMs;
    return 1;
}

void
IwanNtHandshakeReset(
    IWAN_NT_HANDSHAKE *Handshake,
    uint64_t NowMs
    )
{
    if (Handshake == NULL) {
        return;
    }

    Handshake->State = IwanNtHandshakeDown;
    Handshake->Sid = 0;
    Handshake->Token = 0;
    Handshake->Encrypted = 0;
    memset(Handshake->Key, 0, sizeof(Handshake->Key));
    /*
     * Wait one interval before the next OPEN: an immediate retry would spin
     * against a peer that is already refusing us.
     */
    Handshake->NextActionMs = NowMs + IWAN_NT_HANDSHAKE_OPEN_MS;
}

int
IwanNtHandshakeTick(
    IWAN_NT_HANDSHAKE *Handshake,
    uint64_t NowMs,
    uint8_t *Buffer,
    size_t Capacity,
    size_t *Length
    )
{
    if (Handshake == NULL || Buffer == NULL || Length == NULL) {
        return 0;
    }

    /*
     * A session that has been silent for the whole timeout is gone. Reset puts
     * the machine back in Down and schedules the next OPEN one interval out, so
     * the caller does not have to drive reconnection itself.
     */
    if (Handshake->State == IwanNtHandshakeUp &&
        NowMs > Handshake->LastAcceptedMs &&
        (NowMs - Handshake->LastAcceptedMs) >
            (uint64_t)IWAN_NT_HANDSHAKE_DATA_TIMEOUT_MS) {
        Handshake->Timeouts++;
        IwanNtHandshakeReset(Handshake, NowMs);
        return 0;
    }

    if (NowMs < Handshake->NextActionMs) {
        return 0;
    }

    if (Handshake->State == IwanNtHandshakeUp) {
        IWAN_NT_SESSION_RESULT result = IwanNtSessionBuildEchoRequest(
            Handshake->Sid, Handshake->Token, NowMs, Buffer, Capacity, Length);

        if (result != IwanNtSessionOk) {
            Handshake->Fault = result;
            return 0;
        }
        Handshake->Echoes++;
        Handshake->NextActionMs = NowMs + IWAN_NT_HANDSHAKE_ECHO_MS;
        return 1;
    }

    {
        IWAN_NT_SESSION_OPEN open;
        IWAN_NT_SESSION_RESULT result;

        open.User = Handshake->User;
        open.Password = Handshake->Password;
        open.Mtu = Handshake->Mtu;

        result = IwanNtSessionBuildOpen(&open, Buffer, Capacity, Length);
        if (result != IwanNtSessionOk) {
            Handshake->Fault = result;
            return 0;
        }
        Handshake->Opens++;
        Handshake->NextActionMs = NowMs + IWAN_NT_HANDSHAKE_OPEN_MS;
        return 1;
    }
}

IWAN_NT_HANDSHAKE_EVENT
IwanNtHandshakeOnFrame(
    IWAN_NT_HANDSHAKE *Handshake,
    const uint8_t *Frame,
    size_t Length,
    uint64_t NowMs
    )
{
    if (Handshake == NULL || Frame == NULL || Length < 1u) {
        return IwanNtHandshakeEventNone;
    }

    /*
     * Every control frame the peer sends carries the header signature. Drop
     * anything else as foreign: an unsigned CLOSE would otherwise tear the
     * session down, and an unsigned answer would fault a healthy one.
     */
    if (IwanNtSessionVerify(Frame, Length) == 0) {
        Handshake->ForeignFrames++;
        return IwanNtHandshakeEventNone;
    }

    /* Any authenticated frame proves the peer is alive and the key still fits. */
    Handshake->LastAcceptedMs = NowMs;

    switch (Frame[0]) {
    case IWAN_NT_SESSION_TYPE_OPEN_ACK:
    {
        IWAN_NT_SESSION_ACK ack;
        IWAN_NT_SESSION_RESULT result = IwanNtSessionParseAck(Frame, Length, &ack);

        if (result != IwanNtSessionOk) {
            Handshake->Fault = result;
            return IwanNtHandshakeEventFault;
        }
        if (Handshake->State == IwanNtHandshakeUp &&
            ack.Sid == Handshake->Sid && ack.Token == Handshake->Token) {
            /* A duplicate answer to a retransmitted OPEN: nothing changed. */
            return IwanNtHandshakeEventNone;
        }

        IwanNtSessionKey(Handshake->User, Handshake->Password, Handshake->Key);
        Handshake->Sid = ack.Sid;
        Handshake->Token = ack.Token;
        Handshake->Encrypted = ack.Encrypted;
        Handshake->MtuFromPeer = ack.Mtu;
        Handshake->HasAddress = ack.HasAddress ? 1 : 0;
        Handshake->HasGateway = ack.HasGateway ? 1 : 0;
        if (Handshake->HasAddress) {
            memcpy(Handshake->Address, ack.Address, sizeof(Handshake->Address));
        }
        if (Handshake->HasGateway) {
            memcpy(Handshake->Gateway, ack.Gateway, sizeof(Handshake->Gateway));
        }
        Handshake->State = IwanNtHandshakeUp;
        Handshake->EverEstablished = 1;
        Handshake->NextActionMs = NowMs + IWAN_NT_HANDSHAKE_ECHO_MS;
        return IwanNtHandshakeEventEstablished;
    }

    case IWAN_NT_SESSION_TYPE_OPEN_REJECT:
        Handshake->Rejects++;
        IwanNtHandshakeReset(Handshake, NowMs);
        return IwanNtHandshakeEventRejected;

    case IWAN_NT_SESSION_TYPE_CLOSE:
        Handshake->Closes++;
        IwanNtHandshakeReset(Handshake, NowMs);
        return IwanNtHandshakeEventClosed;

    case IWAN_NT_SESSION_TYPE_ECHO_RESPONSE:
    {
        IWAN_NT_SESSION_ECHO echo;
        IWAN_NT_SESSION_RESULT result =
            IwanNtSessionParseEchoResponse(Frame, Length, &echo);

        if (result != IwanNtSessionOk) {
            Handshake->Fault = result;
            return IwanNtHandshakeEventFault;
        }
        if (Handshake->State != IwanNtHandshakeUp) {
            /* An answer without a session is a stray from an older exchange. */
            return IwanNtHandshakeEventNone;
        }

        Handshake->DelayCurrent = echo.Current;
        Handshake->DelayMinimum = echo.Minimum;
        Handshake->DelayMaximum = echo.Maximum;
        Handshake->EchoAnswers++;
        return IwanNtHandshakeEventEchoAnswer;
    }

    default:
        Handshake->ForeignFrames++;
        return IwanNtHandshakeEventNone;
    }
}
