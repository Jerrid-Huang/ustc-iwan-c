#include "iwannt_connect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "iwan_nt_session.h"

/* The deployed protocol resends OPEN every two seconds until the answer lands. */
#define IWANNT_OPEN_INTERVAL_MS 2000u
#define IWANNT_ECHO_INTERVAL_MS 2000u

typedef struct _IWANNT_CONNECT_STATE {
    USHORT Sid;
    ULONG Token;
    ULONG Encrypted;
    BOOLEAN Established;
    ULONG OpensSent;
    ULONG EchoesSent;
    ULONG EchoesAnswered;
    ULONG FramesRead;
    ULONG ForeignFrames;
    ULONG Rejected;
    ULONG Closed;
    BOOLEAN EverEstablished;
    ULONGLONG NextOpen;
    ULONGLONG NextEcho;
} IWANNT_CONNECT_STATE;

static void
PrintAddress(
    _In_ const UCHAR Address[4]
    )
{
    printf("%u.%u.%u.%u", Address[0], Address[1], Address[2], Address[3]);
}

/*
 * Report one received control frame. The caller has already routed it by type, so
 * anything unexpected here is worth naming: a silent skip would hide a protocol
 * change behind an idle loop.
 */
static int
HandleFrame(
    _Inout_ PIWAN_NT_DEVICE Device,
    _Inout_ IWANNT_CONNECT_STATE *State,
    _In_ const UCHAR *Frame,
    _In_ size_t Length,
    _In_ const char *User,
    _In_ const char *Password
    )
{
    IWAN_NT_SESSION_RESULT result;

    if (Frame[0] == IWAN_NT_SESSION_TYPE_OPEN_ACK) {
        IWAN_NT_SESSION_ACK ack;
        UCHAR key[8];

        result = IwanNtSessionParseAck(Frame, Length, &ack);
        if (result != IwanNtSessionOk) {
            fprintf(stderr, "ACK parse failed: %d (%lu bytes)\n", (int)result,
                    (unsigned long)Length);
            return 1;
        }

        IwanNtSessionKey(User, Password, key);
        if (IwanNtSetSession(Device, ack.Sid, ack.Token, ack.Encrypted ? TRUE : FALSE,
                             key) == FALSE) {
            fprintf(stderr, "SET_SESSION failed: %lu\n", GetLastError());
            return 1;
        }

        State->Sid = ack.Sid;
        State->Token = ack.Token;
        State->Encrypted = ack.Encrypted;
        State->Established = TRUE;
        State->EverEstablished = TRUE;

        printf("CONNECT ack sid=%u token=%08lx mtu=%u encrypted=%lu",
               (unsigned)ack.Sid, (unsigned long)ack.Token, (unsigned)ack.Mtu,
               (unsigned long)ack.Encrypted);
        if (ack.HasAddress) {
            printf(" tun=");
            PrintAddress(ack.Address);
        }
        if (ack.HasGateway) {
            printf(" gw=");
            PrintAddress(ack.Gateway);
        }
        printf("\n");
        return 0;
    }

    if (Frame[0] == IWAN_NT_SESSION_TYPE_OPEN_REJECT) {
        /*
         * A rejection is not fatal: the server may be restarting, or the session
         * may have been replaced. Forget the session, announce it, and let the
         * retry timer send OPEN again.
         */
        (void)IwanNtClearSession(Device);
        State->Established = FALSE;
        State->Rejected++;
        printf("CONNECT rejected by peer (#%lu)\n", (unsigned long)State->Rejected);
        return 0;
    }

    if (Frame[0] == IWAN_NT_SESSION_TYPE_ECHO_RESPONSE) {
        IWAN_NT_SESSION_ECHO echo;

        result = IwanNtSessionParseEchoResponse(Frame, Length, &echo);
        if (result != IwanNtSessionOk) {
            fprintf(stderr, "ECHO parse failed: %d\n", (int)result);
            return 1;
        }
        State->EchoesAnswered++;
        printf("CONNECT echo current=%luus min=%luus max=%luus\n",
               (unsigned long)echo.Current, (unsigned long)echo.Minimum,
               (unsigned long)echo.Maximum);
        return 0;
    }

    if (Frame[0] == IWAN_NT_SESSION_TYPE_CLOSE) {
        /*
         * Forget the session here too: the driver must stop transforming DATA
         * with a key the peer has already torn down.
         */
        (void)IwanNtClearSession(Device);
        State->Established = FALSE;
        State->Closed++;
        printf("CONNECT closed by peer (#%lu)\n", (unsigned long)State->Closed);
        return 0;
    }

    State->ForeignFrames++;
    printf("CONNECT frame type=0x%02x len=%lu\n", (unsigned)Frame[0],
           (unsigned long)Length);
    return 0;
}

static int
SendOpen(
    _In_ PIWAN_NT_DEVICE Device,
    _Inout_ IWANNT_CONNECT_STATE *State,
    _In_ const char *User,
    _In_ const char *Password,
    _In_ USHORT Mtu
    )
{
    IWAN_NT_SESSION_OPEN open;
    IWAN_NT_SESSION_RESULT result;
    UCHAR frame[IWAN_NT_SESSION_CONTROL_MAX];
    size_t length = 0;

    open.User = User;
    open.Password = Password;
    open.Mtu = Mtu;

    result = IwanNtSessionBuildOpen(&open, frame, sizeof(frame), &length);
    if (result != IwanNtSessionOk) {
        fprintf(stderr, "OPEN build failed: %d\n", (int)result);
        return 1;
    }
    if (IwanNtSendControl(Device, frame, (UINT32)length) == FALSE) {
        DWORD error = GetLastError();

        fprintf(stderr, "SEND_CONTROL failed: %lu\n", error);
        if (error == ERROR_NOT_READY || error == ERROR_DEVICE_NOT_CONNECTED) {
            /*
             * The transport only runs while the adapter does, and a freshly
             * installed root adapter starts disabled. Say so instead of leaving
             * the operator to guess why a send fails on a "ready" device.
             */
            fprintf(stderr,
                    "the adapter is not up: enable it, for example\n"
                    "  netsh interface set interface \"iWAN NT Transport Adapter\" admin=enable\n");
        }
        return 1;
    }

    State->OpensSent++;
    printf("CONNECT open sent #%lu (%lu bytes)\n", (unsigned long)State->OpensSent,
           (unsigned long)length);
    return 0;
}

static int
SendEcho(
    _In_ PIWAN_NT_DEVICE Device,
    _Inout_ IWANNT_CONNECT_STATE *State
    )
{
    IWAN_NT_SESSION_RESULT result;
    UCHAR frame[IWAN_NT_SESSION_ECHO_LEN];
    size_t length = 0;
    LARGE_INTEGER counter;
    ULONGLONG microseconds = 0;

    QueryPerformanceCounter(&counter);
    microseconds = (ULONGLONG)counter.QuadPart;

    result = IwanNtSessionBuildEchoRequest(State->Sid, State->Token, microseconds,
                                           frame, sizeof(frame), &length);
    if (result != IwanNtSessionOk) {
        fprintf(stderr, "ECHO build failed: %d\n", (int)result);
        return 1;
    }
    if (IwanNtSendControl(Device, frame, (UINT32)length) == FALSE) {
        fprintf(stderr, "SEND_CONTROL failed: %lu\n", GetLastError());
        return 1;
    }

    State->EchoesSent++;
    return 0;
}

int
IwanNtRunConnect(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ int Argc,
    _In_ char **Argv
    )
{
    IWANNT_CONNECT_STATE state;
    UCHAR frame[IWAN_NT_CONTROL_MAX];
    ULONG address = 0;
    USHORT port = 0;
    USHORT mtu = 1400;
    unsigned long seconds = 15;
    const char *user;
    const char *password;
    ULONGLONG deadline;
    int status = 0;

    if (Argc < 6) {
        fprintf(stderr,
                "usage: iwannt-ctl connect <ip> <port> <user> <password> [mtu] [seconds]\n");
        return 1;
    }

    user = Argv[4];
    password = Argv[5];
    address = inet_addr(Argv[2]);
    if (address == INADDR_NONE) {
        fprintf(stderr, "bad address %s\n", Argv[2]);
        return 1;
    }
    port = _byteswap_ushort((USHORT)strtoul(Argv[3], NULL, 10));
    if (Argc >= 7) {
        mtu = (USHORT)strtoul(Argv[6], NULL, 10);
    }
    if (Argc >= 8) {
        seconds = strtoul(Argv[7], NULL, 10);
    }

    if (IwanNtSetPeer(Device, address, port) == FALSE) {
        fprintf(stderr, "SET_PEER failed: %lu\n", GetLastError());
        return 1;
    }

    memset(&state, 0, sizeof(state));
    deadline = GetTickCount64() + (ULONGLONG)seconds * 1000ull;
    state.NextOpen = GetTickCount64();

    for (;;) {
        ULONGLONG now = GetTickCount64();
        UINT32 required = 0;
        int length;

        if (now >= deadline) {
            break;
        }

        if (!state.Established && now >= state.NextOpen) {
            if (SendOpen(Device, &state, user, password, mtu) != 0) {
                status = 1;
                break;
            }
            state.NextOpen = now + IWANNT_OPEN_INTERVAL_MS;
        } else if (!state.Established) {
            /* Waiting for the retry timer; nothing to send this pass. */
        } else if (now >= state.NextEcho) {
            if (SendEcho(Device, &state) != 0) {
                status = 1;
                break;
            }
            state.NextEcho = now + IWANNT_ECHO_INTERVAL_MS;
        }

        /*
         * One frame per pass: the ring is bounded and the driver reports an empty
         * queue as zero bytes, so this drains without ever blocking the keepalive.
         */
        length = IwanNtReadControl(Device, frame, sizeof(frame), &required);
        if (length < 0) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) {
                fprintf(stderr, "READ_CONTROL failed: %lu\n", GetLastError());
                status = 1;
                break;
            }
        } else if (length > 0) {
            state.FramesRead++;
            status = HandleFrame(Device, &state, frame, (size_t)length, user, password);
            if (status != 0) {
                break;
            }
            if (!state.Established) {
                /* The next OPEN must not wait for a stale deadline. */
                state.NextOpen = GetTickCount64() + IWANNT_OPEN_INTERVAL_MS;
            }
        }

        Sleep(10);
    }

    printf("CONNECT done opens=%lu echoes=%lu answered=%lu frames=%lu foreign=%lu "
           "rejected=%lu closed=%lu\n",
           (unsigned long)state.OpensSent, (unsigned long)state.EchoesSent,
           (unsigned long)state.EchoesAnswered, (unsigned long)state.FramesRead,
           (unsigned long)state.ForeignFrames, (unsigned long)state.Rejected,
           (unsigned long)state.Closed);
    if (!state.EverEstablished) {
        status = 3;
    }
    if (state.Established) {
        IWAN_NT_STATS_ABI stats;

        memset(&stats, 0, sizeof(stats));
        if (IwanNtGetStats(Device, &stats) != FALSE) {
            printf("CONNECT stats tx=%llu rx=%llu delivered=%llu dropped=%llu inflight=%lu\n",
                   (unsigned long long)stats.TxAccepted,
                   (unsigned long long)stats.RxIndicated,
                   (unsigned long long)stats.Delivered,
                   (unsigned long long)stats.DroppedBadInner,
                   (unsigned long)stats.TxInFlight);
        }
    }

    return status;
}
