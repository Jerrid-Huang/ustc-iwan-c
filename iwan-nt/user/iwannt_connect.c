/* SPDX-License-Identifier: MIT
 *
 * connect: ask the driver to run the handshake, then follow it.
 *
 * The handshake used to live here, in user mode: this process built OPEN frames,
 * read ACKs from the control ring and installed the session. It works, but it
 * ties the tunnel's liveness to a console window, and a keepalive is exactly the
 * thing that must keep running when no one is looking.
 *
 * The driver owns it now. This command hands over the credentials and watches the
 * counters; it never builds a frame.
 */

#include "iwannt_connect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "iwan_nt_inet.h"

/*
 * How often the counters are sampled. The handshake retransmits every two
 * seconds, so a faster poll only makes the console noisier.
 */
#define IWAN_NT_CONNECT_POLL_MS 200u

static void
PrintAddress(
    _In_ const uint8_t *Address,
    _In_ uint16_t Family
    )
{
    char text[48];

    if (IwanNtFormatAddress(Address, Family, text, sizeof(text)) == NULL) {
        printf("?");
        return;
    }
    printf("%s", text);
}

static int
WaitForTransport(
    _In_ PIWAN_NT_DEVICE Device
    )
{
    IWAN_NT_STATS_ABI stats;
    DWORD started;

    started = GetTickCount();
    for (;;) {
        if (IwanNtGetStats(Device, &stats) == FALSE) {
            fprintf(stderr, "GET_STATS failed: %lu\n", GetLastError());
            return 1;
        }
        if (stats.Running != 0u) {
            return 0;
        }
        if (GetTickCount() - started > 5000u) {
            fprintf(stderr,
                    "the adapter is not up, so the transport is not running\n"
                    "  netsh interface set interface \"iWAN NT Transport "
                    "Adapter\" admin=enable\n");
            return 1;
        }
        Sleep(50);
    }
}

/*
 * Report a transition once, then stay quiet. The counters are cumulative from
 * driver load, so the interesting event is a change, not a value.
 */
typedef struct _IWAN_NT_CONNECT_SEEN {
    uint32_t Up;
    uint64_t Opens;
    uint64_t Echoes;
    uint64_t Rejects;
    uint64_t Closes;
    uint64_t Timeouts;
} IWAN_NT_CONNECT_SEEN;

static void
Report(
    _In_ const IWAN_NT_STATS_ABI *Stats,
    _Inout_ IWAN_NT_CONNECT_SEEN *Seen
    )
{
    if (Stats->PeerOpens != Seen->Opens) {
        printf("CONNECT open #%llu sent\n",
               (unsigned long long)Stats->PeerOpens);
        Seen->Opens = Stats->PeerOpens;
    }
    if (Stats->PeerRejects != Seen->Rejects) {
        fprintf(stderr, "CONNECT rejected by the server (#%llu)\n",
                (unsigned long long)Stats->PeerRejects);
        Seen->Rejects = Stats->PeerRejects;
    }
    if (Stats->PeerCloses != Seen->Closes) {
        printf("CONNECT closed by the server (#%llu)\n",
               (unsigned long long)Stats->PeerCloses);
        Seen->Closes = Stats->PeerCloses;
    }
    if (Stats->PeerTimeouts != Seen->Timeouts) {
        printf("CONNECT timeout after 15s of silence (#%llu), reconnecting\n",
               (unsigned long long)Stats->PeerTimeouts);
        Seen->Timeouts = Stats->PeerTimeouts;
    }
    if (Stats->PeerEchoes != Seen->Echoes && Stats->PeerState != 0u) {
        printf("CONNECT keepalive #%llu  rtt=%u.%03u ms (min %u.%03u, max "
               "%u.%03u)\n",
               (unsigned long long)Stats->PeerEchoes,
               Stats->PeerDelayCurrent / 1000u, Stats->PeerDelayCurrent % 1000u,
               Stats->PeerDelayMinimum / 1000u, Stats->PeerDelayMinimum % 1000u,
               Stats->PeerDelayMaximum / 1000u, Stats->PeerDelayMaximum % 1000u);
        Seen->Echoes = Stats->PeerEchoes;
    }
    if (Stats->PeerState != 0u && Seen->Up == 0u) {
        printf("CONNECT up (the driver holds the session; the adapter needs an "
               "address)\n");
        Seen->Up = 1u;
    } else if (Stats->PeerState == 0u && Seen->Up != 0u) {
        printf("CONNECT down\n");
        Seen->Up = 0u;
    }
}

int
IwanNtRunConnect(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ int Argc,
    _In_ char **Argv
    )
{
    IWAN_NT_CONNECT_SEEN seen;
    IWAN_NT_STATS_ABI stats;
    uint8_t address[16];
    uint16_t family;
    uint16_t mtu;
    DWORD seconds;
    DWORD started;
    uint32_t port;

    if (Argc < 6) {
        fprintf(stderr,
                "usage: connect <ip> <port> <user> <password> [mtu] [seconds]\n"
                "  mtu defaults to 1400, seconds to 15; 0 means until "
                "interrupted.\n");
        return 2;
    }

    port = (uint32_t)strtoul(Argv[2], NULL, 10);
    if (port == 0u || port > 65535u) {
        fprintf(stderr, "invalid port: %s\n", Argv[2]);
        return 2;
    }

    if (!IwanNtParseEndpoint(Argv[1], address, &family)) {
        fprintf(stderr, "invalid address: %s\n", Argv[1]);
        return 2;
    }

    mtu = (Argc > 6) ? (uint16_t)strtoul(Argv[6], NULL, 10) : 1400u;
    if (mtu == 0u) {
        fprintf(stderr, "invalid mtu: %s\n", Argv[6]);
        return 2;
    }
    seconds = (Argc > 7) ? (DWORD)strtoul(Argv[7], NULL, 10) : 15u;

    if (WaitForTransport(Device) != 0) {
        return 1;
    }

    if (IwanNtGetStats(Device, &stats) == FALSE) {
        fprintf(stderr, "GET_STATS failed: %lu\n", GetLastError());
        return 1;
    }
    if (stats.PeerReady != 0u) {
        fprintf(stderr,
                "the driver is already running a handshake; stop it first\n"
                "  iwannt-ctl disconnect\n");
        return 1;
    }
    if (stats.SessionValid != 0u) {
        fprintf(stderr,
                "the device already carries a session, so another connect "
                "owns it\n"
                "  iwannt-ctl clear   (only when that process is gone)\n");
        return 1;
    }

    if (IwanNtSetPeer(Device, address, family, (uint16_t)port) == FALSE) {
        fprintf(stderr, "SET_PEER failed: %lu\n", GetLastError());
        return 1;
    }
    if (IwanNtStartPeer(Device, Argv[3], Argv[4], mtu) == FALSE) {
        fprintf(stderr, "START_PEER failed: %lu\n", GetLastError());
        return 1;
    }

    printf("CONNECT handshake handed to the driver (mtu=%u, peer=", mtu);
    PrintAddress(address, family);
    printf(":%u)\n", (unsigned)port);

    memset(&seen, 0, sizeof(seen));
    started = GetTickCount();

    for (;;) {
        if (IwanNtGetStats(Device, &stats) == FALSE) {
            fprintf(stderr, "GET_STATS failed: %lu\n", GetLastError());
            (void)IwanNtStopPeer(Device);
            return 1;
        }

        Report(&stats, &seen);

        if (seconds != 0u && GetTickCount() - started >= seconds * 1000u) {
            break;
        }
        Sleep(IWAN_NT_CONNECT_POLL_MS);
    }

    printf("CONNECT done opens=%llu echoes=%llu answered=%llu rejected=%llu "
           "closed=%llu foreign=%llu timeouts=%llu state=%s\n",
           (unsigned long long)stats.PeerOpens,
           (unsigned long long)stats.PeerEchoes,
           (unsigned long long)stats.PeerEchoAnswers,
           (unsigned long long)stats.PeerRejects,
           (unsigned long long)stats.PeerCloses,
           (unsigned long long)stats.PeerForeign,
           (unsigned long long)stats.PeerTimeouts,
           stats.PeerState != 0u ? "up" : "down");

    /*
     * Leaving the handshake running would keep the tunnel alive behind a command
     * that has already exited, and the next connect would then be refused.
     */
    if (IwanNtStopPeer(Device) == FALSE) {
        fprintf(stderr, "STOP_PEER failed: %lu\n", GetLastError());
        return 1;
    }

    return (seen.Up != 0u) ? 0 : 3;
}
