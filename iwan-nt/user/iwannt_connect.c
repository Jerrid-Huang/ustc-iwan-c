#include "iwannt_connect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "iwan_nt_peer.h"
#include "iwan_nt_inet.h"
#include "iwan_nt_session.h"

static void
PrintAddress(
    _In_ const UCHAR Address[4]
    )
{
    printf("%u.%u.%u.%u", Address[0], Address[1], Address[2], Address[3]);
}

/*
 * Apply a state change to the driver. The state machine decides what the session
 * is; this only mirrors that decision into the device, so the two cannot disagree
 * about whether a key is installed.
 */
static int
ApplyState(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ const IWAN_NT_PEER *Handshake
    )
{
    if (Handshake->State == IwanNtPeerUp) {
        IWAN_NT_STATS_ABI stats;

        if (IwanNtSetSession(Device, Handshake->Sid, Handshake->Token,
                             Handshake->Encrypted ? TRUE : FALSE,
                             Handshake->Key) == FALSE) {
            fprintf(stderr, "SET_SESSION failed: %lu\n", GetLastError());
            return 1;
        }
        /*
         * Read it back. A session the driver did not actually install looks
         * exactly like a working one from here: sends succeed, and nothing ever
         * arrives.
         */
        if (IwanNtGetStats(Device, &stats) != FALSE && stats.SessionValid == 0u) {
            fprintf(stderr, "SET_SESSION was accepted but the driver is not "
                            "using it\n");
            return 1;
        }
    } else {
        if (IwanNtClearSession(Device) == FALSE) {
            fprintf(stderr, "CLEAR_SESSION failed: %lu\n", GetLastError());
            return 1;
        }
    }
    return 0;
}

static int
Send(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ const uint8_t *Frame,
    _In_ size_t Length
    )
{
    DWORD error;

    if (IwanNtSendControl(Device, Frame, (UINT32)Length) != FALSE) {
        return 0;
    }

    error = GetLastError();
    fprintf(stderr, "SEND_CONTROL failed: %lu\n", error);
    if (error == ERROR_NOT_READY || error == ERROR_DEVICE_NOT_CONNECTED) {
        /*
         * The transport only runs while the adapter does, and a freshly installed
         * root adapter starts disabled. Name the fix instead of leaving the
         * operator to guess why a send fails on a "ready" device.
         */
        fprintf(stderr,
                "the adapter is not up: enable it, for example\n"
                "  netsh interface set interface \"iWAN NT Transport Adapter\" admin=enable\n");
    }
    return 1;
}

int
IwanNtRunConnect(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ int Argc,
    _In_ char **Argv
    )
{
    IWAN_NT_PEER handshake;
    IWAN_NT_STATS_ABI stats;
    uint8_t frame[IWAN_NT_CONTROL_MAX];
    UINT8 address[16];
    UINT16 family = 0;
    USHORT port;
    USHORT mtu = 1400;
    unsigned long seconds = 15;
    ULONGLONG deadline;
    int status = 0;

    if (Argc < 6) {
        fprintf(stderr,
                "usage: iwannt-ctl connect <ip> <port> <user> <password> [mtu] [seconds]\n"
                "  seconds 0 (the default is 15) keeps the session alive until interrupted\n");
        return 1;
    }

    if (!IwanNtParseEndpoint(Argv[2], address, &family)) {
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

    if (IwanNtSetPeer(Device, address, (family == 6) ? AF_INET6 : AF_INET,
                      port) == FALSE) {
        fprintf(stderr, "SET_PEER failed: %lu\n", GetLastError());
        return 1;
    }
    if (IwanNtPeerInitialize(&handshake, Argv[4], Argv[5], mtu,
                                  GetTickCount64()) == 0) {
        fprintf(stderr, "user or password too long\n");
        return 1;
    }

    /*
     * The transport only runs while the adapter does, and a freshly installed
     * root adapter starts disabled. Finding that out from the first send wastes a
     * retry interval on an error the operator can fix in one command, so check
     * the state first and say what is wrong.
     */
    {
        ULONGLONG waitUntil = GetTickCount64() + 5000ull;

        for (;;) {
            memset(&stats, 0, sizeof(stats));
            if (IwanNtGetStats(Device, &stats) == FALSE) {
                fprintf(stderr, "GET_STATS failed: %lu\n", GetLastError());
                return 1;
            }
            if (stats.Running != 0) {
                break;
            }
            if (GetTickCount64() >= waitUntil) {
                fprintf(stderr,
                        "the adapter is not up, so the transport is not running\n"
                        "  netsh interface set interface \"iWAN NT Transport Adapter\" admin=enable\n");
                return 1;
            }
            Sleep(100);
        }
    }

    /*
     * One device carries one session. A second connect would overwrite the first
     * one's identifiers while it is still running and then clear them on its own
     * exit, so refuse instead of letting two processes fight over the device.
     */
    if (stats.SessionValid != 0) {
        fprintf(stderr,
                "the device already carries a session, so another connect owns it\n"
                "  iwannt-ctl clear   (only when that process is gone)\n");
        return 1;
    }

    /*
     * Zero means "until interrupted". Keepalives live in this process by design:
     * when it exits, the peer stops hearing from us and times the session out, so
     * a tunnel that should outlive a shell needs this to run as a service.
     */
    deadline = (seconds == 0) ? 0 : GetTickCount64() + (ULONGLONG)seconds * 1000ull;

    for (;;) {
        ULONGLONG now = GetTickCount64();
        UINT32 required = 0;
        size_t length = 0;
        ULONG timeoutsBefore;
        int pending;
        int read;

        if (deadline != 0 && now >= deadline) {
            break;
        }

        timeoutsBefore = handshake.Timeouts;
        pending = IwanNtPeerTick(&handshake, now, frame, sizeof(frame),
                                      &length);
        if (handshake.Timeouts != timeoutsBefore) {
            printf("CONNECT timeout after %us of silence (#%lu), reconnecting\n",
                   (unsigned)(IWAN_NT_PEER_DATA_TIMEOUT_MS / 1000u),
                   (unsigned long)handshake.Timeouts);
        }
        if (handshake.Fault != IwanNtSessionOk) {
            fprintf(stderr, "frame build failed: %d\n", (int)handshake.Fault);
            status = 1;
            break;
        }
        if (pending) {
            if (Send(Device, frame, length) != 0) {
                status = 1;
                break;
            }
        }

        /*
         * One frame per pass. The ring is bounded and an empty queue is reported
         * as zero bytes, so this drains without ever blocking the timer.
         */
        read = IwanNtReadControl(Device, frame, sizeof(frame), &required);
        if (read < 0) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) {
                fprintf(stderr, "READ_CONTROL failed: %lu\n", GetLastError());
                status = 1;
                break;
            }
        } else if (read > 0) {
            IWAN_NT_PEER_EVENT event = IwanNtPeerOnFrame(
                &handshake, frame, (size_t)read, GetTickCount64());

            if (event == IwanNtPeerEventEstablished) {
                printf("CONNECT ack sid=%u token=%08lx mtu=%u encrypted=%lu",
                       (unsigned)handshake.Sid, (unsigned long)handshake.Token,
                       (unsigned)handshake.MtuFromPeer,
                       (unsigned long)handshake.Encrypted);
                if (handshake.HasAddress) {
                    printf(" tun=");
                    PrintAddress(handshake.Address);
                }
                if (handshake.HasGateway) {
                    printf(" gw=");
                    PrintAddress(handshake.Gateway);
                }
                printf("\n");
                if (handshake.MtuFromPeer != 0u &&
                    handshake.MtuFromPeer < handshake.Mtu) {
                    /*
                     * NDIS does not let a miniport change its MTU at runtime, and
                     * the deployed client uses min(configured, peer) on its tun
                     * device, so the remaining step belongs to the host.
                     */
                    printf("CONNECT the peer accepts %u-byte packets; "
                           "lower the adapter to match:\n"
                           "  netsh interface ipv4 set subinterface "
                           "\"iWAN NT Transport Adapter\" mtu=%u store=persistent\n",
                           (unsigned)handshake.MtuFromPeer,
                           (unsigned)handshake.MtuFromPeer);
                }
                if (handshake.HasAddress) {
                    /*
                     * Print the command rather than running it: the tool talks to
                     * the device, it does not own the host's routing table.
                     */
                    printf("CONNECT to carry traffic, give the adapter that address:\n"
                           "  netsh interface ipv4 set address name=\"iWAN NT Transport Adapter\" "
                           "static %u.%u.%u.%u 255.255.255.0\n",
                           handshake.Address[0], handshake.Address[1],
                           handshake.Address[2], handshake.Address[3]);
                }
            } else if (event == IwanNtPeerEventRejected) {
                printf("CONNECT rejected (#%lu)\n",
                       (unsigned long)handshake.Rejects);
            } else if (event == IwanNtPeerEventClosed) {
                printf("CONNECT closed by peer (#%lu)\n",
                       (unsigned long)handshake.Closes);
            } else if (event == IwanNtPeerEventEchoAnswer) {
                printf("CONNECT echo current=%luus min=%luus max=%luus\n",
                       (unsigned long)handshake.DelayCurrent,
                       (unsigned long)handshake.DelayMinimum,
                       (unsigned long)handshake.DelayMaximum);
            } else if (event == IwanNtPeerEventFault) {
                fprintf(stderr, "frame rejected: %d\n", (int)handshake.Fault);
                status = 1;
                break;
            }

        }

        /*
         * Mirror the state machine every pass: a data timeout resets it without
         * any frame arriving, and the driver must hear about that too.
         */
        if (ApplyState(Device, &handshake) != 0) {
            status = 1;
            break;
        }

        Sleep(10);
    }

    printf("CONNECT done opens=%lu echoes=%lu answered=%lu rejected=%lu closed=%lu "
           "foreign=%lu state=%s\n",
           (unsigned long)handshake.Opens, (unsigned long)handshake.Echoes,
           (unsigned long)handshake.EchoAnswers, (unsigned long)handshake.Rejects,
           (unsigned long)handshake.Closes, (unsigned long)handshake.ForeignFrames,
           (handshake.State == IwanNtPeerUp) ? "up" : "down");

    /*
     * Leave the driver in the state this process ended in. A session nobody is
     * keeping alive would otherwise make the adapter look connected while every
     * packet it carries goes nowhere.
     */
    if (handshake.State == IwanNtPeerUp) {
        (void)IwanNtClearSession(Device);
    }

    if (handshake.EverEstablished == 0) {
        status = 3;
    } else if (handshake.State == IwanNtPeerUp) {
        memset(&stats, 0, sizeof(stats));
        if (IwanNtGetStats(Device, &stats) != FALSE) {
            printf("CONNECT stats tx=%llu rx=%llu delivered=%llu inflight=%lu\n",
                   (unsigned long long)stats.TxAccepted,
                   (unsigned long long)stats.RxIndicated,
                   (unsigned long long)stats.Delivered,
                   (unsigned long)stats.TxInFlight);
        }
    }

    return status;
}
