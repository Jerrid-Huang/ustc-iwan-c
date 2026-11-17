/*
 * iwannt-ctl: talk to the iWAN NT control device from user mode.
 *
 * This is a diagnostic tool, not the client. It exists so the driver can be
 * poked without a full tunnel: install a peer and a session, watch control
 * frames as they arrive, send one by hand, and read the counters back.
 *
 * Usage:
 *   iwannt-ctl stats
 *   iwannt-ctl peer <a.b.c.d> <port>
 *   iwannt-ctl session <sid-hex> <token-hex> <0|1> <key-hex>
 *   iwannt-ctl clear
 *   iwannt-ctl send <hex>
 *   iwannt-ctl read [count]
 *   iwannt-ctl watch <seconds>
 *   iwannt-ctl open <user> <password> <mtu> [send]
 *   iwannt-ctl connect <ip> <port> <user> <password> [mtu] [seconds]
 *   iwannt-ctl disconnect
 *
 * The open subcommand works without the driver loaded: it only builds the frame,
 * which is the fastest way to compare our framing against a captured one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "iwan_nt_control.h"
#include "iwan_nt_inet.h"
#include "iwan_nt_session.h"
#include "iwannt_connect.h"
#include "iwan_nt_lease.h"
#include "iwan_nt_mtu_win.h"

static VOID
Usage(VOID)
{
    fprintf(stderr,
            "usage:\n"
            "  iwannt-ctl check\n"
            "  iwannt-ctl stats\n"
            "  iwannt-ctl lease [ifindex]\n"
            "  iwannt-ctl mtu [<carrier-mtu>|<peer address>]\n"
            "  iwannt-ctl peer <a.b.c.d> <port>\n"
            "  iwannt-ctl session <sid-hex> <token-hex> <0|1> <key-hex>\n"
            "  iwannt-ctl clear\n"
            "  iwannt-ctl send <hex>\n"
            "  iwannt-ctl read [count]\n"
            "  iwannt-ctl watch <seconds>\n"
            "  iwannt-ctl open <user> <password> <mtu> [send]\n"
            "  iwannt-ctl connect <ip> <port> <user> <password> [mtu] [seconds]\n"
            "  iwannt-ctl disconnect\n");
}

static BOOL
ParseHex(
    _In_ const char *Text,
    _Out_writes_bytes_(Capacity) UCHAR *Out,
    _In_ size_t Capacity,
    _Out_ size_t *OutLength
    )
{
    size_t length = 0;
    size_t index;

    if (Text == NULL || Out == NULL || OutLength == NULL) {
        return FALSE;
    }

    length = strlen(Text);
    if ((length % 2u) != 0u || (length / 2u) > Capacity) {
        return FALSE;
    }

    for (index = 0; index < length; index += 2u) {
        unsigned int value = 0u;
        char pair[3];

        pair[0] = Text[index];
        pair[1] = Text[index + 1u];
        pair[2] = '\0';
        if (sscanf_s(pair, "%2x", &value) != 1) {
            return FALSE;
        }
        Out[index / 2u] = (UCHAR)value;
    }

    *OutLength = length / 2u;
    return TRUE;
}

static VOID
PrintHex(
    _In_reads_bytes_(Length) const UCHAR *Data,
    _In_ size_t Length
    )
{
    size_t index;

    for (index = 0; index < Length; index++) {
        printf("%02x", Data[index]);
        if (((index + 1u) % 16u) == 0u) {
            printf(" ");
        }
    }
}

/*
 * Say whether the driver is usable and what is missing, in the order the pieces
 * have to work: device, transport, session. Every step names the command that
 * fixes it, because "open \\.\IwanNt failed: 2" on its own is not actionable.
 */
static int
CommandCheck(
    _In_ PIWAN_NT_DEVICE Device
    )
{
    IWAN_NT_STATS_ABI stats;
    char buffer[64];
    int problems = 0;

    memset(&stats, 0, sizeof(stats));
    if (IwanNtGetStats(Device, &stats) == FALSE) {
        fprintf(stderr, "device is open but GET_STATS failed: %lu\n", GetLastError());
        return 1;
    }

    printf("device      ok (%s)\n", IWAN_NT_WIN32_NAME);

    if (stats.Running != 0) {
        UINT8 boundAddress[16];
        UINT16 boundFamily = 0;
        UINT16 boundPort = 0;

        printf("transport   running\n");
        /*
         * The port is assigned by the provider, so a zero here means the socket
         * is not the one carrying traffic: every reply the peer sends would be
         * blamed on the network instead of on the bind step.
         */
        if (IwanNtGetLocal(Device, boundAddress, &boundFamily, &boundPort) ==
                FALSE ||
            boundPort == 0) {
            printf("socket      no bound port: the datagram socket is not running\n");
            problems++;
        } else {
            printf("socket      %s:%u\n",
                   IwanNtFormatAddress(boundAddress, boundFamily,
                                       buffer, sizeof(buffer)),
                   (unsigned)_byteswap_ushort(boundPort));
        }
    } else {
        printf("transport   NOT running: the adapter is disabled or its session is down\n");
        printf("            netsh interface set interface \"iWAN NT Transport Adapter\" admin=enable\n");
        problems++;
    }

    if (stats.SessionValid != 0) {
        printf("session     installed\n");
    } else {
        if (stats.PeerReady != 0u) {
            printf("session     none: the driver is still handshaking "
                   "(opens=%llu)\n",
                   (unsigned long long)stats.PeerOpens);
        } else {
            printf("session     none: run \"iwannt-ctl connect <ip> <port> "
                   "<user> <password>\"\n");
        }
        problems++;
    }

    if (stats.RxOversize != 0 || stats.RxSinkErrors != 0) {
        printf("receive     %llu oversize and %llu refused datagrams: check the MTU\n",
               (unsigned long long)stats.RxOversize,
               (unsigned long long)stats.RxSinkErrors);
        problems++;
    }

    printf("counters    rx=%llu delivered=%llu tx=%llu inflight=%lu\n",
           (unsigned long long)stats.Receives,
           (unsigned long long)stats.Delivered,
           (unsigned long long)stats.TxAccepted,
           (unsigned long)stats.TxInFlight);

    if (problems != 0) {
        printf("check: %d problem(s)\n", problems);
        return 1;
    }
    printf("check: ready\n");
    return 0;
}

static int
CommandLocal(
    _In_ PIWAN_NT_DEVICE Device
    )
{
    UINT8 address[16];
    UINT16 family = 0;
    UINT16 port = 0;
    char text[64];

    if (IwanNtGetLocal(Device, address, &family, &port) == FALSE) {
        fprintf(stderr, "local failed: %lu\n", GetLastError());
        return 1;
    }
    /* The port is network order on the wire, so it swaps for display. */
    printf("local: %s:%u\n", IwanNtFormatAddress(address, (family == 6) ? 6 : 4,
                                                text, sizeof(text)),
           (unsigned)_byteswap_ushort(port));
    return 0;
}

static int
CommandStats(
    _In_ PIWAN_NT_DEVICE Device
    )
{
    IWAN_NT_STATS_ABI stats;

    if (IwanNtGetStats(Device, &stats) == FALSE) {
        fprintf(stderr, "stats failed: %lu\n", GetLastError());
        return 1;
    }

    printf("receives=%llu delivered=%llu bytes=%llu queued=%llu\n",
           (unsigned long long)stats.Receives,
           (unsigned long long)stats.Delivered,
           (unsigned long long)stats.BytesDelivered,
           (unsigned long long)stats.QueuedControl);
    printf("control read=%llu sent=%llu failed=%llu\n",
           (unsigned long long)stats.ControlRead,
           (unsigned long long)stats.ControlSent,
           (unsigned long long)stats.ControlSendFailed);
    printf("tx accepted=%llu rejected=%llu inflight=%lu staged=%llu maxbatch=%llu "
           "batches=%llu\n",
           (unsigned long long)stats.TxAccepted,
           (unsigned long long)stats.TxRejected,
           (unsigned long)stats.TxInFlight,
           (unsigned long long)stats.TxPending,
           (unsigned long long)stats.TxMaxBatch,
           (unsigned long long)stats.TxBatches);
    printf("rx indicated=%llu dropped=%llu batches=%llu\n",
           (unsigned long long)stats.RxIndicated,
           (unsigned long long)stats.RxDropped,
           (unsigned long long)stats.RxBatches);
    printf("drops: nosession=%llu malformed=%llu badinner=%llu "
           "ctlfull=%llu ctllarge=%llu ctlring=%llu nosink=%llu "
           "segrt=%llu unknown=%llu\n",
           (unsigned long long)stats.DroppedNoSession,
           (unsigned long long)stats.DroppedMalformed,
           (unsigned long long)stats.DroppedBadInner,
           (unsigned long long)stats.DroppedControlFull,
           (unsigned long long)stats.DroppedControlTooLarge,
           (unsigned long long)stats.DroppedControlNoRing,
           (unsigned long long)stats.DroppedNoSink,
           (unsigned long long)stats.DroppedSegrt,
           (unsigned long long)stats.DroppedUnknown);
    printf("drops: oversize=%llu sinkerrors=%llu\n",
           (unsigned long long)stats.RxOversize,
           (unsigned long long)stats.RxSinkErrors);
    printf("mtu: carrier=%lu effective=%lu peer=%lu dropped=%lu\n",
           (unsigned long)stats.CarrierMtu,
           (unsigned long)stats.EffectiveMtu,
           (unsigned long)stats.PeerMtu,
           (unsigned long)stats.MtuDropped);
    printf("state: running=%lu session=%lu\n",
           (unsigned long)stats.Running, (unsigned long)stats.SessionValid);
    printf("peer: ready=%lu state=%s opens=%llu echoes=%llu answered=%llu "
           "rejected=%llu closed=%llu foreign=%llu timeouts=%llu\n",
           (unsigned long)stats.PeerReady,
           stats.PeerState != 0u ? "up" : "down",
           (unsigned long long)stats.PeerOpens,
           (unsigned long long)stats.PeerEchoes,
           (unsigned long long)stats.PeerEchoAnswers,
           (unsigned long long)stats.PeerRejects,
           (unsigned long long)stats.PeerCloses,
           (unsigned long long)stats.PeerForeign,
           (unsigned long long)stats.PeerTimeouts);
    printf("peer: rtt cur=%u.%03u min=%u.%03u max=%u.%03u ms\n",
           stats.PeerDelayCurrent / 1000u, stats.PeerDelayCurrent % 1000u,
           stats.PeerDelayMinimum / 1000u, stats.PeerDelayMinimum % 1000u,
           stats.PeerDelayMaximum / 1000u, stats.PeerDelayMaximum % 1000u);

    return 0;
}

/*
 * mtu                     show what the driver will read at the next start
 * mtu <number>            record a carrier MTU by hand
 * mtu <peer address>      derive it from the route to that peer
 *
 * The driver resolves the advertised MTU once, at adapter init, so a change here
 * takes effect on the next adapter start (device restart), not on the live one.
 */
static int
CommandMtu(
    _In_ int Argc,
    _In_ char **Argv
    )
{
    DWORD carrierMtu = 0;
    DWORD ifIndex = 0;

    if (Argc >= 3 && strchr(Argv[2], '.') != NULL) {
        if (IwanNtMtuProbeRoute(Argv[2], &carrierMtu, &ifIndex) == FALSE) {
            fprintf(stderr, "route probe to %s failed: %lu\n", Argv[2],
                    GetLastError());
            return 1;
        }
        printf("route to %s leaves via interface %lu with MTU %lu\n", Argv[2],
               (unsigned long)ifIndex, (unsigned long)carrierMtu);
    } else if (Argc >= 3) {
        char *end = NULL;
        unsigned long value = strtoul(Argv[2], &end, 10);
        if (end == Argv[2] || *end != '\0' || value < 576 || value > 9216) {
            fprintf(stderr, "carrier MTU must be a number in [576, 9216]\n");
            return 2;
        }
        carrierMtu = (DWORD)value;
    }

    if (carrierMtu != 0) {
        if (IwanNtMtuWriteCarrier(carrierMtu) == FALSE) {
            fprintf(stderr,
                    "writing %s\\%s failed: %lu (the tool needs administrator)\n",
                    IWAN_NT_MTU_REGISTRY_SUBKEY, IWAN_NT_MTU_REGISTRY_VALUE,
                    GetLastError());
            return 1;
        }
        printf("recorded carrier MTU %lu; restart the adapter to use it\n",
               (unsigned long)carrierMtu);
        return 0;
    }

    if (IwanNtMtuReadCarrier(&carrierMtu) == FALSE) {
        printf("carrier MTU: not set (the driver uses %u)\n", 1500u);
        return 0;
    }
    printf("carrier MTU: %lu (effective inner MTU lands at carrier-36 for IPv4)\n",
           (unsigned long)carrierMtu);
    return 0;
}

static int
CommandLease(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ int Argc,
    _In_ char **Argv
    )
{
    IWAN_NT_LEASE_ABI lease;
    UINT32 ifIndex;

    if (IwanNtGetLease(Device, &lease) == FALSE) {
        fprintf(stderr, "lease failed: %lu\n", GetLastError());
        return 1;
    }
    if (lease.HasAddress == 0) {
        printf("lease: none (no acknowledgement accepted yet)\n");
        return 0;
    }

    printf("lease: %u.%u.%u.%u/%u", lease.Address[0], lease.Address[1],
           lease.Address[2], lease.Address[3], (unsigned)lease.Prefix);
    if (lease.HasGateway != 0) {
        printf(" gateway %u.%u.%u.%u", lease.Gateway[0], lease.Gateway[1],
               lease.Gateway[2], lease.Gateway[3]);
    }
    printf("\n");

    if (Argc < 3) {
        return 0;
    }

    ifIndex = (UINT32)strtoul(Argv[2], NULL, 10);
    if (IwanNtLeaseApply(ifIndex, &lease) == FALSE) {
        fprintf(stderr, "apply failed on interface %lu: %lu\n",
                (unsigned long)ifIndex, GetLastError());
        return 1;
    }
    printf("applied on interface %lu\n", (unsigned long)ifIndex);
    return 0;
}

static int
CommandPeer(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ int Argc,
    _In_ char **Argv
    )
{
    UINT8 address[16];
    UINT16 family = 0;
    UINT16 port;

    if (Argc < 4) {
        Usage();
        return 2;
    }

    if (!IwanNtParseEndpoint(Argv[2], address, &family)) {
        fprintf(stderr, "bad address: %s\n", Argv[2]);
        return 2;
    }
    port = (UINT16)strtoul(Argv[3], NULL, 10);
    if (port == 0) {
        fprintf(stderr, "bad port: %s\n", Argv[3]);
        return 2;
    }

    /* The ABI takes the wire form, so the port is stored big endian. */
    if (IwanNtSetPeer(Device, address, (family == 6) ? AF_INET6 : AF_INET,
                      _byteswap_ushort(port)) == FALSE) {
        fprintf(stderr, "peer failed: %lu\n", GetLastError());
        return 1;
    }

    printf("peer set\n");
    return 0;
}

static int
CommandSession(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ int Argc,
    _In_ char **Argv
    )
{
    UCHAR key[8];
    size_t keyLength = 0;
    UINT16 sid;
    UINT32 token;
    BOOL encrypted;

    if (Argc < 6) {
        Usage();
        return 2;
    }

    sid = (UINT16)strtoul(Argv[2], NULL, 16);
    token = (UINT32)strtoul(Argv[3], NULL, 16);
    encrypted = (strcmp(Argv[4], "1") == 0) ? TRUE : FALSE;
    if (ParseHex(Argv[5], key, sizeof(key), &keyLength) == FALSE ||
        keyLength != sizeof(key)) {
        fprintf(stderr, "key must be 16 hex digits\n");
        return 2;
    }

    if (IwanNtSetSession(Device, sid, token, encrypted, key) == FALSE) {
        fprintf(stderr, "session failed: %lu\n", GetLastError());
        return 1;
    }

    printf("session set sid=0x%04x token=0x%08lx enc=%d\n",
           (unsigned)sid, (unsigned long)token, encrypted ? 1 : 0);
    return 0;
}

static int
CommandSend(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ int Argc,
    _In_ char **Argv
    )
{
    UCHAR frame[IWAN_NT_CONTROL_MAX];
    size_t length = 0;

    if (Argc < 3) {
        Usage();
        return 2;
    }
    if (ParseHex(Argv[2], frame, sizeof(frame), &length) == FALSE) {
        fprintf(stderr, "bad hex, or longer than %u bytes\n",
                (unsigned)IWAN_NT_CONTROL_MAX);
        return 2;
    }

    if (IwanNtSendControl(Device, frame, (UINT32)length) == FALSE) {
        fprintf(stderr, "send failed: %lu\n", GetLastError());
        return 1;
    }

    printf("sent %u bytes\n", (unsigned)length);
    return 0;
}

static int
ReadOnce(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ BOOL Quiet
    )
{
    UCHAR frame[IWAN_NT_CONTROL_MAX];
    UINT32 required = 0;
    int length;

    length = IwanNtReadControl(Device, frame, sizeof(frame), &required);
    if (length < 0) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && required != 0) {
            fprintf(stderr, "frame of %lu bytes exceeds %u\n",
                    (unsigned long)required, (unsigned)IWAN_NT_CONTROL_MAX);
        } else {
            fprintf(stderr, "read failed: %lu\n", GetLastError());
        }
        return 1;
    }

    if (length == 0) {
        if (Quiet == FALSE) {
            printf("empty\n");
        }
        return 0;
    }

    printf("frame %d bytes: ", length);
    PrintHex(frame, (size_t)length);
    printf("\n");
    return 0;
}

static int
CommandRead(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ int Argc,
    _In_ char **Argv
    )
{
    unsigned long count = 1;
    unsigned long index;

    if (Argc >= 3) {
        count = strtoul(Argv[2], NULL, 10);
    }

    for (index = 0; index < count; index++) {
        if (ReadOnce(Device, FALSE) != 0) {
            return 1;
        }
    }

    return 0;
}

static int
CommandWatch(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ int Argc,
    _In_ char **Argv
    )
{
    ULONGLONG deadline;
    unsigned long seconds = 10;

    if (Argc >= 3) {
        seconds = strtoul(Argv[2], NULL, 10);
    }
    deadline = GetTickCount64() + (ULONGLONG)seconds * 1000ull;

    while (GetTickCount64() < deadline) {
        if (ReadOnce(Device, TRUE) != 0) {
            return 1;
        }
        Sleep(20);
    }

    return 0;
}

static int
CommandOpen(
    _In_ int Argc,
    _In_ char **Argv
    )
{
    IWAN_NT_SESSION_OPEN open;
    IWAN_NT_SESSION_RESULT status;
    UCHAR frame[IWAN_NT_SESSION_CONTROL_MAX];
    size_t length = 0;
    size_t index;
    BOOL send = FALSE;

    if (Argc < 5) {
        fprintf(stderr, "usage: iwannt-ctl open <user> <password> <mtu> [send]\n");
        return 2;
    }
    if (Argc >= 6) {
        if (strcmp(Argv[5], "send") != 0) {
            fprintf(stderr, "unknown flag %s\n", Argv[5]);
            return 2;
        }
        send = TRUE;
    }

    open.User = Argv[2];
    open.Password = Argv[3];
    open.Mtu = (uint16_t)strtoul(Argv[4], NULL, 10);

    status = IwanNtSessionBuildOpen(&open, frame, sizeof(frame), &length);
    if (status != IwanNtSessionOk) {
        fprintf(stderr, "build OPEN failed: %d\n", (int)status);
        return 1;
    }

    for (index = 0; index < length; index++) {
        printf("%02x", frame[index]);
    }
    printf("\n");

    if (send) {
        IWAN_NT_DEVICE device;

        device.Handle = INVALID_HANDLE_VALUE;
        if (IwanNtOpen(&device) == FALSE) {
            fprintf(stderr, "open %s failed: %lu\n", IWAN_NT_WIN32_NAME,
                    GetLastError());
            return 1;
        }
        if (IwanNtSendControl(&device, frame, (UINT32)length) == 0) {
            fprintf(stderr, "SEND_CONTROL failed: %lu\n", GetLastError());
            IwanNtClose(&device);
            return 1;
        }
        IwanNtClose(&device);
    }

    return 0;
}

int
main(
    _In_ int argc,
    _In_ char **argv
    )
{
    IWAN_NT_DEVICE device;
    int result = 1;

    if (argc < 2) {
        Usage();
        return 2;
    }

    /*
     * open only builds a frame, so it must work with the driver absent: that is
     * the case when comparing our layout against a capture.
     */
    if (strcmp(argv[1], "open") == 0) {
        return CommandOpen(argc, argv);
    }
    /*
     * mtu only touches the registry and the route table, so it must work with
     * the driver stopped: that is exactly when its value is about to be read.
     */
    if (strcmp(argv[1], "mtu") == 0) {
        return CommandMtu(argc, argv);
    }

    device.Handle = INVALID_HANDLE_VALUE;
    if (IwanNtOpen(&device) == FALSE) {
        DWORD error = GetLastError();

        fprintf(stderr, "open %s failed: %lu\n", IWAN_NT_WIN32_NAME, error);
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            /*
             * The first thing that goes wrong on a fresh machine: the control
             * device only exists while the driver is loaded, and a root-enumerated
             * service does not start itself.
             */
            fprintf(stderr,
                    "the driver is not loaded, so the control device does not exist\n"
                    "  sc start iwannt\n");
        }
        return 1;
    }

    if (strcmp(argv[1], "check") == 0) {
        result = CommandCheck(&device);
    } else if (strcmp(argv[1], "stats") == 0) {
        result = CommandStats(&device);
    } else if (strcmp(argv[1], "local") == 0) {
        result = CommandLocal(&device);
    } else if (strcmp(argv[1], "lease") == 0) {
        result = CommandLease(&device, argc, argv);
    } else if (strcmp(argv[1], "peer") == 0) {
        result = CommandPeer(&device, argc, argv);
    } else if (strcmp(argv[1], "session") == 0) {
        result = CommandSession(&device, argc, argv);
    } else if (strcmp(argv[1], "clear") == 0) {
        if (IwanNtClearSession(&device) == FALSE) {
            fprintf(stderr, "clear failed: %lu\n", GetLastError());
            result = 1;
        } else {
            printf("session cleared\n");
            result = 0;
        }
    } else if (strcmp(argv[1], "send") == 0) {
        result = CommandSend(&device, argc, argv);
    } else if (strcmp(argv[1], "read") == 0) {
        result = CommandRead(&device, argc, argv);
    } else if (strcmp(argv[1], "watch") == 0) {
        result = CommandWatch(&device, argc, argv);
    } else if (strcmp(argv[1], "connect") == 0) {
        result = IwanNtRunConnect(&device, argc, argv);
    } else if (strcmp(argv[1], "disconnect") == 0) {
        if (IwanNtStopPeer(&device) == FALSE) {
            fprintf(stderr, "disconnect failed: %lu\n", GetLastError());
            result = 1;
        } else {
            printf("handshake stopped\n");
            result = 0;
        }
    } else {
        Usage();
        result = 2;
    }

    IwanNtClose(&device);
    return result;
}
