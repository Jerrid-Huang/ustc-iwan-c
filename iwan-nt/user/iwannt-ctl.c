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
 *
 * The open subcommand works without the driver loaded: it only builds the frame,
 * which is the fastest way to compare our framing against a captured one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "iwan_nt_control.h"
#include "iwan_nt_session.h"
#include "iwannt_connect.h"

static VOID
Usage(VOID)
{
    fprintf(stderr,
            "usage:\n"
            "  iwannt-ctl check\n"
            "  iwannt-ctl stats\n"
            "  iwannt-ctl peer <a.b.c.d> <port>\n"
            "  iwannt-ctl session <sid-hex> <token-hex> <0|1> <key-hex>\n"
            "  iwannt-ctl clear\n"
            "  iwannt-ctl send <hex>\n"
            "  iwannt-ctl read [count]\n"
            "  iwannt-ctl watch <seconds>\n"
            "  iwannt-ctl open <user> <password> <mtu> [send]\n"
            "  iwannt-ctl connect <ip> <port> <user> <password> [mtu] [seconds]\n");
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
    int problems = 0;

    memset(&stats, 0, sizeof(stats));
    if (IwanNtGetStats(Device, &stats) == FALSE) {
        fprintf(stderr, "device is open but GET_STATS failed: %lu\n", GetLastError());
        return 1;
    }

    printf("device      ok (%s)\n", IWAN_NT_WIN32_NAME);

    if (stats.Running != 0) {
        printf("transport   running\n");
    } else {
        printf("transport   NOT running: the adapter is disabled or its session is down\n");
        printf("            netsh interface set interface \"iWAN NT Transport Adapter\" admin=enable\n");
        problems++;
    }

    if (stats.SessionValid != 0) {
        printf("session     installed\n");
    } else {
        printf("session     none: run \"iwannt-ctl connect <ip> <port> <user> <password>\"\n");
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
    UINT32 address = 0;
    UINT16 port = 0;
    const unsigned char *bytes = (const unsigned char *)&address;

    if (IwanNtGetLocal(Device, &address, &port) == FALSE) {
        fprintf(stderr, "local failed: %lu\n", GetLastError());
        return 1;
    }
    /* The address is network order, so its bytes print in the right order. */
    printf("local: %u.%u.%u.%u:%u\n", bytes[0], bytes[1], bytes[2], bytes[3],
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
    printf("tx accepted=%llu rejected=%llu inflight=%lu\n",
           (unsigned long long)stats.TxAccepted,
           (unsigned long long)stats.TxRejected,
           (unsigned long)stats.TxInFlight);
    printf("rx indicated=%llu dropped=%llu\n",
           (unsigned long long)stats.RxIndicated,
           (unsigned long long)stats.RxDropped);
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
    printf("state: running=%lu session=%lu\n",
           (unsigned long)stats.Running, (unsigned long)stats.SessionValid);

    return 0;
}

static int
CommandPeer(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ int Argc,
    _In_ char **Argv
    )
{
    UINT32 address;
    UINT16 port;

    if (Argc < 4) {
        Usage();
        return 2;
    }

    address = inet_addr(Argv[2]);
    if (address == INADDR_NONE) {
        fprintf(stderr, "bad address: %s\n", Argv[2]);
        return 2;
    }
    port = (UINT16)strtoul(Argv[3], NULL, 10);
    if (port == 0) {
        fprintf(stderr, "bad port: %s\n", Argv[3]);
        return 2;
    }

    /* The ABI takes the wire form, so the port is stored big endian. */
    if (IwanNtSetPeer(Device, address, _byteswap_ushort(port)) == FALSE) {
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
    } else {
        Usage();
        result = 2;
    }

    IwanNtClose(&device);
    return result;
}
