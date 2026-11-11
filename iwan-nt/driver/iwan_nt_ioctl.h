#ifndef IWAN_NT_IOCTL_H
#define IWAN_NT_IOCTL_H

/*
 * iWAN NT control-plane ABI.
 *
 * This header is shared verbatim with user mode, so it depends on nothing:
 * no kernel headers, no CRT headers, no SAL. Every structure is a fixed-size
 * POD with explicit-width fields and no padding surprises; every multi-byte
 * integer is host order unless a field name says otherwise.
 *
 * Why a control device exists at all: the transport owns the outer UDP socket
 * inside the kernel (WSK), so the user-mode client can no longer bind that
 * port to send OPEN/OPEN_ACK/ECHO/CLOSE by itself. Both directions of the
 * control plane therefore cross this device:
 *
 *   user mode -> kernel : IWAN_NT_IOCTL_SEND_CONTROL writes one complete
 *                         control datagram payload (frame header + signature
 *                         + TLVs) and the transport sends it verbatim on the
 *                         already-bound socket.
 *   kernel -> user mode : IWAN_NT_IOCTL_READ_CONTROL dequeues one complete
 *                         control datagram payload from the bounded ring that
 *                         the receive path fills. Nothing is parsed twice:
 *                         the ring carries the exact bytes that arrived.
 *
 * Ordering is preserved per direction: SEND_CONTROL is serialized by the
 * transport send lock, READ_CONTROL is a single-consumer dequeue. A ring
 * overflow drops the newest control frame and is counted, never blocks.
 */

#ifdef _MSC_VER
#pragma warning(push)
/* The ABI below relies on natural alignment of fixed-width fields. */
#endif

/* Device interface. The symbolic link is what user mode opens. */
#define IWAN_NT_DEVICE_NAME L"\\Device\\IwanNt"
#define IWAN_NT_SYMBOLIC_NAME L"\\DosDevices\\IwanNt"
#define IWAN_NT_WIN32_NAME "\\\\.\\IwanNt"

/*
 * IOCTL encoding. METHOD_BUFFERED (0) is the only method used: every request
 * is small, and buffered I/O gives the driver one system buffer that is valid
 * at PASSIVE_LEVEL and needs no MDL probing.
 */
#define IWAN_NT_IOCTL_DEVICE_TYPE 0x8394u
#define IWAN_NT_METHOD_BUFFERED 0u

#define IWAN_NT_CTL_CODE(function)                                  \
    (((uint32_t)IWAN_NT_IOCTL_DEVICE_TYPE << 16) |                  \
     (((uint32_t)(function)) << 2) | (uint32_t)IWAN_NT_METHOD_BUFFERED)

/* Session parameters, applied after OPEN/OPEN_ACK completes. */
#define IWAN_NT_IOCTL_SET_SESSION IWAN_NT_CTL_CODE(0x800u)
/* Remove the session: every later DATA frame is dropped and counted. */
#define IWAN_NT_IOCTL_CLEAR_SESSION IWAN_NT_CTL_CODE(0x801u)
/* Outer peer endpoint used by SEND_CONTROL and by every encapsulated packet. */
#define IWAN_NT_IOCTL_SET_PEER IWAN_NT_CTL_CODE(0x802u)
/* One complete control datagram payload, sent verbatim (write). */
#define IWAN_NT_IOCTL_SEND_CONTROL IWAN_NT_CTL_CODE(0x803u)
/* Dequeue one complete control datagram payload (read). */
#define IWAN_NT_IOCTL_READ_CONTROL IWAN_NT_CTL_CODE(0x804u)
/* Snapshot of every counter the transport keeps (read). */
#define IWAN_NT_IOCTL_GET_STATS IWAN_NT_CTL_CODE(0x805u)

#define IWAN_NT_SESSION_STRUCT_SIZE 16u
#define IWAN_NT_PEER_STRUCT_SIZE 8u
#define IWAN_NT_STATS_STRUCT_SIZE 176u

/* Largest control frame accepted in either direction. */
#define IWAN_NT_CONTROL_MAX 512u

typedef struct _IWAN_NT_SESSION_ABI {
    uint16_t Sid;        /* session id from OPEN_ACK */
    uint16_t Reserved0;  /* must be zero */
    uint32_t Token;      /* token from OPEN_ACK */
    uint32_t Encrypted;  /* nonzero: DATA payloads are XOR transformed */
    uint32_t Reserved1;  /* must be zero */
    uint8_t Key[8];      /* XOR key; only read when Encrypted != 0 */
} IWAN_NT_SESSION_ABI;

typedef struct _IWAN_NT_PEER_ABI {
    uint32_t Address;    /* IPv4, network byte order */
    uint16_t Port;       /* UDP port, network byte order */
    uint16_t Reserved;   /* must be zero */
} IWAN_NT_PEER_ABI;

/*
 * One coherent-enough snapshot. The transport writes this from PASSIVE_LEVEL
 * while the receive path may still be counting, so a value can lag by one
 * datagram; no field is ever torn, because each is a naturally aligned 64-bit
 * or 32-bit quantity with a single writer.
 */
typedef struct _IWAN_NT_STATS_ABI {
    uint64_t Receives;             /* datagrams the receive path looked at */
    uint64_t Delivered;            /* inner packets indicated up to NDIS */
    uint64_t BytesDelivered;       /* inner bytes indicated */
    uint64_t QueuedControl;        /* control frames put on the ring */
    uint64_t DroppedNoSession;
    uint64_t DroppedMalformed;
    uint64_t DroppedBadInner;
    uint64_t DroppedControlFull;
    uint64_t DroppedControlTooLarge;
    uint64_t DroppedControlNoRing;
    uint64_t DroppedNoSink;
    uint64_t DroppedSegrt;
    uint64_t DroppedUnknown;
    uint64_t ControlRead;          /* frames dequeued by READ_CONTROL */
    uint64_t ControlSent;          /* frames accepted by SEND_CONTROL */
    uint64_t ControlSendFailed;
    uint64_t TxAccepted;           /* inner packets the miniport accepted */
    uint64_t TxRejected;           /* inner packets the miniport refused */
    uint64_t RxIndicated;          /* NBLs indicated up */
    uint64_t RxDropped;            /* indications that could not be built */
    uint32_t TxInFlight;           /* send slots currently owned by WSK */
    uint32_t Reserved0;            /* must be zero */
    uint32_t SessionValid;         /* nonzero: a session is installed */
    uint32_t Running;              /* nonzero: the transport is Running */
    /*
     * Control frames waiting to be read are QueuedControl - ControlRead:
     * QueuedControl counts every successful ring push and ControlRead counts
     * every successful dequeue, and a frame is never dropped after it was
     * queued.
     */
} IWAN_NT_STATS_ABI;

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
