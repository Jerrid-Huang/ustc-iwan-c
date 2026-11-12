#ifndef IWAN_NT_IOCTL_H
#define IWAN_NT_IOCTL_H

/*
 * iWAN NT control-plane ABI.
 *
 * This header is shared verbatim with user mode. Its only dependency is
 * iwan_nt_types.h, which supplies the fixed-width integers in both
 * environments (ntddk.h in the kernel, stdint.h everywhere else). Every
 * structure is a fixed-size POD with explicit-width fields and no packing
 * surprises; every multi-byte integer is host order unless a field name says
 * otherwise.
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

#include "iwan_nt_types.h"

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
#define IWAN_NT_IOCTL_GET_LOCAL \
    IWAN_NT_CTL_CODE(0x806)
#define IWAN_NT_IOCTL_GET_STATS IWAN_NT_CTL_CODE(0x805u)
/*
 * Start or stop the in-kernel handshake. Write returns no payload; stop needs
 * no input either.
 */
#define IWAN_NT_IOCTL_START_PEER IWAN_NT_CTL_CODE(0x807u)
#define IWAN_NT_IOCTL_STOP_PEER IWAN_NT_CTL_CODE(0x808u)

#define IWAN_NT_SESSION_STRUCT_SIZE 24u
#define IWAN_NT_ADDR_STRUCT_SIZE 24u
#define IWAN_NT_STATS_STRUCT_SIZE 192u
#define IWAN_NT_CREDENTIALS_STRUCT_SIZE 136u

/* Field widths inside IWAN_NT_CREDENTIALS_ABI. */
#define IWAN_NT_CREDENTIALS_USER_MAX 64u
#define IWAN_NT_CREDENTIALS_PASSWORD_MAX 64u

/* Largest control frame accepted in either direction. */
#define IWAN_NT_CONTROL_MAX 512u

/*
 * Credentials for the in-kernel peer.
 *
 * The driver copies them and never hands the pointers back, so the caller may
 * reuse the buffer as soon as the call returns.
 */
typedef struct _IWAN_NT_CREDENTIALS_ABI {
    uint8_t User[64];
    uint8_t Password[64];
    uint16_t Mtu;
    uint16_t Reserved0;
    uint32_t Reserved1;
} IWAN_NT_CREDENTIALS_ABI;

typedef struct _IWAN_NT_SESSION_ABI {
    uint16_t Sid;        /* session id from OPEN_ACK */
    uint16_t Reserved0;  /* must be zero */
    uint32_t Token;      /* token from OPEN_ACK */
    uint32_t Encrypted;  /* nonzero: DATA payloads are XOR transformed */
    uint32_t Reserved1;  /* must be zero */
    uint8_t Key[8];      /* XOR key; only read when Encrypted != 0 */
} IWAN_NT_SESSION_ABI;

/*
 * One endpoint, either family. The outer packet is carried by a kernel datagram
 * socket, and which family that socket speaks decides the address width, so the
 * request names the family explicitly instead of guessing from the bytes.
 *
 * Address is in network order for the family named by Family (the first four
 * bytes for IPv4, all sixteen for IPv6); Port is in network order too. ScopeId
 * matters only for IPv6 link-local peers and must be zero otherwise.
 */
typedef struct _IWAN_NT_ADDR_ABI {
    uint8_t Address[16];
    uint16_t Port;
    uint16_t Family;     /* AF_INET or AF_INET6 */
    uint32_t ScopeId;
} IWAN_NT_ADDR_ABI;

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

    /*
     * Dropped below the ingress path, in the socket callback itself: a datagram
     * longer than the receive scratch, and one the sink refused. Both are counted
     * here because a drop with no counter is indistinguishable from an idle link.
     */
    uint64_t RxOversize;
    uint64_t RxSinkErrors;
} IWAN_NT_STATS_ABI;

/*
 * The sizes are part of the contract: if a field is ever added or a compiler
 * pads a structure differently, both sides must fail loudly rather than write
 * past a buffer one of them sized from the other's belief.
 */
_Static_assert(sizeof(IWAN_NT_SESSION_ABI) == IWAN_NT_SESSION_STRUCT_SIZE,
               "SESSION ABI size changed");
/*
 * GET_LOCAL returns the address the transport is bound to, in the same shape as
 * the peer request: the port is the part that matters, because it is chosen by
 * the provider and cannot be predicted from user mode.
 */
_Static_assert(sizeof(IWAN_NT_ADDR_ABI) == IWAN_NT_ADDR_STRUCT_SIZE,
               "address ABI size changed");
_Static_assert(sizeof(IWAN_NT_STATS_ABI) == IWAN_NT_STATS_STRUCT_SIZE,
               "STATS ABI size changed");

_Static_assert(sizeof(IWAN_NT_CREDENTIALS_ABI) == IWAN_NT_CREDENTIALS_STRUCT_SIZE,
               "credentials ABI size changed");

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
