#ifndef IWAN_NT_DEMUX_H
#define IWAN_NT_DEMUX_H

/*
 * Receive-side demultiplexing for one outer UDP payload.
 *
 * DATA, control and SEGRT traffic share the outer UDP port, so ingress must
 * classify a payload before handing it to a consumer. This module performs
 * only that decision: it does not decrypt, authenticate, copy or mutate the
 * payload.
 *
 * A normal frame starts with the 8-byte header decoded by iwan_nt_frame.h.
 * SEGRT is the exception: its first byte is the type, so it must be recognized
 * before a normal header is parsed. Control frames add a 16-byte signature
 * after the header; DATA frames put the inner IP packet there.
 *
 * The module is deliberately kernel-free and pure: it allocates nothing,
 * performs no I/O, calls no kernel API and keeps no mutable global state.
 */

#include "iwan_nt_frame.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IWAN_NT_TYPE_SEGRT 0x28u

/*
 * Smallest SEGRT this layer recognizes: the 4-byte source-routing header
 * (type, nextid, link count, algorithm/padding) with zero links. The link
 * array follows and is not length-checked here.
 */
#define IWAN_NT_SEGRT_MIN_LEN 4u

#define IWAN_NT_TYPE_OPEN_REJECT 0x11u
#define IWAN_NT_TYPE_OPEN_ACK 0x12u
#define IWAN_NT_TYPE_OPEN 0x13u
#define IWAN_NT_TYPE_ECHO_REQ 0x15u
#define IWAN_NT_TYPE_ECHO_RESPONSE 0x16u
#define IWAN_NT_TYPE_CLOSE 0x17u

#define IWAN_NT_CONTROL_SIGNATURE_LEN 16u
#define IWAN_NT_CONTROL_MIN_LEN \
    (IWAN_NT_FRAME_HDR_LEN + IWAN_NT_CONTROL_SIGNATURE_LEN)

typedef enum _IWAN_NT_DEMUX_CLASS {
    /* No framing rule is known for this type; it is not an error by itself. */
    IwanNtDemuxClassUnknown = 0,
    /* One of the four DATA frame types; Region is the inner IP packet. */
    IwanNtDemuxClassData,
    /* One of the control types; Region starts after the 16-byte signature. */
    IwanNtDemuxClassControl,
    /* Segment-routing payload with no normal header and no signature. */
    IwanNtDemuxClassSegrt
} IWAN_NT_DEMUX_CLASS;

typedef enum _IWAN_NT_DEMUX_RESULT {
    IwanNtDemuxOk = 0,
    /* NULL decision, payload or session argument. */
    IwanNtDemuxBadArgument,
    /* The buffer ends inside the 8-byte normal header. */
    IwanNtDemuxTooShort,
    /* A control frame does not include its full 16-byte signature. */
    IwanNtDemuxBadSignatureLength,
    IwanNtDemuxSidMismatch,
    IwanNtDemuxTokenMismatch,
    /*
     * The header encrypt flag disagrees with the frame type, or the frame's
     * encryption state disagrees with the session's encryption state.
     */
    IwanNtDemuxEncryptMismatch,
    /* The inner IP version is not the one required by the DATA type, or the
     * inner packet is not structurally sane. */
    IwanNtDemuxBadInnerFamily,
    /* The DATA body is shorter than the inner IP header, or the inner packet
     * declares more bytes than the body holds. */
    IwanNtDemuxBadInnerLength
} IWAN_NT_DEMUX_RESULT;

typedef struct _IWAN_NT_DEMUX_SESSION {
    uint16_t Sid;
    uint32_t Token;
    /* Nonzero when the session negotiated an XOR-transformed DATA body. */
    int Encrypted;
} IWAN_NT_DEMUX_SESSION;

typedef struct _IWAN_NT_DEMUX_DECISION {
    IWAN_NT_DEMUX_CLASS Class;
    IWAN_NT_DEMUX_RESULT Result;
    IWAN_NT_FRAME_HEADER Header;
    /* 1 when the normal 8-byte header was decoded, 0 for SEGRT or truncation. */
    uint8_t HeaderValid;
    /* Meaningful only when Result is IwanNtDemuxOk. */
    size_t RegionOffset;
    size_t RegionLength;
} IWAN_NT_DEMUX_DECISION;

/*
 * Decide how one received payload should be handled.
 *
 * Decision is always overwritten (and zeroed) before any other work. The
 * return value is the same value stored in Decision->Result. A NULL Decision
 * yields IwanNtDemuxBadArgument and cannot fill anything.
 *
 * SEGRT is checked first and bypasses header, sid and token validation because
 * it has no normal header. Its Region starts at offset 0 and covers the whole
 * payload, including the type byte.
 *
 * For a normal header, sid and token must exactly match the session for every
 * class, including control and unknown types. DATA frames additionally require
 * the encrypt flag to agree with both the type and the session. A plaintext
 * DATA frame is checked with IwanNtFrameInnerSane and must carry IPv4 for
 * 0x14/0x18 and IPv6 for 0x23/0x24. An encrypted DATA body is still
 * XOR-transformed at this stage, so its inner packet can only be validated
 * later by IwanNtFrameOpen with the session key; only its minimum length is
 * checked here.
 *
 * Control frames require a zero encrypt flag and the full 16-byte signature.
 * The signature bytes are not authenticated here. Their Region starts after
 * the signature. UNKNOWN types are classified, checked for a normal header
 * and session identity, and otherwise passed through; their Region is the
 * opaque bytes after the header.
 */
IWAN_NT_DEMUX_RESULT IwanNtDemuxPayload(
    _In_reads_bytes_(Length) const uint8_t *Payload,
    _In_ size_t Length,
    _In_ const IWAN_NT_DEMUX_SESSION *Session,
    _Out_ IWAN_NT_DEMUX_DECISION *Decision
    );

#ifdef __cplusplus
}
#endif

#endif
