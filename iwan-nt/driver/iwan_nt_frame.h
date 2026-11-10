#ifndef IWAN_NT_FRAME_H
#define IWAN_NT_FRAME_H

/*
 * iWAN data-frame codec.
 *
 * This module is deliberately free of kernel dependencies: it is plain C over
 * byte buffers, so the same source builds inside the driver and inside a host
 * unit test. It performs no allocation and never blocks.
 *
 * Wire layout of one UDP payload (all fields little-endian on the wire):
 *
 *   +0  type      (1 B)
 *   +1  encrypt   (1 B)
 *   +2  sid       (2 B, little-endian; the reference client writes the raw
 *                       host-order value and the peer echoes it unchanged)
 *   +4  token     (4 B, little-endian, same rule as sid)
 *   +8  body      (inner IP packet, XOR-transformed when encrypt != 0)
 */

#include "iwan_nt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SAL spellings a host compiler does not provide. Each macro is guarded
 * on its own: these three headers include one another, so one shared
 * outer guard would leave later headers with an incomplete set.
 */
#ifndef _In_
#define _In_
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Inout_
#define _Inout_
#endif
#ifndef _In_opt_
#define _In_opt_
#endif
#ifndef _Out_opt_
#define _Out_opt_
#endif
#ifndef _Out_writes_
#define _Out_writes_(n)
#endif
#ifndef _In_reads_bytes_
#define _In_reads_bytes_(n)
#endif
#ifndef _In_reads_bytes_opt_
#define _In_reads_bytes_opt_(n)
#endif
#ifndef _Inout_updates_bytes_
#define _Inout_updates_bytes_(n)
#endif
#ifndef _Out_writes_bytes_to_
#define _Out_writes_bytes_to_(c, l)
#endif
#ifndef _Out_writes_bytes_opt_
#define _Out_writes_bytes_opt_(n)
#endif
#ifndef _Outptr_result_buffer_
#define _Outptr_result_buffer_(n)
#endif
#ifndef _Out_writes_bytes_
#define _Out_writes_bytes_(n)
#endif
#ifndef _Inout_updates_bytes_opt_
#define _Inout_updates_bytes_opt_(n)
#endif

#define IWAN_NT_FRAME_HDR_LEN 8u
#define IWAN_NT_FRAME_KEY_LEN 8u

#define IWAN_NT_TYPE_DATA 0x14u
#define IWAN_NT_TYPE_DATA_ENC 0x18u
#define IWAN_NT_TYPE_DATA6 0x23u
#define IWAN_NT_TYPE_DATA6_ENC 0x24u

#define IWAN_NT_INNER_IP4_MIN 20u
#define IWAN_NT_INNER_IP6_MIN 40u

typedef struct _IWAN_NT_FRAME_HEADER {
    uint8_t Type;
    uint8_t Encrypt;
    uint16_t Sid;
    uint32_t Token;
} IWAN_NT_FRAME_HEADER;

typedef enum _IWAN_NT_FRAME_RESULT {
    IwanNtFrameOk = 0,
    IwanNtFrameBadArgument,
    IwanNtFrameTooShort,
    IwanNtFrameTooLong,
    IwanNtFrameBadType,
    IwanNtFrameBadFamily,
    IwanNtFrameBadLength
} IWAN_NT_FRAME_RESULT;

/* Encode/decode the fixed 8-byte header. */
void IwanNtFrameHeaderEncode(
    _Out_writes_(IWAN_NT_FRAME_HDR_LEN) uint8_t *Out,
    _In_ const IWAN_NT_FRAME_HEADER *Header
    );

IWAN_NT_FRAME_RESULT IwanNtFrameHeaderDecode(
    _In_reads_bytes_(Length) const uint8_t *In,
    _In_ size_t Length,
    _Out_ IWAN_NT_FRAME_HEADER *Header
    );

/*
 * In-place XOR over the body with the repeating 8-byte key. The transform is
 * its own inverse, so the same routine seals and opens a body.
 */
void IwanNtFrameXor(
    _Inout_updates_bytes_(Length) uint8_t *Body,
    _In_ size_t Length,
    _In_reads_bytes_(IWAN_NT_FRAME_KEY_LEN) const uint8_t *Key
    );

/* 4 for IPv4, 6 for IPv6, 0 when the version nibble is neither. */
unsigned IwanNtFrameInnerFamily(
    _In_reads_bytes_opt_(Length) const uint8_t *Inner,
    _In_ size_t Length
    );

/*
 * Reject an inner packet whose declared length exceeds the bytes present.
 * Trailing bytes beyond the declared length are tolerated, matching the
 * reference implementation.
 */
IWAN_NT_FRAME_RESULT IwanNtFrameInnerSane(
    _In_reads_bytes_(Length) const uint8_t *Inner,
    _In_ size_t Length
    );

/*
 * Seal one inner packet into a UDP payload.
 *
 * OutCap must be at least IWAN_NT_FRAME_HDR_LEN + InnerLength. Encrypt selects
 * the DATA_ENC/DATA6_ENC frame type and applies the XOR transform; the caller
 * must supply a key in that case.
 */
IWAN_NT_FRAME_RESULT IwanNtFrameSeal(
    _Out_writes_bytes_to_(OutCap, *OutLength) uint8_t *Out,
    _In_ size_t OutCap,
    _In_reads_bytes_(InnerLength) const uint8_t *Inner,
    _In_ size_t InnerLength,
    _In_ const IWAN_NT_FRAME_HEADER *Header,
    _In_reads_bytes_opt_(IWAN_NT_FRAME_KEY_LEN) const uint8_t *Key,
    _Out_ size_t *OutLength
    );

/*
 * Open one UDP payload: validate the header, check the inner family, undo the
 * XOR transform in place and return a pointer to the inner packet.
 *
 * The transform happens inside Caller's buffer, so the inner packet is only
 * valid while that buffer is. On success Header receives the decoded header.
 */
IWAN_NT_FRAME_RESULT IwanNtFrameOpen(
    _Inout_updates_bytes_(Length) uint8_t *Payload,
    _In_ size_t Length,
    _In_reads_bytes_opt_(IWAN_NT_FRAME_KEY_LEN) const uint8_t *Key,
    _Out_ IWAN_NT_FRAME_HEADER *Header,
    _Outptr_result_buffer_(*InnerLength) const uint8_t **Inner,
    _Out_ size_t *InnerLength
    );

/* True when the frame type carries an XOR-transformed body. */
int IwanNtFrameTypeIsEncrypted(
    _In_ uint8_t Type
    );

/* True when the frame type is a data frame this module accepts. */
int IwanNtFrameTypeIsData(
    _In_ uint8_t Type
    );

#ifdef __cplusplus
}
#endif

#endif
