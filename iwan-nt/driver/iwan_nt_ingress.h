#ifndef IWAN_NT_INGRESS_H
#define IWAN_NT_INGRESS_H

/*
 * iWAN NT receive pipeline.
 *
 * One outer UDP payload goes in; either an inner IP packet comes out through
 * the data sink, or a control frame is queued for the PASSIVE consumer, or the
 * payload is dropped with a counter that says why.
 *
 * This module has no kernel dependency: it is plain C over byte buffers plus
 * the two kernel-free modules it drives (demux and the control ring). It
 * performs no allocation and never blocks, so it can run inside the WSK
 * receive callback at IRQL <= DISPATCH_LEVEL.
 *
 * Serialization: every call must be serialized by the caller. The ring is
 * single-producer, and the counters have one writer per counter, so two
 * concurrent callbacks would break both. The WSK path holds the datagram
 * receive lock across the call, which also keeps the frame transform
 * single-threaded as required.
 *
 * Buffer ownership: Payload is transformed in place when the session is
 * encrypted, so the caller must hand over a writable, contiguous copy of the
 * UDP payload and must not reuse or free it until this call returns. The inner
 * packet handed to the data sink points into that same buffer, so the sink
 * must either consume it synchronously or copy it out; it may not retain the
 * pointer.
 */

#include "iwan_nt_types.h"

#include "iwan_nt_demux.h"
#include "iwan_nt_frame.h"
#include "iwan_nt_ring.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _IWAN_NT_INGRESS_SESSION {
    uint16_t Sid;
    uint32_t Token;
    /* Nonzero when the session negotiated an XOR-transformed DATA body. */
    int Encrypted;
    /* XOR key; read only when Encrypted is nonzero. */
    uint8_t Key[IWAN_NT_FRAME_KEY_LEN];
} IWAN_NT_INGRESS_SESSION;

typedef enum _IWAN_NT_INGRESS_RESULT {
    /* The inner packet was passed to the data sink. */
    IwanNtIngressDelivered = 0,
    /*
     * A control frame was queued on the control ring. The ring holds the
     * complete received frame, header and signature included, so the PASSIVE
     * consumer can run the demux again to recover the type and session fields
     * instead of trusting a second, divergent parser.
     */
    IwanNtIngressQueuedControl,
    /* No session is configured yet; nothing may be accepted. */
    IwanNtIngressDroppedNoSession,
    /* demux rejected the payload: short, wrong sid/token, bad signature, etc. */
    IwanNtIngressDroppedMalformed,
    /* The DATA frame decoded but the inner packet failed validation. */
    IwanNtIngressDroppedBadInner,
    /* A control frame arrived but the ring is full. */
    IwanNtIngressDroppedControlFull,
    /* The control ring is too small to ever hold a frame this long. */
    IwanNtIngressDroppedControlTooLarge,
    /* A control frame arrived and no control ring is configured. */
    IwanNtIngressDroppedControlNoRing,
    /* The inner packet decoded but no data sink is configured. */
    IwanNtIngressDroppedNoSink,
    /* SEGRT payload: recognized, deliberately not handled at this stage. */
    IwanNtIngressDroppedSegrt,
    /* A type with no known framing rule. */
    IwanNtIngressDroppedUnknown,
    /* Bad arguments, or the counters found the module misused. */
    IwanNtIngressBadArgument
} IWAN_NT_INGRESS_RESULT;

/*
 * Hand one decoded inner packet to the adapter for indication.
 *
 * IRQL: <= DISPATCH_LEVEL, same as the caller.
 * Ownership: Inner points into the caller's payload buffer and is only valid
 * during the call. The sink must not block, must not retain the pointer and
 * must not call back into the ingress.
 */
typedef void (*IWAN_NT_INGRESS_DATA_SINK)(
    _In_opt_ void *Context,
    _In_reads_bytes_(Length) const uint8_t *Inner,
    _In_ size_t Length,
    _In_ unsigned Family,
    _In_opt_ void *View
    );

typedef struct _IWAN_NT_INGRESS_COUNTERS {
    uint64_t Receives;          /* every call that had a payload */
    uint64_t Delivered;         /* inner packets handed to the sink */
    uint64_t BytesDelivered;    /* inner bytes handed to the sink */
    uint64_t QueuedControl;     /* control frames put on the ring */
    uint64_t DroppedNoSession;
    uint64_t DroppedMalformed;
    uint64_t DroppedBadInner;
    uint64_t DroppedControlFull;
    uint64_t DroppedControlTooLarge;
    uint64_t DroppedControlNoRing;
    uint64_t DroppedNoSink;
    uint64_t DroppedSegrt;
    uint64_t DroppedUnknown;
} IWAN_NT_INGRESS_COUNTERS;

typedef struct _IWAN_NT_INGRESS {
    /* Optional: when NULL, control frames are dropped and counted. */
    PIWAN_NT_RING ControlRing;
    IWAN_NT_INGRESS_SESSION Session;
    int SessionValid;
    IWAN_NT_INGRESS_DATA_SINK DataSink;
    void *DataSinkContext;
    /*
     * Opaque caller token handed back to the sink unchanged. The kernel receive
     * path uses it to tell the sink where the frame came from, so the sink can
     * point NDIS at the provider's buffer instead of a copy; nothing in this
     * module looks at it. Only IwanNtIngressReceiveWithView sets it.
     */
    void *View;
    IWAN_NT_INGRESS_COUNTERS Counters;
} IWAN_NT_INGRESS, *PIWAN_NT_INGRESS;

/*
 * Zero the module and mark it session-less.
 *
 * IRQL: PASSIVE_LEVEL.
 * Ownership: Ingress is caller-owned and must outlive every Receive.
 */
void IwanNtIngressInitialize(
    _Out_ PIWAN_NT_INGRESS Ingress
    );

/*
 * Install or replace the session parameters.
 *
 * IRQL: PASSIVE_LEVEL, and no Receive may be running concurrently.
 * Ownership: the values are copied, so the caller keeps ownership of Session.
 */
void IwanNtIngressSetSession(
    _Inout_ PIWAN_NT_INGRESS Ingress,
    _In_ const IWAN_NT_INGRESS_SESSION *Session
    );

/*
 * Remove the session so that any further payload is dropped and counted. Used
 * by the stop path; it does not touch the ring or the sink.
 *
 * IRQL: PASSIVE_LEVEL, and no Receive may be running concurrently.
 */
void IwanNtIngressClearSession(
    _Inout_ PIWAN_NT_INGRESS Ingress
    );

/*
 * Attach the control ring and the data sink.
 *
 * IRQL: PASSIVE_LEVEL, and no Receive may be running concurrently.
 * Ownership: neither object is freed here; both must outlive the attachment.
 */
void IwanNtIngressAttach(
    _Inout_ PIWAN_NT_INGRESS Ingress,
    _In_opt_ PIWAN_NT_RING ControlRing,
    _In_opt_ IWAN_NT_INGRESS_DATA_SINK DataSink,
    _In_opt_ void *DataSinkContext
    );

/*
 * Process one received UDP payload.
 *
 * IRQL: <= DISPATCH_LEVEL.
 * Ownership: Payload is writable and owned by the caller for the duration of
 * the call; it may be transformed in place. Length must be at least
 * IWAN_NT_FRAME_HDR_LEN and is the exact UDP payload length.
 *
 * Returns the outcome; the counters are updated for every outcome. Every
 * returned value other than IwanNtIngressDelivered and
 * IwanNtIngressQueuedControl means the payload left no trace other than a
 * counter.
 */
IWAN_NT_INGRESS_RESULT
IwanNtIngressReceive(
    _Inout_ PIWAN_NT_INGRESS Ingress,
    _Inout_updates_bytes_(Length) uint8_t *Payload,
    _In_ size_t Length
    );

/*
 * Same as IwanNtIngressReceive, but hands View to the data sink.
 *
 * View is opaque here and is not interpreted; it only has to stay valid for the
 * duration of the call, exactly like Payload. Passing NULL is the same as
 * calling IwanNtIngressReceive.
 *
 * IRQL: <= DISPATCH_LEVEL. Calls must be serialized.
 */
IWAN_NT_INGRESS_RESULT
IwanNtIngressReceiveWithView(
    _Inout_ PIWAN_NT_INGRESS Ingress,
    _Inout_updates_bytes_(Length) uint8_t *Payload,
    _In_ size_t Length,
    _In_opt_ void *View
    );

/*
 * Copy the counters out.
 *
 * IRQL: <= DISPATCH_LEVEL.
 * This is an advisory snapshot: a concurrent Receive can advance the counters
 * while the copy runs, so a reader must treat it as approximate. Aligned
 * 64-bit loads are indivisible on the supported targets, so no value is torn,
 * only mutually inconsistent by one update.
 */
void IwanNtIngressGetCounters(
    _In_ const IWAN_NT_INGRESS *Ingress,
    _Out_ IWAN_NT_INGRESS_COUNTERS *Counters
    );

#ifdef __cplusplus
}
#endif

#endif
