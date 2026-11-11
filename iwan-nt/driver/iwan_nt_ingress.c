#include "iwan_nt_ingress.h"

#include <string.h>

/*
 * The receive path is one straight line: check that a session exists, let the
 * demux decide what the payload is, then route it. Every early return updates
 * exactly one counter, so the counters always add up to Receives and a silent
 * drop is impossible.
 */

void
IwanNtIngressInitialize(
    PIWAN_NT_INGRESS Ingress
    )
{
    if (Ingress == NULL) {
        return;
    }
    memset(Ingress, 0, sizeof(*Ingress));
    /* memset already clears the session, the counters and both attachments. */
}

void
IwanNtIngressSetSession(
    PIWAN_NT_INGRESS Ingress,
    const IWAN_NT_INGRESS_SESSION *Session
    )
{
    size_t i;

    if (Ingress == NULL || Session == NULL) {
        return;
    }
    Ingress->Session.Sid = Session->Sid;
    Ingress->Session.Token = Session->Token;
    Ingress->Session.Encrypted = Session->Encrypted ? 1 : 0;
    for (i = 0; i < IWAN_NT_FRAME_KEY_LEN; i++) {
        Ingress->Session.Key[i] = Session->Key[i];
    }
    Ingress->SessionValid = 1;
}

void
IwanNtIngressClearSession(
    PIWAN_NT_INGRESS Ingress
    )
{
    if (Ingress == NULL) {
        return;
    }
    Ingress->SessionValid = 0;
    Ingress->Session.Sid = 0;
    Ingress->Session.Token = 0;
    Ingress->Session.Encrypted = 0;
    /* The key is secret material: it does not stay behind after a stop. */
    memset(Ingress->Session.Key, 0, IWAN_NT_FRAME_KEY_LEN);
}

void
IwanNtIngressAttach(
    PIWAN_NT_INGRESS Ingress,
    PIWAN_NT_RING ControlRing,
    IWAN_NT_INGRESS_DATA_SINK DataSink,
    void *DataSinkContext
    )
{
    if (Ingress == NULL) {
        return;
    }
    Ingress->ControlRing = ControlRing;
    Ingress->DataSink = DataSink;
    Ingress->DataSinkContext = DataSinkContext;
}

/*
 * Route one payload the demux already accepted.
 */
/*
 * Types that can legitimately arrive before a session exists: the peer's answer
 * to OPEN, its rejection, a keepalive response, and a close. OPEN itself is
 * client-to-server, so it is not here.
 */
static int
IwanNtIngressIsHandshakeType(
    uint8_t Type
    )
{
    return Type == IWAN_NT_TYPE_OPEN_ACK ||
           Type == IWAN_NT_TYPE_OPEN_REJECT ||
           Type == IWAN_NT_TYPE_ECHO_RESPONSE ||
           Type == IWAN_NT_TYPE_CLOSE;
}

static IWAN_NT_INGRESS_RESULT
IwanNtIngressRouteData(
    PIWAN_NT_INGRESS Ingress,
    uint8_t *Payload,
    size_t Length
    )
{
    IWAN_NT_FRAME_HEADER header;
    const uint8_t *inner = NULL;
    size_t innerLength = 0;
    IWAN_NT_FRAME_RESULT frameResult;
    unsigned family;

    frameResult = IwanNtFrameOpen(
        Payload,
        Length,
        Ingress->Session.Encrypted ? Ingress->Session.Key : NULL,
        &header,
        &inner,
        &innerLength);
    if (frameResult != IwanNtFrameOk) {
        Ingress->Counters.DroppedBadInner++;
        return IwanNtIngressDroppedBadInner;
    }

    family = IwanNtFrameInnerFamily(inner, innerLength);
    if (family == 0) {
        Ingress->Counters.DroppedBadInner++;
        return IwanNtIngressDroppedBadInner;
    }

    if (Ingress->DataSink == NULL) {
        Ingress->Counters.DroppedNoSink++;
        return IwanNtIngressDroppedNoSink;
    }

    Ingress->DataSink(Ingress->DataSinkContext, inner, innerLength, family);
    Ingress->Counters.Delivered++;
    Ingress->Counters.BytesDelivered += (uint64_t)innerLength;
    return IwanNtIngressDelivered;
}

static IWAN_NT_INGRESS_RESULT
IwanNtIngressRouteControl(
    PIWAN_NT_INGRESS Ingress,
    const uint8_t *Payload,
    size_t Length
    )
{
    IWAN_NT_RING_RESULT ringResult;

    if (Ingress->ControlRing == NULL) {
        Ingress->Counters.DroppedControlNoRing++;
        return IwanNtIngressDroppedControlNoRing;
    }

    ringResult = IwanNtRingPush(Ingress->ControlRing, Payload, Length);
    switch (ringResult) {
    case IwanNtRingOk:
        Ingress->Counters.QueuedControl++;
        return IwanNtIngressQueuedControl;
    case IwanNtRingFull:
        Ingress->Counters.DroppedControlFull++;
        return IwanNtIngressDroppedControlFull;
    case IwanNtRingRecordTooLarge:
        Ingress->Counters.DroppedControlTooLarge++;
        return IwanNtIngressDroppedControlTooLarge;
    default:
        /*
         * BadArgument or Corrupt: the ring rejected a frame the demux already
         * length-checked, so the ring itself is misconfigured or damaged.
         */
        Ingress->Counters.DroppedMalformed++;
        return IwanNtIngressDroppedMalformed;
    }
}

IWAN_NT_INGRESS_RESULT
IwanNtIngressReceive(
    PIWAN_NT_INGRESS Ingress,
    uint8_t *Payload,
    size_t Length
    )
{
    IWAN_NT_DEMUX_SESSION demuxSession;
    IWAN_NT_DEMUX_DECISION decision;
    IWAN_NT_DEMUX_RESULT demuxResult;

    if (Ingress == NULL) {
        return IwanNtIngressBadArgument;
    }
    if (Payload == NULL || Length < IWAN_NT_FRAME_HDR_LEN) {
        /*
         * A payload shorter than a header cannot be a frame at all; count it
         * as malformed rather than as a receive so that the counters still
         * reconcile against the socket's own datagram count.
         */
        Ingress->Counters.Receives++;
        Ingress->Counters.DroppedMalformed++;
        return IwanNtIngressDroppedMalformed;
    }

    Ingress->Counters.Receives++;

    if (!Ingress->SessionValid) {
        /*
         * The answer that creates the session arrives before there is a session
         * to check it against, so a control frame from the handshake must reach
         * the ring on the strength of its type alone. Everything else is dropped:
         * DATA with no sid or key has nothing to be validated with.
         */
        if (IwanNtIngressIsHandshakeType(Payload[0])) {
            return IwanNtIngressRouteControl(Ingress, Payload, Length);
        }
        Ingress->Counters.DroppedNoSession++;
        return IwanNtIngressDroppedNoSession;
    }

    demuxSession.Sid = Ingress->Session.Sid;
    demuxSession.Token = Ingress->Session.Token;
    demuxSession.Encrypted = Ingress->Session.Encrypted;

    demuxResult = IwanNtDemuxPayload(Payload, Length, &demuxSession,
                                     &decision);
    if (demuxResult != IwanNtDemuxOk) {
        Ingress->Counters.DroppedMalformed++;
        return IwanNtIngressDroppedMalformed;
    }

    switch (decision.Class) {
    case IwanNtDemuxClassData:
        return IwanNtIngressRouteData(Ingress, Payload, Length);

    case IwanNtDemuxClassControl:
        return IwanNtIngressRouteControl(Ingress, Payload, Length);

    case IwanNtDemuxClassSegrt:
        Ingress->Counters.DroppedSegrt++;
        return IwanNtIngressDroppedSegrt;

    case IwanNtDemuxClassUnknown:
    default:
        Ingress->Counters.DroppedUnknown++;
        return IwanNtIngressDroppedUnknown;
    }
}

void IwanNtIngressGetCounters(
    _In_ const IWAN_NT_INGRESS *Ingress,
    _Out_ IWAN_NT_INGRESS_COUNTERS *Counters
    )
{
    if (Ingress == NULL || Counters == NULL) {
        return;
    }

    *Counters = Ingress->Counters;
}
