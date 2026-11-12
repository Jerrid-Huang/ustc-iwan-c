#include "iwan_nt_transport.h"

#include <stddef.h>

#include "iwan_nt_string.h"

#define IWAN_NT_TAG_SCRATCH 'tcSI'

_IRQL_requires_max_(DISPATCH_LEVEL)
static uint64_t
IwanNtTransportNowMs(VOID);

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
IwanNtTransportApplyPeerStateLocked(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    );

_IRQL_requires_(DISPATCH_LEVEL)
static VOID
IwanNtTransportPeerTimerCallback(
    _In_ PIWAN_NT_TIMER Timer
    );

/*
 * Adapter from the WSK datagram callback to the receive pipeline.
 *
 * IRQL: <= DISPATCH_LEVEL, inside the datagram receive lock. The pipeline
 * transforms the payload in place and never blocks, so this stays a straight
 * call; the counters it updates are read-only to everyone else here.
 */
static VOID
IwanNtTransportReceiveChunk(
    _In_opt_ void *Context,
    _Inout_updates_bytes_(Length) uint8_t *Payload,
    _In_ size_t Length
    )
{
    PIWAN_NT_TRANSPORT transport = (PIWAN_NT_TRANSPORT)Context;
    KIRQL oldIrql;

    if (transport == NULL || Payload == NULL) {
        return;
    }

    /*
     * The control plane replaces the session at PASSIVE_LEVEL while datagrams
     * keep arriving, so the pipeline read needs the same lock the writers take.
     */
    KeAcquireSpinLock(&transport->SessionLock, &oldIrql);

    /*
     * Control frames feed the peer and stop there: they are the handshake, not
     * payload. Everything else goes down the data pipeline.
     */
    if (transport->PeerReady &&
        IwanNtPeerWantsFrame(&transport->Peer, Payload, Length)) {
        (VOID)IwanNtPeerOnFrame(
            &transport->Peer, Payload, Length, IwanNtTransportNowMs());
        IwanNtTransportApplyPeerStateLocked(transport);
    } else {
        (VOID)IwanNtIngressReceive(&transport->Ingress, Payload, Length);
    }

    KeReleaseSpinLock(&transport->SessionLock, oldIrql);
}

/*
 * Pool callback: hand one prepared batch to the socket.
 *
 * IRQL: <= DISPATCH_LEVEL, called from the send path.
 */
static NTSTATUS
IwanNtTransportSubmitSend(
    _In_opt_ void *Context,
    _In_ PWSK_BUF_LIST List,
    _In_ ULONG Messages,
    _In_ const IWAN_NT_SOCKADDR *Remote,
    _In_ PIRP Irp
    )
{
    PIWAN_NT_WSK_DATAGRAM datagram = (PIWAN_NT_WSK_DATAGRAM)Context;

    return IwanNtWskDatagramSubmitSendList(
        datagram, List, Messages, Remote, Irp);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static uint64_t
IwanNtTransportNowMs(VOID)
{
    /*
     * Interrupt time is the monotonic clock every IRQL may read; 10,000 ticks
     * make a millisecond.
     */
    return (uint64_t)(KeQueryInterruptTime() / 10000u);
}

/*
 * Mirror the peer state into the data path.
 *
 * IRQL: <= DISPATCH_LEVEL, session lock held.
 * The peer is the only writer of the session while it runs: when it comes up the
 * sid/token/key are installed, and when it drops they are cleared, so a stale
 * session can never encrypt with a key the server has forgotten.
 */
static VOID
IwanNtTransportApplyPeerStateLocked(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    )
{
    IWAN_NT_INGRESS_SESSION session;

    if (Transport->Peer.State == IwanNtPeerUp) {
        IwanNtMemZero(&session, sizeof(session));
        session.Sid = Transport->Peer.Sid;
        session.Token = Transport->Peer.Token;
        session.Encrypted = (int)Transport->Peer.Encrypted;
        IwanNtMemCopy(session.Key, Transport->Peer.Key, sizeof(session.Key));

        if (Transport->Ingress.SessionValid == 0 ||
            Transport->Ingress.Session.Sid != session.Sid ||
            Transport->Ingress.Session.Token != session.Token) {
            (VOID)IwanNtIngressSetSession(&Transport->Ingress, &session);
        }
    } else if (Transport->Ingress.SessionValid != 0) {
        IwanNtIngressClearSession(&Transport->Ingress);
    }
}

/*
 * Peer clock.
 *
 * IRQL: DISPATCH_LEVEL.
 * The timer callback runs here, so it needs one place to read the monotonic
 * millisecond clock that is legal above PASSIVE.
 */
_IRQL_requires_(DISPATCH_LEVEL)
static VOID
IwanNtTransportPeerTimerCallback(
    _In_ PIWAN_NT_TIMER Timer
    )
{
    PIWAN_NT_TRANSPORT transport = (PIWAN_NT_TRANSPORT)
        ((uint8_t *)Timer - offsetof(IWAN_NT_TRANSPORT, PeerTimer));
    KIRQL oldIrql;
    size_t length;
    NTSTATUS status;
    BOOLEAN again;
    BOOLEAN running;

    length = 0;
    again = FALSE;

    KeAcquireSpinLock(&transport->SessionLock, &oldIrql);
    if (transport->PeerReady &&
        IwanNtPeerTick(
            &transport->Peer,
            IwanNtTransportNowMs(),
            transport->PeerScratch,
            sizeof(transport->PeerScratch),
            &length)) {
        /*
         * Hand the frame straight to the send pool. It carries its own header,
         * so it goes out raw: the peer already sealed it.
         */
        status = IwanNtTxSendRaw(&transport->Tx, transport->PeerScratch, length);
        if (NT_SUCCESS(status)) {
            InterlockedIncrement64((volatile LONG64 *)&transport->ControlSent);
        } else {
            /*
             * The pool is full or the socket is gone. Count it and let the next
             * tick try again: a dropped keepalive is recoverable, a stuck timer
             * is not.
             */
            InterlockedIncrement64((volatile LONG64 *)&transport->ControlSendFailed);
        }
    }
    IwanNtTransportApplyPeerStateLocked(transport);
    again = transport->PeerReady;
    KeReleaseSpinLock(&transport->SessionLock, oldIrql);

    KeAcquireSpinLock(&transport->StateLock, &oldIrql);
    running = (BOOLEAN)(transport->State == IwanNtTransportRunning);
    KeReleaseSpinLock(&transport->StateLock, oldIrql);

    if (again && running) {
        IwanNtTimerArm(Timer, IWAN_NT_PEER_TICK_MS);
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
IwanNtTransportWaitForSends(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    )
{
    PAGED_CODE();
    ExWaitForRundownProtectionRelease(&Transport->Rundown);
    ExRundownCompleted(&Transport->Rundown);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtTransportInitialize(
    _Out_ PIWAN_NT_TRANSPORT Transport,
    _In_ ULONG SendLimit
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (Transport == NULL || SendLimit == 0 || SendLimit > IWAN_NT_MAX_SENDS) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Transport, sizeof(*Transport));
    ExInitializeRundownProtection(&Transport->Rundown);
    KeInitializeSpinLock(&Transport->StateLock);
    KeInitializeSpinLock(&Transport->SessionLock);
    IwanNtTimerInitialize(&Transport->PeerTimer, IwanNtTransportPeerTimerCallback);
    Transport->State = IwanNtTransportUninitialized;
    Transport->SendLimit = SendLimit;

    status = IwanNtWskInitialize(&Transport->Wsk);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Transport->SocketFamily = (uint16_t)AF_INET;
    status = IwanNtWskDatagramInitialize(&Transport->Datagram);
    if (!NT_SUCCESS(status)) {
        IwanNtWskUninitialize(&Transport->Wsk);
        return status;
    }

    IwanNtIngressInitialize(&Transport->Ingress);
    Transport->IngressAttached = FALSE;

    /*
     * The scratch buffer is non-paged because the receive callback may run at
     * DISPATCH_LEVEL; a paged buffer could not be touched there.
     */
    Transport->Scratch = (uint8_t *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, IWAN_NT_SCRATCH_BYTES, IWAN_NT_TAG_SCRATCH);
    if (Transport->Scratch == NULL) {
        (VOID)IwanNtWskDatagramFinalize(&Transport->Datagram);
        IwanNtWskUninitialize(&Transport->Wsk);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Transport->ScratchCapacity = IWAN_NT_SCRATCH_BYTES;

    status = IwanNtTxInitialize(
        &Transport->Tx, IwanNtTransportSubmitSend, &Transport->Datagram);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(Transport->Scratch, IWAN_NT_TAG_SCRATCH);
        Transport->Scratch = NULL;
        Transport->ScratchCapacity = 0;
        (VOID)IwanNtWskDatagramFinalize(&Transport->Datagram);
        IwanNtWskUninitialize(&Transport->Wsk);
        return status;
    }

    Transport->State = IwanNtTransportStopped;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtTransportStart(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    )
{
    KIRQL oldIrql;
    NTSTATUS status;
    BOOLEAN reinitialize;
    BOOLEAN providerWasCaptured;
    BOOLEAN releaseProvider;

    PAGED_CODE();

    if (Transport == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Lifecycle callers serialize Start with Stop and Finalize. */
    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    if (Transport->State != IwanNtTransportStopped) {
        KeReleaseSpinLock(&Transport->StateLock, oldIrql);
        return STATUS_INVALID_DEVICE_STATE;
    }
    reinitialize = Transport->RundownCompleted;
    providerWasCaptured = Transport->Wsk.ProviderCaptured;
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);

    /* Provider capture is nonblocking and is deliberately outside the lock. */
    status = IwanNtWskCaptureProvider(&Transport->Wsk);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* ExReInitializeRundownProtection is PASSIVE/APC only, never DISPATCH. */
    if (reinitialize) {
        ExReInitializeRundownProtection(&Transport->Rundown);
    }

    releaseProvider = FALSE;
    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    if (Transport->State != IwanNtTransportStopped) {
        releaseProvider = (BOOLEAN)!providerWasCaptured;
        KeReleaseSpinLock(&Transport->StateLock, oldIrql);
        if (releaseProvider) {
            IwanNtWskReleaseProvider(&Transport->Wsk);
        }
        return STATUS_INVALID_DEVICE_STATE;
    }
    Transport->RundownCompleted = FALSE;
    Transport->State = IwanNtTransportRunning;
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);

    /*
     * The datagram socket is the only provider consumer at this stage. If it
     * cannot start, fall back to Stopped so the owner can retry, and drop the
     * provider reference again; the send rundown stays open for the next Stop.
     */
    /*
     * Attach the receive path first: the socket enables the event callback
     * inside Start, so a sink installed afterwards could race the first
     * datagram.
     */
    IwanNtWskDatagramAttachReceive(
        &Transport->Datagram,
        Transport->Scratch,
        Transport->ScratchCapacity,
        IwanNtTransportReceiveChunk,
        Transport);
    Transport->IngressAttached = TRUE;

    status = IwanNtWskDatagramStart(
        &Transport->Datagram, &Transport->Wsk.ProviderNpi,
        Transport->SocketFamily);
    if (!NT_SUCCESS(status)) {
        IwanNtWskDatagramAttachReceive(
            &Transport->Datagram, NULL, 0, NULL, NULL);
        Transport->IngressAttached = FALSE;
        IwanNtWskReleaseProvider(&Transport->Wsk);
        KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
        Transport->State = IwanNtTransportStopped;
        KeReleaseSpinLock(&Transport->StateLock, oldIrql);
        return status;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportStop(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    )
{
    KIRQL oldIrql;
    BOOLEAN waitForSends;

    PAGED_CODE();

    if (Transport == NULL) {
        return;
    }

    waitForSends = FALSE;
    /* No tick may start after the socket closes underneath it. */
    (VOID)IwanNtTimerCancel(&Transport->PeerTimer);

    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    if (Transport->State == IwanNtTransportRunning ||
        Transport->State == IwanNtTransportStopping) {
        Transport->State = IwanNtTransportStopping;
        waitForSends = (BOOLEAN)!Transport->RundownCompleted;
    } else if (Transport->State == IwanNtTransportStopped) {
        /* A newly initialized Stopped object still has an open rundown. */
        waitForSends = (BOOLEAN)!Transport->RundownCompleted;
    }
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);

    if (waitForSends) {
        IwanNtTransportWaitForSends(Transport);
        Transport->RundownCompleted = TRUE;
    }

    /*
     * Drain the send pool first. Closing the socket cancels pending IRPs, and a
     * completion that lands after the pool is freed would be unrecoverable, so
     * the pool must be empty before the socket goes away.
     */
    (VOID)IwanNtTxWaitIdle(&Transport->Tx, IWAN_NT_TX_DRAIN_MS);

    /*
     * The socket must be fully closed before its provider reference is
     * released: WskCloseSocket is the last call that may touch the socket.
     */
    (VOID)IwanNtWskDatagramStop(&Transport->Datagram);

    /* Stop has drained the callbacks, so the sink can be detached safely. */
    if (Transport->IngressAttached) {
        IwanNtWskDatagramAttachReceive(
            &Transport->Datagram, NULL, 0, NULL, NULL);
        Transport->IngressAttached = FALSE;
    }

    IwanNtWskReleaseProvider(&Transport->Wsk);

    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    if (Transport->State == IwanNtTransportStopping) {
        Transport->State = IwanNtTransportStopped;
    }
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportFinalize(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    )
{
    KIRQL oldIrql;
    BOOLEAN waitForSends;
    NTSTATUS status;

    PAGED_CODE();

    if (Transport == NULL) {
        return;
    }

    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    if (Transport->State == IwanNtTransportFinalized) {
        KeReleaseSpinLock(&Transport->StateLock, oldIrql);
        return;
    }

    /*
     * Stop the peer clock first: a tick that fires while the socket is being
     * finalized would submit into a pool whose transport is going away.
     */
    (VOID)IwanNtTimerCancel(&Transport->PeerTimer);

    /* Finalizing rejects new sends; the rundown wait closes all prior refs. */
    Transport->State = IwanNtTransportFinalizing;
    waitForSends = (BOOLEAN)!Transport->RundownCompleted;
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);

    if (waitForSends) {
        IwanNtTransportWaitForSends(Transport);

        KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
        Transport->RundownCompleted = TRUE;
        KeReleaseSpinLock(&Transport->StateLock, oldIrql);
    }

    /*
     * Finish the socket before deregistering WSK: after WskDeregister the
     * provider NPI is gone and a stuck socket could never be closed again.
     */
    (VOID)IwanNtTxWaitIdle(&Transport->Tx, IWAN_NT_TX_DRAIN_MS);

    status = IwanNtWskDatagramFinalize(&Transport->Datagram);
    if (!NT_SUCCESS(status)) {
        /* Keep the WSK registration alive; the owner may retry Finalize. */
        KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
        Transport->State = IwanNtTransportFinalizing;
        KeReleaseSpinLock(&Transport->StateLock, oldIrql);
        return;
    }

    if (Transport->IngressAttached) {
        IwanNtWskDatagramAttachReceive(
            &Transport->Datagram, NULL, 0, NULL, NULL);
        Transport->IngressAttached = FALSE;
    }

    if (Transport->Scratch != NULL) {
        ExFreePoolWithTag(Transport->Scratch, IWAN_NT_TAG_SCRATCH);
        Transport->Scratch = NULL;
        Transport->ScratchCapacity = 0;
    }

    IwanNtTxFinalize(&Transport->Tx);
    IwanNtWskUninitialize(&Transport->Wsk);

    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    Transport->State = IwanNtTransportFinalized;
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtTransportSendControl(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_reads_bytes_(Length) const uint8_t *Payload,
    _In_ size_t Length
    )
{
    KIRQL oldIrql;
    BOOLEAN running;
    NTSTATUS status;

    PAGED_CODE();

    if (Transport == NULL || Payload == NULL || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Length > IWAN_NT_CONTROL_MAX) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    running = (BOOLEAN)(Transport->State == IwanNtTransportRunning);
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);
    if (!running) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = IwanNtTxSendRaw(&Transport->Tx, Payload, Length);

    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    if (NT_SUCCESS(status)) {
        Transport->ControlSent++;
    } else {
        Transport->ControlSendFailed++;
    }
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtTransportReadControl(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _Out_writes_bytes_opt_(Capacity) uint8_t *Out,
    _In_ size_t Capacity,
    _Out_ size_t *OutLength,
    _Out_opt_ size_t *Required
    )
{
    IWAN_NT_RING_RESULT result;
    size_t length = 0;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Transport == NULL || OutLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutLength = 0;

    if (Transport->ControlRingInitialized == FALSE) {
        return STATUS_NO_MORE_ENTRIES;
    }

    result = IwanNtRingPeekLength(&Transport->ControlRing, &length);
    if (result == IwanNtRingEmpty) {
        return STATUS_NO_MORE_ENTRIES;
    }
    if (result != IwanNtRingOk) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (length > Capacity || Out == NULL) {
        /*
         * Leave the record in the ring: a caller that guessed the size wrong
         * retries instead of losing a control frame.
         */
        if (Required != NULL) {
            *Required = length;
        }
        return STATUS_BUFFER_TOO_SMALL;
    }

    result = IwanNtRingPop(&Transport->ControlRing, Out, Capacity, &length);
    if (result != IwanNtRingOk) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    *OutLength = length;
    if (Required != NULL) {
        *Required = length;
    }

    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    Transport->ControlRead++;
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportGetStats(
    _In_ PIWAN_NT_TRANSPORT Transport,
    _Out_ IWAN_NT_STATS_ABI *Stats
    )
{
    IWAN_NT_INGRESS_COUNTERS ingress;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Transport == NULL || Stats == NULL) {
        return;
    }

    IwanNtIngressGetCounters(&Transport->Ingress, &ingress);

    Stats->Receives = ingress.Receives;
    Stats->Delivered = ingress.Delivered;
    Stats->BytesDelivered = ingress.BytesDelivered;
    Stats->QueuedControl = ingress.QueuedControl;
    Stats->DroppedNoSession = ingress.DroppedNoSession;
    Stats->DroppedMalformed = ingress.DroppedMalformed;
    Stats->DroppedBadInner = ingress.DroppedBadInner;
    Stats->DroppedControlFull = ingress.DroppedControlFull;
    Stats->DroppedControlTooLarge = ingress.DroppedControlTooLarge;
    Stats->DroppedControlNoRing = ingress.DroppedControlNoRing;
    Stats->DroppedNoSink = ingress.DroppedNoSink;
    Stats->DroppedSegrt = ingress.DroppedSegrt;
    Stats->DroppedUnknown = ingress.DroppedUnknown;

    Stats->TxAccepted = 0;
    Stats->TxRejected = 0;
    Stats->RxIndicated = 0;
    Stats->RxDropped = 0;

    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    /*
     * These two are written by the socket callback without a lock; a snapshot may
     * catch them mid-update, which is acceptable for advisory counters and is
     * why they are documented as such rather than presented as exact.
     */
    Stats->RxOversize = (uint64_t)Transport->Datagram.OversizeDrops;
    Stats->RxSinkErrors = (uint64_t)Transport->Datagram.SinkErrors;
    Stats->ControlRead = Transport->ControlRead;
    Stats->ControlSent = Transport->ControlSent;
    Stats->ControlSendFailed = Transport->ControlSendFailed;
    Stats->Running =
        (uint32_t)(Transport->State == IwanNtTransportRunning ? 1u : 0u);
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);

    /*
     * SessionValid has its own lock: the receive path updates it from the
     * WSK callback, so it must not be read under StateLock.
     */
    KeAcquireSpinLock(&Transport->SessionLock, &oldIrql);
    Stats->SessionValid =
        (uint32_t)(Transport->Ingress.SessionValid != 0 ? 1u : 0u);
    /*
     * The peer counters move on the same lock: the timer callback and the
     * receive path both update them.
     */
    Stats->PeerOpens = Transport->Peer.Opens;
    Stats->PeerEchoes = Transport->Peer.Echoes;
    Stats->PeerEchoAnswers = Transport->Peer.EchoAnswers;
    Stats->PeerRejects = Transport->Peer.Rejects;
    Stats->PeerCloses = Transport->Peer.Closes;
    Stats->PeerForeign = Transport->Peer.ForeignFrames;
    Stats->PeerTimeouts = Transport->Peer.Timeouts;
    Stats->PeerState = (uint32_t)(Transport->Peer.State == IwanNtPeerUp ? 1u : 0u);
    Stats->PeerReady = (uint32_t)(Transport->PeerReady != 0 ? 1u : 0u);
    Stats->PeerDelayCurrent = Transport->Peer.DelayCurrent;
    Stats->PeerDelayMinimum = Transport->Peer.DelayMinimum;
    Stats->PeerDelayMaximum = Transport->Peer.DelayMaximum;
    Stats->Reserved1 = 0;
    KeReleaseSpinLock(&Transport->SessionLock, oldIrql);

    Stats->TxInFlight = (uint32_t)IwanNtTxInFlight(&Transport->Tx);
    Stats->Reserved0 = 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
IwanNtTransportTryAcquireSend(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    )
{
    KIRQL oldIrql;
    BOOLEAN acquired;

    if (Transport == NULL ||
        !ExAcquireRundownProtection(&Transport->Rundown)) {
        return FALSE;
    }

    acquired = FALSE;
    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    if (Transport->State == IwanNtTransportRunning &&
        Transport->OutstandingSends < Transport->SendLimit) {
        Transport->OutstandingSends++;
        acquired = TRUE;
    }
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);

    if (!acquired) {
        ExReleaseRundownProtection(&Transport->Rundown);
    }

    return acquired;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
IwanNtTransportReleaseSend(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    )
{
    KIRQL oldIrql;

    if (Transport == NULL) {
        return;
    }

    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    NT_ASSERT(Transport->OutstandingSends != 0);
    if (Transport->OutstandingSends != 0) {
        Transport->OutstandingSends--;
    }
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);

    ExReleaseRundownProtection(&Transport->Rundown);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportSetSession(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_ const IWAN_NT_INGRESS_SESSION *Session
    )
{
    PAGED_CODE();
    KIRQL oldIrql;

    if (Transport == NULL || Session == NULL) {
        return;
    }

    KeAcquireSpinLock(&Transport->SessionLock, &oldIrql);
    IwanNtIngressSetSession(&Transport->Ingress, Session);
    KeReleaseSpinLock(&Transport->SessionLock, oldIrql);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportClearSession(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    )
{
    PAGED_CODE();
    KIRQL oldIrql;

    if (Transport == NULL) {
        return;
    }

    KeAcquireSpinLock(&Transport->SessionLock, &oldIrql);
    IwanNtIngressClearSession(&Transport->Ingress);
    KeReleaseSpinLock(&Transport->SessionLock, oldIrql);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportSetDataSink(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_opt_ IWAN_NT_INGRESS_DATA_SINK Sink,
    _In_opt_ void *Context
    )
{
    PAGED_CODE();

    if (Transport == NULL) {
        return;
    }

    IwanNtIngressAttach(
        &Transport->Ingress, Transport->Ingress.ControlRing, Sink, Context);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportSetControlRing(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_reads_bytes_opt_(StorageBytes) uint8_t *Storage,
    _In_ size_t StorageBytes
    )
{
    PAGED_CODE();

    if (Transport == NULL) {
        return;
    }

    if (Storage == NULL || StorageBytes == 0) {
        Transport->ControlRingInitialized = FALSE;
        IwanNtIngressAttach(&Transport->Ingress, NULL,
                            Transport->Ingress.DataSink,
                            Transport->Ingress.DataSinkContext);
        return;
    }

    if (!NT_SUCCESS(IwanNtRingInitialize(
            &Transport->ControlRing, Storage, StorageBytes))) {
        IwanNtIngressAttach(&Transport->Ingress, NULL,
                            Transport->Ingress.DataSink,
                            Transport->Ingress.DataSinkContext);
        Transport->ControlRingInitialized = FALSE;
        return;
    }

    Transport->ControlRingInitialized = TRUE;
    IwanNtIngressAttach(&Transport->Ingress, &Transport->ControlRing,
                        Transport->Ingress.DataSink,
                        Transport->Ingress.DataSinkContext);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
IwanNtTransportGetIngressCounters(
    _In_ PIWAN_NT_TRANSPORT Transport,
    _Out_ IWAN_NT_INGRESS_COUNTERS *Counters
    )
{
    if (Transport == NULL || Counters == NULL) {
        return;
    }

    IwanNtIngressGetCounters(&Transport->Ingress, Counters);
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IwanNtTransportGetLocal(
    _In_ const IWAN_NT_TRANSPORT *Transport,
    _Out_ PIWAN_NT_SOCKADDR Local
    )
{
    PAGED_CODE();

    if (Transport == NULL || Local == NULL) {
        return FALSE;
    }
    return IwanNtWskDatagramGetLocal(&Transport->Datagram, Local);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtTransportSetPeer(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_ const IWAN_NT_SOCKADDR *Remote
    )
{
    KIRQL oldIrql;
    uint16_t family;
    BOOLEAN running;
    NTSTATUS status;

    PAGED_CODE();

    if (Transport == NULL || Remote == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    family = IwanNtAddrFamily(Remote);
    if (family == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    running = (Transport->State == IwanNtTransportRunning) ? TRUE : FALSE;
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);

    /*
     * A socket cannot change family, so a peer in the other family needs a new
     * one. Only the socket is recycled: the session, the receive sink and the
     * scratch buffer belong to the transport and survive.
     */
    Transport->SocketFamily = family;

    if (running != FALSE &&
        IwanNtWskDatagramFamily(&Transport->Datagram) != family) {

        (VOID)IwanNtTxWaitIdle(&Transport->Tx, IWAN_NT_TX_DRAIN_MS);
        (VOID)IwanNtWskDatagramStop(&Transport->Datagram);

        status = IwanNtWskDatagramStart(
            &Transport->Datagram, &Transport->Wsk.ProviderNpi, family);
        if (!NT_SUCCESS(status)) {
            KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
            Transport->State = IwanNtTransportStopped;
            KeReleaseSpinLock(&Transport->StateLock, oldIrql);
            return status;
        }
    }

    IwanNtTxSetRemote(&Transport->Tx, Remote);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtTransportStartPeer(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_reads_z_(64) const char *User,
    _In_reads_z_(64) const char *Password,
    _In_ uint16_t Mtu
    )
{
    size_t length;
    KIRQL oldIrql;
    BOOLEAN running;

    PAGED_CODE();

    if (Transport == NULL || User == NULL || Password == NULL || Mtu == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    running = (BOOLEAN)(Transport->State == IwanNtTransportRunning);
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);
    if (!running) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    length = IwanNtStringLength(User);
    if (length >= sizeof(Transport->Peer.User)) {
        return STATUS_INVALID_PARAMETER;
    }
    length = IwanNtStringLength(Password);
    if (length >= sizeof(Transport->Peer.Password)) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Install the credentials under the lock the receive path takes: a second
     * START_PEER while the first is live would otherwise reinitialise the peer
     * under a datagram that is feeding it.
     */
    KeAcquireSpinLock(&Transport->SessionLock, &oldIrql);
    if (Transport->PeerReady) {
        KeReleaseSpinLock(&Transport->SessionLock, oldIrql);
        return STATUS_DEVICE_BUSY;
    }
    if (!IwanNtPeerInitialize(&Transport->Peer, User, Password, Mtu,
                              IwanNtTransportNowMs())) {
        KeReleaseSpinLock(&Transport->SessionLock, oldIrql);
        return STATUS_INVALID_PARAMETER;
    }
    Transport->PeerReady = TRUE;
    KeReleaseSpinLock(&Transport->SessionLock, oldIrql);

    /* From here the handshake runs on its own clock, not on arrivals. */
    IwanNtTimerArm(&Transport->PeerTimer, IWAN_NT_PEER_TICK_MS);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTransportStopPeer(
    _Inout_ PIWAN_NT_TRANSPORT Transport
    )
{
    KIRQL oldIrql;

    PAGED_CODE();

    if (Transport == NULL) {
        return;
    }

    /*
     * Stop the clock before the state: a tick that runs after PeerReady is
     * cleared would be harmless, but waiting for it here keeps the shutdown
     * sequence single-threaded.
     */
    (VOID)IwanNtTimerCancel(&Transport->PeerTimer);

    KeAcquireSpinLock(&Transport->SessionLock, &oldIrql);
    Transport->PeerReady = FALSE;
    IwanNtPeerReset(&Transport->Peer, IwanNtTransportNowMs());
    IwanNtTransportApplyPeerStateLocked(Transport);
    KeReleaseSpinLock(&Transport->SessionLock, oldIrql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
IwanNtTransportSendInnerBatch(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_reads_(Count) const IWAN_NT_TX_ITEM *Items,
    _In_ ULONG Count,
    _Out_ PULONG Accepted
    )
{
    IWAN_NT_FRAME_HEADER header;
    uint8_t key[IWAN_NT_FRAME_KEY_LEN];
    unsigned family = 0;
    unsigned itemFamily;
    ULONG index;
    KIRQL oldIrql;
    BOOLEAN running;
    BOOLEAN sessionValid;
    BOOLEAN encrypted;

    if (Accepted != NULL) {
        *Accepted = 0;
    }
    if (Transport == NULL || Items == NULL || Count == 0 || Accepted == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    running = (BOOLEAN)(Transport->State == IwanNtTransportRunning);
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);
    if (!running) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    /*
     * One header serves the whole batch, so every packet has to agree on the
     * inner family. Checking up front keeps a mixed chain from being sent with
     * the wrong frame type.
     */
    for (index = 0; index < Count; index++) {
        if (Items[index].Inner == NULL || Items[index].InnerLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        itemFamily = IwanNtFrameInnerFamily(Items[index].Inner,
                                            Items[index].InnerLength);
        if (itemFamily != 4 && itemFamily != 6) {
            return STATUS_INVALID_PARAMETER;
        }
        if (index == 0) {
            family = itemFamily;
        } else if (family != itemFamily) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    KeAcquireSpinLock(&Transport->SessionLock, &oldIrql);
    sessionValid = (BOOLEAN)(Transport->Ingress.SessionValid != 0);
    encrypted = (BOOLEAN)(Transport->Ingress.Session.Encrypted != 0);
    header.Sid = Transport->Ingress.Session.Sid;
    header.Token = Transport->Ingress.Session.Token;
    header.Encrypt = (uint8_t)(encrypted ? 1u : 0u);
    RtlCopyMemory(key, Transport->Ingress.Session.Key, sizeof(key));
    KeReleaseSpinLock(&Transport->SessionLock, oldIrql);

    if (!sessionValid) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (family == 4) {
        header.Type = encrypted ? IWAN_NT_TYPE_DATA_ENC : IWAN_NT_TYPE_DATA;
    } else {
        header.Type = encrypted ? IWAN_NT_TYPE_DATA6_ENC : IWAN_NT_TYPE_DATA6;
    }

    return IwanNtTxSendBatch(
        &Transport->Tx, &header, encrypted ? key : NULL, Items, Count, Accepted);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
IwanNtTransportSendInner(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_reads_bytes_(InnerLength) const uint8_t *Inner,
    _In_ size_t InnerLength
    )
{
    IWAN_NT_FRAME_HEADER header;
    uint8_t key[IWAN_NT_FRAME_KEY_LEN];
    unsigned family;
    KIRQL oldIrql;
    BOOLEAN running;
    BOOLEAN sessionValid;
    BOOLEAN encrypted;

    if (Transport == NULL || Inner == NULL || InnerLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Transport->StateLock, &oldIrql);
    running = (BOOLEAN)(Transport->State == IwanNtTransportRunning);
    KeReleaseSpinLock(&Transport->StateLock, oldIrql);
    if (!running) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    family = IwanNtFrameInnerFamily(Inner, InnerLength);
    if (family != 4 && family != 6) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * The session belongs to the ingress object because both directions share
     * one definition of "ours"; reading it here needs no extra copy.
     */
    KeAcquireSpinLock(&Transport->SessionLock, &oldIrql);
    sessionValid = (BOOLEAN)(Transport->Ingress.SessionValid != 0);
    encrypted = (BOOLEAN)(Transport->Ingress.Session.Encrypted != 0);
    header.Sid = Transport->Ingress.Session.Sid;
    header.Token = Transport->Ingress.Session.Token;
    header.Encrypt = (uint8_t)(encrypted ? 1u : 0u);
    RtlCopyMemory(key, Transport->Ingress.Session.Key, sizeof(key));
    KeReleaseSpinLock(&Transport->SessionLock, oldIrql);

    if (!sessionValid) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (family == 4) {
        header.Type = encrypted ? IWAN_NT_TYPE_DATA_ENC : IWAN_NT_TYPE_DATA;
    } else {
        header.Type = encrypted ? IWAN_NT_TYPE_DATA6_ENC : IWAN_NT_TYPE_DATA6;
    }

    return IwanNtTxSend(
        &Transport->Tx, &header, encrypted ? key : NULL, Inner, InnerLength);
}
