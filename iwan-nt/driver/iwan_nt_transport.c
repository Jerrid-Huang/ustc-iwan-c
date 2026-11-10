#include "iwan_nt_transport.h"

#define IWAN_NT_TAG_SCRATCH 'tcSI'

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
    (VOID)IwanNtIngressReceive(&transport->Ingress, Payload, Length);
    KeReleaseSpinLock(&transport->SessionLock, oldIrql);
}

/*
 * Pool callback: hand one prepared datagram to the socket.
 *
 * IRQL: <= DISPATCH_LEVEL, called from the send path.
 */
static NTSTATUS
IwanNtTransportSubmitSend(
    _In_opt_ void *Context,
    _In_ PMDL Mdl,
    _In_ ULONG Length,
    _In_ const SOCKADDR_IN *Remote,
    _In_ PIRP Irp
    )
{
    PIWAN_NT_WSK_DATAGRAM datagram = (PIWAN_NT_WSK_DATAGRAM)Context;

    return IwanNtWskDatagramSubmitSend(datagram, Mdl, Length, Remote, Irp);
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
    Transport->State = IwanNtTransportUninitialized;
    Transport->SendLimit = SendLimit;

    status = IwanNtWskInitialize(&Transport->Wsk);
    if (!NT_SUCCESS(status)) {
        return status;
    }

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
        &Transport->Datagram, &Transport->Wsk.ProviderNpi);
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
VOID
IwanNtTransportSetPeer(
    _Inout_ PIWAN_NT_TRANSPORT Transport,
    _In_ const SOCKADDR_IN *Remote
    )
{
    PAGED_CODE();

    if (Transport == NULL || Remote == NULL) {
        return;
    }

    IwanNtTxSetRemote(&Transport->Tx, Remote);
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
