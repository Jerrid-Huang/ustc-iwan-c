#include "iwan_nt_tx.h"

#define IWAN_NT_TAG_TX_POOL 'pxTI'
#define IWAN_NT_TAG_TX_BUFFER 'bxTI'

/*
 * Completion for one submitted datagram.
 *
 * IRQL: <= DISPATCH_LEVEL.
 *
 * Returning STATUS_MORE_PROCESSING_REQUIRED stops the I/O manager from
 * touching the IRP after this routine, so the pool can reuse it. The slot is
 * returned before the idle event is signalled, so a waiter that observes
 * InFlight == 0 can free the pool without racing this routine.
 */
static NTSTATUS
IwanNtTxComplete(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_opt_ PVOID Context
    )
{
    PIWAN_NT_TX_SLOT slot = (PIWAN_NT_TX_SLOT)Context;
    PIWAN_NT_TX tx;
    KIRQL oldIrql;
    BOOLEAN signalIdle;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    if (slot == NULL || slot->Owner == NULL) {
        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    tx = slot->Owner;

    /*
     * A completion runs at IRQL <= DISPATCH_LEVEL, possibly synchronously
     * inside the submit call at PASSIVE, so the lock must be taken with the
     * IRQL-raising form rather than the at-DPC form.
     *
     * One IRP covers the whole batch, so walk the chain this slot heads and
     * release every slot on it. The list is circular: stop when we come back.
     */
    KeAcquireSpinLock(&tx->Lock, &oldIrql);
    {
        PWSK_BUF_LIST entry = &slot->List;

        while (entry != NULL) {
            PIWAN_NT_TX_SLOT member =
                CONTAINING_RECORD(entry, IWAN_NT_TX_SLOT, List);

            entry = entry->Next;
            member->List.Next = NULL;
            member->InUse = FALSE;
            tx->FreeCount++;
            tx->InFlight--;
            tx->Completed++;
        }
    }
    signalIdle = (BOOLEAN)(tx->InFlight == 0);
    KeReleaseSpinLock(&tx->Lock, oldIrql);

    if (signalIdle) {
        KeSetEvent(&tx->IdleEvent, IO_NO_INCREMENT, FALSE);
    }

    return STATUS_MORE_PROCESSING_REQUIRED;
}

/*
 * Return a claimed slot. The caller holds Lock. Returns TRUE when the caller
 * must signal IdleEvent after dropping the lock, because signalling an event
 * under a spin lock is avoidable and this module does not need to do it.
 */
static BOOLEAN
IwanNtTxReleaseSlotLocked(
    _Inout_ PIWAN_NT_TX Tx,
    _Inout_ PIWAN_NT_TX_SLOT Slot
    )
{
    Slot->InUse = FALSE;
    Tx->FreeCount++;
    Tx->InFlight--;
    return (BOOLEAN)(Tx->InFlight == 0);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IwanNtTxInitialize(
    _Out_ PIWAN_NT_TX Tx,
    _In_ IWAN_NT_TX_SUBMIT Submit,
    _In_opt_ void *SubmitContext
    )
{
    ULONG index;

    PAGED_CODE();

    if (Tx == NULL || Submit == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Tx, sizeof(*Tx));
    KeInitializeSpinLock(&Tx->Lock);
    KeInitializeEvent(&Tx->IdleEvent, NotificationEvent, TRUE);
    Tx->Submit = Submit;
    Tx->SubmitContext = SubmitContext;

    for (index = 0; index < IWAN_NT_TX_SLOTS; index++) {
        PIWAN_NT_TX_SLOT slot = &Tx->Slots[index];

        slot->Buffer = ExAllocatePool2(
            POOL_FLAG_NON_PAGED, IWAN_NT_TX_BUFFER_BYTES,
            IWAN_NT_TAG_TX_BUFFER);
        if (slot->Buffer == NULL) {
            IwanNtTxFinalize(Tx);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        slot->Mdl = IoAllocateMdl(
            slot->Buffer, IWAN_NT_TX_BUFFER_BYTES, FALSE, FALSE, NULL);
        if (slot->Mdl == NULL) {
            IwanNtTxFinalize(Tx);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        MmBuildMdlForNonPagedPool(slot->Mdl);

        slot->Irp = IoAllocateIrp(1, FALSE);
        if (slot->Irp == NULL) {
            IwanNtTxFinalize(Tx);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        slot->Owner = Tx;
        slot->Index = index;
        slot->InUse = FALSE;
    }

    Tx->SlotCount = IWAN_NT_TX_SLOTS;
    Tx->FreeCount = IWAN_NT_TX_SLOTS;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTxFinalize(
    _Inout_ PIWAN_NT_TX Tx
    )
{
    ULONG index;

    PAGED_CODE();

    if (Tx == NULL) {
        return;
    }

    for (index = 0; index < IWAN_NT_TX_SLOTS; index++) {
        PIWAN_NT_TX_SLOT slot = &Tx->Slots[index];

        if (slot->Irp != NULL) {
            IoFreeIrp(slot->Irp);
            slot->Irp = NULL;
        }
        if (slot->Mdl != NULL) {
            IoFreeMdl(slot->Mdl);
            slot->Mdl = NULL;
        }
        if (slot->Buffer != NULL) {
            ExFreePoolWithTag(slot->Buffer, IWAN_NT_TAG_TX_BUFFER);
            slot->Buffer = NULL;
        }
    }

    Tx->SlotCount = 0;
    Tx->FreeCount = 0;
    Tx->InFlight = 0;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IwanNtTxSetRemote(
    _Inout_ PIWAN_NT_TX Tx,
    _In_ const IWAN_NT_SOCKADDR *Remote
    )
{
    PAGED_CODE();

    if (Tx == NULL || Remote == NULL) {
        return;
    }

    Tx->Remote = *Remote;
    Tx->RemoteValid = TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
/*
 * Claim a free slot, or fail without touching the pool.
 *
 * IRQL: <= DISPATCH_LEVEL.
 * Returns NULL when every slot is in flight; that is backpressure, counted as
 * NoSlot, not an error worth waiting for.
 */
static PIWAN_NT_TX_SLOT
IwanNtTxClaimSlot(
    _Inout_ PIWAN_NT_TX Tx
    )
{
    PIWAN_NT_TX_SLOT slot = NULL;
    KIRQL oldIrql;
    ULONG index;

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    for (index = 0; index < Tx->SlotCount; index++) {
        if (!Tx->Slots[index].InUse) {
            slot = &Tx->Slots[index];
            slot->InUse = TRUE;
            Tx->FreeCount--;
            Tx->InFlight++;
            KeClearEvent(&Tx->IdleEvent);
            break;
        }
    }
    if (slot == NULL) {
        Tx->NoSlot++;
    }
    KeReleaseSpinLock(&Tx->Lock, oldIrql);

    return slot;
}

/*
 * Return a slot that was claimed but never submitted, and bump the counter
 * that explains why. The idle event is signalled outside the lock.
 */
static VOID
IwanNtTxAbandonSlot(
    _Inout_ PIWAN_NT_TX Tx,
    _Inout_ PIWAN_NT_TX_SLOT Slot,
    _In_ BOOLEAN CountAsSubmitError
    )
{
    KIRQL oldIrql;
    BOOLEAN signalIdle;

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    if (CountAsSubmitError) {
        Tx->SubmitErrors++;
    }
    signalIdle = IwanNtTxReleaseSlotLocked(Tx, Slot);
    KeReleaseSpinLock(&Tx->Lock, oldIrql);

    if (signalIdle) {
        KeSetEvent(&Tx->IdleEvent, IO_NO_INCREMENT, FALSE);
    }
}

/*
 * Submit an already-filled slot holding Length bytes.
 *
 * IRQL: <= DISPATCH_LEVEL.
 * The IRP stays associated with the slot for its whole life. IoReuseIrp gives
 * it a clean status and no cancellation routine, and the completion routine
 * claims ownership by returning MORE_PROCESSING_REQUIRED.
 */
static NTSTATUS
IwanNtTxSubmitSlot(
    _Inout_ PIWAN_NT_TX Tx,
    _Inout_ PIWAN_NT_TX_SLOT Slot,
    _In_ size_t Length
    )
{
    IWAN_NT_SOCKADDR remote;
    NTSTATUS status;
    KIRQL oldIrql;
    BOOLEAN remoteValid;

    if (Length == 0 || Length > IWAN_NT_TX_BUFFER_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    remoteValid = Tx->RemoteValid;
    remote = Tx->Remote;
    KeReleaseSpinLock(&Tx->Lock, oldIrql);
    if (remoteValid == FALSE) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    /*
     * Single-datagram submit: the slot stands alone as a one-entry chain, so
     * the same provider call and the same completion path serve both shapes.
     */
    Slot->List.Next = NULL;
    Slot->List.Buffer.Mdl = Slot->Mdl;
    Slot->List.Buffer.Offset = 0;
    Slot->List.Buffer.Length = Length;

    IoReuseIrp(Slot->Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(
        Slot->Irp, IwanNtTxComplete, Slot, TRUE, TRUE, TRUE);

    status = Tx->Submit(
        Tx->SubmitContext, &Slot->List, 1, &remote, Slot->Irp);

    if (!NT_SUCCESS(status) && status != STATUS_PENDING) {
        IwanNtTxAbandonSlot(Tx, Slot, TRUE);
        return status;
    }

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    Tx->Submitted++;
    Tx->Batches++;
    KeReleaseSpinLock(&Tx->Lock, oldIrql);

    return STATUS_SUCCESS;
}

/*
 * Submit a chain of already-filled slots under one IRP.
 *
 * IRQL: <= DISPATCH_LEVEL.
 * The chain hangs off Head->List.List; the completion routine walks it and
 * releases every slot, so a failure here has to unwind them itself.
 */
static NTSTATUS
IwanNtTxSubmitChain(
    _Inout_ PIWAN_NT_TX Tx,
    _Inout_ PIWAN_NT_TX_SLOT Head,
    _In_ ULONG Count
    )
{
    IWAN_NT_SOCKADDR remote;
    NTSTATUS status;
    KIRQL oldIrql;
    BOOLEAN remoteValid;

    if (Count == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    remoteValid = Tx->RemoteValid;
    remote = Tx->Remote;
    KeReleaseSpinLock(&Tx->Lock, oldIrql);
    if (remoteValid == FALSE) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    IoReuseIrp(Head->Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(
        Head->Irp, IwanNtTxComplete, Head, TRUE, TRUE, TRUE);

    status = Tx->Submit(
        Tx->SubmitContext, &Head->List, Count, &remote, Head->Irp);

    if (!NT_SUCCESS(status) && status != STATUS_PENDING) {
        /*
         * The completion routine never ran, so nothing has been released: walk
         * the chain here. AbandonSlot touches the counters, so it happens once
         * per slot inside the loop.
         */
        for (;;) {
            PWSK_BUF_LIST next = Head->List.Next;

            IwanNtTxAbandonSlot(Tx, Head, TRUE);
            if (next == NULL) {
                break;
            }
            Head = CONTAINING_RECORD(next, IWAN_NT_TX_SLOT, List);
        }
        return status;
    }

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    Tx->Submitted += Count;
    Tx->Batches++;
    KeReleaseSpinLock(&Tx->Lock, oldIrql);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
IwanNtTxSendBatch(
    _Inout_ PIWAN_NT_TX Tx,
    _In_ const IWAN_NT_FRAME_HEADER *Header,
    _In_reads_bytes_opt_(IWAN_NT_FRAME_KEY_LEN) const uint8_t *Key,
    _In_reads_(Count) const IWAN_NT_TX_ITEM *Items,
    _In_ ULONG Count,
    _Out_ PULONG Accepted
    )
{
    PIWAN_NT_TX_SLOT head = NULL;
    PIWAN_NT_TX_SLOT tail = NULL;
    ULONG taken = 0;
    ULONG index;

    if (Accepted != NULL) {
        *Accepted = 0;
    }
    if (Tx == NULL || Header == NULL || Items == NULL || Count == 0 ||
        Accepted == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0; index < Count; index++) {
        PIWAN_NT_TX_SLOT slot;
        IWAN_NT_FRAME_RESULT seal;
        size_t frameLength;
        size_t innerLength = Items[index].InnerLength;

        if (Items[index].Inner == NULL || innerLength == 0) {
            break;
        }
        frameLength = innerLength + IWAN_NT_FRAME_HDR_LEN;
        if (frameLength > IWAN_NT_TX_BUFFER_BYTES) {
            KIRQL oldIrql;

            KeAcquireSpinLock(&Tx->Lock, &oldIrql);
            Tx->TooLarge++;
            KeReleaseSpinLock(&Tx->Lock, oldIrql);
            break;
        }

        slot = IwanNtTxClaimSlot(Tx);
        if (slot == NULL) {
            break;
        }

        seal = IwanNtFrameSeal(
            (uint8_t *)slot->Buffer, IWAN_NT_TX_BUFFER_BYTES, Items[index].Inner,
            innerLength, Header, Key, &frameLength);
        if (seal != IwanNtFrameOk) {
            IwanNtTxAbandonSlot(Tx, slot, TRUE);
            break;
        }

        slot->List.Next = NULL;
        slot->List.Buffer.Mdl = slot->Mdl;
        slot->List.Buffer.Offset = 0;
        slot->List.Buffer.Length = frameLength;

        if (head == NULL) {
            head = slot;
        } else {
            tail->List.Next = &slot->List;
        }
        tail = slot;
        taken++;
    }

    if (taken == 0) {
        return (Count == 0) ? STATUS_INVALID_PARAMETER
                            : STATUS_INSUFFICIENT_RESOURCES;
    }
    UNREFERENCED_PARAMETER(tail);

    {
        NTSTATUS status = IwanNtTxSubmitChain(Tx, head, taken);

        if (!NT_SUCCESS(status)) {
            /* SubmitChain unwound every slot on the failing path. */
            return status;
        }
    }

    *Accepted = taken;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
IwanNtTxSend(
    _Inout_ PIWAN_NT_TX Tx,
    _In_ const IWAN_NT_FRAME_HEADER *Header,
    _In_reads_bytes_opt_(IWAN_NT_FRAME_KEY_LEN) const uint8_t *Key,
    _In_reads_bytes_(InnerLength) const uint8_t *Inner,
    _In_ size_t InnerLength
    )
{
    PIWAN_NT_TX_SLOT slot;
    IWAN_NT_FRAME_RESULT seal;
    size_t frameLength;
    NTSTATUS status;

    if (Tx == NULL || Header == NULL || Inner == NULL || InnerLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    frameLength = InnerLength + IWAN_NT_FRAME_HDR_LEN;
    if (frameLength > IWAN_NT_TX_BUFFER_BYTES) {
        KIRQL oldIrql;

        KeAcquireSpinLock(&Tx->Lock, &oldIrql);
        Tx->TooLarge++;
        KeReleaseSpinLock(&Tx->Lock, oldIrql);
        return STATUS_INVALID_PARAMETER;
    }

    slot = IwanNtTxClaimSlot(Tx);
    if (slot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    seal = IwanNtFrameSeal(
        (uint8_t *)slot->Buffer, IWAN_NT_TX_BUFFER_BYTES, Inner, InnerLength,
        Header, Key, &frameLength);
    if (seal != IwanNtFrameOk) {
        IwanNtTxAbandonSlot(Tx, slot, TRUE);
        return STATUS_INVALID_PARAMETER;
    }

    status = IwanNtTxSubmitSlot(Tx, slot, frameLength);
    if (!NT_SUCCESS(status)) {
        /* SubmitSlot already returned the slot on every failing path. */
        return status;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
IwanNtTxSendRaw(
    _Inout_ PIWAN_NT_TX Tx,
    _In_reads_bytes_(Length) const uint8_t *Payload,
    _In_ size_t Length
    )
{
    PIWAN_NT_TX_SLOT slot;

    if (Tx == NULL || Payload == NULL || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Length > IWAN_NT_TX_BUFFER_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    slot = IwanNtTxClaimSlot(Tx);
    if (slot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /*
     * Verbatim: the control plane assembles its own frame header, signature
     * and TLVs, so nothing is transformed here.
     */
    RtlCopyMemory(slot->Buffer, Payload, Length);

    return IwanNtTxSubmitSlot(Tx, slot, Length);
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IwanNtTxWaitIdle(
    _Inout_ PIWAN_NT_TX Tx,
    _In_ ULONG TimeoutMilliseconds
    )
{
    LARGE_INTEGER timeout;
    NTSTATUS status;

    PAGED_CODE();

    if (Tx == NULL) {
        return FALSE;
    }

    if (IwanNtTxInFlight(Tx) == 0) {
        return TRUE;
    }
    if (TimeoutMilliseconds == 0) {
        /* A zero timeout means "report the current state", not "wait forever". */
        return FALSE;
    }

    timeout.QuadPart = -((LONGLONG)TimeoutMilliseconds * 10000LL);
    status = KeWaitForSingleObject(
        &Tx->IdleEvent, Executive, KernelMode, FALSE, &timeout);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    /* The event is notification type, so re-check the counter it stands for. */
    return (BOOLEAN)(IwanNtTxInFlight(Tx) == 0);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
IwanNtTxInFlight(
    _In_ PIWAN_NT_TX Tx
    )
{
    KIRQL oldIrql;
    ULONG inFlight;

    if (Tx == NULL) {
        return 0;
    }

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    inFlight = Tx->InFlight;
    KeReleaseSpinLock(&Tx->Lock, oldIrql);
    return inFlight;
}
