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
     */
    KeAcquireSpinLock(&tx->Lock, &oldIrql);
    slot->InUse = FALSE;
    tx->FreeCount++;
    tx->InFlight--;
    tx->Completed++;
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
    _In_ const SOCKADDR_IN *Remote
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
    KIRQL oldIrql;
    SOCKADDR_IN remote;
    NTSTATUS status;
    size_t frameLength;
    ULONG index;
    BOOLEAN signalIdle;

    if (Tx == NULL || Header == NULL || Inner == NULL || InnerLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Claim a slot. Scanning a fixed array costs at most 32 iterations and
     * keeps the allocation order deterministic, which makes leaks obvious.
     */
    slot = NULL;
    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    if (Tx->RemoteValid == FALSE) {
        KeReleaseSpinLock(&Tx->Lock, oldIrql);
        return STATUS_INVALID_DEVICE_STATE;
    }
    remote = Tx->Remote;
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
        KeReleaseSpinLock(&Tx->Lock, oldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KeReleaseSpinLock(&Tx->Lock, oldIrql);

    frameLength = InnerLength + IWAN_NT_FRAME_HDR_LEN;
    if (frameLength > IWAN_NT_TX_BUFFER_BYTES) {
        KeAcquireSpinLock(&Tx->Lock, &oldIrql);
        Tx->TooLarge++;
        signalIdle = IwanNtTxReleaseSlotLocked(Tx, slot);
        KeReleaseSpinLock(&Tx->Lock, oldIrql);
        if (signalIdle) {
            KeSetEvent(&Tx->IdleEvent, IO_NO_INCREMENT, FALSE);
        }
        return STATUS_INVALID_PARAMETER;
    }

    seal = IwanNtFrameSeal(
        (uint8_t *)slot->Buffer, IWAN_NT_TX_BUFFER_BYTES, Inner, InnerLength,
        Header, Key, &frameLength);
    if (seal != IwanNtFrameOk) {
        KeAcquireSpinLock(&Tx->Lock, &oldIrql);
        Tx->SubmitErrors++;
        signalIdle = IwanNtTxReleaseSlotLocked(Tx, slot);
        KeReleaseSpinLock(&Tx->Lock, oldIrql);
        if (signalIdle) {
            KeSetEvent(&Tx->IdleEvent, IO_NO_INCREMENT, FALSE);
        }
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * The IRP stays associated with the slot for its whole life. IoReuseIrp
     * gives it a clean status and no cancellation routine, and the completion
     * routine claims ownership by returning MORE_PROCESSING_REQUIRED.
     */
    IoReuseIrp(slot->Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(
        slot->Irp, IwanNtTxComplete, slot, TRUE, TRUE, TRUE);

    status = Tx->Submit(
        Tx->SubmitContext, slot->Mdl, (ULONG)frameLength, &remote, slot->Irp);

    if (!NT_SUCCESS(status) && status != STATUS_PENDING) {
        KeAcquireSpinLock(&Tx->Lock, &oldIrql);
        Tx->SubmitErrors++;
        signalIdle = IwanNtTxReleaseSlotLocked(Tx, slot);
        KeReleaseSpinLock(&Tx->Lock, oldIrql);
        if (signalIdle) {
            KeSetEvent(&Tx->IdleEvent, IO_NO_INCREMENT, FALSE);
        }
        return status;
    }

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    Tx->Submitted++;
    KeReleaseSpinLock(&Tx->Lock, oldIrql);

    return STATUS_SUCCESS;
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
