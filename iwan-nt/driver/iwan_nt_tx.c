#include "iwan_nt_tx.h"

#include "iwan_nt_string.h"

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
static VOID
IwanNtTxStageSlot(
    _Inout_ PIWAN_NT_TX Tx,
    _Inout_ PIWAN_NT_TX_SLOT Slot
    );

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
     * release every slot on it.
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
            member->Staged = FALSE;
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
    Slot->Staged = FALSE;
    Tx->FreeCount++;
    Tx->InFlight--;
    return (BOOLEAN)(Tx->InFlight == 0);
}

/*
 * Submit a chain of already-filled slots under one IRP.
 *
 * IRQL: <= DISPATCH_LEVEL.
 * The chain hangs off Head->List.Next; the completion routine walks it and
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
    ULONG64 submitStart;

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

    submitStart = KeQueryInterruptTime();
    status = Tx->Submit(
        Tx->SubmitContext, &Head->List, Count, &remote, Head->Irp);

    if (!NT_SUCCESS(status) && status != STATUS_PENDING) {
        /*
         * The completion routine never ran, so nothing has been released: walk
         * the chain here and hand every slot back. A lost datagram is what a
         * tunnel can always do, so it is counted, not retried.
         */
        for (;;) {
            PWSK_BUF_LIST next = Head->List.Next;
            BOOLEAN signalIdle;

            KeAcquireSpinLock(&Tx->Lock, &oldIrql);
            Tx->SubmitErrors++;
            signalIdle = IwanNtTxReleaseSlotLocked(Tx, Head);
            KeReleaseSpinLock(&Tx->Lock, oldIrql);
            if (signalIdle) {
                KeSetEvent(&Tx->IdleEvent, IO_NO_INCREMENT, FALSE);
            }

            if (next == NULL) {
                break;
            }
            Head = CONTAINING_RECORD(next, IWAN_NT_TX_SLOT, List);
        }
        return status;
    }

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    Tx->Submitted += Count;
    Tx->CostSubmit += (ULONG64)(KeQueryInterruptTime() - submitStart);
    Tx->Batches++;
    if ((ULONG64)Count > Tx->MaxBatch) {
        Tx->MaxBatch = (ULONG64)Count;
    }
    KeReleaseSpinLock(&Tx->Lock, oldIrql);

    return STATUS_SUCCESS;
}

/*
 * Second-level queue primitives.
 *
 * A slot costs an MDL and an IRP, so the pool of them is the in-flight window.
 * Frames that arrive while that window is closed wait here as plain bytes.
 * Claim and release are O(1) over a free-index stack; the ring keeps order.
 */
PUCHAR
IwanNtTxClaimQueueBuffer(
    _Inout_ PIWAN_NT_TX Tx
    )
{
    PUCHAR buffer = NULL;
    KIRQL oldIrql;

    if (Tx == NULL || Tx->QueueStorage == NULL) {
        return NULL;
    }

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    if (Tx->FreeTop > 0) {
        ULONG index = Tx->FreeStack[--Tx->FreeTop];

        buffer = Tx->QueueStorage + (SIZE_T)index * IWAN_NT_TX_QUEUE_BYTES;
    }
    KeReleaseSpinLock(&Tx->Lock, oldIrql);
    return buffer;
}

void
IwanNtTxReleaseQueueBuffer(
    _Inout_ PIWAN_NT_TX Tx,
    _Inout_ PUCHAR Buffer
    )
{
    KIRQL oldIrql;
    SIZE_T offset;

    if (Tx == NULL || Buffer == NULL || Tx->QueueStorage == NULL) {
        return;
    }
    offset = (SIZE_T)(Buffer - Tx->QueueStorage);
    if (offset >= (SIZE_T)Tx->QueueCapacity * IWAN_NT_TX_QUEUE_BYTES) {
        return;
    }

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    if (Tx->FreeTop < Tx->QueueCapacity) {
        Tx->FreeStack[Tx->FreeTop++] = (ULONG)(offset / IWAN_NT_TX_QUEUE_BYTES);
    }
    KeReleaseSpinLock(&Tx->Lock, oldIrql);
}

BOOLEAN
IwanNtTxQueueFrame(
    _Inout_ PIWAN_NT_TX Tx,
    _Inout_ PUCHAR Buffer,
    _In_ ULONG Length
    )
{
    KIRQL oldIrql;
    BOOLEAN pushed = FALSE;

    if (Tx == NULL || Buffer == NULL || Length == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    if (Tx->RingCount < IWAN_NT_TX_QUEUE_MAX) {
        Tx->Ring[Tx->RingTail].Buffer = Buffer;
        Tx->Ring[Tx->RingTail].Length = Length;
        Tx->RingTail = (Tx->RingTail + 1) % (ULONG)IWAN_NT_TX_QUEUE_MAX;
        Tx->RingCount++;
        pushed = TRUE;
    } else {
        /* Full: the sender has to drop this one, and the drop is counted. */
        Tx->QueueDrops++;
    }
    KeReleaseSpinLock(&Tx->Lock, oldIrql);
    return pushed;
}

ULONG
IwanNtTxQueueDepth(
    _In_ PIWAN_NT_TX Tx
    )
{
    KIRQL oldIrql;
    ULONG depth;

    if (Tx == NULL) {
        return 0;
    }
    KeAcquireSpinLock((PKSPIN_LOCK)(PVOID)&Tx->Lock, &oldIrql);
    depth = Tx->RingCount;
    KeReleaseSpinLock((PKSPIN_LOCK)(PVOID)&Tx->Lock, oldIrql);
    return depth;
}

/*
 * Pop one queued frame. The caller owns the buffer and must either stage it
 * into a slot or release it back to the queue pool.
 */
static BOOLEAN
IwanNtTxDequeueFrame(
    _Inout_ PIWAN_NT_TX Tx,
    _Out_ PUCHAR *Buffer,
    _Out_ PULONG Length
    )
{
    KIRQL oldIrql;
    BOOLEAN popped = FALSE;

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    if (Tx->RingCount != 0) {
        *Buffer = Tx->Ring[Tx->RingHead].Buffer;
        *Length = Tx->Ring[Tx->RingHead].Length;
        Tx->RingHead = (Tx->RingHead + 1) % (ULONG)IWAN_NT_TX_QUEUE_MAX;
        Tx->RingCount--;
        popped = TRUE;
    }
    KeReleaseSpinLock(&Tx->Lock, oldIrql);
    return popped;
}

/*
 * Move every queued frame that a free slot can take into a slot and stage it.
 * Called from the drain path, so the provider keeps seeing full batches even
 * when the frames spent time waiting in the second level.
 */
static VOID
IwanNtTxDrainQueued(
    _Inout_ PIWAN_NT_TX Tx
    )
{
    for (;;) {
        PIWAN_NT_TX_SLOT slot;
        PUCHAR buffer = NULL;
        ULONG length = 0;

        slot = IwanNtTxClaimSlot(Tx);
        if (slot == NULL) {
            return;
        }
        if (!IwanNtTxDequeueFrame(Tx, &buffer, &length)) {
            IwanNtTxAbandonSlot(Tx, slot, FALSE);
            return;
        }
        RtlCopyMemory(slot->Buffer, buffer, length);
        slot->List.Buffer.Mdl = slot->Mdl;
        slot->List.Buffer.Offset = 0;
        slot->List.Buffer.Length = length;
        IwanNtTxStageSlot(Tx, slot);
        IwanNtTxReleaseQueueBuffer(Tx, buffer);
    }
}

/*
 * Detach up to Max slots from the head of the pending chain. Returns NULL when
 * nothing is staged. The caller owns the returned chain and must submit or
 * abandon it.
 */
static PIWAN_NT_TX_SLOT
IwanNtTxTakePending(
    _Inout_ PIWAN_NT_TX Tx,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
{
    PIWAN_NT_TX_SLOT head;
    PIWAN_NT_TX_SLOT slot;
    ULONG taken = 0;
    KIRQL oldIrql;

    *Count = 0;

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    head = Tx->PendingHead;
    slot = head;
    while (slot != NULL) {
        PWSK_BUF_LIST nextList = slot->List.Next;
        PIWAN_NT_TX_SLOT next = (nextList == NULL)
                                    ? NULL
                                    : CONTAINING_RECORD(
                                          nextList, IWAN_NT_TX_SLOT, List);

        slot->Staged = FALSE;
        taken++;
        if (taken == Max || next == NULL) {
            /* Detached chain ends here; whatever follows stays staged. */
            slot->List.Next = NULL;
            Tx->PendingHead = next;
            if (next == NULL) {
                Tx->PendingTail = NULL;
            }
            break;
        }
        slot = next;
    }
    Tx->PendingCount -= taken;
    KeReleaseSpinLock(&Tx->Lock, oldIrql);

    *Count = taken;
    return head;
}

/*
 * Submit everything that is staged, one provider call per IWAN_NT_TX_MAX_CHAIN
 * frames.
 *
 * IRQL: <= DISPATCH_LEVEL.
 * A submit that fails abandons its own slots, so a failure here never leaves
 * the chain hanging.
 */
static VOID
IwanNtTxDrain(
    _Inout_ PIWAN_NT_TX Tx
    )
{
    for (;;) {
        PIWAN_NT_TX_SLOT head;
        ULONG count = 0;

        /* Frames that waited in the second level go first: they are the oldest. */
        IwanNtTxDrainQueued(Tx);

        head = IwanNtTxTakePending(Tx, IWAN_NT_TX_MAX_CHAIN, &count);
        if (head == NULL || count == 0) {
            return;
        }
        (void)IwanNtTxSubmitChain(Tx, head, count);
    }
}

/*
 * The drain thread: wake at least once per drain interval and submit whatever
 * has accumulated. It exists so that the NDIS send call never waits on the
 * provider and so that the provider sees batches instead of single frames.
 */
static VOID
IwanNtTxDrainThread(
    _In_ PVOID Context
    )
{
    PIWAN_NT_TX tx = (PIWAN_NT_TX)Context;
    LARGE_INTEGER timeout;

    timeout.QuadPart = -((LONGLONG)IWAN_NT_TX_DRAIN_INTERVAL_MS * 10000LL);

    for (;;) {
        KeWaitForSingleObject(
            &tx->DrainEvent, Executive, KernelMode, FALSE, &timeout);
        KeClearEvent(&tx->DrainEvent);

        if (tx->DrainStop) {
            break;
        }
        IwanNtTxDrain(tx);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
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
    NTSTATUS status;
    HANDLE handle = NULL;

    PAGED_CODE();

    if (Tx == NULL || Submit == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Tx, sizeof(*Tx));
    KeInitializeSpinLock(&Tx->Lock);
    KeInitializeEvent(&Tx->IdleEvent, NotificationEvent, TRUE);
    KeInitializeEvent(&Tx->DrainEvent, NotificationEvent, FALSE);
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
        slot->Staged = FALSE;
    }

    Tx->SlotCount = IWAN_NT_TX_SLOTS;
    Tx->FreeCount = IWAN_NT_TX_SLOTS;

    /*
     * Second level: 1024 frame buffers of 2 KB (2 MB) plus the free-index
     * stack. It is optional on purpose: if the allocation fails the tunnel
     * still runs, it just falls back to dropping when the in-flight window
     * closes.
     */
    Tx->QueueStorage = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, IWAN_NT_TX_QUEUE_MAX * IWAN_NT_TX_QUEUE_BYTES,
        IWAN_NT_TAG_TX_BUFFER);
    Tx->FreeStack = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, IWAN_NT_TX_QUEUE_MAX * sizeof(ULONG),
        IWAN_NT_TAG_TX_BUFFER);
    if (Tx->QueueStorage == NULL || Tx->FreeStack == NULL) {
        if (Tx->QueueStorage != NULL) {
            ExFreePoolWithTag(Tx->QueueStorage, IWAN_NT_TAG_TX_BUFFER);
            Tx->QueueStorage = NULL;
        }
        if (Tx->FreeStack != NULL) {
            ExFreePoolWithTag(Tx->FreeStack, IWAN_NT_TAG_TX_BUFFER);
            Tx->FreeStack = NULL;
        }
        Tx->QueueCapacity = 0;
    } else {
        ULONG index2;

        Tx->QueueCapacity = IWAN_NT_TX_QUEUE_MAX;
        for (index2 = 0; index2 < IWAN_NT_TX_QUEUE_MAX; index2++) {
            Tx->FreeStack[index2] = (IWAN_NT_TX_QUEUE_MAX - 1) - index2;
        }
        Tx->FreeTop = IWAN_NT_TX_QUEUE_MAX;
    }

    /*
     * The drain thread is created last: Finalize treats DrainRunning as "the
     * thread object must be closed", so nothing may set it before the thread
     * exists.
     */
    status = PsCreateSystemThread(
        &handle, THREAD_ALL_ACCESS, NULL, NULL, NULL,
        IwanNtTxDrainThread, Tx);
    if (!NT_SUCCESS(status)) {
        IwanNtTxFinalize(Tx);
        return status;
    }

    Tx->DrainRunning = TRUE;
    status = ObReferenceObjectByHandle(
        handle, THREAD_ALL_ACCESS, NULL, KernelMode, &Tx->DrainThread, NULL);
    ZwClose(handle);
    if (!NT_SUCCESS(status)) {
        Tx->DrainRunning = FALSE;
        IwanNtTxFinalize(Tx);
        return status;
    }

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

    /*
     * Stop the drain thread before anything else: it reads the slot array, so
     * freeing a slot under it would be a use after free.
     */
    if (Tx->DrainRunning) {
        Tx->DrainStop = TRUE;
        KeSetEvent(&Tx->DrainEvent, IO_NO_INCREMENT, FALSE);
        if (Tx->DrainThread != NULL) {
            KeWaitForSingleObject(
                Tx->DrainThread, Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(Tx->DrainThread);
            Tx->DrainThread = NULL;
        }
        Tx->DrainRunning = FALSE;
    }

    /* Nothing can stage any more, so what is left may be submitted now. */
    IwanNtTxDrain(Tx);
    (void)IwanNtTxWaitIdle(Tx, 2000);

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

    if (Tx->QueueStorage != NULL) {
        ExFreePoolWithTag(Tx->QueueStorage, IWAN_NT_TAG_TX_BUFFER);
        Tx->QueueStorage = NULL;
    }
    if (Tx->FreeStack != NULL) {
        ExFreePoolWithTag(Tx->FreeStack, IWAN_NT_TAG_TX_BUFFER);
        Tx->FreeStack = NULL;
    }
    Tx->QueueCapacity = 0;
    Tx->FreeTop = 0;
    Tx->RingHead = 0;
    Tx->RingTail = 0;
    Tx->RingCount = 0;

    Tx->SlotCount = 0;
    Tx->FreeCount = 0;
    Tx->InFlight = 0;
    Tx->PendingHead = NULL;
    Tx->PendingTail = NULL;
    Tx->PendingCount = 0;
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
 * Returns NULL when every slot is in flight or staged; that is backpressure,
 * counted as NoSlot, not an error worth waiting for.
 */
PIWAN_NT_TX_SLOT
IwanNtTxClaimSlot(
    _Inout_ PIWAN_NT_TX Tx
    )
{
    PIWAN_NT_TX_SLOT slot = NULL;
    KIRQL oldIrql;
    ULONG index;
    ULONGLONG lockStart;

    /*
     * Time spent waiting for the pool lock: if this grows with the number of
     * sending threads, the global pool is the serializer and the next step is a
     * per-CPU pool rather than a faster one.
     */
    lockStart = KeQueryInterruptTime();
    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    Tx->CostLock += (KeQueryInterruptTime() - lockStart);
    Tx->CostLockCount++;
    for (index = 0; index < Tx->SlotCount; index++) {
        if (!Tx->Slots[index].InUse) {
            slot = &Tx->Slots[index];
            slot->InUse = TRUE;
            slot->Staged = FALSE;
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
VOID
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

VOID
IwanNtTxAbandonItems(
    _Inout_ PIWAN_NT_TX Tx,
    _In_reads_(Count) const IWAN_NT_TX_ITEM *Items,
    _In_ ULONG Count
    )
{
    ULONG index;

    if (Tx == NULL || Items == NULL) {
        return;
    }
    for (index = 0; index < Count; index++) {
        if (Items[index].Slot != NULL) {
            IwanNtTxAbandonSlot(Tx, Items[index].Slot, TRUE);
        } else if (Items[index].Queued != NULL) {
            IwanNtTxReleaseQueueBuffer(Tx, Items[index].Queued);
        }
    }
}

/*
 * Submit an already-filled slot holding Length bytes, without batching.
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
    if (Tx->MaxBatch < 1) {
        Tx->MaxBatch = 1;
    }
    KeReleaseSpinLock(&Tx->Lock, oldIrql);

    return STATUS_SUCCESS;
}

/*
 * Hang a filled slot on the pending chain. Submitting is the caller's job, once
 * per batch (IwanNtTxSendBatch), so this is only a list splice under the lock.
 *
 * IRQL: <= DISPATCH_LEVEL.
 */
static VOID
IwanNtTxStageSlot(
    _Inout_ PIWAN_NT_TX Tx,
    _Inout_ PIWAN_NT_TX_SLOT Slot
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    Slot->List.Next = NULL;
    Slot->Staged = TRUE;
    if (Tx->PendingTail == NULL) {
        Tx->PendingHead = Slot;
    } else {
        Tx->PendingTail->List.Next = &Slot->List;
    }
    Tx->PendingTail = Slot;
    Tx->PendingCount++;
    KeReleaseSpinLock(&Tx->Lock, oldIrql);
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
    ULONG staged = 0;
    ULONG index;
    ULONG64 started;

    if (Accepted != NULL) {
        *Accepted = 0;
    }
    if (Tx == NULL || Header == NULL || Items == NULL || Count == 0 ||
        Accepted == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    started = KeQueryInterruptTime();
    for (index = 0; index < Count; index++) {
        PIWAN_NT_TX_SLOT slot = Items[index].Slot;
        PUCHAR queued = Items[index].Queued;
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

        if (queued != NULL) {
            /*
             * The caller ran out of slots and copied the packet into a frame
             * buffer instead. Seal it there and park it in the second level;
             * the drain path moves it into a slot when one frees. Nothing is
             * dropped just because the in-flight window was closed.
             */
            seal = IwanNtFrameSealInPlace(
                queued, IWAN_NT_TX_QUEUE_BYTES, innerLength, Header, Key,
                &frameLength);
            if (seal != IwanNtFrameOk ||
                !IwanNtTxQueueFrame(Tx, queued, (ULONG)frameLength)) {
                IwanNtTxReleaseQueueBuffer(Tx, queued);
                break;
            }
            staged++;
            continue;
        }

        if (slot == NULL) {
            slot = IwanNtTxClaimSlot(Tx);
            if (slot == NULL) {
                /*
                 * No slot and the caller did not stage a frame buffer: count
                 * the packet as rejected instead of letting the stack drop it
                 * silently (that gap hid a third of the traffic on 2026-11-17).
                 */
                KIRQL dropIrql;

                KeAcquireSpinLock(&Tx->Lock, &dropIrql);
                Tx->NoSlot++;
                KeReleaseSpinLock(&Tx->Lock, dropIrql);
                break;
            }

            /*
             * Payload still in the caller's memory: copy and transform in one
             * pass into the slot. The packet is free to go once this returns,
             * which is what lets the miniport complete the NBL immediately.
             */
            seal = IwanNtFrameSeal(
                (uint8_t *)slot->Buffer, IWAN_NT_TX_BUFFER_BYTES,
                Items[index].Inner, innerLength, Header, Key, &frameLength);
        } else {
            /*
             * The caller already copied the payload straight into the slot
             * body, one memory pass and no shared staging buffer, so the whole
             * send path needs no adapter-wide lock. Seal it where it lies.
             */
            seal = IwanNtFrameSealInPlace(
                (uint8_t *)slot->Buffer, IWAN_NT_TX_BUFFER_BYTES,
                innerLength, Header, Key, &frameLength);
        }
        if (seal != IwanNtFrameOk) {
            IwanNtTxAbandonSlot(Tx, slot, TRUE);
            break;
        }

        slot->List.Buffer.Mdl = slot->Mdl;
        slot->List.Buffer.Offset = 0;
        slot->List.Buffer.Length = frameLength;

        IwanNtTxStageSlot(Tx, slot);
        staged++;
    }

    if (staged == 0) {
        return (Count == 0) ? STATUS_INVALID_PARAMETER
                            : STATUS_INSUFFICIENT_RESOURCES;
    }

    /*
     * Submit from the caller, once per batch, the way WireGuardNT does: the
     * provider call is asynchronous (it returns STATUS_PENDING with our IRP),
     * so the send path only pays for the enqueue, not for the wire. Waking the
     * drain thread per packet cost 10-30us per packet and capped the tunnel at
     * ~33k pps regardless of the bearer, as measured 2026-11-17.
     */
    {
        KIRQL costIrql;

        KeAcquireSpinLock(&Tx->Lock, &costIrql);
        Tx->CostSeal += (ULONG64)(KeQueryInterruptTime() - started);
        Tx->CostCount += staged;
        KeReleaseSpinLock(&Tx->Lock, costIrql);
    }

    /*
     * One provider call costs 11-16us while staging costs 1.7us, so only pay
     * for a call once the queue actually holds FRAMES_PER_CALL frames; the
     * drain takes the whole queue, not just these. Gating on the queue depth
     * instead of a call counter is what the cost model asks for: a counter
     * fires on the wrong number of frames whenever a flush carries more than
     * one packet. The 1 ms drain thread keeps a lone frame moving.
     */
    if (IwanNtTxPending(Tx) + IwanNtTxQueueDepth(Tx) >=
        IWAN_NT_TX_FRAMES_PER_CALL) {
        IwanNtTxDrain(Tx);
    }

    *Accepted = staged;
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
     * and TLVs, so nothing is transformed here. Control frames skip the drain
     * thread: a handshake must not wait behind data.
     */
    RtlCopyMemory(slot->Buffer, Payload, Length);

    return IwanNtTxSubmitSlot(Tx, slot, Length);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
IwanNtTxAddEnterCost(
    _In_ PIWAN_NT_TX Tx,
    _In_ uint64_t Ticks,
    _In_ uint64_t Count
    )
{
    KIRQL oldIrql;

    if (Tx == NULL) {
        return;
    }
    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    Tx->CostEnter += Ticks;
    Tx->CostEnterCount += Count;
    KeReleaseSpinLock(&Tx->Lock, oldIrql);
}

void
IwanNtTxGetCost(
    _In_ PIWAN_NT_TX Tx,
    _Out_ uint64_t *Seal,
    _Out_ uint64_t *Submit,
    _Out_ uint64_t *Count,
    _Out_ uint64_t *Enter,
    _Out_ uint64_t *EnterCount,
    _Out_ uint64_t *LockWait,
    _Out_ uint64_t *LockCount
    )
{
    KIRQL oldIrql;

    if (Tx == NULL || Seal == NULL || Submit == NULL || Count == NULL ||
        Enter == NULL || EnterCount == NULL || LockWait == NULL ||
        LockCount == NULL) {
        return;
    }
    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    *Seal = Tx->CostSeal;
    *Submit = Tx->CostSubmit;
    *Count = Tx->CostCount;
    *Enter = Tx->CostEnter;
    *EnterCount = Tx->CostEnterCount;
    *LockWait = Tx->CostLock;
    *LockCount = Tx->CostLockCount;
    KeReleaseSpinLock(&Tx->Lock, oldIrql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
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

    /*
     * Staged frames are the caller's responsibility too: reporting idle while a
     * chain waits for the drain thread would let the caller close the socket
     * they still need.
     */
    if (IwanNtTxPending(Tx) != 0) {
        IwanNtTxDrain(Tx);
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

    /* The event is notification type, so re-check the counters it stands for. */
    return (BOOLEAN)(IwanNtTxInFlight(Tx) == 0 && IwanNtTxPending(Tx) == 0);
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

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
IwanNtTxPending(
    _In_ PIWAN_NT_TX Tx
    )
{
    KIRQL oldIrql;
    ULONG pending;

    if (Tx == NULL) {
        return 0;
    }

    KeAcquireSpinLock(&Tx->Lock, &oldIrql);
    pending = Tx->PendingCount;
    KeReleaseSpinLock(&Tx->Lock, oldIrql);
    return pending;
}
