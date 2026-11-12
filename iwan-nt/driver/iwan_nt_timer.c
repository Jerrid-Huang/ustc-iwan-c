/* SPDX-License-Identifier: MIT
 *
 * Kernel timer with a DPC callback. See iwan_nt_timer.h for the contract.
 */

#include "iwan_nt_timer.h"

#include "iwan_nt_string.h"

#if defined(IWAN_NT_KERNEL)

/*
 * Coalescing tolerances: the peer needs a two-second keepalive and a
 * two-second OPEN retransmit, so a few hundred milliseconds of slack costs
 * nothing and lets the kernel batch wakeups with other timers.
 */
#define IWAN_NT_TIMER_COALESCENCE_MS 320UL

static VOID IwanNtTimerDpc(KDPC *Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

_Use_decl_annotations_
static VOID
IwanNtTimerDpc(
    KDPC *Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
    )
{
    PIWAN_NT_TIMER timer = CONTAINING_RECORD(Dpc, IWAN_NT_TIMER, Dpc);
    PIWAN_NT_TIMER_CALLBACK callback = (PIWAN_NT_TIMER_CALLBACK)DeferredContext;

    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    /*
     * Clear Pending before the callback runs, so a callback that re-arms itself
     * is not mistaken for a still-outstanding expiration by a cancel.
     */
    InterlockedExchange(&timer->Pending, 0);
    InterlockedIncrement(&timer->Fired);

    if (callback != NULL) {
        callback(timer);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
IwanNtTimerInitialize(
    _Out_ PIWAN_NT_TIMER Timer,
    _In_ PIWAN_NT_TIMER_CALLBACK Callback
    )
{
    IwanNtMemZero(Timer, sizeof(*Timer));
    Timer->Callback = Callback;
    InterlockedExchange(&Timer->Pending, 0);
    InterlockedExchange(&Timer->Fired, 0);
    KeInitializeTimer(&Timer->Timer);
    KeInitializeDpc(&Timer->Dpc, IwanNtTimerDpc, (PVOID)Callback);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
IwanNtTimerArm(
    _Inout_ PIWAN_NT_TIMER Timer,
    _In_ ULONG DueMs
    )
{
    LARGE_INTEGER due;

    /*
     * Negative counts are relative to now, which is what we want: the caller
     * reasons in "how long from here", not in absolute interrupt time.
     */
    due.QuadPart = -((LONGLONG)DueMs * 10000);

    InterlockedExchange(&Timer->Pending, 1);
    KeSetCoalescableTimer(
        &Timer->Timer, due, 0, IWAN_NT_TIMER_COALESCENCE_MS, &Timer->Dpc);
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IwanNtTimerCancel(
    _Inout_ PIWAN_NT_TIMER Timer
    )
{
    PAGED_CODE();

    if (!KeCancelTimer(&Timer->Timer)) {
        /* The timer was not queued, so no callback can be on its way. */
        InterlockedExchange(&Timer->Pending, 0);
        return FALSE;
    }

    /*
     * KeCancelTimer returned TRUE: it de-queued the timer, but a DPC that
     * already started on another processor keeps running. Flush those before
     * telling the caller it is safe to free.
     */
    KeFlushQueuedDpcs();
    InterlockedExchange(&Timer->Pending, 0);
    return FALSE;
}

#endif /* IWAN_NT_KERNEL */
