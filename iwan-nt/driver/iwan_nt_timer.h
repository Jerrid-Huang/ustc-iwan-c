/* SPDX-License-Identifier: MIT
 *
 * A one-shot kernel timer with a DPC callback.
 *
 * The peer has to tick on its own: retransmit OPEN while the session is down and
 * send a keepalive every two seconds once it is up. Without a timer that only
 * happens when a datagram arrives, which is exactly the case a keepalive exists
 * to cover.
 *
 * The shape follows the same idea WireGuard NT uses for its timers: one KDPC
 * paired with one KTIMER, a Pending flag so a cancel can tell whether the
 * callback may still run, and coalescable expirations so the timer is cheap on
 * an idle machine. The implementation here is our own.
 */

#ifndef IWAN_NT_TIMER_H
#define IWAN_NT_TIMER_H

#include "iwan_nt_types.h"

#if defined(IWAN_NT_KERNEL)
#include <ntddk.h>
#endif

struct _IWAN_NT_TIMER;

typedef _Function_class_(IWAN_NT_TIMER_CALLBACK)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
IWAN_NT_TIMER_CALLBACK(
    _In_ struct _IWAN_NT_TIMER *Timer
    );

typedef IWAN_NT_TIMER_CALLBACK *PIWAN_NT_TIMER_CALLBACK;

/*
 * The callback fires at DISPATCH_LEVEL, so it may only use DDIs that are legal
 * there: no allocation, no blocking waits, no PASSIVE-only calls.
 */
typedef struct _IWAN_NT_TIMER {
    KDPC Dpc;
    KTIMER Timer;
    volatile LONG Pending;
    volatile LONG Fired;
    PIWAN_NT_TIMER_CALLBACK Callback;
} IWAN_NT_TIMER, *PIWAN_NT_TIMER;

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
IwanNtTimerInitialize(
    _Out_ PIWAN_NT_TIMER Timer,
    _In_ PIWAN_NT_TIMER_CALLBACK Callback
    );

/*
 * Arm the timer to fire once, DueMs milliseconds from now, replacing any earlier
 * expiration. Safe to call from the callback itself to re-arm.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
IwanNtTimerArm(
    _Inout_ PIWAN_NT_TIMER Timer,
    _In_ ULONG DueMs
    );

/*
 * Cancel a pending expiration.
 *
 * Returns TRUE when the callback may still be running or queued, which means the
 * caller must not free anything the callback touches until it settles. Returns
 * FALSE when the timer is known to be quiet. Call at PASSIVE_LEVEL before
 * releasing the object that owns the timer.
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IwanNtTimerCancel(
    _Inout_ PIWAN_NT_TIMER Timer
    );

#endif /* IWAN_NT_TIMER_H */
