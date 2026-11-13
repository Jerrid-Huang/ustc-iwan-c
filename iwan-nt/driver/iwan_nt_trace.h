#ifndef IWAN_NT_TRACE_H
#define IWAN_NT_TRACE_H

#include "iwan_nt_types.h"

/*
 * Boot-time diagnostics. A driver that hangs before it can be talked to
 * otherwise leaves nothing behind: no bugcheck, no log, no control device.
 * Each call records the stage number under the service parameters key, so the
 * last value written names the step that never returned.
 */
VOID IwanNtTrace(_In_ ULONG Stage);

#define IWAN_NT_STAGE_ENTRY 1u
#define IWAN_NT_STAGE_MINIPORT 2u
#define IWAN_NT_STAGE_CONTROL 3u
#define IWAN_NT_STAGE_ENTRY_DONE 4u
#define IWAN_NT_STAGE_INIT_ENTER 10u
#define IWAN_NT_STAGE_TRANSPORT 11u
#define IWAN_NT_STAGE_RXPOOL 12u
#define IWAN_NT_STAGE_ATTACH 13u
#define IWAN_NT_STAGE_ATTRIBUTES 14u
#define IWAN_NT_STAGE_INIT_DONE 15u
#define IWAN_NT_STAGE_RESTART_ENTER 20u
#define IWAN_NT_STAGE_START 21u
#define IWAN_NT_STAGE_RESTART_DONE 22u

#endif
