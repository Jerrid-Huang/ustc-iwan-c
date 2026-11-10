#ifndef IWAN_NT_TYPES_H
#define IWAN_NT_TYPES_H

/*
 * Fixed-width types for code that builds both inside the driver and on the host.
 *
 * The WDK kernel include path has no <stdint.h> and no <stddef.h>: including them
 * from a kernel translation unit resolves to the user-mode MSVC CRT, which then
 * collides with the kernel headers already in the translation unit (vcruntime.h
 * redefines macros and _VCRUNTIME_DISABLED_WARNINGS is never defined, so the
 * pragma in vcruntime.h becomes a syntax error under /WX). wnidow's kernel
 * headers only provide the WDK names (UCHAR, ULONG, ...).
 *
 * So the kernel branch defines the C99 names itself, exactly as the ABI header of
 * the WFP driver does, and the host branch uses the real headers. C11 allows a
 * typedef to be redefined to the same type (6.7/3), so a future WDK that ships
 * these names does not break this.
 */
/*
 * The project defines IWAN_NT_KERNEL for every driver translation unit, so this
 * header can carry <ntddk.h> itself: a kernel-free header such as the frame
 * codec may then be included first without dragging in the user-mode CRT.
 *
 * The guard must not test _KERNEL_MODE: the driver toolset already defines that
 * on the command line, so testing it would skip <ntddk.h> entirely and leave
 * NULL, KIRQL, PMDL and the real SAL macros undefined.
 */
#if defined(IWAN_NT_KERNEL)
#include <ntddk.h>
#endif

#if defined(_KERNEL_MODE)

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;

/* size_t comes from the WDK itself. */

#else

#include <stddef.h>
#include <stdint.h>

#endif

#endif /* IWAN_NT_TYPES_H */
