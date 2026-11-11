#ifndef IWAN_NT_STRING_H
#define IWAN_NT_STRING_H

#include "iwan_nt_types.h"

/*
 * The few byte helpers the protocol code needs.
 *
 * Including <string.h> in a kernel translation unit drags the user-mode CRT
 * back in, which is the same trap that <stdint.h> set earlier. These are
 * one-liners, and the kernel branch maps them onto the routines the kernel
 * already exports.
 */

#if defined(IWAN_NT_KERNEL)

#define IwanNtMemCopy(Destination, Source, Length) \
    RtlCopyMemory((Destination), (Source), (Length))
#define IwanNtMemZero(Destination, Length) \
    RtlZeroMemory((Destination), (Length))

static __inline size_t
IwanNtStringLength(const char *Text)
{
    size_t length = 0;

    if (Text == NULL) {
        return 0;
    }
    while (Text[length] != '\0') {
        length++;
    }
    return length;
}

#else

#include <string.h>

#define IwanNtMemCopy(Destination, Source, Length) \
    memcpy((Destination), (Source), (Length))
#define IwanNtMemZero(Destination, Length) memset((Destination), 0, (Length))

static __inline size_t
IwanNtStringLength(const char *Text)
{
    return (Text == NULL) ? 0u : strlen(Text);
}

#endif

#endif
