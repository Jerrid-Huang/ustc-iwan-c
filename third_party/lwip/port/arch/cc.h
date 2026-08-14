/*
 * iWAN lwIP port: compiler/platform abstraction (arch/cc.h).
 *
 * lwIP's arch.h provides sensible GCC/clang defaults (packed structs, the
 * stdint-based u8_t..u32_t typedefs, the X8_F/U16_F printf formatters) and
 * only requires the port to supply arch/cc.h. This file supplies the two
 * things that are genuinely target-dependent here:
 *
 *   - BYTE_ORDER: arch.h defaults to LITTLE_ENDIAN, which is wrong for the
 *     big-endian cross targets the CI builds (linux-s390x). Detect it from
 *     the compiler's predefined macros instead.
 *
 *   - LWIP_RAND(): lwIP seeds its ISN (tcp_next_iss) and ephemeral ports
 *     from LWIP_RAND(). glibc rand() is a weak 31-bit LCG, and the project
 *     already has rand_u32() (full 32-bit, CSPRNG-seeded) — a predictable
 *     ISN would let an observer forge RST/ACK segments against a reused
 *     4-tuple, the exact issue the native netstack documents. Delegate to
 *     rand_u32(); it lives in iwan_core (util.c), which links lwip, so the
 *     symbol resolves without a shim.
 */
#ifndef IWAN_LWIP_CC_H
#define IWAN_LWIP_CC_H

#include <stdint.h>

/* arch.h defines LITTLE_ENDIAN (1234) / BIG_ENDIAN (4321) before including
 * this file. On POSIX, <netinet/in.h> -> <endian.h> already defines BYTE_ORDER
 * to the same 1234/4321 convention, so honour it when present (the bridge TU
 * includes both); otherwise derive it from the compiler's predefined macros. */
#if !defined(BYTE_ORDER)
#  if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)
#    if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#      define BYTE_ORDER BIG_ENDIAN
#    else
#      define BYTE_ORDER LITTLE_ENDIAN
#    endif
#  elif defined(__BIG_ENDIAN__) || defined(_BIG_ENDIAN) || defined(__BIG_ENDIAN)
#    define BYTE_ORDER BIG_ENDIAN
#  else
#    define BYTE_ORDER LITTLE_ENDIAN
#  endif
#endif

/* Full-width secure random for ISNs / ephemeral ports (project's util.c). */
uint32_t rand_u32(void);
#define LWIP_RAND() ((uint32_t)rand_u32())

#endif /* IWAN_LWIP_CC_H */
