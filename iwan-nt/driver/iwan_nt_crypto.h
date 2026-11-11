#ifndef IWAN_NT_CRYPTO_H
#define IWAN_NT_CRYPTO_H

/*
 * The two primitives the iWAN handshake needs, written here so the user-mode
 * side of iWAN NT has no third-party dependency.
 *
 * MD5 is used twice by the protocol: as the frame signature (MD5 over the 8-byte
 * frame header plus the ASCII bytes "mw") and as the session key seed
 * (MD5(user || password), first 8 bytes are the XOR key). AES-128-ECB over one
 * block protects the password in the OPEN message.
 *
 * Both are legacy primitives that the deployed protocol cannot change. They are
 * implemented for interoperability, not for new designs.
 */

#include "iwan_nt_types.h"

/*
 * These headers are user-mode only, so they take the C runtime integer types
 * directly instead of the driver's kernel-aware wrapper. Including that wrapper
 * here would make the user build depend on the driver include path for no gain.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _IWAN_NT_MD5_CTX {
    uint32_t State[4];
    uint64_t Bytes;
    uint8_t Buffer[64];
} IWAN_NT_MD5_CTX;

void
IwanNtMd5Initialize(
    IWAN_NT_MD5_CTX *Context
    );

void
IwanNtMd5Update(
    IWAN_NT_MD5_CTX *Context,
    const void *Data,
    size_t Length
    );

void
IwanNtMd5Finalize(
    IWAN_NT_MD5_CTX *Context,
    uint8_t Digest[16]
    );

/* One-shot form of the three calls above. */
void
IwanNtMd5(
    const void *Data,
    size_t Length,
    uint8_t Digest[16]
    );

/*
 * AES-128 in ECB mode over exactly one block. The protocol only ever encrypts a
 * 16-byte password block, so there is no mode, padding or streaming state here.
 */
void
IwanNtAes128EncryptBlock(
    const uint8_t Key[16],
    const uint8_t Input[16],
    uint8_t Output[16]
    );

#ifdef __cplusplus
}
#endif

#endif
