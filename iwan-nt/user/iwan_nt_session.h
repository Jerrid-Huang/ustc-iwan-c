#ifndef IWAN_NT_SESSION_H
#define IWAN_NT_SESSION_H

/*
 * Control-plane framing for iWAN NT, user-mode side.
 *
 * The kernel owns the UDP socket, so the handshake runs here: these helpers turn
 * credentials into an OPEN frame, turn an OPEN_ACK into the values the driver
 * needs (sid, token, key, peer), and keep the ECHO keepalive alive. Nothing here
 * touches a device or a socket, which is why it can be unit tested on the host.
 *
 * Wire format, from the deployed protocol:
 *
 *   control frame = 8-byte header, 16-byte signature, then TLVs
 *   header        = type, encrypt, sid (big endian), token (big endian)
 *   signature     = MD5(header || "mw")
 *   TLV           = type, length (both bytes, length includes itself), value
 */

#include <stddef.h>
#include <stdint.h>

/*
 * These headers are user-mode only, so they take the C runtime integer types
 * directly instead of the driver's kernel-aware wrapper. Including that wrapper
 * here would make the user build depend on the driver include path for no gain.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define IWAN_NT_SESSION_HEADER 8u
#define IWAN_NT_SESSION_SIGNATURE 16u
#define IWAN_NT_SESSION_PREFIX (IWAN_NT_SESSION_HEADER + IWAN_NT_SESSION_SIGNATURE)
#define IWAN_NT_SESSION_CONTROL_MAX 512u
#define IWAN_NT_SESSION_ECHO_LEN 60u

#define IWAN_NT_SESSION_TYPE_OPEN 0x13u
#define IWAN_NT_SESSION_TYPE_OPEN_ACK 0x12u
#define IWAN_NT_SESSION_TYPE_OPEN_REJECT 0x11u
#define IWAN_NT_SESSION_TYPE_ECHO_REQUEST 0x15u
#define IWAN_NT_SESSION_TYPE_ECHO_RESPONSE 0x16u
#define IWAN_NT_SESSION_TYPE_CLOSE 0x17u

#define IWAN_NT_SESSION_TLV_USER 0x01u
#define IWAN_NT_SESSION_TLV_PASSWORD 0x02u
#define IWAN_NT_SESSION_TLV_MTU 0x03u
#define IWAN_NT_SESSION_TLV_ADDRESS 0x04u
#define IWAN_NT_SESSION_TLV_DNS 0x05u
#define IWAN_NT_SESSION_TLV_GATEWAY 0x06u
#define IWAN_NT_SESSION_TLV_ENCRYPT 0x08u

typedef struct _IWAN_NT_SESSION_OPEN {
    const char *User;
    const char *Password;
    uint16_t Mtu;
} IWAN_NT_SESSION_OPEN;

typedef struct _IWAN_NT_SESSION_ACK {
    uint16_t Sid;
    uint32_t Token;
    uint16_t Mtu;
    uint32_t Encrypted;
    int HasAddress;
    uint8_t Address[4];   /* network byte order, as it arrived */
    int HasGateway;
    uint8_t Gateway[4];
} IWAN_NT_SESSION_ACK;

/*
 * A keepalive answer carries the delay the peer measured, which is the only
 * reachability signal that is stronger than "the socket accepted the send".
 */
typedef struct _IWAN_NT_SESSION_ECHO {
    uint16_t Sid;
    uint32_t Token;
    uint64_t Tick;      /* echoed from the request, in microseconds */
    uint32_t Current;   /* microseconds */
    uint32_t Minimum;
    uint32_t Maximum;
} IWAN_NT_SESSION_ECHO;

typedef enum _IWAN_NT_SESSION_RESULT {
    IwanNtSessionOk = 0,
    IwanNtSessionBadArgument,
    IwanNtSessionTooLarge,
    IwanNtSessionWrongType,
    IwanNtSessionShortFrame,
    IwanNtSessionBadTlv,
    IwanNtSessionBadSignature
} IWAN_NT_SESSION_RESULT;

/*
 * XOR key for DATA frames: MD5(user || password), first 8 bytes. The server
 * derives the same value, so a mismatch shows up as garbage rather than a
 * handshake failure.
 */
void
IwanNtSessionKey(
    const char *User,
    const char *Password,
    uint8_t Key[8]
    );

/* Build the OPEN frame, including the signature over its own header. */
IWAN_NT_SESSION_RESULT
IwanNtSessionBuildOpen(
    const IWAN_NT_SESSION_OPEN *Open,
    uint8_t *Buffer,
    size_t Capacity,
    size_t *Length
    );

/* Parse an OPEN_ACK (or OPEN_REJECT, which yields the same header fields). */
IWAN_NT_SESSION_RESULT
IwanNtSessionParseAck(
    const uint8_t *Frame,
    size_t Length,
    IWAN_NT_SESSION_ACK *Ack
    );

/*
 * Build an ECHO request. The payload carries a microsecond tick plus the current
 * and observed min/max delay in microseconds, and a fixed routing block that this
 * build of the protocol never fills in.
 */
IWAN_NT_SESSION_RESULT
IwanNtSessionBuildEchoRequest(
    uint16_t Sid,
    uint32_t Token,
    uint64_t TickMicros,
    uint8_t *Buffer,
    size_t Capacity,
    size_t *Length
    );

/* Parse an ECHO response; the delay fields are big endian, the tick is not. */
IWAN_NT_SESSION_RESULT
IwanNtSessionParseEchoResponse(
    const uint8_t *Frame,
    size_t Length,
    IWAN_NT_SESSION_ECHO *Echo
    );

/* The frame type, for callers that only need to route a received frame. */
/*
 * Non-zero when the 16-byte signature after the header matches
 * md5(header || "mw"). Every control frame carries one, including the answer
 * that installs a session, so nothing is parsed before this passes.
 */
/*
 * Write the signature for Frame into its own bytes 8..23. Exposed so callers
 * that build control frames (and the tests that fabricate peer frames) sign
 * exactly the way this implementation checks.
 */
void
IwanNtSessionSignFrame(
    uint8_t *Frame
    );

int
IwanNtSessionVerify(
    const uint8_t *Frame,
    size_t Length
    );

uint8_t
IwanNtSessionType(
    const uint8_t *Frame,
    size_t Length
    );

#ifdef __cplusplus
}
#endif

#endif
