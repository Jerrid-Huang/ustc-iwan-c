#ifndef IWAN_NT_HANDSHAKE_H
#define IWAN_NT_HANDSHAKE_H

/*
 * The handshake as a state machine, with no Windows dependency.
 *
 * The point of separating it is testability: retry timing, what a rejection means,
 * and what happens when a CLOSE arrives mid-session are decisions that are far
 * cheaper to check on the host than on a guest with a driver loaded. Callers feed
 * it the clock and the frames that arrive, and it tells them which frame to send.
 *
 * Three states only:
 *
 *   Down        -- send OPEN, wait for OPEN_ACK / OPEN_REJECT
 *   Up          -- session installed, send ECHO on its own timer
 *   (back Down) -- on rejection, close, or the caller clearing it
 */

#include <stddef.h>
#include <stdint.h>

#include "iwan_nt_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IWAN_NT_HANDSHAKE_OPEN_MS 2000u
#define IWAN_NT_HANDSHAKE_ECHO_MS 2000u

/*
 * The deployed client gives up on a session that has been silent this long,
 * counting from the last frame it accepted rather than from the last frame it
 * sent: a peer that stopped answering is gone even if the socket still accepts
 * our writes.
 */
#define IWAN_NT_HANDSHAKE_DATA_TIMEOUT_MS 15000u

typedef enum _IWAN_NT_HANDSHAKE_STATE {
    IwanNtHandshakeDown = 0,
    IwanNtHandshakeUp
} IWAN_NT_HANDSHAKE_STATE;

typedef enum _IWAN_NT_HANDSHAKE_EVENT {
    IwanNtHandshakeEventNone = 0,
    IwanNtHandshakeEventEstablished,
    IwanNtHandshakeEventRejected,
    IwanNtHandshakeEventClosed,
    IwanNtHandshakeEventEchoAnswer,
    IwanNtHandshakeEventTimeout,
    IwanNtHandshakeEventFault
} IWAN_NT_HANDSHAKE_EVENT;

typedef struct _IWAN_NT_HANDSHAKE {
    /* Configuration, copied in at initialize so the caller owns no pointers. */
    char User[64];
    char Password[64];
    uint16_t Mtu;

    /* Session, valid while State == Up. */
    uint16_t Sid;
    uint32_t Token;
    uint32_t Encrypted;
    uint8_t Key[8];

    /*
     * The address the server handed us, and the gateway it wants us to use. They
     * are reported rather than applied: installing routes is the caller's job.
     */
    uint16_t MtuFromPeer;
    int HasAddress;
    uint8_t Address[4];
    int HasGateway;
    uint8_t Gateway[4];

    IWAN_NT_HANDSHAKE_STATE State;
    int EverEstablished;

    /*
     * Microsecond delays the peer reported in its last keepalive answer; they are
     * the only reachability evidence stronger than "a send was accepted".
     */
    uint32_t DelayCurrent;
    uint32_t DelayMinimum;
    uint32_t DelayMaximum;

    /* Last accepted frame, for the data timeout above. */
    uint64_t LastAcceptedMs;
    uint64_t NextActionMs;
    uint32_t Opens;
    uint32_t Echoes;
    uint32_t EchoAnswers;
    uint32_t Rejects;
    uint32_t Closes;
    uint32_t ForeignFrames;
    uint32_t Timeouts;
    IWAN_NT_SESSION_RESULT Fault;
} IWAN_NT_HANDSHAKE;

/* Returns nonzero on success; a name or password that does not fit is a bug. */
int
IwanNtHandshakeInitialize(
IWAN_NT_HANDSHAKE *Handshake,
    const char *User,
    const char *Password,
    uint16_t Mtu,
    uint64_t NowMs
    );

/*
 * Ask for the frame that is due now. Returns 1 and fills Buffer when one is due,
 * 0 when nothing is due. The caller sends it and does not retry on its own: the
 * timer inside the state machine is the only retry clock.
 */
int
IwanNtHandshakeTick(
IWAN_NT_HANDSHAKE *Handshake,
    uint64_t NowMs,
    uint8_t *Buffer,
    size_t Capacity,
    size_t *Length
    );

/* Feed one received control frame; returns what changed, if anything. */
IWAN_NT_HANDSHAKE_EVENT
IwanNtHandshakeOnFrame(
IWAN_NT_HANDSHAKE *Handshake,
    const uint8_t *Frame,
    size_t Length,
    uint64_t NowMs
    );

/* Drop the session at the caller's request, keeping the retry clock. */
void
IwanNtHandshakeReset(
IWAN_NT_HANDSHAKE *Handshake,
    uint64_t NowMs
    );

#ifdef __cplusplus
}
#endif

#endif
