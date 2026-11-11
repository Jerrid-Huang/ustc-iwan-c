#ifndef IWANNT_CONNECT_H
#define IWANNT_CONNECT_H

#include "iwan_nt_control.h"

/*
 * Drive one session end to end through the control device: send OPEN, wait for
 * the answer, install the session the driver needs, then keep the keepalive
 * alive and report what comes back.
 *
 * It returns 0 when a session was established, 1 on a transport error, 2 when
 * the peer rejected us, and 3 when the deadline passed without an answer.
 */
int
IwanNtRunConnect(
    _In_ PIWAN_NT_DEVICE Device,
    _In_ int Argc,
    _In_ char **Argv
    );

#endif
