/* macOS TUN backend: utun devices.
 *
 * macOS has no tun-style "open by name" ioctl; utun devices are
 * kernel-assigned interfaces (utun0..utun255) opened as /dev/utunN.
 * The requested name is an app-level handle only: open_tun records the
 * requested->actual mapping and tun_ifname() translates back for
 * ifconfig/route. A single mapping suffices (one TUN per process).
 *
 * utun is single-queue: tun_attach returns -1 so the reader pool stays
 * at one queue, and there is no steering program (tun_steering_attach
 * returns -1), mirroring the wintun backend. */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "tun.h"
#include "util.h"

#define UTUN_MAX 16   /* probe utun0..utun15 for a free device */

static char g_utun_name[IFNAMSIZ];   /* actual interface (utunN) */
static char g_requested[IFNAMSIZ];   /* the app-level name it maps from */

int open_tun(const char *name)
{
    if (!tun_name_valid(name))
        return -1;
    for (int i = 0; i < UTUN_MAX; i++) {
        char dev[32];
        snprintf(dev, sizeof dev, "/dev/utun%d", i);
        int fd = open(dev, O_RDWR);
        if (fd < 0)
            continue;   /* busy or absent */
        snprintf(g_utun_name, sizeof g_utun_name, "utun%d", i);
        snprintf(g_requested, sizeof g_requested, "%s", name);
        /* same reasoning as the Linux backend: the kernel's per-queue
         * ACK stream overflows a small rcvbuf; match the session
         * buffers so the reader can drain bursts. */
        int sz = 4 * 1024 * 1024;
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
        return fd;
    }
    errno = ENOSPC;   /* no free utun device */
    return -1;
}

int tun_attach(const char *name)
{
    (void)name;
    return -1;   /* utun is single-queue */
}

void tun_detach(int fd)
{
    (void)fd;   /* nothing to detach */
}

/* tun_steering_attach comes from tun.c's non-Linux stub (no steering
 * program on macOS). */

const char *tun_ifname(const char *name)
{
    if (g_requested[0] != '\0' && strcmp(name, g_requested) == 0)
        return g_utun_name;
    return name;
}
