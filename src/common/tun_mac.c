/* macOS TUN backend: utun interfaces via the kernel control socket.
 *
 * Modern XNU has no /dev/utunN devfs nodes: utun units are created by
 * opening the "com.apple.net.utun_control" kernel control socket
 * (PF_SYSTEM/SYSPROTO_CONTROL). connect() attaches a fresh utunN
 * interface (sc_unit=0 lets the kernel assign the unit) and
 * UTUN_OPT_IFNAME reports the kernel-assigned interface name.
 * The requested name is an app-level handle only: open_tun records the
 * requested->actual mapping and tun_ifname() translates back for
 * ifconfig/route. A single mapping suffices (one TUN per process).
 *
 * The unit is released when the socket is closed: teardown is plain
 * close(fd), and the interface (with its addresses) disappears.
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

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>

#include "common.h"
#include "tun.h"
#include "util.h"

/* net/if_utun.h is not part of the public SDK; the control name and the
 * option id are stable XNU ABI (bsd/net/if_utun.h). */
#ifndef UTUN_CONTROL_NAME
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#endif
#ifndef UTUN_OPT_IFNAME
#define UTUN_OPT_IFNAME 2
#endif

static char g_utun_name[IFNAMSIZ];   /* actual interface (utunN) */
static char g_requested[IFNAMSIZ];   /* the app-level name it maps from */

int open_tun(const char *name)
{
    if (!tun_name_valid(name))
        return -1;

    /* resolve the control id (com.apple.net.utun_control) */
    struct ctl_info ci;
    memset(&ci, 0, sizeof ci);
    snprintf(ci.ctl_name, sizeof ci.ctl_name, "%s", UTUN_CONTROL_NAME);
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0)
        return -1;
    if (ioctl(fd, CTLIOCGINFO, &ci) < 0) {
        close(fd);
        return -1;
    }

    /* attach a new utun unit (sc_unit=0: kernel picks the next free one) */
    struct sockaddr_ctl sc;
    memset(&sc, 0, sizeof sc);
    sc.sc_id = ci.ctl_id;
    sc.sc_len = sizeof sc;
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit = 0;
    if (connect(fd, (struct sockaddr *)&sc, sizeof sc) < 0) {
        close(fd);
        return -1;
    }

    /* the real interface name is kernel-assigned; do not guess "utun%d" */
    socklen_t nlen = (socklen_t)sizeof g_utun_name;
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, g_utun_name,
                   &nlen) < 0 || g_utun_name[0] == '\0') {
        close(fd);
        errno = EIO;
        return -1;
    }
    g_utun_name[IFNAMSIZ - 1] = '\0';
    snprintf(g_requested, sizeof g_requested, "%s", name);

    /* same reasoning as the Linux backend: the kernel's per-queue
     * ACK stream overflows a small rcvbuf; match the session
     * buffers so the reader can drain bursts. */
    int sz = 4 * 1024 * 1024;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    return fd;
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
