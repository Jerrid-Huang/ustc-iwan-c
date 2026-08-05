#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "tun.h"

int open_tun(const char *name) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
        return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

void tun_close(int fd) {
    close(fd);
}

void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

ptrdiff_t tun_read(int fd, void *buf, size_t len) {
    return (ptrdiff_t)read(fd, buf, len);
}

ptrdiff_t tun_write(int fd, const void *buf, size_t len) {
    return (ptrdiff_t)write(fd, buf, len);
}
