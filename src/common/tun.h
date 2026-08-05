#ifndef IWAN_TUN_H
#define IWAN_TUN_H

#include <stddef.h>

int      open_tun(const char *name);   /* fd or -1 */
void     tun_close(int fd);
void     set_nonblock(int fd);
/* returns n>0, -1(+EAGAIN), -1(fatal) */
ptrdiff_t tun_read(int fd, void *buf, size_t len);
ptrdiff_t tun_write(int fd, const void *buf, size_t len);

#endif
