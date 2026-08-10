#ifndef IWAN_PORT_H
#define IWAN_PORT_H
/* ------------------------------------------------------------------ */
/* Platform abstraction layer (Linux/POSIX vs Windows/Win32-minGW).   */
/*                                                                     */
/* On Linux every wrapper below is a zero-cost static inline around    */
/* the native syscall; on Windows the real implementation lives in     */
/* port.c (winsock2/WSAPoll/BCrypt/etc). The contract:                 */
/*   - socket fds are `int` (SOCKET values are small on Windows);      */
/*   - on failure errno is set to a POSIX-style value (WSA errors are  */
/*     mapped: WSAEWOULDBLOCK -> EAGAIN, WSAEINTR -> EINTR, ...), so   */
/*     existing `errno == EAGAIN` checks and strerror(errno) work;     */
/*   - EWOULDBLOCK == EAGAIN on Windows (folded in this header);       */
/*   - MSG_DONTWAIT/recvmmsg/sendmmsg semantics are emulated: the      */
/*     per-call nonblocking flag becomes ioctlsocket(FIONBIO) around   */
/*     the operation when the socket is not already nonblocking;       */
/*   - port_close is for SOCKETS only; plain close() still closes CRT  */
/*     file descriptors (pass files, oidc state files).                */
/* ------------------------------------------------------------------ */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <errno.h>
#  include <io.h>
#  include <process.h>
#  include <sys/types.h>
#  include <time.h>
#  include <bcrypt.h>

   /* ---- POSIX shims absent from mingw-w64 headers ---- */

   /* ssize_t: defined by corecrt.h on this toolchain; guard anyway */
#  ifndef _SSIZE_T_DEFINED
#    define _SSIZE_T_DEFINED
typedef intptr_t ssize_t;
#  endif

   /* iovec/msghdr/mmsghdr: winsock has WSABUF/WSAMSG, no msghdr */
struct iovec {
    void  *iov_base;
    size_t iov_len;
};

struct msghdr {
    void         *msg_name;
    socklen_t     msg_namelen;
    struct iovec *msg_iov;
    int           msg_iovlen;
    void         *msg_control;
    socklen_t     msg_controllen;
    int           msg_flags;
};

struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int  msg_len;   /* recvmmsg: received bytes */
};

typedef unsigned int nfds_t;

   /* per-call flags have no winsock equivalent; the port layer treats
    * them as hints (MSG_DONTWAIT -> FIONBIO toggling, MSG_TRUNC ->
    * WSAEMSGSIZE detection). Values are local, never passed to winsock.
    * Existing code passes these OR'd with 0, which is harmless. */
#  ifndef MSG_DONTWAIT
#    define MSG_DONTWAIT 0x1
#  endif
#  ifndef MSG_TRUNC
#    define MSG_TRUNC 0x2
#  endif

   /* normalize: winsock reports WSAEWOULDBLOCK where POSIX code checks
    * EAGAIN; the wrappers map to EAGAIN, and EWOULDBLOCK is folded so
    * `errno == EWOULDBLOCK` comparisons also match. */
#  ifdef EWOULDBLOCK
#    undef EWOULDBLOCK
#  endif
#  define EWOULDBLOCK EAGAIN

   /* SOL_UDP / UDP_SEGMENT do not exist in winsock; the values match
    * Linux so port_setsockopt can translate UDP_SEGMENT to the Windows
    * WSAIoctl(SIO_UDP_NETSEGMENT) GSO interface (Win11+; older systems
    * fail with WSAEOPNOTSUPP and the code falls back to per-datagram
    * sends, mirroring the Linux gso_ok == -1 path). */
#  ifndef SOL_UDP
#    define SOL_UDP IPPROTO_UDP
#  endif
#  ifndef UDP_SEGMENT
#    define UDP_SEGMENT 103
#  endif
#  ifndef SIO_UDP_NETSEGMENT
#    define SIO_UDP_NETSEGMENT 0x98030005u
#  endif

   /* WSAPoll rejects negative timeouts (SOCKET_ERROR); callers use
    * explicit positive timeouts, but normalize -1 to INFTIM anyway. */
#  define PORT_POLL_INFTIM (-1)

#else /* !_WIN32 */

#  include <arpa/inet.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <poll.h>
#  include <signal.h>
#  include <strings.h>
#  include <sys/eventfd.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <sys/uio.h>
#  include <time.h>
#  include <unistd.h>

#  define PORT_POLL_INFTIM (-1)

#endif

/* ------------------------- lifecycle ------------------------------- */

/* WSAStartup once (Windows only; no-op elsewhere). Call at the top of
 * every main() before any socket work. */
void port_socket_init(void);

/* ----------------------- clock / entropy / sleep ------------------- */
/* These are implemented in port.c on BOTH platforms (POSIX code paths
 * also use them; util.c's now_ms/rand_u32 route through here). */

/* monotonic clocks, ms/us (QPC on Windows) */
uint64_t port_now_ms(void);
uint64_t port_now_us(void);
/* cryptographically strong entropy (BCryptGenRandom / getrandom).
 * Returns 0 on success, -1 on failure. Callers MUST fail closed: a
 * nonce or session token derived from weak entropy is a hijack hole. */
int port_rand_bytes(void *out, size_t n);
void port_sleep_ms(unsigned ms);
void port_sleep_us(unsigned us);   /* rounds up to the ms timer on win32 */

/* ----------------------- process / env / misc ---------------------- */

long port_cpu_count(void);
/* malloc'd home directory (USERPROFILE on Windows, passwd on POSIX) */
char *port_home_dir(void);

/* Install a process-stop handler: SIGINT/SIGTERM/SIGHUP on POSIX
 * (sigaction), CTRL_C/CTRL_CLOSE on Windows (SetConsoleCtrlHandler).
 * fn(sig) receives SIGINT for any stop signal; g_stop is NOT set by
 * this layer. May be called once; later calls replace the handler. */
int port_set_stop_handler(void (*fn)(int sig));

/* Elevated/admin check: geteuid()==0 on POSIX, Administrators-group
 * membership on Windows (TUN + routing require it there). */
bool port_is_admin(void);

/* Run a helper binary (the `ip`/`netsh`/`route` shell-outs) and wait
 * for it. argv is NULL-terminated with argv[0] = program name.
 * Returns the exit status (0..255) or -1 on spawn failure. */
int port_run_cmd(char *const argv[]);
/* Run a helper and capture its stdout (bounded at max bytes).
 * Returns a malloc'd NUL-terminated string or NULL on failure. */
char *port_cmd_capture(char *const argv[], size_t max);

#ifdef _WIN32

struct mmsghdr;

/* SIGPIPE is a no-op on Windows (winsock surfaces ECONNRESET) */
void port_ignore_sigpipe(void);
int  port_strcasecmp(const char *a, const char *b);
int  port_strncasecmp(const char *a, const char *b, size_t n);

/* ------------------------- fd helpers ------------------------------ */

/* Close a SOCKET. Never use on plain file descriptors (use close). */
int port_close(int fd);

/* Set/clear O_NONBLOCK (ioctlsocket FIONBIO on Windows). */
int port_set_nonblock(int fd, bool nb);

/* ---------------------- datagram / stream I/O ---------------------- */
/* All wrappers set errno on failure and return -1 (or 0 messages for
 * recvmmsg with nothing available, mirroring Linux). send/recv len is
 * size_t; winsock's int limit is irrelevant (<= 64 KiB frames). */

ssize_t port_send(int fd, const void *buf, size_t len, int flags);
ssize_t port_recv(int fd, void *buf, size_t len, int flags);
ssize_t port_sendto(int fd, const void *buf, size_t len, int flags,
                    const struct sockaddr *to, socklen_t tolen);
ssize_t port_recvfrom(int fd, void *buf, size_t len, int flags,
                      struct sockaddr *from, socklen_t *fromlen);
ssize_t port_sendmsg(int fd, const struct msghdr *msg, int flags);
ssize_t port_recvmsg(int fd, struct msghdr *msg, int flags);
int     port_sendmmsg(int fd, struct mmsghdr *msgvec, unsigned vlen,
                      int flags);
int     port_recvmmsg(int fd, struct mmsghdr *msgvec, unsigned vlen,
                      int flags, struct timespec *timeout);
ssize_t port_readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t port_writev(int fd, const struct iovec *iov, int iovcnt);

/* ------------------------- socket setup ---------------------------- */

int port_socket(int domain, int type, int protocol);
int port_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);
int port_connect(int fd, const struct sockaddr *addr, socklen_t len);
int port_bind(int fd, const struct sockaddr *addr, socklen_t len);
int port_listen(int fd, int backlog);
int port_shutdown(int fd, int how);
int port_getsockopt(int fd, int level, int optname, void *optval,
                    socklen_t *optlen);
/* SO_RCVTIMEO/SO_SNDTIMEO: struct timeval on POSIX, DWORD ms on
 * Windows — translated here. UDP_SEGMENT: translated to the Windows
 * GSO ioctl. Everything else passes through. */
int port_setsockopt(int fd, int level, int optname, const void *optval,
                    socklen_t optlen);

/* WSAPoll on Windows (sockets only); poll() on POSIX. timeout_ms is
 * ms, -1 waits forever. */
int port_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms);

/* ------------------ eventfd substitute (wakeup) -------------------- */
/* Linux: eventfd(0, EFD_NONBLOCK). Windows: a self-connected UDP
 * socketpair on loopback (WSAPoll-able; no handle polling). The fd is
 * a socket on both platforms: pollable, closed with port_evfd_close. */
int  port_evfd_create(void);
int  port_evfd_wake(int fd);    /* make the fd readable */
int  port_evfd_drain(int fd);   /* consume pending wakeups, nonblocking */
void port_evfd_close(int fd);

#else /* !_WIN32 */

static inline int port_close(int fd) { return close(fd); }
static inline int port_set_nonblock(int fd, bool nb)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0)
        return -1;
    return fcntl(fd, F_SETFL, nb ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
}
static inline ssize_t port_send(int fd, const void *buf, size_t len, int flags)
{ return send(fd, buf, len, flags); }
static inline ssize_t port_recv(int fd, void *buf, size_t len, int flags)
{ return recv(fd, buf, len, flags); }
static inline ssize_t port_sendto(int fd, const void *buf, size_t len,
                                  int flags, const struct sockaddr *to,
                                  socklen_t tolen)
{ return sendto(fd, buf, len, flags, to, tolen); }
static inline ssize_t port_recvfrom(int fd, void *buf, size_t len, int flags,
                                    struct sockaddr *from, socklen_t *fromlen)
{ return recvfrom(fd, buf, len, flags, from, fromlen); }
static inline ssize_t port_sendmsg(int fd, const struct msghdr *msg, int flags)
{ return sendmsg(fd, msg, flags); }
static inline ssize_t port_recvmsg(int fd, struct msghdr *msg, int flags)
{ return recvmsg(fd, msg, flags); }
static inline int port_sendmmsg(int fd, struct mmsghdr *msgvec,
                                unsigned vlen, int flags)
{ return sendmmsg(fd, msgvec, vlen, flags); }
static inline int port_recvmmsg(int fd, struct mmsghdr *msgvec,
                                unsigned vlen, int flags,
                                struct timespec *timeout)
{ return recvmmsg(fd, msgvec, vlen, flags, timeout); }
static inline ssize_t port_readv(int fd, const struct iovec *iov, int iovcnt)
{ return readv(fd, iov, iovcnt); }
static inline ssize_t port_writev(int fd, const struct iovec *iov, int iovcnt)
{ return writev(fd, iov, iovcnt); }
static inline int port_socket(int domain, int type, int protocol)
{ return socket(domain, type, protocol); }
static inline int port_accept(int fd, struct sockaddr *addr,
                              socklen_t *addrlen)
{ return accept(fd, addr, addrlen); }
static inline int port_connect(int fd, const struct sockaddr *addr,
                               socklen_t len)
{ return connect(fd, addr, len); }
static inline int port_bind(int fd, const struct sockaddr *addr,
                            socklen_t len)
{ return bind(fd, addr, len); }
static inline int port_listen(int fd, int backlog)
{ return listen(fd, backlog); }
static inline int port_shutdown(int fd, int how)
{ return shutdown(fd, how); }
static inline int port_getsockopt(int fd, int level, int optname,
                                  void *optval, socklen_t *optlen)
{ return getsockopt(fd, level, optname, optval, optlen); }
static inline int port_setsockopt(int fd, int level, int optname,
                                  const void *optval, socklen_t optlen)
{ return setsockopt(fd, level, optname, optval, optlen); }
static inline int port_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms)
{ return poll(fds, nfds, timeout_ms); }
static inline int port_evfd_create(void) { return eventfd(0, EFD_NONBLOCK); }
static inline int port_evfd_wake(int fd)
{
    uint64_t one = 1;
    return write(fd, &one, sizeof one) == (ssize_t)sizeof one ? 0 : -1;
}
static inline int port_evfd_drain(int fd)
{
    uint64_t v;
    return read(fd, &v, sizeof v) > 0 ? 0 : -1;
}
static inline void port_evfd_close(int fd) { close(fd); }
static inline void port_ignore_sigpipe(void)
{
    signal(SIGPIPE, SIG_IGN);
}
static inline int port_strcasecmp(const char *a, const char *b)
{ return strcasecmp(a, b); }
static inline int port_strncasecmp(const char *a, const char *b, size_t n)
{ return strncasecmp(a, b, n); }
#endif /* !_WIN32 */

#endif /* IWAN_PORT_H */
