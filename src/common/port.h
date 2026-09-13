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

   /* ssize_t: defined by corecrt.h on this toolchain; guard anyway.
    *
    * NOTE for the ILP32 (i686) mingw build: intptr_t is 32-bit there, so this
    * ssize_t is `int` (32-bit) and an `unsigned int` source does not widen on
    * assignment — it is a sign-changing narrowing. Every `ssize_t n =
    * <msg_len>` from a struct mmsghdr below therefore needs an explicit
    * (ssize_t) cast; that cast is a harmless no-op where ssize_t is already
    * 64-bit (LLP64) and keeps the site clean on both architectures. x86_64 is
    * LLP64 (intptr_t is 64-bit), so it never warned, which is how the i686
    * sites stayed hidden until the R38 i686 gate ran: since R37 R7 the
    * Windows strict tier applies the full flag set, -Wconversion and
    * -Wsign-conversion included, on every architecture. */
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

#else /* !_WIN32 */

#  include <arpa/inet.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <poll.h>
#  include <signal.h>
#  include <strings.h>
#  ifdef __linux__
#    include <sys/eventfd.h>
#  endif
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <sys/uio.h>
#  include <time.h>
#  include <unistd.h>

   /* macOS lacks the mmsghdr type and the sendmmsg/recvmmsg syscalls
    * (Linux-only). Define the type like the Windows branch and emulate
    * the batching with a sendmsg/recvmsg loop below. SOL_UDP and
    * UDP_SEGMENT are Linux socket constants absent from macOS; defining
    * them to the Linux values lets the GSO probe in socks.c fail with
    * ENOPROTOOPT and degrade to per-datagram sends, exactly like Linux
    * without GSO support. */
#  ifdef __APPLE__
struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int  msg_len;
};
#    ifndef SOL_UDP
#      define SOL_UDP IPPROTO_UDP
#    endif
#    ifndef UDP_SEGMENT
#      define UDP_SEGMENT 103
#    endif
#  endif

#endif

/* ------------------- platform-typed fd argument -------------------- */
/* Socket handles cross the platform boundary in two spellings: the port
 * layer keeps fds as `int` everywhere, but winsock declares `SOCKET`
 * arguments and `WSAPOLLFD.fd` as SOCKET (unsigned, 64-bit on LLP64)
 * while POSIX uses int. Passing/assigning a plain int fd to those is an
 * implicit int -> unsigned conversion, which the Windows strict tier
 * rejects (-Wsign-conversion). PORT_FD_ARG is the single place that knows
 * the platform's spelling, so shared call sites stay cast-free:
 *
 *     pfd.fd = PORT_FD_ARG(fd);
 *     (void)send(PORT_FD_ARG(sock), buf, len, 0);
 *
 * The argument must be a valid, non-negative handle. The Windows arm goes
 * through `unsigned` first so that neither step is int -> 64-bit-unsigned
 * (which is what -Wsign-conversion flags). */
#ifdef _WIN32
#  define PORT_FD_ARG(fdv) ((SOCKET)(unsigned)(fdv))
#else
#  define PORT_FD_ARG(fdv) (fdv)
#endif

/* ---------------- platform-typed msg_iovlen argument --------------- */
/* struct msghdr::msg_iovlen crosses the same boundary as the fd above, but
 * with the opposite spelling problem: POSIX declares it `size_t`, while the
 * WSABUF-backed shim in the Windows branch above declares it `int` — and so
 * does Darwin, which deviates from POSIX here (XNU's struct msghdr has
 * `int msg_iovlen`, the same 32-bit field as its msghdr_x extension). A
 * plain cast to either spelling is wrong elsewhere under the strict tier:
 * int -> size_t is a sign change on LP64 POSIX, and on ILP32 mingw size_t
 * is `unsigned int`, so size_t -> int is one there too (on LLP64 it is
 * instead a 64 -> 32 narrowing). PORT_MSG_IOVLEN is the single place that
 * knows the platform's spelling, so shared call sites stay cast-free:
 *
 *     mh.msg_iovlen = PORT_MSG_IOVLEN(npk);
 *
 * The argument is an iovec/message count, bounded by the caller's array.
 * The _Static_asserts are the self-check: if a future edit (or a new libc)
 * changes a field's width, that platform fails HERE instead of shipping a
 * silently wrong cast that only some other toolchain's -Wsign-conversion
 * would have caught. */
#if defined(_WIN32)
#  define PORT_MSG_IOVLEN(n) ((int)(n))
_Static_assert(sizeof(((struct msghdr *)0)->msg_iovlen) == sizeof(int),
               "Windows shim msg_iovlen must be int");
#elif defined(__APPLE__)
#  define PORT_MSG_IOVLEN(n) ((int)(n))
_Static_assert(sizeof(((struct msghdr *)0)->msg_iovlen) == sizeof(int),
               "Darwin msghdr.msg_iovlen is int, not size_t");
#else
#  define PORT_MSG_IOVLEN(n) ((size_t)(n))
_Static_assert(sizeof(((struct msghdr *)0)->msg_iovlen) == sizeof(size_t),
               "POSIX msghdr.msg_iovlen must be size_t");
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
/* malloc'd home directory (USERPROFILE on Windows, passwd on POSIX).
 * Windows: only a fully-qualified path is accepted — drive-absolute
 * (X:\ or X:/) or UNC (\\server\share) for USERPROFILE, and HOMEDRIVE
 * must be "X:" with HOMEPATH starting in a separator; a malformed
 * environment yields NULL (never a CWD- or drive-relative path, which
 * would move the credential store). POSIX: $HOME, then the passwd
 * entry. */
char *port_home_dir(void);

/* Install a process-stop handler: SIGINT/SIGTERM/SIGHUP on POSIX
 * (sigaction), CTRL_C/CTRL_CLOSE on Windows (SetConsoleCtrlHandler).
 * fn(sig) receives SIGINT for any stop signal; g_stop is NOT set by
 * this layer. May be called once; later calls replace the handler. */
int port_set_stop_handler(void (*fn)(int sig));

/* Elevated/admin check: geteuid()==0 on POSIX, Administrators-group
 * membership on Windows (TUN + routing require it there). */
bool port_is_admin(void);

/* Relaunch the current executable as administrator via a UAC prompt
 * (ShellExecuteW "runas"). argv is the original main() argv; the
 * executable path is resolved from the running image. Returns 0 when
 * the elevated instance was launched (the caller should exit — the new
 * process owns the work), -1 when elevation failed or was declined. */
int port_elevate_self(int argc, char **argv);

/* Install the Windows unhandled-exception reporter (prints the
 * exception code/address/module and holds a UAC-relaunched window
 * open). Call once at startup. */
void port_install_crash_handler(void);

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
int  port_strncasecmp(const char *a, const char *b, size_t n);

/* ------------------------- fd helpers ------------------------------ */

/* Close a SOCKET. Never use on plain file descriptors (use close). */
int port_close(int fd);

/* Set/clear O_NONBLOCK (ioctlsocket FIONBIO on Windows). */
int port_set_nonblock(int fd, bool nb);

/* ---------------------- datagram / stream I/O ---------------------- */
/* All wrappers set errno on failure and return -1 (recvmmsg with
 * nothing available also returns -1/EAGAIN, mirroring Linux — callers
 * poll on that). send/recv len is size_t; winsock's int limit is
 * irrelevant (<= 64 KiB frames). */

ssize_t port_send(int fd, const void *buf, size_t len, int flags);
ssize_t port_recv(int fd, void *buf, size_t len, int flags);
ssize_t port_sendmsg(int fd, const struct msghdr *msg, int flags);
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
 * ms, -1 waits forever. Negative-fd slots are ignored with revents=0 on
 * BOTH platforms (POSIX poll() already does that; the Windows wrapper
 * strips them because WSAPoll would otherwise fail the whole set with
 * WSAENOTSOCK) — indices into the caller's array stay valid. */
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
static inline void port_set_cloexec(int fd)
{
    int fl = fcntl(fd, F_GETFD, 0);
    if (fl >= 0)
        (void)fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
}
static inline ssize_t port_send(int fd, const void *buf, size_t len, int flags)
{ return send(fd, buf, len, flags); }
static inline ssize_t port_recv(int fd, void *buf, size_t len, int flags)
{ return recv(fd, buf, len, flags); }
static inline ssize_t port_sendmsg(int fd, const struct msghdr *msg, int flags)
{ return sendmsg(fd, msg, flags); }
static inline int port_sendmmsg(int fd, struct mmsghdr *msgvec,
                                unsigned vlen, int flags)
{
#  ifdef __APPLE__
    /* macOS has no sendmmsg: emulate with a loop. Semantics match
     * Linux: the batch count returned on error reflects messages sent
     * (partial batches are not errors), mirroring the winsock path. */
    unsigned sent = 0;
    for (; sent < vlen; sent++) {
        ssize_t n = sendmsg(fd, &msgvec[sent].msg_hdr, flags);
        if (n < 0) {
            if (sent > 0)
                return (int)sent;
            return -1;
        }
    }
    return (int)sent;
#  else
    return sendmmsg(fd, msgvec, vlen, flags);
#  endif
}
static inline int port_recvmmsg(int fd, struct mmsghdr *msgvec,
                                unsigned vlen, int flags,
                                struct timespec *timeout)
{
#  ifdef __APPLE__
    /* recvmmsg emulation: same drained-shape as the winsock path
     * (EINTR/ECONNRESET with no messages is not an error). M12
     * (SUMMARY-2): an EMPTY queue must read as -1/EAGAIN like Linux
     * recvmmsg(MSG_DONTWAIT) — callers only park on v < 0, so
     * returning 0 here made the pump loop busy-spin a full core (the
     * exact bug the winsock path already fixed). A partial batch
     * (got > 0) is still returned as messages received. */
    (void)timeout;
    unsigned got = 0;
    for (; got < vlen; got++) {
        ssize_t n = recvmsg(fd, &msgvec[got].msg_hdr, flags);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (got > 0)
                    return (int)got;
                errno = EAGAIN;
                return -1;
            }
            if (errno == EINTR || errno == ECONNRESET)
                return (int)got;
            if (got > 0)
                return (int)got;
            return -1;
        }
        msgvec[got].msg_len = (unsigned)n;
    }
    return (int)got;
#  else
    return recvmmsg(fd, msgvec, vlen, flags, timeout);
#  endif
}
static inline ssize_t port_readv(int fd, const struct iovec *iov, int iovcnt)
{ return readv(fd, iov, iovcnt); }
static inline ssize_t port_writev(int fd, const struct iovec *iov, int iovcnt)
{ return writev(fd, iov, iovcnt); }
static inline int port_socket(int domain, int type, int protocol)
{
#  ifdef __linux__
    /* SOCK_CLOEXEC is an independent bit (0x80000 on Linux): OR-ing it
     * into the socket() type does not change SOCK_STREAM/SOCK_DGRAM
     * semantics, only marks the fd close-on-exec (L-F3). No caller
     * inspects the exact type bits afterwards. */
    return socket(domain, type | SOCK_CLOEXEC, protocol);
#  else
    /* macOS/BSD has no SOCK_CLOEXEC: mark the fd close-on-exec with
     * fcntl instead so it cannot leak into forked helper subprocesses
     * (ifconfig/route/netstat) (L-F3 / M-2). */
    int fd = socket(domain, type, protocol);
    if (fd >= 0)
        port_set_cloexec(fd);
    return fd;
#  endif
}
static inline int port_accept(int fd, struct sockaddr *addr,
                              socklen_t *addrlen)
{
#  ifdef __linux__
    /* accept4(..., SOCK_CLOEXEC): accepted client sockets must not leak
     * into helper subprocesses either (L-F3). */
    return accept4(fd, addr, addrlen, SOCK_CLOEXEC);
#  else
    /* macOS/BSD has no accept4: mark the accepted fd close-on-exec with
     * fcntl so it cannot leak into forked helper subprocesses (M-2). */
    int afd = accept(fd, addr, addrlen);
    if (afd >= 0)
        port_set_cloexec(afd);
    return afd;
#  endif
}
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
#  ifdef __APPLE__
/* macOS: no eventfd; implemented in port.c as a self-connected UDP
 * socketpair on loopback (poll-able), like the Windows substitute. */
int  port_evfd_create(void);
int  port_evfd_wake(int fd);    /* make the fd readable */
int  port_evfd_drain(int fd);   /* consume pending wakeups, nonblocking */
void port_evfd_close(int fd);
#  else
static inline int port_evfd_create(void)
{ return eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC); }   /* L-F3: no fd leak
                                                      * into helpers */
static inline int port_evfd_wake(int fd)
{
    uint64_t one = 1;
    /* R38 P2-5: EINTR means the write was interrupted BEFORE the eventfd
     * counter was incremented — the 8-byte eventfd write is all-or-nothing
     * (no partial write is possible) and with EFD_NONBLOCK it never sleeps,
     * so a failure that is not EAGAIN left no wake behind. The tree
     * installs every sigaction with sa_flags = 0 (no SA_RESTART), so an
     * ordinary signal can land here; reporting it as a plain failure would
     * drop the wakeup and park the event loop until the next event or poll
     * timeout even though a DNS result is waiting. Retry instead. The
     * attempt bound only keeps a pathological signal storm from spinning
     * this inline forever; the caller logs any non-zero return, and EAGAIN
     * (counter already non-zero = a wake is pending, the reader is/will be
     * awake) still propagates unchanged. */
    for (int i = 0; i < 8; i++) {
        if (write(fd, &one, sizeof one) == (ssize_t)sizeof one)
            return 0;
        if (errno != EINTR)
            return -1;   /* EAGAIN/EWOULDBLOCK included: wake already pending */
    }
    return -1;   /* errno == EINTR from the last attempt */
}
static inline int port_evfd_drain(int fd)
{
    uint64_t v;
    return read(fd, &v, sizeof v) > 0 ? 0 : -1;
}
static inline void port_evfd_close(int fd) { close(fd); }
#  endif /* __APPLE__ */
static inline void port_ignore_sigpipe(void)
{
    signal(SIGPIPE, SIG_IGN);
}
static inline int port_strncasecmp(const char *a, const char *b, size_t n)
{ return strncasecmp(a, b, n); }
#endif /* !_WIN32 */

#endif /* IWAN_PORT_H */
