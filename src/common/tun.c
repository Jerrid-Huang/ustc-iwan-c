#ifdef __linux__
#include <elf.h>
#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#endif
#include <arpa/inet.h>    /* htonl (utun family header) */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>   /* AF_INET/AF_INET6 (utun framing, macOS) */
#include <unistd.h>

#include "common.h"
#include "tun.h"
#include "util.h"

/* tun_name_valid lives in tun.h (static inline): all backends share the
 * same device-name rule set. */

#ifdef __linux__
/* Shared TUN open path. `extra_flags` is OR-ed into the TUNSETIFF
 * flags. Main-device creation passes IFF_TUN_EXCL (open_tun); extra
 * queue attach passes none (tun_attach), because the device name is
 * already taken by the very device we are attaching to. */
static int open_tun_flags(const char *name, int extra_flags) {
    if (!tun_name_valid(name))
        return -1;
    int fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr;
    if (fd < 0)
        return -1;
    memset(&ifr, 0, sizeof ifr);
    /* ifr_flags is a kernel-ABI *bit container* (`short`, 16 bits), not an
     * arithmetic value: TUNSETIFF only tests its bits, and IFF_TUN_EXCL
     * (0x8000) deliberately sets the top one, so the combined value 0x9101
     * exceeds SHRT_MAX. Build the mask in unsigned, refuse anything that
     * does not fit the 16-bit field (defence in depth — today's only
     * callers pass IFF_TUN_EXCL or 0), then copy the exact bit pattern in,
     * instead of an implementation-defined int->short conversion. */
    _Static_assert(sizeof(uint16_t) == sizeof ifr.ifr_flags,
                   "TUNSETIFF flag field must be exactly 16 bits");
    unsigned int flags =
        (unsigned int)(IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE) |
        (unsigned int)extra_flags;
    if (flags > 0xFFFFu) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    uint16_t raw_flags = (uint16_t)flags;
    memcpy(&ifr.ifr_flags, &raw_flags, sizeof raw_flags);
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

int open_tun(const char *name) {
    /* IFF_TUN_EXCL: main-device creation must never silently attach to
     * an interface created by someone else — TUNSETIFF fails EBUSY if
     * `name` is already in use, instead of joining it (and then
     * setup_tun flushing its addresses). */
    return open_tun_flags(name, IFF_TUN_EXCL);
}

/* attach another queue fd to an existing IFF_MULTI_QUEUE device.
 * Deliberately NO IFF_TUN_EXCL: the name is already taken by the device
 * we own and EXCL would make TUNSETIFF fail EBUSY, so extra queues
 * would be impossible. (A legacy SO_RCVBUF setsockopt was removed here:
 * a tun device fd is a character device, so setsockopt always returns
 * ENOTSOCK and never did anything — the receive-side buffering is the
 * device packet queue, not a socket rcvbuf.) */
int tun_attach(const char *name) {
    return open_tun_flags(name, 0);
}

void tun_detach(int fd) {
    struct ifreq ifr;

    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_DETACH_QUEUE;
    /* TUNSETQUEUE copies a full struct ifreq from userspace; passing the
     * bare flag integer as the ioctl arg made the kernel fail with
     * EFAULT, silently masked by the close() that followed (the close
     * does detach the queue regardless). The real detach still happens
     * on close, so failure here is non-fatal — log it for diagnosis. */
    if (ioctl(fd, TUNSETQUEUE, &ifr) < 0)
        log_debug("tun_detach: TUNSETQUEUE: %s (close will detach)",
                  strerror(errno));
}

/* macOS/other non-Linux backends (tun_mac.c) implement open_tun,
 * tun_attach, tun_detach and tun_steering_attach themselves. */

/* tun_ifname: the interface name to hand to ifconfig/route.
 * Linux/Windows: the requested name IS the interface name.
 * macOS: utun names are kernel-assigned, so the requested name maps
 * to the actual utunN (see tun_mac.c). */
const char *tun_ifname(const char *name)
{
    return name;
}
#endif /* __linux__ */

#ifdef __linux__
/* ---- tun steering eBPF (Linux only) ----
 * The tun driver's automq flow table degenerates on this kernel: the
 * flow hash collapses to a per-device constant (observed: every flood
 * run pinned every flow onto one queue, the queue varying per run).
 * TUNSETSTEERINGEBPF replaces queue selection with a deterministic
 * flow hash; the kernel maps the return value via ret % numqueues.
 * The program is embedded (steer_bpf.o -> steer_bpf_data.c, see
 * CMakeLists.txt). When the build cannot produce a BPF object
 * (IWAN_NO_STEER_BPF: no clang bpf target or no linux/bpf.h — e.g.
 * cross builds without kernel headers), tun_steering_attach degrades
 * to the kernel automq steering, like the Windows backend. */

#ifndef IWAN_NO_STEER_BPF
static int bpf_prog_load_steer(const struct bpf_insn *insns,
                                   unsigned int cnt, const char *license)
{
    /* Zero the log before use: the first load runs with log_level=0
     * (the kernel need not write anything); if the retry with the
     * verifier log enabled also fails before filling it, the log_err
     * below would otherwise print uninitialized stack garbage. */
    char log[4096] = {0};
    union bpf_attr attr;
    int fd;

    memset(&attr, 0, sizeof attr);
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = cnt;
    attr.insns = (unsigned long)insns;
    attr.license = (unsigned long)license;
    attr.log_buf = (unsigned long)log;
    attr.log_size = sizeof log;
    fd = (int)syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof attr);
    if (fd < 0) {
        /* retry with the verifier log for diagnostics */
        attr.log_level = 1;
        fd = (int)syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof attr);
        if (fd < 0)
            log_err("tun steering: bpf load: %s", log);
    }
    if (fd < 0)
        log_err("tun steering: bpf load failed: %s", strerror(errno));
    return fd;
}
#endif /* !IWAN_NO_STEER_BPF */

int tun_steering_attach(int tun_fd)
{
#ifndef IWAN_NO_STEER_BPF
    extern const unsigned char steer_bpf_o[];
    extern const unsigned int steer_bpf_o_len;
    const unsigned char *o = steer_bpf_o;
    size_t olen = steer_bpf_o_len;
    const Elf64_Ehdr *eh;
    const Elf64_Shdr *sh, *shstr;
    const char *shstrtab;
    const struct bpf_insn *insns = NULL;
    unsigned int insn_cnt = 0;
    const char *license = "Dual MIT/GPL";
    int prog_fd, rc;

    if (olen < sizeof(Elf64_Ehdr))
        return -1;
    eh = (const Elf64_Ehdr *)o;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64)
        return -1;
    /* Bounds checks in subtraction form so a malicious blob can never
     * make the 64-bit offsets/shifts integer-overflow past olen. */
    if (eh->e_shoff > olen ||
        (size_t)eh->e_shnum > (olen - eh->e_shoff) / sizeof(Elf64_Shdr))
        return -1;
    sh = (const Elf64_Shdr *)(o + eh->e_shoff);
    if (eh->e_shstrndx >= eh->e_shnum)
        return -1;
    shstr = &sh[eh->e_shstrndx];
    if (shstr->sh_offset > olen || shstr->sh_size > olen - shstr->sh_offset)
        return -1;
    shstrtab = (const char *)(o + shstr->sh_offset);

    for (int i = 0; i < eh->e_shnum; i++) {
        const char *name;

        if (sh[i].sh_offset > olen || sh[i].sh_size > olen - sh[i].sh_offset)
            continue;
        /* R21b: sh_name is an offset into the string table — bound it to
         * the table and require a NUL within it before strcmp can read
         * past the embedded blob */
        if (sh[i].sh_name >= shstr->sh_size)
            continue;
        name = shstrtab + sh[i].sh_name;
        if (!memchr(name, '\0', shstr->sh_size - sh[i].sh_name))
            continue;
        if (strcmp(name, "classifier") == 0) {
            /* the kernel reads insns as (cnt * sizeof insn) bytes; a
             * trailing partial instruction would be loaded silently —
             * reject it explicitly instead of truncating */
            if (sh[i].sh_size % sizeof(struct bpf_insn) != 0) {
                log_err("tun steering: classifier section is %zu bytes, "
                        "not a multiple of %zu", (size_t)sh[i].sh_size,
                        sizeof(struct bpf_insn));
                return -1;
            }
            insns = (const struct bpf_insn *)(o + sh[i].sh_offset);
            insn_cnt = (unsigned int)(sh[i].sh_size /
                                      sizeof(struct bpf_insn));
        } else if (strcmp(name, "license") == 0) {
            /* bpf syscall expects a NUL-terminated license string; the
             * section data must carry the terminator inside the blob */
            if (!memchr(o + sh[i].sh_offset, '\0', sh[i].sh_size)) {
                log_err("tun steering: license section is not "
                        "NUL-terminated");
                return -1;
            }
            license = (const char *)(o + sh[i].sh_offset);
        }
    }
    if (!insns || insn_cnt == 0)
        return -1;

    prog_fd = bpf_prog_load_steer(insns, insn_cnt, license);
    if (prog_fd < 0)
        return -1;
    rc = ioctl(tun_fd, TUNSETSTEERINGEBPF, &prog_fd);
    close(prog_fd);
    if (rc < 0)
        log_err("tun steering attach: %s", strerror(errno));
    return rc < 0 ? -1 : 0;
#else
    /* IWAN_NO_STEER_BPF: no embedded program; the tun automq flow hash
     * is used instead (matches the tun_win.c behavior). */
    (void)tun_fd;
    return -1;
#endif
}

#else /* !__linux__ */
/* Non-Linux backends (tun_mac.c) have no steering program. */
int tun_steering_attach(int tun_fd)
{
    (void)tun_fd;
    return -1;
}
#endif /* __linux__ */

void tun_close(int fd) {
    close(fd);
}

/* Pre-open up to `maxn` extra queue fds for an existing IFF_MULTI_QUEUE
 * device. The server calls this while still root (CAP_NET_ADMIN held,
 * before fork+setuid) so the queue fan-out actually exists in the
 * unprivileged child; after the privilege drop /dev/net/tun open+TUNSETIFF
 * would fail EPERM and the pool would degrade to a single queue. Stops at
 * the first failure; returns the number actually opened. On non-Linux
 * backends tun_attach returns -1, so this yields 0 and callers fall back to
 * attaching after the pool starts (unchanged behavior). */
int tun_attach_many(const char *name, int *fds, int maxn)
{
    int n = 0;

    while (n < maxn) {
        int fd = tun_attach(name);
        if (fd < 0)
            break;
        fds[n++] = fd;
    }
    return n;
}

/* R37 WG-E2 (R3-L6): the old set_nonblock() swallowed fcntl failures, so a
 * queue fd could silently stay BLOCKING. A blocking reader parks in read()
 * once the device queue is drained and then never looks at q->stop /
 * pool->abort again, which makes tun_pool_destroy()'s pthread_join hang
 * forever (the process can no longer exit). Returns 0 only when O_NONBLOCK
 * is verifiably in effect; -1 with errno set otherwise. */
static int set_nonblock_checked(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (!(flags & O_NONBLOCK)) {
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
            return -1;
        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0)
            return -1;
    }
    if (!(flags & O_NONBLOCK)) {
        errno = EINVAL;   /* flag accepted but not applied: fail closed */
        return -1;
    }
    return 0;
}

void set_nonblock(int fd) {
    if (set_nonblock_checked(fd) != 0)
        log_err("tun: cannot set O_NONBLOCK on fd %d: %s", fd,
                strerror(errno));
}

ptrdiff_t tun_write(int fd, const void *buf, size_t len) {
#if defined(__APPLE__)
    /* utun frames carry a 4-byte address-family header on BOTH
     * directions, in NETWORK byte order (AF_INET=2 -> 00 00 00 02).
     * Verified empirically on a macOS 14 runner: a native-order family
     * is silently discarded by the kernel while the network-order one
     * delivers (the common "native order" claim, wireguard-go's
     * nativeEndian included, does not hold for the utun control
     * socket). The datagram is all-or-nothing, so report only the
     * payload length consumed to keep tun_write_retry's partial-write
     * arithmetic intact. */
    static _Thread_local uint8_t wbuf[4 + 65536];
    /* XNU's max datagram for the utun control socket is 65536 bytes
     * INCLUDING the 4-byte address-family header, so the true maximum
     * payload is 65532; a 65533..65536 payload would be rejected as
     * EMSGSIZE by the kernel and take the session down. */
    if (len == 0 || len > 65536 - 4) {
        errno = len ? EMSGSIZE : EINVAL;
        return -1;
    }
    uint32_t fam = htonl((((const uint8_t *)buf)[0] >> 4) == 6
                             ? (uint32_t)AF_INET6
                             : (uint32_t)AF_INET);
    memcpy(wbuf, &fam, sizeof fam);
    memcpy(wbuf + sizeof fam, buf, len);
    ssize_t w = write(fd, wbuf, len + sizeof fam);
    /* SOCK_DGRAM writes are normally all-or-nothing, but we must not
     * report a short positive write as a full send (fail closed). */
    if (w < 0)
        return -1;
    if ((size_t)w != len + sizeof fam) {
        errno = EIO;
        return -1;
    }
    return (ptrdiff_t)len;
#else
    return (ptrdiff_t)write(fd, buf, len);
#endif
}

int tun_write_retry(int fd, const uint8_t *pkt, size_t len, int max_ms,
                    atomic_bool *stop) {
    uint64_t t0 = now_ms();
    while (len > 0 && (stop == NULL || !*stop)) {
        ptrdiff_t w = tun_write(fd, pkt, len);
        if (w > 0) {
            pkt += w;
            len -= (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR) {
            /* R37 WG-E2 (R3-L8): this retry used to `continue` past the
             * max_ms budget check below, so a permanent EINTR made the
             * 50ms bound (and its "still full after the bound: dropped"
             * contract) unenforceable — measured >3s for a 50ms budget
             * with a reader keeping the pipe drained. Check the same
             * budget here. */
            if (max_ms > 0 && now_ms() - t0 >= (uint64_t)max_ms)
                return -1;   /* interrupted past the bound: dropped */
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            uint64_t now = now_ms();
            if (max_ms > 0 && now - t0 >= (uint64_t)max_ms)
                return -1; /* still full after the bound: dropped */
            int to = max_ms > 0
                         ? (int)((uint64_t)max_ms - (now - t0))
                         : 100;
            if (to < 1)
                to = 1;
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            int pr = poll(&pfd, 1, to);
            /* NOTE: no usleep after a writable poll. The original
             * 1ms sleep per EAGAIN cost the single-threaded server
             * main loop 1-3ms per congested packet (three orders of
             * magnitude off its ~360k pps drain), turning a transient
             * TUN backlog into guaranteed UDP rcvbuf overflow and an
             * RTO storm on the far side. poll() already waited; just
             * retry the write. */
            (void)pr;
            continue;
        }
        return -1; /* fatal; errno preserved */
    }
    return len == 0 ? 0 : -1;
}

/* ---- generic IFF_MULTI_QUEUE reader pool ----
 * One device, up to TUN_POOL_MAX queue fds, each drained by its own
 * thread. tun_pool_tick (500ms) grows/shrinks the pool with TCP-style
 * AIMD on the poll-timeout busy signal. Callbacks may run concurrently
 * on different queues; per-queue ordering is preserved by the kernel's
 * flow-hash steering. */
#define TUN_QCTL_MS TUN_POOL_TICK_MS
#define TUN_POLL_MS 100   /* tun reader poll timeout; the AIMD busy ratio
                           * below divides by it, so the two stay in
                           * lockstep */
#define TUN_BUSY_GROW 0.85
#define TUN_BUSY_SHRINK 0.60

/* queue index of the calling reader thread (0..pool size-1), set once at
 * thread start; consumers (the server's per-reader downlink fd + batch
 * state) read it inside the packet callback. Always 0 on Windows (the
 * wintun pool is single-queue and never sets it). */
static _Thread_local int t_reader_qid;

int tun_reader_qid(void)
{
    return t_reader_qid;
}

struct tun_queue {
    struct tun_pool *pool;
    int fd;
    pthread_t th;
    _Atomic int stop;   /* R30-f2E: atomic so the reader thread and uplink
                          * writers never race the pool owner's del/destroy */
    _Atomic int dead;   /* R54-WG3-1: set by the reader thread when it exits
                          * WITHOUT a pool-owner stop (its queue fd died:
                          * POLLHUP/POLLERR after an external device
                          * deletion, or a hard poll error). tun_pool_tick
                          * consults it before the AIMD grow (growing would
                          * re-create the vanished device under the same
                          * name and mask the caller's dead-tunnel probe),
                          * and tun_pool_readers_lost() reports it to the
                          * server's fail-fast probe. tun_pool_add_fd
                          * re-arms the slot to 0 when a new reader starts
                          * in it (shrink-then-grow slot reuse). */
    atomic_uint_fast64_t waits; /* poll timeouts in current window */
};

struct tun_pool {
    struct tun_queue qs[TUN_POOL_MAX];
    tun_pkt_fn cb;
    void *ud;
    atomic_bool *abort;
    _Atomic tun_exit_fn exit_cb;   /* per-reader-thread cleanup, may be NULL */
    atomic_int nq;         /* live queue count; read by uplink writers
                            * (server recv threads), written by the
                            * pool owner (tun_pool_tick) */
    atomic_uint_fast64_t wstall; /* uplink write stalls since last tick:
                            * writers signal congestion so the AIMD
                            * never shrinks the pool under upload load
                            * (write-side fan-out must not collapse) */
    pthread_rwlock_t rw;   /* R54-WG3-3: bounds the writer-fd TOCTOU once
                            * and for all. Uplink writers (tun_pool_write)
                            * hold the READ side across the entire device
                            * write; tun_pool_del / tun_pool_destroy close
                            * the extra queue fds holding the WRITE side.
                            * A closed-and-recycled fd number can therefore
                            * never be hit by an in-flight write: the close
                            * cannot even start until every writer that
                            * selected the queue has released its read
                            * lock. Always taken by the pool owner thread
                            * (tick) or by writers — never by reader
                            * threads, whose exit path does not touch it. */
    int maxq;
    int slow_start;   /* AIMD state: slow-start phase flag */
    int idle_cycles;  /* consecutive idle ticks before shrink */
    char tunname[IFNAMSIZ];
};

static void *tun_reader_main(void *ud)
{
    struct tun_queue *q = ud;
    struct tun_pool *pool = q->pool;
    struct pollfd pfd = { .fd = q->fd, .events = POLLIN };
    static _Thread_local uint8_t buf[65536];

    t_reader_qid = (int)(q - pool->qs);
    while (!atomic_load_explicit(&q->stop, memory_order_acquire) &&
       (pool->abort == NULL || !*pool->abort)) {
        int pr = poll(&pfd, 1, TUN_POLL_MS);
        if (pr < 0 && errno != EINTR) {
            /* R54-WG3-1: hard poll error on a pool fd without a
             * pool-owner stop = the queue is gone (same class as the
             * POLLHUP path below). Mark it dead so tun_pool_tick never
             * grows onto a vanished device. */
            atomic_store_explicit(&q->dead, 1, memory_order_release);
            break;
        }
        if (pr == 0) {
            atomic_fetch_add(&q->waits, 1);
            continue;
        }
        if (pfd.revents & POLLIN) {
            ssize_t r;
            uint64_t woke = now_ms();
            int npk = 0;
            while ((r = read(q->fd, buf, sizeof buf)) > 0) {
#if defined(__APPLE__)
                /* strip utun's 4-byte address-family header here,
                 * before any downstream slot-size guard can see the
                 * inflated length (see tun_write for the framing) */
                if ((size_t)r <= 4)
                    continue;
                r -= 4;
                memmove(buf, buf + 4, (size_t)r);
#endif
                pool->cb(pool->ud, buf, (size_t)r, false);
                npk++;
            }
            /* flush signal: batch-oriented callbacks send their partial
             * batch instead of holding it until the next wake */
            pool->cb(pool->ud, NULL, 0, true);
            /* diagnostic (IWAN_DEBUG=1): reader wake -> drain latency.
             * A late wake (poll slept far past the packet's arrival) or a
             * slow drain pinpoints the downlink (ACK) path delay. */
            if (debug_enabled() && npk > 0) {
                static _Thread_local uint64_t last_print;
                if (woke - last_print >= 250) {
                    last_print = woke;
                    fprintf(stderr,
                            "[reader] q=%ld wake=%llu pkts=%d "
                            "last_poll_was_%s\n",
                            (long)(q - pool->qs),
                            (unsigned long long)woke, npk,
                            pr == 0 ? "timeout" : "event");
                }
            }
        }
        /* Device deleted (e.g. `ip link del`): poll then reports
         * POLLHUP|POLLERR immediately on every call, so without this
         * the reader would busy-spin forever. POLLIN is drained first
         * above, so any data queued before deletion is still delivered
         * (on deletion the kernel sets POLLIN|POLLHUP together); the
         * read below then confirms the end of the fd (0 = EOF, < 0 =
         * error) before exiting. */
        if (pfd.revents & (POLLERR | POLLHUP)) {
            ssize_t r = read(q->fd, buf, sizeof buf);
            if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                log_debug("tun reader q=%ld: fd gone (%s)",
                          (long)(q - pool->qs), strerror(errno));
            /* R54-WG3-1: this exit has NO pool-owner stop — the queue's
             * device fd died under us, which for a pool-owned tun means
             * external deletion (`ip link del`, netns teardown, driver
             * unload). Publish dead BEFORE leaving so tun_pool_tick can
             * tell "quietly empty queues" (legitimate AIMD grow: readers
             * alive and just idle) apart from "readers have vanished"
             * (device gone: growing would re-create the same-named device
             * and mask the caller's dead-tunnel probe). Reader threads
             * exited by tun_pool_del / destroy always carry stop==1 and
             * never take this branch. */
            atomic_store_explicit(&q->dead, 1, memory_order_release);
            break;
        }
    }
    /* drain the ring before exiting: packets already queued on this fd
     * would otherwise be lost when the pool detaches+closes it, stalling
     * the client flow until TCP RTO retransmits */
    while (!(pool->abort != NULL && *pool->abort)) {
        ssize_t r = read(q->fd, buf, sizeof buf);
        if (r <= 0)
            break;
#if defined(__APPLE__)
        if ((size_t)r <= 4)
            continue;
        r -= 4;
        memmove(buf, buf + 4, (size_t)r);
#endif
        pool->cb(pool->ud, buf, (size_t)r, false);
    }
    if (!(pool->abort != NULL && *pool->abort))
        pool->cb(pool->ud, NULL, 0, true);
    /* per-thread cleanup runs on this exiting reader thread, strictly
     * after the final flush callback, so a batch-oriented callback can
     * still use its TLS buffer until here (client pump frees its batch) */
    tun_exit_fn ec = atomic_load_explicit(&pool->exit_cb,
                                          memory_order_acquire);
    if (ec)
        ec();
    return NULL;
}

/* start a reader thread on an already-open queue fd and publish it as
 * the newest pool queue. On success the pool owns `fd` (as an extra
 * queue, later closed by tun_pool_destroy/del). On failure `fd` is NOT
 * closed here — the caller keeps ownership and must close it (this keeps
 * the pre-opened-fd path free of double-close when create_pre bins the
 * leftovers). */
static int tun_pool_add_fd(struct tun_pool *pool, int fd)
{
    int nq = atomic_load(&pool->nq);

    if (nq >= pool->maxq)
        return -1;
    if (set_nonblock_checked(fd) != 0) {
        log_err("tun pool: fd %d cannot be switched to nonblocking (%s); "
                "refusing a reader that could block in read() forever",
                fd, strerror(errno));
        return -1;
    }
    {
        struct tun_queue *q = &pool->qs[nq];
        q->pool = pool;
        q->fd = fd;
        atomic_store_explicit(&q->stop, 0, memory_order_relaxed);
        /* R54-WG3-1: a slot whose previous reader died (dead==1) is
         * reusable after the pool removed it (shrink): a fresh reader
         * must not inherit the stale dead mark or every later tick would
         * refuse to grow and tun_pool_readers_lost() would report a
         * phantom loss. */
        atomic_store_explicit(&q->dead, 0, memory_order_relaxed);
        atomic_store(&q->waits, 0);
        if (pthread_create(&q->th, NULL, tun_reader_main, q) != 0)
            return -1;
    }
    atomic_store(&pool->nq, nq + 1);
    return 0;
}

/* attach one extra queue the ordinary way (needs CAP_NET_ADMIN /
 * /dev/net/tun access at call time) and add it to the pool */
static int tun_pool_add(struct tun_pool *pool)
{
    int fd;

    if (atomic_load(&pool->nq) >= pool->maxq)
        return -1;
    fd = tun_attach(pool->tunname);
    if (fd < 0)
        return -1;
    if (tun_pool_add_fd(pool, fd) != 0) {
        close(fd);   /* ownership stayed with us on failure */
        return -1;
    }
    return 0;
}

/* drop the newest queue; queue 0 (the device owner) is never dropped.
 * The nq store happens BEFORE pthread_join: once nq no longer includes
 * this queue, a concurrent uplink writer (tun_pool_write_fd, tid % nq)
 * can no longer select its fd, so nothing writes to the fd after this.
 * join waits for the reader thread to leave the fd, then detach/close
 * are safe (M3, bughunt: the old order joined first and left the fd
 * selectable-and-going-away during the wait). */
static void tun_pool_del(struct tun_pool *pool)
{
    int i;

    if (atomic_load(&pool->nq) <= 1)
        return;
    i = atomic_load(&pool->nq) - 1;
    atomic_store_explicit(&pool->qs[i].stop, 1,
                          memory_order_relaxed);
    atomic_store(&pool->nq, i);
    pthread_join(pool->qs[i].th, NULL);
    /* R54-WG3-3 (writer-fd TOCTOU): from the nq publish above no NEW
     * uplink writer can select queue i (writers spread across tid % nq
     * and i is now out of range). A writer that had already read the old
     * nq and selected i is either (a) still writing under the pool's
     * read lock — the write lock below waits for it, so its write lands
     * on the still-open fd and only then do we close — or (b) already
     * dropped on stop==1. Under this ordering the close can never be
     * followed by a stale writer write to a recycled fd number: the
     * detach/close hold the write lock, and every writer holds the read
     * lock across the whole write (tun_pool_write). The join stays
     * BEFORE the lock: it only waits for the reader thread to leave the
     * fd (never touches rw), so the lock is held just for the two ioctl/
     * close syscalls, never across a thread join. */
    pthread_rwlock_wrlock(&pool->rw);
    tun_detach(pool->qs[i].fd);
    tun_close(pool->qs[i].fd);
    pthread_rwlock_unlock(&pool->rw);
}

struct tun_pool *tun_pool_create_pre(const char *name, int fd0, int maxq,
                                     int initq, const int *prefds, int npre,
                                     tun_pkt_fn cb, void *ud,
                                     atomic_bool *abort)
{
    struct tun_pool *pool = calloc(1, sizeof *pool);
    struct tun_queue *q;
    int pi = 0;   /* index of the next pre-opened fd to consume */

    if (!pool)
        return NULL;
    if (pthread_rwlock_init(&pool->rw, NULL) != 0) {
        free(pool);
        return NULL;
    }
    pool->cb = cb;
    pool->ud = ud;
    pool->abort = abort;
    atomic_init(&pool->exit_cb, NULL);
    pool->maxq = maxq > TUN_POOL_MAX ? TUN_POOL_MAX : (maxq < 1 ? 1 : maxq);
    snprintf(pool->tunname, sizeof pool->tunname, "%s", name);
    q = &pool->qs[0];
    q->pool = pool;
    q->fd = fd0;
    q->stop = 0;
    q->dead = 0;   /* R54-WG3-1: queue 0 must not start as "lost" */
    atomic_store(&q->waits, 0);
    /* R37 WG-E2 (R3-L6): the pool owns fd0's reader from here on; if the
     * fd cannot be made nonblocking the reader would block in read() and
     * tun_pool_destroy() would never join it, so refuse to start. */
    if (set_nonblock_checked(fd0) != 0) {
        log_err("tun pool: fd %d cannot be switched to nonblocking (%s); "
                "refusing to start a reader that could block in read() "
                "forever", fd0, strerror(errno));
        pthread_rwlock_destroy(&pool->rw);
        free(pool);
        return NULL;
    }
    if (pthread_create(&q->th, NULL, tun_reader_main, q) != 0) {
        pthread_rwlock_destroy(&pool->rw);
        free(pool);
        return NULL;
    }
    atomic_store(&pool->nq, 1);
    pool->slow_start = 1;
    pool->idle_cycles = 0;
    /* eager start: reach initq-1 extra queues up front (used by the
     * client pump, whose bulk uplink would otherwise make the AIMD hunt
     * between the single-queue and multi-queue capacities). Prefer the
     * caller's pre-opened queue fds (taken, not attached) — the server
     * opened them while still root so the unprivileged child can keep a
     * real multi-queue fan-out; any shortfall then falls back to
     * tun_attach for deployments that still have the capability at pool
     * time (non-root servers that own /dev/net/tun, clients). */
    if (initq > pool->maxq)
        initq = pool->maxq;
    /* first consume the pre-opened fds; ownership of all `prefds`
     * transfers to the pool (any left over are closed here) */
    while (atomic_load(&pool->nq) < initq && prefds && pi < npre) {
        if (tun_pool_add_fd(pool, prefds[pi]) != 0)
            break;
        pi++;
    }
    for (; pi < npre; pi++)
        close(prefds[pi]);   /* hand back unused pre-opened fds */
    /* then attach any still-needed extra queues the ordinary way */
    while (atomic_load(&pool->nq) < initq) {
        if (tun_pool_add(pool) != 0)
            break;
    }
    return pool;
}

struct tun_pool *tun_pool_create(const char *name, int fd0, int maxq,
                                 int initq, tun_pkt_fn cb, void *ud,
                                 atomic_bool *abort)
{
    /* no pre-opened fds: same eager fill via tun_pool_add as before */
    return tun_pool_create_pre(name, fd0, maxq, initq, NULL, 0,
                               cb, ud, abort);
}

int tun_pool_queues(const struct tun_pool *pool)
{
    return atomic_load(&pool->nq);
}

/* Select the queue fd an uplink writer (recv thread `tid`) should use:
 * writers spread across the pool's queue fds so the single device
 * write lock no longer serializes every uplink frame (measured: TUN
 * write was 85-90% of per-frame cost at >5 Gbit/s aggregate). The pool
 * owner may grow/shrink nq concurrently; the load is atomic and a
 * writer can only observe fds that are fully initialized (add fills
 * the slot before publishing nq; del publishes the smaller nq before
 * closing). -1 when the pool is empty. */
int tun_pool_write_fd(const struct tun_pool *pool, unsigned tid)
{
    /* R30-f2E: tun_pool_del marks the last queue stop==1 BEFORE publishing
     * the smaller nq and closing it — retrying with the fresh nq closes the
     * classic "loaded old nq then used the just-removed fd" TOCTOU window.
     * (The stop flag is atomic; a reader that raced a del can still get an
     * EBADF in the tiny gap before close, which the caller treats as a
     * transient drop — this removes the deterministic reuse-of-removed-fd.)
     * R54-WG3-3: this API returns a raw fd, so it CANNOT hold the pool's
     * read lock across the caller's write; the residual window (del closes
     * the fd after we return it, the fd number is recycled by a concurrent
     * open, and our write lands on an unrelated socket) is real. The
     * server no longer calls it — uplink writes go through tun_pool_write,
     * which performs the write under the pool lock and makes that window
     * unreachable. Kept for callers that need the raw fd and accept the
     * documented transient-drop contract. */
    for (int attempt = 0; attempt < 2; attempt++) {
        int nq = atomic_load(&pool->nq);
        if (nq <= 0)
            return -1;
        const struct tun_queue *q = &pool->qs[tid % (unsigned)nq];
        if (!atomic_load_explicit(&q->stop, memory_order_acquire))
            return q->fd;
    }
    return -1;   /* still pointing at a queue being removed: caller drops */
}

/* R54-WG3-3: lock-protected uplink write — the server's ONLY pool write
 * path. Selects the queue fd for uplink writer `tid` exactly like
 * tun_pool_write_fd, but performs the whole tun_write_retry while holding
 * the pool's read lock, and tun_pool_del / tun_pool_destroy close queue
 * fds under the write lock. Static argument that a stale write can then
 * never hit a closed-and-recycled fd number:
 *   - while the write runs, del's close cannot even start (write lock
 *     acquisition blocks until we release the read lock), so the fd is
 *     open for the whole write — the byte we write goes to the tun device
 *     and nothing else;
 *   - once del's close has run, every writer that selected that queue has
 *     already released its read lock (that is the only way del obtained
 *     the write lock), and no NEW writer can select the removed queue
 *     because nq no longer includes it (writers spread across tid % nq).
 * A lock-free epoch counter cannot give this guarantee: the writer could
 * only compare epochs before/after the write syscall, leaving the syscall
 * itself as a window in which the fd could be closed+reused; mutual
 * exclusion is the only way to bind fd validity to the write itself.
 * Returns tun_write_retry's result: 0 fully written, -1 transient drop
 * (persistent EAGAIN past max_ms, or EBADF-class fd death — serving the
 * same "drop, the client retransmits" contract as before). */
int tun_pool_write(struct tun_pool *pool, unsigned tid,
                   const uint8_t *pkt, size_t len, int max_ms)
{
    int r;

    if (!pool)
        return -1;
    pthread_rwlock_rdlock(&pool->rw);
    int nq = atomic_load(&pool->nq);
    if (nq <= 0) {
        pthread_rwlock_unlock(&pool->rw);
        return -1;
    }
    const struct tun_queue *q = &pool->qs[tid % (unsigned)nq];
    if (atomic_load_explicit(&q->stop, memory_order_acquire)) {
        /* Defensive only: under the read lock a completed del already
         * excluded this queue from nq (del publishes nq before taking the
         * write lock), so a stop==1 queue inside [0, nq) is unobservable —
         * this guards against future ownership patterns, not today's. */
        pthread_rwlock_unlock(&pool->rw);
        return -1;
    }
    r = tun_write_retry(q->fd, pkt, len, max_ms, NULL);
    pthread_rwlock_unlock(&pool->rw);
    return r;
}

/* R54-WG3-1: count pool queues whose reader exited unexpectedly (dead
 * mark set). The server's fail-fast probe reads this once per second as
 * an INDEPENDENT death signal: after an external device deletion every
 * reader gets POLLHUP and exits with stop==0, so this is >0 even in the
 * sub-second window before if_nametoindex runs — and, crucially, even if
 * a racing tun_pool_tick grow already re-created the same-named device
 * (the dead reader marks stay in the pool, so the recreation cannot hide
 * the loss from this probe). Normal pool death (del/destroy stop, then
 * join) never sets the mark. */
int tun_pool_readers_lost(const struct tun_pool *pool)
{
    int nq, lost = 0;

    if (!pool)
        return 0;
    nq = atomic_load(&pool->nq);
    for (int i = 0; i < nq; i++)
        if (atomic_load_explicit(&pool->qs[i].dead, memory_order_acquire))
            lost++;
    return lost;
}

/* An uplink writer hit the device queue (EAGAIN / write-budget expiry):
 * record the congestion so the next tun_pool_tick treats the pool as
 * busy and never shrinks the write fan-out under upload load. */
void tun_pool_note_stall(struct tun_pool *pool)
{
    if (pool)
        atomic_fetch_add(&pool->wstall, 1);
}

void tun_pool_set_exit_cb(struct tun_pool *pool, tun_exit_fn cb)
{
    if (pool)
        atomic_store_explicit(&pool->exit_cb, cb, memory_order_release);
}

void tun_pool_destroy(struct tun_pool *pool)
{
    int i;
    if (!pool)
        return;   /* must precede any deref: no-tun servers pass NULL */
    int nq = atomic_load(&pool->nq);
    for (i = 0; i < nq; i++)
        atomic_store_explicit(&pool->qs[i].stop, 1,
                          memory_order_relaxed);
    for (i = 0; i < nq; i++)
        pthread_join(pool->qs[i].th, NULL);
    /* R54-WG3-3: close the extra queue fds under the write lock so a
     * concurrently writing tun_pool_write (in a caller that tears the
     * pool down before joining its writers) can never hit a closed-and-
     * recycled fd. The server joins its recv threads first, so this is
     * normally uncontended. */
    pthread_rwlock_wrlock(&pool->rw);
    for (i = 1; i < nq; i++) {
        tun_detach(pool->qs[i].fd);
        tun_close(pool->qs[i].fd);
    }
    pthread_rwlock_unlock(&pool->rw);
    pthread_rwlock_destroy(&pool->rw);
    free(pool);
}

/* AIMD controller: poll-timeout busy signal drives queue count */
void tun_pool_tick(struct tun_pool *pool)
{
    uint64_t wsum = 0;
    double busy;
    int target;
    int nq = atomic_load(&pool->nq);

    /* R54-WG3-1: unexpected reader exits (dead marks) mean the device fds
     * died without a pool-owner stop — external `ip link del`, netns
     * teardown, driver unload. The wait-based busy signal then reads
     * "no poll ever timed out" as busy=1.0 and would GROW: tun_pool_add ->
     * tun_attach would re-create a fresh device with the same name, attach
     * a new reader, and the caller's if_nametoindex dead-tunnel probe
     * would see a live index again — the deleted tunnel "resurrects" as a
     * nameless, route-less device while keepalives still look alive,
     * masking the R43-C1-L1 fail-fast. Refuse BOTH grow and shrink while
     * any in-range reader is dead: growing would mask the loss, shrinking
     * would merely drop queues whose fd is already gone, and every
     * legitimate queue death sets stop (del/destroy) and never reaches
     * this branch — so AIMD grow under load (all readers alive polling)
     * is untouched. The server's probe exits the process promptly; this
     * guard is what prevents the rebuild in the window before that. */
    {
        int dead = 0;
        for (int i = 0; i < nq; i++)
            if (atomic_load_explicit(&pool->qs[i].dead,
                                     memory_order_acquire))
                dead++;
        if (dead > 0) {
            fprintf(stderr,
                    "tun reader pool: %d reader(s) lost without a pool "
                    "stop (device deleted?); refusing AIMD resize\n",
                    dead);
            return;   /* leave waits/wstall accounting untouched */
        }
    }

    for (int i = 0; i < nq; i++)
        wsum += atomic_exchange(&pool->qs[i].waits, 0);
    busy = 1.0 - (double)wsum /
                  ((double)TUN_QCTL_MS / (double)TUN_POLL_MS *
                   (double)nq);
    /* uplink writers stalled since the last tick (write EAGAIN / budget
     * expiry): treat the pool as busy so the fan-out never shrinks while
     * uploads are actively congesting the device queue */
    if (atomic_exchange(&pool->wstall, 0) > 0)
        busy = 1;
    if (busy < 0)
        busy = 0;
    if (busy > 1)
        busy = 1;

    target = nq;
    if (busy > TUN_BUSY_GROW) {
        pool->idle_cycles = 0;
        if (pool->slow_start) {
            target = nq * 2;
            if (target >= 4)
                pool->slow_start = 0;
        } else {
            target = nq + 1;
        }
    } else if (busy < TUN_BUSY_SHRINK) {
        pool->idle_cycles++;
        if (pool->idle_cycles >= 4 && nq > 1) {
            /* conservative shrink: only after 2s of sustained idle, so
             * brief load gaps (test pauses, app think time) do not drop
             * queued packets of live flows */
            target = nq / 2;
            if (target < 1)
                target = 1;
            pool->idle_cycles = 0;
        }
    } else {
        pool->idle_cycles = 0;
    }
    if (target > pool->maxq)
        target = pool->maxq;

    while (atomic_load(&pool->nq) < target) {
        if (tun_pool_add(pool) != 0)
            break;
        fprintf(stderr, "tun reader pool: %d queues\n",
                atomic_load(&pool->nq));
    }
    while (atomic_load(&pool->nq) > target &&
           atomic_load(&pool->nq) > 1) {
        tun_pool_del(pool);
        fprintf(stderr, "tun reader pool: %d queues\n",
                atomic_load(&pool->nq));
    }
}
