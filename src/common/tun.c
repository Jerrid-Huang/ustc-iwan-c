#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "common.h"
#include "tun.h"
#include "util.h"

/* tun_name_valid lives in tun.h (static inline): both the Linux and the
 * Windows backend share the same device-name rule set. */

int open_tun(const char *name) {
    if (!tun_name_valid(name))
        return -1;
    int fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr;
    if (fd < 0)
        return -1;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    /* the TUN receive queue carries the peer kernel's ACK stream: the
     * default rcvbuf (~212KB) overflows in ~2ms under a high-rate
     * upload burst and TCP ACKs are never retransmitted, so every
     * overflowed ACK forces a full RTO recovery on the far side.
     * Match the UDP session buffers (4MiB) so the reader pool can
     * drain bursts instead of the kernel dropping them. */
    int sz = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    return fd;
}

/* attach another queue fd to an existing IFF_MULTI_QUEUE device */
int tun_attach(const char *name) {
    return open_tun(name);
}

void tun_detach(int fd) {
    ioctl(fd, TUNSETQUEUE, (void *)(long)IFF_DETACH_QUEUE);
}

/* ---- tun steering eBPF ----
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
    char log[4096];
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
    if (eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf64_Shdr) > olen)
        return -1;
    sh = (const Elf64_Shdr *)(o + eh->e_shoff);
    if (eh->e_shstrndx >= eh->e_shnum)
        return -1;
    shstr = &sh[eh->e_shstrndx];
    if (shstr->sh_offset + shstr->sh_size > olen)
        return -1;
    shstrtab = (const char *)(o + shstr->sh_offset);

    for (int i = 0; i < eh->e_shnum; i++) {
        const char *name;

        if (sh[i].sh_offset + sh[i].sh_size > olen)
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

void tun_close(int fd) {
    close(fd);
}

void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

ptrdiff_t tun_write(int fd, const void *buf, size_t len) {
    return (ptrdiff_t)write(fd, buf, len);
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
        if (w < 0 && errno == EINTR)
            continue;
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

struct tun_queue {
    struct tun_pool *pool;
    int fd;
    pthread_t th;
    volatile int stop;
    atomic_uint_fast64_t waits; /* poll timeouts in current window */
};

struct tun_pool {
    struct tun_queue qs[TUN_POOL_MAX];
    tun_pkt_fn cb;
    void *ud;
    atomic_bool *abort;
    tun_exit_fn exit_cb;   /* per-reader-thread cleanup, may be NULL */
    int nq;
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

    while (!q->stop && (pool->abort == NULL || !*pool->abort)) {
        int pr = poll(&pfd, 1, TUN_POLL_MS);
        if (pr < 0 && errno != EINTR)
            break;
        if (pr == 0) {
            atomic_fetch_add(&q->waits, 1);
            continue;
        }
        if (pfd.revents & POLLIN) {
            ssize_t r;
            uint64_t woke = now_ms();
            int npk = 0;
            while ((r = read(q->fd, buf, sizeof buf)) > 0) {
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
        pool->cb(pool->ud, buf, (size_t)r, false);
    }
    if (!(pool->abort != NULL && *pool->abort))
        pool->cb(pool->ud, NULL, 0, true);
    /* per-thread cleanup runs on this exiting reader thread, strictly
     * after the final flush callback, so a batch-oriented callback can
     * still use its TLS buffer until here (client pump frees its batch) */
    if (pool->exit_cb)
        pool->exit_cb();
    return NULL;
}

static int tun_pool_add(struct tun_pool *pool)
{
    int fd;

    if (pool->nq >= pool->maxq)
        return -1;
    fd = tun_attach(pool->tunname);
    if (fd < 0)
        return -1;
    set_nonblock(fd);
    {
        struct tun_queue *q = &pool->qs[pool->nq];
        q->pool = pool;
        q->fd = fd;
        q->stop = 0;
        atomic_store(&q->waits, 0);
        if (pthread_create(&q->th, NULL, tun_reader_main, q) != 0) {
            close(fd);
            return -1;
        }
    }
    pool->nq++;
    return 0;
}

/* drop the newest queue; queue 0 (the device owner) is never dropped */
static void tun_pool_del(struct tun_pool *pool)
{
    int i;

    if (pool->nq <= 1)
        return;
    i = pool->nq - 1;
    pool->qs[i].stop = 1;
    pthread_join(pool->qs[i].th, NULL);
    tun_detach(pool->qs[i].fd);
    tun_close(pool->qs[i].fd);
    pool->nq--;
}

struct tun_pool *tun_pool_create(const char *name, int fd0, int maxq,
                                 int initq, tun_pkt_fn cb, void *ud,
                                 atomic_bool *abort)
{
    struct tun_pool *pool = calloc(1, sizeof *pool);
    struct tun_queue *q;

    if (!pool)
        return NULL;
    pool->cb = cb;
    pool->ud = ud;
    pool->abort = abort;
    pool->exit_cb = NULL;
    pool->maxq = maxq > TUN_POOL_MAX ? TUN_POOL_MAX : (maxq < 1 ? 1 : maxq);
    snprintf(pool->tunname, sizeof pool->tunname, "%s", name);
    q = &pool->qs[0];
    q->pool = pool;
    q->fd = fd0;
    q->stop = 0;
    atomic_store(&q->waits, 0);
    if (pthread_create(&q->th, NULL, tun_reader_main, q) != 0) {
        free(pool);
        return NULL;
    }
    pool->nq = 1;
    pool->slow_start = 1;
    pool->idle_cycles = 0;
    /* eager start: attach initq-1 extra queues up front (used by the
     * client pump, whose bulk uplink would otherwise make the AIMD hunt
     * between the single-queue and multi-queue capacities) */
    if (initq > pool->maxq)
        initq = pool->maxq;
    while (pool->nq < initq) {
        if (tun_pool_add(pool) != 0)
            break;
    }
    return pool;
}

void tun_pool_set_exit_cb(struct tun_pool *pool, tun_exit_fn cb)
{
    if (pool)
        pool->exit_cb = cb;
}

void tun_pool_destroy(struct tun_pool *pool)
{
    int i;

    if (!pool)
        return;
    for (i = 0; i < pool->nq; i++)
        pool->qs[i].stop = 1;
    for (i = 0; i < pool->nq; i++)
        pthread_join(pool->qs[i].th, NULL);
    for (i = 1; i < pool->nq; i++) {
        tun_detach(pool->qs[i].fd);
        tun_close(pool->qs[i].fd);
    }
    free(pool);
}

/* AIMD controller: poll-timeout busy signal drives queue count */
void tun_pool_tick(struct tun_pool *pool)
{
    uint64_t wsum = 0;
    double busy;
    int target;

    for (int i = 0; i < pool->nq; i++)
        wsum += atomic_exchange(&pool->qs[i].waits, 0);
    busy = 1.0 - (double)wsum /
                  ((double)TUN_QCTL_MS / (double)TUN_POLL_MS *
                   (double)pool->nq);
    if (busy < 0)
        busy = 0;
    if (busy > 1)
        busy = 1;

    target = pool->nq;
    if (busy > TUN_BUSY_GROW) {
        pool->idle_cycles = 0;
        if (pool->slow_start) {
            target = pool->nq * 2;
            if (target >= 4)
                pool->slow_start = 0;
        } else {
            target = pool->nq + 1;
        }
    } else if (busy < TUN_BUSY_SHRINK) {
        pool->idle_cycles++;
        if (pool->idle_cycles >= 4 && pool->nq > 1) {
            /* conservative shrink: only after 2s of sustained idle, so
             * brief load gaps (test pauses, app think time) do not drop
             * queued packets of live flows */
            target = pool->nq / 2;
            if (target < 1)
                target = 1;
            pool->idle_cycles = 0;
        }
    } else {
        pool->idle_cycles = 0;
    }
    if (target > pool->maxq)
        target = pool->maxq;

    while (pool->nq < target) {
        if (tun_pool_add(pool) != 0)
            break;
        fprintf(stderr, "tun reader pool: %d queues\n", pool->nq);
    }
    while (pool->nq > target && pool->nq > 1) {
        tun_pool_del(pool);
        fprintf(stderr, "tun reader pool: %d queues\n", pool->nq);
    }
}
