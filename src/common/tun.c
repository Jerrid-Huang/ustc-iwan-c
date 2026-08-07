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

int open_tun(const char *name) {
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
 * The program is embedded (steer_bpf.o, linked with -r -b binary). */

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
            log_debug("bpf load: %s", log);
    }
    if (fd < 0)
        log_debug("bpf load failed: %s", strerror(errno));
    return fd;
}

int tun_steering_attach(int tun_fd)
{
    extern const unsigned char steer_bpf_o[];
    extern const unsigned int steer_bpf_o_len;
    const unsigned char *o = steer_bpf_o;
    size_t olen = steer_bpf_o_len;
    const Elf64_Ehdr *eh;
    const Elf64_Shdr *sh, *shstr;
    const char *shstrtab;
    const struct bpf_insn *insns = NULL;
    unsigned int insn_cnt = 0;
    const char *license = "GPL";
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
        const char *name = shstrtab + sh[i].sh_name;
        if (sh[i].sh_offset + sh[i].sh_size > olen)
            continue;
        if (strcmp(name, "classifier") == 0) {
            insns = (const struct bpf_insn *)(o + sh[i].sh_offset);
            insn_cnt = (unsigned int)(sh[i].sh_size /
                                      sizeof(struct bpf_insn));
        } else if (strcmp(name, "license") == 0) {
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
        log_debug("tun steering attach: %s", strerror(errno));
    return rc < 0 ? -1 : 0;
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

int tun_write_retry(int fd, const uint8_t *pkt, size_t len, int max_ms,
                    volatile sig_atomic_t *stop) {
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
            /* if poll claims writable but EAGAIN persists, back off
             * briefly instead of busy-spinning */
            if (pr > 0 && (pfd.revents & POLLOUT))
                usleep(1000);
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
    volatile sig_atomic_t *abort;
    int nq;
    int maxq;
    char tunname[IFNAMSIZ];
};

static void *tun_reader_main(void *ud)
{
    struct tun_queue *q = ud;
    struct tun_pool *pool = q->pool;
    struct pollfd pfd = { .fd = q->fd, .events = POLLIN };
    static _Thread_local uint8_t buf[65536];

    while (!q->stop && (pool->abort == NULL || !*pool->abort)) {
        int pr = poll(&pfd, 1, 100);
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
                                 volatile sig_atomic_t *abort)
{
    struct tun_pool *pool = calloc(1, sizeof *pool);
    struct tun_queue *q;

    if (!pool)
        return NULL;
    pool->cb = cb;
    pool->ud = ud;
    pool->abort = abort;
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
    static int slow_start = 1;
    static int idle_cycles = 0;
    uint64_t wsum = 0;
    double busy;
    int target;

    for (int i = 0; i < pool->nq; i++)
        wsum += atomic_exchange(&pool->qs[i].waits, 0);
    busy = 1.0 - (double)wsum /
                  ((double)TUN_QCTL_MS / 100.0 * (double)pool->nq);
    if (busy < 0)
        busy = 0;
    if (busy > 1)
        busy = 1;

    target = pool->nq;
    if (busy > TUN_BUSY_GROW) {
        idle_cycles = 0;
        if (slow_start) {
            target = pool->nq * 2;
            if (target >= 4)
                slow_start = 0;
        } else {
            target = pool->nq + 1;
        }
    } else if (busy < TUN_BUSY_SHRINK) {
        idle_cycles++;
        if (idle_cycles >= 4 && pool->nq > 1) {
            /* conservative shrink: only after 2s of sustained idle, so
             * brief load gaps (test pauses, app think time) do not drop
             * queued packets of live flows */
            target = pool->nq / 2;
            if (target < 1)
                target = 1;
            idle_cycles = 0;
        }
    } else {
        idle_cycles = 0;
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
