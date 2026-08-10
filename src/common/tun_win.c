/* Windows (MinGW-w64) TUN backend: the wintun driver (wintun.dll).
 *
 * The wintun API is resolved at runtime with LoadLibraryA/GetProcAddress,
 * so the binary links and runs without the DLL present — only open_tun
 * fails then, with a message pointing at wintun.net. A wintun "adapter"
 * is a persistent virtual NIC created on demand; the "session" (ring
 * buffer) is the live data path, and there is exactly one session per
 * adapter. That single-queue reality shapes the tun.h shim:
 *   - tun_attach / tun_detach / set_nonblock / tun_steering_attach are
 *     no-ops (steering logs once, then returns -1);
 *   - the tun_pool reader pool collapses to ONE reader thread;
 *   - tun fds are small indexes into a static session table (open/close
 *     are single-threaded in the client, so the table needs no locks);
 *   - tun_write (WintunSendPacket) blocks while the ring is full — the
 *     kernel ring IS the backpressure, so no EAGAIN can occur.
 *
 * Compile/Windows only: the Makefile excludes tun.c and builds this file
 * instead. The _WIN32 guard makes an accidental Linux compile degrade to
 * an empty translation unit rather than a hard error.
 */
#ifdef _WIN32

#include <errno.h>
#include <process.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"   /* port.h: winsock2.h + windows.h + errno.h first */
#include "iphlpapi.h" /* NET_LUID for WintunGetAdapterLuid's signature */
#include "tun.h"
#include "util.h"

/* ------------------------- wintun API (runtime) -------------------- */
/* Types are declared locally instead of shipping a wintun.h copy; the
 * layout of the (opaque) handles and the signatures below are part of
 * the stable wintun ABI (https://www.wintun.net/build/wintun.h). */

typedef struct _WINTUN_ADAPTER *WINTUN_ADAPTER_HANDLE;
typedef struct _WINTUN_SESSION *WINTUN_SESSION_HANDLE;

typedef WINTUN_ADAPTER_HANDLE(WINAPI *wintun_create_adapter_fn)(
    const WCHAR *name, const WCHAR *tunnel_type, const GUID *guid);
typedef void (WINAPI *wintun_delete_adapter_fn)(WINTUN_ADAPTER_HANDLE adapter,
                                                BOOL force_close_sessions);
typedef WINTUN_ADAPTER_HANDLE(WINAPI *wintun_open_adapter_fn)(
    const WCHAR *name, const WCHAR *tunnel_type);
typedef void (WINAPI *wintun_close_adapter_fn)(WINTUN_ADAPTER_HANDLE adapter);
typedef WINTUN_SESSION_HANDLE(WINAPI *wintun_start_session_fn)(
    WINTUN_ADAPTER_HANDLE adapter, DWORD capacity);
typedef void (WINAPI *wintun_end_session_fn)(WINTUN_SESSION_HANDLE session);
typedef BOOL (WINAPI *wintun_get_adapter_luid_fn)(WINTUN_ADAPTER_HANDLE adapter,
                                                  NET_LUID *luid);
typedef DWORD (WINAPI *wintun_get_running_driver_version_fn)(void);
typedef BOOL (WINAPI *wintun_send_packet_fn)(WINTUN_SESSION_HANDLE session,
                                             const BYTE *packet,
                                             DWORD packet_size);
typedef BYTE *(WINAPI *wintun_receive_packet_fn)(WINTUN_SESSION_HANDLE session,
                                                 DWORD *packet_size);
typedef void (WINAPI *wintun_release_receive_packet_fn)(
    WINTUN_SESSION_HANDLE session, const BYTE *packet);
typedef HANDLE (WINAPI *wintun_get_read_wait_event_fn)(
    WINTUN_SESSION_HANDLE session);

struct wintun_api {
    HMODULE dll;
    wintun_create_adapter_fn create_adapter;
    wintun_delete_adapter_fn delete_adapter;
    wintun_open_adapter_fn open_adapter;
    wintun_close_adapter_fn close_adapter;
    wintun_start_session_fn start_session;
    wintun_end_session_fn end_session;
    wintun_get_adapter_luid_fn get_adapter_luid;
    wintun_get_running_driver_version_fn get_running_driver_version;
    wintun_send_packet_fn send_packet;
    wintun_receive_packet_fn receive_packet;
    wintun_release_receive_packet_fn release_receive_packet;
    wintun_get_read_wait_event_fn get_read_wait_event;
};

/* 0 = not yet attempted, 1 = loaded, -1 = load failed (logged already) */
static struct wintun_api iwan_wintun;
static int iwan_wintun_loaded;

#define IWAN_WINTUN_POOL L"iWAN"
/* 4 MiB ring: matches the 4 MiB SO_RCVBUF the Linux backend gives the
 * TUN fd, so burst behavior (pacing, batch flush) stays comparable */
#define IWAN_WINTUN_RING_CAPACITY 0x400000u
#define TUN_WIN_POLL_MS 100   /* reader wait cadence (tun.c TUN_POLL_MS) */

/* Fixed adapter GUID: one stable identity for every run and every
 * machine, so Windows tracks the adapter as "the" iwan adapter. Random
 * constant generated once for this project. NEVER change it — a changed
 * GUID orphans previously created adapters (they linger as stale
 * interfaces in ncpa.cpl until deleted by hand). */
static const GUID IWAN_WINTUN_GUID = {
    0x1e8c1f5a, 0x0f2a, 0x4a9b,
    { 0x9c, 0x6e, 0x3d, 0x8b, 0x1a, 0x2c, 0x7d, 0x4e }
};

static bool wintun_load(void)
{
    if (iwan_wintun_loaded != 0)
        return iwan_wintun_loaded > 0;
    iwan_wintun.dll = LoadLibraryA("wintun.dll");
    if (iwan_wintun.dll == NULL) {
        log_err("wintun.dll not found — install the wintun driver from "
                "wintun.net (or WireGuard) and place wintun.dll next to "
                "the executable");
        iwan_wintun_loaded = -1;
        return false;
    }
#define WINTUN_LOAD_ONE(member, name)                                         \
    do {                                                                      \
        iwan_wintun.member =                                                  \
            (void *)GetProcAddress(iwan_wintun.dll, name);                    \
        if (iwan_wintun.member == NULL) {                                     \
            log_err("wintun.dll is missing %s — update wintun.dll from "      \
                    "wintun.net", name);                                      \
            FreeLibrary(iwan_wintun.dll);                                     \
            iwan_wintun_loaded = -1;                                          \
            return false;                                                     \
        }                                                                     \
    } while (0)
    WINTUN_LOAD_ONE(create_adapter, "WintunCreateAdapter");
    WINTUN_LOAD_ONE(delete_adapter, "WintunDeleteAdapter");
    WINTUN_LOAD_ONE(open_adapter, "WintunOpenAdapter");
    WINTUN_LOAD_ONE(close_adapter, "WintunCloseAdapter");
    WINTUN_LOAD_ONE(start_session, "WintunStartSession");
    WINTUN_LOAD_ONE(end_session, "WintunEndSession");
    WINTUN_LOAD_ONE(get_adapter_luid, "WintunGetAdapterLuid");
    WINTUN_LOAD_ONE(get_running_driver_version, "WintunGetRunningDriverVersion");
    WINTUN_LOAD_ONE(send_packet, "WintunSendPacket");
    WINTUN_LOAD_ONE(receive_packet, "WintunReceivePacket");
    WINTUN_LOAD_ONE(release_receive_packet, "WintunReleaseReceivePacket");
    WINTUN_LOAD_ONE(get_read_wait_event, "WintunGetReadWaitEvent");
#undef WINTUN_LOAD_ONE
    iwan_wintun_loaded = 1;
    return true;
}

/* ------------------------- session fd table ------------------------ */
/* fds are slot indexes (0..3), not OS handles. open/close are
 * single-threaded in the client, and the pool reader thread is joined
 * before its session is closed, so no locking is required. */

#define TUN_FD_SLOTS 4

struct tun_slot {
    int used;                    /* slot allocated */
    BOOL created;                /* adapter created here vs. reused */
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;
    HANDLE read_ev;              /* owned by the session; do not close */
};

static struct tun_slot tun_slots[TUN_FD_SLOTS];

static struct tun_slot *tun_slot_get(int fd)
{
    if (fd < 0 || fd >= TUN_FD_SLOTS)
        return NULL;
    return tun_slots[fd].used ? &tun_slots[fd] : NULL;
}

static int tun_slot_alloc(void)
{
    for (int i = 0; i < TUN_FD_SLOTS; i++) {
        if (!tun_slots[i].used)
            return i;
    }
    return -1;
}

static bool utf8_to_wchar(const char *s, wchar_t *out, size_t cap)
{
    return MultiByteToWideChar(CP_UTF8, 0, s, -1, out, (int)cap) > 0;
}

/* ------------------------- tun.h API ------------------------------- */

int open_tun(const char *name)
{
    wchar_t name16[IFNAMSIZ];
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;
    HANDLE read_ev;
    BOOL created;
    int idx;

    if (!tun_name_valid(name))
        return -1;
    if (!wintun_load())
        return -1;
    if (!utf8_to_wchar(name, name16, IFNAMSIZ)) {
        log_err("tun: device name '%s' does not convert to UTF-16", name);
        return -1;
    }

    /* reuse a stale adapter from an earlier (possibly crashed) run;
     * only create one when no adapter with this name exists */
    adapter = iwan_wintun.open_adapter(name16, IWAN_WINTUN_POOL);
    if (adapter != NULL) {
        created = FALSE;
    } else {
        adapter = iwan_wintun.create_adapter(name16, IWAN_WINTUN_POOL,
                                             &IWAN_WINTUN_GUID);
        created = TRUE;
        if (adapter == NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
            /* lost a create race with another process: open the winner */
            adapter = iwan_wintun.open_adapter(name16, IWAN_WINTUN_POOL);
            created = FALSE;
        }
        if (adapter == NULL) {
            log_err("tun: cannot open or create wintun adapter '%s' "
                    "(wintun driver installed? error %lu)", name,
                    (unsigned long)GetLastError());
            return -1;
        }
    }

    session = iwan_wintun.start_session(adapter, IWAN_WINTUN_RING_CAPACITY);
    if (session == NULL) {
        log_err("tun: WintunStartSession failed (error %lu)",
                (unsigned long)GetLastError());
        iwan_wintun.close_adapter(adapter);
        return -1;
    }
    read_ev = iwan_wintun.get_read_wait_event(session);
    if (read_ev == NULL) {
        log_err("tun: WintunGetReadWaitEvent failed (error %lu)",
                (unsigned long)GetLastError());
        iwan_wintun.end_session(session);
        iwan_wintun.close_adapter(adapter);
        return -1;
    }

    idx = tun_slot_alloc();
    if (idx < 0) {
        log_err("tun: too many open devices (%d sessions max)", TUN_FD_SLOTS);
        iwan_wintun.end_session(session);
        iwan_wintun.close_adapter(adapter);
        return -1;
    }
    struct tun_slot *s = &tun_slots[idx];
    s->used = 1;
    s->created = created;
    s->adapter = adapter;
    s->session = session;
    s->read_ev = read_ev;
    log_debug("tun: wintun adapter '%s' fd=%d driver=%lu (%s)", name, idx,
              (unsigned long)iwan_wintun.get_running_driver_version(),
              created ? "created" : "reused");
    return idx;
}

int tun_attach(const char *name)
{
    (void)name;
    return -1;   /* wintun sessions are single-queue: no extra fds */
}

void tun_detach(int fd)
{
    (void)fd;   /* no extra queues on Windows; nothing to detach */
}

void tun_close(int fd)
{
    struct tun_slot *s = tun_slot_get(fd);
    if (s == NULL)
        return;
    /* end the session before closing the adapter; the read-wait event is
     * owned by the session and must NOT be CloseHandle'd. The adapter
     * itself is left in the system (mirrors Linux's persistent tun): the
     * next run reuses it through open_tun's WintunOpenAdapter path. */
    iwan_wintun.end_session(s->session);
    iwan_wintun.close_adapter(s->adapter);
    memset(s, 0, sizeof *s);
}

void set_nonblock(int fd)
{
    (void)fd;   /* wintun receive is always non-blocking, send blocking */
}

ptrdiff_t tun_write(int fd, const void *buf, size_t len)
{
    struct tun_slot *s = tun_slot_get(fd);
    if (s == NULL) {
        errno = EBADF;
        return -1;
    }
    /* WintunSendPacket blocks while the ring is full (that IS the
     * backpressure); FALSE therefore means the session is gone */
    if (!iwan_wintun.send_packet(s->session, buf, (DWORD)len)) {
        errno = EIO;
        return -1;
    }
    return (ptrdiff_t)len;
}

int tun_write_retry(int fd, const uint8_t *pkt, size_t len, int max_ms,
                    atomic_bool *stop)
{
    /* WintunSendPacket blocks until the ring has room, so a single call
     * is the whole write and no EAGAIN exists: the max_ms bound is
     * inherent to the kernel ring. The stop flag is honored at entry. */
    (void)max_ms;
    if (stop != NULL && *stop)
        return -1;
    return tun_write(fd, pkt, len) == (ptrdiff_t)len ? 0 : -1;
}

int tun_steering_attach(int tun_fd)
{
    static int logged;
    (void)tun_fd;
    if (!logged) {
        logged = 1;
        log_debug("tun steering: eBPF unavailable on Windows (single queue)");
    }
    return -1;
}

/* ------------------------- reader pool ----------------------------- */
/* One reader thread, exactly. The callback contract is unchanged:
 * cb(ud, pkt, len, false) per packet, then cb(ud, NULL, 0, true) once
 * the ring drains; the exit callback runs on the reader thread itself
 * after the final flush (mirroring tun.c). fd0 ownership stays with the
 * caller; tun_pool_destroy only stops and joins the thread. */

struct tun_pool {
    int fd;                /* session slot, owned by the caller */
    tun_pkt_fn cb;
    void *ud;
    atomic_bool *abort;    /* shared process stop flag (util.h g_stop) */
    tun_exit_fn exit_cb;
    volatile LONG stop;
    HANDLE thread;         /* reader thread; NULL after destroy */
};

static unsigned __stdcall tun_reader_main(void *ud)
{
    struct tun_pool *pool = ud;
    struct tun_slot *s = tun_slot_get(pool->fd);

    if (s != NULL) {
        while (!pool->stop && (pool->abort == NULL || !*pool->abort)) {
            if (WaitForSingleObject(s->read_ev, TUN_WIN_POLL_MS) ==
                WAIT_TIMEOUT)
                continue;   /* idle wake, like tun.c's poll timeout */
            DWORD sz;
            BYTE *pkt;
            while ((pkt = iwan_wintun.receive_packet(s->session, &sz)) !=
                   NULL) {
                pool->cb(pool->ud, pkt, (size_t)sz, false);
                iwan_wintun.release_receive_packet(s->session, pkt);
            }
            /* flush signal: batch-oriented callbacks send their partial
             * batch instead of holding it until the next wake */
            pool->cb(pool->ud, NULL, 0, true);
        }
        /* drain the ring before exiting (mirror tun.c): packets queued
         * but never delivered would be dropped by end_session */
        while (!(pool->abort != NULL && *pool->abort)) {
            DWORD sz;
            BYTE *pkt = iwan_wintun.receive_packet(s->session, &sz);
            if (pkt == NULL)
                break;
            pool->cb(pool->ud, pkt, (size_t)sz, false);
            iwan_wintun.release_receive_packet(s->session, pkt);
        }
        if (!(pool->abort != NULL && *pool->abort))
            pool->cb(pool->ud, NULL, 0, true);
    }
    /* per-thread cleanup runs on this exiting reader thread, strictly
     * after the final flush callback (client pump frees its TLS batch) */
    if (pool->exit_cb)
        pool->exit_cb();
    return 0;
}

struct tun_pool *tun_pool_create(const char *name, int fd0, int maxq,
                                 int initq, tun_pkt_fn cb, void *ud,
                                 atomic_bool *abort)
{
    struct tun_pool *pool;
    unsigned thrid;

    /* wintun sessions are single-queue: maxq/initq clamp to 1 */
    (void)name;
    (void)maxq;
    (void)initq;
    if (tun_slot_get(fd0) == NULL)
        return NULL;   /* fd0 must be a live session slot */
    pool = calloc(1, sizeof *pool);
    if (pool == NULL)
        return NULL;
    pool->fd = fd0;
    pool->cb = cb;
    pool->ud = ud;
    pool->abort = abort;
    pool->exit_cb = NULL;
    pool->stop = 0;
    pool->thread = (HANDLE)_beginthreadex(NULL, 0, tun_reader_main, pool, 0,
                                          &thrid);
    if (pool->thread == NULL) {
        free(pool);
        return NULL;
    }
    return pool;
}

void tun_pool_set_exit_cb(struct tun_pool *pool, tun_exit_fn cb)
{
    if (pool)
        pool->exit_cb = cb;
}

void tun_pool_tick(struct tun_pool *pool)
{
    /* AIMD is meaningless with a single queue; the symbol stays for link
     * compatibility with the caller's 500ms tick cadence */
    (void)pool;
}

void tun_pool_destroy(struct tun_pool *pool)
{
    if (pool == NULL)
        return;
    InterlockedExchange(&pool->stop, 1);
    if (pool->thread != NULL) {
        WaitForSingleObject(pool->thread, INFINITE);
        CloseHandle(pool->thread);
        pool->thread = NULL;
    }
    free(pool);
}

#endif /* _WIN32 */
