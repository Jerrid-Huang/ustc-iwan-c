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
#include <setupapi.h> /* SP_DEVINFO_DATA / DIF_REMOVE for adapter deletion */
#include <devguid.h>  /* GUID_DEVCLASS_NET */
#include <wintrust.h> /* WinVerifyTrust: Authenticode check for wintun.dll */
#include <softpub.h>  /* WINTRUST_ACTION_GENERIC_VERIFY_V2 */
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
typedef WINTUN_ADAPTER_HANDLE(WINAPI *wintun_open_adapter_fn)(
    const WCHAR *name, const WCHAR *tunnel_type);
typedef void (WINAPI *wintun_close_adapter_fn)(WINTUN_ADAPTER_HANDLE adapter);
typedef WINTUN_SESSION_HANDLE(WINAPI *wintun_start_session_fn)(
    WINTUN_ADAPTER_HANDLE adapter, DWORD capacity);
typedef void (WINAPI *wintun_end_session_fn)(WINTUN_SESSION_HANDLE session);
typedef DWORD (WINAPI *wintun_get_running_driver_version_fn)(void);
/* wintun >= 0.14: reserve ring space (blocks until room) then send the
 * reserved buffer (VOID — cannot fail); wintun <= 0.13 used a single
 * BOOL send(Session, Packet, PacketSize). Both are kept: the 0.14 form
 * is detected by the WintunAllocateSendPacket export. */
typedef BYTE *(WINAPI *wintun_allocate_send_packet_fn)(
    WINTUN_SESSION_HANDLE session, DWORD packet_size);
typedef void (WINAPI *wintun_send_packet_fn)(WINTUN_SESSION_HANDLE session,
                                             const BYTE *packet);
typedef BOOL (WINAPI *wintun_send_packet_old_fn)(WINTUN_SESSION_HANDLE session,
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
    wintun_open_adapter_fn open_adapter;
    wintun_close_adapter_fn close_adapter;
    wintun_start_session_fn start_session;
    wintun_end_session_fn end_session;
    wintun_get_running_driver_version_fn get_running_driver_version;
    wintun_allocate_send_packet_fn allocate_send_packet;
    wintun_send_packet_fn send_packet;
    wintun_send_packet_old_fn send_packet_old;
    wintun_receive_packet_fn receive_packet;
    wintun_release_receive_packet_fn release_receive_packet;
    wintun_get_read_wait_event_fn get_read_wait_event;
};

/* 0 = not yet attempted, 1 = loaded, -1 = load failed (logged already) */
static struct wintun_api iwan_wintun;
static int iwan_wintun_loaded;

#define IWAN_WINTUN_POOL L"iWAN"
/* 8 MiB ring: matches Xray-core's wintun session capacity
 * (StartSession(0x800000)); the larger ring absorbs the send/recv
 * bursts from the pump's GSO batches without the kernel stalling the
 * session under load. */
#define IWAN_WINTUN_RING_CAPACITY 0x800000u
#define TUN_WIN_POLL_MS 100   /* reader wait cadence (tun.c TUN_POLL_MS) */

/* [prof] reader/write accounting, printed by the client pump profiler
 * (proxy.c declares these extern): wait = reader parked in
 * WaitForSingleObject (idle park + wake latency), timeouts = idle
 * WAIT_TIMEOUT wakes, wakeups = signaled wakes, pkts = packets drained,
 * drain = drain-loop time (cb + release), allocfail = tun_write
 * AllocateSendPacket first-try misses (TX ring full backpressure) */
atomic_uint_fast64_t g_tun_wait_us, g_tun_timeouts, g_tun_wakeups,
                     g_tun_pkts, g_tun_drain_us, g_tun_allocfail;

/* Fixed adapter GUID: one stable identity for every run and every
 * machine, so Windows tracks the adapter as "the" iwan adapter. Random
 * constant generated once for this project. NEVER change it — a changed
 * GUID orphans previously created adapters (they linger as stale
 * interfaces in ncpa.cpl until deleted by hand). */
static const GUID IWAN_WINTUN_GUID = {
    0x1e8c1f5a, 0x0f2a, 0x4a9b,
    { 0x9c, 0x6e, 0x3d, 0x8b, 0x1a, 0x2c, 0x7d, 0x4e }
};

/* Authenticode verification via WinVerifyTrust (no UI, no network
 * revocation checks: offline-friendly). Returns true for a valid
 * signature chain back to a CA the system trusts. */
static bool wintun_verify(const wchar_t *path)
{
    WINTRUST_FILE_INFO fi;
    WINTRUST_DATA wd;
    GUID act = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    memset(&fi, 0, sizeof fi);
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = path;
    fi.hFile = NULL;
    fi.pgKnownSubject = NULL;

    memset(&wd, 0, sizeof wd);
    wd.cbStruct = sizeof wd;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_SAFER_FLAG;

    LONG st = WinVerifyTrust(NULL, &act, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)WinVerifyTrust(NULL, &act, &wd);

    return st == ERROR_SUCCESS;
}

static bool wintun_load(void)
{
    if (iwan_wintun_loaded != 0)
        return iwan_wintun_loaded > 0;

    /* Load from the exe's own directory by absolute path first: that
     * directory is by definition readable (the exe itself runs from
     * it), and this sidesteps loader search-order quirks when running
     * from network shares. Then System32 only. The CWD/PATH search is
     * deliberately NOT used: an attacker-writable directory earlier in
     * the order would inject a hostile wintun.dll into this process
     * (audit M1). Both candidates are Authenticode-verified first. */
    {
        wchar_t dllpath[MAX_PATH * 2];
        DWORD n = GetModuleFileNameW(NULL, dllpath,
                                     (DWORD)(sizeof dllpath /
                                             sizeof dllpath[0]));

        if (n > 0 && n < sizeof dllpath / sizeof dllpath[0]) {
            wchar_t *slash = wcsrchr(dllpath, L'\\');

            if (slash) {
                wcscpy(slash + 1, L"wintun.dll");
                if (wintun_verify(dllpath)) {
                    iwan_wintun.dll = LoadLibraryW(dllpath);
                    /* NOTE: no early return here — the GetProcAddress
                     * resolution below MUST run for every successful
                     * load, or the API pointers stay NULL and open_tun
                     * calls through a NULL function pointer. */
                } else {
                    log_err("wintun.dll failed Authenticode "
                            "verification (exe dir); refusing to load "
                            "an unverified driver shim");
                }
            }
        }
    }
    if (iwan_wintun.dll == NULL) {
        DWORD dir_err = GetLastError();

        /* system-wide install (WireGuard et al): System32 only */
        wchar_t sysdll[MAX_PATH];
        DWORD sn = GetSystemDirectoryW(sysdll,
                                       (UINT)(MAX_PATH - 16));
        if (sn > 0 && sn < MAX_PATH - 16) {
            wcscpy(sysdll + sn, L"\\wintun.dll");
            if (wintun_verify(sysdll)) {
                iwan_wintun.dll = LoadLibraryW(sysdll);
            } else {
                log_err("wintun.dll failed Authenticode "
                        "verification (System32); refusing to load an "
                        "unverified driver shim");
            }
        }
        if (iwan_wintun.dll == NULL) {
            log_err("wintun.dll not found or blocked — install the "
                    "wintun driver from wintun.net (or WireGuard) and "
                    "place wintun.dll next to the executable "
                    "(exe-dir load error %lu, system load error %lu)",
                    dir_err, GetLastError());
            iwan_wintun_loaded = -1;
            return false;
        }
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
    WINTUN_LOAD_ONE(open_adapter, "WintunOpenAdapter");
    WINTUN_LOAD_ONE(close_adapter, "WintunCloseAdapter");
    WINTUN_LOAD_ONE(start_session, "WintunStartSession");
    WINTUN_LOAD_ONE(end_session, "WintunEndSession");
    WINTUN_LOAD_ONE(get_running_driver_version, "WintunGetRunningDriverVersion");
    /* 0.14+ exports WintunAllocateSendPacket; 0.13 and earlier do not
     * (there WintunSendPacket takes the packet size as the 3rd arg) */
    iwan_wintun.allocate_send_packet = (wintun_allocate_send_packet_fn)
        (void *)GetProcAddress(iwan_wintun.dll, "WintunAllocateSendPacket");
    iwan_wintun.send_packet = (wintun_send_packet_fn)
        (void *)GetProcAddress(iwan_wintun.dll, "WintunSendPacket");
    if (iwan_wintun.send_packet == NULL) {
        log_err("wintun.dll is missing WintunSendPacket — update "
                "wintun.dll from wintun.net");
        FreeLibrary(iwan_wintun.dll);
        iwan_wintun_loaded = -1;
        return false;
    }
    if (iwan_wintun.allocate_send_packet == NULL)
        iwan_wintun.send_packet_old = (wintun_send_packet_old_fn)
            (void *)iwan_wintun.send_packet;
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

/* wintun >= 0.14 removed WintunDeleteAdapter from the DLL, so a wedged
 * stale adapter is deleted through SetupDi (DIF_REMOVE) by matching the
 * adapter's friendly name. Returns 1 when a device was removed. */
static int wintun_delete_adapter_by_name(const wchar_t *name)
{
    HDEVINFO devs;
    SP_DEVINFO_DATA devinfo;
    wchar_t dn[256];
    DWORD i;
    int removed = 0;

    devs = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, NULL, NULL,
                                DIGCF_PRESENT);
    if (devs == INVALID_HANDLE_VALUE)
        return 0;
    devinfo.cbSize = sizeof devinfo;
    for (i = 0; SetupDiEnumDeviceInfo(devs, i, &devinfo); i++) {
        DWORD n = 0;
        if (!SetupDiGetDeviceRegistryPropertyW(devs, &devinfo,
                                               SPDRP_FRIENDLYNAME, NULL,
                                               (PBYTE)dn, sizeof dn, &n))
            continue;
        /* exact FriendlyName match only: a substring match could remove
         * an unrelated adapter whose name merely contains ours */
        if (wcscmp(dn, name) != 0)
            continue;
        /* and it must really be a wintun device (hardware ID starts
         * with SWD\WINTUN) so a non-wintun NIC that happens to share
         * the name is never removed */
        wchar_t hw[512];
        int is_wintun = 0;
        if (!SetupDiGetDeviceRegistryPropertyW(devs, &devinfo,
                                               SPDRP_HARDWAREID, NULL,
                                               (PBYTE)hw, sizeof hw, &n))
            continue;
        for (const wchar_t *q = hw; *q; q += wcslen(q) + 1) {
            if (wcsncmp(q, L"SWD\\WINTUN", 11) == 0) {
                is_wintun = 1;
                break;
            }
        }
        if (!is_wintun)
            continue;
        if (SetupDiCallClassInstaller(DIF_REMOVE, devs, &devinfo))
            removed = 1;
        break;
    }
    SetupDiDestroyDeviceInfoList(devs);
    return removed;
}

/* ------------------------- tun.h API ------------------------------- */

/* tun_ifname: the interface name to hand to ifconfig/route.
 * Linux/Windows: the requested name IS the interface name.
 * macOS: utun names are kernel-assigned, so the requested name maps
 * to the actual utunN (see tun_mac.c). */
const char *tun_ifname(const char *name)
{
    return name;
}

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
        DWORD serr = GetLastError();
        int attempt;

        /* A freshly created/reused adapter can need a moment before
         * WintunStartSession succeeds (driver state settling); retry a
         * few times before declaring failure. */
        for (attempt = 0; attempt < 4 && session == NULL; attempt++) {
            Sleep(500);
            session = iwan_wintun.start_session(adapter,
                                                IWAN_WINTUN_RING_CAPACITY);
        }

        /* A reused adapter can be left wedged by a crashed or killed
         * previous run (e.g. its process was terminated while holding
         * the session, leaving the adapter in a state where
         * WintunStartSession fails with ERROR_DEVICE_NOT_CONNECTED,
         * 1247). Deleting and recreating the adapter once clears that
         * state; a freshly created adapter has no stale state to clear,
         * so only the reused path retries. wintun >= 0.14 has no
         * WintunDeleteAdapter export, so the stale adapter is removed
         * through SetupDi by name. */
        if (session == NULL && !created) {
            log_err("tun: WintunStartSession failed on reused adapter "
                    "(error %lu); deleting stale adapter and retrying",
                    (unsigned long)serr);
            iwan_wintun.close_adapter(adapter);
            adapter = NULL;
            wintun_delete_adapter_by_name(name16);
            for (attempt = 0; attempt < 8 && adapter == NULL; attempt++) {
                adapter = iwan_wintun.create_adapter(name16,
                                                     IWAN_WINTUN_POOL,
                                                     &IWAN_WINTUN_GUID);
                if (adapter == NULL)
                    Sleep(500);
            }
            if (adapter != NULL) {
                created = TRUE;
                for (attempt = 0; attempt < 4 && session == NULL;
                     attempt++) {
                    session = iwan_wintun.start_session(
                        adapter, IWAN_WINTUN_RING_CAPACITY);
                    if (session == NULL)
                        Sleep(500);
                }
            }
        }
        if (session == NULL) {
            log_err("tun: WintunStartSession failed (error %lu)",
                    (unsigned long)GetLastError());
            if (adapter != NULL)
                iwan_wintun.close_adapter(adapter);
            return -1;
        }
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
    if (iwan_wintun.allocate_send_packet) {
        /* wintun 0.14+: reserve ring space (blocks until room — that is
         * the backpressure), copy, then send the reserved buffer; the
         * send itself cannot fail. A NULL alloc normally means the
         * session is gone (or the packet exceeds WINTUN_MAX_IP_PACKET_SIZE),
         * but on real Windows it can also be a transient driver stall
         * under load; retry briefly before declaring the session dead. */
        BYTE *dst = NULL;
        for (int i = 0; i < 20 && dst == NULL; i++) {
            dst = iwan_wintun.allocate_send_packet(s->session,
                                                   (DWORD)len);
            if (dst == NULL) {
                atomic_fetch_add(&g_tun_allocfail, 1);
                Sleep(10);
            }
        }
        if (dst == NULL) {
            errno = EIO;
            return -1;
        }
        memcpy(dst, buf, len);
        iwan_wintun.send_packet(s->session, dst);
    } else {
        /* wintun <= 0.13: BOOL send(Session, Packet, PacketSize) */
        BOOL ok = FALSE;
        for (int i = 0; i < 20 && !ok; i++) {
            ok = iwan_wintun.send_packet_old(s->session, buf,
                                             (DWORD)len);
            if (!ok)
                Sleep(10);
        }
        if (!ok) {
            errno = EIO;
            return -1;
        }
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

    /* experimental pinning (IWAN_WIN_THREAD_PIN=1): uplink reader ->
     * CPU 1, ABOVE_NORMAL. Avoids vCPU migration (L1/L2 cold) and
     * stays off CPU 0, where the virtio/wintun DPCs land. */
    {
        const char *pin = getenv("IWAN_WIN_THREAD_PIN");
        if (pin && pin[0] != '0') {
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            if (si.dwNumberOfProcessors > 1)
                SetThreadAffinityMask(GetCurrentThread(),
                                      (DWORD_PTR)1 << 1);
            SetThreadPriority(GetCurrentThread(),
                              THREAD_PRIORITY_ABOVE_NORMAL);
        }
    }

    if (s != NULL) {
        while (!pool->stop && (pool->abort == NULL || !*pool->abort)) {
            uint64_t w0 = now_us();
            DWORD wr = WaitForSingleObject(s->read_ev, TUN_WIN_POLL_MS);
            uint64_t wdt = now_us() - w0;
            atomic_fetch_add(&g_tun_wait_us, wdt);
            if (wr == WAIT_TIMEOUT) {
                atomic_fetch_add(&g_tun_timeouts, 1);
                continue;   /* idle wake, like tun.c's poll timeout */
            }
            atomic_fetch_add(&g_tun_wakeups, 1);
            uint64_t d0 = now_us();
            DWORD sz;
            BYTE *pkt;
            while ((pkt = iwan_wintun.receive_packet(s->session, &sz)) !=
                   NULL) {
                atomic_fetch_add(&g_tun_pkts, 1);
                pool->cb(pool->ud, pkt, (size_t)sz, false);
                iwan_wintun.release_receive_packet(s->session, pkt);
            }
            atomic_fetch_add(&g_tun_drain_us, now_us() - d0);
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

int tun_pool_queues(const struct tun_pool *pool)
{
    (void)pool;
    return 1;   /* wintun sessions are single-queue: one reader thread */
}

/* Windows backend has no per-queue write fds (wintun sends go through
 * the single session), so there is no queue to spread uplink writes
 * across; this only completes the link contract. The sole caller
 * (server.c) is Linux-only and never runs here. */
int tun_pool_write_fd(const struct tun_pool *pool, unsigned tid)
{
    (void)pool;
    (void)tid;
    return -1;
}

/* No AIMD shrink exists on Windows (single queue), so an uplink write
 * stall needs no bookkeeping; this only completes the link contract.
 * The sole caller (server.c) is Linux-only and never runs here. */
void tun_pool_note_stall(struct tun_pool *pool)
{
    (void)pool;
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
