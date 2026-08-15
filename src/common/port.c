#include "port.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#ifdef __linux__
#include <sys/random.h>
#endif
#include <sys/wait.h>
#else
#include <signal.h>
#include <shellapi.h>   /* ShellExecuteW (port_elevate_self) */
#include <winnetwk.h>   /* WNetGetConnectionW (UNC for elevation) */
#include <conio.h>      /* _getch (crash filter window hold) */
#endif

#ifdef _WIN32
/* Crash reporter: Windows console apps die silently on unhandled
 * exceptions, and a UAC-relaunched instance's console window vanishes
 * with it. Print the exception code, the faulting address and its
 * module, then hold the window open if this was a UAC relaunch. */
static LONG WINAPI iwan_crash_filter(EXCEPTION_POINTERS *ep)
{
    const EXCEPTION_RECORD *er = ep->ExceptionRecord;
    HMODULE mod = NULL;
    wchar_t modpath[MAX_PATH] = L"?";

    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)er->ExceptionAddress, &mod) && mod)
        GetModuleFileNameW(mod, modpath, MAX_PATH);
    fprintf(stderr,
            "\n*** runtime error: exception 0x%08lX at %p, module %ls ***\n",
            (unsigned long)er->ExceptionCode, er->ExceptionAddress,
            modpath);
    fflush(stderr);
    if (getenv("IWAN_ELEVATED_RELAUNCH")) {
        fprintf(stderr, "Press any key to close this window...");
        fflush(stderr);
        _getch();
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

void port_install_crash_handler(void)
{
    SetUnhandledExceptionFilter(iwan_crash_filter);
}
#endif

/* ================================================================== */
/* Dual-platform utilities (clock, entropy, sleep, process, misc).    */
/* ================================================================== */

uint64_t port_now_ms(void)
{
#ifdef _WIN32
    static LARGE_INTEGER freq;
    static int have_freq;
    LARGE_INTEGER c;
    if (!have_freq) {
        QueryPerformanceFrequency(&freq);
        have_freq = 1;
    }
    QueryPerformanceCounter(&c);
    return (uint64_t)(c.QuadPart * 1000 / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}

uint64_t port_now_us(void)
{
#ifdef _WIN32
    static LARGE_INTEGER freq;
    static int have_freq;
    LARGE_INTEGER c;
    if (!have_freq) {
        QueryPerformanceFrequency(&freq);
        have_freq = 1;
    }
    QueryPerformanceCounter(&c);
    return (uint64_t)(c.QuadPart * 1000000 / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
#endif
}

int port_rand_bytes(void *out, size_t n)
{
#ifdef _WIN32
    /* BCryptGenRandom with the process handle needs no provider handle
     * and never fails for our sizes on Win7+; use it directly so a
     * failure can abort rather than degrade to a weak fallback. */
    if (BCryptGenRandom(NULL, (PUCHAR)out, (ULONG)n,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return -1;
    return 0;
#else
#ifdef __APPLE__
    /* arc4random_buf never fails (kernel entropy, fail-closed by
     * contract) */
    arc4random_buf(out, n);
    return 0;
#else
    ssize_t r = getrandom(out, n, 0);
    if (r == (ssize_t)n)
        return 0;
    /* getrandom(0) may return short reads on some kernels; loop, but a
     * hard failure must surface as -1 (callers fail closed). */
    uint8_t *p = out;
    size_t got = 0;
    while (got < n) {
        r = getrandom(p + got, n - got, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
#endif /* __APPLE__ */
#endif
}

void port_sleep_ms(unsigned ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts = { .tv_sec = ms / 1000,
                           .tv_nsec = (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
        ;
#endif
}

void port_sleep_us(unsigned us)
{
#ifdef _WIN32
    /* the CRT/win32 timer granularity is ms; round up so callers that
     * sleep to pace never spin harder than intended */
    Sleep((us + 999) / 1000);
#else
    usleep(us);
#endif
}

#ifdef _WIN32
/* console ctrl events have no signal numbers; normalize every stop
 * event to SIGINT and forward to the registered handler */
static void (*g_stop_fn)(int);

static BOOL WINAPI iwan_ctrl_handler(DWORD type)
{
    (void)type;
    if (g_stop_fn)
        g_stop_fn(SIGINT);
    return TRUE;
}
#endif

int port_set_stop_handler(void (*fn)(int sig))
{
#ifdef _WIN32
    g_stop_fn = fn;
    return SetConsoleCtrlHandler(iwan_ctrl_handler, TRUE) ? 0 : -1;
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = fn;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) != 0 ||
        sigaction(SIGTERM, &sa, NULL) != 0 ||
        sigaction(SIGHUP, &sa, NULL) != 0)
        return -1;
    return 0;
#endif
}

bool port_is_admin(void)
{
#ifdef _WIN32
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
        return false;
    DWORD sz = 0;
    GetTokenInformation(tok, TokenGroups, NULL, 0, &sz);
    if (sz == 0) {
        CloseHandle(tok);
        return false;
    }
    TOKEN_GROUPS *tg = malloc(sz);
    if (!tg) {
        CloseHandle(tok);
        return false;
    }
    bool admin = false;
    if (GetTokenInformation(tok, TokenGroups, tg, sz, &sz)) {
        SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
        PSID admins = NULL;
        if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                     DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0,
                                     0, 0, &admins)) {
            for (DWORD i = 0; i < tg->GroupCount; i++)
                /* UAC-filtered tokens still CONTAIN the Administrators
                 * SID, marked deny-only (no SE_GROUP_ENABLED); without
                 * the attribute check every admin user is misdetected
                 * as elevated and the UAC relaunch is skipped. */
                if (EqualSid(tg->Groups[i].Sid, admins) &&
                    (tg->Groups[i].Attributes & SE_GROUP_ENABLED)) {
                    admin = true;
                    break;
                }
            FreeSid(admins);
        }
    }
    free(tg);
    CloseHandle(tok);
    return admin;
#else
    return geteuid() == 0;
#endif
}

#ifdef _WIN32
/* join argv[start..] with spaces into a Windows command line; quote
 * args containing spaces and escape embedded quotes. Every argument is
 * converted UTF-8 -> UTF-16 first: netsh interface names (e.g. "以太网"
 * on a zh-CN system) reach here as UTF-8 via route.c's
 * WideCharToMultiByte(CP_UTF8), and a byte-for-byte (wchar_t) cast
 * would garble them so netsh could not find the interface. The helper
 * programs (netsh, route, ...) are trusted, fixed strings. Returns the
 * length written (excluding NUL), 0 when nothing was written. */
static size_t win_join_argv(char *const argv[], int start, wchar_t *out,
                            size_t outsz)
{
    size_t n = 0;

    for (int i = start; argv[i]; i++) {
        const char *a = argv[i];
        size_t alen = strlen(a);
        wchar_t *w = NULL;
        int wlen = 0;

        /* UTF-8 -> UTF-16 (wlen includes the NUL): worst case one
         * wchar per 3 UTF-8 bytes, so 2*(len+1) always fits. */
        if (alen <= (SIZE_MAX / 2) - 1) {
            size_t wcap = 2 * (alen + 1);
            w = malloc(wcap * sizeof *w);
            if (w != NULL) {
                wlen = MultiByteToWideChar(CP_UTF8, 0, a, -1, w, (int)wcap);
                if (wlen <= 0) {
                    /* invalid UTF-8 (defensive; not expected): fall back
                     * to the historical byte-for-byte cast */
                    wlen = (int)alen + 1;
                    for (size_t k = 0; k <= alen; k++)
                        w[k] = (wchar_t)(unsigned char)a[k];
                }
            }
        }
        if (w == NULL) {
            /* allocation failure: write the raw bytes directly */
            int quote = strchr(a, ' ') != NULL || strchr(a, '\t') != NULL;
            if (i > start && n < outsz - 1)
                out[n++] = L' ';
            if (quote)
                out[n++] = L'"';
            while (*a && n < outsz - 2) {
                if (*a == '"')
                    out[n++] = L'\\';
                out[n++] = (wchar_t)(unsigned char)*a;
                a++;
            }
            if (quote)
                out[n++] = L'"';
            continue;
        }
        int quote = 0;
        for (int k = 0; k < wlen - 1; k++) {
            if (w[k] == L' ' || w[k] == L'\t') {
                quote = 1;
                break;
            }
        }
        if (i > start && n < outsz - 1)
            out[n++] = L' ';
        if (quote)
            out[n++] = L'"';
        for (int k = 0; k < wlen - 1 && n < outsz - 2; k++) {
            if (w[k] == L'"')
                out[n++] = L'\\';
            out[n++] = w[k];
        }
        if (quote)
            out[n++] = L'"';
        free(w);
    }
    if (n < outsz)
        out[n] = L'\0';
    return n;
}
#endif /* _WIN32 */

int port_elevate_self(int argc, char **argv)
{
    (void)argc;
#ifdef _WIN32
    wchar_t exe[MAX_PATH];
    wchar_t args[4096];
    wchar_t unc[MAX_PATH * 2];
    wchar_t unc_dir[MAX_PATH * 2];
    bool have_unc = false;
    size_t n;

    if (!GetModuleFileNameW(NULL, exe, MAX_PATH))
        return -1;
    /* The UAC elevation machinery (AppInfo service, session 0) cannot
     * resolve drive letters: an exe launched from a mapped drive fails
     * with ERROR_PATH_NOT_FOUND (3) even though the file exists. Resolve
     * the UNC form — WNetGetConnectionW for standard mappings,
     * QueryDosDeviceW for SUBST'd drives — and relaunch via that. */
    if (exe[0] != L'\0' && exe[1] == L':') {
        wchar_t dletter[3] = { exe[0], L':', L'\0' };
        wchar_t remote[4096] = L"";
        DWORD rlen = (DWORD)(sizeof remote / sizeof remote[0]);
        DWORD we = WNetGetConnectionW(dletter, remote, &rlen);

        if (we == NO_ERROR && remote[0] != L'\0') {
            int m = _snwprintf(unc, MAX_PATH * 2, L"%s%s", remote,
                               exe + 2);

            if (m > 0 && (size_t)m < MAX_PATH * 2)
                have_unc = true;
        } else {
            /* not a WNet mapping (SUBST / session-scoped): the DOS
             * device name records the target too */
            wchar_t dev[4096] = L"";
            DWORD dn = QueryDosDeviceW(
                dletter, dev, (DWORD)(sizeof dev / sizeof dev[0]));

            if (dn > 0 && wcsncmp(dev, L"\\??\\UNC\\", 8) == 0) {
                int m = _snwprintf(unc, MAX_PATH * 2, L"\\\\%s%s",
                                   dev + 8, exe + 2);

                if (m > 0 && (size_t)m < MAX_PATH * 2)
                    have_unc = true;
            }
            log_debug("elevation: WNetGetConnectionW(%ls) failed (%lu), "
                      "QueryDosDeviceW -> %ls", dletter, we, dev);
        }
    }
    n = win_join_argv(argv, 1, args, sizeof args / sizeof args[0]);
    /* Try the launch path first, then the UNC form. lpDirectory is set
     * explicitly: the current directory (the Z: prompt) is exactly the
     * kind of path the elevated context cannot resolve, and an
     * unresolvable CWD makes process creation fail with error 3. */
    for (int attempt = 0; attempt < 2; attempt++) {
        SHELLEXECUTEINFOW sei;
        const wchar_t *file = attempt == 0 ? exe : unc;
        const wchar_t *dir = L"C:\\";
        wchar_t *slash;

        if (attempt == 1 && !have_unc)
            break;
        if (attempt == 0 && have_unc) {
            wcsncpy(unc_dir, unc, MAX_PATH * 2 - 1);
            unc_dir[MAX_PATH * 2 - 1] = L'\0';
            slash = wcsrchr(unc_dir, L'\\');
            if (slash) {
                *slash = L'\0';
                dir = unc_dir;
            }
        }
        memset(&sei, 0, sizeof sei);
        sei.cbSize = sizeof sei;
        sei.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = L"runas";
        sei.lpFile = file;
        sei.lpParameters = n > 0 ? args : NULL;
        sei.lpDirectory = dir;
        sei.nShow = SW_SHOWNORMAL;
        /* marker for the elevated instance: its console window closes
         * on exit, so error paths hold it open (oidc_pause_if_relaunched) */
        SetEnvironmentVariableW(L"IWAN_ELEVATED_RELAUNCH", L"1");
        if (ShellExecuteExW(&sei)) {
            if (sei.hProcess)
                CloseHandle(sei.hProcess);
            return 0;
        }
        log_err("UAC elevation refused for %ls (error %d)", file,
                (int)(intptr_t)sei.hInstApp);
    }
    /* Diagnose the cause: the two UAC policies that make runas fail
     * without showing a prompt. */
    {
        DWORD vas = 0, lua = 0, vsz = sizeof vas, lsz = sizeof lua;

        RegGetValueA(HKEY_LOCAL_MACHINE,
                     "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                     "Policies\\System",
                     "ValidateAdminCodeSignatures", RRF_RT_REG_DWORD,
                     NULL, &vas, &vsz);
        RegGetValueA(HKEY_LOCAL_MACHINE,
                     "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                     "Policies\\System",
                     "EnableLUA", RRF_RT_REG_DWORD, NULL, &lua, &lsz);
        log_err("UAC policies: ValidateAdminCodeSignatures=%lu "
                "EnableLUA=%lu%s",
                vas, lua,
                vas ? " — this policy blocks elevating UNSIGNED "
                      "executables without any prompt; disable it or run "
                      "iwan from an administrator console" : "");
    }
    log_err("elevation failed: if the exe lives on a mapped/SUBST drive "
            "that UAC cannot resolve, copy the binaries to a local disk "
            "(e.g. C:\\iwan) and run them from there, or start an "
            "elevated console (right-click -> Run as administrator)");
    return -1;
#else
    /* POSIX elevation is handled by the callers (sudo re-exec) */
    (void)argv;
    return -1;
#endif
}

long port_cpu_count(void)
{
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    long n = (long)si.dwNumberOfProcessors;
    return n > 0 ? n : 1;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? n : 1;
#endif
}

char *port_home_dir(void)
{
#ifdef _WIN32
    const char *home = getenv("USERPROFILE");
    if (home && home[0])
        return strdup(home);
    const char *hd = getenv("HOMEDRIVE");
    const char *hp = getenv("HOMEPATH");
    if (hd && hp && hd[0]) {
        size_t n = strlen(hd) + strlen(hp);
        char *buf = malloc(n + 1);
        if (buf) {
            snprintf(buf, n + 1, "%s%s", hd, hp);
            return buf;
        }
    }
    return NULL;
#else
    const char *home = getenv("HOME");
    if (home && home[0])
        return strdup(home);
    return NULL;
#endif
}

#ifdef _WIN32
int port_strcasecmp(const char *a, const char *b)
{
    return _stricmp(a, b);
}

int port_strncasecmp(const char *a, const char *b, size_t n)
{
    return _strnicmp(a, b, n);
}
#endif

/* ----------------------- subprocess helpers ------------------------ */
/* Windows: CreateProcessW with redirected stdio. POSIX: fork+execvp
 * (used by util.c's ip_run family on Linux). */

int port_run_cmd(char *const argv[])
{
#ifdef _WIN32
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t cmdline[2048];

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);

    win_join_argv(argv, 0, cmdline, sizeof cmdline / sizeof cmdline[0]);

    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return -1;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)code;
#else
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        exec_sanitize();
        execvp(argv[0], argv);
        _exit(127);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return -1;
#endif
}

char *port_cmd_capture(char *const argv[], size_t max)
{
#ifdef _WIN32
    HANDLE rd, wr;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t cmdline[2048];
    size_t n = 0;

    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0))
        return NULL;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = NULL;
    si.hStdInput = NULL;
    memset(&pi, 0, sizeof pi);

    for (int i = 0; argv[i]; i++) {
        const char *a = argv[i];
        int quote = strchr(a, ' ') != NULL || strchr(a, '\t') != NULL;
        if (i > 0 && n < sizeof cmdline - 1)
            cmdline[n++] = L' ';
        if (quote)
            cmdline[n++] = L'"';
        while (*a && n < sizeof cmdline - 2) {
            if (*a == '"')
                cmdline[n++] = L'\\';
            cmdline[n++] = (wchar_t)(unsigned char)*a;
            a++;
        }
        if (quote)
            cmdline[n++] = L'"';
    }
    cmdline[n] = L'\0';

    if (!CreateProcessW(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        CloseHandle(rd);
        CloseHandle(wr);
        return NULL;
    }
    CloseHandle(wr);
    CloseHandle(pi.hThread);

    char *out = malloc(max + 1);
    if (!out) {
        CloseHandle(pi.hProcess);
        CloseHandle(rd);
        oom_abort();
    }
    size_t got = 0;
    DWORD r = 0;
    while (got < max && ReadFile(rd, out + got, (DWORD)(max - got), &r,
                                 NULL) && r > 0)
        got += r;
    out[got] = '\0';
    CloseHandle(rd);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    return out;
#else
    int fds[2];
    if (pipe(fds) != 0)
        return NULL;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return NULL;
    }
    if (pid == 0) {
        exec_sanitize();
        close(fds[0]);
        dup2(fds[1], 1);
        close(fds[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    char *out = malloc(max + 1);
    if (!out) {
        close(fds[0]);
        oom_abort();
    }
    size_t got = 0;
    while (got < max) {
        ssize_t r = read(fds[0], out + got, max - got);
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    close(fds[0]);
    out[got] = '\0';
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    return out;
#endif
}

#ifndef _WIN32
void port_socket_init(void)
{
    /* POSIX sockets need no global init */
}
#endif

/* ================================================================== */
/* Windows-only winsock wrappers. On POSIX these are static inline     */
/* passthroughs in port.h, so everything below is _WIN32-gated.        */
/* ================================================================== */

#ifdef _WIN32

/* WSA error -> POSIX errno. The mapping is deliberately coarse but
 * complete for every error the code checks: EAGAIN/EWOULDBLOCK,
 * EINTR, ECONNRESET, ECONNREFUSED, ETIMEDOUT, ENETUNREACH,
 * EHOSTUNREACH, ENOBUFS, EINVAL, EAFNOSUPPORT, EADDRINUSE,
 * EADDRNOTAVAIL, EISCONN, ENOTCONN, EOPNOTSUPP, EMSGSIZE, EACCES. */
static int wsa_errno(int e)
{
    switch (e) {
    case WSAEWOULDBLOCK:      return EAGAIN;
    case WSAEINTR:            return EINTR;
    case WSAEINPROGRESS:      return EINPROGRESS;
    case WSAEALREADY:         return EALREADY;
    case WSANOTINITIALISED:   return EINVAL;
    case WSAEFAULT:           return EFAULT;
    case WSAESHUTDOWN:        return EINVAL;
    case WSAEHOSTDOWN:        return ENETUNREACH;
    case WSAETOOMANYREFS:     return EIO;
    case WSAEDISCON:          return EIO;
    case WSAENOMORE:          return EIO;
    case WSAEPROCLIM:         return EIO;
    case WSAECONNRESET:       return ECONNRESET;
    case WSAECONNABORTED:     return ECONNABORTED;
    case WSAECONNREFUSED:     return ECONNREFUSED;
    case WSAETIMEDOUT:        return ETIMEDOUT;
    case WSAENETUNREACH:      return ENETUNREACH;
    case WSAEHOSTUNREACH:     return EHOSTUNREACH;
    case WSAENOBUFS:          return ENOBUFS;
    case WSAEINVAL:           return EINVAL;
    case WSAEAFNOSUPPORT:     return EAFNOSUPPORT;
    case WSAEADDRINUSE:       return EADDRINUSE;
    case WSAEADDRNOTAVAIL:    return EADDRNOTAVAIL;
    case WSAEISCONN:          return EISCONN;
    case WSAENOTCONN:         return ENOTCONN;
    case WSAEOPNOTSUPP:       return EOPNOTSUPP;
    case WSAEMSGSIZE:         return EMSGSIZE;
    case WSAEACCES:           return EACCES;
    case WSAENETDOWN:         return ENETDOWN;
    case WSAENETRESET:        return ENETRESET;
    case WSAEPROTONOSUPPORT:  return EPROTONOSUPPORT;
    case WSAEPROTOTYPE:       return EPROTOTYPE;
    default:                  return EIO;
    }
}

static void set_sock_errno_fn(int fd, const char *who)
{
    int e = WSAGetLastError();
    errno = wsa_errno(e);
    /* WSAEWOULDBLOCK / WSAEINTR are routine conditions on nonblocking
     * sockets (idle listener accept, flow IO): the callers handle them
     * like Linux's EAGAIN/EINTR, so log them as quietly as Linux does */
    if (e == WSAEWOULDBLOCK || e == WSAEINTR)
        return;
    log_debug("set_sock_errno(%s, fd=%d): winsock error %d -> errno %d",
              who, fd, e, errno);
}

/* logging macro: the failing wrapper's name and fd are recorded so a
 * winsock error can be traced to its call site */
#define set_sock_errno(fd) set_sock_errno_fn((int)(fd), __func__)

void port_socket_init(void)
{
    /* WSAStartup is refcounted and may be called again after a
     * WSANOTINITIALISED recovery (see port_socket); no WSACleanup is
     * ever issued, so the count only grows. */
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) {
        fprintf(stderr, "iwan: WSAStartup failed\n");
        exit(1);
    }
    /* the program writes UTF-8 (source literals); without this, wine
     * decodes console output as CP1252 and cmd.exe as the ANSI codepage
     * (e.g. GBK), mangling Chinese server names. Windows 10+ terminals
     * and wine honor CP_UTF8. Piped output is unaffected (raw bytes). */
    SetConsoleOutputCP(CP_UTF8);
}

int port_close(int fd)
{
    if (closesocket((SOCKET)fd) == SOCKET_ERROR) {
        set_sock_errno(fd);
        return -1;
    }
    return 0;
}

/* Toggle nonblocking with ioctlsocket FIONBIO. */
int port_set_nonblock(int fd, bool nb)
{
    u_long mode = nb ? 1 : 0;
    if (ioctlsocket((SOCKET)fd, FIONBIO, &mode) == SOCKET_ERROR) {
        set_sock_errno(fd);
        return -1;
    }
    return 0;
}

/* Per-call MSG_DONTWAIT emulation: winsock has no per-call flag, so
 * FIONBIO is toggled around the operation when the socket is blocking.
 * The nonblocking state is left ON once set (callers that need blocking
 * semantics — the auth socket — never pass MSG_DONTWAIT). */
static int ensure_nonblock(int fd)
{
    u_long mode = 1;
    if (ioctlsocket((SOCKET)fd, FIONBIO, &mode) == SOCKET_ERROR) {
        set_sock_errno(fd);
        return -1;
    }
    return 0;
}

ssize_t port_send(int fd, const void *buf, size_t len, int flags)
{
    int r;
    if ((flags & MSG_DONTWAIT) && ensure_nonblock(fd) != 0)
        return -1;
    r = send((SOCKET)fd, (const char *)buf, (int)len, 0);
    if (r == SOCKET_ERROR) {
        set_sock_errno(fd);
        return -1;
    }
    return (ssize_t)r;
}

ssize_t port_recv(int fd, void *buf, size_t len, int flags)
{
    int r;
    if ((flags & MSG_DONTWAIT) && ensure_nonblock(fd) != 0)
        return -1;
    r = recv((SOCKET)fd, (char *)buf, (int)len, 0);
    if (r == SOCKET_ERROR) {
        set_sock_errno(fd);
        return -1;
    }
    return (ssize_t)r;
}

ssize_t port_sendto(int fd, const void *buf, size_t len, int flags,
                    const struct sockaddr *to, socklen_t tolen)
{
    int r;
    if ((flags & MSG_DONTWAIT) && ensure_nonblock(fd) != 0)
        return -1;
    r = sendto((SOCKET)fd, (const char *)buf, (int)len, 0,
               (const struct sockaddr *)to, (int)tolen);
    if (r == SOCKET_ERROR) {
        set_sock_errno(fd);
        return -1;
    }
    return (ssize_t)r;
}

ssize_t port_recvfrom(int fd, void *buf, size_t len, int flags,
                      struct sockaddr *from, socklen_t *fromlen)
{
    int r;
    if ((flags & MSG_DONTWAIT) && ensure_nonblock(fd) != 0)
        return -1;
    r = recvfrom((SOCKET)fd, (char *)buf, (int)len, 0,
                 (struct sockaddr *)from, (int *)fromlen);
    if (r == SOCKET_ERROR) {
        set_sock_errno(fd);
        return -1;
    }
    return (ssize_t)r;
}

/* Convert an iovec array to WSABUF layout. NOTE: WSABUF is {ULONG len;
 * CHAR *buf} — the reverse field order of struct iovec {void *iov_base;
 * size_t iov_len} — so a direct cast is invalid (WSAEFAULT). Use the
 * stack array when it fits, else heap. Returns NULL with errno=ENOMEM
 * on allocation failure (heap path only); *heap_out records ownership. */
#define IOV_TO_WSABUF_STACK 64

static LPWSABUF iov_to_wsabuf(const struct iovec *iov, int n,
                              WSABUF *stack, bool *heap_out)
{
    int i;
    LPWSABUF w;

    *heap_out = false;
    if (n <= IOV_TO_WSABUF_STACK) {
        w = stack;
    } else {
        w = calloc((size_t)n, sizeof *w);
        if (!w) {
            errno = ENOMEM;
            return NULL;
        }
        *heap_out = true;
    }
    for (i = 0; i < n; i++) {
        w[i].len = (ULONG)iov[i].iov_len;
        w[i].buf = (CHAR *)iov[i].iov_base;
    }
    return w;
}

ssize_t port_sendmsg(int fd, const struct msghdr *msg, int flags)
{
    DWORD sent = 0;
    WSABUF stack[IOV_TO_WSABUF_STACK];
    bool heap = false;
    LPWSABUF w;

    if ((flags & MSG_DONTWAIT) && ensure_nonblock(fd) != 0)
        return -1;
    /* WSASendTo with a WSABUF array sends ONE datagram (concatenated
     * buffers), exactly the Linux sendmsg contract for SOCK_DGRAM. */
    w = iov_to_wsabuf(msg->msg_iov, msg->msg_iovlen, stack, &heap);
    if (!w)
        return -1;
    if (WSASendTo((SOCKET)fd, w, (DWORD)msg->msg_iovlen, &sent, 0,
                  (const struct sockaddr *)msg->msg_name,
                  (int)msg->msg_namelen, NULL, NULL) == SOCKET_ERROR) {
        if (heap)
            free(w);
        set_sock_errno(fd);
        return -1;
    }
    if (heap)
        free(w);
    return (ssize_t)sent;
}

ssize_t port_recvmsg(int fd, struct msghdr *msg, int flags)
{
    DWORD got = 0;
    DWORD wflags = 0;
    int namelen = (int)msg->msg_namelen;
    WSABUF stack[IOV_TO_WSABUF_STACK];
    bool heap = false;
    LPWSABUF w;

    if ((flags & MSG_DONTWAIT) && ensure_nonblock(fd) != 0)
        return -1;
    w = iov_to_wsabuf(msg->msg_iov, msg->msg_iovlen, stack, &heap);
    if (!w)
        return -1;
    /* Windows quirk: WSARecvFrom with lpFrom=NULL and a NON-NULL
     * lpFromlen fails with WSAEFAULT even on connected datagram
     * sockets (Linux accepts both). Pass both NULL when the caller
     * does not want the source address. */
    if (WSARecvFrom((SOCKET)fd, w, (DWORD)msg->msg_iovlen, &got, &wflags,
                    (struct sockaddr *)msg->msg_name,
                    msg->msg_name ? &namelen : NULL, NULL,
                    NULL) == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (heap)
            free(w);
        if (e == WSAEMSGSIZE) {
            /* datagram did not fit the buffers: report MSG_TRUNC like
             * Linux so the caller drops it (see socks.c/proxy.c) */
            msg->msg_flags |= MSG_TRUNC;
            return (ssize_t)got;
        }
        errno = wsa_errno(e);
            log_debug("port_sendto: winsock error %d -> errno %d", e, errno);
        return -1;
    }
    if (heap)
        free(w);
    msg->msg_namelen = (socklen_t)namelen;
    msg->msg_flags = 0;
    return (ssize_t)got;
}

int port_sendmmsg(int fd, struct mmsghdr *msgvec, unsigned vlen, int flags)
{
    unsigned sent = 0;
    if ((flags & MSG_DONTWAIT) && ensure_nonblock(fd) != 0)
        return -1;
    for (; sent < vlen; sent++) {
        DWORD n = 0;
        WSABUF stack[IOV_TO_WSABUF_STACK];
        bool heap = false;
        LPWSABUF w = iov_to_wsabuf(msgvec[sent].msg_hdr.msg_iov,
                                   msgvec[sent].msg_hdr.msg_iovlen, stack,
                                   &heap);
        if (!w)
            return -1;
        if (WSASendTo((SOCKET)fd, w,
                      (DWORD)msgvec[sent].msg_hdr.msg_iovlen, &n, 0,
                      (const struct sockaddr *)msgvec[sent].msg_hdr.msg_name,
                      (int)msgvec[sent].msg_hdr.msg_namelen, NULL,
                      NULL) == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (heap)
                free(w);
            if (sent > 0)
                return (int)sent;   /* partial batch: Linux semantics */
            errno = wsa_errno(e);
            log_debug("port_sendmmsg: winsock error %d -> errno %d", e, errno);
            return -1;
        }
        if (heap)
            free(w);
    }
    return (int)sent;
}

int port_recvmmsg(int fd, struct mmsghdr *msgvec, unsigned vlen, int flags,
                  struct timespec *timeout)
{
    unsigned got = 0;
    (void)timeout;   /* Linux's timeout bounds only the first wait; the
                      * callers here use MSG_DONTWAIT + poll instead */
    if ((flags & MSG_DONTWAIT) && ensure_nonblock(fd) != 0)
        return -1;
    for (; got < vlen; got++) {
        DWORD n = 0;
        DWORD wflags = 0;
        int namelen = (int)msgvec[got].msg_hdr.msg_namelen;
        WSABUF stack[IOV_TO_WSABUF_STACK];
        bool heap = false;
        LPWSABUF w = iov_to_wsabuf(msgvec[got].msg_hdr.msg_iov,
                                   msgvec[got].msg_hdr.msg_iovlen, stack,
                                   &heap);
        if (!w)
            return -1;
        if (WSARecvFrom((SOCKET)fd, w,
                        (DWORD)msgvec[got].msg_hdr.msg_iovlen, &n, &wflags,
                        (struct sockaddr *)msgvec[got].msg_hdr.msg_name,
                        msgvec[got].msg_hdr.msg_name ? &namelen : NULL,
                        NULL, NULL) == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (heap)
                free(w);
            if (e == WSAEMSGSIZE) {
                msgvec[got].msg_len = n;
                msgvec[got].msg_hdr.msg_flags |= MSG_TRUNC;
                got++;
                return (int)got;
            }
            if (e == WSAEWOULDBLOCK || e == WSAEINTR ||
                e == WSAECONNRESET)
                return (int)got;   /* drained: 0 messages is not an
                                    * error; WSAECONNRESET is the
                                    * connected-UDP ICMP artifact
                                    * (SIO_UDP_CONNRESET disables it at
                                    * the socket, this is the backstop) */
            if (got > 0)
                return (int)got;
            errno = wsa_errno(e);
            log_debug("port_recvmmsg: winsock error %d -> errno %d", e, errno);
            return -1;
        }
        if (heap)
            free(w);
        msgvec[got].msg_len = n;
        msgvec[got].msg_hdr.msg_flags = 0;
    }
    return (int)got;
}

#define READV_BOUNCE_BYTES 16384

ssize_t port_readv(int fd, const struct iovec *iov, int iovcnt)
{
    /* Real Windows (observed on Tiny11) fails WSARecv with WSAEFAULT
     * (10014) for scatter/gather buffers located in the module's static
     * data on an otherwise healthy accepted TCP socket — while plain
     * recv() on the same socket works (the SOCKS handshake proves it).
     * recv() has no gather: bounce through a stack buffer and copy out. */
    char bounce[READV_BOUNCE_BYTES];
    size_t total = 0;
    int i;
    ssize_t n;

    if (iovcnt <= 0 || !iov)
        return 0;
    for (i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len >= READV_BOUNCE_BYTES - total) {
            total = READV_BOUNCE_BYTES;
            break;
        }
        total += iov[i].iov_len;
    }
    if (total == 0)
        return 0;
    n = recv((SOCKET)fd, bounce, (int)total, 0);
    if (n == SOCKET_ERROR) {
        set_sock_errno(fd);
        return -1;
    }
    if (n > 0) {
        size_t off = 0;
        for (i = 0; i < iovcnt && off < (size_t)n; i++) {
            size_t c = iov[i].iov_len;
            if (c > (size_t)n - off)
                c = (size_t)n - off;
            memcpy(iov[i].iov_base, bounce + off, c);
            off += c;
        }
    }
    return (ssize_t)n;
}

ssize_t port_writev(int fd, const struct iovec *iov, int iovcnt)
{
    DWORD sent = 0;
    WSABUF stack[IOV_TO_WSABUF_STACK];
    bool heap = false;
    LPWSABUF w = iov_to_wsabuf(iov, iovcnt, stack, &heap);
    if (!w)
        return -1;
    if (WSASend((SOCKET)fd, w, (DWORD)iovcnt, &sent, 0, NULL, NULL) ==
        SOCKET_ERROR) {
        if (heap)
            free(w);
        set_sock_errno(fd);
        return -1;
    }
    if (heap)
        free(w);
    return (ssize_t)sent;
}

int port_socket(int domain, int type, int protocol)
{
    SOCKET s = socket(domain, type, protocol);
    if (s == INVALID_SOCKET) {
        int e = WSAGetLastError();
        log_debug("port_socket(%d,%d,%d): wsa %d", domain, type, protocol,
                  e);
        /* wine has been observed to lose the WSAStartup state between
         * long idle gaps (subsequent socket() reports WSANOTINITIALISED
         * even though main() initialized it); re-initialize once and
         * retry instead of failing the request */
        if (e == WSANOTINITIALISED) {
            port_socket_init();
            s = socket(domain, type, protocol);
            if (s != INVALID_SOCKET) {
                log_debug("port_socket: recovered after WSANOTINITIALISED");
                return (int)s;
            }
            e = WSAGetLastError();
        }
        errno = wsa_errno(e);
            log_debug("port_socket: winsock error %d -> errno %d", e, errno);
        return -1;
    }
    return (int)s;
}

int port_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    SOCKET s = accept((SOCKET)fd, addr, (int *)addrlen);
    if (s == INVALID_SOCKET) {
        set_sock_errno(fd);
        return -1;
    }
    return (int)s;
}

int port_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    if (connect((SOCKET)fd, (const struct sockaddr *)addr, (int)len) ==
        SOCKET_ERROR) {
        int e = WSAGetLastError();
        /* nonblocking connect: POSIX reports EINPROGRESS; winsock may
         * report WSAEWOULDBLOCK, WSAEINPROGRESS or WSAEALREADY —
         * normalize all three so callers' EINPROGRESS/EAGAIN checks
         * catch every in-flight case */
        if (e == WSAEWOULDBLOCK || e == WSAEINPROGRESS ||
            e == WSAEALREADY) {
            errno = EINPROGRESS;
            return -1;
        }
        errno = wsa_errno(e);
            log_debug("port_connect: winsock error %d -> errno %d", e, errno);
        return -1;
    }
    return 0;
}

int port_bind(int fd, const struct sockaddr *addr, socklen_t len)
{
    if (bind((SOCKET)fd, (const struct sockaddr *)addr, (int)len) ==
        SOCKET_ERROR) {
        set_sock_errno(fd);
        return -1;
    }
    return 0;
}

int port_listen(int fd, int backlog)
{
    if (listen((SOCKET)fd, backlog) == SOCKET_ERROR) {
        set_sock_errno(fd);
        return -1;
    }
    return 0;
}

int port_shutdown(int fd, int how)
{
    if (shutdown((SOCKET)fd, how) == SOCKET_ERROR) {
        set_sock_errno(fd);
        return -1;
    }
    return 0;
}

int port_getsockopt(int fd, int level, int optname, void *optval,
                    socklen_t *optlen)
{
    if (getsockopt((SOCKET)fd, level, optname, (char *)optval,
                   (int *)optlen) == SOCKET_ERROR) {
        set_sock_errno(fd);
        return -1;
    }
    return 0;
}

int port_setsockopt(int fd, int level, int optname, const void *optval,
                    socklen_t optlen)
{
    /* SO_RCVTIMEO / SO_SNDTIMEO: winsock wants DWORD milliseconds. */
    if ((level == SOL_SOCKET) &&
        (optname == SO_RCVTIMEO || optname == SO_SNDTIMEO)) {
        const struct timeval *tv = (const struct timeval *)optval;
        DWORD ms = (DWORD)(tv->tv_sec * 1000 + tv->tv_usec / 1000);
        if (setsockopt((SOCKET)fd, SOL_SOCKET, optname, (const char *)&ms,
                       sizeof ms) == SOCKET_ERROR) {
            set_sock_errno(fd);
            return -1;
        }
        return 0;
    }
    /* UDP_SEGMENT (Linux GSO) -> SIO_UDP_NETSEGMENT (Win11+). Fails
     * with WSAEOPNOTSUPP on older systems: callers cache gso_ok=-1
     * and fall back to per-datagram sends, exactly like Linux. */
    if (level == SOL_UDP && optname == UDP_SEGMENT) {
        DWORD mss = *(const int *)optval > 0 ? (DWORD)(*(const int *)optval)
                                             : 0;
        DWORD ret = 0;
        if (WSAIoctl((SOCKET)fd, SIO_UDP_NETSEGMENT, &mss, sizeof mss,
                     NULL, 0, &ret, NULL, NULL) == SOCKET_ERROR) {
            set_sock_errno(fd);
            return -1;
        }
        return 0;
    }
    if (setsockopt((SOCKET)fd, level, optname, (const char *)optval,
                   (int)optlen) == SOCKET_ERROR) {
        set_sock_errno(fd);
        return -1;
    }
    return 0;
}

int port_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms)
{
    int r = WSAPoll(fds, nfds, timeout_ms < 0 ? -1 : timeout_ms);
    if (r == SOCKET_ERROR) {
        int e = WSAGetLastError();
        errno = wsa_errno(e);
            log_debug("port_poll: winsock error %d -> errno %d", e, errno);
        return -1;
    }
    return r;
}

/* ---- eventfd substitute: self-connected UDP socketpair ------------ */
/* The wake side is a static peer socket: only one evfd exists per
 * process in practice (the SOCKS DNS wakeup), and the peer is closed
 * on process exit. The returned fd is a normal socket: pollable with
 * WSAPoll and closed with port_evfd_close. */

static SOCKET g_evfd_peer = INVALID_SOCKET;

int port_evfd_create(void)
{
    struct sockaddr_in a;
    socklen_t alen = sizeof a;
    SOCKET s, peer;
    int one = 1;

    /* process-level singleton: only one evfd exists per process (the
     * SOCKS DNS wakeup). A second create would otherwise silently
     * redirect the first one's wakeups; retire the old peer first. */
    if (g_evfd_peer != INVALID_SOCKET) {
        closesocket(g_evfd_peer);
        g_evfd_peer = INVALID_SOCKET;
    }

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
        return -1;
    peer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (peer == INVALID_SOCKET) {
        closesocket(s);
        return -1;
    }
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR ||
        getsockname(s, (struct sockaddr *)&a, &alen) == SOCKET_ERROR) {
        closesocket(s);
        closesocket(peer);
        return -1;
    }
    if (connect(peer, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR) {
        closesocket(s);
        closesocket(peer);
        return -1;
    }
    /* the read side must never block the drain; the peer side is only
     * ever written to */
    {
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
    }
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&one, sizeof one);
    /* loopback rcvbuf: a wake byte is tiny; keep defaults otherwise */
    g_evfd_peer = peer;
    return (int)s;
}

int port_evfd_wake(int fd)
{
    char c = 1;
    (void)fd;   /* the wake side is the static peer socket */
    if (g_evfd_peer == INVALID_SOCKET)
        return -1;
    if (send(g_evfd_peer, &c, 1, 0) == SOCKET_ERROR)
        return -1;
    return 0;
}

int port_evfd_drain(int fd)
{
    char buf[64];
    for (;;) {
        int r = recv((SOCKET)fd, buf, sizeof buf, 0);
        if (r == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAEWOULDBLOCK)
                return 0;
            return -1;
        }
    }
}

void port_evfd_close(int fd)
{
    closesocket((SOCKET)fd);
    if (g_evfd_peer != INVALID_SOCKET) {
        closesocket(g_evfd_peer);
        g_evfd_peer = INVALID_SOCKET;
    }
}

void port_ignore_sigpipe(void)
{
    /* winsock surfaces peer death as WSAECONNRESET; no SIGPIPE exists */
}

#endif /* _WIN32 */

#ifdef __APPLE__
/* ---- macOS eventfd substitute: self-connected UDP socketpair ---- */
/* Identical shape to the Windows substitute (port.h documents the
 * contract): the wake side is a static peer socket — only one evfd
 * exists per process in practice (the SOCKS DNS wakeup) — and the
 * returned fd is a normal socket: poll-able and closed with
 * port_evfd_close. */

static int g_evfd_peer = -1;

int port_evfd_create(void)
{
    struct sockaddr_in a;
    socklen_t alen = sizeof a;
    int s, peer;
    int one = 1;

    /* process-level singleton, same reasoning as the winsock version */
    if (g_evfd_peer >= 0) {
        close(g_evfd_peer);
        g_evfd_peer = -1;
    }

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0)
        return -1;
    peer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (peer < 0) {
        close(s);
        return -1;
    }
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 ||
        getsockname(s, (struct sockaddr *)&a, &alen) != 0) {
        close(s);
        close(peer);
        return -1;
    }
    if (connect(peer, (struct sockaddr *)&a, sizeof a) != 0) {
        close(s);
        close(peer);
        return -1;
    }
    /* the read side must never block the drain; the peer side is only
     * ever written to */
    if (port_set_nonblock(s, true) != 0) {
        close(s);
        close(peer);
        return -1;
    }
    (void)setsockopt(s, SOL_SOCKET, SO_RCVBUF, &one, sizeof one);
    g_evfd_peer = peer;
    return s;
}

int port_evfd_wake(int fd)
{
    char c = 1;
    (void)fd;   /* the wake side is the static peer socket */
    if (g_evfd_peer < 0)
        return -1;
    if (send(g_evfd_peer, &c, 1, 0) != 1)
        return -1;
    return 0;
}

int port_evfd_drain(int fd)
{
    char buf[64];
    for (;;) {
        ssize_t r = recv(fd, buf, sizeof buf, 0);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            return -1;
        }
    }
}

void port_evfd_close(int fd)
{
    close(fd);
    if (g_evfd_peer >= 0) {
        close(g_evfd_peer);
        g_evfd_peer = -1;
    }
}
#endif /* __APPLE__ */
