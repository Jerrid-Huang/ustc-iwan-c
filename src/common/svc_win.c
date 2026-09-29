/* svc_win.c — Windows service front-end for the classic client.
 *
 * iwan-winsvc.exe = iwan_client.c (compiled with IWAN_HEADLESS_SVC, so
 * its main() is renamed to iwan_client_main) + this shell. The service
 * does NOT re-implement anything: it synthesizes the same argv a user
 * would type and runs the real command path on a worker thread.
 *
 * Scope guards (see README "Windows service"): classic protocol only.
 * OIDC login needs a browser + stdin and the pwsecret store is a
 * DPAPI user blob — both structurally unavailable to a session-0
 * service, so an OIDC profile must keep running in user context.
 *
 * Lifecycle: the SCM stop command never reaches a console handler in
 * session 0 (no console). The control handler therefore calls
 * port_raise_stop() — the exact function path a console Ctrl+C takes —
 * plus re-raises while the worker outlives the grace window. The
 * worker exits through the same teardown a Ctrl+C drives (route
 * teardown, default-route restore), so no service-specific cleanup.
 *
 * argv flow: install bakes the client args verbatim into the service
 * ImagePath after `--`; `run` re-reads them with CommandLineToArgvW,
 * converts to UTF-8 (the client expects UTF-8 args like every other
 * Windows entry point here) and passes them to iwan_client_main.
 *
 * Modes:
 *   --service install -- <client argv...>   (admin; --name --display
 *                                            --manual --start --log)
 *   --service uninstall|start|stop|status   (admin for the first three)
 *   --service run                           (SCM entry, baked ImagePath)
 *   anything else                           classic client, foreground
 */
#include <winsock2.h>   /* before windows.h (mingw winsock2.h #warnings) */
#include <windows.h>
#include <shellapi.h>   /* CommandLineToArgvW */

#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "port.h"

#ifndef IWAN_SVC_VERSION
#define IWAN_SVC_VERSION "0.8.0"
#endif

extern int iwan_client_main(int argc, char **argv);

#define SVC_DEFAULT_NAME    L"iwan-winsvc"
#define SVC_DEFAULT_DISPLAY L"USTC iWAN Client"
#define SVC_LOG_MAX_BYTES   (5u << 20)
#define SVC_STOP_GRACE_MS   60000   /* worker exit grace before we stop anyway */

static SERVICE_STATUS_HANDLE g_ssh;
static SERVICE_STATUS g_status;
static HANDLE g_stop_ev;        /* autoreset: stop requested */
static HANDLE g_worker;

/* ------------------------------------------------------------------ */
/* small wide-string helpers (fixed buffers: paths here are bounded)   */
/* ------------------------------------------------------------------ */

static bool g_wput_overflow;    /* wput silently cannot append: the
                                 * caller must fail instead of installing
                                 * a truncated ImagePath */

static void wput(wchar_t *buf, size_t cap, size_t *len, const wchar_t *s)
{
    size_t n = wcslen(s);
    if (*len + n + 1 > cap) {
        g_wput_overflow = true;
        return;
    }
    wcscpy(buf + *len, s);
    *len += n;
}

/* Quote one argument the way CommandLineToArgvW parses (backslash runs
 * before quotes doubled, arg quoted when it holds space/tab/quote). */
static void wput_arg(wchar_t *buf, size_t cap, size_t *len, const wchar_t *a)
{
    bool q = wcspbrk(a, L" \t\"") != NULL;
    if (!q) {
        wput(buf, cap, len, a);
        wput(buf, cap, len, L" ");
        return;
    }
    wput(buf, cap, len, L"\"");
    size_t bs = 0;
    for (const wchar_t *p = a; ; p++) {
        if (*p == L'\\') {
            bs++;
            continue;
        }
        if (*p == L'"') {
            for (size_t i = 0; i < bs * 2 + 1; i++)
                wput(buf, cap, len, L"\\");
            wput(buf, cap, len, L"\"");
        } else if (*p == L'\0') {
            for (size_t i = 0; i < bs * 2; i++)   /* trailing backslashes */
                wput(buf, cap, len, L"\\");
            break;
        } else {
            for (size_t i = 0; i < bs; i++)
                wput(buf, cap, len, L"\\");
            wchar_t one[2] = { *p, 0 };
            wput(buf, cap, len, one);
        }
        bs = 0;
    }
    wput(buf, cap, len, L"\" ");
}

/* ------------------------------------------------------------------ */
/* service status / control                                            */
/* ------------------------------------------------------------------ */

/* Non-zero once the run is known to have failed: reported through
 * ERROR_SERVICE_SPECIFIC_ERROR so the SCM's failure actions (restart
 * 10s/30s/60s, set at install) actually fire. A clean stop must report
 * NO_ERROR, so this must survive later set_status() calls. */
static DWORD g_exit_code;

static void set_status(DWORD state, DWORD checkpoint, DWORD wait_hint)
{
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted =
        state == SERVICE_RUNNING
            ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN |
               SERVICE_ACCEPT_PRESHUTDOWN)
            : 0;   /* INTERROGATE needs no acceptance bit */
    g_status.dwCheckPoint = checkpoint;
    g_status.dwWaitHint = wait_hint;
    if (g_exit_code != 0) {
        g_status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        g_status.dwServiceSpecificExitCode = g_exit_code;
    } else {
        g_status.dwWin32ExitCode = NO_ERROR;
        g_status.dwServiceSpecificExitCode = 0;
    }
    SetServiceStatus(g_ssh, &g_status);
}

static void svc_pre_stop(int sig)   /* cdecl: port.h contract, not WINAPI */
{
    (void)sig;
    SetEvent(g_stop_ev);
}

static DWORD WINAPI svc_ctrl(DWORD ctrl, DWORD evt, void *data, void *ctx)
{
    (void)evt; (void)data; (void)ctx;
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
    case SERVICE_CONTROL_PRESHUTDOWN:
        SetEvent(g_stop_ev);
        port_raise_stop();      /* same path as a console Ctrl+C */
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        if (g_ssh)
            SetServiceStatus(g_ssh, &g_status);
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/* ------------------------------------------------------------------ */
/* logging: the service has no console; point stdout+stderr at a file  */
/* ------------------------------------------------------------------ */

static void log_ts(void)
{
    SYSTEMTIME t;
    GetLocalTime(&t);
    printf("[%04u-%02u-%02u %02u:%02u:%02u] ", t.wYear, t.wMonth, t.wDay,
           t.wHour, t.wMinute, t.wSecond);
}

static void open_log(const wchar_t *path)
{
    wchar_t dir[MAX_PATH];
    wcscpy(dir, path);
    wchar_t *slash = wcsrchr(dir, L'\\');
    if (slash != NULL) {
        *slash = L'\0';
        _wmkdir(dir);           /* EEXIST fine; parent assumed present */
    }
    struct _stati64 st;
    if (_wstati64(path, &st) == 0 && (unsigned long long)st.st_size >
        SVC_LOG_MAX_BYTES) {
        wchar_t oldp[MAX_PATH];
        _snwprintf(oldp, sizeof oldp / sizeof oldp[0], L"%ls.old", path);
        _wunlink(oldp);
        _wrename(path, oldp);   /* single-generation rotation at startup */
    }
    int fd = _wopen(path, O_WRONLY | O_APPEND | O_CREAT | O_BINARY,
                    _S_IREAD | _S_IWRITE);
    if (fd < 0)
        return;                 /* keep going: logs lost beats service dead */
    _dup2(fd, 1);
    _dup2(fd, 2);
    if (fd > 2)
        _close(fd);
    setvbuf(stdout, NULL, _IOLBF, 4096);
    setvbuf(stderr, NULL, _IONBF, 0);
}

/* ------------------------------------------------------------------ */
/* run mode (SCM)                                                      */
/* ------------------------------------------------------------------ */

struct worker_args {
    int argc;
    char **argv;
};

static DWORD WINAPI worker(LPVOID p)
{
    struct worker_args *wa = (struct worker_args *)p;
    return (DWORD)iwan_client_main(wa->argc, wa->argv);
}

/* default log: %PROGRAMDATA%\iwan\service.log */
static void default_log_path(wchar_t *out, size_t cap)
{
    wchar_t base[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"PROGRAMDATA", base, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        wcscpy(base, L"C:\\ProgramData");
    _snwprintf(out, cap, L"%ls\\iwan\\service.log", base);
}

static bool name_ok(const wchar_t *n)
{
    if (n == NULL || *n == L'\0' || wcslen(n) > 80)
        return false;
    for (const wchar_t *p = n; *p; p++) {
        bool ok = (*p >= L'A' && *p <= L'Z') || (*p >= L'a' && *p <= L'z') ||
                  (*p >= L'0' && *p <= L'9') || *p == L'-' || *p == L'_';
        if (!ok)
            return false;
    }
    return true;
}

static void WINAPI svc_main(DWORD argc, LPWSTR *argv)
{
    (void)argc; (void)argv;
    wchar_t name[96] = L"";
    wchar_t logpath[MAX_PATH];
    default_log_path(logpath, MAX_PATH);

    /* own command line == baked ImagePath: [--service run] [--name N]
     * [--log P] -- <client args...> */
    int n = 0;
    LPWSTR *wv = CommandLineToArgvW(GetCommandLineW(), &n);
    if (wv == NULL)
        return;
    int client0 = -1;
    wchar_t parsed_name[96] = L"";
    for (int i = 1; i < n; i++) {
        if (client0 < 0 && wcscmp(wv[i], L"--") == 0) {
            client0 = i + 1;
            continue;
        }
        if (client0 >= 0)
            continue;
        if (wcscmp(wv[i], L"--name") == 0 && i + 1 < n)
            wcscpy(parsed_name, wv[++i]);
        else if (wcscmp(wv[i], L"--log") == 0 && i + 1 < n)
            wcscpy(logpath, wv[++i]);
    }
    if (name_ok(parsed_name))
        wcscpy(name, parsed_name);
    else
        wcscpy(name, SVC_DEFAULT_NAME);

    g_stop_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_stop_ev == NULL) {
        LocalFree(wv);
        return;
    }
    g_ssh = RegisterServiceCtrlHandlerExW(name, svc_ctrl, NULL);
    if (g_ssh == NULL) {
        LocalFree(wv);
        return;
    }
    memset(&g_status, 0, sizeof g_status);
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    set_status(SERVICE_START_PENDING, 10, 30000);

    open_log(logpath);
    log_ts();
    printf("iwan-winsvc %s starting (service \"%ls\", log %S)\n",
           IWAN_SVC_VERSION, name, logpath);

    if (client0 < 0 || client0 >= n) {
        log_ts();
        printf("error: no client args in ImagePath (installed without "
               "\"-- <client args>\"?) — refusing to start\n");
        g_exit_code = 87;
        set_status(SERVICE_STOPPED, 0, 0);
        ExitProcess(87);
    }

    /* build UTF-8 argv: [self, client args...] */
    int ca = n - client0 + 1;
    char **av = calloc((size_t)ca + 1, sizeof(char *));
    if (av == NULL) {
        g_exit_code = 14;
        set_status(SERVICE_STOPPED, 0, 0);
        ExitProcess(14);
    }
    av[0] = _strdup("iwan-winsvc");
    for (int i = client0; i < n; i++) {
        int need = WideCharToMultiByte(CP_UTF8, 0, wv[i], -1, NULL, 0, NULL,
                                       NULL);
        av[i - client0 + 1] = malloc(need > 0 ? (size_t)need : 1);
        if (av[i - client0 + 1] == NULL) {
            g_exit_code = 14;
            set_status(SERVICE_STOPPED, 0, 0);
            ExitProcess(14);
        }
        WideCharToMultiByte(CP_UTF8, 0, wv[i], -1, av[i - client0 + 1], need,
                            NULL, NULL);
    }
    LocalFree(wv);
    wv = NULL;

    log_ts();
    /* the service log is a file that outlives the console: secrets must
     * never land in it (the client itself cleanses them everywhere).
     * Both spellings the parser accepts: "--pass V" and "--pass=V". */
    printf("client args:");
    bool redact_next = false;
    for (int i = 1; i < ca; i++) {
        if (redact_next) {
            printf(" ****");
            redact_next = false;
            continue;
        }
        const char *eq = strchr(av[i], '=');
        bool secret = false;
        if (strncmp(av[i], "--", 2) == 0) {
            static const char *const sec[] = { "--pass", "--ct-pass",
                                               "--socks-token" };
            for (size_t k = 0; k < sizeof sec / sizeof sec[0]; k++) {
                size_t sl = strlen(sec[k]);
                if ((eq != NULL && (size_t)(eq - av[i]) == sl &&
                     strncmp(av[i], sec[k], sl) == 0) ||
                    (eq == NULL && strcmp(av[i], sec[k]) == 0)) {
                    secret = true;
                    break;
                }
            }
        }
        if (secret) {
            if (eq != NULL)
                printf(" %.*s=****", (int)(eq - av[i]), av[i]);
            else {
                printf(" %s ****", av[i]);
                redact_next = true;
            }
            continue;
        }
        printf(" %s", av[i]);
    }
    printf("\n");

    /* stop handler until the client installs its own: fires the event;
     * after that port_raise_stop() routes to the client's handler */
    port_set_stop_handler(svc_pre_stop);

    static struct worker_args wa;   /* the worker keeps this pointer;
                                     * static so a return cannot dangle it */
    wa.argc = ca;
    wa.argv = av;
    g_worker = CreateThread(NULL, 0, worker, &wa, 0, NULL);
    if (g_worker == NULL) {
        log_ts();
        printf("error: CreateThread failed (%lu)\n", GetLastError());
        g_exit_code = 5;
        set_status(SERVICE_STOPPED, 0, 0);
        ExitProcess(5);
    }

    /* start window: checkpoints while the client authenticates */
    for (int i = 0; i < 24; i++) {
        if (WaitForSingleObject(g_stop_ev, 500) == WAIT_OBJECT_0)
            break;
        set_status(SERVICE_START_PENDING, 20 + (DWORD)i, 30000);
    }
    bool stop_wanted = WaitForSingleObject(g_stop_ev, 0) == WAIT_OBJECT_0;
    if (!stop_wanted) {
        log_ts();
        printf("running (state RUNNING; \"sc stop %S\")\n", name);
        set_status(SERVICE_RUNNING, 0, 0);
    } else {
        set_status(SERVICE_STOP_PENDING, 50, 20000);
    }

    /* steady state: wait for stop request or worker exit */
    HANDLE hs[2] = { g_stop_ev, g_worker };
    WaitForMultipleObjects(2, hs, FALSE, INFINITE);
    log_ts();
    printf("stopping: signaling the client, route teardown follows\n");
    set_status(SERVICE_STOP_PENDING, 60, SVC_STOP_GRACE_MS);
    DWORD r = WAIT_TIMEOUT;
    for (int i = 0;
         i < 20 &&
         (r = WaitForSingleObject(g_worker, 3000)) == WAIT_TIMEOUT;
         i++) {
        port_raise_stop();      /* the client may install its handler late */
        set_status(SERVICE_STOP_PENDING, 61 + (DWORD)i, SVC_STOP_GRACE_MS);
    }
    DWORD rc = 0;
    if (r == WAIT_OBJECT_0) {
        GetExitCodeThread(g_worker, &rc);
        log_ts();
        printf("client exited rc=%lu\n", rc);
    } else {
        log_ts();
        printf("client did not stop within grace; service goes STOPPED "
               "(routes self-heal: tun routes die with the adapter)\n");
        rc = 0xdead;
    }
    g_exit_code = rc;           /* non-zero => SCM failure actions fire */
    set_status(SERVICE_STOPPED, 0, 0);
    ExitProcess(0);             /* reap whatever the client left behind */
}

/* ------------------------------------------------------------------ */
/* install / uninstall / start / stop / status (CLI)                   */
/* ------------------------------------------------------------------ */

static const wchar_t *state_str(DWORD s)
{
    switch (s) {
    case SERVICE_STOPPED:          return L"STOPPED";
    case SERVICE_START_PENDING:    return L"START_PENDING";
    case SERVICE_STOP_PENDING:     return L"STOP_PENDING";
    case SERVICE_RUNNING:          return L"RUNNING";
    case SERVICE_CONTINUE_PENDING: return L"CONTINUE_PENDING";
    case SERVICE_PAUSE_PENDING:    return L"PAUSE_PENDING";
    case SERVICE_PAUSED:           return L"PAUSED";
    default:                       return L"?";
    }
}

static SC_HANDLE open_svc(const wchar_t *name, DWORD access)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL)
        return NULL;
    SC_HANDLE svc = OpenServiceW(scm, name, access);
    CloseServiceHandle(scm);
    return svc;
}

static int wait_state(SC_HANDLE svc, DWORD want, int seconds)
{
    SERVICE_STATUS st;
    for (int i = 0; i < seconds * 10; i++) {
        if (!QueryServiceStatus(svc, &st))
            return -1;
        if (st.dwCurrentState == want)
            return 0;
        if (want == SERVICE_STOPPED &&
            st.dwCurrentState == SERVICE_STOPPED)
            return 0;
        Sleep(100);
    }
    return -1;
}

static void usage(void)
{
    fprintf(stderr,
        "iwan-winsvc " IWAN_SVC_VERSION " - USTC iWAN client, Windows service front-end\n"
        "\n"
        "usage (service, elevated):\n"
        "  iwan-winsvc --service install [--name N] [--display D]\n"
        "              [--manual] [--start] [--log PATH] -- <client args>\n"
        "      client args are stored verbatim in the ImagePath, e.g.:\n"
        "        -- proxy -c --server HOST:6001 --config-dir C:\\ProgramData\\iwan\n"
        "      classic protocol only (no OIDC in service context); AUTO_START\n"
        "      unless --manual; failure restarts 10s/30s/60s\n"
        "  iwan-winsvc --service uninstall|start|stop|status [--name N]\n"
        "\n"
        "service log: %%PROGRAMDATA%%\\iwan\\service.log (rotate: service.log.old)\n"
        "any other args run the classic client in the foreground (iwan-client)\n");
}

static int cmd_install(int argc, char **argv)
{
    wchar_t name[96] = L"";
    wchar_t display[160] = L"";
    wchar_t logp[MAX_PATH];
    bool have_log = false, manual = false, start_now = false;
    int dashdash = -1;
    char *name_a = NULL, *disp_a = NULL, *log_a = NULL;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            dashdash = i;
            break;
        } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc)
            name_a = argv[++i];
        else if (strcmp(argv[i], "--display") == 0 && i + 1 < argc)
            disp_a = argv[++i];
        else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc)
            log_a = argv[++i];
        else if (strcmp(argv[i], "--manual") == 0)
            manual = true;
        else if (strcmp(argv[i], "--start") == 0)
            start_now = true;
        else {
            fprintf(stderr, "error: unknown install option '%s'\n", argv[i]);
            return 2;
        }
    }
    if (dashdash < 0 || dashdash + 1 >= argc) {
        fprintf(stderr, "error: install needs the client args after `--`, "
                        "e.g. `-- proxy -c --server H:P --config-dir D`\n");
        return 2;
    }
    if (!port_is_admin()) {
        fprintf(stderr, "error: install needs an elevated prompt\n");
        return 1;
    }
    if (name_a != NULL)
        MultiByteToWideChar(CP_UTF8, 0, name_a, -1, name, 96);
    if (!name_ok(name))
        wcscpy(name, SVC_DEFAULT_NAME);
    if (disp_a != NULL)
        MultiByteToWideChar(CP_UTF8, 0, disp_a, -1, display, 160);
    if (*display == L'\0')
        wcscpy(display, SVC_DEFAULT_DISPLAY);
    if (log_a != NULL) {
        if (MultiByteToWideChar(CP_UTF8, 0, log_a, -1, logp, MAX_PATH) <= 0) {
            fprintf(stderr, "error: bad --log path '%s'\n", log_a);
            return 2;
        }
        have_log = true;
    } else {
        default_log_path(logp, MAX_PATH);
    }

    wchar_t img[8192];
    size_t len = 0;
    wchar_t mod[MAX_PATH];
    GetModuleFileNameW(NULL, mod, MAX_PATH);
    wput_arg(img, sizeof img / sizeof img[0], &len, mod);
    wput(img, sizeof img / sizeof img[0], &len, L"--service run ");
    wput(img, sizeof img / sizeof img[0], &len, L"--name ");
    wput(img, sizeof img / sizeof img[0], &len, name);
    wput(img, sizeof img / sizeof img[0], &len, L" ");
    if (have_log) {
        wput(img, sizeof img / sizeof img[0], &len, L"--log ");
        wput_arg(img, sizeof img / sizeof img[0], &len, logp);
    }
    wput(img, sizeof img / sizeof img[0], &len, L"-- ");
    for (int i = dashdash + 1; i < argc; i++) {
        wchar_t a[2048];
        a[0] = L'\0';
        if (MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, a, 2048) <= 0) {
            fprintf(stderr, "error: argument %d is not valid UTF-8 or is "
                            "too long\n", i);
            return 2;
        }
        wput_arg(img, sizeof img / sizeof img[0], &len, a);
    }
    if (g_wput_overflow) {
        fprintf(stderr, "error: client args do not fit the service ImagePath "
                        "(%lu chars); shorten --config-dir or split the args\n",
                (unsigned long)len);
        return 2;
    }
    img[len] = L'\0';

    /* log dir parent up-front so a bad --log fails at install time */
    wchar_t dir[MAX_PATH];
    wcscpy(dir, logp);
    wchar_t *slash = wcsrchr(dir, L'\\');
    if (slash != NULL) {
        *slash = L'\0';
        _wmkdir(dir);
    }

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (scm == NULL) {
        fprintf(stderr, "error: OpenSCManager (%lu)\n", GetLastError());
        return 1;
    }
    SC_HANDLE svc = CreateServiceW(
        scm, name, display, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        manual ? SERVICE_DEMAND_START : SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL, img, NULL, NULL, NULL, NULL, NULL);
    if (svc == NULL) {
        DWORD e = GetLastError();
        fprintf(stderr, "error: CreateService (%lu)%s\n", e,
                e == 1073 ? " [service already exists]" :
                e == 1072 ? " [marked for deletion, reboot first]" : "");
        CloseServiceHandle(scm);
        return 1;
    }
    const wchar_t *desc =
        L"USTC iWAN client (classic protocol). Runs \"iwan-winsvc --service "
        L"run\": tunnel up at boot, no console. OIDC profiles must keep "
        L"logging in in user context; see README.";
    SERVICE_DESCRIPTIONW d = { (LPWSTR)desc };
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &d);
    SC_ACTION acts[3] = { { SC_ACTION_RESTART, 10000 },
                          { SC_ACTION_RESTART, 30000 },
                          { SC_ACTION_RESTART, 60000 } };
    SERVICE_FAILURE_ACTIONSW fa;
    memset(&fa, 0, sizeof fa);
    fa.dwResetPeriod = 86400;
    fa.lpRebootMsg = NULL;
    fa.lpCommand = NULL;
    fa.cActions = 3;
    fa.lpsaActions = acts;   /* mingw member name; layout == MS SC_FAILURE_ACTIONSW */
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
    CloseServiceHandle(scm);

    printf("installed \"%ls\": %s\n", name, manual ? "MANUAL" : "AUTO_START");
    printf("  image: %S\n", img);
    printf("  log:   %S\n", logp);
    if (start_now) {
        if (StartServiceW(svc, 0, NULL))
            printf("start requested\n");
        else
            fprintf(stderr, "warning: StartService failed (%lu)\n",
                    GetLastError());
    } else {
        printf("start with: sc start %s\n", name_a ? name_a : "iwan-winsvc");
    }
    CloseServiceHandle(svc);
    return 0;
}

static int cmd_uninstall(const wchar_t *name)
{
    if (!port_is_admin()) {
        fprintf(stderr, "error: uninstall needs an elevated prompt\n");
        return 1;
    }
    SC_HANDLE svc = open_svc(name, SERVICE_STOP | SERVICE_QUERY_STATUS |
                             SERVICE_INTERROGATE | DELETE);
    if (svc == NULL) {
        fprintf(stderr, "error: OpenService (%lu)\n", GetLastError());
        return 1;
    }
    SERVICE_STATUS st;
    if (QueryServiceStatus(svc, &st) && st.dwCurrentState != SERVICE_STOPPED) {
        ControlService(svc, SERVICE_CONTROL_STOP, &st);
        if (wait_state(svc, SERVICE_STOPPED, 70) != 0) {
            fprintf(stderr, "warning: still not STOPPED after 70s; "
                            "delete will be pending until reboot\n");
        }
    }
    if (!DeleteService(svc)) {
        fprintf(stderr, "error: DeleteService (%lu)\n", GetLastError());
        CloseServiceHandle(svc);
        return 1;
    }
    CloseServiceHandle(svc);
    printf("deleted \"%S\" (log/config under ProgramData\\iwan kept)\n", name);
    return 0;
}

static int cmd_simple(const wchar_t *name, bool start)
{
    SC_HANDLE svc = open_svc(name,
                             start ? SERVICE_START
                                   : (SERVICE_STOP | SERVICE_QUERY_STATUS));
    if (svc == NULL) {
        fprintf(stderr, "error: OpenService (%lu)\n", GetLastError());
        return 1;
    }
    int rc = 1;
    if (start) {
        if (StartServiceW(svc, 0, NULL)) {
            printf("start requested\n");
            rc = 0;
        } else
            fprintf(stderr, "error: StartService (%lu)\n", GetLastError());
    } else {
        SERVICE_STATUS st;
        if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
            rc = wait_state(svc, SERVICE_STOPPED, 70) == 0 ? 0 : 1;
            printf(rc == 0 ? "stopped\n" : "warning: stop timed out\n");
        } else
            fprintf(stderr, "error: ControlService (%lu)\n", GetLastError());
    }
    CloseServiceHandle(svc);
    return rc;
}

static int cmd_status(const wchar_t *name)
{
    SC_HANDLE svc = open_svc(name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (svc == NULL) {
        fprintf(stderr, "error: OpenService (%lu)\n", GetLastError());
        return 1;
    }
    SERVICE_STATUS st;
    QUERY_SERVICE_CONFIGW *cfg = NULL;
    DWORD need = 0;
    if (!QueryServiceConfigW(svc, NULL, 0, &need) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        cfg = malloc(need);
        if (cfg != NULL)
            QueryServiceConfigW(svc, cfg, need, &need);
    }
    if (QueryServiceStatus(svc, &st))
        printf("state: %ls\n", state_str(st.dwCurrentState));
    if (cfg != NULL) {
        printf("start: %s\n",
               cfg->dwStartType == SERVICE_AUTO_START ? "AUTO_START" :
               cfg->dwStartType == SERVICE_DEMAND_START ? "MANUAL" : "other");
        printf("image: %S\n", cfg->lpBinaryPathName);
        printf("acct:  %S\n",
               cfg->lpServiceStartName ? cfg->lpServiceStartName
                                       : L"LocalSystem");
        free(cfg);
    }
    CloseServiceHandle(svc);
    return 0;
}

static int svc_cli(int argc, char **argv)
{
    if (argc < 3) {
        usage();
        return 2;
    }
    const char *sub = argv[2];
    char *name_a = NULL;
    for (int i = 3; i < argc; i++)
        if (strcmp(argv[i], "--name") == 0 && i + 1 < argc)
            name_a = argv[i + 1];
    wchar_t name[96] = L"";
    if (name_a != NULL)
        MultiByteToWideChar(CP_UTF8, 0, name_a, -1, name, 96);
    if (!name_ok(name))
        wcscpy(name, SVC_DEFAULT_NAME);

    if (strcmp(sub, "install") == 0)
        return cmd_install(argc, argv);
    if (strcmp(sub, "uninstall") == 0)
        return cmd_uninstall(name);
    if (strcmp(sub, "start") == 0)
        return cmd_simple(name, true);
    if (strcmp(sub, "stop") == 0)
        return cmd_simple(name, false);
    if (strcmp(sub, "status") == 0)
        return cmd_status(name);
    fprintf(stderr, "error: unknown --service subcommand '%s'\n", sub);
    usage();
    return 2;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--service") == 0) {
        /* the run submode must come up as a real service; the CLI
         * submodes are plain console commands */
        if (argc >= 3 && strcmp(argv[2], "run") == 0) {
            SERVICE_TABLE_ENTRYW t[2];
            wchar_t name[96] = L"";
            for (int i = 3; i < argc; i++) {
                if (strcmp(argv[i], "--") == 0)
                    break;
                if (strcmp(argv[i], "--name") == 0 && i + 1 < argc)
                    MultiByteToWideChar(CP_UTF8, 0, argv[++i], -1, name, 96);
            }
            if (!name_ok(name))
                wcscpy(name, SVC_DEFAULT_NAME);
            t[0].lpServiceName = name;
            t[0].lpServiceProc = svc_main;
            t[1].lpServiceName = NULL;
            t[1].lpServiceProc = NULL;
            if (!StartServiceCtrlDispatcherW(t)) {
                DWORD e = GetLastError();
                fprintf(stderr,
                        "StartServiceCtrlDispatcher failed (%lu)%s\n", e,
                        e == 1063 ? " — \"--service run\" is started by the "
                                   "SCM; use `--service start`" : "");
                return 1;
            }
            return 0;
        }
        return svc_cli(argc, argv);
    }
    /* every other invocation is the classic client, foreground */
    return iwan_client_main(argc, argv);
}
