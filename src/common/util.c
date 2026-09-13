#include "util.h"
#include "common.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>   /* LLONG_MAX/ULLONG_MAX for parse_ll_strict */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/stat.h>   /* stat: root-owned TLS anchor check (see below) */
#endif

#ifndef _WIN32
#include <signal.h>   /* kill/SIGKILL for the bounded cmd_capture reap */
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef IWAN_DEBUG_STRIP
/* R20 (T2): debug_enabled() is called from every server recv thread on its
 * first use — a plain lazy static is a data race across threads. Atomic. */
static _Atomic int debug_cached = -1;
#endif

/* process-wide stop flag (see util.h). atomic_bool is lock-free on every
 * supported target, so the relaxed store below is legal in a signal
 * handler (C11 7.14.1.1) and race-free against event-loop readers. */
atomic_bool g_stop;
atomic_bool g_user_stop;

void util_ignore_sigpipe(void)
{
    port_ignore_sigpipe();
}

_Noreturn void oom_abort(void)
{
    fprintf(stderr, "out of memory\n");
    abort();
}

/* R37 R5 (R3-L17): the shared boolean-env rule — full contract in
 * util.h. Defined unconditionally (outside IWAN_DEBUG_STRIP): the
 * Windows-only callers (tun_win.c, proxy.c, port.c, oidc_util.c) exist
 * in stripped builds too.
 * R37 R7 WG-E (R6-I4): the predicate is now env_bool_value(), shared with
 * dbg_env()/the security opt-outs, so the four spellings exist exactly
 * once in the tree. */
bool env_bool_value(env_bool_kind kind, const char *v, bool dflt)
{
    switch (kind) {
    case ENV_BOOL_LOOSE:
        if (v == NULL || *v == '\0')
            return dflt;
        /* exact match, case-insensitive: port_strncasecmp() compares up to
         * the literal's NUL, so "0x"/"offline"/"nothing" are not off
         * spellings (they stay ON, like every other unknown value) */
        return !(port_strncasecmp(v, "0", 2) == 0 ||
                 port_strncasecmp(v, "false", 6) == 0 ||
                 port_strncasecmp(v, "no", 3) == 0 ||
                 port_strncasecmp(v, "off", 4) == 0);
    case ENV_BOOL_CS:
        /* dbg_env()'s documented exception, kept value-for-value: the off
         * list {0,false,off} is case-SENSITIVE and has no "no", so
         * no/NO/False/Off/0x/00/"0 " all stay ON. Unset AND set-but-empty
         * are OFF (dflt): the pre-R7 inline chain tested `v && *v` before
         * the strcmp list, so an empty value must not reach it. The R7
         * refactor initially dropped that test and turned IWAN_RXDBG= (set
         * but empty) ON — caught by the 116-cell equivalence matrix in
         * .cc_tmp/r37/r7/envmatrix.c. */
        if (v == NULL || *v == '\0')
            return dflt;
        return !(strcmp(v, "0") == 0 || strcmp(v, "false") == 0 ||
                 strcmp(v, "off") == 0);
    case ENV_BOOL_PRESENT:
        /* IWAN_PUMP_PROF: set at all == ON, empty string included */
        return v != NULL ? true : dflt;
    case ENV_BOOL_EXACT1:
        return v != NULL && strcmp(v, "1") == 0;
    case ENV_BOOL_POSITIVE:
        return v != NULL && (port_strncasecmp(v, "1", 2) == 0 ||
                             port_strncasecmp(v, "true", 5) == 0 ||
                             port_strncasecmp(v, "yes", 4) == 0 ||
                             port_strncasecmp(v, "on", 3) == 0);
    case ENV_BOOL_CS_NO:
        /* IWAN_SRV_TUN_SINGLE's rule, kept value-for-value with the inline
         * chain at its (single) read site: the LOOSE off list, but
         * case-sensitive. Unset and set-but-empty are OFF (dflt), matching
         * the `e && *e` guard there. Provided so the rule is named and
         * testable rather than spelled out at the call site. */
        if (v == NULL || *v == '\0')
            return dflt;
        return !(strcmp(v, "0") == 0 || strcmp(v, "false") == 0 ||
                 strcmp(v, "no") == 0 || strcmp(v, "off") == 0);
    case ENV_KIND_NUM:
        break;   /* not a boolean; callers use env_u64()/env_ms_range() */
    }
    return dflt;
}

bool env_bool_ex(const char *name, env_bool_kind kind, bool dflt)
{
    return env_bool_value(kind, getenv(name), dflt);
}

bool env_bool(const char *name, bool dflt)
{
    return env_bool_ex(name, ENV_BOOL_LOOSE, dflt);
}

#ifndef IWAN_DEBUG_STRIP
bool debug_enabled(void)
{
    int c = atomic_load_explicit(&debug_cached, memory_order_relaxed);
    if (c < 0) {
        /* env_bool does the single getenv(); the atomic cache stays, so
         * the per-recv-thread callers still read a cached int (R20) */
        c = env_bool("IWAN_DEBUG", false);
        atomic_store_explicit(&debug_cached, c, memory_order_relaxed);
    }
    return c != 0;
}
#endif

#ifndef _WIN32
/* R37 WG6 #1: SSL_CERT_FILE/SSL_CERT_DIR are read LATER by the (possibly
 * root) process as its only TLS trust anchors (https.c:402). sudo's default
 * env_reset already drops them, but with 'env_keep += "SSL_CERT_FILE"',
 * '!env_reset' or 'sudo -E' a user-written file would become the root
 * process's trust anchor -> user-controlled CA -> MITM of the elevated
 * request. Keep the variable only while the anchor is root-owned and not
 * group/other-writable (the standard way to install a corporate CA);
 * everything else is dropped so the loader falls back to the system
 * bundles (which include the Homebrew paths https.c:394-401 probes). */
static void keep_root_owned_anchor(const char *name)
{
    const char *v = getenv(name);
    struct stat st;

    if (!v || !v[0])
        return;
    if (stat(v, &st) != 0 || st.st_uid != 0 ||
        (st.st_mode & (S_IWGRP | S_IWOTH)))
        unsetenv(name);
}
#endif

/* Neutralize PATH and loader-injection environment before exec'ing helper
 * binaries: the daemon may run as root, and a hostile PATH entry (or
 * LD_PRELOAD) would execute attacker code with root privileges. */
void exec_sanitize(void)
{
#ifndef _WIN32
    setenv("PATH", "/usr/sbin:/sbin:/usr/bin:/bin", 1);
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("LD_AUDIT");
    unsetenv("GLIBC_TUNABLES");
    /* macOS loader-injection equivalents (sudo's env_reset usually
     * covers these too; keep the hardening symmetric) */
    unsetenv("DYLD_INSERT_LIBRARIES");
    unsetenv("DYLD_LIBRARY_PATH");
    unsetenv("DYLD_FRAMEWORK_PATH");
    unsetenv("DYLD_FALLBACK_LIBRARY_PATH");
    /* R37 R3-M6: these three select CODE, not just a trust anchor — a
     * config file may load providers/engines, and the other two name the
     * directories those loadable objects are searched in. sudo's
     * env_reset drops them by default, but 'env_keep += "OPENSSL_CONF"',
     * '!env_reset' or 'sudo -E' would hand a user-controlled file or
     * directory to the ROOT re-exec (oidc_connect.c execs /usr/bin/sudo
     * right after this call) => arbitrary code as root. There is no
     * legitimate non-default value to preserve here: the corporate-CA
     * case is covered by the root-owned SSL_CERT_FILE/SSL_CERT_DIR
     * anchors kept below, and a system-wide provider/engine setup
     * belongs in the compiled-in /etc/ssl/openssl.cnf, which OpenSSL
     * loads with no environment variable at all. Drop all three. */
    unsetenv("OPENSSL_CONF");
    unsetenv("OPENSSL_MODULES");
    unsetenv("OPENSSL_ENGINES");
    keep_root_owned_anchor("SSL_CERT_FILE");
    keep_root_owned_anchor("SSL_CERT_DIR");
#else
    /* no exec of helper binaries on Windows (port_run_cmd uses
     * CreateProcess); kept as a defined no-op so callers compile */
#endif
}

/* argv with "ip" prepended; args[0] is "-4", "route", ... or already "ip".
 * The Windows port-layer helpers pass argv WITHOUT argv[0] (e.g.
 * {"-4","route","show","default"}), while port_run_cmd/port_cmd_capture
 * want argv[0] = program name. */
static char **ip_argv(char *const args[])
{
    size_t argc = 0;
    while (args[argc])
        argc++;
    char **argv = malloc((argc + 2) * sizeof(char *));
    if (!argv)
        return NULL;
    size_t off = (argc > 0 && strcmp(args[0], "ip") == 0) ? 0 : 1;
    argv[0] = "ip";
    for (size_t i = 0; i < argc; i++)
        argv[i + off] = args[i];
    argv[argc + off] = NULL;
    return argv;
}

#ifndef _WIN32
static bool run_ip_child(char *const args[])
{
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        exec_sanitize();
        char **argv = ip_argv(args);
        if (!argv)
            _exit(127);
        execvp("ip", argv);
        _exit(127);
    }
    int st = 0;
    pid_t w;
    while ((w = waitpid(pid, &st, 0)) < 0 && errno == EINTR)
        ;
    /* R37 R3-L7: a non-EINTR waitpid failure (ECHILD after a SIGCHLD
     * handler with SA_NOCLDWAIT, EINVAL, ...) used to fall through with
     * st still 0 => WIFEXITED(0) true and WEXITSTATUS(0) == 0 => ip_run
     * reported success for a command whose exit status is unknown
     * (route_setup would then believe the host was hijacked). port.c's
     * port_run_cmd returns -1 here; match it. */
    if (w < 0)
        return false;
    if (!WIFEXITED(st))
        return false;
    return WEXITSTATUS(st) == 0;
}
#else /* _WIN32 */
#endif /* _WIN32 */

bool ip_run(char *const args[])
{
#ifndef _WIN32
    return run_ip_child(args);
#else
    char **argv = ip_argv(args);
    if (!argv)
        return false;
    int rc = port_run_cmd(argv);
    free(argv);
    return rc == 0;
#endif
}

/* Capture stdout of `ip ...` (bounded semantics, platform-aligned):
 * Linux forks/reads itself but reaps with the same 60s + SIGKILL policy
 * as port.c port_cmd_capture (R4 fix) — a wedged `ip`/helper must not
 * hang route configuration or the daemon forever, and on timeout the
 * captured-so-far output is returned (partial output beats an indefinite
 * wedge, exactly like the Windows branch, which delegates to
 * port_cmd_capture's own 60s+SIGKILL below). */
#ifndef _WIN32
/* R19: bounded reap for the OOM read-abort paths — mirror the normal
 * path's 60s + SIGKILL policy so a wedged child cannot hang the
 * daemon even when we are abandoning the capture. */
static void cmd_capture_reap_bounded(pid_t pid, int *st, uint64_t deadline)
{
    for (;;) {
        if (waitpid(pid, st, WNOHANG) == pid)
            return;
        if (now_ms() >= deadline) {
            kill(pid, SIGKILL);
            continue;
        }
        port_sleep_ms(10);
    }
}
#endif

char *cmd_capture(char *const args[])
{
#ifndef _WIN32
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
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
        int fdnull = open("/dev/null", O_WRONLY);
        if (fdnull >= 0) {
            dup2(fdnull, STDERR_FILENO);
            if (fdnull > STDERR_FILENO)
                close(fdnull);
        }
        char **argv = ip_argv(args);
        if (!argv)
            _exit(127);
        execvp("ip", argv);
        _exit(127);
    }
    close(fds[1]);
    size_t cap = 256;
    size_t len = 0;
    int st = 0;
    bool read_err = false;
    bool timed_out = false;
    /* single 60s budget shared by the bounded read phase and the bounded
     * reap below (one deadline for the whole capture, mirroring the
     * Windows branch / port_cmd_capture's 60s+SIGKILL) */
    uint64_t deadline = now_ms() + 60000;
    char *out = malloc(cap);
    if (!out) {
        close(fds[0]);
        cmd_capture_reap_bounded(pid, &st, deadline);
        return NULL;
    }
    for (;;) {
        if (len + 1 >= cap) {
            /* at the size ceiling, grow by the exact minimum */
            size_t ncap = cap > SIZE_MAX / 2 ? len + 1 : cap * 2;
            char *nr = realloc(out, ncap);
            if (!nr) {
                free(out);
                close(fds[0]);
                cmd_capture_reap_bounded(pid, &st, deadline);
                return NULL;
            }
            out = nr;
            cap = ncap;
        }
        /* bounded read: a plain read() could block forever if the child
         * hangs without writing and without closing stdout, so the 60s
         * budget would never be reached. Poll with the remaining budget
         * before every read. */
        uint64_t now = now_ms();
        int remaining = deadline > now ? (int)(deadline - now) : 0;
        if (remaining == 0) {
            timed_out = true;
            break;
        }
        struct pollfd pfd;
        pfd.fd = fds[0];
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = port_poll(&pfd, 1, remaining);
        if (pr == 0) {
            timed_out = true;   /* no data within the 60s budget */
            break;
        }
        if (pr < 0) {
            if (errno == EINTR)
                continue;       /* retry the poll */
            read_err = true;    /* hard poll error: fail like read errors */
            break;
        }
        /* pr > 0: POLLIN/POLLHUP/POLLERR — proceed to read; EOF (HUP)
         * reads as 0 and hard errors set read_err below */
        ssize_t n = read(fds[0], out + len, cap - len - 1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            /* hard read error: a truncated buffer would silently drop
             * output, so fail like every other error path */
            read_err = true;
            break;
        }
        if (n == 0)
            break;
        len += (size_t)n;
    }
    close(fds[0]);
    if (timed_out) {
        /* the 60s read budget expired (child hung without writing and
         * without closing stdout): the child is still alive, so SIGKILL
         * it NOW and let the reap loop below just collect it — this
         * avoids a second full 60s wait inside the reap. */
        kill(pid, SIGKILL);
    }
    /* bounded reap, same policy as port.c port_cmd_capture (R4 fix):
     * poll with WNOHANG so a signal cannot wedge us; EINTR only retries
     * the poll. If the child is still alive at the (shared) deadline we
     * SIGKILL it and keep reaping (the SIGKILLed child still needs a
     * waitpid to reclaim it), then return whatever we captured. */
    for (;;) {
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == pid)
            break;
        if (r < 0) {
            if (errno == EINTR)
                continue;   /* retry the poll */
            break;          /* ECHILD etc.: nothing more to reap */
        }
        if (now_ms() >= deadline) {
            timed_out = true;
            kill(pid, SIGKILL);
            continue;   /* keep reaping until waitpid returns the pid */
        }
        port_sleep_ms(10);
    }
    out[len] = '\0';
    if (timed_out) {
        /* we SIGKILLed the child ourselves: partial output is the
         * deliberate result here, so WIFSIGNALED(st) (set for our own
         * SIGKILL) must NOT drop through to the failure path below —
         * same policy as the Windows branch / port_cmd_capture. */
        log_err("cmd_capture: %s timed out after 60s; returning partial "
                "output", args[0]);
        return out;
    }
    if (read_err || len == 0 || (WIFEXITED(st) && WEXITSTATUS(st) == 127) ||
        WIFSIGNALED(st)) {
        free(out);
        return NULL;
    }
    return out;
#else
    char **argv = ip_argv(args);
    if (!argv)
        return NULL;
    /* consumers parse `ip route/addr` output (a few hundred bytes); the
     * 1 MiB bound is far above any real output. Divergence: on success
     * with empty output this returns "" where Linux returns NULL — the
     * util.h contract notes callers treat the two identically. */
    char *out = port_cmd_capture(argv, 1024 * 1024);
    free(argv);
    return out;
#endif
}

void log_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

void log_err(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

#ifndef IWAN_DEBUG_STRIP
void log_debug(const char *fmt, ...)
{
    if (!debug_enabled())
        return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
#endif

void err_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    /* stderr becomes fully buffered when redirected to a file on the
     * MinGW CRT; a hard kill (TerminateProcess) then loses the buffer.
     * Errors must be visible even for daemons killed with -Force. */
    fflush(stderr);
}

bool dbg_env(const char *name)
{
    static const char *names[3];
    static int vals[3];
    static int n = 0;
    for (int i = 0; i < n; i++)
        if (strcmp(names[i], name) == 0)
            return vals[i] != 0;
    {
        /* R37 R7 WG-E: the predicate is env_bool_value(ENV_BOOL_CS, ...) —
         * one implementation, value-for-value identical to the old inline
         * strcmp chain (0/false/off exact and case-sensitive, no "no",
         * empty value OFF, unset OFF). */
        int val = env_bool_value(ENV_BOOL_CS, getenv(name), false);
        if (n < 3) {
            names[n] = name;
            vals[n] = val;
            n++;
        }
        return val != 0;
    }
}

/* Strict decimal scan for the numeric env vars (R37 R3 / L18): the WHOLE
 * string must be a canonical decimal integer. strtoll() (used here before)
 * silently accepted leading whitespace (" 1") and an explicit '+' ("+1"),
 * while parse_uint() — the parser behind IWAN_SRV_THREADS and the CLI
 * numbers — rejects both, so "IWAN_AUTH_FAIL_MAX=' 1'" quietly tightened
 * the brute-force lockout to 1 failure while "IWAN_SRV_THREADS=' 1'" warned
 * and fell back to the default. Both domains now reject the same spellings
 * (leading/trailing whitespace, '+', trailing garbage, empty, overflow):
 * the caller logs the value and keeps its default. A leading '-' is kept
 * for API generality (env_ms_range takes signed bounds); the min/max check
 * in the caller still rejects negatives for every current variable.
 * R37 R7 WG-E (R6-I4): this is now THE scanner — env_scan_i64() is the
 * signed form and env_scan_u64() (below, the body parse_uint() used to
 * carry) the unsigned one; env_ms_range(), env_u64(), parse_uint() and
 * str_to_u16() all delegate here, so the accepted domain is one function.
 * Returns 0 and stores the value on success, -1 otherwise. */
int env_scan_i64(const char *s, long long *out)
{
    if (!s || !*s)
        return -1;
    const char *p = s;
    int neg = 0;
    if (*p == '-') {
        neg = 1;
        p++;
    }
    if (*p < '0' || *p > '9')
        return -1;
    unsigned long long v = 0;
    for (; *p; p++) {
        if (*p < '0' || *p > '9')
            return -1;
        unsigned d = (unsigned)(*p - '0');
        if (v > (ULLONG_MAX - d) / 10ULL)
            return -1;                 /* overflow: out of range */
        v = v * 10ULL + d;
    }
    if (neg) {
        if (v > (unsigned long long)LLONG_MAX + 1ULL)
            return -1;
        *out = (v == (unsigned long long)LLONG_MAX + 1ULL)
                   ? LLONG_MIN
                   : -(long long)v;
    } else {
        if (v > (unsigned long long)LLONG_MAX)
            return -1;
        *out = (long long)v;
    }
    return 0;
}

/* Parse an environment variable as a millisecond duration. Returns defval
 * when the variable is unset/empty, when it fails to parse, or when it is
 * out of [min, max]; a warning is logged for the bad-value cases. When
 * allow_zero is nonzero, an explicit 0 is returned unvalidated — the
 * "watchdog disabled" sentinel. Wrapper callers that must parse once per
 * process cache the result themselves. */
long long env_ms_range(const char *name, long long defval, long long min,
                       long long max, int allow_zero,
                       const char *range_desc)
{
    const char *v = getenv(name);
    long long n;

    if (!v || !v[0])
        return defval;
    if (env_scan_i64(v, &n) != 0) {
        log_err("%s: invalid value '%s' (%s); using default",
                name, v, range_desc);
        return defval;
    }
    if (n == 0 && allow_zero)
        return 0;
    if (n < min || n > max) {
        log_err("%s: invalid value '%s' (%s); using default",
                name, v, range_desc);
        return defval;
    }
    return n;
}

/* R37 R7 WG-E: unsigned sibling of env_ms_range — same contract, same
 * warning text, and the same env_scan_u64() domain as parse_uint().
 * R38 (P1-2): this function is now really called — lwip_bridge.c:569
 * (ns_init(), IWAN_NS_CONNECT_TIMEOUT_MS, min 1000/max 300000, allow_zero
 * deliberately 0) is its call site, and the hand-written strtoul()
 * +end-pointer block that used to sit there (R2-G1 §N3) is gone. That
 * block accepted " 1000"/"+1000"/"\t1000"; this one rejects them with the
 * warning above and returns defval, because env_scan_u64() (util.h) is the
 * env layer's only strict decimal scanner — the remaining local strtol
 * parsers (proxy.c queue counts, server.c rate_limit_parse()) have their
 * own narrower jobs and are not env-layer scanners. */
uint64_t env_u64(const char *name, uint64_t defval, uint64_t min,
                 uint64_t max, int allow_zero, const char *range_desc)
{
    const char *v = getenv(name);
    uint64_t n;

    if (!v || !v[0])
        return defval;
    if (env_scan_u64(v, max, &n) != PARSE_UINT_OK) {
        log_err("%s: invalid value '%s' (%s); using default",
                name, v, range_desc);
        return defval;
    }
    if (n == 0 && allow_zero)
        return 0;
    if (n < min) {
        log_err("%s: invalid value '%s' (%s); using default",
                name, v, range_desc);
        return defval;
    }
    return n;   /* n <= max: env_scan_u64()'s ceiling */
}

/* ---------- string list ---------- */
void slist_init(slist_t *s)
{
    s->v = NULL;
    s->n = 0;
    s->cap = 0;
}

void slist_free(slist_t *s)
{
    for (size_t i = 0; i < s->n; i++)
        free(s->v[i]);
    free(s->v);
    s->v = NULL;
    s->n = 0;
    s->cap = 0;
}

void slist_push(slist_t *s, const char *str)
{
    if (s->n == s->cap) {
        size_t ncap;
        if (!grow_cap(s->n, 1, s->cap, 4, sizeof(char *), &ncap))
            oom_abort();   /* n == SIZE_MAX: no representable array */
        s->v = realloc(s->v, ncap * sizeof(char *));
        if (!s->v)
            oom_abort();
        s->cap = ncap;
    }
    s->v[s->n++] = xstrdup(str);
}

void slist_push_csv(slist_t *s, const char *csv)
{
    const char *p = csv;
    while (*p) {
        while (*p == ',')
            p++;
        if (!*p)
            break;
        const char *start = p;
        while (*p && *p != ',')
            p++;
        const char *end = p;
        while (end > start && isspace((unsigned char)end[-1]))
            end--;
        while (start < end && isspace((unsigned char)*start))
            start++;
        if (start < end) {
            size_t n = (size_t)(end - start);
            char *piece = malloc(n + 1);
            if (!piece)
                oom_abort();   /* never NULL-halts on OOM (matches xstrdup) */
            memcpy(piece, start, n);
            piece[n] = '\0';
            slist_push(s, piece);
            free(piece);
        }
    }
}

char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *out = malloc(n);
    if (!out)
        oom_abort();   /* matches the "never NULL-halts on OOM" contract */
    memcpy(out, s, n);
    return out;
}

/* See util.h. The growth strategy is the repository-wide one: double
 * from the current capacity until the needed total fits; at the size_t
 * ceiling degrade to the exact needed size instead of overflowing. */
size_t grow_cap(size_t used, size_t extra, size_t cap, size_t init,
                size_t esize, size_t *newcap)
{
    if (extra > SIZE_MAX - used)
        return 0;   /* no representable total */
    size_t need = used + extra;
    if (need <= cap) {
        *newcap = cap;
        return cap;
    }
    size_t ncap = cap ? cap * 2 : init;
    if (ncap < cap) {
        ncap = need;   /* the *2 wrapped: no power-of-two growth */
    } else {
        while (ncap < need) {
            if (ncap > SIZE_MAX / 2) {
                ncap = need;
                break;
            }
            ncap *= 2;
        }
        if (ncap > SIZE_MAX / esize)
            ncap = need;   /* byte-size overflow: exact fit */
    }
    *newcap = ncap;
    return ncap;
}

/* shared append-and-NUL-terminate implementation behind json.c's jbuf
 * and https.c's sbuf. memmove (not memcpy) + noinline: gcc >= 16
 * -Wrestrict cannot prove the caller buffer does not alias the buffer
 * and errors on the (in practice impossible) huge-length path; noinline
 * keeps IPA from folding caller arguments into a -Wstringop-overflow
 * false positive (observed on riscv64/i686 musl cross builds). */
#if defined(__GNUC__) && __GNUC__ >= 12
__attribute__((noinline))
#endif
void sbuf_app(sbuf *s, const void *p, size_t n)
{
    size_t nc;
    if (!grow_cap(s->len, n + 1, s->cap, 256, 1, &nc))
        oom_abort();   /* length overflow: no representable buffer */
    if (nc > s->cap) {
        s->d = realloc(s->d, nc);
        if (!s->d)
            oom_abort();
        s->cap = nc;
    }
    /* memmove, not memcpy: gcc >= 16 -Wrestrict cannot prove the caller
     * buffer does not alias the buffer and errors on the (in practice
     * impossible) huge-length path */
    memmove(s->d + s->len, p, n);
    s->len += n;
    s->d[s->len] = '\0';
}

uint32_t rand_u32(void)
{
    uint32_t v;

    /* fail-closed (F6): the old getrandom -> /dev/urandom -> weak-mix
     * fallback chain could hand out a guessable value; a guessable nonce
     * or token is a session-hijack hole, so RNG failure is fatal. */
    if (port_rand_bytes(&v, sizeof v) != 0) {
        log_err("rand_u32: cannot obtain secure randomness "
                "(port_rand_bytes failed); aborting");
        abort();
    }
    return v;
}

uint64_t now_ms(void)
{
    return port_now_ms();
}

uint64_t now_us(void)
{
    return port_now_us();
}

/* ---------------- aggregate send pacing ---------------- */

void pace_bucket_init(pace_bucket *b)
{
    static int cached = -1;
    static uint32_t cached_pps;

    if (cached < 0) {
        const char *v = getenv("IWAN_SEND_PACING_PPS");
        uint64_t pps = 0;
        if (v && *v) {
            /* R37 L16: 0 is the documented "pacing disabled" sentinel
             * (util.h) and is exactly what an unset variable yields, so
             * an explicit "0" must be accepted silently — the old
             * `&& pps > 0` test reported it as an invalid value and
             * printed a bogus error (IWAN_RX_STALE_MS=0 has always been
             * accepted via allow_zero). The resulting state is identical:
             * pps==0 -> pace_take() returns immediately. */
            if (parse_uint(v, 10000000, &pps) == 0) {
                cached_pps = (uint32_t)pps;
            } else {
                log_err("invalid IWAN_SEND_PACING_PPS '%s': pacing disabled",
                        v);
                cached_pps = 0;
            }
        } else {
            /* default: no pacing. The C server in this repo drains with
             * multiple queues and has no single-thread ceiling; the Rust
             * reference server needs IWAN_SEND_PACING_PPS=300000 (see
             * util.h). */
            cached_pps = 0;
        }
        cached = 1;
    }
    b->pps = cached_pps;
    b->budget = 0;
    b->last = 0;
}

void pace_take(pace_bucket *b, int npk)
{
    uint64_t now, budget;

    if (b->pps == 0)
        return;
    now = now_us();
    if (!b->last)
        b->last = now;
    budget = b->budget + (now - b->last) * b->pps / 1000000u;
    if (budget > b->pps / 10u)
        budget = b->pps / 10u;   /* cap the burst */
    b->last = now;
    if ((uint64_t)npk > budget) {
        uint64_t need = ((uint64_t)npk - budget) * 1000000u / b->pps;
        b->budget = 0;
        if (need > 0)
            port_sleep_us((unsigned)need);
    } else {
        b->budget = budget - (uint64_t)npk;
    }
}

/* The unsigned strict-decimal scanner (R37 R7 WG-E): this body used to BE
 * parse_uint(); it is now shared, so parse_uint(), env_u64() and
 * str_to_u16() cannot drift apart. */
int env_scan_u64(const char *s, uint64_t max, uint64_t *out)
{
    if (!s || !*s)
        return PARSE_UINT_BAD;
    const char *p = s;
    while (*p) {
        if (*p < '0' || *p > '9')
            return PARSE_UINT_BAD;
        p++;
    }
    uint64_t v = 0;
    for (p = s; *p; p++) {
        uint64_t d = (uint64_t)(*p - '0');
        /* d > max would underflow max - d below (unsigned wrap) and
         * admit out-of-range values when max < 9 */
        if (d > max || v > (max - d) / 10)
            return PARSE_UINT_RANGE;
        v = v * 10 + d;
    }
    *out = v;
    return PARSE_UINT_OK;
}

int parse_uint(const char *s, uint64_t max, uint64_t *out)
{
    return env_scan_u64(s, max, out);
}

int str_to_u16(const char *s, uint16_t *out)
{
    uint64_t v;
    if (parse_uint(s, UINT16_MAX, &v) != 0)
        return -1;
    *out = (uint16_t)v;
    return 0;
}

const char *unbracket_ipv6(const char *s, char *buf, size_t n)
{
    if (s[0] == '[') {
        size_t len = strlen(s);
        if (len >= 3 && s[len - 1] == ']' && len - 2 < n) {
            memcpy(buf, s + 1, len - 2);
            buf[len - 2] = '\0';
            return buf;
        }
    }
    return s;
}
