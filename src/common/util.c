#include "util.h"
#include "common.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

static int debug_cached = -1;

/* process-wide stop flag (see util.h). atomic_bool is lock-free on every
 * supported target, so the relaxed store below is legal in a signal
 * handler (C11 7.14.1.1) and race-free against event-loop readers. */
atomic_bool g_stop;
atomic_bool g_user_stop;

void util_ignore_sigpipe(void)
{
    port_ignore_sigpipe();
}

void oom_abort(void)
{
    fprintf(stderr, "out of memory\n");
    abort();
}

bool debug_enabled(void)
{
    if (debug_cached < 0) {
        const char *v = getenv("IWAN_DEBUG");
        debug_cached = v && *v && strcmp(v, "0") != 0 &&
                       strcmp(v, "false") != 0 && strcmp(v, "off") != 0;
    }
    return debug_cached != 0;
}

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
static bool run_ip_child(char *const args[], bool quiet)
{
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        exec_sanitize();
        if (quiet) {
            int fd = open("/dev/null", O_RDWR);
            if (fd >= 0) {
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                if (fd > STDERR_FILENO)
                    close(fd);
            }
        }
        char **argv = ip_argv(args);
        if (!argv)
            _exit(127);
        execvp("ip", argv);
        _exit(127);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    if (!WIFEXITED(st))
        return false;
    return WEXITSTATUS(st) == 0;
}
#else /* _WIN32 */
#endif /* _WIN32 */

bool ip_run(char *const args[])
{
#ifndef _WIN32
    return run_ip_child(args, false);
#else
    char **argv = ip_argv(args);
    if (!argv)
        return false;
    int rc = port_run_cmd(argv);
    free(argv);
    return rc == 0;
#endif
}

bool ip_run_quiet(char *const args[])
{
#ifndef _WIN32
    return run_ip_child(args, true);
#else
    /* Divergence: port_run_cmd cannot redirect the child's stdout/stderr,
     * so output is not swallowed on Windows (CREATE_NO_WINDOW keeps it off
     * the console). Callers treat ip_run_quiet as best-effort. */
    return ip_run(args);
#endif
}

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
    char *out = malloc(cap);
    if (!out) {
        close(fds[0]);
        waitpid(pid, &st, 0);
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
                waitpid(pid, &st, 0);
                return NULL;
            }
            out = nr;
            cap = ncap;
        }
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
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    if (read_err || len == 0 || (WIFEXITED(st) && WEXITSTATUS(st) == 127)) {
        free(out);
        return NULL;
    }
    out[len] = '\0';
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
        const char *v = getenv(name);
        int val = v && *v && strcmp(v, "0") != 0 &&
                  strcmp(v, "false") != 0 && strcmp(v, "off") != 0;
        if (n < 3) {
            names[n] = name;
            vals[n] = val;
            n++;
        }
        return val != 0;
    }
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
            if (parse_uint(v, 10000000, &pps) == 0 && pps > 0) {
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

int parse_uint(const char *s, uint64_t max, uint64_t *out)
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
