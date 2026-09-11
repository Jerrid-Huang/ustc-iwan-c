#ifndef IWAN_UTIL_H
#define IWAN_UTIL_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* R37-F3 (R3-M5): format checking for our own printf-like wrappers.
 * Without this attribute the compiler did not check any of the 250+
 * log/error call sites at all, which is how a %zu in a log call could
 * pass every gate but the two places that went through libc's fprintf
 * (that exact split is R3-H1: auth.c:416 broke the mingw build while
 * oidc_config.c's err_printf was silently unchecked).
 *
 * The archetype is the plain `printf`, i.e. "whatever the target libc's
 * printf is" — exactly the contract of these wrappers, which all forward
 * `fmt` to vfprintf/vsnprintf. Measured on this tree:
 *   - gcc/Linux and clang/Linux: %zu is valid (gnu semantics), other
 *     mismatches are still rejected;
 *   - MinGW gcc, under the win64 build flags: the same attribute yields
 *     byte-identical diagnostics to a direct libc fprintf call — both
 *     reject %zu with "unknown conversion type character 'z' in format"
 *     — so a %zu in a log call is caught in win-cross exactly the way
 *     R3-H1's auth.c:416 direct fprintf was, instead of shipping a
 *     broken deliverable.
 * The named archetypes are NOT portable, measured on this tree:
 *   gnu_printf — clang: "'format' attribute argument not supported"
 *                (with -Werror that breaks the CI clang leg);
 *   ms_printf  — gcc/Linux: "unrecognized format function type", and
 *                clang rejects it too;
 *   gnu_printf — MinGW gcc accepts it but treats %zu as valid, which
 *                would silently defeat the Windows check.
 * NOTE: __MINGW_PRINTF_FORMAT cannot be used here either — it is not
 * guaranteed to be defined at this point of the include graph (util.h
 * pulls in no libc stdio header), and util.h is included very early
 * everywhere. */
#if defined(__GNUC__)
#  define IWAN_PRINTF_FMT printf
#  define IWAN_PRINTF_LIKE(a, b) __attribute__((format(IWAN_PRINTF_FMT, a, b)))
#else
#  define IWAN_PRINTF_LIKE(a, b)   /* non-GCC: no checking */
#endif

#ifdef IWAN_DEBUG_STRIP
#define log_debug(...) ((void)0)
static inline bool debug_enabled(void) { return false; }
#else
bool debug_enabled(void);
#endif
/* reset PATH to a safe default and clear loader-injection vars; call in
 * the child before exec of helper binaries (root daemon hardening) */
void exec_sanitize(void);
/* run `ip` with argv (NULL-terminated, excluding argv[0]="ip"). Returns exit==0. */
bool ip_run(char *const args[]);
/* capture stdout of a command (NULL-terminated argv, excluding argv[0]).
 * Returns malloc'd string or NULL. NOTE: NULL is returned both when the
 * command fails AND when it succeeds with empty output (callers so far
 * treat the two identically — verify before relying on the distinction). */
char *cmd_capture(char *const args[]);

/* allocation failure is fatal: growable buffers and string helpers have no
 * error path, so report and abort instead of dereferencing NULL */
_Noreturn void oom_abort(void);

void log_info(const char *fmt, ...) IWAN_PRINTF_LIKE(1, 2);   /* -> stdout */
void log_err(const char *fmt, ...) IWAN_PRINTF_LIKE(1, 2);    /* -> stderr */
#ifndef IWAN_DEBUG_STRIP
void log_debug(const char *fmt, ...) IWAN_PRINTF_LIKE(1, 2);  /* -> stderr if IWAN_DEBUG */
#endif
/* raw stderr printf (no newline, no flush): the shared implementation
 * behind the eprintf/oidc_eprintf helpers (log_err appends a newline
 * instead) */
void err_printf(const char *fmt, ...) IWAN_PRINTF_LIKE(1, 2);

/* diagnostic env flags (IWAN_RXDBG / IWAN_FLOWDBG): parsed once per name
 * and cached; any value other than 0/false/off enables */
bool dbg_env(const char *name);

/* parse a millisecond duration from env var `name`; see util.c. Returns
 * defval when unset/empty/unparseable/out-of-range (with a warning);
 * allow_zero lets an explicit 0 (the "disabled" sentinel) pass through.
 * The value must be a canonical decimal integer: leading/trailing
 * whitespace, a '+' sign and trailing garbage are rejected, matching
 * parse_uint (the parser behind the CLI numbers and IWAN_SRV_THREADS). */
long long env_ms_range(const char *name, long long defval, long long min,
                       long long max, int allow_zero,
                       const char *range_desc);

/* ---------------- shared parsing / buffer-growth helpers ---------------- */

/* 0-15 for a hex digit ('0'-'9', 'a'-'f', 'A'-'F'), else -1 */
static inline int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Grow a heap buffer's capacity. `used` is the current fill, `extra` the
 * additional capacity that must become representable, `cap` the current
 * capacity, `init` the capacity of a fresh empty buffer (used when
 * cap==0), `esize` the size of one element in bytes (1 for a byte
 * buffer). Doubles from the current capacity until `used + extra` fits,
 * degrading to the exact needed size at the size_t ceiling (both the *2
 * and the byte-size multiply are guarded). Returns the new capacity
 * (stored in *newcap; == cap when nothing needed to grow), or 0 when
 * `used + extra` is not representable (callers abort: allocation failure
 * is fatal in this codebase). */
size_t grow_cap(size_t used, size_t extra, size_t cap, size_t init,
                size_t esize, size_t *newcap);

/* ---------- shared NUL-terminated growable byte buffer ---------- */

/* Growable string buffer that is always kept NUL-terminated (one byte
 * past len). `d` may be NULL while empty {0} is still NUL-terminatable;
 * callers treat d+len as the contents. Single shared definition: json.c
 * (jbuf) and https.c (sbuf) used to carry verbatim local copies. */
typedef struct sbuf {
    char  *d;
    size_t len;
    size_t cap;
} sbuf;

/* append n bytes from p to s, growing as needed; s remains NUL-terminated.
 * Allocation failure is fatal (oom_abort). */
void sbuf_app(sbuf *s, const void *p, size_t n);

/* parse_uint result codes (the function itself is declared in common.h;
 * the three-state contract below supersedes its "0/-1" doc comment):
 * 0 on success; on failure the code tells check_uint (cli.c) which clap
 * message to emit without re-scanning the string. */
enum {
    PARSE_UINT_OK = 0,     /* parsed; *out holds the value */
    PARSE_UINT_BAD = -1,   /* empty string or a non-digit character */
    PARSE_UINT_RANGE = -2, /* all digits, but the value exceeds max */
};

/* ---------------- process-wide signal state ---------------- */

/* shared stop flag: written by SIGINT/SIGTERM handlers (relaxed atomic
 * store: lock-free on every supported target), read by the event loops.
 * Defined once in util.c; socks.c/proxy.c/iwan_server.c use it instead of
 * private copies. */
extern atomic_bool g_stop;
/* set (with g_stop) by the SIGINT/SIGTERM/console-ctrl handler only;
 * lets reconnect loops distinguish "user pressed Ctrl-C" from the
 * pump's own session-loss flag (which also sets g_stop) */
extern atomic_bool g_user_stop;
/* SIG_IGN SIGPIPE once per process: pipe writes then surface EPIPE
 * instead of killing the process. Call at the top of each main(). */
void util_ignore_sigpipe(void);

/* monotonic microsecond clock (defined in util.c). The pump's fine-grained
 * batch-latency cap and the pacing bucket use it; now_ms() (common.h) is
 * the millisecond-resolution timeout clock. */
uint64_t now_us(void);

/* ---------------- aggregate send pacing (optional) ---------------- */

/* Token-bucket pacing for the aggregate UDP send rate. This is the
 * shared implementation of what used to be two verbatim copies in
 * socks.c and proxy.c.
 *
 * Enabled only when the environment variable IWAN_SEND_PACING_PPS is set
 * to a rate in 1..10000000 packets/s; unset/empty and an explicit 0 (the
 * documented "disabled" sentinel) both leave pacing off (default: 0 =
 * disabled). The pacing exists because
 * the Rust reference server's single-threaded drain (~360k pps) silently
 * drops UDP bursts past its rcvbuf, collapsing the inner TCP into an RTO
 * storm; the C server in this repo has no such ceiling, so no pacing is
 * applied unless explicitly requested (IWAN_SEND_PACING_PPS=300000).
 *
 * Not thread-safe: callers with concurrent senders (proxy.c pump threads)
 * must serialize pace_take with their send lock. */
typedef struct {
    uint32_t pps;      /* 0 = disabled */
    uint64_t budget;   /* unused send budget, in packets */
    uint64_t last;     /* last refill timestamp (us) */
} pace_bucket;

void pace_bucket_init(pace_bucket *b);   /* reads IWAN_SEND_PACING_PPS */
/* account npk packets against the bucket, sleeping when over budget */
void pace_take(pace_bucket *b, int npk);

#endif
