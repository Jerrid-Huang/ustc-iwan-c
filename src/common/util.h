#ifndef IWAN_UTIL_H
#define IWAN_UTIL_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

bool debug_enabled(void);
/* reset PATH to a safe default and clear loader-injection vars; call in
 * the child before exec of helper binaries (root daemon hardening) */
void exec_sanitize(void);
/* run `ip` with argv (NULL-terminated, excluding argv[0]="ip"). Returns exit==0. */
bool ip_run(char *const args[]);
bool ip_run_quiet(char *const args[]);
/* capture stdout of a command (NULL-terminated argv, excluding argv[0]).
 * Returns malloc'd string or NULL. NOTE: NULL is returned both when the
 * command fails AND when it succeeds with empty output (callers so far
 * treat the two identically — verify before relying on the distinction). */
char *cmd_capture(char *const args[]);

/* allocation failure is fatal: growable buffers and string helpers have no
 * error path, so report and abort instead of dereferencing NULL */
void oom_abort(void);

void log_info(const char *fmt, ...);   /* -> stdout */
void log_err(const char *fmt, ...);    /* -> stderr */
void log_debug(const char *fmt, ...);  /* -> stderr if IWAN_DEBUG */

/* diagnostic env flags (IWAN_RXDBG / IWAN_RETX / IWAN_FLOWDBG): parsed
 * once per name and cached; any value other than 0/false/off enables */
bool dbg_env(const char *name);

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
 * to a positive rate (default: 0 = disabled). The pacing exists because
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
