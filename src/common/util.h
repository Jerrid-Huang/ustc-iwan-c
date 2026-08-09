#ifndef IWAN_UTIL_H
#define IWAN_UTIL_H

#include <stdbool.h>

bool debug_enabled(void);
/* reset PATH to a safe default and clear loader-injection vars; call in
 * the child before exec of helper binaries (root daemon hardening) */
void exec_sanitize(void);
/* run `ip` with argv (NULL-terminated, excluding argv[0]="ip"). Returns exit==0. */
bool ip_run(char *const args[]);
bool ip_run_quiet(char *const args[]);
/* capture stdout of a command (NULL-terminated argv, excluding argv[0]).
 * Returns malloc'd string or NULL. */
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

#endif
