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

void log_info(const char *fmt, ...);   /* -> stdout */
void log_err(const char *fmt, ...);    /* -> stderr */
void log_debug(const char *fmt, ...);  /* -> stderr if IWAN_DEBUG */

/* tun device names are fed to `ip link del/set` as root: restrict to a
 * safe Linux ifname charset (IFNAMSIZ-1, [A-Za-z0-9_], not "."/".."). */
bool valid_tun_name(const char *name);

#endif
