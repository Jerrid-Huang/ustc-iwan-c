#ifndef IWAN_UTIL_H
#define IWAN_UTIL_H

#include <stdbool.h>

bool debug_enabled(void);
/* run `ip` with argv (NULL-terminated, excluding argv[0]="ip"). Returns exit==0. */
bool ip_run(char *const args[]);
bool ip_run_quiet(char *const args[]);
/* capture stdout of a command (NULL-terminated argv, excluding argv[0]).
 * Returns malloc'd string or NULL. */
char *cmd_capture(char *const args[]);

void log_info(const char *fmt, ...);   /* -> stdout */
void log_err(const char *fmt, ...);    /* -> stderr */
void log_debug(const char *fmt, ...);  /* -> stderr if IWAN_DEBUG */

#endif
