#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int debug_cached = -1;

bool debug_enabled(void)
{
    if (debug_cached < 0) {
        const char *v = getenv("IWAN_DEBUG");
        debug_cached = v && *v && strcmp(v, "0") != 0 &&
                       strcmp(v, "false") != 0 && strcmp(v, "off") != 0;
    }
    return debug_cached != 0;
}

/* argv with "ip" prepended; args[0] is "-4", "route", ... or already "ip" */
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

static bool run_ip_child(char *const args[], bool quiet)
{
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
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
    if (waitpid(pid, &st, 0) < 0)
        return false;
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

bool ip_run(char *const args[])
{
    return run_ip_child(args, false);
}

bool ip_run_quiet(char *const args[])
{
    return run_ip_child(args, true);
}

char *cmd_capture(char *const args[])
{
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
    char *out = malloc(cap);
    for (;;) {
        if (len + 1 >= cap) {
            cap *= 2;
            out = realloc(out, cap);
        }
        ssize_t n = read(fds[0], out + len, cap - len - 1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        len += (size_t)n;
    }
    close(fds[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    if (len == 0 || (WIFEXITED(st) && WEXITSTATUS(st) == 127)) {
        free(out);
        return NULL;
    }
    out[len] = '\0';
    return out;
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
