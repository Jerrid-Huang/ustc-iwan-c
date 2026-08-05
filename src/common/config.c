#include "common.h"

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int load_cidr_file(const char *path, slist_t *out)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    char line[1024];
    while (fgets(line, sizeof line, f)) {
        if (strchr(line, '\n') == NULL && !feof(f)) {
            /* line longer than the buffer: refuse rather than split it */
            errno = EFBIG;
            fclose(f);
            return -1;
        }
        char *p = line;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (*p == '\0' || *p == '#')
            continue;
        char *end = p + strlen(p);
        while (end > p && (end[-1] == ' ' || end[-1] == '\t' ||
                           end[-1] == '\r' || end[-1] == '\n'))
            *--end = '\0';
        slist_push_csv(out, p);
    }
    fclose(f);
    return 0;
}

static char *home_dir(void)
{
    const char *su = getenv("SUDO_USER");
    if (su && *su && strcmp(su, "root") != 0) {
        long bufsz = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsz <= 0)
            bufsz = 16384;
        char *buf = malloc((size_t)bufsz);
        struct passwd pw;
        struct passwd *res = NULL;
        int rc = getpwnam_r(su, &pw, buf, (size_t)bufsz, &res);
        if (rc == 0 && res && pw.pw_dir) {
            char *home = xstrdup(pw.pw_dir);
            free(buf);
            return home;
        }
        free(buf);
        size_t n = strlen("/home/") + strlen(su) + 1;
        char *fallback = malloc(n);
        snprintf(fallback, n, "/home/%s", su);
        return fallback;
    }
    const char *home = getenv("HOME");
    if (home && *home)
        return xstrdup(home);
    return xstrdup("/");
}

char *resolve_config_dir(const char *dir)
{
    if (strncmp(dir, "~/", 2) != 0)
        return xstrdup(dir);
    char *home = home_dir();
    const char *rest = dir + 2;
    size_t hlen = strlen(home);
    size_t rlen = strlen(rest);
    char *out = malloc(hlen + 1 + rlen + 1);
    memcpy(out, home, hlen);
    out[hlen] = '/';
    memcpy(out + hlen + 1, rest, rlen + 1);
    free(home);
    return out;
}