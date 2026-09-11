#include "common.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <pwd.h>
#include <unistd.h>
#endif

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

/* Home directory for "~/" config resolution. Under sudo the passwd
 * entry of the invoking user (SUDO_USER) is used, else the passwd entry
 * of our own uid, else $HOME (absolute only), else NULL. Never guesses
 * "/" or "/home/<name>": a wrong guess could point at a writable path
 * an attacker controls. Returns NULL when undeterminable. */
static char *home_dir(void)
{
#ifdef _WIN32
    /* no passwd database on Windows: USERPROFILE (the port layer's
     * canonical home) first, then $HOME for msys-style environments —
     * absolute POSIX-style paths only, matching the Linux paranoia */
    char *h = port_home_dir();
    if (h && *h)
        return h;
    const char *home = getenv("HOME");
    if (home && *home && home[0] == '/')
        return xstrdup(home);
    return NULL;
#else
    const char *su = getenv("SUDO_USER");
    if (su && *su && strcmp(su, "root") != 0) {
        struct passwd *pw = getpwnam(su);
        if (pw && pw->pw_dir)
            return xstrdup(pw->pw_dir);
    }
    struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_dir)
        return xstrdup(pw->pw_dir);
    const char *home = getenv("HOME");
    if (home && *home && home[0] == '/')
        return xstrdup(home);
    return NULL;
#endif
}

char *resolve_config_dir(const char *dir)
{
    /* R37-WG-E1 (L26): a bare "~" is the home directory, not a literal
     * directory named "~". Accepting only the "~/" spelling was
     * inconsistent: "~/.." WAS expanded (to the home parent) while "~"
     * alone was joined onto the cwd, so --config-dir ~ created a real
     * "<cwd>/~" directory that only looked like the home directory.
     * "~user" stays untouched (it is not something this helper has ever
     * resolved; expanding it needs a getpwnam policy decision). */
    bool bare = dir[0] == '~' && dir[1] == '\0';
    if (!bare && strncmp(dir, "~/", 2) != 0)
        return xstrdup(dir);
    char *home = home_dir();
    if (!home)
        return NULL;
    const char *rest = dir + 1;              /* "" for "~", "/x" for "~/x" */
    size_t hlen = strlen(home);
    size_t rlen = strlen(rest);
    char *out = malloc(hlen + rlen + 1);
    if (!out)
        oom_abort();
    memcpy(out, home, hlen);
    memcpy(out + hlen, rest, rlen + 1);
    free(home);
    return out;
}