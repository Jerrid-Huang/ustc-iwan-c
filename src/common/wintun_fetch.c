/* wintun_fetch.c — locate / interactively fetch wintun.dll (Windows only)
 *
 * TUN mode needs wintun.dll next to the executable. When it is missing:
 *   - interactive stdin: ask once, then download the LATEST build from
 *     https://www.wintun.net/ (page is scraped for the newest
 *     builds/wintun-<ver>.zip link), extract the arch-matching DLL via
 *     PowerShell and drop it beside the exe;
 *   - non-interactive stdin: print the manual download recipe instead of
 *     prompting, so services/scripts never hang on a question.
 *
 * Everything shells out to PowerShell (guaranteed on any Windows that
 * can run wintun); no new third-party dependencies. */
#include "wintun_fetch.h"

#ifdef _WIN32

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <io.h>
#include <stdlib.h>

#include "util.h"
#include "wintun_pin.h"

#define WINTUN_PAGE_URL "https://www.wintun.net/"
#define WINTUN_ZIP_FMT  "https://www.wintun.net/builds/wintun-%s.zip"
#define PS_CMD_MAX      1024

static void exe_dir(char *out, size_t cap)
{
    DWORD n = GetModuleFileNameA(NULL, out, (DWORD)cap);
    if (n == 0 || n >= cap) {
        out[0] = '\0';
        return;
    }
    char *slash = strrchr(out, '\\');
    if (slash)
        *slash = '\0';
}

static void dll_path(char *out, size_t cap)
{
    char dir[MAX_PATH];
    exe_dir(dir, sizeof dir);
    snprintf(out, cap, "%s%swintun.dll", dir,
             dir[0] && dir[strlen(dir) - 1] == '\\' ? "" : "\\");
}

static int file_exists(const char *path)
{
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

/* Escape a value for a PowerShell single-quoted literal: embedded
 * single quotes are doubled. The exe dir is attacker-influenceable
 * (install path), so every interpolated path goes through here. */
static void ps_squote(char *out, size_t cap, const char *src)
{
    size_t o = 0;
    char q = 39;
    for (size_t i = 0; src && src[i] && o + 1 < cap; i++) {
        if (src[i] == q) {
            if (o + 1 < cap) out[o++] = q;
            if (o + 1 < cap) out[o++] = q;
        } else {
            out[o++] = src[i];
        }
    }
    out[o] = 0;
}

/* run a command and capture its stdout (line-oriented use only) */
static char *ps_capture(const char *ps_expr){
    char cmd[PS_CMD_MAX];
    snprintf(cmd, sizeof cmd,
             "powershell -NoProfile -Command \"%s\"", ps_expr);
    FILE *p = _popen(cmd, "r");
    if (!p)
        return NULL;
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        _pclose(p);
        return NULL;
    }
    buf[0] = '\0';   /* FIND-W-2: a child with no stdout leaves the malloc'd
                      * buffer untouched — ensure NUL so consumers (strstr
                      * over it) read an empty string, not uninitialized
                      * (possibly over-read) heap */
    char line[512];
    while (fgets(line, sizeof line, p)) {
        size_t ll = strlen(line);
        if (len + ll + 1 > cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb)
                break;
            buf = nb;
        }
        memcpy(buf + len, line, ll + 1);
        len += ll;
    }
    _pclose(p);
    return buf;
}

/* parse the wintun.net index page for the highest builds/wintun-<v>.zip */
static int latest_zip_version(const char *html, char *ver_out, size_t cap)
{
    const char *needle = "builds/wintun-";
    unsigned best_a = 0, best_b = 0, best_c = 0;
    int found = 0;
    const char *p = html;
    while ((p = strstr(p, needle)) != NULL) {
        p += strlen(needle);
        unsigned a, b, c;
        if (sscanf(p, "%u.%u.%u", &a, &b, &c) == 3) {
            /* only accept it if this really is followed by .zip */
            const char *rest = p;
            while (*rest && (*rest == '.' ||
                   (*rest >= '0' && *rest <= '9')))
                rest++;
            if (strncmp(rest, ".zip", 4) != 0)
                continue;
            if (!found || a > best_a || (a == best_a && b > best_b) ||
                (a == best_a && b == best_b && c > best_c)) {
                best_a = a; best_b = b; best_c = c;
                found = 1;
            }
        }
    }
    if (!found)
        return -1;
    snprintf(ver_out, cap, "%u.%u.%u", best_a, best_b, best_c);
    return 0;
}

static int arch_tag(char *out, size_t cap)
{
#if defined(__aarch64__) || defined(_M_ARM64)
    snprintf(out, cap, "arm64");
#elif defined(__x86_64__) || defined(_M_X64)
    snprintf(out, cap, "amd64");
#elif defined(__i386__) || defined(_M_IX86)
    snprintf(out, cap, "x86");
#else
    return -1;
#endif
    return 0;
}

int wintun_ensure(void)
{
    char dll[MAX_PATH];
    dll_path(dll, sizeof dll);
    if (dll[0] == '\0')
        return -1;
    if (file_exists(dll))
        return 0;

    char manual[1024];
    snprintf(manual, sizeof manual,
             "download https://www.wintun.net/ , open the zip and copy "
             "bin\\<arch>\\wintun.dll to %s",
             dll);

    if (!_isatty(_fileno(stdin))) {
        log_err("wintun.dll not found at %s (non-interactive stdin: %s)",
                dll, manual);
        return -1;
    }

    printf("wintun.dll not found at %s\n", dll);
    printf("Download the latest build from wintun.net now? [Y/n]: ");
    fflush(stdout);
    char ans[16];
    if (!fgets(ans, sizeof ans, stdin)) {
        log_err("aborted (%s)", manual);
        return -1;
    }
    if (ans[0] == 'n' || ans[0] == 'N') {
        log_err("declined (%s)", manual);
        return -1;
    }

    char dir[MAX_PATH];
    exe_dir(dir, sizeof dir);

    log_info("fetching the wintun.net index page...");
    char *html = ps_capture(
        "(Invoke-WebRequest -UseBasicParsing '" WINTUN_PAGE_URL "').Content");
    if (!html) {
        log_err("cannot reach " WINTUN_PAGE_URL);
        return -1;
    }
    char ver[32];
    if (latest_zip_version(html, ver, sizeof ver) != 0) {
        free(html);
        log_err("cannot find a wintun build on the index page");
        return -1;
    }
    free(html);
    log_info("latest wintun build: %s", ver);

    char arch[16];
    if (arch_tag(arch, sizeof arch) != 0) {
        log_err("unsupported architecture for wintun");
        return -1;
    }

    char zip[MAX_PATH], tmpdir[MAX_PATH];
    snprintf(zip, sizeof zip, "%s%swintun-%s.zip", dir,
             dir[0] && dir[strlen(dir) - 1] == '\\' ? "" : "\\", ver);
    snprintf(tmpdir, sizeof tmpdir, "%s%swintun-tmp", dir,
             dir[0] && dir[strlen(dir) - 1] == '\\' ? "" : "\\");

    char cmd[PS_CMD_MAX];
    char zipq[PS_CMD_MAX], tmpq[PS_CMD_MAX];
    ps_squote(zipq, sizeof zipq, zip);
    ps_squote(tmpq, sizeof tmpq, tmpdir);
    /* FIND-W-1: the two %s slots were reversed — the URL wants the
     * VERSION (wintun-%s.zip), -OutFile wants the local zip path. As
     * written, every download produced a 404 URL + a file named "0.14.1" */
    snprintf(cmd, sizeof cmd,
             "(Invoke-WebRequest -UseBasicParsing '" WINTUN_ZIP_FMT "')"
             " -OutFile '%s'", ver, zipq);
    log_info("downloading wintun-%s.zip ...", ver);
    ps_capture(cmd);

    snprintf(cmd, sizeof cmd,
             "Expand-Archive -Path '%s' -DestinationPath '%s' -Force",
             zipq, tmpq);
    ps_capture(cmd);

    char src[MAX_PATH];
    /* Expand-Archive preserves the zip's top-level wintun/ folder */
    snprintf(src, sizeof src, "%s\\wintun\\bin\\%s\\wintun.dll", tmpdir, arch);
    if (!file_exists(src)) {
        log_err("wintun-%s.zip does not contain bin\\%s\\wintun.dll",
                ver, arch);
        return -1;
    }
    /* the fetched artifact must match the pinned official build before
     * it lands next to the exe — the download is over TLS but a pinned
     * hash also protects against a compromised mirror / on-disk tamper */
    if (!wintun_pin_ok_a(src)) {
        log_err("downloaded wintun.dll does not match the pinned build; "
                "deleting it");
        DeleteFileA(src);
        DeleteFileA(zip);
        return -1;
    }
    if (!MoveFileA(src, dll)) {
        log_err("cannot move %s -> %s (error %lu)", src, dll,
                (unsigned long)GetLastError());
        return -1;
    }

    /* best-effort cleanup of the temp artifacts */
    DeleteFileA(zip);
    {
        char sub[MAX_PATH];
        snprintf(sub, sizeof sub, "%s\\wintun\\bin\\%s", tmpdir, arch);
        DeleteFileA(sub);          /* fails while dirs exist; ignore */
        snprintf(sub, sizeof sub, "%s\\wintun\\bin\\%s", tmpdir, arch);
        RemoveDirectoryA(sub);
        snprintf(sub, sizeof sub, "%s\\wintun\\bin", tmpdir);
        RemoveDirectoryA(sub);
        snprintf(sub, sizeof sub, "%s\\wintun", tmpdir);
        RemoveDirectoryA(sub);
        RemoveDirectoryA(tmpdir);
    }

    printf("wintun.dll installed: %s\n", dll);
    return 0;
}

#else /* !_WIN32: keep TU non-empty for pedantic builds */

int wintun_fetch_not_windows(void);

int wintun_fetch_not_windows(void)
{
    return 0;
}

#endif /* _WIN32 */
