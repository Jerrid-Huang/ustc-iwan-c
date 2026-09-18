/* wintun_fetch.c — locate / interactively fetch wintun.dll (Windows only)
 *
 * TUN mode needs wintun.dll next to the executable. When it is missing:
 *   - interactive stdin: ask once, then download the PINNED build
 *     (WINTUN_PINNED_VERSION, matched by the SHA-256 pin in
 *     wintun_pin.h) from wintun.net as wintun-<ver>.zip, extract the
 *     arch-matching DLL via PowerShell and drop it beside the exe;
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

/* M2 (FIND): fetching "the latest" build while the SHA-256 pin in
 * wintun_pin.h is fixed to exactly WINTUN_PINNED_VERSION is
 * self-contradictory — the moment upstream ships anything newer (or drops
 * 0.14.1), the downloaded DLL fails the pin and the auto-install breaks
 * permanently (fail-closed but functionally dead). So we deliberately
 * fetch the one version the pin can accept, from the official release
 * URL below (wintun.net/builds/wintun-<ver>.zip, same naming the index
 * page uses). Upgrading wintun now requires bumping WINTUN_PINNED_VERSION
 * AND the matching hash(es) in wintun_pin.h together — no "latest"
 * tracking by design. */
#define WINTUN_PINNED_VERSION "0.14.1"
#define WINTUN_ZIP_FMT  "https://www.wintun.net/builds/wintun-%s.zip"
/* R37/FIX-R1-A3: these caps used to be 1024 / MAX_PATH, which made GCC's
 * -Wformat-truncation=1 conclude that the two-path PowerShell command lines
 * and the tmpdir-derived paths below could not fit (7 warnings that broke
 * the -DIWAN_WERROR=ON Windows cross build). Size every buffer to the worst
 * case its inputs can actually expand to, and check each snprintf return
 * value at the call site — nothing here may truncate silently. */
/* A MAX_PATH-sized directory plus an appended component, and with room for
 * ps_squote() doubling every embedded quote (2 * (MAX_PATH - 1) bytes). */
#define PS_PATH_MAX     (2 * MAX_PATH)
/* A path derived from another PS_PATH_MAX buffer (tmpdir + "\wintun\bin\x"). */
#define PS_PATH_DERIVED_MAX (PS_PATH_MAX + 64)
/* PowerShell command line: worst case is two escaped PS_PATH_MAX paths plus
 * the surrounding literal ("Expand-Archive -Path '...' -DestinationPath '...'"). */
#define PS_CMD_MAX      (2 * PS_PATH_MAX + 128)

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
    int n = snprintf(out, cap, "%s%swintun.dll", dir,
                     dir[0] && dir[strlen(dir) - 1] == '\\' ? "" : "\\");
    if (n < 0 || (size_t)n >= cap) {
        if (cap > 0)
            out[0] = '\0';   /* truncated: report "no path" (callers already
                              * treat an empty result as failure) */
    }
}

static int file_exists(const char *path)
{
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

/* Escape a value for a PowerShell single-quoted literal: embedded
 * single quotes are doubled. The exe dir is attacker-influenceable
 * (install path), so every interpolated path goes through here.
 * Returns 0 on success and -1 when the escaped form does not fit in
 * `cap` — like every snprintf-based sibling above, a truncation is
 * REPORTED, never silent, and the caller fails closed. (The ceiling
 * cannot be reached through a MAX_PATH-limited directory — even a
 * directory made entirely of single quotes would need >240 of them to
 * overflow 2*MAX_PATH — but a consistency check costs nothing and the
 * sibling paths all fail loud.) */
static int ps_squote(char *out, size_t cap, const char *src)
{
    size_t o = 0;
    char q = 39;
    if (cap == 0)
        return -1;   /* cannot even store the NUL terminator */
    for (size_t i = 0; src && src[i]; i++) {
        size_t need = (size_t)((src[i] == q) ? 2 : 1);
        if (o + need + 1 > cap) {
            out[o] = 0;   /* leave a NUL-terminated partial for the log */
            return -1;
        }
        out[o++] = src[i];
        if (src[i] == q)
            out[o++] = q;
    }
    out[o] = 0;
    return 0;
}

/* run a command and capture its stdout (line-oriented use only).
 *
 * R18-1: the result must participate in the caller's failure decision.
 * *ps_rc (optional) receives 0 on success and 1 on ANY failure — a
 * non-zero PowerShell exit status (every command below runs under
 * $ErrorActionPreference='Stop' and ends with `; exit $LASTEXITCODE`,
 * so a cmdlet error really turns into a non-zero process exit), a
 * spawn failure, or an out-of-memory condition.  On success the
 * returned buffer is malloc'd (possibly empty) and is now the CALLER's
 * to free; on failure NULL is returned.  stderr is folded into the
 * captured stream (2>&1) so an error report is visible to the caller. */
static char *ps_capture(const char *ps_expr, int *ps_rc){
    /* +64 covers the wrapper below, so any expression built into a
     * PS_CMD_MAX buffer fits; a longer one is reported, not truncated. */
    char cmd[PS_CMD_MAX + 64];
    int n = snprintf(cmd, sizeof cmd,
                     "powershell -NoProfile -Command \"%s\" 2>&1", ps_expr);
    if (n < 0 || (size_t)n >= sizeof cmd) {
        log_err("internal error: PowerShell command line too long (%d bytes)", n);
        if (ps_rc) *ps_rc = 1;
        return NULL;
    }
    FILE *p = _popen(cmd, "r");
    if (!p) {
        if (ps_rc) *ps_rc = 1;
        return NULL;
    }
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        _pclose(p);
        if (ps_rc) *ps_rc = 1;
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
    /* _pclose returns the command interpreter's exit status (-1 when it
     * cannot be reaped: treat that as a failure as well). */
    int rc = _pclose(p);
    if (ps_rc)
        *ps_rc = (rc == 0) ? 0 : 1;
    return buf;
}

/* Recursively remove a directory tree (files as well as subdirectories).
 * R20-1/T1: RemoveDirectoryA only removes an EMPTY directory, so a
 * partially-extracted tmpdir (Expand-Archive failing mid-flight) was
 * never cleaned up by the old `RemoveDirectoryA(tmpdir)` call — "fail
 * then clean" was structurally ineffective. Walk the tree with
 * FindFirstFile/FindNextFile instead and remove everything; each step is
 * best-effort (a failure may leave a residual entry, but the routine
 * degrades per entry, never abandoning the whole tree). */
static void delete_tree(const char *path)
{
    /* R25 (R24-A1-1): the ROOT entry `path` itself may be a pre-planted
     * junction/symlink (<exe_dir>\wintun-tmp) — FindFirstFileA(path\*)
     * FOLLOWS the link transparently and would enumerate and recursively
     * delete the TARGET's contents (the exact hole 910dd02's inner-item
     * guard missed at the function entry). Check the entry itself and,
     * when it is a reparse point, remove just the link without following
     * and return — same RemoveDirectoryA+DeleteFileA pair as the inner
     * branch below. This is a PRE-ENUMERATION check: the entry is
     * verified before FindFirstFileA ever sees it, so a residual
     * entry-swap TOCTOU is not statically reachable in the routine's
     * control flow (each recursion level re-checks the path it
     * dereferences). */
    DWORD attr = GetFileAttributesA(path);
    if (attr != INVALID_FILE_ATTRIBUTES &&
        (attr & FILE_ATTRIBUTE_REPARSE_POINT)) {
        RemoveDirectoryA(path);
        DeleteFileA(path);
        return;
    }
    char pat[PS_PATH_DERIVED_MAX];
    int n = snprintf(pat, sizeof pat, "%s\\*", path);
    if (n < 0 || (size_t)n >= sizeof pat) {
        log_err("internal error: cleanup glob too long; leaving %s", path);
        return;
    }
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 ||
                strcmp(fd.cFileName, "..") == 0)
                continue;
            char sub[PS_PATH_DERIVED_MAX];
            int m = snprintf(sub, sizeof sub, "%s\\%s", path,
                             fd.cFileName);
            if (m < 0 || (size_t)m >= sizeof sub)
                continue;   /* cannot address this entry; skip it */
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                /* R22-A1-1: never recurse into a reparse point
                 * (junction/symlink) — that would FOLLOW the link and
                 * delete the TARGET's contents, or recurse forever on a
                 * self-referencing link (stack overflow). Remove the
                 * link itself without following: RemoveDirectoryA
                 * removes a junction (and a dir symlink), DeleteFileA
                 * also removes a dir symlink — both best-effort, the
                 * miss of one is covered by the other. */
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                    RemoveDirectoryA(sub);
                    DeleteFileA(sub);
                } else {
                    delete_tree(sub);   /* real dir: contents + itself */
                }
            } else {
                DeleteFileA(sub);       /* a real file */
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryA(path);
}

/* Best-effort removal of the download zip plus the extraction tree.
 * Shared by the success path and the unified failure exit below, so the
 * two can never diverge on what "cleaned up" means. */
static void fetch_cleanup(const char *zip, const char *tmpdir)
{
    DeleteFileA(zip);
    delete_tree(tmpdir);
}

static int arch_tag(char *out, size_t cap)
{
    int n;
#if defined(__aarch64__) || defined(_M_ARM64)
    n = snprintf(out, cap, "arm64");
#elif defined(__x86_64__) || defined(_M_X64)
    n = snprintf(out, cap, "amd64");
#elif defined(__i386__) || defined(_M_IX86)
    n = snprintf(out, cap, "x86");
#else
    return -1;
#endif
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;   /* -1 = "unsupported" */
}

int wintun_ensure(void)
{
    char dll[PS_PATH_MAX];
    dll_path(dll, sizeof dll);
    if (dll[0] == '\0')
        return -1;
    if (file_exists(dll))
        return 0;

    int n = 0;
    char manual[1024];
    n = snprintf(manual, sizeof manual,
                 "download https://www.wintun.net/ , open the zip and copy "
                 "bin\\<arch>\\wintun.dll to %s",
                 dll);
    if (n < 0 || (size_t)n >= sizeof manual) {
        log_err("internal error: wintun installation hint too long");
        return -1;
    }

    if (!_isatty(_fileno(stdin))) {
        log_err("wintun.dll not found at %s (non-interactive stdin: %s)",
                dll, manual);
        return -1;
    }

    printf("wintun.dll not found at %s\n", dll);
    printf("Download the pinned wintun build (%s) from wintun.net now? "
           "[Y/n]: ", WINTUN_PINNED_VERSION);
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

    /* M2: use the pinned version directly (WINTUN_PINNED_VERSION), not
     * whatever the wintun.net index currently headlines. The pin gate
     * below (wintun_pin_ok_a) can only accept WINTUN_PINNED_VERSION's
     * DLL, so there is no point round-tripping through a "latest" page
     * scrape — that was exactly the self-contradiction that broke the
     * auto-install on the next upstream release. */
    char ver[32];
    n = snprintf(ver, sizeof ver, "%s", WINTUN_PINNED_VERSION);
    if (n < 0 || (size_t)n >= sizeof ver) {
        log_err("internal error: pinned wintun version does not fit");
        return -1;
    }
    log_info("fetching pinned wintun build: %s", ver);

    char arch[16];
    if (arch_tag(arch, sizeof arch) != 0) {
        log_err("unsupported architecture for wintun");
        return -1;
    }

    char zip[PS_PATH_MAX], tmpdir[PS_PATH_MAX];
    n = snprintf(zip, sizeof zip, "%s%swintun-%s.zip", dir,
                 dir[0] && dir[strlen(dir) - 1] == '\\' ? "" : "\\", ver);
    if (n < 0 || (size_t)n >= sizeof zip) {
        log_err("internal error: local zip path too long");
        return -1;
    }
    n = snprintf(tmpdir, sizeof tmpdir, "%s%swintun-tmp", dir,
                 dir[0] && dir[strlen(dir) - 1] == '\\' ? "" : "\\");
    if (n < 0 || (size_t)n >= sizeof tmpdir) {
        log_err("internal error: temp extraction path too long");
        return -1;
    }

    char cmd[PS_CMD_MAX];
    int rc = 1;
    char zipq[PS_PATH_MAX], tmpq[PS_PATH_MAX];
    if (ps_squote(zipq, sizeof zipq, zip) != 0 ||
        ps_squote(tmpq, sizeof tmpq, tmpdir) != 0) {
        log_err("internal error: wintun path does not fit its escaped "
                "PowerShell buffer");
        return -1;   /* fail closed like every sibling snprintf check;
                      * nothing has been downloaded or extracted yet */
    }
    /* FIND-W-1: the two %s slots were reversed — the URL wants the
     * VERSION (wintun-%s.zip), -OutFile wants the local zip path. As
     * written, every download produced a 404 URL + a file named "0.14.1".
     * R18-1: the old command opened with a parenthesized expression and
     * appended the named parameter outside it — "(Invoke-WebRequest …)
     * -OutFile '…'" — which is a PARSE error in PowerShell (after a
     * closed `)` only an operator, `.`/`::` member access, `[ ]`
     * indexing, `( )` invocation or a pipe/redirection may follow; a
     * named parameter token cannot.  Verified against PowerShell:
     * "Unexpected token '-OutFile' in expression or statement.").
     * Command-first form is legal, and
     * $ErrorActionPreference='Stop' makes a cmdlet failure a TERMINATING
     * error so the process (whose status _pclose() returns) exits
     * non-zero instead of PowerShell silently exiting 0. */
    n = snprintf(cmd, sizeof cmd,
                 "$ErrorActionPreference='Stop'; Invoke-WebRequest"
                 " -UseBasicParsing '" WINTUN_ZIP_FMT "' -OutFile '%s';"
                 " exit $LASTEXITCODE", ver, zipq);
    if (n < 0 || (size_t)n >= sizeof cmd) {
        log_err("internal error: PowerShell download command too long");
        return -1;
    }
    log_info("downloading wintun-%s.zip ...", ver);
    char *dlout = ps_capture(cmd, &rc);
    /* R18-1: the caller's decision must use ps_capture()'s result — the
     * old code discarded it, so a parse-error'd / failed download raced
     * on to Expand-Archive and then mis-reported "zip does not contain
     * bin\amd64\wintun.dll".  Check the exit status AND the produced zip
     * (the file check is the ground truth the download exists to serve). */
    if (rc != 0) {
        log_err("PowerShell failed to download %s (pinned wintun build); "
                "auto-install aborted (%s)", zip, manual);
        if (dlout && dlout[0])
            log_err("PowerShell output: %s", dlout);
        free(dlout);
        goto fail;   /* unified cleanup: nothing extracted yet, but the
                      * (partial) zip goes away with the rest */
    }
    free(dlout);
    if (!file_exists(zip)) {
        log_err("download did not produce %s; auto-install aborted (%s)",
                zip, manual);
        goto fail;
    }

    n = snprintf(cmd, sizeof cmd,
                 "$ErrorActionPreference='Stop'; Expand-Archive"
                 " -Path '%s' -DestinationPath '%s' -Force;"
                 " exit $LASTEXITCODE", zipq, tmpq);
    if (n < 0 || (size_t)n >= sizeof cmd) {
        log_err("internal error: PowerShell expand command too long");
        goto fail;
    }
    char *exout = ps_capture(cmd, &rc);
    if (rc != 0) {
        log_err("PowerShell failed to extract %s; auto-install aborted "
                "(%s)", zip, manual);
        if (exout && exout[0])
            log_err("PowerShell output: %s", exout);
        free(exout);
        /* T1/R20-1: the Expand failure branch used to return after a
         * bare RemoveDirectoryA(tmpdir) — a NO-OP while tmpdir holds the
         * files Expand already wrote - so partial extraction residue was
         * left in the exe directory. Route through the single cleanup
         * exit below, which recursively removes the whole tree. */
        goto fail;
    }
    free(exout);

    char src[PS_PATH_DERIVED_MAX];
    /* Expand-Archive preserves the zip's top-level wintun/ folder */
    n = snprintf(src, sizeof src, "%s\\wintun\\bin\\%s\\wintun.dll", tmpdir,
                 arch);
    if (n < 0 || (size_t)n >= sizeof src) {
        log_err("internal error: extracted DLL path too long");
        goto fail;
    }
    if (!file_exists(src)) {
        log_err("wintun-%s.zip does not contain bin\\%s\\wintun.dll",
                ver, arch);
        goto fail;
    }
    /* the fetched artifact must match the pinned official build before
     * it lands next to the exe — the download is over TLS but a pinned
     * hash also protects against a compromised mirror / on-disk tamper */
    if (!wintun_pin_ok_a(src)) {
        log_err("downloaded wintun.dll does not match the pinned build; "
                "deleting it");
        goto fail;   /* unified cleanup removes src + zip + tmpdir tree */
    }
    if (!MoveFileA(src, dll)) {
        log_err("cannot move %s -> %s (error %lu)", src, dll,
                (unsigned long)GetLastError());
        /* R18-1/T3 + T1/R20-1: this failure branch used to leak the
         * zip/DLL/late-extraction files in tmpdir — the unified failure
         * exit below now owns all of them. */
        goto fail;
    }

    /* success path: remove the temp artifacts through the SAME routine
     * as the failure exit, so the two can never diverge (T1/R20-1) */
    fetch_cleanup(zip, tmpdir);

    printf("wintun.dll installed: %s\n", dll);
    return 0;

fail:
    /* T1/R20-1: single exit for every failure after the download phase
     * (i.e. once zip/tmpdir can exist on disk). One place owns "remove
     * the zip + recursively remove the tmpdir tree", so a failed
     * Expand-Archive (partial files already written), a missing arch
     * folder, a pin mismatch or a failed MoveFileA can no longer leave
     * residue in the exe directory. Best-effort by design — cleanup
     * never changes the failure return. */
    fetch_cleanup(zip, tmpdir);
    return -1;
}

#else /* !_WIN32: keep TU non-empty for pedantic builds */

int wintun_fetch_not_windows(void);

int wintun_fetch_not_windows(void)
{
    return 0;
}

#endif /* _WIN32 */
