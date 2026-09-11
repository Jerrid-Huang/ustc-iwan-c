/* Config file load/save and the /m/config remote fetch. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#else
#include <direct.h>
#include <io.h>
#include <winsock2.h>  /* before windows.h (its own requirement) */
#include <windows.h>   /* MoveFileExA (M5: CRT rename cannot replace) */
#endif

#include <openssl/crypto.h>   /* OPENSSL_cleanse (L2) */

#include "common.h"
#include "crypto.h"
#include "gcm.h"     /* decrypt_password: the server-sent blob */
#include "json.h"
#include "oidc.h"
#include "oidc_pwsecret.h"
#include "util.h"

static long server_port(Json *s)
{
    Json *p = json_get(s, "serverPort");
    long v = 0;
    if (p && json_type(p) == JSON_NUM) {
        /* L9 (bughunt, #6): a remote /m/config can carry serverPort:1e19
         * — a legal double (< DBL_MAX), but out of long range, so the
         * (long) cast below would be UB. Check the numeric domain FIRST
         * (exact port, 1..65535), then cast. */
        double dv = json_num(p);
        if (dv < 1.0 || dv > 65535.0 || dv != (double)(long)dv)
            return 0;
        v = (long)dv;
    } else if (p && json_type(p) == JSON_STR) {
        /* strtol + full-consumption: reject "80http", whitespace and
         * overflow instead of atol's silent clamp / partial parse */
        char *end = NULL;
        errno = 0;
        v = strtol(json_str(p), &end, 10);
        if (errno != 0 || end == json_str(p) || *end != '\0')
            return 0;
    } else {
        return 0;
    }
    /* 0 == "omit"; the connect path then applies its own default */
    return (v >= 1 && v <= 65535) ? v : 0;
}

static bool mkdir_p(const char *path)
{
    /* returns true when at least one directory component was actually
     * created (i.e. did not already exist) — the caller uses this to
     * decide whether it is safe to chown a directory it made vs one
     * that predates the run (chowning a pre-existing system dir such as
     * /etc/cron.d would be a local privilege-escalation primitive) */
    bool created = false;
    char tmp[4096];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof tmp)
        oidc_die("config dir path too long");
    memcpy(tmp, path, n + 1);
    if (tmp[n - 1] == '/')
        tmp[n - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        /* treat '\' as an equivalent separator so explicit Windows
         * paths like C:\a\b work; on POSIX '\' is an ordinary char */
        if (*p == '/' || *p == '\\') {
            char sep = *p;
            *p = '\0';
#ifdef _WIN32
            /* _mkdir ignores the mode argument (Windows has no 0700;
             * ACLs govern access) */
            if (_mkdir(tmp) == 0)
                created = true;
            else if (errno != EEXIST)
#else
            if (mkdir(tmp, 0700) == 0)
                created = true;
            else if (errno != EEXIST)
#endif
                oidc_die("cannot create dir %s: %s", tmp, strerror(errno));
            *p = sep;
        }
    }
#ifdef _WIN32
    if (_mkdir(tmp) == 0)
        created = true;
    else if (errno != EEXIST)
#else
    if (mkdir(tmp, 0700) == 0)
        created = true;
    else if (errno != EEXIST)
#endif
        oidc_die("cannot create dir %s: %s", tmp, strerror(errno));
    return created;
}

static bool is_path_sep(char c)
{
    /* R37-FIX-A2b (R2-B2-2): '\' is a separator ONLY on Windows. The
     * previous revision accepted it on POSIX as well, which turned the
     * relative spelling "\etc" into the ABSOLUTE "/etc": the root guard
     * saw a non-root path and let it through, while the kernel — for
     * which '\' is an ordinary character — would have kept it in the cwd.
     * As root (sudo re-exec) that wrote /etc/servers.json and chown()ed it
     * to SUDO_UID; before that revision the same spelling died cleanly in
     * the root guard. On POSIX only '/' starts or divides components.
     * (mkdir_p() below still treats '\' as a separator on POSIX: that only
     * ever creates an extra intermediate directory, it can never change
     * which file open()/rename()/chown() act on — those hand the path to
     * the kernel, which splits on '/' alone.) */
#ifdef _WIN32
    return c == '/' || c == '\\';
#else
    return c == '/';
#endif
}

#ifdef _WIN32
static bool is_ascii_alpha(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}
#endif

/* Prefix a relative path with the current directory. Returns NULL when
 * getcwd() is unavailable (deleted cwd, or a cwd whose absolute spelling
 * exceeds PATH_MAX). The caller must then REFUSE the path (L27, R3-A3):
 * keeping the relative spelling leaves `rooted` false, so the root-write
 * guard reports "not root" for a spelling the kernel still resolves
 * against a cwd we cannot see — exactly the fail-open the guard exists to
 * prevent. */
static char *join_cwd(const char *path)
{
    char cwd[4096];
#ifdef _WIN32
    if (!_getcwd(cwd, (int)sizeof cwd))
#else
    if (!getcwd(cwd, sizeof cwd))
#endif
        return NULL;
    size_t cl = strlen(cwd);
    size_t pl = strlen(path);
    char *out = malloc(cl + 1 + pl + 1);
    if (!out)
        oom_abort();
    memcpy(out, cwd, cl);
    out[cl] = '/';
    memcpy(out + cl + 1, path, pl + 1);
    return out;
}

/* R37-FIX-A2 (HIGH, R1-D-a-1 / R1-D-3): component-wise canonicalization of
 * a config path. The guard that refuses to write into the filesystem root
 * used to look at the RAW spelling, so `--config-dir /foo/..` (and "/..",
 * "/tmp/../..", "~/../..") passed it, joined into "/foo/../servers.json",
 * and as root (sudo re-exec) wrote /servers.json and — via mkdir_p +
 * restore_owner — chown()ed "/" to the invoking user.
 *
 * Canonicalization stays TEXTUAL on purpose: realpath() resolves symlinks,
 * and this result is handed to mkdir_p()/open()/rename()/chown(); following
 * a symlink there is exactly what must NOT happen. The hole that left open
 * (M9, R3-A3: every one of those calls is resolved by the KERNEL, which
 * follows intermediate symlinks) is closed separately in
 * oidc_save_config() with component-wise lstat() checks. realpath() is
 * used only as a BOOLEAN input to the root verdict in
 * oidc_config_dir_resolves_to_root() — never as a path given to a syscall.
 *   - a RELATIVE spelling is first joined with the cwd (see join_cwd), so
 *     ".." is resolved against the real root and the result denotes the
 *     same object the kernel resolves the raw spelling to;
 *   - both '/' and '\' are separators (see is_path_sep);
 *   - "." and empty components (repeated/trailing separators) vanish;
 *   - ".." pops the previous real component; at/above a root marker it is
 *     a no-op ("/.." == "/", "C:\.." == "C:\", UNC share root stays);
 *   - Windows drive ("C:", "C:/", "C:\") and UNC ("\\server\share")
 *     prefixes are the root marker and are never popped, so every
 *     spelling of a drive/share root normalizes to the marker itself.
 * A legitimate absolute path ("/etc/iwan", "/home/u/.config/iwan") is
 * returned unchanged apart from the "."/".."/separator clean-up.
 *
 * Returns a malloc'd canonical path, or NULL on allocation failure.
 * res->is_root is set when nothing but a root marker is left (i.e. the
 * path IS the filesystem/drive/share root).
 * res->unresolved is set when the textual result must NOT be trusted:
 *   - L27 (R3-A3): a relative spelling whose join_cwd() failed — res->err
 *     carries the getcwd() errno;
 *   - L38 (R3-A3): a ".." with nothing left to pop and no root marker to
 *     stop at. The old code appended ".." there and the NEXT ".." popped
 *     it again ("../.." -> ".", "../../.." -> "..", ...), so the result
 *     denoted a different directory than the caller spelled; the branch
 *     now marks the normalization unresolvable instead of fabricating
 *     self-cancelling text.
 * Every caller MUST refuse an unresolved result. is_root is also forced
 * true for it, so a caller that only consults is_root still fails closed.
 * The result is never the empty string (a fully-popped relative path
 * becomes "."), so callers may pass it straight to mkdir_p()/open(). */
typedef struct {
    bool is_root;       /* the path IS the filesystem/drive/share root */
    bool unresolved;    /* the result cannot be trusted; callers refuse */
    int  err;           /* getcwd() errno behind `unresolved`, else 0 */
} NormPath;

static char *normalize_path(const char *path, NormPath *res)
{
    res->is_root = false;
    res->unresolved = false;
    res->err = 0;
    /* R37-FIX-A2 (2nd half): resolve a relative spelling against the cwd
     * FIRST. Without this the previous attempt merely dropped leading ".."
     * ("../cfg" -> "cfg"), which silently retargeted the save while
     * oidc_load_config() still opened the raw spelling: --fetch wrote
     * ./cfg/servers.json and --list then read ../cfg/servers.json. It also
     * left a relative root escape open (--config-dir ../../.. from a
     * shallow cwd resolves to "/" — the guard saw only the text and let a
     * root write through). Joining makes guard, mkdir_p(), rename() and
     * chown() all see the real target. (_WIN32 drive-relative "C:foo" is
     * left alone: cwd-joining would change its meaning.) */
    char *joined = NULL;
    if (path[0] != '\0' && !is_path_sep(path[0])
#ifdef _WIN32
        && path[1] != ':'
#endif
        ) {
        joined = join_cwd(path);
        if (joined) {
            path = joined;
        } else {
            /* L27 (R3-A3): fail-CLOSED. Keeping the relative spelling is
             * not an option — `rooted` would stay false, the root guard
             * would report "not root" and a spelling like "../.." (which
             * the kernel resolves against a cwd we failed to read) would
             * be written as root. Mark the whole normalization unusable
             * and let the callers refuse (they report errno). */
            res->unresolved = true;
            res->err = errno;
        }
    }
    size_t n = strlen(path);
    char *out = malloc(n + 4);   /* + "C:" -> "C:/" and the NUL */
    if (!out) {
        free(joined);
        return NULL;
    }
    size_t olen = 0;
    size_t i = 0;
    bool rooted = false;

#ifdef _WIN32
    if (n >= 2 && is_ascii_alpha(path[0]) && path[1] == ':' &&
        (n == 2 || is_path_sep(path[2]))) {
        /* drive-absolute; "C:" alone is the drive root here because the
         * caller joins it with a separator ("C:" + "/servers.json") */
        out[olen++] = path[0];
        out[olen++] = ':';
        out[olen++] = '/';
        rooted = true;
        i = 2;
        while (i < n && is_path_sep(path[i]))
            i++;
    } else if (n >= 2 && is_path_sep(path[0]) && is_path_sep(path[1])) {
        /* UNC: "\\server\share" is the root marker — keep both components
         * so ".." can never climb above the share root */
        rooted = true;
        i = 2;
        out[olen++] = '\\';
        for (int comp = 0; comp < 2; comp++) {
            while (i < n && is_path_sep(path[i]))
                i++;
            if (i >= n)
                break;
            size_t s = i;
            while (i < n && !is_path_sep(path[i]))
                i++;
            out[olen++] = comp == 0 ? '\\' : '/';
            memcpy(out + olen, path + s, i - s);
            olen += i - s;
        }
        while (i < n && is_path_sep(path[i]))
            i++;
    } else
#endif
    if (n > 0 && is_path_sep(path[0])) {
        rooted = true;
        out[olen++] = '/';
        i = 1;
        while (i < n && is_path_sep(path[i]))
            i++;                     /* "//".. collapses to the root */
    }
    const size_t root_end = olen;    /* ".." may not pop past this */

    while (i < n) {
        while (i < n && is_path_sep(path[i]))
            i++;                     /* repeated/trailing separators */
        size_t s = i;
        while (i < n && !is_path_sep(path[i]))
            i++;
        size_t clen = i - s;
        if (clen == 0)
            break;                   /* trailing separator(s) */
        const char *c = path + s;
        if (clen == 1 && c[0] == '.')
            continue;                /* "." is not a component */
        if (clen == 2 && c[0] == '.' && c[1] == '.') {
            if (olen > root_end) {
                while (olen > root_end && !is_path_sep(out[olen - 1]))
                    olen--;          /* drop the previous component */
                if (olen > root_end)
                    olen--;          /* and its separator */
            } else if (!rooted) {
                /* L38 (R3-A3): nothing left to pop and no root marker to
                 * stop at. The old code appended ".." here, and the next
                 * ".." immediately popped it again ("../.." -> ".",
                 * "../../.." -> ".."): the two branches cancelled, so the
                 * result pointed at a directory the caller never spelled
                 * (and a legitimate ".." was silently dropped). Do not
                 * emit that text at all — mark the normalization
                 * unresolvable (err stays 0: not an OS error) and let the
                 * callers refuse. A faithful "preserve every .." result
                 * would be WORSE: combined with the fail-open L27 above it
                 * would resolve to "/" and turn a rejected spelling into a
                 * real root write. */
                res->unresolved = true;
            }
            continue;                /* else: no-op at/above the root */
        }
        if (olen > 0 && !is_path_sep(out[olen - 1]))
            out[olen++] = '/';
        memcpy(out + olen, c, clen);
        olen += clen;
    }
    res->is_root = (rooted && olen == root_end) || res->unresolved;
    if (olen == 0)
        out[olen++] = '.';           /* relative, all components popped */
    out[olen] = '\0';
    free(joined);
    return out;
}

/* R37-FIX-A2: does this --config-dir value resolve to the filesystem root
 * no matter how it is spelled? Shared by the CLI gates (oidc_cli.c,
 * iwan_client_oidc.c) and the oidc_save_config() backstop, so a spelling
 * one of them accepts can never be a spelling another one rejects.
 * (The prototype is repeated in those two .c files: adding it to oidc.h
 * was outside this fix's file scope.)
 * Relative values are resolved against the cwd exactly like the save path,
 * so "--config-dir ../../.." from a shallow cwd is recognized as a root
 * write instead of being silently rewritten.
 * An empty/NULL value is NOT reported as root here — the CLI gates reject
 * empty separately with a clearer message, and the save backstop treats
 * "/servers.json" (a value with no directory component) as root itself.
 * M9 (R3-A3): a textual verdict cannot see a SYMLINK, so a path that
 * exists is additionally resolved with realpath() and reported as root
 * when that lands on "/" (e.g. --config-dir link-to-/). realpath() feeds
 * THIS BOOLEAN ONLY: its result is never handed to mkdir/open/rename/chown
 * — the save path re-validates every component with lstat() and keeps
 * using the caller's (normalized) spelling.
 * L27/L38 (R3-A3): an unresolvable normalization (getcwd() failed for a
 * relative value, or a ".." that cannot be popped) is reported as root so
 * every gate refuses it — fail-closed. */
bool oidc_config_dir_resolves_to_root(const char *dir)
{
    if (!dir || dir[0] == '\0')
        return false;
    NormPath res;
    char *np = normalize_path(dir, &res);
    if (!np)
        oom_abort();
    bool root = res.is_root;         /* already true when unresolved */
#ifndef _WIN32
    if (!root) {
        /* realpath() may fail (the directory does not exist yet) — then
         * the textual verdict stands. Only the boolean is taken: the
         * resolved string is never used for a syscall target. */
        char rp[4096];
        if (realpath(np, rp) != NULL && strcmp(rp, "/") == 0)
            root = true;
    }
#endif
    free(np);
    return root;
}

/* R37-FIX-A2b (R2-B2-1): the ONE canonical spelling of the config file
 * path for the whole process. main() calls this once, right after joining
 * --config-dir with "/servers.json", and hands the result to
 * oidc_save_config(), oidc_load_config(), the proxy.conf sibling and every
 * diagnostic — otherwise --fetch writes the normalized path while
 * --list/--connect fopen() the raw spelling, and any ".." (or, before this
 * revision, "\") component makes the two disagree. normalize_path() inside
 * oidc_save_config() stays as an idempotent backstop for direct callers.
 * Never returns the empty string; the caller owns the result. Dies
 * (fail-closed) when the input cannot be resolved at all — see L27/L38. */
char *oidc_config_canon_path(const char *path)
{
    NormPath res;
    char *np = normalize_path(path, &res);
    if (!np)
        oom_abort();
    /* L27/L38 (R3-A3): never hand back a spelling that is not a faithful
     * resolution of the input — the save backstop would otherwise be the
     * only thing standing between it and a filesystem write. */
    if (res.unresolved) {
        const char *why = res.err ? strerror(res.err)
                                  : "a \"..\" that cannot be resolved";
        free(np);
        oidc_die("cannot canonicalize config path \"%s\": %s", path, why);
    }
    return np;
}

void oidc_fetch_config(Config *cf)
{
    char *kp = NULL;
    char *username = NULL;
    oidc_login(&kp, &username);

    uint8_t rb[8];
    oidc_rand_bytes(rb, sizeof rb);
    char device_id[17];
    hex_encode(rb, sizeof rb, device_id);
    if (debug_enabled())
        oidc_eprintf("  device_id=%s\n", device_id);

    char *dev_body = oidc_build_dev_body("android", device_id, username);
    char *ka_body = oidc_build_dev_body("keepalive", device_id, username);

    oidc_eprintf("  Registering device... ");
    fflush(stderr);
    char *resp = NULL;
    int st = oidc_ctrl_post("/m/auth", dev_body, kp, &resp);
    if (st != 200) {
        /* M1 (bughunt): oidc_die formats %s from `detail` AFTER free —
         * detail is only an alias pointer into resp, so vfprintf reads
         * freed heap. Copy the body into a stack buffer first.
         * R37-WG-G (L28): the body is remote controlled (controller
         * /m/auth). Neutralize it BEFORE the stack copy so only the
         * filtered text reaches the terminal, and free the heap copy
         * before oidc_die(): the sanitized buffer is never transferred
         * to the _Noreturn path. */
        const char *detail = resp ? resp : "";
        char *detail_s = oidc_printable_dup(detail);
        char dbuf[256];
        snprintf(dbuf, sizeof dbuf, "%s", detail_s);
        free(detail_s);
        free(resp);
        resp = NULL;
        oidc_die("fail HTTP %d: %s", st, dbuf);
    }
    free(resp);
    oidc_eprintf("OK\n");

    st = oidc_ctrl_post("/m/keepalive", ka_body, kp, &resp);
    free(resp);
    if (st != 200)
        oidc_die("keepalive failed HTTP %d", st);

    oidc_eprintf("  Fetching server config... ");
    fflush(stderr);
    st = oidc_ctrl_post("/m/config", dev_body, kp, &resp);
    free(dev_body);
    free(ka_body);
    if (st != 200) {
        /* R37-WG-G (L28): same treatment as the /m/auth body above —
         * the response body is remote controlled, so the terminal gets
         * a filtered copy (bounded by the same 256-byte stack buffer),
         * freed before oidc_die(). The raw `resp` stays the only buffer
         * that is ever parsed (see json_parse(resp) below). */
        char *resp_s = oidc_printable_dup(resp ? resp : "");
        char dbuf[256];
        snprintf(dbuf, sizeof dbuf, "%s", resp_s);
        free(resp_s);
        free(resp);
        resp = NULL;
        oidc_die("fail HTTP %d: %s", st, dbuf);
    }
    oidc_eprintf("OK\n");

    Json *respj = json_parse(resp);
    free(resp);
    if (!respj)
        oidc_die("cannot parse /m/config response");
    Json *raw = json_get(respj, "serverlist.serverlist");
    size_t n = (raw && json_type(raw) == JSON_ARR) ? json_arr_len(raw) : 0;

    buf_t b;
    buf_init(&b);
    buf_put_str(&b, "{\n  \"domain\": \"" OIDC_DOMAIN "\",\n  \"servers\": [\n");
    for (size_t i = 0; i < n; i++) {
        Json *s = json_arr_at(raw, i);
        buf_put_str(&b, "    {\n");
        buf_put_str(&b, "      \"name\": \"");
        oidc_esc_put(&b, json_get_str(s, "name"));
        buf_put_str(&b, "\",\n      \"host\": \"");
        oidc_esc_put(&b, json_get_str(s, "serverName"));
        buf_put_str(&b, "\",\n");
        long port = server_port(s);
        if (port != 0) {
            char pbuf[64];
            snprintf(pbuf, sizeof pbuf, "      \"port\": %ld,\n", port);
            buf_put_str(&b, pbuf);
        }
        buf_put_str(&b, "      \"username\": \"");
        oidc_esc_put(&b, json_get_str(s, "userName"));
        buf_put_str(&b, "\",\n      \"passWord\": \"");
        {
            /* The server sends the password GCM-encrypted (its wire
             * format; the key derives from the public app secret, so
             * the ciphertext is obfuscation only). Decrypt ONCE here
             * and store the PLAINTEXT: Windows seals it with DPAPI and
             * macOS moves it into the login Keychain directly, and on
             * Linux the file is 0600 plaintext by decision — the
             * app-secret ciphertext layer added nothing (the binary is
             * public). json_get_str returns NULL for a missing field,
             * and the wrap routine feeds it to strlen(); a malicious
             * /m/config entry without passWord/userName must not crash
             * the whole (possibly root) process — treat missing as
             * empty. An undecryptable blob is stored verbatim (the
             * connect path's legacy-GCM fallback handles it). */
            const char *pw_raw = json_get_str(s, "passWord");
            const char *un_raw = json_get_str(s, "userName");
            char *plain = decrypt_password(pw_raw ? pw_raw : "",
                                           OIDC_APP_SECRET, OIDC_DOMAIN,
                                           un_raw ? un_raw : "");
            char *pw = oidc_wrap_password(plain ? plain
                                               : (pw_raw ? pw_raw : ""),
                                          OIDC_DOMAIN,
                                          un_raw ? un_raw : "");
            if (plain) {
                OPENSSL_cleanse(plain, strlen(plain));
                free(plain);
            }
            oidc_esc_put(&b, pw ? pw : (pw_raw ? pw_raw : ""));
            free(pw);
        }
        buf_put_str(&b, "\"\n    }");
        if (i + 1 < n)
            buf_put_str(&b, ",");
        buf_put_str(&b, "\n");
    }
    buf_put_str(&b, "  ]\n}\n");
    oidc_buf_cstr(&b);
    json_free(respj);

    Json *root = json_parse((char *)b.data);
    if (!root)
        oidc_die("cannot parse generated config");
    cf->domain = xstrdup(OIDC_DOMAIN);
    cf->root = root;
    cf->servers = json_get(root, "servers");
    cf->pretty = oidc_buf_to_cstr(&b);

    /* L2 (bughunt): kp holds the access_token — scrub before release */
    if (kp) {
        OPENSSL_cleanse(kp, strlen(kp));
        free(kp);
    }
    free(username);
}

#ifndef _WIN32
/* ---------------------------------------------------------------------
 * M9 (R3-A3): every path below is resolved by the KERNEL, which follows
 * intermediate symlinks — while the root guard above only reads text.
 * A3 proved the hole with inode + strace + a non-root equivalent: with a
 * link planted in a writable directory (`ln -s / <writable>/rootlink`),
 * `--all --config-dir <…>/rootlink[/<newdir>]` (the sudo re-exec keeps
 * the spelling) made the guard — and all four gates — say "not root",
 * then mkdir_p()/open()/rename()/chown() wrote to the LINK TARGET; when
 * mkdir_p() created the directory through the link, dir_created became
 * true and restore_owner() chowned that directory (any name, any
 * traversable location) to the invoking user: a local escalation
 * primitive from a non-root invocation.
 *
 * A textual check cannot fix this — that IS the bug — so the components
 * are inspected with lstat(2) instead. The checks are deliberately
 * conservative (a symlinked ANCESTOR such as ~/.config -> /data/config is
 * refused too): refusing a save that cannot be proven safe is the
 * fail-closed direction, and passing the resolved path still works.
 *
 * These checks are NOT atomic. An attacker able to write a parent can
 * swap a component between the lstat() and the mkdir/open/rename/chown()
 * that follows (TOCTOU). The complete fix is fd-relative (openat(dirfd,
 * comp, O_NOFOLLOW|O_DIRECTORY), openat(dirfd, tmp, …), renameat(),
 * fchownat(dirfd, name, …, AT_SYMLINK_NOFOLLOW), fsync(dirfd)); it is
 * deliberately not attempted here. The window is narrowed by re-running
 * the checks right before rename() and by re-inspecting both chown()
 * targets immediately before each chown(). */

enum {
    DIRCHK_OK = 0,
    DIRCHK_SYMLINK,     /* a component is a symlink */
    DIRCHK_NOTDIR,      /* a component is not a directory */
    DIRCHK_STAT         /* lstat() failed for a reason other than ENOENT */
};

/* Walk every prefix of `dir` that ends at a separator, plus `dir` itself,
 * with lstat(2). Missing components (ENOENT) are fine: mkdir_p() creates
 * them, and something that does not exist cannot be a symlink. On refusal
 * `*off` is the length of the offending prefix and `*err` the lstat errno
 * for DIRCHK_STAT. */
static int config_dir_check(const char *dir, size_t *off, int *err)
{
    char buf[4096];
    size_t n = strlen(dir);
    if (n == 0 || n >= sizeof buf)   /* normalized paths: "" cannot occur */
        oidc_die("config dir path too long");
    memcpy(buf, dir, n + 1);
    for (size_t i = 1; i <= n; i++) {
        if (i < n && buf[i] != '/')
            continue;
        char sep = buf[i];
        buf[i] = '\0';
        struct stat st;
        int rc = lstat(buf, &st);
        int lerr = errno;
        buf[i] = sep;
        if (rc == 0) {
            if (S_ISLNK(st.st_mode)) {
                *off = i;
                return DIRCHK_SYMLINK;
            }
            if (!S_ISDIR(st.st_mode)) {
                *off = i;
                return DIRCHK_NOTDIR;
            }
        } else if (lerr != ENOENT) {
            *off = i;
            *err = lerr;
            return DIRCHK_STAT;
        }
    }
    return DIRCHK_OK;
}

static _Noreturn void config_dir_check_die(const char *dir, size_t off,
                                           int why, int err)
{
    switch (why) {
    case DIRCHK_SYMLINK:
        oidc_die("refusing to use config dir %s: component \"%.*s\" is a "
                 "symlink, and mkdir/open/rename/chown would follow it",
                 dir, (int)off, dir);
    case DIRCHK_STAT:
        oidc_die("cannot inspect config dir %s: component \"%.*s\": %s",
                 dir, (int)off, dir, strerror(err));
    default:
        oidc_die("refusing to use config dir %s: component \"%.*s\" is not "
                 "a directory", dir, (int)off, dir);
    }
    abort();                             /* _Noreturn: unreachable */
}

enum {
    TGTCHK_OK = 0,
    TGTCHK_SYMLINK,
    TGTCHK_NOTREG,
    TGTCHK_HARDLINK,
    TGTCHK_STAT
};

/* The rename()/chown() target. rename(2) does not follow a final symlink
 * (it replaces the link itself, so the link TARGET is not written), but
 * chown(2) DOES follow it, and the link is destroyed either way: a symlink
 * standing at <dir>/servers.json is never a legitimate destination for a
 * root-run save. Rejecting (rather than unlinking first) keeps one
 * invariant for the whole function: no symlink is ever present at a path
 * this code renames or chowns. st_nlink > 1 is refused too — replacing one
 * of several hard-link names silently drops that name, and any chown that
 * still sees the shared inode (the pre-rename window, or a future
 * reordering of rename/chown) changes the owner of every other name. A
 * non-regular target (directory, fifo, device) is refused as well: it is
 * never a config file we wrote. */
static int config_target_check(const char *path, int *err)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT)
            return TGTCHK_OK;           /* fresh save: nothing to replace */
        *err = errno;
        return TGTCHK_STAT;
    }
    if (S_ISLNK(st.st_mode))
        return TGTCHK_SYMLINK;
    if (!S_ISREG(st.st_mode))
        return TGTCHK_NOTREG;
    if (st.st_nlink > 1)
        return TGTCHK_HARDLINK;
    return TGTCHK_OK;
}

static _Noreturn void config_target_check_die(const char *path, int why,
                                              int err)
{
    switch (why) {
    case TGTCHK_SYMLINK:
        oidc_die("refusing to replace config %s: it is a symlink "
                 "(rename would destroy the link and chown follows it)",
                 path);
    case TGTCHK_NOTREG:
        oidc_die("refusing to replace config %s: it is not a regular file",
                 path);
    case TGTCHK_HARDLINK:
        oidc_die("refusing to replace config %s: it has hard links "
                 "(st_nlink > 1), so it is one of several names of the "
                 "same inode", path);
    default:
        oidc_die("cannot inspect config target %s: %s", path, strerror(err));
    }
    abort();                             /* _Noreturn: unreachable */
}

/* Both checks, used right before the operations that depend on them
 * (mkdir_p(), the temp-file open and rename(), and each chown()).
 * `tmp_to_unlink` (may be NULL) is removed first so a refusal at the
 * last-moment call leaves no temp file behind. */
static void config_dest_verify(const char *path, const char *dir,
                               const char *tmp_to_unlink)
{
    size_t off = 0;
    int err = 0;
    if (dir) {
        int bad = config_dir_check(dir, &off, &err);
        if (bad != DIRCHK_OK) {
            if (tmp_to_unlink)
                unlink(tmp_to_unlink);
            config_dir_check_die(dir, off, bad, err);
        }
    }
    int bad = config_target_check(path, &err);
    if (bad != TGTCHK_OK) {
        if (tmp_to_unlink)
            unlink(tmp_to_unlink);
        config_target_check_die(path, bad, err);
    }
}

/* L17 (R3-A3): strict decimal parse of a SUDO_UID/SUDO_GID value.
 * strtoul(s, NULL, 10) alone is far too permissive: ""/"abc"/"0x10" fold
 * to uid 0 (the config silently stays root-owned, so the next non-sudo
 * run cannot read it), "-1"/an overflowing number fold to (uid_t)-1 which
 * chown(2) reads as "do not change" (a silent no-op), and "1000abc"/
 * " 1000" are accepted partially. Require at least one digit, full
 * consumption and a value that fits in uid_t/gid_t. */
static bool parse_sudo_id(const char *s, unsigned long max,
                          unsigned long *out)
{
    if (!s || s[0] < '0' || s[0] > '9')
        return false;               /* empty, signed or whitespace-padded */
    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0')
        return false;               /* overflow or trailing junk */
    if (v > max)
        return false;               /* outside uid_t/gid_t (incl. -1) */
    *out = v;
    return true;
}

/* chown(2) treats (uid_t)-1 / (gid_t)-1 as "leave unchanged", so that
 * sentinel (and anything above it) is never a valid hand-back target */
#define SUDO_ID_MAX(t) ((unsigned long)((t)-1) - 1UL)
#endif /* !_WIN32 */

/* --all re-execs via sudo, so the fresh file (and any dir we just
 * created) are root-owned; hand both back to the invoking user, or
 * the next non-sudo run cannot read or rewrite the config.
 * R37-FIX-A2: both arguments are now the NORMALIZED paths from
 * oidc_save_config() — chown() must never receive a raw "…/.." spelling,
 * which the kernel resolves (chown("/foo/..") is chown("/")).
 * L17 + M9 re-check (R3-A3): the SUDO_* values are parsed strictly (a bad
 * value skips the chown with a warning instead of silently chowning to
 * uid 0 or to the "do not change" sentinel), and both chown() targets are
 * re-inspected with lstat() immediately before the call — chown(2)
 * follows a final symlink and resolves every intermediate one. */
static void restore_owner(const char *path, const char *dir, bool dir_created)
{
#ifndef _WIN32
    const char *su = getenv("SUDO_UID");
    const char *sg = getenv("SUDO_GID");
    if (getuid() == 0 && su && sg) {
        unsigned long uid = 0;
        unsigned long gid = 0;
        if (!parse_sudo_id(su, SUDO_ID_MAX(uid_t), &uid) ||
            !parse_sudo_id(sg, SUDO_ID_MAX(gid_t), &gid)) {
            oidc_eprintf("WARNING: ignoring SUDO_UID=\"%s\" SUDO_GID=\"%s\": "
                         "not a plain decimal id; %s stays root-owned\n",
                         su, sg, path);
            return;
        }
        /* M9 last-moment re-check: never hand chown() a target that is
         * not the file/dir this save just created. */
        {
            struct stat pst;
            if (lstat(path, &pst) != 0 || !S_ISREG(pst.st_mode))
                oidc_die("refusing to chown %s: not a regular file "
                         "(symlink, directory, or replaced since rename)",
                         path);
            if (dir_created && dir) {
                struct stat dst;
                if (lstat(dir, &dst) != 0 || !S_ISDIR(dst.st_mode))
                    oidc_die("refusing to chown config dir %s: not a real "
                             "directory (symlink, or replaced since "
                             "mkdir)", dir);
            }
        }
        if (chown(path, (uid_t)uid, (gid_t)gid) != 0)
            oidc_die("cannot chown config %s: %s", path, strerror(errno));
        /* only chown a directory we actually created this run: chowning
         * a pre-existing directory (e.g. --config-dir /etc/cron.d) would
         * hand ownership of that tree to the invoking user */
        if (dir_created && dir && chown(dir, (uid_t)uid, (gid_t)gid) != 0)
            oidc_die("cannot chown config dir %s: %s", dir,
                     strerror(errno));
    }
#else
    /* Windows has no unix ownership; files inherit the caller's ACLs
     * (and there is no sudo re-exec to undo) */
    (void)path;
    (void)dir;
    (void)dir_created;
#endif
}

/* R14-M-1's dir_component_is_root() lived here and only stripped leading
 * separators; R37-FIX-A2 replaced it with normalize_path() +
 * oidc_config_dir_resolves_to_root() above, which also sees through ".",
 * "..", repeated/trailing separators and Windows drive/UNC roots. */

void oidc_save_config(const char *path, const Config *cf)
{
    if (!cf->servers || json_type(cf->servers) != JSON_ARR ||
        json_arr_len(cf->servers) == 0)
        oidc_die("cannot save config: server list is empty "
                 "(refusing to write an unusable config)");

    /* R37-FIX-A2 (HIGH): every decision AND every filesystem action below
     * uses ONE canonical spelling of the path. Normalizing only the guard
     * would leave mkdir_p()/chown() on the raw "…/.." string — which is how
     * `--config-dir /foo/..` both created "/foo" and chown()ed "/" (the
     * kernel resolves "..", our text check did not). */
    const char *opath = path;
    NormPath nres;
    char *npath = normalize_path(path, &nres);
    if (!npath)
        oom_abort();
    /* L27/L38 (R3-A3) fail-CLOSED: an unresolved normalization must never
     * reach a syscall. The old code kept the relative spelling when
     * getcwd() failed, the guard then saw rooted == false and let it
     * through — and with L38 fixed to preserve ".." that spelling would
     * have resolved to "/" under root. Report the real reason instead. */
    if (nres.unresolved) {
        const char *why = nres.err ? strerror(nres.err)
                                   : "a \"..\" that cannot be resolved";
        free(npath);
        oidc_die("refusing to save config: cannot resolve \"%s\" (%s); "
                 "run from a readable current directory or pass an "
                 "absolute --config-dir", opath, why);
    }
    path = npath;
    bool path_is_root = nres.is_root;

    /* Windows users may pass C:\a\b: look for both separators and keep
     * the later one ('\' is an ordinary char on POSIX, so this is a
     * no-op there). The normalized path has no "."/".."/repeated/trailing
     * separator left (and a relative spelling is now absolute), so this
     * really is the parent directory. */
    const char *slash = strrchr(path, '/');
    const char *bslash = strrchr(path, '\\');
    if (bslash && (!slash || bslash > slash))
        slash = bslash;
    char *dir = NULL;
    bool dir_created = false;
    if (slash && slash != path) {
        dir = malloc((size_t)(slash - path) + 1);
        if (!dir)
            oom_abort();
        memcpy(dir, path, (size_t)(slash - path));
        dir[slash - path] = '\0';
    }
    /* R13-M-5 + R14-M-1 + R37-FIX-A2 root-write guard: refuse to save into
     * the filesystem ROOT. R13-M-5 covered a single leading separator
     * (slash == path -> dir stays NULL), i.e. --config-dir "" joining
     * into "/servers.json". R14-M-1 extended it to "leading consecutive
     * separators" (--config-dir "//" -> "///servers.json"). Both looked at
     * the raw spelling only: `..` is not a separator, so "/foo/..",
     * "/..", "/tmp/../..", "~/../.." and "C:\" sailed through, and the
     * sudo re-exec wrote /servers.json as root. The check now runs on the
     * NORMALIZED (cwd-joined, for relative spellings) parent, BEFORE
     * mkdir_p() (so no "/foo" is left behind) and long before chown().
     * Writing there as root is a misconfiguration, never a legitimate
     * save: refuse loudly. */
    bool parent_is_root = false;
    if (!dir)
        /* no directory component: a leading separator means the parent IS
         * the root ("/servers.json"); a plain relative name means the
         * current directory */
        parent_is_root = is_path_sep(path[0]);
    else
        parent_is_root = oidc_config_dir_resolves_to_root(dir);
    if (path_is_root || parent_is_root)
        oidc_die("refusing to save config into the filesystem root "
                 "(path \"%s\" resolves to \"%s\"): is --config-dir "
                 "empty, all separators, or pointing at the root?",
                 opath, path);
#ifndef _WIN32
    /* M9 (R3-A3): the textual guard above cannot see symlinks, but every
     * syscall below is resolved by the kernel, which follows intermediate
     * ones. Refuse BEFORE mkdir_p() so a link-planted path never creates a
     * directory (or writes, or chowns) on the other side of the link. */
    config_dest_verify(path, dir, NULL);
#endif
    if (dir)
        dir_created = mkdir_p(dir);
#ifndef _WIN32
    /* M9: re-inspect now that mkdir_p() ran. A component that did not
     * exist during the first walk cannot have been a link then, but an
     * attacker who created it FIRST (as a link) made mkdir() fail with
     * EEXIST, which mkdir_p() treats as success — so this second walk is
     * what catches that sequence. The target is checked here too, before
     * any temp file exists, so a refusal leaves nothing behind. */
    config_dest_verify(path, dir, NULL);
#endif
    /* write a sibling temp file, then rename() over the target so the
     * config is replaced atomically: a concurrent reader never sees a
     * half-written file. Same directory keeps rename() on one filesystem.
     * O_NOFOLLOW: this runs as root (sudo re-exec) writing into the
     * invoking user's home; a pre-planted symlink at the temp path must
     * not become an arbitrary-root-file truncate/overwrite primitive */
    size_t tlen = strlen(path) + sizeof ".tmp";
    char *tmp = malloc(tlen);
    if (!tmp)
        oom_abort();
    snprintf(tmp, tlen, "%s.tmp", path);
    /* unpredictable temp name + exclusive create on BOTH platforms:
     * O_NOFOLLOW alone cannot stop a pre-planted HARDLINK, and a fixed
     * name with O_TRUNC would let anyone who can write the config dir
     * make this (sudo re-exec'd, root) process truncate an arbitrary
     * same-filesystem file. rand_u32 is CSPRNG-backed. rename() still
     * replaces the target atomically. */
    tmp = realloc(tmp, tlen + 16);
    if (!tmp)
        oom_abort();
    int fd = -1;
    for (int attempt = 0; attempt < 8 && fd < 0; attempt++) {
        snprintf(tmp, tlen + 16, "%s.tmp.%08x", path, rand_u32());
#ifdef _WIN32
        fd = _open(tmp, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, 0600);
#else
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
#endif
    }
    if (fd < 0)
        oidc_die("cannot write config to %s", path);
    FILE *f = fdopen(fd, "wb");
    if (!f) {
#ifdef _WIN32
        _close(fd);
        _unlink(tmp);
#else
        close(fd);
        unlink(tmp);
#endif
        oidc_die("cannot write config to %s", path);
    }
    /* the file holds decryptable password blobs: never world-readable */
#ifdef _WIN32
    /* _chmod: Windows permissions are ACL-driven, so this only clears
     * the read-only attribute; the 0600 intent is best-effort there */
    (void)_chmod(tmp, 0600);
#else
    (void)fchmod(fileno(f), 0600);
#endif
    /* run fclose even when an earlier write/fsync step failed (the old
     * short-circuit && chain skipped it and leaked the fd until process
     * exit); any error still fails the save and unlinks the temp file */
    bool write_ok = true;
    if (fputs(cf->pretty, f) == EOF || fflush(f) != 0)
        write_ok = false;
#ifdef _WIN32
    if (_commit(fileno(f)) != 0)
        write_ok = false;
#else
    if (fsync(fileno(f)) != 0)
        write_ok = false;
#endif
    if (fclose(f) != 0)
        write_ok = false;
    if (!write_ok) {
#ifdef _WIN32
        _unlink(tmp);
#else
        unlink(tmp);
#endif
        oidc_die("cannot write config to %s: %s", path, strerror(errno));
    }
#ifdef _WIN32
    /* M5 (SUMMARY-2): the CRT rename cannot replace an existing target
     * (the second --fetch would die forever); MoveFileExA with
     * REPLACE_EXISTING keeps the atomic-replace semantics */
    if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING)) {
        /* M3-7: MoveFileExA reports failure via GetLastError (ERROR_*),
         * not errno — strerror(errno) was stale/misleading */
        DWORD gle = GetLastError();
        _unlink(tmp);
        oidc_die("cannot write config to %s: Windows error %lu (0x%lx)",
                 path, (unsigned long)gle, (unsigned long)gle);
    }
#else
    /* M9 last-moment re-check (R3-A3): between the check after mkdir_p()
     * and this rename() an attacker who can write a parent can swap a
     * component for a symlink; rename() would then follow it. Re-run the
     * checks and remove the temp file before dying, so a refusal leaves
     * neither a redirected write nor a stray .tmp. (Not atomic — the
     * fd-relative form documented at config_dir_check() is the real fix.) */
    config_dest_verify(path, dir, tmp);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        oidc_die("cannot write config to %s: %s", path, strerror(errno));
    }
#endif
#ifndef _WIN32
    /* fsync the parent directory so the rename itself is durable: an
     * atomic-replace promise is only half kept if a crash can roll the
     * directory entry back to the old file. Guard the empty case
     * (dir == NULL or ""): open(NULL, O_RDONLY|O_DIRECTORY) is UB, and
     * with no directory component there is simply no parent dir to
     * fsync — skip it (log_debug). Non-empty normal paths are unchanged. */
    if (dir && dir[0] != '\0') {
        int dfd = open(dir, O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) {
            (void)fsync(dfd);
            close(dfd);
        }
    } else {
        log_debug("config save: no parent directory to fsync (dir is "
                  "empty/absent) — skipping parent-dir fsync");
    }
#endif
    free(tmp);

    restore_owner(path, dir, dir_created);
    free(dir);
    /* WIN-RUNTIME (R3-A3): %zu is not implemented by the Windows msvcrt
     * printf — it prints a wrong value at runtime (oidc_eprintf has no
     * format attribute, so the compiler cannot catch it). %llu with an
     * explicit cast is the in-tree convention (json.c:55, auth.c:463). */
    oidc_eprintf("  Saved %llu server(s) to %s\n",
                 (unsigned long long)json_arr_len(cf->servers), path);
    free(npath);
}

void oidc_load_config(const char *path, Config *cf)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        char msg[512];
        snprintf(msg, sizeof msg,
                 "cannot read config file %s (run iwan-client-oidc --fetch first)",
                 path);
        oidc_die_with_cause(msg, strerror(errno));
    }
    /* the file holds per-line PLAINTEXT server passwords (by decision:
     * the app-secret ciphertext layer was obfuscation only) — warn when
     * it is group/world readable instead of silently loading (POSIX
     * only: Windows has no group/world permission bits) */
#ifndef _WIN32
    {
        struct stat st;
        if (fstat(fileno(f), &st) == 0 &&
            (st.st_mode & (S_IRWXG | S_IRWXO)))
            oidc_eprintf("WARNING: %s is group/world readable; "
                         "chmod 600 it\n", path);
    }
#endif
    buf_t b;
    buf_init(&b);
    char tmp[4096];
    size_t n;
    while ((n = fread(tmp, 1, sizeof tmp, f)) > 0)
        buf_put(&b, tmp, n);
    fclose(f);
    oidc_buf_cstr(&b);

    char jerr[160];
    Json *root = json_parse_ex((char *)b.data, jerr, sizeof jerr);
    buf_free(&b);
    if (!root)
        oidc_die_with_cause("parse config", jerr);
    Json *servers = json_get(root, "servers");
    if (!servers || json_type(servers) != JSON_ARR) {
        json_free(root);
        oidc_die("config missing servers array");
    }
    const char *dom = json_get_str(root, "domain");
    cf->domain = xstrdup(dom && *dom ? dom : OIDC_DOMAIN);
    cf->root = root;
    cf->servers = servers;
    cf->pretty = NULL;
}

void oidc_config_free(Config *cf)
{
    free(cf->domain);
    free(cf->pretty);
    json_free(cf->root);
    memset(cf, 0, sizeof *cf);
}