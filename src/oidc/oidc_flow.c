/* OIDC device login (PKCE) and HMAC-signed config-server POSTs. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#else
#include <io.h>
#endif

#include "common.h"
#include <openssl/crypto.h>
#include "crypto.h"
#include "https.h"
#include "json.h"
#include "oidc.h"
#include "util.h"   /* oidc_eprintf is err_printf (oidc.h) */

/* JSON-escaped request body for /m/auth, /m/keepalive, /m/config */
char *oidc_build_dev_body(const char *type, const char *device_id,
                          const char *username)
{
    buf_t b;
    buf_init(&b);
    buf_put_str(&b, "{\"domain\":\"");
    oidc_esc_put(&b, OIDC_DOMAIN);
    buf_put_str(&b, "\",\"type\":\"");
    oidc_esc_put(&b, type);
    buf_put_str(&b, "\",\"oem_name\":\"panabit\",\"device_id\":\"");
    oidc_esc_put(&b, device_id);
    buf_put_str(&b, "\",\"userName\":\"");
    oidc_esc_put(&b, username);
    buf_put_str(&b, "\",\"serverlist_version\":\"0\",\"ipfilter_version\":\"0\",\"branding_version\":\"0\"}");
    return oidc_buf_to_cstr(&b);
}

/* Where the OAuth state is persisted between issuing the authorize URL
 * and validating the pasted redirect URL: a per-user temp file, 0600.
 * R49-L3: the OIDC nonce is persisted on the second line of the same
 * file, so it survives to the id_token check with the same lifecycle as
 * the state. (oidc_login has no config-dir handle -- the CLI resolves it
 * in main -- so a standard per-user temp location is used.) */
#ifndef _WIN32
/* R37-WG-E1 (L21): XDG_RUNTIME_DIR/TMPDIR are inherited environment, not a
 * contract: a relative value ("." or "relative/dir") used to drop the state
 * file into the current working directory — possibly a shared one — and a
 * value pointing at someone else's directory is not ours to write into.
 * Accept only an existing absolute directory owned by us or by root (so
 * /tmp, root-owned and sticky, stays eligible); the mitigations around the
 * file itself (CSPRNG name, O_EXCL|O_NOFOLLOW, 0600, unlink after use)
 * already make the fallback location as safe as the intended one. */
static bool state_dir_ok(const char *dir)
{
    struct stat st;
    if (dir[0] != '/')
        return false;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
        return false;
    return st.st_uid == getuid() || st.st_uid == (uid_t)0;
}

/* first usable candidate of XDG_RUNTIME_DIR, TMPDIR; "/tmp" otherwise */
static const char *state_dir_pick(void)
{
    const char *dir = getenv("XDG_RUNTIME_DIR");
    if (dir && *dir) {
        if (state_dir_ok(dir))
            return dir;
        /* never print the value itself: it is attacker-influenced env */
        log_debug("ignoring XDG_RUNTIME_DIR for the OAuth state file: not "
                  "an absolute existing directory owned by this user or root");
    }
    dir = getenv("TMPDIR");
    if (dir && *dir) {
        if (state_dir_ok(dir))
            return dir;
        log_debug("ignoring TMPDIR for the OAuth state file: not an "
                  "absolute existing directory owned by this user or root");
    }
    return "/tmp";
}
#endif

static char *state_file_path(void)
{
    const char *dir;
#ifndef _WIN32
    dir = state_dir_pick();
#else
    dir = getenv("XDG_RUNTIME_DIR");
    if (!dir || !*dir)
        dir = getenv("TMPDIR");
    if (!dir || !*dir)
        dir = getenv("TEMP");
    if (!dir || !*dir)
        dir = getenv("TMP");
    if (!dir || !*dir)
        dir = ".";
#endif
    size_t n = strlen(dir) + 64;
    char *p = malloc(n);
    if (!p)
        oidc_die("out of memory");   /* fail closed: cannot persist the state */
#ifdef _WIN32
    /* no uid on Windows: the USERNAME env var stands in for the per-user
     * directory component. This is not a security boundary — the file is
     * 0600-created with O_EXCL and the random suffix does that work. */
    const char *user = getenv("USERNAME");
    snprintf(p, n, "%s/iwan-oidc-state-%.32s-%08lx", dir,
             user && *user ? user : "unknown", (unsigned long)rand_u32());
#else
    snprintf(p, n, "%s/iwan-oidc-state-%ld-%08lx", dir, (long)getuid(),
             (unsigned long)rand_u32());
#endif
    return p;
}

static void save_state_file(const char *path, const char *state,
                            const char *nonce)
{
    /* O_EXCL|O_NOFOLLOW: never follow a pre-planted symlink, never
     * overwrite someone else's file. The randomized name makes a
     * collision negligible, so EEXIST is a hard failure.
     * Windows: O_NOFOLLOW has no equivalent, but the file is created
     * fresh with O_CREAT|O_EXCL (fails if ANYTHING exists at the random
     * path), so there is no pre-existing link to follow. */
#ifndef _WIN32
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
#else
    int fd = _open(path, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, 0600);
#endif
    if (fd < 0)
        oidc_die("cannot create OAuth state file %s: %s", path,
                 strerror(errno));
    FILE *f = fdopen(fd, "wb");
    if (!f) {
#ifdef _WIN32
        _close(fd);
        _unlink(path);
#else
        close(fd);
        unlink(path);
#endif
        oidc_die("cannot create OAuth state file %s", path);
    }
    /* two lines: state, then nonce (R49-L3) — both are written in one
     * fputs run, so a partially-written file (crash mid-write) cannot
     * look like a complete previous state */
    if (fputs(state, f) == EOF || fputc('\n', f) == EOF ||
        fputs(nonce, f) == EOF || fputc('\n', f) == EOF ||
        fflush(f) != 0 || fclose(f) != 0) {
#ifdef _WIN32
        _unlink(path);
#else
        unlink(path);
#endif
        oidc_die("cannot create OAuth state file %s", path);
    }
}

/* read the two persisted lines back (state, then nonce); 0 on success,
 * -1 on any failure (including a file without a nonce line) */
static int load_state_file(const char *path, char *state_out, size_t state_sz,
                           char *nonce_out, size_t nonce_sz)
{
    char buf[160];   /* 32-char state + '\n' + 32-char nonce + '\n' */
#ifdef _WIN32
    /* O_NOFOLLOW has no Windows equivalent; the path is our own freshly
     * created random-suffixed file, read back immediately (see the
     * save_state_file comment). */
    int fd = _open(path, _O_RDONLY | _O_BINARY);
    if (fd < 0)
        return -1;
    int n;
    do {
        n = _read(fd, buf, (unsigned int)(sizeof buf - 1));
    } while (n < 0 && errno == EINTR);   /* R37-WG-E1 (R3-L4) */
    if (_close(fd) != 0)
        log_err("cannot close OAuth state file %s: %s (state kept)",
                path, strerror(errno));
#else
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    ssize_t n;
    /* R37-WG-E1 (R3-L4): a signal delivered mid-read made this return -1,
     * and the caller reported it as "authorization response state does not
     * match the saved state (CSRF check failed)" — an ordinary IO hiccup
     * presented as an attack, forcing a fresh login. Retry EINTR. */
    do {
        n = read(fd, buf, sizeof buf - 1);
    } while (n < 0 && errno == EINTR);
    /* R3-L4: a failing close() does not invalidate the bytes just read;
     * warn only, the read result below decides. (close() on a read-only
     * descriptor loses no data.) */
    if (close(fd) != 0)
        log_err("cannot close OAuth state file %s: %s (state kept)",
                path, strerror(errno));
#endif
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    char *nl = strchr(buf, '\n');
    if (!nl)
        return -1;                 /* not even one line: not our format */
    *nl = '\0';                    /* line 1: state */
    char *nonce = nl + 1;          /* line 2: nonce (R49-L3) */
    size_t nn = strlen(nonce);
    if (nn > 0 && nonce[nn - 1] == '\n')   /* tolerate trailing newline */
        nonce[nn - 1] = '\0';
    /* R49-L3: our writer always emits a nonce line; a file without one is
     * stale (pre-nonce format), refuse it so the CSRF check forces a
     * fresh login instead of silently skipping the nonce check. */
    if (nonce[0] == '\0')
        return -1;
    /* never truncate a CSRF/binding value: a too-small buffer is failure */
    if (snprintf(state_out, state_sz, "%s", buf) >= (int)state_sz ||
        snprintf(nonce_out, nonce_sz, "%s", nonce) >= (int)nonce_sz)
        return -1;
    return 0;
}

/* RFC 7636 PKCE: a random verifier and its S256 challenge (both malloc'd) */
static void make_pkce(char **verifier_out, char **challenge_out)
{
    uint8_t vb[64];
    oidc_rand_bytes(vb, sizeof vb);
    char *code_verifier = b64url_no_pad(vb, sizeof vb);
    if (!code_verifier)
        oidc_die("out of memory");   /* fail closed: no verifier, no login */
    uint8_t ch[32];
    sha256(code_verifier, strlen(code_verifier), ch);
    *verifier_out = code_verifier;
    *challenge_out = b64url_no_pad(ch, sizeof ch);
    if (!*challenge_out)
        oidc_die("out of memory");   /* fail closed: no S256 challenge */
}

/* 32 random alphanumeric characters, malloc'd */
static char *make_state(void)
{
    static const char ALPH[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    char *state = malloc(33);
    if (!state)
        oidc_die("out of memory");   /* fail closed: no CSRF state to issue */
    for (int i = 0; i < 32; i++)
        state[i] = ALPH[rand_u32() % 62];
    state[32] = '\0';
    return state;
}

/* R49-L3: 16 CSPRNG bytes rendered as 32 upper-hex characters, malloc'd.
 * The OIDC `nonce` (OIDC Core 3.1.3.7; RFC 8252 6.3 for native apps)
 * binds the id_token to THIS authorization session: it is sent in the
 * authorize request and must be echoed verbatim in the id_token, which
 * validate_claims enforces (fail closed). Same generation mechanism as
 * the X-Auth-Nonce random in oidc_ctrl_post below. */
static char *make_nonce(void)
{
    uint8_t nb[16];
    oidc_rand_bytes(nb, sizeof nb);
    char *nonce = malloc(33);
    if (!nonce)
        oidc_die("out of memory");   /* fail closed: no nonce, no login */
    oidc_hex_upper(nb, sizeof nb, nonce);
    return nonce;
}

/* authorize URL carrying the PKCE challenge, CSRF state and the OIDC
 * nonce (R49-L3); malloc'd */
static char *build_auth_url(const char *code_challenge, const char *state,
                            const char *nonce)
{
    buf_t url;
    buf_init(&url);
    buf_put_str(&url, "https://" OIDC_AUTH_HOST OIDC_AUTH_PATH "?client_id=");
    oidc_urlenc(OIDC_CLIENT_ID, &url);
    buf_put_str(&url, "&redirect_uri=");
    oidc_urlenc(OIDC_REDIRECT, &url);
    buf_put_str(&url, "&response_type=code");
    buf_put_str(&url, "&scope=");
    oidc_urlenc(OIDC_SCOPE, &url);
    buf_put_str(&url, "&code_challenge=");
    oidc_urlenc(code_challenge, &url);
    buf_put_str(&url, "&code_challenge_method=S256");
    buf_put_str(&url, "&state=");
    oidc_urlenc(state, &url);
    /* R49-L3: OIDC Core 3.1.3.7 mandates a nonce for requests that need
     * the id_token bound to the client session (RFC 8252 6.3 for native
     * apps). The same value is later checked against the id_token's
     * nonce claim (validate_claims, fail closed). */
    buf_put_str(&url, "&nonce=");
    oidc_urlenc(nonce, &url);
    oidc_buf_cstr(&url);
    return (char *)url.data;
}

/* prompt for and read the paste-back redirect URL; dies unless it uses
 * our private-use scheme */
static char *read_redirect_url(void)
{
    fprintf(stderr, "  Paste redirect URL: ");
    fflush(stderr);

    char rline[4096];
    if (!fgets(rline, sizeof rline, stdin))
        oidc_die("no redirect URL");
    size_t len = strlen(rline);
    if (len > 0 && rline[len - 1] == '\n') {
        rline[--len] = '\0';
        if (len > 0 && rline[len - 1] == '\r')
            rline[--len] = '\0';          /* CRLF paste */
    } else if (!feof(stdin) && len >= sizeof rline - 1) {
        /* buffer full, no newline, not EOF: either genuinely too long or
         * a 4095-byte paste whose newline is still pending; peek one
         * char to tell them apart (fail only when the URL really
         * exceeds 4095) */
        int c = fgetc(stdin);
        if (c != '\n' && c != EOF && c != '\r')
            oidc_die("redirect URL too long (max 4095 bytes)");
        /* whitespace after the URL (newline/CR) is fine */
        if (c != EOF) {
            int c2 = (c == '\r') ? fgetc(stdin) : c;   /* consume optional \r\n */
            (void)c2;
        }
    }

    /* refuse URLs that do not carry our private-use scheme: pasting an
     * arbitrary http(s) URL here would otherwise make the client parse
     * (and trust) code/state from any site the user was redirected to */
    char *rp = rline;
    while (*rp == ' ' || *rp == '\t')
        rp++;
    /* prefix match must end at a scheme boundary: without this,
     * "com.panabit.mobile://oauth2redirect.evil.com" would also pass */
    size_t rl = strlen(OIDC_REDIRECT);
    if (strncmp(rp, OIDC_REDIRECT, rl) != 0 ||
        (rp[rl] != '\0' && rp[rl] != '?' && rp[rl] != '/' &&
         rp[rl] != ' ' && rp[rl] != '\t'))
        oidc_die("redirect URL must start with "
                 "com.panabit.mobile://oauth2redirect");
    return xstrdup(rline);
}

/* exchange the authorization code for tokens (RFC 6749 4.1.3); returns
 * the parsed JSON response, dies on transport/HTTP/parse errors */
static Json *exchange_code(const char *code, const char *code_verifier)
{
    buf_t body;
    buf_init(&body);
    buf_put_str(&body, "{\"client_id\":\"");
    oidc_esc_put(&body, OIDC_CLIENT_ID);
    buf_put_str(&body, "\",\"code\":\"");
    oidc_esc_put(&body, code);
    buf_put_str(&body, "\",\"code_verifier\":\"");
    oidc_esc_put(&body, code_verifier);
    buf_put_str(&body, "\",\"redirect_uri\":\"");
    oidc_esc_put(&body, OIDC_REDIRECT);
    buf_put_str(&body, "\",\"grant_type\":\"authorization_code\"}");
    oidc_buf_cstr(&body);

    const char *headers[] = { "Content-Type: application/json", NULL };
    int st = 0;
    char *resp = NULL;
    if (!https_post(OIDC_AUTH_HOST, OIDC_TOKEN_PATH, (char *)body.data,
                    headers, &st, &resp)) {
        /* R4-03-4: free resp on the die path, but format the message
         * FIRST — oidc_die consumes its args immediately and resp must
         * still be alive while it is read */
        char msg[512];
        /* R37-WG-E1 (L28): the token endpoint's response body is remote
         * controlled — neutralize it for the terminal, keeping the raw
         * pointer for the cleanse below */
        char *resp_s = oidc_printable_dup(resp && *resp ? resp
                                                       : "no response (transport error)");
        snprintf(msg, sizeof msg, "token exchange failed (HTTP %d): %s", st,
                 resp_s);
        OPENSSL_cleanse(resp_s, strlen(resp_s));
        free(resp_s);
        /* FIX-E: scrub the raw OAuth request body (code + PKCE
         * code_verifier) and the response (tokens) before release */
        OPENSSL_cleanse(body.data, body.len);
        buf_free(&body);
        if (resp)
            OPENSSL_cleanse(resp, strlen(resp));
        free(resp);
        oidc_die("%s", msg);
    }
    OPENSSL_cleanse(body.data, body.len);
    buf_free(&body);
    if (st != 200) {
        /* R4-03-4: same ordering — format before freeing resp */
        char msg[512];
        /* R37-WG-E1 (L28): same remote-controlled body as above */
        char *resp_s = oidc_printable_dup(resp ? resp : "");
        snprintf(msg, sizeof msg, "token exchange failed HTTP %d: %s", st,
                 resp_s);
        OPENSSL_cleanse(resp_s, strlen(resp_s));
        free(resp_s);
        if (resp)
            OPENSSL_cleanse(resp, strlen(resp));
        free(resp);
        oidc_die("%s", msg);
    }

    Json *tok = json_parse(resp);
    if (resp)
        OPENSSL_cleanse(resp, strlen(resp));
    free(resp);
    if (!tok)
        oidc_die("cannot parse token response");
    return tok;
}

/* the id_token is the client's proof of authentication: verify its
 * signature against the issuer's JWKS and its aud/iss/exp claims
 * (plus the OIDC nonce, R49-L3) before trusting any of its contents
 * (fail-closed). expected_nonce is the value sent in the authorize
 * request; the id_token must echo it or verification fails. Returns the
 * verified id_token string (points into tok), so oidc_login does not
 * fetch it a second time for username extraction. */
static const char *verify_id_token(Json *tok, const char *expected_nonce)
{
    const char *id_token = json_get_str(tok, "id_token");
    if (!id_token)
        oidc_die("login response missing id_token");
    if (oidc_jwt_verify(id_token, OIDC_CLIENT_ID,
                        "https://" OIDC_AUTH_HOST, expected_nonce) != 0)
        oidc_die("id_token verification failed");
    return id_token;
}

/* OIDC Core 3.1.2.1 (CSRF): the authorization response must echo back
 * the state saved when the request started; dies otherwise */
static void check_csrf_state(const char *cb_state, const char *saved,
                             int have_state)
{
    if (!cb_state)
        oidc_die("authorization response missing state parameter "
                 "(OIDC Core 3.1.2.1 CSRF check failed)");
    /* L1 (bughunt): constant-time compare like the other sensitive
     * comparisons in this tree (crypto.c ct_eq); state is a fixed-length
     * CSPRNG string, so a length check first is fine. ct_eq returns
     * non-zero on a MATCH, so a mismatch dies on == 0 (the polarity
     * here was once inverted — see bughunt SUMMARY-2 H2). */
    if (!have_state || strlen(cb_state) != strlen(saved) ||
        ct_eq(cb_state, saved, strlen(cb_state)) == 0)
        oidc_die("authorization response state does not match the saved "
                 "state (OIDC Core 3.1.2.1 CSRF check failed)");
}

/* R10 (CRLF injection): the access_token is pasted verbatim into
 * "Authorization: Bearer %s" (see oidc_ctrl_post) and sent to the controller
 * host, so its character set is a security boundary, not cosmetics: a CR/LF
 * inside it would start a new header on the wire (the audit probe injected
 * "X-Injected-Header: pwned" that way). RFC 6750 2.1 defines the token as
 *     b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
 * i.e. at least one base64url/base64 character, optionally padded with '='.
 * Anything else is refused. Deliberately hand-rolled instead of isalnum():
 * that is locale- and sign-dependent for bytes >= 0x80. */
static bool oidc_b64token_ok(const char *s)
{
    size_t i = 0;

    if (!s || !s[0])
        return false;
    for (; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '=')
            break;   /* padding starts: nothing but '=' may follow */
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
              c == '~' || c == '+' || c == '/'))
            return false;
    }
    if (i == 0)
        return false;   /* "*=" alone: RFC 6750 requires 1*(...) first */
    for (; s[i]; i++)
        if (s[i] != '=')
            return false;
    return true;
}

/* pull the access_token out of the token response; dies when absent or when
 * it is not an RFC 6750 b64token (the value goes into a request header, so a
 * malformed one must fail closed rather than be forwarded) */
static char *take_access_token(Json *tok)
{
    const char *at = json_get_str(tok, "access_token");
    if (!at)
        oidc_die("no access_token");
    /* the offending value is NOT echoed: it is a bearer credential */
    if (!oidc_b64token_ok(at))
        oidc_die("access_token is not a valid RFC 6750 b64token "
                 "(refusing to build an Authorization header from it)");
    return xstrdup(at);
}

/* pull "code=..." out of an OAuth redirect URL/query string (moved here
 * from oidc_util.c: the only caller is oidc_login) */
static char *oidc_extract_code(const char *s)
{
    return oidc_url_param(s, "code");
}

void oidc_login(char **kp_out, char **user_out)
{
    char *code_verifier, *code_challenge;
    make_pkce(&code_verifier, &code_challenge);
    char *state = make_state();
    /* R49-L3: a fresh per-session nonce, persisted beside the state and
     * checked against the id_token's nonce claim after the exchange
     * (token/session binding); fail closed on absence/mismatch. */
    char *nonce = make_nonce();

    /* persist the state (and nonce) before issuing the request: the
     * authorization response must echo state back or the flow is
     * rejected below; the id_token must echo the nonce back. */
    char *state_path = state_file_path();
    save_state_file(state_path, state, nonce);

    char *url = build_auth_url(code_challenge, state, nonce);
    oidc_eprintf("  Open in browser:\n  %s\n\n", url);
    free(url);
    free(code_challenge);
    free(state);

    /* the persisted state file has served its purpose once read back:
     * remove it now, before the interactive input, so no random-named
     * 0600 file is left behind on any error path below. */
    char saved[64];
    char saved_nonce[64];
    int have_state = load_state_file(state_path, saved, sizeof saved,
                                     saved_nonce, sizeof saved_nonce) == 0;
#ifdef _WIN32
    _unlink(state_path);
#else
    unlink(state_path);
#endif
    free(state_path);

    char *rline = read_redirect_url();
    char *code = oidc_extract_code(rline);
    char *cb_state = oidc_url_param(rline, "state");
    free(rline);

    check_csrf_state(cb_state, saved, have_state);
    free(cb_state);
    if (!code)
        oidc_die("no authorization code in redirect URL");

    Json *tok = exchange_code(code, code_verifier);
    /* secrets live in heap strings; scrub them like every other key
     * material in this codebase before releasing the memory */
    OPENSSL_cleanse(code, strlen(code));
    free(code);
    OPENSSL_cleanse(code_verifier, strlen(code_verifier));
    free(code_verifier);

    char *kp = take_access_token(tok);
    /* R49-L3: the id_token must echo the nonce we issued (validate_claims
     * rejects a missing/mismatched nonce, fail closed). `have_state` is
     * always true here — check_csrf_state above dies unless the persisted
     * record was actually loaded — the conditional is API robustness. */
    const char *id_token = verify_id_token(tok,
                                           have_state ? saved_nonce : NULL);
    /* the nonce has served its session-binding purpose: scrub it like the
     * other session material before release */
    OPENSSL_cleanse(nonce, strlen(nonce));
    free(nonce);
    /* L2 (bughunt): scrub the refresh_token/access_token heap strings
     * before json_free drops them — they outlive their use by a long
     * shot (offline_access scope), so swap-forget is out. */
    {
        const char *rt = json_get_str(tok, "refresh_token");
        if (rt) {
            OPENSSL_cleanse((void *)rt, strlen(rt));
        }
    }

    char *username = oidc_id_token_username(id_token);
    json_free(tok);
    if (!username)
        username = xstrdup("unknown");
    {
        /* R37-WG-E1 (L28): the name inside the (signature-verified)
         * id_token is still issuer-controlled text; the returned
         * *user_out keeps the raw value — only this print is filtered */
        char *user_s = oidc_printable_dup(username);
        oidc_eprintf("  Authenticated as %s\n", user_s);
        free(user_s);
    }

    *kp_out = kp;
    *user_out = username;
}

/* X-Auth-Sign: HMAC-SHA256 over the canonical request string
 * POST\n<path>\n\n<sha256(body) hex>\n<ts>\n<nonce>, hex-encoded */
static void sign_request(const char *path, const char *body, const char *ts,
                         const char *nonce, char sig[65])
{
    uint8_t h[32];
    sha256(body, strlen(body), h);
    char bh[65];
    hex_encode(h, sizeof h, bh);

    buf_t canon;
    buf_init(&canon);
    buf_put_str(&canon, "POST\n");
    buf_put_str(&canon, path);
    buf_put_str(&canon, "\n\n");
    buf_put_str(&canon, bh);
    buf_put_str(&canon, "\n");
    buf_put_str(&canon, ts);
    buf_put_str(&canon, "\n");
    buf_put_str(&canon, nonce);
    oidc_buf_cstr(&canon);

    uint8_t sm[32];
    hmac_sha256((const uint8_t *)OIDC_APP_SECRET, strlen(OIDC_APP_SECRET),
                canon.data, canon.len, sm);
    buf_free(&canon);
    hex_encode(sm, sizeof sm, sig);
}

int oidc_ctrl_post(const char *path, const char *body,
                   const char *kp_token, char **resp_out)
{
    char ts[32];
    snprintf(ts, sizeof ts, "%lld", (long long)time(NULL));

    uint8_t nb[16];
    oidc_rand_bytes(nb, sizeof nb);
    char nonce[33];
    oidc_hex_upper(nb, sizeof nb, nonce);

    char sig[65];
    sign_request(path, body, ts, nonce, sig);

    char *auth = malloc(strlen(kp_token) + 32);
    if (!auth)
        oidc_die("out of memory");   /* fail closed: same as the state-file
                                      * allocation above; snprintf(NULL, ...)
                                      * would SEGV */
    snprintf(auth, strlen(kp_token) + 32, "Authorization: Bearer %s",
             kp_token);
    char ts_hdr[64];
    char nonce_hdr[64];
    char sig_hdr[128];
    snprintf(ts_hdr, sizeof ts_hdr, "X-Auth-Timestamp: %s", ts);
    snprintf(nonce_hdr, sizeof nonce_hdr, "X-Auth-Nonce: %s", nonce);
    snprintf(sig_hdr, sizeof sig_hdr, "X-Auth-Sign: %s", sig);
    const char *headers[] = {
        "Content-Type: application/json",
        auth,
        "X-Auth-AppId: " OIDC_APP_ID,
        ts_hdr,
        nonce_hdr,
        sig_hdr,
        NULL,
    };

    int st = 0;
    char *resp = NULL;
    if (!https_post(OIDC_CONTROLLER_HOST, path, body, headers, &st, &resp)) {
        /* R13-M-6: auth holds "Authorization: Bearer <token>" — scrub
         * the heap copy before release (R12 L-7: OPENSSL_cleanse) */
        OPENSSL_cleanse(auth, strlen(auth));
        free(auth);
        /* R37-WG-E1 (L28): controller response body is remote controlled;
         * oidc_die() never returns, so the printable copy needs no free */
        oidc_die("request to %s failed (HTTP %d): %s", path, st,
                 oidc_printable_dup(resp && *resp ? resp
                                                  : "no response (transport error)"));
    }
    /* R13-M-6: scrub the Bearer heap copy on the success path too */
    OPENSSL_cleanse(auth, strlen(auth));
    free(auth);
    *resp_out = resp;
    return st;
}