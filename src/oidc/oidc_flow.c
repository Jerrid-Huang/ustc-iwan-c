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
#include "crypto.h"
#include "https.h"
#include "json.h"
#include "oidc.h"

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
 * (oidc_login has no config-dir handle -- the CLI resolves it in main --
 * so a standard per-user temp location is used.) */
static char *state_file_path(void)
{
    const char *dir = getenv("XDG_RUNTIME_DIR");
    if (!dir || !*dir)
        dir = getenv("TMPDIR");
#ifndef _WIN32
    if (!dir || !*dir)
        dir = "/tmp";
#else
    if (!dir || !*dir)
        dir = getenv("TEMP");
    if (!dir || !*dir)
        dir = getenv("TMP");
    if (!dir || !*dir)
        dir = ".";
#endif
    size_t n = strlen(dir) + 64;
    char *p = malloc(n);
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

static void save_state_file(const char *path, const char *state)
{
    /* O_EXCL|O_NOFOLLOW: never follow a pre-planted symlink, never
     * overwrite someone else's file. The randomized name makes a
     * collision negligible, so EEXIST is a hard failure.
     * Windows: O_NOFOLLOW has no equivalent, but the file is created
     * fresh with O_CREAT|O_EXCL (fails if ANYTHING exists at the random
     * path), so there is no pre-existing link to follow. */
#ifdef _WIN32
    int fd = _open(path, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, 0600);
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
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
    if (fputs(state, f) == EOF || fputc('\n', f) == EOF ||
        fflush(f) != 0 || fclose(f) != 0) {
#ifdef _WIN32
        _unlink(path);
#else
        unlink(path);
#endif
        oidc_die("cannot create OAuth state file %s", path);
    }
}

/* read the persisted state back; 0 on success, -1 on any failure */
static int load_state_file(const char *path, char *out, size_t outsz)
{
#ifdef _WIN32
    /* O_NOFOLLOW has no Windows equivalent; the path is our own freshly
     * created random-suffixed file, read back immediately (see the
     * save_state_file comment). */
    int fd = _open(path, _O_RDONLY | _O_BINARY);
    if (fd < 0)
        return -1;
    int n = _read(fd, out, (unsigned int)(outsz - 1));
    if (_close(fd) != 0)
        return -1;
#else
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, out, outsz - 1);
    if (close(fd) != 0)
        return -1;
#endif
    if (n <= 0)
        return -1;
    out[n] = '\0';
    if (out[n - 1] == '\n')   /* tolerate our own trailing newline */
        out[n - 1] = '\0';
    return 0;
}

/* RFC 7636 PKCE: a random verifier and its S256 challenge (both malloc'd) */
static void make_pkce(char **verifier_out, char **challenge_out)
{
    uint8_t vb[64];
    oidc_rand_bytes(vb, sizeof vb);
    char *code_verifier = b64url_no_pad(vb, sizeof vb);
    uint8_t ch[32];
    sha256(code_verifier, strlen(code_verifier), ch);
    *verifier_out = code_verifier;
    *challenge_out = b64url_no_pad(ch, sizeof ch);
}

/* 32 random alphanumeric characters, malloc'd */
static char *make_state(void)
{
    static const char ALPH[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    char *state = malloc(33);
    for (int i = 0; i < 32; i++)
        state[i] = ALPH[rand_u32() % 62];
    state[32] = '\0';
    return state;
}

/* authorize URL carrying the PKCE challenge and CSRF state; malloc'd */
static char *build_auth_url(const char *code_challenge, const char *state)
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
    char *nl = strchr(rline, '\n');
    if (nl)
        *nl = '\0';
    else if (!feof(stdin))
        /* no newline but not EOF: the paste exceeded the buffer and was
         * silently truncated — the resulting URL would fail with a
         * baffling state/code mismatch later, so fail loudly instead */
        oidc_die("redirect URL too long (max 4095 bytes)");

    /* refuse URLs that do not carry our private-use scheme: pasting an
     * arbitrary http(s) URL here would otherwise make the client parse
     * (and trust) code/state from any site the user was redirected to */
    char *rp = rline;
    while (*rp == ' ' || *rp == '\t')
        rp++;
    if (strncmp(rp, OIDC_REDIRECT, strlen(OIDC_REDIRECT)) != 0)
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
        buf_free(&body);
        oidc_die("token exchange failed (HTTP %d): %s", st,
                 resp && *resp ? resp : "no response (transport error)");
    }
    buf_free(&body);
    if (st != 200)
        oidc_die("token exchange failed HTTP %d: %s", st, resp ? resp : "");

    Json *tok = json_parse(resp);
    free(resp);
    if (!tok)
        oidc_die("cannot parse token response");
    return tok;
}

/* the id_token is the client's proof of authentication: verify its
 * signature against the issuer's JWKS and its aud/iss/exp claims
 * before trusting any of its contents (fail-closed) */
static void verify_id_token(Json *tok)
{
    const char *id_token = json_get_str(tok, "id_token");
    if (!id_token)
        oidc_die("login response missing id_token");
    if (oidc_jwt_verify(id_token, OIDC_CLIENT_ID,
                        "https://" OIDC_AUTH_HOST) != 0)
        oidc_die("id_token verification failed");
}

/* OIDC Core 3.1.2.1 (CSRF): the authorization response must echo back
 * the state saved when the request started; dies otherwise */
static void check_csrf_state(const char *cb_state, const char *saved,
                             int have_state)
{
    if (!cb_state)
        oidc_die("authorization response missing state parameter "
                 "(OIDC Core 3.1.2.1 CSRF check failed)");
    if (!have_state || strcmp(cb_state, saved) != 0)
        oidc_die("authorization response state does not match the saved "
                 "state (OIDC Core 3.1.2.1 CSRF check failed)");
}

/* pull the access_token out of the token response; dies when absent */
static char *take_access_token(Json *tok)
{
    const char *at = json_get_str(tok, "access_token");
    if (!at)
        oidc_die("no access_token");
    return xstrdup(at);
}

void oidc_login(char **kp_out, char **user_out)
{
    char *code_verifier, *code_challenge;
    make_pkce(&code_verifier, &code_challenge);
    char *state = make_state();

    /* persist the state before issuing the request: the authorization
     * response must echo it back or the flow is rejected below */
    char *state_path = state_file_path();
    save_state_file(state_path, state);

    char *url = build_auth_url(code_challenge, state);
    oidc_eprintf("  Open in browser:\n  %s\n\n", url);
    free(url);
    free(code_challenge);
    free(state);

    /* the persisted state file has served its purpose once read back:
     * remove it now, before the interactive input, so no random-named
     * 0600 file is left behind on any error path below. */
    char saved[64];
    int have_state = load_state_file(state_path, saved, sizeof saved) == 0;
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
    free(code);
    free(code_verifier);

    char *kp = take_access_token(tok);
    verify_id_token(tok);

    char *username = oidc_id_token_username(tok);
    json_free(tok);
    if (!username)
        username = xstrdup("unknown");
    oidc_eprintf("  Authenticated as %s\n", username);

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
        free(auth);
        oidc_die("request to %s failed (HTTP %d): %s", path, st,
                 resp && *resp ? resp : "no response (transport error)");
    }
    free(auth);
    *resp_out = resp;
    return st;
}