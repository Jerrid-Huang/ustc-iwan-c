/* OIDC device login (PKCE) and HMAC-signed config-server POSTs. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

void oidc_login(char **kp_out, char **user_out)
{
    uint8_t vb[64];
    oidc_rand_bytes(vb, sizeof vb);
    char *code_verifier = b64url_no_pad(vb, sizeof vb);
    uint8_t ch[32];
    sha256(code_verifier, strlen(code_verifier), ch);
    char *code_challenge = b64url_no_pad(ch, sizeof ch);

    static const char ALPH[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    char state[33];
    for (int i = 0; i < 32; i++)
        state[i] = ALPH[rand_u32() % 62];
    state[32] = '\0';

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

    oidc_eprintf("  Open in browser:\n  %s\n\n", (char *)url.data);
    buf_free(&url);
    fprintf(stderr, "  Paste redirect URL: ");
    fflush(stderr);

    char rline[4096];
    if (!fgets(rline, sizeof rline, stdin))
        oidc_die("no redirect URL");
    char *nl = strchr(rline, '\n');
    if (nl)
        *nl = '\0';

    char *code = oidc_extract_code(rline);
    if (!code)
        oidc_die("no authorization code in redirect URL");

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
    free(code);
    free(code_verifier);

    const char *headers[] = { "Content-Type: application/json", NULL };
    int st = 0;
    char *resp = NULL;
    https_post_json(OIDC_AUTH_HOST, OIDC_TOKEN_PATH, (char *)body.data, headers,
                    &st, &resp);
    buf_free(&body);
    if (st != 200)
        oidc_die("token exchange failed HTTP %d: %s", st, resp ? resp : "");

    Json *tok = json_parse(resp);
    free(resp);
    if (!tok)
        oidc_die("cannot parse token response");
    const char *at = json_get_str(tok, "access_token");
    if (!at) {
        json_free(tok);
        oidc_die("no access_token");
    }
    char *kp = xstrdup(at);
    char *username = oidc_id_token_username(tok);
    json_free(tok);
    if (!username)
        username = xstrdup("unknown");
    oidc_eprintf("  Authenticated as %s\n", username);

    free(code_challenge);
    *kp_out = kp;
    *user_out = username;
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
    char sig[65];
    hex_encode(sm, sizeof sm, sig);
    buf_free(&canon);

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
    https_post_json(OIDC_CONTROLLER_HOST, path, body, headers, &st, &resp);
    free(auth);
    *resp_out = resp;
    return st;
}