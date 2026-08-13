/* OIDC id_token verification: RS256 signature check against the
 * issuer's published JWKS, plus aud/iss/exp claim validation
 * (OIDC Core 3.1.3.7). Fail-closed: any lookup or parse error rejects
 * the token. */

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common.h"
#include "crypto.h"
#include "https.h"
#include "json.h"
#include "oidc.h"

/* per RFC 7515 the base64url alphabet contains no '.', so a well-formed
 * JWT has exactly two dots and a non-empty signature */
static int jwt_split(const char *jwt, const char **hdr, size_t *hdr_len,
                     const char **payload, size_t *payload_len,
                     const char **sig)
{
    const char *d1 = strchr(jwt, '.');
    if (!d1 || d1 == jwt)
        return -1;
    const char *d2 = strchr(d1 + 1, '.');
    if (!d2 || d2 == d1 + 1 || d2[1] == '\0' || strchr(d2 + 1, '.'))
        return -1;
    *hdr = jwt;
    *hdr_len = (size_t)(d1 - jwt);
    *payload = d1 + 1;
    *payload_len = (size_t)(d2 - d1 - 1);
    *sig = d2 + 1;
    return 0;
}

/* decode one base64url JWT segment into a NUL-terminated string */
static char *seg_decode(const char *seg, size_t seg_len)
{
    char *tmp = malloc(seg_len + 1);
    size_t raw_len = 0;
    uint8_t *raw;
    char *txt;
    if (!tmp)
        return NULL;
    memcpy(tmp, seg, seg_len);
    tmp[seg_len] = '\0';
    raw = b64url_decode(tmp, &raw_len);
    free(tmp);
    if (!raw)
        return NULL;
    txt = malloc(raw_len + 1);
    if (!txt) {
        free(raw);
        return NULL;
    }
    memcpy(txt, raw, raw_len);
    txt[raw_len] = '\0';
    free(raw);
    return txt;
}

/* extract one base64url segment of a JWT (0=header, 1=payload, 2=sig),
 * decoded to a NUL-terminated string; NULL on malformed input or
 * allocation failure */
char *oidc_jwt_segment(const char *jwt, int idx)
{
    const char *hdr, *payload, *sig;
    size_t hdr_len, payload_len;
    const char *seg;
    size_t seg_len;

    if (jwt_split(jwt, &hdr, &hdr_len, &payload, &payload_len, &sig) != 0)
        return NULL;
    switch (idx) {
    case 0:
        seg = hdr;
        seg_len = hdr_len;
        break;
    case 1:
        seg = payload;
        seg_len = payload_len;
        break;
    case 2:
        seg = sig;
        seg_len = strlen(sig);
        break;
    default:
        return NULL;
    }
    return seg_decode(seg, seg_len);
}

/* split "https://host[:port]/path..." into host and path (path always
 * starts with '/', query/fragment stripped); 1 on success */
static int split_https_url(const char *url, char *host, size_t hostsz,
                           char *path, size_t pathsz)
{
    const char *u = url;
    const char *slash;
    const char *end;
    const char *q, *f;
    size_t n;

    if (strncmp(u, "https://", 8) != 0)
        return 0;
    u += 8;
    slash = strchr(u, '/');
    n = slash ? (size_t)(slash - u) : strlen(u);
    if (n == 0 || n >= hostsz || memchr(u, '@', n) != NULL)
        return 0;
    memcpy(host, u, n);
    host[n] = '\0';
    if (!slash) {
        if (pathsz < 2)
            return 0;
        strcpy(path, "/");
        return 1;
    }
    /* path runs from the first '/' to the end of the URL (or to a
     * '?'/'#' if present); end must default to the URL end, not to
     * slash — otherwise any URL without a query/fragment yields an
     * empty path and is rejected (e.g. jwks_uri) */
    end = slash + strlen(slash);
    q = strchr(slash, '?');
    f = strchr(slash, '#');
    if (q && (!f || q < f))
        end = q;
    else if (f)
        end = f;
    n = (size_t)(end - slash);
    if (n == 0 || n >= pathsz)
        return 0;
    memcpy(path, slash, n);
    path[n] = '\0';
    return 1;
}

/* GET host+path, parse the JSON body; NULL on any failure (reported) */
static Json *fetch_json(const char *host, const char *path, const char *what)
{
    int st = 0;
    char *body = NULL;
    Json *j;

    if (!https_get(host, path, &st, &body)) {
        oidc_eprintf("oidc_jwt_verify: cannot fetch %s (HTTP %d): %s\n",
                     what, st, body && *body ? body : "no response");
        free(body);
        return NULL;
    }
    if (st != 200) {
        oidc_eprintf("oidc_jwt_verify: %s returned HTTP %d: %s\n", what, st,
                     body && *body ? body : "no body");
        free(body);
        return NULL;
    }
    j = json_parse(body);
    free(body);
    if (!j)
        oidc_eprintf("oidc_jwt_verify: cannot parse %s\n", what);
    return j;
}

/* aud may be a string or an array of strings (RFC 7519 4.1.3) */
static int aud_matches(Json *tok, const char *aud)
{
    Json *a = json_get(tok, "aud");
    if (!a)
        return 0;
    if (json_type(a) == JSON_STR)
        return strcmp(json_str(a), aud) == 0;
    if (json_type(a) == JSON_ARR) {
        size_t n = json_arr_len(a);
        for (size_t i = 0; i < n; i++) {
            Json *e = json_arr_at(a, i);
            if (json_type(e) == JSON_STR && strcmp(json_str(e), aud) == 0)
                return 1;
        }
    }
    return 0;
}

/* build an RSA EVP_PKEY from JWKS n/e (base64url big-endian integers,
 * no padding); NULL on failure */
static EVP_PKEY *jwks_rsa_key(Json *key)
{
    const char *n_b64 = json_get_str(key, "n");
    const char *e_b64 = json_get_str(key, "e");
    uint8_t *n_raw = NULL, *e_raw = NULL;
    size_t n_len = 0, e_len = 0;
    BIGNUM *n = NULL, *e = NULL;
    RSA *rsa = NULL;
    EVP_PKEY *pkey = NULL;

    if (!n_b64 || !e_b64)
        return NULL;
    n_raw = b64url_decode(n_b64, &n_len);
    e_raw = b64url_decode(e_b64, &e_len);
    if (!n_raw || !e_raw || n_len == 0 || e_len == 0)
        goto out;
    n = BN_bin2bn(n_raw, (int)n_len, NULL);
    e = BN_bin2bn(e_raw, (int)e_len, NULL);
    if (!n || !e)
        goto out;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    rsa = RSA_new();
    if (!rsa)
        goto out;
    if (RSA_set0_key(rsa, n, e, NULL) != 1)
        goto out;
    n = NULL;   /* owned by rsa from here on */
    e = NULL;
    pkey = EVP_PKEY_new();
    if (pkey && EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    if (!pkey)
        RSA_free(rsa);
#pragma GCC diagnostic pop
out:
    free(n_raw);
    free(e_raw);
    BN_free(n);
    BN_free(e);
    return pkey;
}

/* decode and parse the JWT header/payload, enforce alg==RS256 and a
 * kid. Returns the payload claims JSON (NULL on failure, reason on
 * stderr); *sig points into jwt, *hdr_out receives the header JSON. */
static Json *decode_jwt_parts(const char *jwt, const char **sig,
                              Json **hdr_out)
{
    const char *hdr, *payload, *sigp;
    size_t hdr_len, payload_len;
    char *hdr_txt = NULL, *pay_txt = NULL;
    Json *hdr_j = NULL, *pay_j = NULL;
    const char *alg;

    if (jwt_split(jwt, &hdr, &hdr_len, &payload, &payload_len, &sigp) != 0) {
        oidc_eprintf("oidc_jwt_verify: malformed JWT (expected three "
                     "base64url segments)\n");
        return NULL;
    }
    hdr_txt = seg_decode(hdr, hdr_len);
    pay_txt = seg_decode(payload, payload_len);
    if (!hdr_txt || !pay_txt) {
        oidc_eprintf("oidc_jwt_verify: cannot base64url-decode JWT "
                     "segments\n");
        goto fail;
    }
    hdr_j = json_parse(hdr_txt);
    pay_j = json_parse(pay_txt);
    if (!hdr_j || !pay_j) {
        oidc_eprintf("oidc_jwt_verify: JWT header/payload is not valid "
                     "JSON\n");
        goto fail;
    }
    alg = json_get_str(hdr_j, "alg");
    if (!alg) {
        oidc_eprintf("oidc_jwt_verify: JWT header missing alg\n");
        goto fail;
    }
    if (strcmp(alg, "RS256") != 0) {
        oidc_eprintf("oidc_jwt_verify: unsupported alg \"%s\" "
                     "(RS256 only)\n", alg);
        goto fail;
    }
    if (!json_get_str(hdr_j, "kid")) {
        oidc_eprintf("oidc_jwt_verify: JWT header missing kid\n");
        goto fail;
    }
    free(hdr_txt);
    free(pay_txt);
    *sig = sigp;
    *hdr_out = hdr_j;
    return pay_j;
fail:
    free(hdr_txt);
    free(pay_txt);
    json_free(hdr_j);
    json_free(pay_j);
    return NULL;
}

/* exp/aud/iss claim validation (RFC 7519 / OIDC Core); 0 on success */
static int validate_claims(Json *pay_j, const char *aud, const char *iss)
{
    time_t now = time(NULL);
    Json *exp = json_get(pay_j, "exp");
    if (!exp || json_type(exp) != JSON_NUM) {
        oidc_eprintf("oidc_jwt_verify: id_token has no numeric exp\n");
        return -1;
    }
    /* 60s clock-skew tolerance: a client clock up to a minute fast
     * must not permanently fail login on a freshly-issued token */
    if (json_num(exp) <= (double)(now - 60)) {
        oidc_eprintf("oidc_jwt_verify: id_token expired\n");
        return -1;
    }
    {
        Json *nbf = json_get(pay_j, "nbf");
        if (nbf && json_type(nbf) == JSON_NUM &&
            json_num(nbf) > (double)(now + 60)) {
            oidc_eprintf("oidc_jwt_verify: id_token not yet valid (nbf)\n");
            return -1;
        }
    }
    if (!aud_matches(pay_j, aud)) {
        oidc_eprintf("oidc_jwt_verify: id_token aud does not include "
                     "\"%s\"\n", aud);
        return -1;
    }
    /* RFC 7519 4.1.3: when aud is an array, the token must carry azp
     * naming the authorized party — otherwise an id_token issued for
     * another client under the same issuer would pass the array check */
    {
        Json *audc = json_get(pay_j, "aud");
        if (audc && json_type(audc) == JSON_ARR) {
            const char *azp = json_get_str(pay_j, "azp");
            if (!azp || strcmp(azp, aud) != 0) {
                oidc_eprintf("oidc_jwt_verify: id_token azp \"%s\" != "
                             "\"%s\"\n", azp ? azp : "(missing)", aud);
                return -1;
            }
        }
    }
    {
        const char *tiss = json_get_str(pay_j, "iss");
        if (!tiss || strcmp(tiss, iss) != 0) {
            oidc_eprintf("oidc_jwt_verify: id_token iss \"%s\" != \"%s\"\n",
                         tiss ? tiss : "(missing)", iss);
            return -1;
        }
    }
    return 0;
}

/* fetch the issuer's JWKS: the discovery document pins the issuer and
 * names the jwks_uri; both are fetched fresh over verified TLS. Returns
 * the parsed JWKS JSON or NULL (reason on stderr). */
static Json *fetch_jwks(const char *iss)
{
    Json *disc = fetch_json(OIDC_AUTH_HOST, "/.well-known/openid-configuration",
                            "OIDC discovery document");
    Json *jwks = NULL;
    const char *dis_iss, *jwks_uri;
    char host[256] = {0};
    char path[1024] = {0};

    if (!disc)
        return NULL;
    dis_iss = json_get_str(disc, "issuer");
    if (!dis_iss || strcmp(dis_iss, iss) != 0) {
        oidc_eprintf("oidc_jwt_verify: discovery issuer \"%s\" != \"%s\"\n",
                     dis_iss ? dis_iss : "(missing)", iss);
        goto out;
    }
    jwks_uri = json_get_str(disc, "jwks_uri");
    if (!jwks_uri) {
        oidc_eprintf("oidc_jwt_verify: discovery document has no "
                     "jwks_uri\n");
        goto out;
    }
    if (split_https_url(jwks_uri, host, sizeof host, path, sizeof path) == 0) {
        oidc_eprintf("oidc_jwt_verify: invalid jwks_uri \"%s\"\n", jwks_uri);
        goto out;
    }
    jwks = fetch_json(host, path, "JWKS");
out:
    json_free(disc);
    return jwks;
}

/* pick the RSA/sig key whose kid matches the JWT header; NULL on
 * failure (reason on stderr) */
static EVP_PKEY *select_jwks_key(Json *jwks, const char *kid)
{
    Json *keys = json_get(jwks, "keys");
    int saw_kid = 0;
    if (!keys || json_type(keys) != JSON_ARR) {
        oidc_eprintf("oidc_jwt_verify: JWKS has no keys array\n");
        return NULL;
    }
    for (size_t i = 0; i < json_arr_len(keys); i++) {
        Json *k = json_arr_at(keys, i);
        const char *kkid = json_get_str(k, "kid");
        const char *use = json_get_str(k, "use");
        const char *kty = json_get_str(k, "kty");
        if (!kkid || strcmp(kkid, kid) != 0)
            continue;
        saw_kid = 1;
        if (!use || strcmp(use, "sig") != 0 ||
            !kty || strcmp(kty, "RSA") != 0)
            continue;
        EVP_PKEY *pkey = jwks_rsa_key(k);
        if (pkey)
            return pkey;
    }
    if (!saw_kid)
        oidc_eprintf("oidc_jwt_verify: JWKS has no key with kid \"%s\"\n",
                     kid);
    else
        oidc_eprintf("oidc_jwt_verify: no usable RSA/sig key with "
                     "kid \"%s\"\n", kid);
    return NULL;
}

/* verify the RS256 signature over the "header.payload" bytes
 * (RFC 7515 5.1); 0 on success */
static int verify_signature(const char *jwt, const char *sig, EVP_PKEY *pkey)
{
    size_t sig_len = 0;
    uint8_t *sig_raw = b64url_decode(sig, &sig_len);
    EVP_MD_CTX *mctx = NULL;
    int rc = -1;

    if (!sig_raw || sig_len == 0) {
        oidc_eprintf("oidc_jwt_verify: cannot decode JWT signature\n");
        goto out;
    }
    mctx = EVP_MD_CTX_new();
    if (!mctx) {
        oidc_eprintf("oidc_jwt_verify: out of memory creating verify "
                     "context\n");
        goto out;
    }
    if (EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey) != 1 ||
        EVP_DigestVerifyUpdate(mctx, jwt, (size_t)(sig - jwt) - 1) != 1 ||
        EVP_DigestVerifyFinal(mctx, sig_raw, sig_len) != 1) {
        oidc_eprintf("oidc_jwt_verify: signature verification failed\n");
        goto out;
    }
    rc = 0;
out:
    free(sig_raw);
    EVP_MD_CTX_free(mctx);
    return rc;
}

int oidc_jwt_verify(const char *jwt, const char *aud, const char *iss)
{
    const char *sig;
    Json *hdr_j = NULL;
    Json *pay_j = decode_jwt_parts(jwt, &sig, &hdr_j);
    Json *jwks = NULL;
    EVP_PKEY *pkey = NULL;
    int rc = -1;

    if (!pay_j)
        return -1;
    if (validate_claims(pay_j, aud, iss) != 0)
        goto out;
    jwks = fetch_jwks(iss);
    if (!jwks)
        goto out;
    pkey = select_jwks_key(jwks, json_get_str(hdr_j, "kid"));
    if (!pkey)
        goto out;
    if (verify_signature(jwt, sig, pkey) != 0)
        goto out;
    rc = 0;
out:
    json_free(hdr_j);
    json_free(pay_j);
    json_free(jwks);
    EVP_PKEY_free(pkey);
    return rc;
}
