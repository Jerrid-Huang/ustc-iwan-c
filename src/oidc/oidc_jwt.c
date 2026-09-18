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


/* GET host+path, parse the JSON body; NULL on any failure (reported) */
static Json *fetch_json(const char *host, const char *path, const char *what)
{
    int st = 0;
    char *body = NULL;
    Json *j;

    if (!https_get(host, path, &st, &body)) {
        /* R37-WG-G (L28): the response body is remote controlled — the
         * terminal copy is neutralized. The raw `body` buffer is still
         * the one freed here and parsed below: no verdict depends on
         * the sanitized string. */
        char *body_s = oidc_printable_dup(body && *body ? body
                                                        : "no response");
        oidc_eprintf("oidc_jwt_verify: cannot fetch %s (HTTP %d): %s\n",
                     what, st, body_s);
        free(body_s);
        free(body);
        return NULL;
    }
    if (st != 200) {
        /* L28: same as above, non-200 branch */
        char *body_s = oidc_printable_dup(body && *body ? body : "no body");
        oidc_eprintf("oidc_jwt_verify: %s returned HTTP %d: %s\n", what, st,
                     body_s);
        free(body_s);
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
#define JWKS_RSA_MIN_BITS 2048
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
    /* R54-WG4-6: strength floor on the RSA signing key BEFORE it is
     * accepted (defense in depth). A token that passes RS256 is enough
     * to authenticate as the user; a weak n (factorable) or a broken e
     * (e=1/2/even: fixed-point or degenerate verification) would let a
     * forger mint id_tokens. The issuer is the configured trust root,
     * so this guards the "IdP key compromised / mis-issued" case — the
     * client fails closed rather than verify with a weak key. Rejecting
     * the key only SKIPS it (select_jwks_key moves on; other keys are
     * still usable, and if none is left the verify fails closed). */
    if (pkey) {
        const BIGNUM *ke = NULL;
        int bits = EVP_PKEY_get_bits(pkey);
        int bad_bits, bad_e;

        RSA_get0_key(rsa, NULL, &ke, NULL);
        bad_bits = bits < JWKS_RSA_MIN_BITS;
        bad_e = !ke || BN_cmp(ke, BN_value_one()) <= 0 || !BN_is_odd(ke);
        if (bad_bits || bad_e) {
            /* only small local integers are printed — the kid is left
             * to the caller's filtered diagnostic */
            oidc_eprintf("oidc_jwt_verify: refusing weak JWKS RSA key: "
                         "%d-bit modulus (min %d)%s, exponent=%d bits%s\n",
                         bits, JWKS_RSA_MIN_BITS,
                         bad_bits ? " [below floor]" : "",
                         ke ? BN_num_bits(ke) : -1,
                         bad_e ? " [e<=1 or even]" : "");
            EVP_PKEY_free(pkey);   /* strength check failed: skip this key */
            pkey = NULL;
        }
    }
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
        /* R37-WG-G (L28): header alg is attacker supplied. The accept
         * decision above is a strcmp() on the RAW value; only the copy
         * handed to the terminal is filtered. */
        char *alg_s = oidc_printable_dup(alg);
        oidc_eprintf("oidc_jwt_verify: unsupported alg \"%s\" "
                     "(RS256 only)\n", alg_s);
        free(alg_s);
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

/* exp/aud/iss claim validation (RFC 7519 / OIDC Core); 0 on success.
 * expected_nonce (NULL = no nonce check): the OIDC `nonce` sent in the
 * authorization request — OIDC Core 3.1.3.7 requires the id_token to
 * echo it back, which binds the token to the client session (RFC 8252
 * 6.3 for native apps). Absent or mismatched -> reject (fail closed). */
static int validate_claims(Json *pay_j, const char *aud, const char *iss,
                           const char *expected_nonce)
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
    {
        /* issued-at must not be in the future (same 60s skew window as
         * nbf): a future iat means either a forged token or a badly
         * skewed clock, both of which should fail closed */
        Json *iat = json_get(pay_j, "iat");
        if (iat && json_type(iat) == JSON_NUM &&
            json_num(iat) > (double)(now + 60)) {
            oidc_eprintf("oidc_jwt_verify: id_token issued in the future "
                         "(iat)\n");
            return -1;
        }
    }
    if (!aud_matches(pay_j, aud)) {
        /* aud is the caller's local OIDC_CLIENT_ID constant (oidc_flow.c
         * passes the literal), so it is deliberately NOT filtered. */
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
                /* R37-WG-G (L28): azp is issuer controlled; the strcmp()
                 * above still compares the raw claim, only the printed
                 * copy is filtered. `aud` is a local constant. */
                char *azp_s = oidc_printable_dup(azp ? azp : "(missing)");
                oidc_eprintf("oidc_jwt_verify: id_token azp \"%s\" != "
                             "\"%s\"\n", azp_s, aud);
                free(azp_s);
                return -1;
            }
        }
    }
    {
        const char *tiss = json_get_str(pay_j, "iss");
        if (!tiss || strcmp(tiss, iss) != 0) {
            /* R37-WG-G (L28): the claim is issuer controlled, the
             * expected `iss` is the caller's local "https://auth…"
             * literal. Comparison stays on the raw strings. */
            char *tiss_s = oidc_printable_dup(tiss ? tiss : "(missing)");
            oidc_eprintf("oidc_jwt_verify: id_token iss \"%s\" != \"%s\"\n",
                         tiss_s, iss);
            free(tiss_s);
            return -1;
        }
    }
    /* R49-L3: OIDC Core 3.1.3.7 — when the authorization request carried
     * a nonce (this client always does), the id_token MUST echo it back;
     * a missing or mismatched nonce means the token was minted for a
     * different client session (token/session binding). Fail closed.
     * Local, fixed-length strings; constant-time compare like the other
     * sensitive comparisons here (ct_eq returns non-zero on a MATCH). The
     * claim value is issuer-controlled text, but only the diagnostic
     * copy is filtered — the verdict uses the raw bytes. */
    if (expected_nonce) {
        const char *tnonce = json_get_str(pay_j, "nonce");
        if (!tnonce || strlen(tnonce) != strlen(expected_nonce) ||
            ct_eq(tnonce, expected_nonce, strlen(expected_nonce)) == 0) {
            oidc_eprintf("oidc_jwt_verify: id_token nonce does not match "
                         "the nonce sent in the authorization request "
                         "(OIDC Core 3.1.3.7)\n");
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
    char *jhost = NULL, *jpath = NULL;

    if (!disc)
        return NULL;
    dis_iss = json_get_str(disc, "issuer");
    if (!dis_iss || strcmp(dis_iss, iss) != 0) {
        /* R37-WG-G (L28): discovery fields are remote controlled (the
         * document is fetched over TLS from the issuer host but its
         * contents are still attacker-influenced text). The pinning
         * strcmp() above uses the raw claim. */
        char *dis_iss_s = oidc_printable_dup(dis_iss ? dis_iss
                                                     : "(missing)");
        oidc_eprintf("oidc_jwt_verify: discovery issuer \"%s\" != \"%s\"\n",
                     dis_iss_s, iss);
        free(dis_iss_s);
        goto out;
    }
    jwks_uri = json_get_str(disc, "jwks_uri");
    if (!jwks_uri) {
        oidc_eprintf("oidc_jwt_verify: discovery document has no "
                     "jwks_uri\n");
        goto out;
    }
    if (!https_url_split(jwks_uri, &jhost, &jpath)) {
        /* L28: display only — the rejected URL is parsed as-is above */
        char *uri_s = oidc_printable_dup(jwks_uri);
        oidc_eprintf("oidc_jwt_verify: invalid jwks_uri \"%s\"\n", uri_s);
        free(uri_s);
        goto out;
    }
    jwks = fetch_json(jhost, jpath, "JWKS");
out:
    free(jhost);
    free(jpath);
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
    if (!saw_kid) {
        /* R37-WG-G (L28): `kid` comes from the JWT header, the JWKS is
         * remote. The key hunt above (strcmp against kkid) used the raw
         * kid; only these two diagnostics are filtered. */
        char *kid_s = oidc_printable_dup(kid ? kid : "(missing)");
        oidc_eprintf("oidc_jwt_verify: JWKS has no key with kid \"%s\"\n",
                     kid_s);
        free(kid_s);
    } else {
        char *kid_s = oidc_printable_dup(kid ? kid : "(missing)");
        oidc_eprintf("oidc_jwt_verify: no usable RSA/sig key with "
                     "kid \"%s\"\n", kid_s);
        free(kid_s);
    }
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

int oidc_jwt_verify(const char *jwt, const char *aud, const char *iss,
                    const char *expected_nonce)
{
    const char *sig;
    Json *hdr_j = NULL;
    Json *pay_j = decode_jwt_parts(jwt, &sig, &hdr_j);
    Json *jwks = NULL;
    EVP_PKEY *pkey = NULL;
    int rc = -1;

    if (!pay_j)
        return -1;
    if (validate_claims(pay_j, aud, iss, expected_nonce) != 0)
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
