#ifndef IWAN_OIDC_PWSECRET_H
#define IWAN_OIDC_PWSECRET_H

/* At-rest protection for the per-line password blobs in servers.json
 * (audit M8). The controller-issued blob is AES-GCM under a hardcoded
 * app secret — obfuscation only (strings-able). On Windows the blob is
 * additionally sealed with DPAPI (CurrentUser) before landing on disk;
 * on macOS it is moved into the login Keychain; elsewhere the legacy
 * form is kept (and the help text labels it obfuscation-level). */

/* Wrap a plaintext password blob for storage. Returns a malloc'd
 * marker-prefixed string on platforms with at-rest protection, or a
 * copy of the input elsewhere. domain/user tag the protection (DPAPI
 * entropy / Keychain account) and are needed to unwrap. */
char *oidc_wrap_password(const char *blob, const char *domain,
                         const char *user);

/* Reverse of wrap: returns the plaintext blob (malloc'd) or NULL when
 * the platform protection is unrecoverable (e.g. Keychain item
 * missing). Legacy inputs without a marker are returned verbatim. */
char *oidc_unwrap_password(const char *stored, const char *domain,
                           const char *user);

#endif
