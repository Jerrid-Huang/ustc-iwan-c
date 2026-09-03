#ifndef IWAN_OIDC_PWSECRET_H
#define IWAN_OIDC_PWSECRET_H

/* At-rest protection for the per-line passwords in servers.json.
 * The stored value is the PLAINTEXT password (by decision: the former
 * app-secret GCM layer was obfuscation only — the binary is public, so
 * it protected nothing). The at-rest protection is the OS facility
 * alone: on Windows the password is sealed with DPAPI (CurrentUser +
 * machine) before landing on disk; on macOS it lives in the login
 * Keychain (servers.json keeps only a marker); on Linux the file is
 * plaintext with 0600 permissions (load_config warns on group/world
 * readable). The connect path additionally GCM-decrypts LEGACY
 * ciphertext-format files (see stored_password in oidc_connect.c). */

/* Wrap the plaintext password for storage. Returns a malloc'd
 * marker-prefixed string on platforms with at-rest protection, or a
 * copy of the input elsewhere. domain/user tag the protection
 * (Keychain account) and are needed to unwrap. */
char *oidc_wrap_password(const char *blob, const char *domain,
                         const char *user);

/* Reverse of wrap: returns the plaintext password (malloc'd) or NULL
 * when the platform protection is unrecoverable (e.g. Keychain item
 * missing). Legacy inputs without a marker are returned verbatim. */
char *oidc_unwrap_password(const char *stored, const char *domain,
                           const char *user);

#endif
