#ifndef IWAN_WINTUN_FETCH_H
#define IWAN_WINTUN_FETCH_H

/* Windows only: make sure wintun.dll sits next to the executable.
 * Missing + interactive stdin -> ask once, then fetch the latest build
 * from wintun.net and extract the arch-matching DLL. Missing +
 * non-interactive stdin -> print the manual recipe and fail. */
#ifdef _WIN32
int wintun_ensure(void);
#endif

#endif /* IWAN_WINTUN_FETCH_H */
