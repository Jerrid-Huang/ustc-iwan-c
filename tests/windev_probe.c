/* SPDX-License-Identifier: GPL-2.0 */
/*
 * windev_probe.c - build and error-path checks for the Windows device layer (src/common/windev.c).
 *
 * What it checks: on a machine without the driver, the device layer must return a distinguishable
 * error code (WINDEV_ENODEV), so auto plane selection can correctly fall back to the TUN plane
 * instead of conflating "driver not installed" with "bad parameter". On a machine with the driver
 * it should open the device, and querying a session before one exists must fail cleanly, not crash.
 *
 * How to run locally (no Windows, no driver):
 *   x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -Isrc/common \
 *       tests/windev_probe.c src/common/windev.c -o /tmp/windev_probe.exe
 *   wine /tmp/windev_probe.exe
 */
#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)

int main(void)
{
	printf("windev_probe: skipped (non-Windows target)\n");
	return 0;
}

#else

#include "windev.h"

int main(void)
{
	char err[512];
	windev_t *d = NULL;
	IWAN_WIN_SESSION_INFO info;
	int rc, fails = 0;

	memset(err, 0, sizeof(err));

	/* 1. Probe: just report the result; both outcomes are valid */
	printf("windev_probe: driver present? %s\n",
	       windev_present(err, sizeof(err)) ? "yes" : "no");
	if (err[0] != '\0')
		printf("  probe detail: %s\n", err);

	/* 2. Open the device */
	err[0] = '\0';
	rc = windev_open(&d, err, sizeof(err));
	if (rc != WINDEV_OK) {
		/* Driver missing or permission denied are both acceptable; other error codes mean misclassification */
		if (rc != WINDEV_ENODEV && rc != WINDEV_EACCES) {
			printf("FAIL opening device returned unexpected error code %d: %s\n", rc, err);
			fails++;
		} else {
			printf("  open device: %s (distinguishable error as expected)\n", err);
		}
	} else {
		/* 3. Driver installed: session query must fail cleanly before a session exists */
		err[0] = '\0';
		rc = windev_session_get(d, &info, err, sizeof(err));
		if (rc == WINDEV_OK) {
			printf("FAIL got session info before any session was created (sid=%u)\n",
			       (unsigned)info.sid);
			fails++;
		} else {
			printf("  session query before creation: clean failure (rc=%d)\n", rc);
		}

		/* 4. Shared memory: must also fail cleanly when there is no session */
		{
			const IWAN_WIN_SHM *shm = NULL;

			err[0] = '\0';
			rc = windev_shm_map(d, &shm, err, sizeof(err));
			if (rc == WINDEV_OK) {
				printf("FAIL obtained shared-memory mapping with no session\n");
				fails++;
			} else {
				printf("  shared-memory map before session creation: clean failure (rc=%d)\n", rc);
			}
		}
		windev_close(d);
	}

	printf("windev_probe: %s (%d failures)\n", fails == 0 ? "PASS" : "FAIL", fails);
	return fails == 0 ? 0 : 1;
}

#endif
