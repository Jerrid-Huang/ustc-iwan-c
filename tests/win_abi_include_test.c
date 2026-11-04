/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Including iwan_win_abi.h twice in the same translation unit: the include guard must block the second definition.
 *
 * This case comes from a real incident: when adding a diagnostic area to the shared
 * page I "appended the new block to the end of the file", and the last line happened
 * to be the closing #endif (followed by a comment IWAN_WIN_ABI_H) -- so the new block
 * landed outside the guard, so any TU indirectly including the header twice redefined IWAN_WIN_DIAG:
 *
 *   iwan_win_abi.h(342,16): error C2011: '_IWAN_WIN_DIAG': 'struct' type redefinition
 *   iwan_win_abi.h(352,1): error C2338: static_assert failed: 'IWAN_WIN_DIAG size'
 *
 * The second error is an artifact: after the type redefinition, evaluating
 * static_assert is unreliable. The criterion is narrow and strict -- "duplicate inclusion produces no diagnostics" -- and needs no layout knowledge.
 */
#include "iwan_win_abi.h"
#include "iwan_win_abi.h"

int main(void)
{
	/* Also pin the diagnostic area's external contract: 40 bytes, fully inside the shared page. */
	if (sizeof(IWAN_WIN_DIAG) != 40)
		return 1;
	if (IWAN_WIN_SHM_OFF_DIAG + sizeof(IWAN_WIN_DIAG) > 4096)
		return 2;

	return 0;
}
