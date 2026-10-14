/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 同一翻译单元里重复包含 iwan_win_abi.h：包含卫士必须挡住第二次定义。
 *
 * 这个用例来自一次真实事故。给共享页加诊断区时，我把新块"追加到文件末尾"，
 * 而文件末行恰好是那个收尾的 `#endif`（后面跟一行注释 IWAN_WIN_ABI_H）——
 * 新块落在卫士之外，于是
 * 任何一个间接包含两次该头的翻译单元都会重新定义 IWAN_WIN_DIAG：
 *
 *   iwan_win_abi.h(342,16): error C2011: '_IWAN_WIN_DIAG': 'struct' type redefinition
 *   iwan_win_abi.h(352,1): error C2338: static_assert failed: 'IWAN_WIN_DIAG 大小'
 *
 * 第二个报错是假象：类型重定义之后 static_assert 的求值已不可信。
 * 用例本身的判据很窄也很硬——"重复包含不产生诊断"，不需要知道任何布局。
 */
#include "iwan_win_abi.h"
#include "iwan_win_abi.h"

int main(void)
{
	/* 顺带固定住诊断区的对外承诺：40 字节，且完全落在共享页内。 */
	if (sizeof(IWAN_WIN_DIAG) != 40)
		return 1;
	if (IWAN_WIN_SHM_OFF_DIAG + sizeof(IWAN_WIN_DIAG) > 4096)
		return 2;

	return 0;
}
