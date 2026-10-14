/* SPDX-License-Identifier: GPL-2.0 */
/*
 * windev_probe.c — Windows 设备层（src/common/windev.c）的编译与错误路径检查。
 *
 * 能验什么：设备层在"没有驱动"的机器上必须给出可分辨的错误码
 * （WINDEV_ENODEV），这样 auto 选面才能正确地回退到 TUN 面，而不是把
 * "驱动没装"混成"参数错误"。装了驱动的机器上则应当能打开设备，且未建会话
 * 时查会话必须是干净失败而不是崩溃。
 *
 * 本机跑法（无 Windows、无驱动）：
 *   x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -Isrc/common \
 *       tests/windev_probe.c src/common/windev.c -o /tmp/windev_probe.exe
 *   wine /tmp/windev_probe.exe
 */
#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)

int main(void)
{
	printf("windev_probe: 跳过（非 Windows 目标）\n");
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

	/* 1. 探测：只报告结果，两种结果都合法 */
	printf("windev_probe: 驱动在位？%s\n",
	       windev_present(err, sizeof(err)) ? "是" : "否");
	if (err[0] != '\0')
		printf("  探测说明: %s\n", err);

	/* 2. 打开设备 */
	err[0] = '\0';
	rc = windev_open(&d, err, sizeof(err));
	if (rc != WINDEV_OK) {
		/* 没装驱动或权限不足都是可接受的结果；其它错误码说明分类错了 */
		if (rc != WINDEV_ENODEV && rc != WINDEV_EACCES) {
			printf("FAIL 打开设备返回了意外错误码 %d: %s\n", rc, err);
			fails++;
		} else {
			printf("  打开设备: %s（预期内的可分辨错误）\n", err);
		}
	} else {
		/* 3. 装了驱动：未建会话时查会话必须是干净失败 */
		err[0] = '\0';
		rc = windev_session_get(d, &info, err, sizeof(err));
		if (rc == WINDEV_OK) {
			printf("FAIL 未建会话却查到了会话信息（sid=%u）\n",
			       (unsigned)info.sid);
			fails++;
		} else {
			printf("  未建会话时查会话: 干净失败（rc=%d）\n", rc);
		}

		/* 4. 共享内存：没有会话时也必须干净失败 */
		{
			const IWAN_WIN_SHM *shm = NULL;

			err[0] = '\0';
			rc = windev_shm_map(d, &shm, err, sizeof(err));
			if (rc == WINDEV_OK) {
				printf("FAIL 没有会话却拿到了共享内存映射\n");
				fails++;
			} else {
				printf("  未建会话时映射共享内存: 干净失败（rc=%d）\n", rc);
			}
		}
		windev_close(d);
	}

	printf("windev_probe: %s（失败 %d 项）\n", fails == 0 ? "通过" : "不通过", fails);
	return fails == 0 ? 0 : 1;
}

#endif
