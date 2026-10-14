/* SPDX-License-Identifier: GPL-2.0 */
/*
 * win_abi_layout.c — 打印 Windows 数据面 ABI 的尺寸与偏移，供 32/64 位比对。
 *
 * 驱动（64 位）与客户端（可能是 32 位）共用 src/common/iwan_win_abi.h，
 * 所以同一份结构体在两种目标下的布局必须逐字段一致。用法：
 *
 *   x86_64-w64-mingw32-gcc -std=c11 -I src/common tests/win_abi_layout.c -o /tmp/l64 && /tmp/l64 > a
 *   i686-w64-mingw32-gcc   -std=c11 -I src/common tests/win_abi_layout.c -o /tmp/l32 && /tmp/l32 > b
 *   diff a b        # 必须无输出
 *
 * 只依赖 iwan_win_abi.h 里的断言与这里的打印，不需要驱动、不需要联网。
 */
#include <stdio.h>
#include <stddef.h>

#include "iwan_win_abi.h"

#define P(s, f) printf("%-34s %-22s %3u\n", #s, #f, (unsigned)offsetof(IWAN_WIN_##s, f))
#define SZ(s)   printf("%-34s %-22s %3u\n", #s, "sizeof", (unsigned)sizeof(IWAN_WIN_##s))

int main(void)
{
	printf("%-34s %-22s %3s\n", "struct", "field", "off");

	P(TARGET, family);
	P(TARGET, prefix_len);
	P(TARGET, addr);
	SZ(TARGET);

	P(SESSION_OPEN, abi_version);
	P(SESSION_OPEN, size);
	P(SESSION_OPEN, sid);
	P(SESSION_OPEN, tok);
	P(SESSION_OPEN, enc);
	P(SESSION_OPEN, key);
	P(SESSION_OPEN, outer_src);
	P(SESSION_OPEN, outer_dst);
	P(SESSION_OPEN, sport);
	P(SESSION_OPEN, dport);
	P(SESSION_OPEN, outer_src6);
	P(SESSION_OPEN, outer_dst6);
	P(SESSION_OPEN, flags);
	P(SESSION_OPEN, oif_index);
	P(SESSION_OPEN, bind_ip);
	P(SESSION_OPEN, bind_ip6);
	P(SESSION_OPEN, inner_ip);
	P(SESSION_OPEN, inner_ip6);
	P(SESSION_OPEN, inner_mtu);
	P(SESSION_OPEN, carrier_mtu);
	P(SESSION_OPEN, target_offset);
	P(SESSION_OPEN, target_count);
	SZ(SESSION_OPEN);

	P(SESSION_INFO, abi_version);
	P(SESSION_INFO, size);
	P(SESSION_INFO, sid);
	P(SESSION_INFO, peer_state);
	P(SESSION_INFO, enabled);
	P(SESSION_INFO, effective_mtu);
	P(SESSION_INFO, carrier_index);
	P(SESSION_INFO, dev_owned);
	P(SESSION_INFO, last_rx_ms);
	P(SESSION_INFO, shm_section_size);
	P(SESSION_INFO, shm_user_va);
	P(SESSION_INFO, stats);
	SZ(SESSION_INFO);

	P(STATS, rx_pkts);
	P(STATS, ev_dropped);
	SZ(STATS);

	P(SHM, version);
	P(SHM, last_rx_ms);
	P(SHM, peer_state);
	P(SHM, enabled);
	P(SHM, rx_frames);
	P(SHM, rx_ctrl_frame);
	SZ(SHM);

	printf("sizeof(void*)                     %3u\n", (unsigned)sizeof(void *));
	return 0;
}
