/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_shm.h — /dev/iwan 共享内存页的 ABI（v1，冻结）。
 *
 * 一片内存 = 一页（PAGE_SIZE），**每个 netns 一份**。内核写、用户态只读：
 * 用户态 mmap() 之后按下面的固定偏移读字段，不需要任何系统调用就能轮询
 * "对端还活着吗"。
 *
 * 约定（与 kernel/iwan_genl.h 的字节序约定一致）：
 *   · 所有字段**主机序** —— 这一页只在本机内共享，不经网络；
 *   · last_rx_ms 的时基与 netlink 的 IWAN_A_LAST_KEEPALIVE_MS **完全相同**
 *     （iwan_now_ms()：ktime_get_mono_fast_ns() 折算的单调毫秒），而且两者
 *     是**同一个存储**（struct iwan_session 里不再另存一份，见 iwan.h 的
 *     访问器与 iwan_netlink.c 的 GET_STATS）；
 *   · 0 表示"从未收到 / 已断开"：收到 PT_CLOSE(0x17) 时 last_rx_ms 立即置 0，
 *     用户态见到 0 即可判定断线并退出；
 *   · 内核只在收到**通过凭据闸门**的帧时写它；用户态从不写（open() 拒绝写
 *     方式打开、mmap() 拒绝 PROT_WRITE）。
 *
 * 页面布局（偏移 + 大小，全部相对于映射起始地址）：
 *
 *   0x00 u32 version        布局版本 = IWAN_SHM_VERSION
 *   0x04 u32 pad            对齐填充，恒 0
 *   0x08 u64 last_rx_ms     最近一次有效帧的单调毫秒；0 = 无/已断开
 *   0x10 u32 peer_state     enum iwan_peer_state（iwan_genl.h）复用于此
 *   0x14 u32 enabled        会话级数据面开关（见 CONTROL-PLANE.md §11）
 *   0x18 u64 rx_frames      数据帧计数（pn->st.rx_frames 的镜像快照）
 *   0x20 u64 rx_ctrl_frame  控制帧计数（pn->st.rx_ctrl_frame 的镜像快照）
 *   0x28 .. PAGE_SIZE-1     保留，恒 0（写者只写上面这几个字段）
 *
 * 端点：misc 设备，devtmpfs 自动建出 /dev/iwan；mmap 只允许偏移 0、长度
 * 不超过一页。本文件只用 <linux/types.h>，内核与用户态都可以直接 include。
 */
#ifndef IWAN_SHM_H
#define IWAN_SHM_H

#include <linux/types.h>

/* 布局版本：字段增删必须 +1，并同步 kernel/iwan_shm.c 的偏移断言与用户态 */
#define IWAN_SHM_VERSION	1

/* 设备名（misc_register → /dev/iwan） */
#define IWAN_SHM_DEV_NAME	"iwan"

/* 固定偏移：用户态按这些值读，不依赖结构体布局 */
#define IWAN_SHM_OFF_VERSION		0x00
#define IWAN_SHM_OFF_PAD		0x04
#define IWAN_SHM_OFF_LAST_RX_MS		0x08
#define IWAN_SHM_OFF_PEER_STATE		0x10
#define IWAN_SHM_OFF_ENABLED		0x14
#define IWAN_SHM_OFF_RX_FRAMES		0x18
#define IWAN_SHM_OFF_RX_CTRL_FRAME	0x20

/* 有定义的头部长度；0x28 之后到页尾是保留区（必须为 0） */
#define IWAN_SHM_HDR_SIZE		0x28

/*
 * 页面头部。只覆盖有定义的 0x28 字节，**不**声明到页尾：
 * 页面大小是 PAGE_SIZE，用户态 mmap 得到的是整页，保留区不在结构体里。
 * 内核侧 iwan_shm.c 用 static_assert 把每个 offsetof 钉在 IWAN_SHM_OFF_* 上。
 */
struct iwan_shm {
	__u32	version;	/* IWAN_SHM_VERSION */
	__u32	pad;		/* 恒 0 */
	__u64	last_rx_ms;	/* 单调毫秒；0 = 从未收到 / 已断开 */
	__u32	peer_state;	/* enum iwan_peer_state */
	__u32	enabled;	/* 会话级数据面开关：1 = 已启用 */
	__u64	rx_frames;	/* 数据帧计数（会话级视图） */
	__u64	rx_ctrl_frame;	/* 控制帧计数（会话级视图） */
};

#endif /* IWAN_SHM_H */
