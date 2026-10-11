/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_abi.h — Windows 内核数据面（WFP callout）与用户态客户端之间的 ABI。
 *
 * 设计对应关系（详见 docs/win-wfp-data-plane.md）：
 *   · 会话模型逐项对应 Linux 侧 genetlink 的属性集（kernel/iwan_genl.h）：
 *     外层端点、内层 MTU、加密标志与密钥、绑定（出口网卡/出口 IP）、
 *     会话 id/令牌、开关位、统计计数器；
 *   · 存活状态对应 /dev/iwan 那一页只读共享内存（kernel/iwan_shm.h）：
 *     布局版本、固定偏移、0 = 从未收到/已断开，语义完全一致；
 *   · Windows 多出来的三项是平台差异，不是语义差异：
 *     内层地址（回环适配器上要挂哪个地址）、被代理目标集合（WFP 出向按它
 *     匹配，用来替代 Linux 的"路由到 iwan0"）、流上下文开关（WFP 自带
 *     连接跟踪，用来替代 Linux 的 conntrack + fwmark 策略路由）。
 *
 * 约定：
 *   · 所有字段主机序；只有外层地址/端口按网络序解释（与 Linux 侧一致）；
 *   · 结构体只显式补齐到固定布局，偏移由本文件末尾的断言钉死；
 *   · 版本号只在字段增删时 +1，且必须同步驱动、客户端与本文件的断言。
 *
 * 本文件不依赖 WDK 专有头：内核态包含 ntddk.h/wdm.h，用户态包含
 * windows.h/winioctl.h，两边都能直接 include。
 */
#ifndef IWAN_WIN_ABI_H
#define IWAN_WIN_ABI_H

#if defined(_KERNEL_MODE)
#  include <ntddk.h>
#  include <wdm.h>          /* CTL_CODE */
/*
 * 内核态没有 C99 定长类型：WDK 的内核包含路径里没有 <stdint.h>，wdm.h 只提供
 * INT8..UINT64 这组 WDK 名字。本文件通篇用 C99 名字（用户态那两侧本来就有
 * <stdint.h>），所以在这里补一层等宽别名，而不是把上百处字段类型改成 WDK 名字
 * 再分两套维护 —— ABI 结构体的字段类型在三个编译目标里必须是同一份声明。
 *
 * C11 允许把 typedef 重定义成同一类型（6.7/3），MSVC 在 /std:c11 下同样接受，
 * 所以将来某个 WDK 若自己提供了这些名字，只要宽度相同也不会冲突。
 */
typedef signed char        int8_t;
typedef unsigned char      uint8_t;
typedef short              int16_t;
typedef unsigned short     uint16_t;
typedef int                int32_t;
typedef unsigned int       uint32_t;
typedef long long          int64_t;
typedef unsigned long long uint64_t;

/*
 * 同理没有 offsetof：它是 <stddef.h> 的宏，内核包含路径里没有这个头。
 * 用编译器内建的那套写法自己给一个；C11 允许同一宏重定义为相同展开，
 * 所以万一将来某个 WDK 提供了它也不会冲突。size_t 由 WDK 自己提供。
 */
#  ifndef offsetof
#    define offsetof(type, member) ((size_t)(ULONG_PTR)&(((type *)0)->member))
#  endif
#elif defined(IWAN_WIN_ABI_BARE)
/* 裸模式：主机侧对拍测试（tests/win_frame_test.c）只要结构与常量，
 * 不引入 windows.h，这样同一份 ABI 能在 Linux 上编译检查。 */
#  include <stdint.h>
#  include <stddef.h>
#else
#  include <windows.h>
#  include <winioctl.h>     /* CTL_CODE */
#  include <stdint.h>
#endif

/* ---- 版本 ------------------------------------------------------------- */

/* 设备与 IOCTL 的 ABI 版本：驱动与客户端不一致时拒绝开会话 */
#define IWAN_WIN_ABI_VERSION      1u

/* 存活共享内存页的布局版本：与 Linux 的 IWAN_SHM_VERSION 同步（同一套
 * 用户态读取代码吃两边的页，所以版本号必须一起动） */
#define IWAN_WIN_SHM_VERSION      1u

/* ---- 设备名（裸模式不需要） ------------------------------------------- */

#if !defined(IWAN_WIN_ABI_BARE)

#define IWAN_WIN_DEVICE_NAME      L"\\Device\\iwan"
#define IWAN_WIN_DOS_NAME         L"\\DosDevices\\iwan"
#define IWAN_WIN_USER_PATH        L"\\\\.\\iwan"
/* 只读映射给用户态的命名节对象（对应 Linux 的 /dev/iwan mmap） */
#define IWAN_WIN_SHM_NAME         L"\\BaseNamedObjects\\iwan_shm"

/* ---- IOCTL ------------------------------------------------------------ */

#define IWAN_WIN_DEVICE_TYPE      0x8331u   /* 自定义，避开系统设备类型 */

#define IOCTL_IWAN_SESSION_OPEN \
	CTL_CODE(IWAN_WIN_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_IWAN_SESSION_CLOSE \
	CTL_CODE(IWAN_WIN_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_IWAN_SESSION_GET \
	CTL_CODE(IWAN_WIN_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_IWAN_SHM_QUERY \
	CTL_CODE(IWAN_WIN_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA)

#endif /* !IWAN_WIN_ABI_BARE */

/* ---- 会话开关位（对应 IWAN_A_FLAG_*） --------------------------------- */

/* 把内层地址挂到回环适配器上（Linux 侧对应"创建 iwan0"，默认置位）。
 * 不置位时驱动只做转发，不碰本机地址表。 */
#define IWAN_WIN_FLAG_BIND_INNER      0x0001u
/* 为入向连接建立流上下文，使其回包按来路回去（Linux 侧对应 conntrack +
 * fwmark 策略路由那一整套；Windows 用 WFP 原生流上下文，默认置位） */
#define IWAN_WIN_FLAG_REPLY_VIA_TUNNEL 0x0002u
/* 显式绑定了外层出口网卡（oi f_index 有效），对应 IWAN_A_OIF */
#define IWAN_WIN_FLAG_BIND_OIF        0x0004u
/* 显式绑定了外层出口 IP（bind_ip / bind_ip6 有效），对应 IWAN_A_IP* */
#define IWAN_WIN_FLAG_BIND_IP         0x0008u

/* ---- 对端状态（对应 enum iwan_peer_state） ---------------------------- */

enum iwan_win_peer_state {
	IWAN_WIN_PEER_UNKNOWN = 0,
	IWAN_WIN_PEER_UP,	/* 收过有效帧 */
	IWAN_WIN_PEER_SILENT,	/* 保留编号：驱动无定时器，判活由用户态轮询 */
	IWAN_WIN_PEER_CLOSED,	/* 收到 PT_CLOSE */
};

/* ---- 目标集合条目（被代理目标；WFP 出向按它做最长前缀匹配） ----------- */

#define IWAN_WIN_AF_V4            4u
#define IWAN_WIN_AF_V6            6u

/* 目标集合条目上限：客户端与驱动共用同一个界，超出时开会话必须明确失败，
 * 避免用户态把内核池吃光（Linux 侧的等价边界在用户态展开 --proxy-cidr 时）。 */
#define IWAN_WIN_MAX_TARGETS      4096u

typedef struct _IWAN_WIN_TARGET {
	uint32_t family;	/* IWAN_WIN_AF_V4 / IWAN_WIN_AF_V6 */
	uint32_t prefix_len;	/* v4: 0..32，v6: 0..128 */
	uint8_t  addr[16];	/* 网络序；v4 用前 4 字节，其余为 0 */
} IWAN_WIN_TARGET, *PIWAN_WIN_TARGET;

/* ---- 开会话请求 ------------------------------------------------------- */

/*
 * 变长：targets 紧跟在结构体之后（同一块 IOCTL 缓冲），共 target_count 项，
 * 每项 IWAN_WIN_TARGET。target_offset 是相对本结构体起始的偏移，正常情况下
 * 等于 sizeof(IWAN_WIN_SESSION_OPEN)；留出这个字段是为了将来在前面追加字段
 * 时不破坏旧客户端。
 */
typedef struct _IWAN_WIN_SESSION_OPEN {
	uint32_t abi_version;	/* IWAN_WIN_ABI_VERSION */
	uint32_t size;		/* 本结构体大小，用于版本兼容判断 */

	/* 会话标识与控制面参数（对应 SID/TOK/ENC/KEY） */
	uint16_t sid;
	uint16_t reserved0;
	uint32_t tok;
	uint8_t  enc;		/* 1 = PT_DATA_ENC + XOR，0 = 明文 */
	uint8_t  key[8];	/* MD5(user||pass)[0..8) */

	/* 外层端点（主机序字段 + 网络序地址/端口，与 Linux 侧一致） */
	uint32_t outer_src;	/* be32 */
	uint32_t outer_dst;	/* be32 */
	uint16_t sport;		/* be16；0 表示与 dport 相同 */
	uint16_t dport;		/* be16 */
	uint8_t  outer_src6[16];/* 外层 v6 源；与 outer_dst6 同时非零才按 v6 处理 */
	uint8_t  outer_dst6[16];/* 外层 v6 目的 */

	/* 绑定（对应 IWAN_A_OIF / IWAN_A_IP / IWAN_A_IP6） */
	uint32_t flags;		/* IWAN_WIN_FLAG_* */
	uint32_t oif_index;	/* 承载网卡 ifindex（BIND_OIF） */
	uint32_t bind_ip;	/* be32，本端外层出口 IP（BIND_IP） */
	uint8_t  bind_ip6[16];	/* 本端外层出口 v6 */

	/* 内层（Windows 特有：Linux 侧内层地址由模块建 iwan0 时自己挂） */
	uint32_t inner_ip;	/* be32，本机分配到的内层地址 */
	uint8_t  inner_ip6[16];	/* 内层 v6（ULA），无则全 0 */
	uint32_t inner_mtu;	/* 内层 MTU；0 = carrier_mtu - 封装开销 */
	uint32_t carrier_mtu;	/* 承载网卡 MTU：客户端查得后报上来，驱动按
				 * "inner_mtu + 开销 <= carrier_mtu" 校验 */

	/* 目标集合 */
	uint32_t target_offset;	/* 相对本结构体起始 */
	uint32_t target_count;
} IWAN_WIN_SESSION_OPEN, *PIWAN_WIN_SESSION_OPEN;

/* ---- 统计（计数器名称与顺序对应 enum iwan_stats_attr） ---------------- */

typedef struct _IWAN_WIN_STATS {
	uint64_t rx_pkts;
	uint64_t rx_outer;
	uint64_t rx_reasm;
	uint64_t rx_frames;
	uint64_t rx_delivered;
	uint64_t rx_batch;
	uint64_t rx_batch_skip;
	uint64_t rx_bad_hdr;
	uint64_t rx_bad_inner;
	uint64_t rx_nomem;
	uint64_t rx_ctrl_frame;
	uint64_t tx_pkts;
	uint64_t tx_bytes;
	uint64_t tx_bad_state;
	uint64_t tx_bad_inner;
	uint64_t tx_err;
	uint64_t ev_dropped;
} IWAN_WIN_STATS, *PIWAN_WIN_STATS;

/* ---- 查询会话（SESSION_GET / SHM_QUERY 的回复） ----------------------- */

typedef struct _IWAN_WIN_SESSION_INFO {
	uint32_t abi_version;
	uint32_t size;

	uint16_t sid;
	uint16_t reserved0;
	uint32_t peer_state;	/* enum iwan_win_peer_state */
	uint32_t enabled;	/* 会话级数据面开关 */
	uint32_t effective_mtu;	/* 生效的内层 MTU（会话建立时按承载网卡 MTU 校验过） */
	uint32_t carrier_index;	/* 实际承载网卡 ifindex（对应 IWAN_A_CARRIER） */
	uint32_t dev_owned;	/* 1 = 内层地址由本驱动挂上（对应 IWAN_A_DEV_OWNED） */
	uint32_t reserved1;

	uint64_t last_rx_ms;	/* 与共享内存页同一份存储（对应 IWAN_A_LAST_KEEPALIVE_MS） */
	uint64_t shm_section_size;	/* 共享内存页大小（SHM_QUERY 用） */
	uint64_t shm_user_va;	/* SHM_QUERY：映射到调用进程的只读地址；
				 * 只在调用 SHM_QUERY 的那个进程里有效 */

	IWAN_WIN_STATS stats;
} IWAN_WIN_SESSION_INFO, *PIWAN_WIN_SESSION_INFO;

/* ---- 存活共享内存页（布局与 kernel/iwan_shm.h 一致） ------------------ */

#define IWAN_WIN_SHM_OFF_VERSION        0x00
#define IWAN_WIN_SHM_OFF_PAD            0x04
#define IWAN_WIN_SHM_OFF_LAST_RX_MS     0x08
#define IWAN_WIN_SHM_OFF_PEER_STATE     0x10
#define IWAN_WIN_SHM_OFF_ENABLED        0x14
#define IWAN_WIN_SHM_OFF_RX_FRAMES      0x18
#define IWAN_WIN_SHM_OFF_RX_CTRL_FRAME  0x20
#define IWAN_WIN_SHM_HDR_SIZE           0x28

typedef struct _IWAN_WIN_SHM {
	uint32_t version;	/* IWAN_WIN_SHM_VERSION */
	uint32_t pad;		/* 恒 0 */
	uint64_t last_rx_ms;	/* 单调毫秒；0 = 从未收到 / 已断开 */
	uint32_t peer_state;	/* enum iwan_win_peer_state */
	uint32_t enabled;
	uint64_t rx_frames;
	uint64_t rx_ctrl_frame;
} IWAN_WIN_SHM, *PIWAN_WIN_SHM;

/* ---- 布局断言（内核态、用户态、交叉编译器都要过） --------------------- */

#if defined(_KERNEL_MODE)
#  define IWAN_WIN_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#elif defined(__cplusplus)
#  define IWAN_WIN_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
#  define IWAN_WIN_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

/* 共享内存页：与 Linux 的 IWAN_SHM_OFF_* 逐个对齐（同一份用户态读取代码） */
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_VERSION == 0x00, "shm version offset");
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_PAD == 0x04, "shm pad offset");
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_LAST_RX_MS == 0x08, "shm last_rx offset");
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_PEER_STATE == 0x10, "shm peer_state offset");
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_ENABLED == 0x14, "shm enabled offset");
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_RX_FRAMES == 0x18, "shm rx_frames offset");
IWAN_WIN_STATIC_ASSERT(IWAN_WIN_SHM_OFF_RX_CTRL_FRAME == 0x20, "shm rx_ctrl offset");

IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, version) == IWAN_WIN_SHM_OFF_VERSION,
		       "IWAN_WIN_SHM.version 偏移");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, pad) == IWAN_WIN_SHM_OFF_PAD,
		       "IWAN_WIN_SHM.pad 偏移");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, last_rx_ms) == IWAN_WIN_SHM_OFF_LAST_RX_MS,
		       "IWAN_WIN_SHM.last_rx_ms 偏移");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, peer_state) == IWAN_WIN_SHM_OFF_PEER_STATE,
		       "IWAN_WIN_SHM.peer_state 偏移");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, enabled) == IWAN_WIN_SHM_OFF_ENABLED,
		       "IWAN_WIN_SHM.enabled 偏移");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, rx_frames) == IWAN_WIN_SHM_OFF_RX_FRAMES,
		       "IWAN_WIN_SHM.rx_frames 偏移");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SHM, rx_ctrl_frame) == IWAN_WIN_SHM_OFF_RX_CTRL_FRAME,
		       "IWAN_WIN_SHM.rx_ctrl_frame 偏移");
IWAN_WIN_STATIC_ASSERT(sizeof(IWAN_WIN_SHM) == IWAN_WIN_SHM_HDR_SIZE,
		       "IWAN_WIN_SHM 必须恰好是 0x28 字节");

/* ---- 冻结偏移：实测值，改字段前先看 tests/win_abi_layout.c -------------
 *
 * 驱动是 64 位、客户端可能是 32 位，所以下面这些数字必须在两种目标下一致。
 * 已用 x86_64-w64-mingw32-gcc 与 i686-w64-mingw32-gcc 各编译运行一次并逐行
 * 比对过（见 tests/win_abi_layout.c 的用法），除 sizeof(void*) 外无差异；
 * mingw 与 MSVC 对 __int64 都是 8 字节对齐，所以 MSVC 目标同样成立。
 * 这些断言一旦失败，说明 ABI 破了 —— 客户端与驱动会各按各的偏移解释同一块
 * 缓冲，必须同时改驱动、客户端与本文件的版本号。
 */
IWAN_WIN_STATIC_ASSERT(sizeof(IWAN_WIN_TARGET) == 24, "IWAN_WIN_TARGET 必须是 24 字节");
IWAN_WIN_STATIC_ASSERT(sizeof(IWAN_WIN_STATS) == 17 * 8, "IWAN_WIN_STATS 必须是 17 个 u64");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_STATS, ev_dropped) == 128,
		       "IWAN_WIN_STATS.ev_dropped 偏移");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_OPEN, outer_src6) == 40,
		       "SESSION_OPEN.outer_src6 偏移");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_OPEN, inner_ip6) == 104,
		       "SESSION_OPEN.inner_ip6 偏移");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_OPEN, carrier_mtu) == 124,
		       "SESSION_OPEN.carrier_mtu 偏移");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_OPEN, target_offset) == 128,
		       "SESSION_OPEN.target_offset 偏移");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_OPEN, target_count) == 132,
		       "SESSION_OPEN.target_count 偏移");
IWAN_WIN_STATIC_ASSERT(sizeof(IWAN_WIN_SESSION_OPEN) == 136,
		       "IWAN_WIN_SESSION_OPEN 必须是 136 字节");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_INFO, last_rx_ms) == 40,
		       "SESSION_INFO.last_rx_ms 偏移");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_INFO, shm_user_va) == 56,
		       "SESSION_INFO.shm_user_va 偏移");
IWAN_WIN_STATIC_ASSERT(offsetof(IWAN_WIN_SESSION_INFO, stats) == 64,
		       "SESSION_INFO.stats 偏移");
IWAN_WIN_STATIC_ASSERT(sizeof(IWAN_WIN_SESSION_INFO) == 200,
		       "IWAN_WIN_SESSION_INFO 必须是 200 字节");

#endif /* IWAN_WIN_ABI_H */
