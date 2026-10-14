// SPDX-License-Identifier: GPL-2.0
/*
 * iwan_shm.c — /dev/iwan 共享内存页的只读查看工具（纯 libc）。
 *
 *   iwan_shm dump  [--pread]
 *   iwan_shm watch [--count N] [--interval MS] [--leave-netns]
 *
 * 背景：keepalive 的发送在用户态，内核每收到一个通过凭据闸门的帧就把当前
 * 单调毫秒写进**该 netns 一页**共享内存；本工具只读这一页（内核侧 open()
 * 拒绝写方式打开、mmap() 拒绝 PROT_WRITE）。用户态的断线判据：
 *   · last_rx_ms == 0  → 从未收到 / 已断开（PT_CLOSE 会把时间戳置 0）；
 *   · 超过阈值没推进   → 判定断线并退出（阈值由调用方决定，本工具只报数）。
 *
 * 页面布局与偏移来自 kernel/iwan_shm.h（冻结 ABI）；本文件对同一批偏移再
 * 做一次静态断言，内核改了而用户态没跟上就编译不过。
 *
 * 编译（见 kernel/tests/shm_test.sh）：
 *   cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o iwan_shm iwan_shm.c
 *
 * 退出码（与 iwan_ctl.c 同风格）：0 成功；1 打开/映射/读取失败；2 用法错误。
 */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "../iwan_shm.h"

/* 用户态这一侧也把 ABI 偏移钉死：页面布局改动必须两边同时改 */
_Static_assert(offsetof(struct iwan_shm, version) == IWAN_SHM_OFF_VERSION,
	       "iwan_shm: version 偏移与 ABI 不符");
_Static_assert(offsetof(struct iwan_shm, pad) == IWAN_SHM_OFF_PAD,
	       "iwan_shm: pad 偏移与 ABI 不符");
_Static_assert(offsetof(struct iwan_shm, last_rx_ms) == IWAN_SHM_OFF_LAST_RX_MS,
	       "iwan_shm: last_rx_ms 偏移与 ABI 不符");
_Static_assert(offsetof(struct iwan_shm, peer_state) == IWAN_SHM_OFF_PEER_STATE,
	       "iwan_shm: peer_state 偏移与 ABI 不符");
_Static_assert(offsetof(struct iwan_shm, enabled) == IWAN_SHM_OFF_ENABLED,
	       "iwan_shm: enabled 偏移与 ABI 不符");
_Static_assert(offsetof(struct iwan_shm, rx_frames) == IWAN_SHM_OFF_RX_FRAMES,
	       "iwan_shm: rx_frames 偏移与 ABI 不符");
_Static_assert(offsetof(struct iwan_shm, rx_ctrl_frame) ==
	       IWAN_SHM_OFF_RX_CTRL_FRAME,
	       "iwan_shm: rx_ctrl_frame 偏移与 ABI 不符");

#define DEV_PATH	"/dev/iwan"
#define INIT_NETNS	"/proc/1/ns/net"

static const char *progname = "iwan_shm";

static void die(const char *fmt, ...)
	__attribute__((noreturn, format(printf, 1, 2)));

static void die(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: 错误: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static void usage(FILE *fd)
{
	fprintf(fd,
"用法:\n"
"  iwan_shm dump  [--pread]\n"
"  iwan_shm watch [--count N] [--interval MS] [--leave-netns]\n"
"\n"
"说明:\n"
"  · 打开 %s（只读）并 mmap 一页：dump 打印一次全部字段，watch 每\n"
"    --interval 毫秒打印一行（带与上次的差值，便于看时间戳是否在推进）。\n"
"  · 字段一律主机序；peer_state_name: 0=UNKNOWN 1=UP 2=SILENT 3=CLOSED；\n"
"    last_rx_ms=0 表示从未收到有效帧或对端已 PT_CLOSE（用户态据此判定断线）。\n"
"  · --pread: dump 改用 pread(2) 读整页快照（不开映射），用来对照 mmap 与\n"
"    read 两条路径是否给出同一份数据。\n"
"  · --leave-netns: mmap 之后把进程挪到 PID 1 所在 netns，于是**原 netns\n"
"    可以被删除**（页面由打开的 file 持有引用）；成功后打印 left_netns=1。\n"
"    用来验证「先 mmap 再删 netns」时映射仍然有效、值保持最后一次内容。\n"
"  · watch --count 0（默认）表示一直打印；每行以 iter= 开头，t_ms= 是本进程\n"
"    单调时钟（自启动起的毫秒）。\n"
"  · 退出码: 0 成功, 1 打开/映射/读取失败, 2 用法错误。\n",
		DEV_PATH);
}

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static void sleep_ms(uint64_t ms)
{
	struct timespec ts = {
		.tv_sec  = (time_t)(ms / 1000),
		.tv_nsec = (long)((ms % 1000) * 1000000),
	};

	while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
		;	/* 只被信号中断：按剩余时间接着睡 */
}

static const char *peer_state_name(uint32_t s)
{
	switch (s) {
	case 0:  return "UNKNOWN";
	case 1:  return "UP";
	case 2:  return "SILENT";
	case 3:  return "CLOSED";
	default: return "?";
	}
}

/*
 * 打开 /dev/iwan 并按 mode 取得页面视图。
 *   use_mmap=true  → mmap(PROT_READ, MAP_SHARED)：零系统调用的轮询路径；
 *   use_mmap=false → pread 整页到本地缓冲：对照路径（进度用）。
 * 返回的指针带 volatile：这一页是内核随时在写的共享内存，循环里必须每次实读。
 */
static const volatile struct iwan_shm *open_page(bool use_mmap, void **map_out,
						 size_t *map_len,
						 unsigned char **buf_out)
{
	long page_size = sysconf(_SC_PAGESIZE);
	const volatile struct iwan_shm *shm;
	int fd;

	if (page_size <= 0 || (size_t)page_size < sizeof(struct iwan_shm))
		die("系统页大小异常: %ld", page_size);

	fd = open(DEV_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("打开 %s 失败: %s（模块加载了吗？）", DEV_PATH,
		    strerror(errno));

	if (use_mmap) {
		void *p = mmap(NULL, (size_t)page_size, PROT_READ, MAP_SHARED,
			       fd, 0);

		if (p == MAP_FAILED)
			die("mmap(%s, %ld, PROT_READ, MAP_SHARED) 失败: %s",
			    DEV_PATH, page_size, strerror(errno));
		shm = (const volatile struct iwan_shm *)p;
		*map_out = p;
		*map_len = (size_t)page_size;
		*buf_out = NULL;
	} else {
		unsigned char *b = malloc((size_t)page_size);
		ssize_t n;

		if (!b)
			die("malloc(%ld) 失败", page_size);
		n = pread(fd, b, (size_t)page_size, 0);
		if (n < 0)
			die("pread(%s) 失败: %s", DEV_PATH, strerror(errno));
		if (n != page_size)
			die("pread(%s) 只返回 %zd 字节（期望 %ld）", DEV_PATH,
			    n, page_size);
		shm = (const volatile struct iwan_shm *)b;
		*map_out = NULL;
		*map_len = 0;
		*buf_out = b;
	}

	/* 版本不匹配只告警不失败：字段偏移可能仍然可用，交给调用方判断 */
	if (shm->version != IWAN_SHM_VERSION)
		fprintf(stderr,
			"%s: 警告: 页面 version=%u，本工具期望 %u\n",
			progname, (unsigned)shm->version, IWAN_SHM_VERSION);
	return shm;
}

static void print_head(bool use_mmap, size_t map_len)
{
	printf("dev=%s\n", DEV_PATH);
	printf("method=%s\n", use_mmap ? "mmap" : "pread");
	if (use_mmap)
		printf("map_len=%zu\n", map_len);
	printf("page_size=%ld\n", sysconf(_SC_PAGESIZE));
}

static int cmd_dump(bool use_mmap)
{
	const volatile struct iwan_shm *shm;
	unsigned char *buf;
	void *map;
	size_t map_len;

	shm = open_page(use_mmap, &map, &map_len, &buf);
	printf("ready=1\n");
	print_head(use_mmap, map_len);
	printf("version=%u\n", (unsigned)shm->version);
	printf("pad=%u\n", (unsigned)shm->pad);
	printf("last_rx_ms=%llu\n", (unsigned long long)shm->last_rx_ms);
	printf("peer_state=%u\n", (unsigned)shm->peer_state);
	printf("peer_state_name=%s\n", peer_state_name(shm->peer_state));
	printf("enabled=%u\n", (unsigned)shm->enabled);
	printf("rx_frames=%llu\n", (unsigned long long)shm->rx_frames);
	printf("rx_ctrl_frame=%llu\n", (unsigned long long)shm->rx_ctrl_frame);
	fflush(stdout);

	if (map)
		munmap(map, map_len);
	free(buf);
	return 0;
}

static int cmd_watch(unsigned long count, uint64_t interval, bool leave_netns)
{
	const volatile struct iwan_shm *shm;
	unsigned char *buf;
	void *map;
	size_t map_len;
	uint64_t t0, last_rx = 0, last_frames = 0, last_ctrl = 0;
	unsigned long i;

	shm = open_page(true, &map, &map_len, &buf);
	printf("ready=1\n");
	print_head(true, map_len);
	fflush(stdout);

	if (leave_netns) {
		int nfd = open(INIT_NETNS, O_RDONLY | O_CLOEXEC);

		if (nfd < 0)
			die("打开 %s 失败: %s", INIT_NETNS, strerror(errno));
		if (setns(nfd, CLONE_NEWNET) != 0)
			die("setns(%s, CLONE_NEWNET) 失败: %s", INIT_NETNS,
			    strerror(errno));
		close(nfd);
		/* 脚本等这一行：此刻 mmap 已完成，且本进程不再持有原 netns */
		printf("left_netns=1\n");
		fflush(stdout);
	}

	t0 = now_ms();
	for (i = 0; count == 0 || i < count; i++) {
		uint64_t t = now_ms() - t0;
		uint64_t rx = shm->last_rx_ms;
		uint64_t frames = shm->rx_frames;
		uint64_t ctrl = shm->rx_ctrl_frame;

		/* 差值为有符号：last_rx_ms 会因为 PT_CLOSE 归零而变小 */
		printf("iter=%lu t_ms=%llu last_rx_ms=%llu d_last_rx_ms=%lld "
		       "peer_state=%u peer_state_name=%s enabled=%u "
		       "rx_frames=%llu d_rx_frames=%lld "
		       "rx_ctrl_frame=%llu d_rx_ctrl_frame=%lld\n",
		       i, (unsigned long long)t, (unsigned long long)rx,
		       (long long)(rx - last_rx), (unsigned)shm->peer_state,
		       peer_state_name(shm->peer_state),
		       (unsigned)shm->enabled, (unsigned long long)frames,
		       (long long)(frames - last_frames),
		       (unsigned long long)ctrl, (long long)(ctrl - last_ctrl));
		fflush(stdout);
		last_rx = rx;
		last_frames = frames;
		last_ctrl = ctrl;

		if (count == 0 || i + 1 < count)
			sleep_ms(interval);
	}

	munmap(map, map_len);
	return 0;
}

/* ---------------------------------------------------------------- main */

enum {
	OPT_COUNT = 1, OPT_INTERVAL, OPT_LEAVE_NETNS, OPT_PREAD, OPT_HELP,
};

static const struct option long_opts[] = {
	{ "count",		required_argument,	NULL, OPT_COUNT },
	{ "interval",		required_argument,	NULL, OPT_INTERVAL },
	{ "leave-netns",	no_argument,		NULL, OPT_LEAVE_NETNS },
	{ "pread",		no_argument,		NULL, OPT_PREAD },
	{ "help",		no_argument,		NULL, OPT_HELP },
	{ NULL, 0, NULL, 0 },
};

static unsigned long parse_ul(const char *s, const char *what)
{
	char *end;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &end, 0);
	if (errno || *end || end == s)
		die("%s 不是合法数字: \"%s\"", what, s);
	return v;
}

int main(int argc, char **argv)
{
	unsigned long count = 0;
	uint64_t interval = 1000;
	bool leave_netns = false, pread_mode = false;
	const char *cmd;
	int c;

	if (argc < 2) {
		usage(stderr);
		return 2;
	}
	cmd = argv[1];
	if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help") || !strcmp(cmd, "help")) {
		usage(stdout);
		return 0;
	}

	optind = 2;	/* 跳过子命令，从它的参数开始解析 */
	while ((c = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
		switch (c) {
		case OPT_COUNT:
			count = parse_ul(optarg, "--count");
			break;
		case OPT_INTERVAL:
			interval = parse_ul(optarg, "--interval");
			break;
		case OPT_LEAVE_NETNS:
			leave_netns = true;
			break;
		case OPT_PREAD:
			pread_mode = true;
			break;
		case OPT_HELP:
			usage(stdout);
			return 0;
		default:
			usage(stderr);
			return 2;
		}
	}

	if (!strcmp(cmd, "dump")) {
		if (optind != argc)
			die("dump 有多余参数: %s", argv[optind]);
		if (leave_netns)
			die("dump 不支持 --leave-netns（用 watch）");
		return cmd_dump(!pread_mode);
	} else if (!strcmp(cmd, "watch")) {
		if (optind != argc)
			die("watch 有多余参数: %s", argv[optind]);
		if (pread_mode)
			die("watch 不支持 --pread（watch 就是 mmap 轮询路径）");
		return cmd_watch(count, interval, leave_netns);
	}
	fprintf(stderr, "%s: 未知子命令 \"%s\"\n", progname, cmd);
	usage(stderr);
	return 2;
}
