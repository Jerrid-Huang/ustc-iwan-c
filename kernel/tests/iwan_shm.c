// SPDX-License-Identifier: GPL-2.0
/*
 * iwan_shm.c - read-only inspection tool for the /dev/iwan shared memory page (pure libc).
 *
 *   iwan_shm dump  [--pread]
 *   iwan_shm watch [--count N] [--interval MS] [--leave-netns]
 *
 * Background: keepalive sending is in userspace; for every frame passing the credential gate the
 * kernel writes the current monotonic ms into **the one page of that netns**; this tool only reads
 * that page (kernel open() rejects write mode, mmap() rejects PROT_WRITE). Userspace link-down rules:
 *   - last_rx_ms == 0  -> never received / disconnected (PT_CLOSE zeroes the timestamp);
 *   - no advance past a threshold -> down and exit (caller decides it; this tool only reports values).
 *
 * The page layout and offsets come from kernel/iwan_shm.h (frozen ABI); this file re-checks the
 * same offsets with static assertions, so a kernel change without userspace fails to compile.
 *
 * Build (see kernel/tests/shm_test.sh):
 *   cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o iwan_shm iwan_shm.c
 *
 * Exit codes (same style as iwan_ctl.c): 0 success; 1 open/mmap/read failure; 2 usage error.
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

/* The userspace side also pins the ABI offsets: any layout change must update both sides */
_Static_assert(offsetof(struct iwan_shm, version) == IWAN_SHM_OFF_VERSION,
	       "iwan_shm: version offset does not match ABI");
_Static_assert(offsetof(struct iwan_shm, pad) == IWAN_SHM_OFF_PAD,
	       "iwan_shm: pad offset does not match ABI");
_Static_assert(offsetof(struct iwan_shm, last_rx_ms) == IWAN_SHM_OFF_LAST_RX_MS,
	       "iwan_shm: last_rx_ms offset does not match ABI");
_Static_assert(offsetof(struct iwan_shm, peer_state) == IWAN_SHM_OFF_PEER_STATE,
	       "iwan_shm: peer_state offset does not match ABI");
_Static_assert(offsetof(struct iwan_shm, enabled) == IWAN_SHM_OFF_ENABLED,
	       "iwan_shm: enabled offset does not match ABI");
_Static_assert(offsetof(struct iwan_shm, rx_frames) == IWAN_SHM_OFF_RX_FRAMES,
	       "iwan_shm: rx_frames offset does not match ABI");
_Static_assert(offsetof(struct iwan_shm, rx_ctrl_frame) ==
	       IWAN_SHM_OFF_RX_CTRL_FRAME,
	       "iwan_shm: rx_ctrl_frame offset does not match ABI");

#define DEV_PATH	"/dev/iwan"
#define INIT_NETNS	"/proc/1/ns/net"

static const char *progname = "iwan_shm";

static void die(const char *fmt, ...)
	__attribute__((noreturn, format(printf, 1, 2)));

static void die(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: error: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static void usage(FILE *fd)
{
	fprintf(fd,
"Usage:\n"
"  iwan_shm dump  [--pread]\n"
"  iwan_shm watch [--count N] [--interval MS] [--leave-netns]\n"
"\n"
"Description:\n"
"  - open %s (read-only) and mmap one page: dump prints all fields once, watch prints\n"
"    one line every --interval ms (with the delta from the previous line, to see progress).\n"
"  - all fields are host byte order; peer_state_name: 0=UNKNOWN 1=UP 2=SILENT 3=CLOSED;\n"
"    last_rx_ms=0 means no valid frame ever received or the peer sent PT_CLOSE (userspace declares down).\n"
"  - --pread: dump uses pread(2) to read a whole-page snapshot (no mapping), to compare\n"
"    whether the mmap and read paths return the same data.\n"
"  - --leave-netns: after mmap, move the process into the netns of PID 1, so the **original\n"
"    netns can be deleted** (the page is referenced by the open file); then prints left_netns=1.\n"
"    Used to verify that after mmap-then-delete-netns the mapping stays valid and keeps the last content.\n"
"  - watch --count 0 (default) prints forever; each line starts with iter=, t_ms= is this\n"
"    process's monotonic clock (ms since boot).\n"
"  - exit codes: 0 success, 1 open/mmap/read failure, 2 usage error.\n",
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
		;	/* interrupted only by a signal: sleep for the remaining time */
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
 * Open /dev/iwan and obtain a page view according to the mode.
 *   use_mmap=true  -> mmap(PROT_READ, MAP_SHARED): zero-syscall polling path;
 *   use_mmap=false -> pread the whole page into a local buffer: reference path (for progress).
 * The pointer is volatile: the kernel writes this shared page anytime, so reload it every loop.
 */
static const volatile struct iwan_shm *open_page(bool use_mmap, void **map_out,
						 size_t *map_len,
						 unsigned char **buf_out)
{
	long page_size = sysconf(_SC_PAGESIZE);
	const volatile struct iwan_shm *shm;
	int fd;

	if (page_size <= 0 || (size_t)page_size < sizeof(struct iwan_shm))
		die("abnormal system page size: %ld", page_size);

	fd = open(DEV_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open %s failed: %s (is the module loaded?)", DEV_PATH,
		    strerror(errno));

	if (use_mmap) {
		void *p = mmap(NULL, (size_t)page_size, PROT_READ, MAP_SHARED,
			       fd, 0);

		if (p == MAP_FAILED)
			die("mmap(%s, %ld, PROT_READ, MAP_SHARED) failed: %s",
			    DEV_PATH, page_size, strerror(errno));
		shm = (const volatile struct iwan_shm *)p;
		*map_out = p;
		*map_len = (size_t)page_size;
		*buf_out = NULL;
	} else {
		unsigned char *b = malloc((size_t)page_size);
		ssize_t n;

		if (!b)
			die("malloc(%ld) failed", page_size);
		n = pread(fd, b, (size_t)page_size, 0);
		if (n < 0)
			die("pread(%s) failed: %s", DEV_PATH, strerror(errno));
		if (n != page_size)
			die("pread(%s) returned only %zd bytes (expected %ld)", DEV_PATH,
			    n, page_size);
		shm = (const volatile struct iwan_shm *)b;
		*map_out = NULL;
		*map_len = 0;
		*buf_out = b;
	}

	/* Version mismatch only warns, does not fail: offsets may still work; caller decides */
	if (shm->version != IWAN_SHM_VERSION)
		fprintf(stderr,
			"%s: warning: page version=%u, this tool expects %u\n",
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
			die("open %s failed: %s", INIT_NETNS, strerror(errno));
		if (setns(nfd, CLONE_NEWNET) != 0)
			die("setns(%s, CLONE_NEWNET) failed: %s", INIT_NETNS,
			    strerror(errno));
		close(nfd);
		/* The script waits for this line: mmap is done and this process no longer holds the netns */
		printf("left_netns=1\n");
		fflush(stdout);
	}

	t0 = now_ms();
	for (i = 0; count == 0 || i < count; i++) {
		uint64_t t = now_ms() - t0;
		uint64_t rx = shm->last_rx_ms;
		uint64_t frames = shm->rx_frames;
		uint64_t ctrl = shm->rx_ctrl_frame;

		/* Deltas are signed: last_rx_ms can go backwards when PT_CLOSE zeroes it */
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
		die("%s is not a valid number: \"%s\"", what, s);
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

	optind = 2;	/* skip the subcommand, start parsing at its arguments */
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
			die("dump has extra arguments: %s", argv[optind]);
		if (leave_netns)
			die("dump does not support --leave-netns (use watch)");
		return cmd_dump(!pread_mode);
	} else if (!strcmp(cmd, "watch")) {
		if (optind != argc)
			die("watch has extra arguments: %s", argv[optind]);
		if (pread_mode)
			die("watch does not support --pread (watch is the mmap polling path)");
		return cmd_watch(count, interval, leave_netns);
	}
	fprintf(stderr, "%s: unknown subcommand \"%s\"\n", progname, cmd);
	usage(stderr);
	return 2;
}
