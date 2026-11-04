/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_shm.h - ABI of the /dev/iwan shared memory page (v1, frozen).
 *
 * One memory region = one page (PAGE_SIZE), **one per netns**. Kernel writes, userspace read-only:
 * after mmap() userspace reads the fields at the fixed offsets below; it can poll
 * "is the peer still alive" without any system call.
 *
 * Conventions (same byte order conventions as kernel/iwan_genl.h):
 *   - all fields are in **host byte order** -- this page is shared only locally, not over the network;
 *   - the time base of last_rx_ms is **exactly the same** as netlink's IWAN_A_LAST_KEEPALIVE_MS
 *     (iwan_now_ms(): monotonic milliseconds from ktime_get_mono_fast_ns()), and both are
 *     **the same storage** (struct iwan_session keeps no second copy; see the accessors
 *     in iwan.h and GET_STATS in iwan_netlink.c);
 *   - 0 means "never received / disconnected": on PT_CLOSE(0x17) last_rx_ms is set to 0 at once,
 *     seeing 0 lets userspace declare the link down and exit;
 *   - the kernel writes it only for frames that pass the **credential gate**; userspace never
 *     writes (open() rejects write mode, mmap() rejects PROT_WRITE).
 *
 * Page layout (offset + size, all relative to the mapping start address):
 *
 *   0x00 u32 version        layout version = IWAN_SHM_VERSION
 *   0x04 u32 pad            alignment padding, always 0
 *   0x08 u64 last_rx_ms     monotonic ms of the last valid frame; 0 = none/disconnected
 *   0x10 u32 peer_state     enum iwan_peer_state (iwan_genl.h) reused here
 *   0x14 u32 enabled        session-level data plane switch (see CONTROL-PLANE.md section 11)
 *   0x18 u64 rx_frames      data frame count (mirror snapshot of pn->st.rx_frames)
 *   0x20 u64 rx_ctrl_frame  control frame count (mirror snapshot of pn->st.rx_ctrl_frame)
 *   0x28 .. PAGE_SIZE-1     reserved, always 0 (the writer only writes the fields above)
 *
 * Endpoint: misc device, devtmpfs creates /dev/iwan automatically; mmap allows only offset 0
 * and length <= one page. This file uses only <linux/types.h>; kernel and userspace can include it directly.
 */
#ifndef IWAN_SHM_H
#define IWAN_SHM_H

#include <linux/types.h>

/* Layout version: adding/removing fields requires +1, and update the offset asserts in kernel/iwan_shm.c and userspace in sync */
#define IWAN_SHM_VERSION	1

/* Device name (misc_register -> /dev/iwan) */
#define IWAN_SHM_DEV_NAME	"iwan"

/* Fixed offsets: userspace reads by these values, independent of struct layout */
#define IWAN_SHM_OFF_VERSION		0x00
#define IWAN_SHM_OFF_PAD		0x04
#define IWAN_SHM_OFF_LAST_RX_MS		0x08
#define IWAN_SHM_OFF_PEER_STATE		0x10
#define IWAN_SHM_OFF_ENABLED		0x14
#define IWAN_SHM_OFF_RX_FRAMES		0x18
#define IWAN_SHM_OFF_RX_CTRL_FRAME	0x20

/* Defined header length; after 0x28 up to the page end is reserved (must be 0) */
#define IWAN_SHM_HDR_SIZE		0x28

/*
 * Page header. Covers only the defined 0x28 bytes and does **not** extend to the page end:
 * the page size is PAGE_SIZE, userspace mmap gets the whole page, and the reserved area is not in the struct.
 * The kernel side (iwan_shm.c) pins every offsetof to IWAN_SHM_OFF_* with its static_assert.
 */
struct iwan_shm {
	__u32	version;	/* IWAN_SHM_VERSION */
	__u32	pad;		/* always 0 */
	__u64	last_rx_ms;	/* monotonic ms; 0 = never received / disconnected */
	__u32	peer_state;	/* enum iwan_peer_state */
	__u32	enabled;	/* session-level data plane switch: 1 = enabled */
	__u64	rx_frames;	/* data frame count (session-level view) */
	__u64	rx_ctrl_frame;	/* control frame count (session-level view) */
};

#endif /* IWAN_SHM_H */
