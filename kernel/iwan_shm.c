// SPDX-License-Identifier: GPL-2.0
/*
 * iwan_shm.c - /dev/iwan: one read-only shared memory page per netns (mmap for userspace).
 *
 * Why it is needed: keepalive **sending** is in userspace (the kernel does not send), but
 * "is the peer still alive" must have kernel evidence -- for every frame (data or control)
 * that passes the credential gate the kernel writes the current monotonic ms into this page,
 * so userspace just polls, no syscall; PT_CLOSE(0x17) zeroes it, and seeing 0 means down => exit.
 *
 * The layout is frozen in kernel/iwan_shm.h (offsets + version + static_assert); userspace reads
 * by those fixed offsets. The time base is iwan_now_ms(), exactly identical to netlink's
 * IWAN_A_LAST_KEEPALIVE_MS, and it is **the same storage** (no second copy in struct iwan_session).
 *
 * Lifecycle (no use-after-free: userspace may "mmap first, then delete the netns"):
 *   - one page per netns: the 1 reference taken by alloc_page() is the **pernet reference**;
 *   - each open() takes 1 more ref via get_page(); release() does put_page(); the mmap
 *     mapping holds the file ref via its vma => while the mapping lives the file lives, so
 *     the page is not freed early; reading it after the netns is gone is safe;
 *   - pernet exit order is a hard constraint: first detach the netfilter hooks (iwan_rx_net_exit
 *     contains synchronize_rcu(), guaranteeing no in-flight hook still writes this page), then
 *     set pn->shm to NULL, and finally drop the pernet reference;
 *   - the last reference is reclaimed by put_page() (internal __free_page, order 0).
 *
 * Why userspace is read-only: this page is a one-way "kernel -> userspace" snapshot; userspace
 * writes have no semantics (the kernel overwrites the timestamp on every frame). open() rejects
 * write mode outright, mmap() rejects non-zero offset / more than one page / PROT_WRITE, and
 * clears VM_MAYWRITE so even mprotect cannot make it writable. The page holds no keys or other
 * sensitive data, so no capability check: a process can only see the page of **its own netns**.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/build_bug.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "iwan.h"
#include "iwan_genl.h"
#include "iwan_shm.h"

/* ---- Layout asserts: IWAN_SHM_OFF_* is the ABI ------------------------
 *
 * The offsets given to userspace by the header are frozen; if struct field order/type changes,
 * this fails at compile time (the userspace tool has an equivalent assert, see tests/iwan_shm.c).
 */
static_assert(offsetof(struct iwan_shm, version) == IWAN_SHM_OFF_VERSION,
	      "iwan_shm: version offset does not match ABI");
static_assert(offsetof(struct iwan_shm, pad) == IWAN_SHM_OFF_PAD,
	      "iwan_shm: pad offset does not match ABI");
static_assert(offsetof(struct iwan_shm, last_rx_ms) == IWAN_SHM_OFF_LAST_RX_MS,
	      "iwan_shm: last_rx_ms offset does not match ABI");
static_assert(offsetof(struct iwan_shm, peer_state) == IWAN_SHM_OFF_PEER_STATE,
	      "iwan_shm: peer_state offset does not match ABI");
static_assert(offsetof(struct iwan_shm, enabled) == IWAN_SHM_OFF_ENABLED,
	      "iwan_shm: enabled offset does not match ABI");
static_assert(offsetof(struct iwan_shm, rx_frames) == IWAN_SHM_OFF_RX_FRAMES,
	      "iwan_shm: rx_frames offset does not match ABI");
static_assert(offsetof(struct iwan_shm, rx_ctrl_frame) ==
	      IWAN_SHM_OFF_RX_CTRL_FRAME,
	      "iwan_shm: rx_ctrl_frame offset does not match ABI");
static_assert(sizeof(struct iwan_shm) == IWAN_SHM_HDR_SIZE,
	      "iwan_shm: header size does not match ABI (trailing reserved area is not part of the struct)");
static_assert(IWAN_SHM_HDR_SIZE <= PAGE_SIZE,
	      "iwan_shm: the ABI header does not fit in one page");

/* ---- Per-netns page: allocate / free ---------------------------------- */

int iwan_shm_net_init(struct iwan_net *pn)
{
	struct page *page;
	struct iwan_shm *shm;

	/* This 1 reference = the pernet reference; the caller returns it on exit */
	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return -ENOMEM;
	shm = page_address(page);
	if (!shm) {
		/* Highmem without kmap: this module targets 64-bit servers and does not
		 * support that setup. Fail netns init rather than leave a page userspace cannot read. */
		__free_page(page);
		return -ENOMEM;
	}
	/* Version is the page identity; __GFP_ZERO already cleared the rest:
	 * enabled = 0, last_rx_ms = 0, peer_state = IWAN_PEER_UNKNOWN = 0 */
	WRITE_ONCE(shm->version, IWAN_SHM_VERSION);
	WRITE_ONCE(pn->shm_page, page);
	WRITE_ONCE(pn->shm, shm);
	return 0;
}

void iwan_shm_net_exit(struct iwan_net *pn)
{
	struct page *page = READ_ONCE(pn->shm_page);

	/* The caller must already have detached the netfilter hooks (iwan_net_exit order).
	 * Detach the pointer first: any stray reader (READ_ONCE(pn->shm)) sees NULL and does nothing;
	 * then drop the pernet reference; the page is freed when the last reference goes away. */
	WRITE_ONCE(pn->shm, NULL);
	WRITE_ONCE(pn->shm_page, NULL);
	if (page)
		put_page(page);
}

/* ---- Session-level fields (called from the control plane; process context) -- */

void iwan_shm_session_up(struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	if (!shm)
		return;
	/* A new session starts from zero: timestamp 0 ("no frame received yet"), peer_state back
	 * to UNKNOWN, session-level counters zeroed. Note enabled is NOT set here -- after the
	 * session really takes effect (valid set) the caller calls iwan_shm_set_enabled(), so
	 * userspace does not see enabled=1 before the data plane is wired up. */
	WRITE_ONCE(shm->version, IWAN_SHM_VERSION);
	WRITE_ONCE(shm->last_rx_ms, 0);
	WRITE_ONCE(shm->peer_state, IWAN_PEER_UNKNOWN);
	WRITE_ONCE(shm->rx_frames, 0);
	WRITE_ONCE(shm->rx_ctrl_frame, 0);
}

void iwan_shm_session_down(struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	if (!shm)
		return;
	/* Zero the whole page (including the reserved area), keeping only version: the ABI version
	 * is the page identity, not lost with the session. Userspace may be reading now and see
	 * mid-zeroing state, but all fields settle to "no session" (enabled=0, last_rx_ms=0): safe. */
	memset(shm, 0, PAGE_SIZE);
	WRITE_ONCE(shm->version, IWAN_SHM_VERSION);
}

/*
 * Page enabled = the **session-level** data plane switch of this netns, same definition as
 * dp.enabled of iwan_dp_get() in the data plane: session switch && module parameter master switch.
 *   - with a session: SESSION_UP / SET_ENABLED(1) -> 1 (still 0 when module param enabled=0);
 *   - without a session (module parameter fallback path, old tcp_echo_test scenario):
 *     always 0 -- the page is a session-level view and userspace on that path never reads it.
 */
void iwan_shm_set_enabled(struct iwan_net *pn, bool sess_enabled)
{
	struct iwan_shm *shm = iwan_shm_of(pn);
	bool on = sess_enabled && READ_ONCE(iwan_cfg_get()->enabled);

	if (shm)
		WRITE_ONCE(shm->enabled, on ? 1u : 0u);
}

/* ---- /dev/iwan file interface ------------------------------------------- */

static int iwan_shm_open(struct inode *inode, struct file *file)
{
	struct iwan_net *pn;
	struct page *page;

	(void)inode;
	/* This page is a kernel-write / userspace-read one-way snapshot: write open is meaningless */
	if (file->f_mode & FMODE_WRITE)
		return -EACCES;

	/*
	 * Bind to the **netns of the opening process at open time**. No get_net() is needed here and
	 * there is no race with pernet exit: the caller's nsproxy holds a reference to that netns, so
	 * as long as it is still in this netns, cleanup (and the subsequent pernet exit) cannot happen
	 * -- therefore net_generic() and pn->shm_page are both valid right now.
	 *
	 * After binding, file only knows the struct page (file->private_data), never pn again: this
	 * is why "mmap/open first, delete netns later" works -- after the netns disappears pn and
	 * the net_generic memory are gone, while the page survives on the file reference.
	 */
	pn = iwan_net_of(current->nsproxy->net_ns);
	page = READ_ONCE(pn->shm_page);
	if (!page)
		return -ENODEV;		/* this netns' page was detached or allocation failed */
	get_page(page);			/* each open file holds 1 reference */
	file->private_data = page;
	return 0;
}

static int iwan_shm_release(struct inode *inode, struct file *file)
{
	(void)inode;
	put_page(file->private_data);	/* frees the whole page on the last reference */
	file->private_data = NULL;
	return 0;
}

/* One-shot read helper path (troubleshooting, and where mmap is unsupported): whole-page
 * snapshot; simple_read_from_buffer trims offset and length. Use mmap for polling. */
static ssize_t iwan_shm_read(struct file *file, char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	struct page *page = file->private_data;

	return simple_read_from_buffer(ubuf, count, ppos, page_address(page),
				       PAGE_SIZE);
}

static int iwan_shm_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct page *page = file->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;

	/* The ABI is one page: offset must be 0 and length must not exceed one page
	 * (the mmap length has already been rounded up to a page boundary by the VFS) */
	if (vma->vm_pgoff != 0 || size > PAGE_SIZE)
		return -EINVAL;
	/* Read-only: reject PROT_WRITE and clear VM_MAYWRITE so a later
	 * mprotect(PROT_WRITE) also fails -- userspace read-only is part of the ABI */
	if (vma->vm_flags & VM_WRITE)
		return -EPERM;
	vm_flags_clear(vma, VM_MAYWRITE);
	/* No mremap expansion, no core dump (the two flags named by the requirement;
	 * remap_pfn_range also sets VM_DONTEXPAND|VM_DONTDUMP|VM_IO|VM_PFNMAP itself) */
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);

	/* file holds the page ref, vma holds the file ref => the page is not freed while mapped.
	 * A VM_PFNMAP mapping takes no part in fault allocation; userspace reads via normal loads. */
	return remap_pfn_range(vma, vma->vm_start, page_to_pfn(page), size,
			       vma->vm_page_prot);
}

static const struct file_operations iwan_shm_fops = {
	.owner		= THIS_MODULE,
	.open		= iwan_shm_open,
	.release	= iwan_shm_release,
	.read		= iwan_shm_read,
	.mmap		= iwan_shm_mmap,
};

static struct miscdevice iwan_shm_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= IWAN_SHM_DEV_NAME,
	.fops	= &iwan_shm_fops,
	.mode	= 0444,		/* devtmpfs creates /dev/iwan automatically, read-only node */
};

int iwan_shm_init(void)
{
	int err = misc_register(&iwan_shm_dev);

	if (err)
		pr_err("/dev/%s registration failed %d\n", IWAN_SHM_DEV_NAME, err);
	return err;
}

void iwan_shm_exit(void)
{
	misc_deregister(&iwan_shm_dev);
}
