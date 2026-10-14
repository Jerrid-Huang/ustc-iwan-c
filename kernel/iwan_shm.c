// SPDX-License-Identifier: GPL-2.0
/*
 * iwan_shm.c — /dev/iwan：每 netns 一页只读共享内存（mmap 给用户态）。
 *
 * 为什么需要它：keepalive 的**发送**在用户态（内核不管发送），但"对端还活着
 * 吗"必须由内核给出依据 —— 内核每收到一个通过凭据闸门的帧（数据帧或控制帧）
 * 就把当前单调毫秒写进这一页，用户态定期轮询即可，不需要任何系统调用。
 * 收到 PT_CLOSE(0x17) 时时间戳置 0，用户态见到 0 即判定断线并退出。
 *
 * 布局冻结在 kernel/iwan_shm.h（偏移 + 版本 + static_assert），用户态按固定
 * 偏移读；时基是 iwan_now_ms()，与 netlink 的 IWAN_A_LAST_KEEPALIVE_MS 完全
 * 一致，而且是**同一个存储**（struct iwan_session 里不再存第二份）。
 *
 * 生命周期（不能有 use-after-free，用户态可能"先 mmap 再删 netns"）：
 *   · 每 netns 一页：alloc_page() 拿到的 1 个引用就是 **pernet 引用**；
 *   · 每次 open() 用 get_page() 再持 1 个引用，release() 时 put_page()；
 *     mmap 的映射经 vma 持有 file 引用 ⇒ 只要映射还在，file 就在，页面引用
 *     就不会提前释放；用户在 netns 消失后继续读自己的映射是安全的；
 *   · pernet exit 的顺序是硬约束：先摘 netfilter 钩子（iwan_rx_net_exit 内含
 *     synchronize_rcu()，保证没有在途钩子还会写这一页），再把 pn->shm 置 NULL，
 *     最后放 pernet 引用；
 *   · 最后一个引用由 put_page() 回收（内部 __free_page，order 0）。
 *
 * 为什么用户态只读：这一页是"内核 → 用户态"的单向快照，用户态写它没有任何
 * 语义（内核每个帧都会覆盖时间戳）。open() 直接拒绝写方式打开，mmap() 拒绝
 * 偏移非 0/超过一页/PROT_WRITE，并清掉 VM_MAYWRITE 让 mprotect 也改不成可写。
 * 页面里没有密钥等敏感数据，因此不加 capability 检查：进程只能看到**自己
 * netns** 的那一页。
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

/* ---- 布局断言：IWAN_SHM_OFF_* 就是 ABI -------------------------------
 *
 * 头文件给用户态的偏移是冻结值，结构体字段顺序/类型若被改动，
 * 这里编译期就会失败（用户态工具也有一份等价断言，见 tests/iwan_shm.c）。
 */
static_assert(offsetof(struct iwan_shm, version) == IWAN_SHM_OFF_VERSION,
	      "iwan_shm: version 偏移与 ABI 不符");
static_assert(offsetof(struct iwan_shm, pad) == IWAN_SHM_OFF_PAD,
	      "iwan_shm: pad 偏移与 ABI 不符");
static_assert(offsetof(struct iwan_shm, last_rx_ms) == IWAN_SHM_OFF_LAST_RX_MS,
	      "iwan_shm: last_rx_ms 偏移与 ABI 不符");
static_assert(offsetof(struct iwan_shm, peer_state) == IWAN_SHM_OFF_PEER_STATE,
	      "iwan_shm: peer_state 偏移与 ABI 不符");
static_assert(offsetof(struct iwan_shm, enabled) == IWAN_SHM_OFF_ENABLED,
	      "iwan_shm: enabled 偏移与 ABI 不符");
static_assert(offsetof(struct iwan_shm, rx_frames) == IWAN_SHM_OFF_RX_FRAMES,
	      "iwan_shm: rx_frames 偏移与 ABI 不符");
static_assert(offsetof(struct iwan_shm, rx_ctrl_frame) ==
	      IWAN_SHM_OFF_RX_CTRL_FRAME,
	      "iwan_shm: rx_ctrl_frame 偏移与 ABI 不符");
static_assert(sizeof(struct iwan_shm) == IWAN_SHM_HDR_SIZE,
	      "iwan_shm: 头部大小与 ABI 不符（尾部保留区不算在结构体里）");
static_assert(IWAN_SHM_HDR_SIZE <= PAGE_SIZE,
	      "iwan_shm: 一页放不下 ABI 头部");

/* ---- 每 netns 页面：分配 / 释放 -------------------------------------- */

int iwan_shm_net_init(struct iwan_net *pn)
{
	struct page *page;
	struct iwan_shm *shm;

	/* 这 1 个引用 = pernet 引用；调用者负责在 exit 时归还 */
	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return -ENOMEM;
	shm = page_address(page);
	if (!shm) {
		/* 高端内存且未 kmap：本模块面向 64 位服务器，不支持这种配置。
		 * 宁可让该 netns 初始化失败，也不要留下一页用户态读不到的页。 */
		__free_page(page);
		return -ENOMEM;
	}
	/* 版本是页面身份；其余字段 __GFP_ZERO 已清零：
	 * enabled = 0、last_rx_ms = 0、peer_state = IWAN_PEER_UNKNOWN = 0 */
	WRITE_ONCE(shm->version, IWAN_SHM_VERSION);
	WRITE_ONCE(pn->shm_page, page);
	WRITE_ONCE(pn->shm, shm);
	return 0;
}

void iwan_shm_net_exit(struct iwan_net *pn)
{
	struct page *page = READ_ONCE(pn->shm_page);

	/* 调用者必须已经摘掉 netfilter 钩子（iwan_net_exit 的顺序）。
	 * 先摘指针：任何漏网的读者（READ_ONCE(pn->shm)）看到 NULL 就什么都不做；
	 * 再放 pernet 引用，最后一个引用消失时整页回收。 */
	WRITE_ONCE(pn->shm, NULL);
	WRITE_ONCE(pn->shm_page, NULL);
	if (page)
		put_page(page);
}

/* ---- 会话级字段（控制面调用；进程上下文） ---------------------------- */

void iwan_shm_session_up(struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	if (!shm)
		return;
	/* 新会话从零开始：时间戳 0（"还没收到过帧"）、peer_state 回 UNKNOWN、
	 * 会话级计数器归零。注意不在这里置 enabled —— 会话真正生效（valid
	 * 置位）之后由调用者调 iwan_shm_set_enabled()，避免用户态先看到
	 * enabled=1 而数据面还没接上。 */
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
	/* 整页清零（含保留区），只保留 version：ABI 版本是页面身份，不随会话
	 * 消失。用户态此刻可能正在读这一页，看到的是"清零过程中"的中间态，
	 * 但所有字段的终态都是"无会话"（enabled=0、last_rx_ms=0），语义安全。 */
	memset(shm, 0, PAGE_SIZE);
	WRITE_ONCE(shm->version, IWAN_SHM_VERSION);
}

/*
 * 页面 enabled = 该 netns 的**会话级**数据面开关，与数据面 iwan_dp_get() 的
 * dp.enabled 同口径：会话开关 && 模块参数总开关。
 *   · 有会话：SESSION_UP / SET_ENABLED(1) → 1（模块参数 enabled=0 时仍为 0）；
 *   · 无会话（模块参数回落路径，旧的 tcp_echo_test 场景）：恒 0 —— 页面是
 *     会话级视图，那条路径的用户态不读这一页。
 */
void iwan_shm_set_enabled(struct iwan_net *pn, bool sess_enabled)
{
	struct iwan_shm *shm = iwan_shm_of(pn);
	bool on = sess_enabled && READ_ONCE(iwan_cfg_get()->enabled);

	if (shm)
		WRITE_ONCE(shm->enabled, on ? 1u : 0u);
}

/* ---- /dev/iwan 文件接口 ---------------------------------------------- */

static int iwan_shm_open(struct inode *inode, struct file *file)
{
	struct iwan_net *pn;
	struct page *page;

	(void)inode;
	/* 这一页是内核写、用户态读的单向快照：写方式打开没有意义 */
	if (file->f_mode & FMODE_WRITE)
		return -EACCES;

	/*
	 * 按**打开进程当时的 netns** 绑定。这里不需要 get_net()，也不会与
	 * pernet exit 竞争：调用者的 nsproxy 就持有该 netns 的引用，只要它还在
	 * 这个 netns 里，netns 清理（以及随后的 pernet exit）就不可能发生 ——
	 * 所以 net_generic() 与 pn->shm_page 此刻都有效。
	 *
	 * 绑定完成后 file 只认 struct page（file->private_data），不再解引用 pn：
	 * 这正是"先 mmap/打开、再删 netns"能安全工作的原因 —— netns 消失后
	 * pn 连同 net_generic 的内存一起没了，而页面靠 file 的引用活着。
	 */
	pn = iwan_net_of(current->nsproxy->net_ns);
	page = READ_ONCE(pn->shm_page);
	if (!page)
		return -ENODEV;		/* 该 netns 的页面已被摘除/分配失败 */
	get_page(page);			/* 每个打开的 file 持 1 个引用 */
	file->private_data = page;
	return 0;
}

static int iwan_shm_release(struct inode *inode, struct file *file)
{
	(void)inode;
	put_page(file->private_data);	/* 最后一个引用时回收整页 */
	file->private_data = NULL;
	return 0;
}

/* 一次性读取的辅助路径（排障、以及不支持 mmap 的场合）：整页快照，
 * 偏移与长度由 simple_read_from_buffer 裁剪。轮询请用 mmap。 */
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

	/* ABI 只有一页：偏移必须为 0，长度不得超过一页
	 * （mmap 的长度已被 VFS 向上取整到页边界） */
	if (vma->vm_pgoff != 0 || size > PAGE_SIZE)
		return -EINVAL;
	/* 只读：拒绝 PROT_WRITE，并清掉 VM_MAYWRITE，使随后的
	 * mprotect(PROT_WRITE) 也失败 —— 用户态只读是 ABI 的一部分 */
	if (vma->vm_flags & VM_WRITE)
		return -EPERM;
	vm_flags_clear(vma, VM_MAYWRITE);
	/* 不许 mremap 扩张、不进 core dump（要求里点名的两个标志；
	 * remap_pfn_range 自己也会置 VM_DONTEXPAND|VM_DONTDUMP|VM_IO|VM_PFNMAP） */
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);

	/* file 持页面引用、vma 持 file 引用 ⇒ 映射期间页面不会被回收。
	 * VM_PFNMAP 的映射不参与缺页分配，用户态只能通过普通访存读。 */
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
	.mode	= 0444,		/* devtmpfs 自动建出 /dev/iwan，只读节点 */
};

int iwan_shm_init(void)
{
	int err = misc_register(&iwan_shm_dev);

	if (err)
		pr_err("/dev/%s 注册失败 %d\n", IWAN_SHM_DEV_NAME, err);
	return err;
}

void iwan_shm_exit(void)
{
	misc_deregister(&iwan_shm_dev);
}
