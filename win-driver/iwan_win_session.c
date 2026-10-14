/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_session.c — 会话、目标集合、统计与共享内存页。
 *
 * 对应 Linux 侧的：struct iwan_session（kernel/iwan.h）、genetlink 的
 * SESSION_UP/SESSION_DOWN/GET_STATS，以及 /dev/iwan 那一页（kernel/iwan_shm.c）。
 *
 * 并发模型见 iwan_win.h 顶部注释：控制面（本文件）在 PASSIVE_LEVEL 用
 * ctrl_mutex 串行化；数据面先取得 rundown 保护再读会话状态。两者之间靠
 * ExWaitForRundownProtectionRelease / ExReInitializeRundownProtection 交接，
 * 因此本文件里可以放心做池分配、用户地址映射与解映射、等待进程退出状态。
 */
#include "iwan_win.h"

/* 封装开销：与 kernel/iwan_genl.h 的 IWAN_OVERHEAD / IWAN_OVERHEAD_V6 一致 */
#define IWAN_WIN_OVERHEAD_V4		36u
#define IWAN_WIN_OVERHEAD_V6		56u
/* 内层 MTU 的上下界：与 kernel 侧 IWAN_MIN_MTU / IWAN_MTU_HARD_MAX* 一致 */
#define IWAN_WIN_MTU_MIN		68u
#define IWAN_WIN_MTU_HARD_MAX_V4	65499u
#define IWAN_WIN_MTU_HARD_MAX_V6	65479u

static __inline BOOLEAN
iwan_win_is_zero16(_In_reads_bytes_(16) const UINT8 *p)
{
	int i;

	for (i = 0; i < 16; i++)
		if (p[i] != 0)
			return FALSE;
	return TRUE;
}

BOOLEAN
iwan_win_session_is_v6(_In_ const IWAN_WIN_SESSION *s)
{
	return !iwan_win_is_zero16(s->outer_dst6);
}

/* ---- 出向拒绝样本（共享页诊断区） ------------------------------------- */

/*
 * 只写不判，用户态经 SHM_QUERY 读（布局见 src/common/iwan_win_abi.h）。
 * 两个数据面（WFP 平面 iwan.sys 与 NDIS 平面 iwanmp.sys）共用这一份实现：
 * 记录的字段布局与写入顺序是现场诊断的唯一依据，任何一处分叉都会让两边的
 * 读数不可比。只在拒绝路径上写，正常路径零开销。
 */
VOID
iwan_win_diag_tx(_Inout_ IWAN_WIN_SESSION *s, _In_ UINT32 reason,
		 _In_ ULONG len, _In_ ULONG tot, _In_ ULONG pkt0,
		 _In_reads_bytes_opt_(len) const UINT8 *pkt)
{
	IWAN_WIN_DIAG *d;
	ULONG n;

	if (s->shm == NULL)
		return;
	d = (IWAN_WIN_DIAG *)((UINT8 *)s->shm + IWAN_WIN_SHM_OFF_DIAG);
	d->magic = IWAN_WIN_DIAG_MAGIC;
	d->reason = reason;
	d->len = (UINT32)len;
	d->tot = (UINT32)tot;
	d->pkt0 = (UINT32)pkt0;
	RtlZeroMemory(d->first, sizeof(d->first));
	if (pkt != NULL) {
		n = len < sizeof(d->first) ? len : sizeof(d->first);
		RtlCopyMemory(d->first, pkt, n);
	}
	/* 字段全部写完再自增序号：读者据此判断记录已更新（先写后记是约定） */
	InterlockedIncrement((volatile LONG *)&d->seq);
}

/* ---- 控制面基础设施 --------------------------------------------------- */

#ifdef IWAN_WIN_PLANE_MP
/*
 * DriverEntry 阶段的失败诊断。
 *
 * 驱动加载失败时没有任何用户态通道可用：控制设备还没建起来，事件日志要走
 * IoAllocateErrorLogEntry，客体上也没有内核调试器。退而求其次，把"走到第几步、
 * 这一步的状态码"写进服务键的 Parameters 子键（两个 REG_DWORD），客体上一条
 * reg query 就能读到，重启也不丢。
 *
 * 只在注册与初始化路径上调用，数据面不碰它。
 */
VOID
iwan_win_mp_trace(_In_ ULONG stage, _In_ LONG status)
{
	UNICODE_STRING path, vn;
	OBJECT_ATTRIBUTES oa;
	HANDLE key = NULL;

	RtlInitUnicodeString(&path,
			     L"\\Registry\\Machine\\System\\CurrentControlSet"
			     L"\\Services\\iwanmp\\Parameters");
	InitializeObjectAttributes(&oa, &path,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				   NULL, NULL);
	if (!NT_SUCCESS(ZwCreateKey(&key, KEY_SET_VALUE, &oa, 0, NULL,
				    REG_OPTION_NON_VOLATILE, NULL)))
		return;

	RtlInitUnicodeString(&vn, L"Stage");
	(void)ZwSetValueKey(key, &vn, 0, REG_DWORD, &stage, sizeof(stage));
	RtlInitUnicodeString(&vn, L"Status");
	(void)ZwSetValueKey(key, &vn, 0, REG_DWORD, &status, sizeof(status));
	ZwClose(key);
}
#endif /* IWAN_WIN_PLANE_MP */

VOID
iwan_win_ctrl_init(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	KeInitializeMutex(&ext->ctrl_mutex, 0);
	/* 初始为"已放行"状态：数据面会取得保护、看到 valid == 0、立刻放回 */
	ExInitializeRundownProtection(&ext->rundown);
}

VOID
iwan_win_ctrl_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	/* 排空数据面读者后不再放行：卸载路径上调用，之后不会再有人进来 */
	ExWaitForRundownProtectionRelease(&ext->rundown);
}

/* ---- 共享内存页（对应 /dev/iwan mmap 的那一页） ----------------------- */

static NTSTATUS
iwan_win_shm_create(_Inout_ IWAN_WIN_SESSION *s)
{
	s->shm = (IWAN_WIN_SHM *)IWAN_ALLOC(PAGE_SIZE, IWAN_TAG_SHM);
	if (s->shm == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(s->shm, PAGE_SIZE);
	s->shm->version = IWAN_WIN_SHM_VERSION;
	s->shm->pad = 0;
	s->shm->last_rx_ms = 0;			/* 0 = 从未收到 */
	s->shm->peer_state = IWAN_WIN_PEER_UNKNOWN;
	s->shm->enabled = 1;
	return STATUS_SUCCESS;
}

/*
 * 撤销用户态映射。映射只在属主进程的地址空间里存在，所以必须切到它的上下文
 * 里解映射；属主已经退出时地址空间随之销毁，这里只需释放 MDL。
 * 属主进程对象在建立映射时已持引用（见 shm_map_user），所以不受 PID 复用影响。
 */
static VOID
iwan_win_shm_unmap_user(_Inout_ IWAN_WIN_SESSION *s)
{
	PMDL mdl = s->shm_mdl;
	PVOID va = s->shm_user_va;
	PEPROCESS owner = s->shm_owner;

	s->shm_mdl = NULL;
	s->shm_user_va = NULL;
	s->shm_owner = NULL;

	if (mdl == NULL)
		return;

	if (owner != NULL) {
		if (PsGetProcessExitStatus(owner) == STATUS_PENDING) {
			KAPC_STATE apc;

			KeStackAttachProcess(owner, &apc);
			MmUnmapLockedPages(va, mdl);
			KeUnstackDetachProcess(&apc);
		}
		ObDereferenceObject(owner);
	}
	IoFreeMdl(mdl);
}

static VOID
iwan_win_shm_destroy(_Inout_ IWAN_WIN_SESSION *s)
{
	iwan_win_shm_unmap_user(s);		/* 先撤映射，再放页 */
	if (s->shm != NULL) {
		ExFreePoolWithTag(s->shm, IWAN_TAG_SHM);
		s->shm = NULL;
	}
}

static NTSTATUS
iwan_win_shm_map_user(_Inout_ IWAN_WIN_SESSION *s)
{
	PEPROCESS owner = PsGetCurrentProcess();
	PMDL mdl;
	PVOID va;

	if (s->shm == NULL)
		return STATUS_INVALID_DEVICE_STATE;
	if (s->shm_mdl != NULL) {
		/* 同一页只映射给一个进程：映射地址在别的进程里没有意义 */
		if (s->shm_owner != owner)
			return STATUS_DEVICE_BUSY;
		return STATUS_SUCCESS;
	}

	mdl = IoAllocateMdl(s->shm, PAGE_SIZE, FALSE, FALSE, NULL);
	if (mdl == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	MmBuildMdlForNonPagedPool(mdl);
	mdl->MdlFlags |= MDL_MAPPING_CAN_FAIL;

	/* UserMode 映射是只读的（对应 Linux 侧 mmap 只给 PROT_READ）：
	 * 用户态能轮询时间戳，但改不了内核写的任何字段。 */
	va = MmMapLockedPagesSpecifyCache(mdl, UserMode, MmCached, NULL, FALSE,
					  NormalPagePriority | MdlMappingNoExecute);
	if (va == NULL) {
		IoFreeMdl(mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ObReferenceObject(owner);
	s->shm_mdl = mdl;
	s->shm_user_va = va;
	s->shm_owner = owner;
	return STATUS_SUCCESS;
}

/* ---- 数据面记账（只在这里写共享内存页） ------------------------------- */

VOID
iwan_win_session_mark_rx(_Inout_ IWAN_WIN_SESSION *s, _In_ UINT32 is_ctrl)
{
	volatile LONG64 *slot;

	if (s->shm == NULL)
		return;

	/*
	 * 不取锁：只有驱动在写，用户态只读。时间戳是单个 8 字节写（x64 上原子），
	 * 计数器用互锁自增，因此数据面每报文没有锁开销 —— 与 Linux 模块同一取向。
	 */
	s->shm->last_rx_ms = iwan_win_now_ms();
	s->shm->peer_state = IWAN_WIN_PEER_UP;
	slot = is_ctrl ? (volatile LONG64 *)&s->shm->rx_ctrl_frame
		       : (volatile LONG64 *)&s->shm->rx_frames;
	InterlockedIncrement64((volatile LONG64 *)slot);
}

/*
 * 对端 PT_CLOSE：把共享内存页的时间戳归零并把 peer_state 置为已关闭。
 * 用户态的判活只看时间戳（归零 = 断线），所以这一笔必须在放行 CLOSE 帧
 * 之前写下去 —— 与 kernel/iwan_rx.c 的 iwan_ev_peer_close 同语义
 * （内核把 PT_CLOSE 的时间戳覆盖成 0）。
 */
VOID
iwan_win_session_mark_close(_Inout_ IWAN_WIN_SESSION *s)
{
	if (s == NULL || s->shm == NULL)
		return;
	s->shm->last_rx_ms = 0;
	s->shm->peer_state = IWAN_WIN_PEER_CLOSED;
	KeMemoryBarrier();
	/* 不在这里计数：调用点已经走过 mark_rx(s, 1)（共享内存页的镜像计数）
	 * 并各自记了驱动侧统计，这里只负责"把时间戳归零 + 置已关闭"。 */
}

/* ---- 目标集合：最长前缀匹配 ------------------------------------------- */

/* ---- 会话生命周期 ----------------------------------------------------- */

static VOID
iwan_win_session_reset(_Inout_ IWAN_WIN_SESSION *s)
{
	s->valid = 0;
	iwan_win_shm_destroy(s);
	if (s->targets != NULL) {
		ExFreePoolWithTag(s->targets, IWAN_TAG_TARGET);
		s->targets = NULL;
	}
	RtlZeroMemory(&s->stats, sizeof(s->stats));
	s->target_count = 0;
}

VOID
iwan_win_session_teardown(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	KeWaitForSingleObject(&ext->ctrl_mutex, Executive, KernelMode, FALSE, NULL);
	ExWaitForRundownProtectionRelease(&ext->rundown);	/* 排空数据面 */
	iwan_win_session_reset(&ext->sess);
	ExReInitializeRundownProtection(&ext->rundown);		/* 重新放行（此时无会话） */
	KeReleaseMutex(&ext->ctrl_mutex, FALSE);
}

/* 把请求里的目标集合复制并规范化；失败返回错误码，成功返回数组（可为 NULL） */
static NTSTATUS
iwan_win_targets_import(_In_reads_bytes_(in_len) const IWAN_WIN_SESSION_OPEN *req,
			_In_ ULONG in_len, _Out_ IWAN_WIN_TARGET **out, _Out_ ULONG *out_count)
{
	IWAN_WIN_TARGET *targets;
	ULONG need, i;

	*out = NULL;
	*out_count = 0;

	if (req->target_count == 0)
		return STATUS_SUCCESS;
	if (req->target_count > IWAN_WIN_MAX_TARGETS)
		return STATUS_INVALID_PARAMETER;

	need = req->target_offset + req->target_count * sizeof(IWAN_WIN_TARGET);
	if (req->target_offset < sizeof(IWAN_WIN_SESSION_OPEN) ||
	    need < req->target_offset || need > in_len)
		return STATUS_INVALID_PARAMETER;

	targets = (IWAN_WIN_TARGET *)IWAN_ALLOC(
		req->target_count * sizeof(IWAN_WIN_TARGET), IWAN_TAG_TARGET);
	if (targets == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlCopyMemory(targets, (const UINT8 *)req + req->target_offset,
		      req->target_count * sizeof(IWAN_WIN_TARGET));

	for (i = 0; i < req->target_count; i++) {
		if (targets[i].family == IWAN_WIN_AF_V4) {
			if (targets[i].prefix_len > 32) {
				ExFreePoolWithTag(targets, IWAN_TAG_TARGET);
				return STATUS_INVALID_PARAMETER;
			}
			/* v4 条目只允许用前 4 字节，其余清零：避免同一前缀
			 * 因为垃圾字节被当成两条。 */
			RtlZeroMemory(targets[i].addr + 4, 12);
		} else if (targets[i].family == IWAN_WIN_AF_V6) {
			if (targets[i].prefix_len > 128) {
				ExFreePoolWithTag(targets, IWAN_TAG_TARGET);
				return STATUS_INVALID_PARAMETER;
			}
		} else {
			ExFreePoolWithTag(targets, IWAN_TAG_TARGET);
			return STATUS_INVALID_PARAMETER;
		}
	}

	*out = targets;
	*out_count = req->target_count;
	return STATUS_SUCCESS;
}

/*
 * ABI 里的端口是"网络序字节"（iwan_win_abi.h 写明 be16；Windows 客户端直接放
 * sockaddr 的 sin_port，本来就是网络序）。会话内部统一成**大端整数**这一种表示，
 * 与 IWAN_WIN_OUTER.sport/dport（iwan_win_rd16 读出来的值）一致：
 *   · 出向用 iwan_win_wr16 写回字节，得到正确的外层端口；
 *   · 入向闸门拿 iwan_win_rd16 读出的端口直接比。
 * 曾经原样当 uint16 用，等于两边差一次字节序：入向闸门永远不相等 -> 整批放行，
 * 外层帧一路交付到用户态套接字；出向封装出去的端口也是反的。
 */
static USHORT
iwan_win_abi_port(_In_ USHORT be)
{
	return iwan_win_rd16((const UINT8 *)&be);
}

/* v4 地址同理：ABI 里是网络序字节，内部统一成大端整数（iwan_win_outer_hdr4
 * 的参数、WFP 固定字段 IP_LOCAL/REMOTE_ADDRESS 都是这个表示）。 */
static UINT32
iwan_win_abi_addr(_In_ UINT32 be)
{
	return iwan_win_rd32((const UINT8 *)&be);
}

/* 参数是否完全一致（用于 SESSION_OPEN 的幂等语义） */
static BOOLEAN
iwan_win_session_same(_In_ const IWAN_WIN_SESSION *s,
		      _In_reads_bytes_(in_len) const IWAN_WIN_SESSION_OPEN *req,
		      _In_ ULONG in_len)
{
	if (!s->valid)
		return FALSE;
	return s->sid == req->sid && s->tok == req->tok && s->enc == req->enc &&
	       RtlCompareMemory(s->key, req->key, sizeof(s->key)) == sizeof(s->key) &&
	       s->outer_src == iwan_win_abi_addr(req->outer_src) &&
	       s->outer_dst == iwan_win_abi_addr(req->outer_dst) &&
	       s->outer_hop == iwan_win_abi_addr(req->outer_hop) &&
	       s->sport == iwan_win_abi_port(req->sport != 0 ? req->sport
							     : req->dport) &&
	       s->dport == iwan_win_abi_port(req->dport) &&
	       RtlCompareMemory(s->outer_src6, req->outer_src6, 16) == 16 &&
	       RtlCompareMemory(s->outer_dst6, req->outer_dst6, 16) == 16 &&
	       s->flags == req->flags && s->oif_index == req->oif_index &&
	       s->bind_ip == req->bind_ip &&
	       s->inner_ip == req->inner_ip && s->inner_mtu == req->inner_mtu &&
	       s->carrier_mtu == req->carrier_mtu &&
	       s->target_count == req->target_count &&
	       (req->target_count == 0 ||
		RtlCompareMemory(s->targets, (const UINT8 *)req + req->target_offset,
				 req->target_count * sizeof(IWAN_WIN_TARGET)) ==
		req->target_count * sizeof(IWAN_WIN_TARGET));
	UNREFERENCED_PARAMETER(in_len);
}

NTSTATUS
iwan_win_session_open(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		      _In_reads_bytes_(in_len) const IWAN_WIN_SESSION_OPEN *req,
		      _In_ ULONG in_len)
{
	IWAN_WIN_SESSION *s = &ext->sess;
	IWAN_WIN_TARGET *targets = NULL;
	ULONG tcount = 0, overhead, mtu, carrier_mtu;
	BOOLEAN v6;
	NTSTATUS st;

	if (req->abi_version != IWAN_WIN_ABI_VERSION)
		return STATUS_REVISION_MISMATCH;
	if (req->size < sizeof(IWAN_WIN_SESSION_OPEN))
		return STATUS_INVALID_PARAMETER;

	v6 = !iwan_win_is_zero16(req->outer_dst6);
	overhead = v6 ? IWAN_WIN_OVERHEAD_V6 : IWAN_WIN_OVERHEAD_V4;

	/* MTU：客户端把承载网卡 MTU 一并报上来（Windows 侧没有 netns，驱动
	 * 不做 FIB 查询），驱动按"内层 + 开销 <= 承载"校验并定出生效值 ——
	 * 与 Linux 会话建立时的校验同一口径。外层 v6 不分片，所以更要卡死。 */
	carrier_mtu = req->carrier_mtu;
	if (carrier_mtu == 0 || carrier_mtu > 65535)
		return STATUS_INVALID_PARAMETER;
	mtu = req->inner_mtu != 0 ? req->inner_mtu : carrier_mtu - overhead;
	if (mtu < IWAN_WIN_MTU_MIN || mtu + overhead > carrier_mtu)
		return STATUS_INVALID_PARAMETER;
	if (mtu > (v6 ? IWAN_WIN_MTU_HARD_MAX_V6 : IWAN_WIN_MTU_HARD_MAX_V4))
		return STATUS_INVALID_PARAMETER;

	st = iwan_win_targets_import(req, in_len, &targets, &tcount);
	if (!NT_SUCCESS(st))
		return st;

	KeWaitForSingleObject(&ext->ctrl_mutex, Executive, KernelMode, FALSE, NULL);

	if (s->valid && iwan_win_session_same(s, req, in_len)) {
		/* 幂等：同一份请求重复下发，返回既有会话 */
		KeReleaseMutex(&ext->ctrl_mutex, FALSE);
		if (targets != NULL)
			ExFreePoolWithTag(targets, IWAN_TAG_TARGET);
		return STATUS_SUCCESS;
	}

	/* 从这里开始要改会话状态：先把数据面排空，之后直到
	 * ExReInitializeRundownProtection 之前，数据面会直接返回"不处理"。 */
	ExWaitForRundownProtectionRelease(&ext->rundown);
	iwan_win_session_reset(s);

	if (s->shm == NULL) {
		st = iwan_win_shm_create(s);
		if (!NT_SUCCESS(st)) {
			ExReInitializeRundownProtection(&ext->rundown);
			KeReleaseMutex(&ext->ctrl_mutex, FALSE);
			if (targets != NULL)
				ExFreePoolWithTag(targets, IWAN_TAG_TARGET);
			return st;
		}
	}

	s->sid = req->sid;
	s->tok = req->tok;
	s->enc = req->enc;
	RtlCopyMemory(s->key, req->key, sizeof(s->key));
	s->outer_src = iwan_win_abi_addr(req->outer_src);
	s->outer_dst = iwan_win_abi_addr(req->outer_dst);
	s->outer_hop = iwan_win_abi_addr(req->outer_hop);
	s->sport = iwan_win_abi_port(req->sport != 0 ? req->sport : req->dport);
	s->dport = iwan_win_abi_port(req->dport);
	RtlCopyMemory(s->outer_src6, req->outer_src6, 16);
	RtlCopyMemory(s->outer_dst6, req->outer_dst6, 16);
	s->flags = req->flags;
	s->oif_index = req->oif_index;
	s->bind_ip = req->bind_ip;
	RtlCopyMemory(s->bind_ip6, req->bind_ip6, 16);
	s->carrier_index = req->oif_index;
	s->carrier_mtu = carrier_mtu;
	s->inner_ip = req->inner_ip;
	RtlCopyMemory(s->inner_ip6, req->inner_ip6, 16);
	s->inner_mtu = mtu;
	s->effective_mtu = mtu;
	s->targets = targets;
	s->target_count = tcount;

	KeMemoryBarrier();		/* 字段全部就绪后再置 valid */
	s->valid = 1;

	ExReInitializeRundownProtection(&ext->rundown);	/* 放行数据面 */
	KeReleaseMutex(&ext->ctrl_mutex, FALSE);
	return STATUS_SUCCESS;
}

NTSTATUS
iwan_win_session_close(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	/* 与控制面串行，排空数据面后再撤销用户态映射、释放页与目标集合。
	 * 共享内存映射由驱动主动撤销（切到属主进程上下文解映射），所以
	 * 客户端可以在任意时刻关闭，不需要先"放手"那一页。 */
	iwan_win_session_teardown(ext);
	return STATUS_SUCCESS;
}

VOID
iwan_win_session_info(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		      _Out_ IWAN_WIN_SESSION_INFO *info)
{
	IWAN_WIN_SESSION *s = &ext->sess;

	RtlZeroMemory(info, sizeof(*info));
	info->abi_version = IWAN_WIN_ABI_VERSION;
	info->size = sizeof(*info);

	if (!s->valid)
		return;

	info->sid = s->sid;
	info->peer_state = s->shm != NULL ? s->shm->peer_state : IWAN_WIN_PEER_UNKNOWN;
	info->enabled = s->shm != NULL ? s->shm->enabled : 0;
	info->effective_mtu = s->effective_mtu;
	info->carrier_index = s->carrier_index;
	info->dev_owned = (s->flags & IWAN_WIN_FLAG_BIND_INNER) ? 1 : 0;
	info->last_rx_ms = s->shm != NULL ? s->shm->last_rx_ms : 0;
	info->shm_section_size = s->shm != NULL ? PAGE_SIZE : 0;
	info->shm_user_va = (UINT64)(ULONG_PTR)s->shm_user_va;
	info->stats = s->stats;		/* 快照语义：可能落后一个报文，与 Linux 一致 */
}

NTSTATUS
iwan_win_session_query_shm(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			   _Out_ IWAN_WIN_SESSION_INFO *info)
{
	NTSTATUS st;

	KeWaitForSingleObject(&ext->ctrl_mutex, Executive, KernelMode, FALSE, NULL);
	if (!ext->sess.valid) {
		KeReleaseMutex(&ext->ctrl_mutex, FALSE);
		return STATUS_INVALID_DEVICE_STATE;
	}
	st = iwan_win_shm_map_user(&ext->sess);
	if (NT_SUCCESS(st))
		iwan_win_session_info(ext, info);
	KeReleaseMutex(&ext->ctrl_mutex, FALSE);
	return st;
}
