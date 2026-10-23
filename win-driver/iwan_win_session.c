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

/* 封装开销与内层 MTU 上下界：常量已上移到 src/common/iwan_win_abi.h，客户端与
 * 驱动只需一套定义 —— 两处各写一份的结果是"客户端按 36 算、驱动按 38 校验"，
 * 最后表现为偶发的会话建立失败或大包黑洞，而不是一眼可见的编译错误。 */

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
	{
		NTSTATUS ks = ZwCreateKey(&key, KEY_SET_VALUE, &oa, 0, NULL,
					  REG_OPTION_NON_VOLATILE, NULL);

		/* 静默的诊断通道等于没有诊断：键建不出来（路径/权限）时至少让
		 * DbgPrint 留一句，否则现场看起来"什么都没发生"。 */
		if (!NT_SUCCESS(ks)) {
			DbgPrint("iwanmp: trace 键打不开 0x%08lx（stage=%ld）\n",
				 (unsigned long)ks, (long)stage);
			return;
		}
	}

	RtlInitUnicodeString(&vn, L"Stage");
	(void)ZwSetValueKey(key, &vn, 0, REG_DWORD, &stage, sizeof(stage));
	RtlInitUnicodeString(&vn, L"Status");
	if (!NT_SUCCESS(ZwSetValueKey(key, &vn, 0, REG_DWORD, &status,
				      sizeof(status))))
		DbgPrint("iwanmp: trace 写失败（stage=%ld）\n", (long)stage);

	/* 每个阶段再各写一个不会互相覆盖的键（T<十进制阶段号>）：Stage/Status
	 * 只留最后一次，而"哪一步失败"往往要靠更早的那一次才能判读。键名现拼
	 * 而不是写死 switch——阶梯实验会一次写下十几个阶段，写死的表只会让没
	 * 列进去的阶段静默消失，那一轮装机读数就白跑了（踩过）。 */
	{
		WCHAR name[16], digits[12];
		ULONG n = stage, i = 0, t = 0;

		name[i++] = L'T';
		do {
			digits[t++] = (WCHAR)(L'0' + (n % 10u));
			n /= 10u;
		} while (n != 0 && t < RTL_NUMBER_OF(digits));
		while (t > 0)
			name[i++] = digits[--t];
		name[i] = L'\0';
		RtlInitUnicodeString(&vn, name);
		(void)ZwSetValueKey(key, &vn, 0, REG_DWORD, &status,
				    sizeof(status));
	}
	ZwClose(key);
}
#endif /* IWAN_WIN_PLANE_MP */

VOID
iwan_win_ctrl_init(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	KeInitializeMutex(&ext->ctrl_mutex, 0);
	/* 初始为"已放行"状态：数据面会取得保护、看到 valid == 0、立刻放回 */
	ExInitializeRundownProtection(&ext->rundown);
	/* 控制设备的在途 IRP 排空：分发入口 IoAcquireRemoveLock、卸载路径
	 * IoReleaseRemoveLockAndWait。没有它，扩展可能在某个 IOCTL 正用着
	 * &ext->ctrl_mutex / session_open 的时候被 ExFreePoolWithTag 掉
	 * —— IoDeleteDevice/NdisDeregisterDeviceEx 都**不等待**在途 IRP。 */
	IoInitializeRemoveLock(&ext->ctrl_remove_lock, IWAN_TAG_SESS, 0, 0);
	InterlockedExchange(&ext->ctrl_remove_init, 1);
}

VOID
iwan_win_ctrl_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	/* 排空数据面读者后不再放行：卸载路径上调用，之后不会再有人进来 */
	ExWaitForRundownProtectionRelease(&ext->rundown);
}

/* 读服务键下的下一跳 MAC 固化值（REG_BINARY 6 字节）。返回 6 = 读到，
 * 其余 = 未设置/形状不对。只在 IOCTL_SESSION_OPEN（PASSIVE）调用。 */
_Success_(return != 0)
static ULONG
iwan_win_reg_read_mac(_Out_writes_(6) UINT8 *out)
{
	/* 缓冲必须放进结构体里：KEY_VALUE_PARTIAL_INFORMATION 的 Data 是
	 * UCHAR[1]，结构体自身只容得下 12+1 字节，而内核会把 12+DataLength
	 * 都写进调用者的缓冲；用裸 UINT8[] 再强转既不安全（边界靠 sizeof
	 * 撑着）又让分析器认为读的是未初始化内存（C28199）。 */
	typedef struct {
		KEY_VALUE_PARTIAL_INFORMATION hdr;
		UINT8 tail[16];
	} IWAN_WIN_KV_MAC;
	UNICODE_STRING path, vn;
	OBJECT_ATTRIBUTES oa;
	HANDLE key = NULL;
	IWAN_WIN_KV_MAC kv;
	ULONG len = 0;
	NTSTATUS st;

	RtlZeroMemory(&kv, sizeof(kv));
	RtlInitUnicodeString(&path,
			     L"\\Registry\\Machine\\System\\CurrentControlSet"
			     L"\\Services\\iwanmp\\Parameters");
	InitializeObjectAttributes(&oa, &path,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				   NULL, NULL);
	if (!NT_SUCCESS(ZwOpenKey(&key, KEY_READ, &oa)))
		return 0;
	RtlInitUnicodeString(&vn, L"MpPeerMac");
	st = ZwQueryValueKey(key, &vn, KeyValuePartialInformation, &kv,
			     sizeof(kv), &len);
	ZwClose(key);
	if (!NT_SUCCESS(st))
		return 0;
	if (kv.hdr.Type != REG_BINARY || kv.hdr.DataLength != 6)
		return 0;
	RtlCopyMemory(out, kv.hdr.Data, 6);
	return 6;
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
	 * 用户态能轮询时间戳，但改不了内核写的任何字段。
	 *
	 * MmMapLockedPagesSpecifyCache 的 UserMode 变体在映射失败时可以抛异常
	 * （KE 文档与 PREfast C28125 都要求放在 try/except 里）。异常里把 MDL
	 * 收回来：异常路径不能继续持有它，否则每次失败都漏一个 MDL。 */
	va = NULL;
	__try {
		va = MmMapLockedPagesSpecifyCache(mdl, UserMode, MmCached, NULL,
						  FALSE,
						  NormalPagePriority |
						  MdlMappingNoExecute);
	} __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION ||
		    GetExceptionCode() == STATUS_INVALID_PARAMETER
		    ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
		/* 只吞这两族：它们是“这一个用户 VA 不可用”的确定答复，别的异常
		 * （栈溢出、页错误链断掉等）属于本函数不该承担的故障，往上抛。 */
		va = NULL;
	}
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
	ULONG need, bytes, cnt, off;

	*out = NULL;
	*out_count = 0;

	if (req->target_count == 0)
		return STATUS_SUCCESS;
	if (req->target_count > IWAN_WIN_MAX_TARGETS)
		return STATUS_INVALID_PARAMETER;

	/* 逐条 sizeof(IWAN_WIN_TARGET) 字节、条数上限 IWAN_WIN_MAX_TARGETS。
	 * 分配与拷贝都只用同一个局部量 bytes：这样“分配了多少”与“拷了多少”
	 * 在源码上就是同一个数（C6385 的成因正是二者被当成两个表达式）。 */
	cnt = req->target_count;
	bytes = cnt * (ULONG)sizeof(IWAN_WIN_TARGET);
	need = req->target_offset + bytes;
	if (req->target_offset < sizeof(IWAN_WIN_SESSION_OPEN) ||
	    need < req->target_offset || need > in_len)
		return STATUS_INVALID_PARAMETER;

	targets = (IWAN_WIN_TARGET *)IWAN_ALLOC(bytes, IWAN_TAG_TARGET);
	if (targets == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlCopyMemory(targets, (const UINT8 *)req + req->target_offset, bytes);

	/* 按字节偏移走，而不是按条数下标走：循环条件直接就是
	 *   off + 一条 <= bytes
	 * 与下面每次读写的上界是同一个表达式，静态分析不必再自己把
	 * "cnt 条 × 每条的字节数" 乘回去（C6385 报的就是它乘不动）。
	 * off 每次加 sizeof(IWAN_WIN_TARGET)（24 字节），池分配 16 字节对齐，
	 * 所以每个 t 都是对齐的。 */
	for (off = 0; off + sizeof(IWAN_WIN_TARGET) <= bytes;
	     off += sizeof(IWAN_WIN_TARGET)) {
		IWAN_WIN_TARGET *t = (IWAN_WIN_TARGET *)((UINT8 *)targets + off);

		if (t->family == IWAN_WIN_AF_V4) {
			if (t->prefix_len > 32) {
				ExFreePoolWithTag(targets, IWAN_TAG_TARGET);
				return STATUS_INVALID_PARAMETER;
			}
			/* v4 条目只允许用前 4 字节，其余清零：避免同一前缀
			 * 因为垃圾字节被当成两条。 */
			RtlZeroMemory(t->addr + 4, 12);
		} else if (t->family == IWAN_WIN_AF_V6) {
			if (t->prefix_len > 128) {
				ExFreePoolWithTag(targets, IWAN_TAG_TARGET);
				return STATUS_INVALID_PARAMETER;
			}
		} else {
			ExFreePoolWithTag(targets, IWAN_TAG_TARGET);
			return STATUS_INVALID_PARAMETER;
		}
	}

	*out = targets;
	*out_count = cnt;
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
	       RtlCompareMemory(s->outer_if_guid, req->outer_if_guid, 16) == 16 &&
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
	RtlCopyMemory(s->outer_if_guid, req->outer_if_guid, 16);
	/* 测试旋钮：Parameters\MpPeerMac（REG_BINARY 6 字节）给死下一跳 MAC。
	 * 存在理由：某些承载（KM-TEST 回环）根本不回 ARP，而有回包的链路又
	 * 会把报文送出虚拟网卡，二者都无法在没有邻居的情况下跑通数据面；
	 * 给死 MAC 才能把"数据面本身能跑多快"与"ARP 能不能解析"解耦。
	 * 生产路径不设这个键时行为完全不变（照常 ARP）。 */
	{
		UINT8 mac[6];

		s->peer_mac_fixed_valid = 0;
		if (iwan_win_reg_read_mac(mac) == 6) {
			RtlCopyMemory(s->peer_mac_fixed, mac, 6);
			s->peer_mac_fixed_valid = 1;
		}
	}
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

	/* 调用者可能已经持锁（query_shm 就在锁内调本函数）：KMUTEX 可递归，
	 * 多取一次多放一次即可。不取锁就会与 CLOSE 的
	 * iwan_win_session_reset → iwan_win_shm_destroy → ExFreePoolWithTag(s->shm)
	 * 竞态，读到已释放的共享页（shm 是普通非分页池，普通池页仍映射，所以
	 * 平时不立刻崩，开 Driver Verifier 或特殊池就直接蓝屏）。 */
	KeWaitForSingleObject(&ext->ctrl_mutex, Executive, KernelMode, FALSE, NULL);
	RtlZeroMemory(info, sizeof(*info));
	info->abi_version = IWAN_WIN_ABI_VERSION;
	info->size = sizeof(*info);

	if (!s->valid) {
		KeReleaseMutex(&ext->ctrl_mutex, FALSE);
		return;
	}

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
	KeReleaseMutex(&ext->ctrl_mutex, FALSE);
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
