/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_session.c - session, target set, statistics and shared memory page.
 *
 * Corresponds to the Linux side: struct iwan_session (kernel/iwan.h), the genetlink
 * SESSION_UP/SESSION_DOWN/GET_STATS, and the /dev/iwan page (kernel/iwan_shm.c).
 *
 * Concurrency model, see the top comment of iwan_win.h: the control plane (this file) at PASSIVE_LEVEL
 * serializes with ctrl_mutex; the data plane takes rundown protection before reading session state. The two hand over via
 * ExWaitForRundownProtectionRelease / ExReInitializeRundownProtection,
 * so this file can safely do pool allocation, user address map/unmap and waiting on process exit status.
 */
#include "iwan_win.h"

/* Encapsulation overhead and inner MTU bounds: constants moved up to src/common/iwan_win_abi.h, client and
 * driver need only one definition -- with a copy in each place the result is 'client computes 36, driver validates 38',
 * ending up as occasional session setup failures or big-packet black holes, not a compile error visible at a glance. */

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

/* ---- TX rejection samples (shared page diagnostic area) ----------------- */

/*
 * Write only, never decide; user mode reads them via SHM_QUERY (layout in src/common/iwan_win_abi.h).
 * Both data planes (WFP plane iwan.sys and NDIS plane iwanmp.sys) share this one implementation:
 * the field layout and write order of a record are the only basis for field diagnostics; any divergence makes the two
 * readings incomparable. Written only on rejection paths, zero cost on the normal path.
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
	/* Increment the sequence only after all fields are written: readers use it to tell the record was updated (write-then-mark is the convention) */
	InterlockedIncrement((volatile LONG *)&d->seq);
}

/* ---- Control plane infrastructure --------------------------------------- */

#ifdef IWAN_WIN_PLANE_MP
/*
 * Failure diagnostics for the DriverEntry stage.
 *
 * When driver loading fails there is no user-mode channel at all: the control device is not created yet, the event log would need
 * IoAllocateErrorLogEntry, and there is no kernel debugger on the guest either. As a fallback, write 'which step was reached,
 * and the status code of that step' into the Parameters subkey of the service key (two REG_DWORDs), so a single
 * reg query on the guest reads it, and it survives a reboot.
 *
 * Called only on the registration and init paths; the data plane does not touch it.
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

		/* A silent diagnostic channel equals no diagnostics: when the key cannot be created (path/permission), at least let
		 * DbgPrint leave one line, otherwise the field looks like 'nothing happened'. */
		if (!NT_SUCCESS(ks)) {
			DbgPrint("iwanmp: cannot open trace key 0x%08lx (stage=%ld)\n",
				 (unsigned long)ks, (long)stage);
			return;
		}
	}

	RtlInitUnicodeString(&vn, L"Stage");
	(void)ZwSetValueKey(key, &vn, 0, REG_DWORD, &stage, sizeof(stage));
	RtlInitUnicodeString(&vn, L"Status");
	if (!NT_SUCCESS(ZwSetValueKey(key, &vn, 0, REG_DWORD, &status,
				      sizeof(status))))
		DbgPrint("iwanmp: trace write failed (stage=%ld)\n", (long)stage);

	/* Each stage also writes its own non-overlapping key (T<decimal stage number>): Stage/Status
	 * keep only the last one, while 'which step failed' often requires an earlier one to interpret. Key names are composed
	 * on the fly instead of a hard-coded switch -- a stepwise experiment writes a dozen stages at once, and a hard-coded table would make
	 * unlisted stages silently disappear; that install round's readings would be wasted (been there). */
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
	/* Initially in the 'released' state: the data plane takes protection, sees valid == 0, and returns immediately */
	ExInitializeRundownProtection(&ext->rundown);
	/* Drain in-flight IRPs of the control device: dispatch entry does IoAcquireRemoveLock, unload path
	 * IoReleaseRemoveLockAndWait. Without it, the extension could be ExFreePoolWithTag'd while some IOCTL is still using
	 * &ext->ctrl_mutex / session_open
	 * -- IoDeleteDevice/NdisDeregisterDeviceEx both **do not wait** for in-flight IRPs. */
	IoInitializeRemoveLock(&ext->ctrl_remove_lock, IWAN_TAG_SESS, 0, 0);
	InterlockedExchange(&ext->ctrl_remove_init, 1);
}

VOID
iwan_win_ctrl_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	/* After draining data-plane readers, block further entry: called on the unload path, nobody comes in afterwards */
	ExWaitForRundownProtectionRelease(&ext->rundown);
}

/* The Parameters subkey of this image's own service, i.e. where the diagnostics below are read from.
 * It must follow the plane: iwan.sys (WFP) lives under Services\iwan and iwanmp.sys under Services\iwanmp. Reading the
 * other image's key is a silent failure mode by construction -- the knob exists, the driver starts, and the value simply
 * never takes effect -- so the path is not spelled out twice in the code. */
#ifdef IWAN_WIN_PLANE_MP
#define IWAN_WIN_PARAM_KEY \
	L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\iwanmp\\Parameters"
#else
#define IWAN_WIN_PARAM_KEY \
	L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\iwan\\Parameters"
#endif

/* Read the pinned next-hop MAC from the service key (REG_BINARY 6 bytes). Returns 6 = read,
 * anything else = not set / bad shape. Only called from IOCTL_SESSION_OPEN (PASSIVE). */
_Success_(return != 0)
static ULONG
iwan_win_reg_read_mac(_Out_writes_(6) UINT8 *out)
{
	/* The buffer must live inside the struct: KEY_VALUE_PARTIAL_INFORMATION's Data is
	 * UCHAR[1], the struct itself holds only 12+1 bytes, while the kernel writes 12+DataLength
	 * into the caller's buffer; casting a naked UINT8[] is both unsafe (bounds rest on sizeof)
	 * and makes the analyzer think uninitialized memory is read (C28199). */
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
	RtlInitUnicodeString(&path, IWAN_WIN_PARAM_KEY);
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

/* Read a REG_DWORD diagnostic switch from the Parameters subkey of this image's service key.
 * Returns TRUE = read (value is stored in *out), FALSE = not set / wrong shape (the caller keeps its default).
 * Only called from IOCTL_SESSION_OPEN (PASSIVE).
 * _Success_(return != 0) is not decoration: FALSE is a normal outcome here ("value absent"), and without the
 * annotation PREfast reads the _Out_ contract literally and reports C6101 "returning uninitialized memory" on the
 * FALSE paths (every early return). The annotation is exactly what the analyzer asks for. */
_Success_(return != 0)
static BOOLEAN
iwan_win_reg_read_dword(_In_ PCWSTR name, _Out_ UINT32 *out)
{
	typedef struct {
		KEY_VALUE_PARTIAL_INFORMATION hdr;
		UINT8 tail[8];
	} IWAN_WIN_KV_DWORD;
	UNICODE_STRING path, vn;
	OBJECT_ATTRIBUTES oa;
	HANDLE key = NULL;
	IWAN_WIN_KV_DWORD kv;
	ULONG len = 0;
	NTSTATUS st;

	RtlZeroMemory(&kv, sizeof(kv));
	RtlInitUnicodeString(&path, IWAN_WIN_PARAM_KEY);
	InitializeObjectAttributes(&oa, &path,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				   NULL, NULL);
	if (!NT_SUCCESS(ZwOpenKey(&key, KEY_READ, &oa)))
		return FALSE;
	RtlInitUnicodeString(&vn, name);
	st = ZwQueryValueKey(key, &vn, KeyValuePartialInformation, &kv,
			     sizeof(kv), &len);
	ZwClose(key);
	if (!NT_SUCCESS(st) || kv.hdr.Type != REG_DWORD ||
	    kv.hdr.DataLength != sizeof(UINT32))
		return FALSE;
	RtlCopyMemory(out, kv.hdr.Data, sizeof(UINT32));
	return TRUE;
}

/* ---- Shared memory page (the page corresponding to /dev/iwan mmap) ------ */

static NTSTATUS
iwan_win_shm_create(_Inout_ IWAN_WIN_SESSION *s)
{
	s->shm = (IWAN_WIN_SHM *)IWAN_ALLOC(PAGE_SIZE, IWAN_TAG_SHM);
	if (s->shm == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(s->shm, PAGE_SIZE);
	s->shm->version = IWAN_WIN_SHM_VERSION;
	s->shm->pad = 0;
	s->shm->last_rx_ms = 0;			/* 0 = never received */
	s->shm->peer_state = IWAN_WIN_PEER_UNKNOWN;
	s->shm->enabled = 1;
	return STATUS_SUCCESS;
}

/*
 * Revoke the user-mode mapping. The mapping exists only in the owner process's address space, so we must switch to its context
 * to unmap; when the owner has already exited the address space is destroyed with it and only the MDL needs freeing.
 * The owner process object was referenced when the mapping was created (see shm_map_user), so PID reuse does not matter.
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
	iwan_win_shm_unmap_user(s);		/* unmap first, then free the page */
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
		/* One page is mapped to only one process: a mapping address is meaningless in another process */
		if (s->shm_owner != owner)
			return STATUS_DEVICE_BUSY;
		return STATUS_SUCCESS;
	}

	mdl = IoAllocateMdl(s->shm, PAGE_SIZE, FALSE, FALSE, NULL);
	if (mdl == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	MmBuildMdlForNonPagedPool(mdl);
	mdl->MdlFlags |= MDL_MAPPING_CAN_FAIL;

	/* The UserMode mapping is read-only (matching the Linux mmap that grants PROT_READ only):
	 * user mode can poll the timestamp but cannot change any field written by the kernel.
	 *
	 * The UserMode variant of MmMapLockedPagesSpecifyCache can raise on mapping failure
	 * (KE docs and PREfast C28125 both require wrapping it in try/except). In the exception path take the MDL
	 * back: the exception path must not keep holding it, otherwise every failure leaks one MDL. */
	va = NULL;
	__try {
		va = MmMapLockedPagesSpecifyCache(mdl, UserMode, MmCached, NULL,
						  FALSE,
						  NormalPagePriority |
						  MdlMappingNoExecute);
	} __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION ||
		    GetExceptionCode() == STATUS_INVALID_PARAMETER
		    ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
		/* Swallow only these two families: they are the definite answer that 'this one user VA is unusable'; other exceptions
		 * (stack overflow, broken page-fault chain, etc.) are failures this function should not own, so throw them up. */
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

/* ---- Data plane accounting (only place that writes the shared memory page) */

VOID
iwan_win_session_mark_rx(_Inout_ IWAN_WIN_SESSION *s, _In_ UINT32 is_ctrl)
{
	volatile LONG64 *slot;

	if (s->shm == NULL)
		return;

	/*
	 * No lock: only the driver writes, user mode only reads. The timestamp is a single 8-byte write (atomic on x64),
	 * counters use interlocked increment, so the data plane has no per-packet lock cost -- same direction as the Linux module.
	 */
	s->shm->last_rx_ms = iwan_win_now_ms();
	s->shm->peer_state = IWAN_WIN_PEER_UP;
	slot = is_ctrl ? (volatile LONG64 *)&s->shm->rx_ctrl_frame
		       : (volatile LONG64 *)&s->shm->rx_frames;
	InterlockedIncrement64((volatile LONG64 *)slot);
}

/*
 * Peer PT_CLOSE: zero the shared page timestamp and set peer_state to closed.
 * User-mode liveness only looks at the timestamp (zero = disconnected), so this write must land before the CLOSE frame
 * is released -- same semantics as iwan_ev_peer_close in kernel/iwan_rx.c
 * (the kernel overwrites the PT_CLOSE timestamp with 0).
 */
VOID
iwan_win_session_mark_close(_Inout_ IWAN_WIN_SESSION *s)
{
	if (s == NULL || s->shm == NULL)
		return;
	s->shm->last_rx_ms = 0;
	s->shm->peer_state = IWAN_WIN_PEER_CLOSED;
	KeMemoryBarrier();
	/* Do not count here: the call site has already gone through mark_rx(s, 1) (mirror counting on the shared page)
	 * and recorded driver-side stats separately; this only handles 'zero the timestamp + mark closed'. */
}

/* ---- Target set: longest prefix match ----------------------------------- */

/* ---- Session lifecycle -------------------------------------------------- */

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
	ExWaitForRundownProtectionRelease(&ext->rundown);	/* drain the data plane */
	iwan_win_session_reset(&ext->sess);
	ExReInitializeRundownProtection(&ext->rundown);		/* allow entry again (no session at this point) */
	KeReleaseMutex(&ext->ctrl_mutex, FALSE);
}

/* Copy and normalize the target set in the request; on failure return an error code, on success return the array (may be NULL) */
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

	/* sizeof(IWAN_WIN_TARGET) bytes each, count capped at IWAN_WIN_MAX_TARGETS.
	 * Both allocation and copy use the same local variable bytes: thus 'how much was allocated' and 'how much was copied'
	 * are the same number in the source (the cause of C6385 is exactly that they were treated as two expressions). */
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

	/* Walk by byte offset rather than by item index: the loop condition is directly
	 *   off + one item <= bytes
	 * which is the same expression as the upper bound of every read/write below, so static analysis need not multiply
	 * 'cnt items x bytes per item' back itself (C6385 reports exactly that it cannot do the multiplication).
	 * off advances by sizeof(IWAN_WIN_TARGET) (24 bytes) each time; pool allocation is 16-byte aligned,
	 * so every t is aligned. */
	for (off = 0; off + sizeof(IWAN_WIN_TARGET) <= bytes;
	     off += sizeof(IWAN_WIN_TARGET)) {
		IWAN_WIN_TARGET *t = (IWAN_WIN_TARGET *)((UINT8 *)targets + off);

		if (t->family == IWAN_WIN_AF_V4) {
			if (t->prefix_len > 32) {
				ExFreePoolWithTag(targets, IWAN_TAG_TARGET);
				return STATUS_INVALID_PARAMETER;
			}
			/* For a v4 entry only the first 4 bytes are used, the rest is zeroed: avoid the same prefix
			 * being taken as two entries because of garbage bytes. */
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
 * Ports in the ABI are 'network-order bytes' (iwan_win_abi.h states be16; the Windows client stores
 * sockaddr's sin_port directly, which is already network order). Internally the session unifies on **big-endian integers** as the single representation,
 * consistent with IWAN_WIN_OUTER.sport/dport (the value read by iwan_win_rd16):
 *   - TX uses iwan_win_wr16 to write bytes back, yielding the correct outer port;
 *   - the RX gate compares the port read by iwan_win_rd16 directly.
 * It used to be used as-is as uint16, which equals one byte-order mismatch between the two sides: the RX gate never matches -> everything passes,
 * outer frames are delivered all the way to the user-mode socket; the port encapsulated on TX is reversed too.
 */
static USHORT
iwan_win_abi_port(_In_ USHORT be)
{
	return iwan_win_rd16((const UINT8 *)&be);
}

/* Same for v4 addresses: the ABI holds network-order bytes, internally unified to big-endian integers (the
 * parameters of iwan_win_outer_hdr4 and the WFP fixed fields IP_LOCAL/REMOTE_ADDRESS use this representation). */
static UINT32
iwan_win_abi_addr(_In_ UINT32 be)
{
	return iwan_win_rd32((const UINT8 *)&be);
}

/* Whether the parameters are exactly identical (used for SESSION_OPEN idempotent semantics) */
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

	/* MTU: the client reports the carrier NIC MTU along with the request (Windows has no netns, the driver
	 * does no FIB lookup); the driver validates 'inner + overhead <= carrier' and derives the effective value --
	 * same criterion as the Linux session setup. Outer v6 is not fragmented, so this must be enforced even harder. */
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
		/* Idempotent: the same request sent again returns the existing session */
		KeReleaseMutex(&ext->ctrl_mutex, FALSE);
		if (targets != NULL)
			ExFreePoolWithTag(targets, IWAN_TAG_TARGET);
		return STATUS_SUCCESS;
	}

	/* From here the session state will be modified: drain the data plane first; until
	 * ExReInitializeRundownProtection, the data plane returns 'not handled' immediately. */
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
	/* Test knob: Parameters\MpPeerMac (REG_BINARY 6 bytes) pins the next-hop MAC.
	 * Rationale: some carriers (KM-TEST loopback) never answer ARP, and links that do reply
	 * send packets out the virtual NIC instead; neither can run the data plane without a neighbor;
	 * pinning the MAC decouples 'how fast the data plane itself can go' from 'whether ARP resolves'.
	 * When this key is not set, the production path behaves exactly the same (normal ARP). */
	{
		UINT8 mac[6];

		s->peer_mac_fixed_valid = 0;
		if (iwan_win_reg_read_mac(mac) == 6) {
			RtlCopyMemory(s->peer_mac_fixed, mac, 6);
			s->peer_mac_fixed_valid = 1;
		}
	}
	/* Diagnostic pass-through: Parameters\PassThrough (REG_DWORD, bits IWAN_WIN_PASS_TX / IWAN_WIN_PASS_RX).
	 * Read at session setup rather than at load so that switching it needs no driver reload (a reload costs a reboot on this
	 * platform, see the NdisRegisterDeviceEx note). Absent = 0 = normal forwarding, bit-for-bit the old behavior.
	 * Whatever the previous session left behind is cleared first: a stale 1 must never survive into a new session. */
	ext->pass_through = 0;
	{
		UINT32 pt = 0;

		if (iwan_win_reg_read_dword(L"PassThrough", &pt))
			ext->pass_through = pt;
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

	KeMemoryBarrier();		/* set valid only after all fields are ready */
	s->valid = 1;

	ExReInitializeRundownProtection(&ext->rundown);	/* allow the data plane in */
	KeReleaseMutex(&ext->ctrl_mutex, FALSE);
	return STATUS_SUCCESS;
}

NTSTATUS
iwan_win_session_close(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	/* Serialize with the control plane, drain the data plane, then revoke the user-mode mapping, free the page and target set.
	 * The shared memory mapping is revoked by the driver itself (switch to the owner process context to unmap), so
	 * the client can close at any time without 'letting go' of that page first. */
	iwan_win_session_teardown(ext);
	return STATUS_SUCCESS;
}

VOID
iwan_win_session_info(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		      _Out_ IWAN_WIN_SESSION_INFO *info)
{
	IWAN_WIN_SESSION *s = &ext->sess;

	/* The caller may already hold the lock (query_shm calls this inside the lock): KMUTEX is recursive,
	 * so taking it once more and releasing once more is fine. Without the lock it would race with CLOSE's
	 * iwan_win_session_reset -> iwan_win_shm_destroy -> ExFreePoolWithTag(s->shm)
	 * and read a freed shared page (shm is ordinary non-paged pool, ordinary pool pages stay mapped, so
	 * it usually does not crash immediately, but Driver Verifier or special pool gives a direct BSOD). */
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
	info->stats = s->stats;		/* snapshot semantics: may lag by one packet, same as Linux */
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
