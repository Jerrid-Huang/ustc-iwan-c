/*
 * iwan_cnt.c -- counting-only, echo-capable virtual Ethernet NIC (iwancnt.sys)
 *
 * Purpose: give the Windows data plane a peer that "does not go through QEMU slirp or user space", so the tunnel
 * can run at line rate and be counted frame by frame. It is an 802.3 miniport:
 *
 *   - send path: every frame handed down by the stack is counted (split into "to the peer" and "from the peer"),
 *     which is the load the tunnel actually pushes;
 *   - bridging: install two of these NICs (A, B); each copies frames with "destination IP = PeerIp", rewrites
 *     the Ethernet header (source = this NIC, destination = peer NIC's MAC) and indicates them on the peer NIC, which amounts to a cable;
 *     with a user-space endpoint on each end (client / counting server) you can measure both directions;
 *   - ARP: answer on behalf of PeerIp -- tcpip does not consider that address local, so without answering
 *     the next hop never resolves;
 *   - counters are exposed only through NDIS statistics (Get-NetAdapterStatistics reads them directly); no
 *     control device is created and no shared memory is opened: less code means less chance of hanging the machine.
 *
 * Parameters (HKLM\SYSTEM\CurrentControlSet\Services\iwancnt\Parameters):
 *   Disarm   DWORD default 1 (fuse closed). When 1, InitializeEx fails outright: the driver
 *                  is installed but does not work -- the lesson from one bad registration that kept the machine from booting.
 *   PeerIp   SZ    default "10.200.0.1", the peer address: answer ARP for it and bridge frames
 *                  destined for it to the other instance. Each of the two NICs just fills in the other's address.
 *   Bridge   DWORD default 1: when 0, count only and do not bridge (pure "count the peer only").
 *   Mac      SZ    default "02-00-49-57-41-4e".
 *
 * Scope: iwan.sys is the WFP plane and iwanmp.sys is the NDIS plane; this driver belongs to neither,
 * it is just the NIC at their far end.
 */

#include <ndis.h>

#define IWAN_CNT_TAG            'TNCW'
#define IWAN_CNT_MTU            1500u
#define IWAN_CNT_NBL_CTX_SIZE   16u
#define IWAN_CNT_LINK_SPEED     10000000000ULL
/* Diagnostic key, resolved from the registry path DriverEntry was given: a hard-wired
 * Services\iwancnt\Parameters made a second instance (iwancnt2) write its stages into the
 * first instance's key, which reads as "the new image never ran" when it did. */
static UNICODE_STRING g_cnt_param_path;

#define IWAN_CNT_ETH_HDR        14u
#define IWAN_CNT_ETH_IPV4       0x0800u
#define IWAN_CNT_ETH_ARP        0x0806u
#define IWAN_CNT_HDR_SNIFF      64u

typedef struct _IWAN_CNT_NBL_CTX {
	UCHAR                          *buf;
	PMDL                            mdl;
} IWAN_CNT_NBL_CTX, *PIWAN_CNT_NBL_CTX;

typedef struct _IWAN_CNT_ADAPTER {
	NDIS_HANDLE                     adapter_handle;
	NDIS_HANDLE                     nbl_pool;
	volatile LONG                   running;
	volatile LONG                   inflight;
	UCHAR                           mac[6];
	LIST_ENTRY                      link;		/* global instance list */
	ULONG                           peer_ip;	/* same byte order as the bytes in the frame */
	volatile LONG                   bridge;
	volatile LONG64                 tx_frames;
	volatile LONG64                 tx_bytes;
	volatile LONG64                 peer_in_frames;
	volatile LONG64                 peer_out_frames;
	volatile LONG64                 rx_frames;	/* frames bridged to the peer instance */
	volatile LONG64                 rx_bytes;
	volatile LONG64                 arp_req;
	volatile LONG64                 arp_rep;
	volatile LONG64                 drops;
	volatile LONG64                 other_frames;
} IWAN_CNT_ADAPTER, *PIWAN_CNT_ADAPTER;

/*
 * Instance table: several NICs of the same driver bridge to each other (the Windows veth pair). The list and lock are
 * initialized in DriverEntry and afterwards only inserted/removed, never moved.
 */
#define IWAN_CNT_MAX_PEERS 8u

static LIST_ENTRY g_cnt_list;
static KSPIN_LOCK g_cnt_lock;
static BOOLEAN g_cnt_list_ready;

static VOID iwan_cnt_trace(_In_ ULONG stage, _In_ LONG status);

/* ---- Byte-order helpers ---------------------------------------------------- */

static UINT16
iwan_cnt_rd16(_In_reads_bytes_(2) const UCHAR *p)
{
	return (UINT16)(((UINT16)p[0] << 8) | (UINT16)p[1]);
}

static UINT32
iwan_cnt_rd32(_In_reads_bytes_(4) const UCHAR *p)
{
	return ((UINT32)p[0] << 24) | ((UINT32)p[1] << 16) |
	       ((UINT32)p[2] << 8) | (UINT32)p[3];
}

static VOID
iwan_cnt_wr16(_Out_writes_bytes_(2) UCHAR *p, _In_ UINT16 v)
{
	p[0] = (UCHAR)(v >> 8);
	p[1] = (UCHAR)(v & 0xFF);
}

static VOID
iwan_cnt_wr32(_Out_writes_bytes_(4) UCHAR *p, _In_ UINT32 v)
{
	p[0] = (UCHAR)(v >> 24);
	p[1] = (UCHAR)((v >> 16) & 0xFF);
	p[2] = (UCHAR)((v >> 8) & 0xFF);
	p[3] = (UCHAR)(v & 0xFF);
}

static UINT16
iwan_cnt_csum(_In_reads_bytes_(len) const UCHAR *p, _In_ ULONG len)
{
	UINT32 sum = 0;
	ULONG i;

	for (i = 0; i + 1 < len; i += 2)
		sum += ((UINT32)p[i] << 8) | (UINT32)p[i + 1];
	if (i < len)
		sum += ((UINT32)p[i] << 8);
	while ((sum >> 16) != 0)
		sum = (sum & 0xFFFFu) + (sum >> 16);
	return (UINT16)(~sum & 0xFFFFu);
}

static VOID
iwan_cnt_ip4_csum(_Inout_updates_bytes_(20) UCHAR *ip)
{
	ULONG ihl = (ULONG)(ip[0] & 0x0Fu) * 4;

	if (ihl < 20)
		return;
	iwan_cnt_wr16(ip + 10, 0);
	iwan_cnt_wr16(ip + 10, iwan_cnt_csum(ip, ihl));
}

/* ---- Registry parameters and stage tracing -------------------------------------------- */

/*
 * Open the parameter key. Prefer "this device instance's driver key" (Class\{4D36E972..}\00NN):
 * bridging needs two NICs and each must have its own PeerIp and MAC; the service key is global, so
 * two instances would read the same configuration and never bridge together. If the driver key is unavailable, fall back to the service key,
 * and the single-NIC (counting-only) case still works.
 */
static BOOLEAN
iwan_cnt_open_params(_In_ NDIS_HANDLE adapter_handle, _Out_ HANDLE *key)
{
	PDEVICE_OBJECT pdo = NULL;
	UNICODE_STRING path;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS st;

	NdisMGetDeviceProperty(adapter_handle, &pdo, NULL, NULL, NULL, NULL);
	if (pdo != NULL) {
		st = IoOpenDeviceRegistryKey(pdo, PLUGPLAY_REGKEY_DRIVER,
					     KEY_READ, key);
		if (NT_SUCCESS(st)) {
			/* The INF puts Disarm/Bridge/PeerIp/Mac under the "Parameters" subkey of the
			 * driver key (same shape as Services\<name>\Parameters); open that, and fall
			 * back to the key root when it is absent. Reading only the root made the fuse
			 * unfixable: the INF wrote into Parameters, the driver looked at the root, saw
			 * nothing and kept its "disarmed" default forever (device stayed at Code 10). */
			HANDLE sub = NULL;
			UNICODE_STRING pn;
			OBJECT_ATTRIBUTES sa;

			RtlInitUnicodeString(&pn, L"Parameters");
			InitializeObjectAttributes(&sa, &pn,
						   OBJ_CASE_INSENSITIVE |
							   OBJ_KERNEL_HANDLE,
						   *key, NULL);
			if (NT_SUCCESS(ZwOpenKey(&sub, KEY_READ, &sa))) {
				ZwClose(*key);
				*key = sub;
			}
			return TRUE;
		}
	}

	if (g_cnt_param_path.Buffer == NULL)
		return FALSE;
	path = g_cnt_param_path;
	InitializeObjectAttributes(&oa, &path,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				   NULL, NULL);
	st = ZwOpenKey(key, KEY_READ, &oa);
	return (BOOLEAN)NT_SUCCESS(st);
}

static ULONG
iwan_cnt_param_u32(_In_ HANDLE key, _In_ PCWSTR name, _In_ ULONG dflt)
{
	UNICODE_STRING vn;
	UCHAR buf[64];
	ULONG need = 0;
	PKEY_VALUE_PARTIAL_INFORMATION pi;

	/* Zeroing is only so that the analyzer sees "buffer initialized"; the real layout is guaranteed by the API contract:
	 * on success ZwQueryValueKey writes back a KEY_VALUE_PARTIAL_INFORMATION. */
	RtlZeroMemory(buf, sizeof(buf));
	RtlInitUnicodeString(&vn, name);
	if (!NT_SUCCESS(ZwQueryValueKey(key, &vn, KeyValuePartialInformation,
					buf, sizeof(buf), &need)))
		return dflt;
	pi = (PKEY_VALUE_PARTIAL_INFORMATION)(PVOID)buf;
	/* C28199: the analyzer thinks buf is never assigned, but ZwQueryValueKey fills it per contract. */
#pragma warning(suppress: 28199)
	if (pi->Type != REG_DWORD || pi->DataLength < sizeof(ULONG))
		return dflt;
	return *(const ULONG *)(PVOID)pi->Data;
}

static BOOLEAN
iwan_cnt_param_str(_In_ HANDLE key, _In_ PCWSTR name,
		   _Out_writes_(cap) WCHAR *out, _In_ ULONG cap)
{
	UNICODE_STRING vn;
	UCHAR buf[256];
	ULONG need = 0;
	PKEY_VALUE_PARTIAL_INFORMATION pi;
	ULONG n;

	RtlZeroMemory(buf, sizeof(buf));
	if (cap == 0)
		return FALSE;
	out[0] = L'\0';
	RtlInitUnicodeString(&vn, name);
	if (!NT_SUCCESS(ZwQueryValueKey(key, &vn, KeyValuePartialInformation,
					buf, sizeof(buf), &need)))
		return FALSE;
	pi = (PKEY_VALUE_PARTIAL_INFORMATION)(PVOID)buf;
#pragma warning(suppress: 28199)
	if (pi->Type != REG_SZ || pi->DataLength < sizeof(WCHAR))
		return FALSE;
	n = (pi->DataLength / sizeof(WCHAR)) - 1;
	if (n >= cap)
		n = cap - 1;
	RtlCopyMemory(out, pi->Data, n * sizeof(WCHAR));
	out[n] = L'\0';
	return TRUE;
}

/* "10.200.0.1" -> 0x0AC80001 (same order as iwan_cnt_rd32: byte-stream order). */
static ULONG
iwan_cnt_parse_ip(_In_ PCWSTR s)
{
	ULONG part = 0, npart = 0, out = 0, v = 0, i;

	for (i = 0;; i++) {
		WCHAR c = s[i];

		if (c >= L'0' && c <= L'9') {
			part = part * 10u + (ULONG)(c - L'0');
			if (part > 255u)
				return 0;
			v = 1;
			continue;
		}
		if (c != L'.' && c != L'\0')
			return 0;
		if (v == 0 || npart >= 4)
			return 0;
		out = (out << 8) | part;
		npart++;
		part = 0;
		v = 0;
		if (c == L'\0')
			break;
	}
	return (npart == 4) ? out : 0;
}

static BOOLEAN
iwan_cnt_parse_mac(_In_ PCWSTR s, _Out_writes_(6) UCHAR *mac)
{
	ULONG i, nibbles = 0;
	LONG hi = -1;

	/* The output is meaningless on FALSE; zeroing keeps both the analyzer and the caller from guessing. */
	RtlZeroMemory(mac, 6);

	for (i = 0;; i++) {
		WCHAR c = s[i];
		ULONG v;

		if (c == L'\0')
			return (BOOLEAN)(nibbles == 12 && hi < 0);
		if (c == L'-' || c == L':') {
			if (hi >= 0)
				return FALSE;
			continue;
		}
		if (c >= L'0' && c <= L'9')
			v = (ULONG)(c - L'0');
		else if (c >= L'a' && c <= L'f')
			v = (ULONG)(c - L'a') + 10u;
		else if (c >= L'A' && c <= L'F')
			v = (ULONG)(c - L'A') + 10u;
		else
			return FALSE;
		if (hi < 0) {
			hi = (LONG)v;
			continue;
		}
		if (nibbles >= 12)
			return FALSE;
		mac[nibbles / 2] = (UCHAR)(((ULONG)hi << 4) | v);
		nibbles += 2;
		hi = -1;
	}
}

static VOID
iwan_cnt_trace(_In_ ULONG stage, _In_ LONG status)
{
	UNICODE_STRING path, vn;
	OBJECT_ATTRIBUTES oa;
	HANDLE key = NULL;
	WCHAR name[16];
	WCHAR digits[12];
	ULONG n = stage, t = 0, i = 0;
	ULONG v = (ULONG)status;

	if (g_cnt_param_path.Buffer == NULL)
		return;
	path = g_cnt_param_path;
	InitializeObjectAttributes(&oa, &path,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				   NULL, NULL);
	if (!NT_SUCCESS(ZwCreateKey(&key, KEY_SET_VALUE, &oa, 0, NULL,
				    REG_OPTION_VOLATILE, NULL))) {
		DbgPrint("iwancnt: trace key unavailable (stage=%lu)\n",
			 (unsigned long)stage);
		return;
	}
	RtlInitUnicodeString(&vn, L"Stage");
	ZwSetValueKey(key, &vn, 0, REG_DWORD, &stage, sizeof(stage));
	RtlInitUnicodeString(&vn, L"Status");
	ZwSetValueKey(key, &vn, 0, REG_DWORD, &v, sizeof(v));

	/* Key name T<decimal stage number>: a hard-coded switch would silently lose unlisted stages. */
	name[i++] = L'T';
	if (n == 0)
		digits[t++] = L'0';
	while (n != 0 && t < RTL_NUMBER_OF(digits)) {
		digits[t++] = (WCHAR)(L'0' + (n % 10u));
		n /= 10u;
	}
	while (t > 0)
		name[i++] = digits[--t];
	name[i] = L'\0';
	RtlInitUnicodeString(&vn, name);
	ZwSetValueKey(key, &vn, 0, REG_DWORD, &v, sizeof(v));
	ZwClose(key);
}

/* ---- Supported OIDs ------------------------------------------------------ */

static const NDIS_OID iwan_cnt_oids[] = {
	OID_GEN_SUPPORTED_LIST,
	OID_GEN_HARDWARE_STATUS,
	OID_GEN_MEDIA_SUPPORTED,
	OID_GEN_MEDIA_IN_USE,
	OID_GEN_PHYSICAL_MEDIUM,
	OID_GEN_MAXIMUM_LOOKAHEAD,
	OID_GEN_MAXIMUM_FRAME_SIZE,
	OID_GEN_MAXIMUM_TOTAL_SIZE,
	OID_GEN_MAC_OPTIONS,
	OID_GEN_MEDIA_CONNECT_STATUS,
	OID_GEN_LINK_SPEED,
	OID_GEN_TRANSMIT_BLOCK_SIZE,
	OID_GEN_RECEIVE_BLOCK_SIZE,
	OID_GEN_TRANSMIT_BUFFER_SPACE,
	OID_GEN_RECEIVE_BUFFER_SPACE,
	OID_GEN_VENDOR_ID,
	OID_GEN_VENDOR_DESCRIPTION,
	OID_GEN_DRIVER_VERSION,
	OID_GEN_CURRENT_PACKET_FILTER,
	OID_GEN_CURRENT_LOOKAHEAD,
	OID_GEN_XMIT_OK,
	OID_GEN_RCV_OK,
	OID_GEN_XMIT_ERROR,
	OID_GEN_RCV_ERROR,
	OID_GEN_STATISTICS,
	OID_GEN_DIRECTED_FRAMES_XMIT,
	OID_GEN_DIRECTED_FRAMES_RCV,
	OID_GEN_BYTES_XMIT,
	OID_GEN_BYTES_RCV,
	OID_802_3_CURRENT_ADDRESS,
	OID_802_3_PERMANENT_ADDRESS,
	OID_802_3_MAXIMUM_LIST_SIZE,
	OID_802_3_MULTICAST_LIST,
	OID_PNP_QUERY_POWER,
	OID_PNP_SET_POWER
};

/* OID values are always written back in **host byte order** (the NDIS convention), with the width defined by the OID. */
static NDIS_STATUS
iwan_cnt_oid_put_width(_Inout_ PNDIS_OID_REQUEST oid, _In_ UINT64 v,
		       _In_ ULONG width)
{
	PUCHAR buf = (PUCHAR)oid->DATA.QUERY_INFORMATION.InformationBuffer;

	if (oid->DATA.QUERY_INFORMATION.InformationBufferLength < width) {
		oid->DATA.QUERY_INFORMATION.BytesNeeded = width;
		return NDIS_STATUS_BUFFER_TOO_SHORT;
	}
	if (width == 8)
		*(UINT64 UNALIGNED *)(PVOID)buf = v;
	else if (width == 4)
		*(UINT32 UNALIGNED *)(PVOID)buf = (UINT32)v;
	else
		*(UINT16 UNALIGNED *)(PVOID)buf = (UINT16)v;
	oid->DATA.QUERY_INFORMATION.BytesWritten = width;
	return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
iwan_cnt_oid_put_u64(_Inout_ PNDIS_OID_REQUEST oid, _In_ UINT64 v)
{
	return iwan_cnt_oid_put_width(oid, v, 8);
}

static NDIS_STATUS
iwan_cnt_oid_put_u32(_Inout_ PNDIS_OID_REQUEST oid, _In_ UINT32 v)
{
	return iwan_cnt_oid_put_width(oid, v, 4);
}

static NDIS_STATUS
iwan_cnt_oid_put_u16(_Inout_ PNDIS_OID_REQUEST oid, _In_ UINT16 v)
{
	return iwan_cnt_oid_put_width(oid, v, 2);
}

static NDIS_STATUS
iwan_cnt_oid_string(_Inout_ PNDIS_OID_REQUEST oid, _In_ const char *s)
{
	size_t n = 0;
	PUCHAR buf = (PUCHAR)oid->DATA.QUERY_INFORMATION.InformationBuffer;

	while (s[n] != '\0')
		n++;
	n++;			/* include the terminating NUL */
	if (oid->DATA.QUERY_INFORMATION.InformationBufferLength < n) {
		oid->DATA.QUERY_INFORMATION.BytesNeeded = (ULONG)n;
		return NDIS_STATUS_BUFFER_TOO_SHORT;
	}
	RtlCopyMemory(buf, s, n);
	oid->DATA.QUERY_INFORMATION.BytesWritten = (ULONG)n;
	return NDIS_STATUS_SUCCESS;
}

/* ---- Indication, ARP and echo ------------------------------------------------ */

/*
 * Hand a frame back to the stack: ownership of the buffer and MDL transfers to NDIS and is released in the return callback.
 * Each NBL carries exactly one frame, so the single-ethertype flag matches the frame type information.
 */
static VOID
iwan_cnt_indicate(_Inout_ PIWAN_CNT_ADAPTER a, _In_ UCHAR *buf, _In_ ULONG len,
		  _In_ UINT16 ethertype, _In_ BOOLEAN dispatch)
{
	PMDL mdl;
	PNET_BUFFER_LIST nbl;
	PIWAN_CNT_NBL_CTX ctx;

	mdl = IoAllocateMdl(buf, len, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		ExFreePoolWithTag(buf, IWAN_CNT_TAG);
		InterlockedIncrement64(&a->drops);
		return;
	}
	MmBuildMdlForNonPagedPool(mdl);
	/* C6014 false positive: the indication call below transfers ownership of nbl to NDIS; the return callback frees it. */
#pragma warning(suppress: 6014)
	nbl = NdisAllocateNetBufferAndNetBufferList(
		a->nbl_pool, IWAN_CNT_NBL_CTX_SIZE, 0, mdl, 0, len);
	if (nbl == NULL) {
		IoFreeMdl(mdl);
		ExFreePoolWithTag(buf, IWAN_CNT_TAG);
		InterlockedIncrement64(&a->drops);
		return;
	}
	ctx = (PIWAN_CNT_NBL_CTX)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
	ctx->buf = buf;
	ctx->mdl = mdl;
	nbl->SourceHandle = a->adapter_handle;
	NET_BUFFER_LIST_INFO(nbl, NetBufferListFrameType) =
		(PVOID)(ULONG_PTR)ethertype;

	InterlockedIncrement(&a->inflight);
	InterlockedIncrement64(&a->rx_frames);
	InterlockedAdd64(&a->rx_bytes, (LONG64)len);
	/* Ownership transfers here: the later return is handled by ReturnNetBufferLists. */
#pragma warning(suppress: 6014)
	NdisMIndicateReceiveNetBufferLists(
		a->adapter_handle, nbl, NDIS_DEFAULT_PORT_NUMBER, 1,
		NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE |
			(dispatch ? NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL : 0));
}

/* Answer ARP requests for PeerIp on its behalf. */
#pragma warning(push)
#pragma warning(disable: 6014)	/* buffer ownership is handed to iwan_cnt_indicate */
static VOID
iwan_cnt_arp_reply(_Inout_ PIWAN_CNT_ADAPTER a,
		   _In_reads_bytes_(len) const UCHAR *p, _In_ ULONG len,
		   _In_ BOOLEAN dispatch)
{
	UCHAR *r;

	if (len < 42)
		return;
	if (iwan_cnt_rd16(p + 20) != 1)		/* op = request */
		return;
	if (iwan_cnt_rd32(p + 38) != a->peer_ip)	/* target = us */
		return;
	r = (UCHAR *)ExAllocatePool2(POOL_FLAG_NON_PAGED, 42, IWAN_CNT_TAG);
	if (r == NULL) {
		InterlockedIncrement64(&a->drops);
		return;
	}
	RtlZeroMemory(r, 42);
	RtlCopyMemory(r, p + 6, 6);		/* destination MAC = requester */
	RtlCopyMemory(r + 6, a->mac, 6);	/* source MAC = this NIC */
	iwan_cnt_wr16(r + 12, IWAN_CNT_ETH_ARP);
	iwan_cnt_wr16(r + 14, 1);		/* htype ethernet */
	iwan_cnt_wr16(r + 16, IWAN_CNT_ETH_IPV4);
	r[18] = 6;
	r[19] = 4;
	iwan_cnt_wr16(r + 20, 2);		/* op = reply */
	RtlCopyMemory(r + 22, a->mac, 6);	/* sha */
	iwan_cnt_wr32(r + 28, a->peer_ip);	/* spa */
	RtlCopyMemory(r + 32, p + 22, 6);	/* tha */
	RtlCopyMemory(r + 38, p + 28, 4);	/* tpa */
	InterlockedIncrement64(&a->arp_req);
	InterlockedIncrement64(&a->arp_rep);
	iwan_cnt_indicate(a, r, 42, IWAN_CNT_ETH_ARP, dispatch);
}
#pragma warning(pop)

/*
 * Bridge a frame to the remaining instances: set the source MAC to this NIC and the destination MAC to the peer NIC's MAC.
 * Why the destination MAC must change: the peer stack's receive filter accepts only frames "sent to this NIC" and broadcast
 * frames; a frame left unchanged carries this NIC's MAC and is dropped immediately at the peer.
 * The caller has already confirmed this frame is "destined for PeerIp"; with no peer instance nothing is done (counting-only mode).
 */
#pragma warning(push)
#pragma warning(disable: 6014)	/* buffer ownership is handed to iwan_cnt_indicate */
static VOID
iwan_cnt_bridge(_Inout_ PIWAN_CNT_ADAPTER a,
		_In_reads_bytes_(len) const UCHAR *p, _In_ ULONG len,
		_In_ UINT16 ethertype, _In_ BOOLEAN dispatch)
{
	PIWAN_CNT_ADAPTER peers[IWAN_CNT_MAX_PEERS];
	ULONG npeers = 0, i;
	PLIST_ENTRY e;
	KIRQL old;

	if (len < IWAN_CNT_ETH_HDR)
		return;
	if (InterlockedCompareExchange(&a->bridge, 1, 1) == 0)
		return;
	if (!g_cnt_list_ready)
		return;

	/* Copy the peer pointers out under the lock, then allocate and indicate outside it: an NDIS call can re-enter
	 * this driver's send path, and holding a lock across such a call is the classic deadlock recipe. */
	KeAcquireSpinLock(&g_cnt_lock, &old);
	for (e = g_cnt_list.Flink;
	     e != NULL && e != &g_cnt_list && npeers < IWAN_CNT_MAX_PEERS;
	     e = e->Flink) {
		PIWAN_CNT_ADAPTER peer =
			CONTAINING_RECORD(e, IWAN_CNT_ADAPTER, link);

		if (peer == a)
			continue;
		if (InterlockedCompareExchange(&peer->running, 1, 1) == 0)
			continue;
		peers[npeers++] = peer;
	}
	KeReleaseSpinLock(&g_cnt_lock, old);

	for (i = 0; i < npeers; i++) {
		PIWAN_CNT_ADAPTER peer = peers[i];
		UCHAR *buf = (UCHAR *)ExAllocatePool2(
			POOL_FLAG_NON_PAGED, len, IWAN_CNT_TAG);

		if (buf == NULL) {
			InterlockedIncrement64(&a->drops);
			continue;
		}
		RtlCopyMemory(buf, p, len);
		RtlCopyMemory(buf, peer->mac, 6);	/* destination = peer NIC */
		RtlCopyMemory(buf + 6, a->mac, 6);	/* source = this NIC */
		iwan_cnt_indicate(peer, buf, len, ethertype, dispatch);
	}
}
#pragma warning(pop)

/* ---- Miniport: send / return / cancel ------------------------------------ */

static
_Function_class_(MINIPORT_SEND_NET_BUFFER_LISTS)
VOID
iwan_cnt_send_nbls(_In_ NDIS_HANDLE MiniportAdapterContext,
		   _In_ PNET_BUFFER_LIST NetBufferLists,
		   _In_ ULONG PortNumber,
		   _In_ ULONG SendFlags)
{
	PIWAN_CNT_ADAPTER a = (PIWAN_CNT_ADAPTER)MiniportAdapterContext;
	PNET_BUFFER_LIST nbl, next;
	BOOLEAN dispatch = (SendFlags & NDIS_SEND_FLAGS_DISPATCH_LEVEL) != 0;

	UNREFERENCED_PARAMETER(PortNumber);

	if (a == NULL) {
		return;
	}
	if (InterlockedCompareExchange(&a->running, 1, 1) == 0) {
		NdisMSendNetBufferListsComplete(
			a->adapter_handle, NetBufferLists,
			dispatch ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);
		return;
	}

	for (nbl = NetBufferLists; nbl != NULL; nbl = next) {
		PNET_BUFFER nb;

		next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		for (nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb != NULL;
		     nb = NET_BUFFER_NEXT_NB(nb)) {
			ULONG len = NET_BUFFER_DATA_LENGTH(nb);
			UCHAR hdr[IWAN_CNT_HDR_SNIFF];
			const UCHAR *hp;
			UINT16 et;
			ULONG want;
			PVOID q;

			InterlockedIncrement64(&a->tx_frames);
			InterlockedAdd64(&a->tx_bytes, (LONG64)len);
			if (len < IWAN_CNT_ETH_HDR) {
				InterlockedIncrement64(&a->other_frames);
				continue;
			}
			want = (len < IWAN_CNT_HDR_SNIFF) ?
				len : IWAN_CNT_HDR_SNIFF;
			q = NdisGetDataBuffer(nb, want, hdr, 1, 0);
			if (q == NULL) {
				InterlockedIncrement64(&a->other_frames);
				continue;
			}
			hp = (const UCHAR *)q;
			et = iwan_cnt_rd16(hp + 12);
			if (et == IWAN_CNT_ETH_ARP) {
				PVOID full = NdisGetDataBuffer(nb, len,
							       NULL, 1, 0);

				if (full != NULL)
					iwan_cnt_arp_reply(a,
							   (const UCHAR *)full,
							   len, dispatch);
				continue;
			}
			if (et != IWAN_CNT_ETH_IPV4) {
				InterlockedIncrement64(&a->other_frames);
				continue;
			}
			if (want < IWAN_CNT_ETH_HDR + 20) {
				InterlockedIncrement64(&a->other_frames);
				continue;
			}
			{
				ULONG saddr = iwan_cnt_rd32(hp + 26);
				ULONG daddr = iwan_cnt_rd32(hp + 30);

				if (daddr == a->peer_ip) {
					PVOID full;

					InterlockedIncrement64(
						&a->peer_in_frames);
					full = NdisGetDataBuffer(nb, len,
								 NULL, 1, 0);
					if (full != NULL)
						iwan_cnt_bridge(
							a,
							(const UCHAR *)full,
							len, et, dispatch);
				} else if (saddr == a->peer_ip) {
					InterlockedIncrement64(
						&a->peer_out_frames);
				} else {
					InterlockedIncrement64(
						&a->other_frames);
				}
			}
		}
	}

	NdisMSendNetBufferListsComplete(
		a->adapter_handle, NetBufferLists,
		dispatch ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);
}

static
_Function_class_(MINIPORT_RETURN_NET_BUFFER_LISTS)
VOID
iwan_cnt_return_nbls(_In_ NDIS_HANDLE MiniportAdapterContext,
		     _In_ PNET_BUFFER_LIST NetBufferLists,
		     _In_ ULONG ReturnFlags)
{
	PIWAN_CNT_ADAPTER a = (PIWAN_CNT_ADAPTER)MiniportAdapterContext;
	PNET_BUFFER_LIST nbl, next;

	UNREFERENCED_PARAMETER(ReturnFlags);

	for (nbl = NetBufferLists; nbl != NULL; nbl = next) {
		PIWAN_CNT_NBL_CTX ctx;

		next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		ctx = (PIWAN_CNT_NBL_CTX)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
		if (ctx != NULL) {
			if (ctx->mdl != NULL) {
				IoFreeMdl(ctx->mdl);
				ctx->mdl = NULL;
			}
			if (ctx->buf != NULL) {
				ExFreePoolWithTag(ctx->buf, IWAN_CNT_TAG);
				ctx->buf = NULL;
			}
		}
		if (a != NULL)
			InterlockedDecrement(&a->inflight);
		NdisFreeNetBufferList(nbl);
	}
}

static
_Function_class_(MINIPORT_CANCEL_SEND)
VOID
iwan_cnt_cancel_send(_In_ NDIS_HANDLE MiniportAdapterContext,
		     _In_ PVOID CancelId)
{
	/* The send path completes synchronously, so there is no queued NBL to cancel. */
	UNREFERENCED_PARAMETER(MiniportAdapterContext);
	UNREFERENCED_PARAMETER(CancelId);
}

/* ---- Miniport: OID --------------------------------------------------- */

static
_Function_class_(MINIPORT_OID_REQUEST)
NDIS_STATUS
iwan_cnt_oid_request(_In_ NDIS_HANDLE MiniportAdapterContext,
		     _In_ PNDIS_OID_REQUEST OidRequest)
{
	PIWAN_CNT_ADAPTER a = (PIWAN_CNT_ADAPTER)MiniportAdapterContext;

	if (a == NULL)
		return NDIS_STATUS_FAILURE;

	if (OidRequest->RequestType == NdisRequestSetInformation) {
		switch (OidRequest->DATA.SET_INFORMATION.Oid) {
		case OID_GEN_CURRENT_PACKET_FILTER:
		case OID_GEN_CURRENT_LOOKAHEAD:
		case OID_802_3_MULTICAST_LIST:
		case OID_PNP_SET_POWER:
			return NDIS_STATUS_SUCCESS;
		default:
			return NDIS_STATUS_NOT_SUPPORTED;
		}
	}
	if (OidRequest->RequestType != NdisRequestQueryInformation)
		return NDIS_STATUS_NOT_SUPPORTED;

	switch (OidRequest->DATA.QUERY_INFORMATION.Oid) {
	case OID_GEN_SUPPORTED_LIST: {
		ULONG bytes = sizeof(iwan_cnt_oids);
		PUCHAR buf = (PUCHAR)OidRequest->DATA.QUERY_INFORMATION.
			InformationBuffer;

		if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength <
		    bytes) {
			OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytes;
			return NDIS_STATUS_BUFFER_TOO_SHORT;
		}
		RtlCopyMemory(buf, iwan_cnt_oids, bytes);
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = bytes;
		return NDIS_STATUS_SUCCESS;
	}
	case OID_GEN_HARDWARE_STATUS:
		return iwan_cnt_oid_put_u32(OidRequest,
					    (UINT32)NdisHardwareStatusReady);
	case OID_GEN_MEDIA_SUPPORTED:
	case OID_GEN_MEDIA_IN_USE:
		return iwan_cnt_oid_put_u32(OidRequest, (UINT32)NdisMedium802_3);
	case OID_GEN_PHYSICAL_MEDIUM:
		return iwan_cnt_oid_put_u32(
			OidRequest, (UINT32)NdisPhysicalMediumUnspecified);
	case OID_GEN_MAC_OPTIONS:
		return iwan_cnt_oid_put_u32(
			OidRequest, NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA);
	case OID_GEN_LINK_SPEED:
		/* Nominal link speed in units of 100 bps: 10 Gbps => 100,000,000. */
		return iwan_cnt_oid_put_u32(OidRequest, 100000000u);
	case OID_GEN_MAXIMUM_LOOKAHEAD:
	case OID_GEN_MAXIMUM_FRAME_SIZE:
	case OID_GEN_TRANSMIT_BLOCK_SIZE:
	case OID_GEN_RECEIVE_BLOCK_SIZE:
	case OID_GEN_CURRENT_LOOKAHEAD:
		return iwan_cnt_oid_put_u32(OidRequest, IWAN_CNT_MTU);
	case OID_GEN_MAXIMUM_TOTAL_SIZE:
		return iwan_cnt_oid_put_u32(OidRequest,
					    IWAN_CNT_MTU + IWAN_CNT_ETH_HDR);
	case OID_GEN_TRANSMIT_BUFFER_SPACE:
	case OID_GEN_RECEIVE_BUFFER_SPACE:
		return iwan_cnt_oid_put_u32(OidRequest, 0x400000u);
	case OID_GEN_VENDOR_ID:
		return iwan_cnt_oid_put_u32(OidRequest, 0xFFFFFF00u);
	case OID_GEN_VENDOR_DESCRIPTION:
		return iwan_cnt_oid_string(OidRequest, "iWAN counting NIC");
	case OID_GEN_DRIVER_VERSION:
		return iwan_cnt_oid_put_u16(
			OidRequest, (UINT16)(NdisGetVersion() & 0xFFFFu));
	case OID_GEN_MEDIA_CONNECT_STATUS:
		return iwan_cnt_oid_put_u32(
			OidRequest, (UINT32)NdisMediaStateConnected);
	case OID_GEN_CURRENT_PACKET_FILTER:
		return iwan_cnt_oid_put_u32(
			OidRequest, NDIS_PACKET_TYPE_DIRECTED |
			NDIS_PACKET_TYPE_BROADCAST |
			NDIS_PACKET_TYPE_ALL_MULTICAST);
	case OID_802_3_CURRENT_ADDRESS:
	case OID_802_3_PERMANENT_ADDRESS: {
		PUCHAR buf = (PUCHAR)OidRequest->DATA.QUERY_INFORMATION.
			InformationBuffer;

		if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength <
		    6) {
			OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = 6;
			return NDIS_STATUS_BUFFER_TOO_SHORT;
		}
		RtlCopyMemory(buf, a->mac, 6);
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 6;
		return NDIS_STATUS_SUCCESS;
	}
	case OID_802_3_MAXIMUM_LIST_SIZE:
		return iwan_cnt_oid_put_u32(OidRequest, 32u);
	case OID_GEN_XMIT_OK:
	case OID_GEN_DIRECTED_FRAMES_XMIT:
		return iwan_cnt_oid_put_u64(OidRequest, (UINT64)a->tx_frames);
	case OID_GEN_RCV_OK:
	case OID_GEN_DIRECTED_FRAMES_RCV:
		return iwan_cnt_oid_put_u64(OidRequest, (UINT64)a->rx_frames);
	case OID_GEN_XMIT_ERROR:
		return iwan_cnt_oid_put_u64(OidRequest, (UINT64)a->drops);
	case OID_GEN_RCV_ERROR:
		return iwan_cnt_oid_put_u64(OidRequest, (UINT64)0);
	case OID_GEN_BYTES_XMIT:
		return iwan_cnt_oid_put_u64(OidRequest, (UINT64)a->tx_bytes);
	case OID_GEN_BYTES_RCV:
		return iwan_cnt_oid_put_u64(OidRequest, (UINT64)a->rx_bytes);
	case OID_GEN_STATISTICS: {
		PNDIS_STATISTICS_INFO si = (PNDIS_STATISTICS_INFO)(PVOID)
			OidRequest->DATA.QUERY_INFORMATION.InformationBuffer;
		ULONG need = NDIS_SIZEOF_STATISTICS_INFO_REVISION_1;

		if (OidRequest->DATA.QUERY_INFORMATION.
		    InformationBufferLength < need) {
			OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = need;
			return NDIS_STATUS_BUFFER_TOO_SHORT;
		}
		RtlZeroMemory(si, need);
		si->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
		si->Header.Revision = NDIS_STATISTICS_INFO_REVISION_1;
		si->Header.Size = (USHORT)need;
		si->SupportedStatistics =
				NDIS_STATISTICS_DIRECTED_FRAMES_XMIT_SUPPORTED |
			NDIS_STATISTICS_BYTES_RCV_SUPPORTED |
			NDIS_STATISTICS_BYTES_XMIT_SUPPORTED |
			NDIS_STATISTICS_XMIT_ERROR_SUPPORTED |
			NDIS_STATISTICS_XMIT_OK_SUPPORTED |
			NDIS_STATISTICS_RCV_OK_SUPPORTED;
		si->ifHCInUcastPkts = (UINT64)a->rx_frames;
		si->ifHCInOctets = (UINT64)a->rx_bytes;
		si->ifHCOutUcastPkts = (UINT64)a->tx_frames;
		si->ifHCOutOctets = (UINT64)a->tx_bytes;
		si->ifOutErrors = (UINT64)a->drops;
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = need;
		return NDIS_STATUS_SUCCESS;
	}
	case OID_PNP_QUERY_POWER:
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
		return NDIS_STATUS_SUCCESS;
	default:
		return NDIS_STATUS_NOT_SUPPORTED;
	}
}

static
_Function_class_(MINIPORT_CANCEL_OID_REQUEST)
VOID
iwan_cnt_cancel_oid(_In_ NDIS_HANDLE MiniportAdapterContext,
		    _In_ PVOID RequestId)
{
	UNREFERENCED_PARAMETER(MiniportAdapterContext);
	UNREFERENCED_PARAMETER(RequestId);
}

static
_Function_class_(MINIPORT_DEVICE_PNP_EVENT_NOTIFY)
VOID
iwan_cnt_pnp_event(_In_ NDIS_HANDLE MiniportAdapterContext,
		   _In_ PNET_DEVICE_PNP_EVENT NetDevicePnPEvent)
{
	UNREFERENCED_PARAMETER(MiniportAdapterContext);
	UNREFERENCED_PARAMETER(NetDevicePnPEvent);
}

static
_Function_class_(MINIPORT_SHUTDOWN)
VOID
iwan_cnt_shutdown(_In_ NDIS_HANDLE MiniportAdapterContext,
		  _In_ NDIS_SHUTDOWN_ACTION ShutdownAction)
{
	UNREFERENCED_PARAMETER(MiniportAdapterContext);
	UNREFERENCED_PARAMETER(ShutdownAction);
}

/* ---- Miniport: pause / restart ------------------------------------------ */

static
_Function_class_(MINIPORT_PAUSE)
NDIS_STATUS
iwan_cnt_pause(_In_ NDIS_HANDLE MiniportAdapterContext,
	       _In_ PNDIS_MINIPORT_PAUSE_PARAMETERS PauseParameters)
{
	PIWAN_CNT_ADAPTER a = (PIWAN_CNT_ADAPTER)MiniportAdapterContext;

	UNREFERENCED_PARAMETER(PauseParameters);
	if (a != NULL)
		InterlockedExchange(&a->running, 0);
	return NDIS_STATUS_SUCCESS;
}

static
_Function_class_(MINIPORT_RESTART)
NDIS_STATUS
iwan_cnt_restart(_In_ NDIS_HANDLE MiniportAdapterContext,
		 _In_ PNDIS_MINIPORT_RESTART_PARAMETERS RestartParameters)
{
	PIWAN_CNT_ADAPTER a = (PIWAN_CNT_ADAPTER)MiniportAdapterContext;

	UNREFERENCED_PARAMETER(RestartParameters);
	if (a != NULL)
		InterlockedExchange(&a->running, 1);
	return NDIS_STATUS_SUCCESS;
}

/* ---- Miniport: initialize / halt ---------------------------------------- */

/*
 * Both C6014 reports in this function (adapter extension a, NBL pool a->nbl_pool) are driver-lifetime
 * assets: a is freed by HaltHandlerEx and the pool is freed by HaltHandlerEx too (when in-flight returns
 * do not come back, the pool is leaked rather than freed). The analyzer only sees "allocated, not released before the function returns success".
 */
#pragma warning(push)
#pragma warning(disable: 6014)
static
_Function_class_(MINIPORT_INITIALIZE)
NDIS_STATUS
iwan_cnt_initialize(_In_ NDIS_HANDLE MiniportAdapterHandle,
		    _In_ NDIS_HANDLE MiniportDriverContext,
		    _In_ PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters)
{
	PIWAN_CNT_ADAPTER a;
	NDIS_STATUS st;
	NET_BUFFER_LIST_POOL_PARAMETERS pool;
	NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES reg;
	NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES gen;
	HANDLE key = NULL;
	WCHAR tmp[64];
	ULONG disarm = 1;
	BOOLEAN mac_given = FALSE;

	UNREFERENCED_PARAMETER(MiniportDriverContext);
	UNREFERENCED_PARAMETER(MiniportInitParameters);

	iwan_cnt_trace(20, 0);

	a = (PIWAN_CNT_ADAPTER)ExAllocatePool2(
		POOL_FLAG_NON_PAGED, sizeof(*a), IWAN_CNT_TAG);
	if (a == NULL) {
		iwan_cnt_trace(21, (LONG)NDIS_STATUS_RESOURCES);
		return NDIS_STATUS_RESOURCES;
	}
	RtlZeroMemory(a, sizeof(*a));
	InitializeListHead(&a->link);
	a->adapter_handle = MiniportAdapterHandle;

	if (iwan_cnt_open_params(MiniportAdapterHandle, &key)) {
		disarm = iwan_cnt_param_u32(key, L"Disarm", 1);
		a->bridge = iwan_cnt_param_u32(key, L"Bridge", 1);
		if (iwan_cnt_param_str(key, L"PeerIp", tmp,
				       RTL_NUMBER_OF(tmp)))
			a->peer_ip = iwan_cnt_parse_ip(tmp);
		if (iwan_cnt_param_str(key, L"Mac", tmp, RTL_NUMBER_OF(tmp)))
			mac_given = iwan_cnt_parse_mac(tmp, a->mac);
		ZwClose(key);
	}
	if (a->peer_ip == 0)
		a->peer_ip = iwan_cnt_parse_ip(L"10.200.0.1");
	if (!mac_given) {
		a->mac[0] = 0x02;
		a->mac[1] = 0x00;
		a->mac[2] = 0x49;
		a->mac[3] = 0x57;
		a->mac[4] = 0x41;
		a->mac[5] = 0x4E;
	}

	if (disarm != 0) {
		/* Fuse closed: it installs but does not work. Write 0 to make it effective. */
		iwan_cnt_trace(22, 1);
		ExFreePoolWithTag(a, IWAN_CNT_TAG);
		return NDIS_STATUS_FAILURE;
	}

	RtlZeroMemory(&pool, sizeof(pool));
	pool.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	pool.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	pool.Header.Size =
		NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	pool.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
	pool.fAllocateNetBuffer = TRUE;
	pool.ContextSize = IWAN_CNT_NBL_CTX_SIZE;
	pool.PoolTag = IWAN_CNT_TAG;
	a->nbl_pool = NdisAllocateNetBufferListPool(MiniportAdapterHandle,
						    &pool);
	if (a->nbl_pool == NULL) {
		iwan_cnt_trace(23, (LONG)NDIS_STATUS_RESOURCES);
		ExFreePoolWithTag(a, IWAN_CNT_TAG);
		return NDIS_STATUS_RESOURCES;
	}

	RtlZeroMemory(&reg, sizeof(reg));
	reg.Header.Type =
		NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;
	reg.Header.Revision =
		NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
	reg.Header.Size =
		NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
	reg.MiniportAdapterContext = a;
	reg.AttributeFlags = NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND |
			     NDIS_MINIPORT_ATTRIBUTES_SURPRISE_REMOVE_OK;
	reg.CheckForHangTimeInSeconds = 0;
	reg.InterfaceType = NdisInterfaceInternal;
	st = NdisMSetMiniportAttributes(MiniportAdapterHandle,
					(PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&reg);
	if (st != NDIS_STATUS_SUCCESS) {
		iwan_cnt_trace(24, (LONG)st);
		NdisFreeNetBufferListPool(a->nbl_pool);
		ExFreePoolWithTag(a, IWAN_CNT_TAG);
		return st;
	}

	RtlZeroMemory(&gen, sizeof(gen));
	gen.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;
	/* Same convention as iwanmp: REVISION_1. This WDK's struct is a single definition, and the trailing
	 * SupportedStatistics / SupportedOidList can also be written; the revision only decides
	 * how much of it NDIS recognizes, while we handle statistics through our own OID_GEN_STATISTICS. */
	gen.Header.Revision =
		NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
	gen.Header.Size =
		NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
	gen.MediaType = NdisMedium802_3;
	gen.PhysicalMediumType = NdisPhysicalMediumUnspecified;
	gen.MtuSize = IWAN_CNT_MTU;
	gen.MaxXmitLinkSpeed = IWAN_CNT_LINK_SPEED;
	gen.XmitLinkSpeed = IWAN_CNT_LINK_SPEED;
	gen.MaxRcvLinkSpeed = IWAN_CNT_LINK_SPEED;
	gen.RcvLinkSpeed = IWAN_CNT_LINK_SPEED;
	gen.MediaConnectState = MediaConnectStateConnected;
	gen.MediaDuplexState = MediaDuplexStateFull;
	gen.LookaheadSize = IWAN_CNT_MTU;
	gen.MacOptions = NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA |
			 NDIS_MAC_OPTION_NO_LOOPBACK;
	gen.SupportedPacketFilters = NDIS_PACKET_TYPE_DIRECTED |
				     NDIS_PACKET_TYPE_MULTICAST |
				     NDIS_PACKET_TYPE_ALL_MULTICAST |
				     NDIS_PACKET_TYPE_BROADCAST |
				     NDIS_PACKET_TYPE_PROMISCUOUS;
	gen.MaxMulticastListSize = 32;
	gen.MacAddressLength = 6;
	RtlCopyMemory(gen.PermanentMacAddress, a->mac, 6);
	RtlCopyMemory(gen.CurrentMacAddress, a->mac, 6);
	gen.RecvScaleCapabilities = NULL;
	gen.AccessType = NET_IF_ACCESS_BROADCAST;
	gen.DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
	gen.ConnectionType = NET_IF_CONNECTION_DEDICATED;
	gen.IfType = IF_TYPE_ETHERNET_CSMACD;
	gen.IfConnectorPresent = FALSE;
	gen.SupportedStatistics =
		NDIS_STATISTICS_DIRECTED_FRAMES_XMIT_SUPPORTED |
		NDIS_STATISTICS_BYTES_XMIT_SUPPORTED |
		NDIS_STATISTICS_BYTES_RCV_SUPPORTED |
		NDIS_STATISTICS_XMIT_ERROR_SUPPORTED |
		NDIS_STATISTICS_XMIT_OK_SUPPORTED |
		NDIS_STATISTICS_RCV_OK_SUPPORTED;
	gen.SupportedPauseFunctions = NdisPauseFunctionsUnsupported;
	gen.DataBackFillSize = 0;
	gen.ContextBackFillSize = 0;
	gen.SupportedOidList = (PNDIS_OID)(PVOID)iwan_cnt_oids;
	gen.SupportedOidListLength = sizeof(iwan_cnt_oids);
	gen.AutoNegotiationFlags = 0;
	st = NdisMSetMiniportAttributes(MiniportAdapterHandle,
					(PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&gen);
	if (st != NDIS_STATUS_SUCCESS) {
		iwan_cnt_trace(25, (LONG)st);
		NdisFreeNetBufferListPool(a->nbl_pool);
		ExFreePoolWithTag(a, IWAN_CNT_TAG);
		return st;
	}

	/* Insert into the instance table before enabling running: a bridger that sees running=1 can always walk the list. */
	if (g_cnt_list_ready)
		ExInterlockedInsertTailList(&g_cnt_list, &a->link,
					    &g_cnt_lock);
	InterlockedExchange(&a->running, 1);
	iwan_cnt_trace(26, (LONG)a->peer_ip);
	DbgPrint("iwancnt: up, peer %u.%u.%u.%u bridge %lu\n",
		 (unsigned)((a->peer_ip >> 24) & 0xFF),
		 (unsigned)((a->peer_ip >> 16) & 0xFF),
		 (unsigned)((a->peer_ip >> 8) & 0xFF),
		 (unsigned)(a->peer_ip & 0xFF),
		 (unsigned long)a->bridge);
	return NDIS_STATUS_SUCCESS;
}
#pragma warning(pop)

static
_Function_class_(MINIPORT_HALT)
VOID
iwan_cnt_halt(_In_ NDIS_HANDLE MiniportAdapterContext,
	      _In_ NDIS_HALT_ACTION HaltAction)
{
	PIWAN_CNT_ADAPTER a = (PIWAN_CNT_ADAPTER)MiniportAdapterContext;
	ULONG i;

	UNREFERENCED_PARAMETER(HaltAction);
	if (a == NULL)
		return;
	InterlockedExchange(&a->running, 0);
	if (g_cnt_list_ready) {
		KIRQL old;

		KeAcquireSpinLock(&g_cnt_lock, &old);
		RemoveEntryList(&a->link);
		KeReleaseSpinLock(&g_cnt_lock, old);
	}
	/* Wait for in-flight bridged frames to be returned; if they do not come back, leak the pool rather than free a pool that may still be referenced. */
	for (i = 0; i < 1000; i++) {
		if (InterlockedCompareExchange(&a->inflight, 0, 0) == 0)
			break;
		KeStallExecutionProcessor(1000);
	}
	if (a->nbl_pool != NULL &&
	    InterlockedCompareExchange(&a->inflight, 0, 0) == 0) {
		NdisFreeNetBufferListPool(a->nbl_pool);
		a->nbl_pool = NULL;
	} else if (a->nbl_pool != NULL) {
		DbgPrint("iwancnt: %ld frames still outstanding at halt, pool not freed\n",
			 (long)InterlockedCompareExchange(&a->inflight, 0, 0));
	}
	ExFreePoolWithTag(a, IWAN_CNT_TAG);
}

/* ---- Driver entry -------------------------------------------------------- */

typedef struct {
	UCHAR minor;	/* 0xFF = use the runtime minor version */
	UCHAR rev;
} IWAN_CNT_CH_CAND;

static const IWAN_CNT_CH_CAND iwan_cnt_ch_cands[] = {
	{ 0xFF, NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3 },
	{ 0xFF, NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2 },
	{ 0xFF, NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1 },
	{ 80,   NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1 },
	{ 60,   NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1 },
	{ 20,   NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1 }
};

/* First failure seen by any load attempt, and the candidate that produced it. Every PnP instance runs DriverEntry
 * once, and a later attempt reports STATUS_DRIVER_FAILED_PRIOR_UNLOAD because the earlier failure left the driver
 * object referenced -- that overwrites Status/T31 and hides the original cause. These two are written once only. */
static volatile LONG g_cnt_first_st;
static volatile LONG g_cnt_first_idx;
static volatile LONG g_cnt_entry_count;

/* MiniportDriverUnload: required for NDIS 6.0 and later drivers, and registration is rejected outright when it is
 * NULL. Nothing to tear down here -- a PnP miniport is halted through HaltHandlerEx, and this image is never
 * unloaded while the machine lives. */
static
_Function_class_(MINIPORT_DRIVER_UNLOAD)
VOID
iwan_cnt_unload(_In_ PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);
}

static VOID
iwan_cnt_fill_ch(_Out_ PNDIS_MINIPORT_DRIVER_CHARACTERISTICS ch,
		 _In_ UCHAR minor, _In_ UCHAR revision)
{
	RtlZeroMemory(ch, sizeof(*ch));
	ch->Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
	ch->Header.Revision = revision;
	switch (revision) {
	case NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3:
		ch->Header.Size =
			NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3;
		break;
	case NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2:
		ch->Header.Size =
			NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
		break;
	default:
		ch->Header.Size =
			NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;
		break;
	}
	ch->MajorNdisVersion = 6;
	ch->MinorNdisVersion = minor;
	ch->MajorDriverVersion = 1;
	ch->MinorDriverVersion = 0;
	ch->Flags = 0;
	ch->InitializeHandlerEx = iwan_cnt_initialize;
	ch->HaltHandlerEx = iwan_cnt_halt;
	ch->PauseHandler = iwan_cnt_pause;
	ch->RestartHandler = iwan_cnt_restart;
	ch->OidRequestHandler = iwan_cnt_oid_request;
	ch->SendNetBufferListsHandler = iwan_cnt_send_nbls;
	ch->ReturnNetBufferListsHandler = iwan_cnt_return_nbls;
	ch->CancelSendHandler = iwan_cnt_cancel_send;
	ch->DevicePnPEventNotifyHandler = iwan_cnt_pnp_event;
	ch->ShutdownHandlerEx = iwan_cnt_shutdown;
	ch->CancelOidRequestHandler = iwan_cnt_cancel_oid;
	ch->UnloadHandler = iwan_cnt_unload;
}

NDIS_STATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
	    _In_ PUNICODE_STRING RegistryPath)
{
	NDIS_MINIPORT_DRIVER_CHARACTERISTICS ch;
	NDIS_HANDLE handle = NULL;
	NDIS_STATUS st;
	UCHAR runtime;
	ULONG i;

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
	/* <RegistryPath>\Parameters, so every instance traces into its own key. Freed never: the
	 * driver lives as long as the machine, and a dangling UNICODE_STRING is worse than a leak. */
	if (g_cnt_param_path.Buffer == NULL && RegistryPath != NULL &&
	    RegistryPath->Buffer != NULL && RegistryPath->Length > 0) {
		static const WCHAR tail[] = L"\\Parameters";
		USHORT total = (USHORT)(RegistryPath->Length + sizeof(tail) - sizeof(WCHAR));
		PWCH buf = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, total,
						 IWAN_CNT_TAG);

		if (buf != NULL) {
			RtlCopyMemory(buf, RegistryPath->Buffer, RegistryPath->Length);
			RtlCopyMemory((PUCHAR)buf + RegistryPath->Length, tail,
				      sizeof(tail) - sizeof(WCHAR));
			g_cnt_param_path.Buffer = buf;
			g_cnt_param_path.Length = (USHORT)(total - sizeof(WCHAR));
			g_cnt_param_path.MaximumLength = total;
		}
	}
	/* The instance table must be ready before any NIC's InitializeEx runs: bridgers walk it. */
	InitializeListHead(&g_cnt_list);
	KeInitializeSpinLock(&g_cnt_lock);
	g_cnt_list_ready = TRUE;
	iwan_cnt_trace(30, (LONG)NdisGetVersion());
	/* T47: how many times DriverEntry has run on this boot. Two PnP instances means twice; a number larger than the
	 * instance count means the loader retried after a failure. */
	iwan_cnt_trace(47, InterlockedIncrement(&g_cnt_entry_count));

	/* Miniport registration: try the highest characteristics revision first, then fall back.
	 * A hard-wired REVISION_1 at the runtime minor version is rejected on a current NDIS (the
	 * first bring-up came back as 0xC0000365, "a previous version is still in memory", which is
	 * not what happened -- nothing had ever been loaded); iwanmp found the same thing and is
	 * registered as runtime minor + REVISION_3. */
	runtime = (UCHAR)(NdisGetVersion() & 0xFFu);
	st = NDIS_STATUS_BAD_CHARACTERISTICS;
	for (i = 0; i < RTL_NUMBER_OF(iwan_cnt_ch_cands); i++) {
		UCHAR minor = iwan_cnt_ch_cands[i].minor;
		UCHAR rev = iwan_cnt_ch_cands[i].rev;

		if (minor == 0xFFu)
			minor = (runtime < 20) ? 20 : runtime;
		iwan_cnt_fill_ch(&ch, minor, rev);
		st = NdisMRegisterMiniportDriver(DriverObject, RegistryPath,
						 NULL, &ch, &handle);
		iwan_cnt_trace(31, (LONG)st);
		if (st == NDIS_STATUS_SUCCESS) {
			iwan_cnt_trace(32, (LONG)(((ULONG)minor << 8) | rev));
			break;
		}
		/* T40..T45: the status of each candidate, in order. T46/T48: the first failure ever seen and its candidate
		 * index, written once so that a later STATUS_DRIVER_FAILED_PRIOR_UNLOAD cannot bury the real reason. */
		iwan_cnt_trace(40 + i, (LONG)st);
		if (InterlockedCompareExchange(&g_cnt_first_st, (LONG)st, 0) == 0) {
			iwan_cnt_trace(46, (LONG)st);
			iwan_cnt_trace(48, (LONG)i);
		}
	}
	if (st != NDIS_STATUS_SUCCESS) {
		/* Registration failed: the image will be unloaded, so returning failure is safe. */
		return st;
	}
	/* After successful registration never return failure and never unregister again: otherwise NDIS would hold callbacks
	 * pointing into an unloaded image and the machine would not boot (a pit iwanmp already fell into). */
	DriverObject->DriverUnload = NULL;
	return NDIS_STATUS_SUCCESS;
}
