/*
 * iwan_cnt.c —— 只计数、可回声的以太虚拟网卡（iwancnt.sys）
 *
 * 用途：给 Windows 数据面提供一个"不经 QEMU slirp、不过用户态"的对端，让隧道
 * 能以线速跑满并逐帧计数。它是一张 802.3 小型端口：
 *
 *   - 发送路径：协议栈交下来的每一帧都累加计数（分"去往对端"与"来自对端"
 *     两类），这就是隧道真正压出来的负载；
 *   - 回声：交换以太头后把帧原样指示回协议栈（相当于一根回环线），于是同一
 *     台机器上可以同时观察两个方向；
 *   - ARP：对 EchoIp 代答 —— tcpip 不认为该地址属于本机，不代答就永远解析
 *     不出下一跳；
 *   - 计数只暴露在 NDIS 统计里（Get-NetAdapterStatistics 直接可读），不建
 *     控制设备、不开共享内存：越少代码越不可能把整机搞挂。
 *
 * 参数（HKLM\SYSTEM\CurrentControlSet\Services\iwancnt\Parameters）：
 *   Disarm   DWORD 默认 1（合上保险丝）。为 1 时 InitializeEx 直接失败，驱动
 *                  装着但不工作 —— 一次错误注册就让整机起不来的教训。
 *   EchoIp   SZ    默认 "10.200.0.1"，对端地址。
 *   EchoMode DWORD 默认 1：1 = 只交换以太头（回环给本机协议栈）；2 = 再交换
 *                  外层 IPv4 的源/目的与 UDP 端口（反射模式）。
 *   InnerOff DWORD 默认 0：非 0 时在该偏移处再交换内层 IPv4（明文隧道帧才
 *                  能用；加密载荷不能动，故默认关）。
 *   Mac      SZ    默认 "02-00-49-57-41-4e"。
 *
 * 边界：iwan.sys 是 WFP 平面、iwanmp.sys 是 NDIS 平面；本驱动不属于任何平面，
 * 只是它们对端的一张网卡。
 */

#include <ndis.h>

#define IWAN_CNT_TAG            'TNCW'
#define IWAN_CNT_MTU            1500u
#define IWAN_CNT_NBL_CTX_SIZE   16u
#define IWAN_CNT_LINK_SPEED     10000000000ULL
#define IWAN_CNT_PARAM_PATH \
	L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\iwancnt\\Parameters"

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
	ULONG                           echo_ip;	/* 与帧内字节同序 */
	ULONG                           echo_mode;
	ULONG                           inner_off;
	volatile LONG64                 tx_frames;
	volatile LONG64                 tx_bytes;
	volatile LONG64                 peer_in_frames;
	volatile LONG64                 peer_out_frames;
	volatile LONG64                 echo_frames;
	volatile LONG64                 echo_bytes;
	volatile LONG64                 arp_req;
	volatile LONG64                 arp_rep;
	volatile LONG64                 drops;
	volatile LONG64                 other_frames;
} IWAN_CNT_ADAPTER, *PIWAN_CNT_ADAPTER;

static VOID iwan_cnt_trace(_In_ ULONG stage, _In_ LONG status);

/* ---- 字节序小工具 ---------------------------------------------------- */

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

/* ---- 注册表参数与阶段追踪 -------------------------------------------- */

static BOOLEAN
iwan_cnt_open_params(_Out_ HANDLE *key)
{
	UNICODE_STRING path;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS st;

	RtlInitUnicodeString(&path, IWAN_CNT_PARAM_PATH);
	InitializeObjectAttributes(&oa, &path,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				   NULL, NULL);
	st = ZwOpenKey(key, KEY_READ | KEY_SET_VALUE, &oa);
	return (BOOLEAN)NT_SUCCESS(st);
}

static ULONG
iwan_cnt_param_u32(_In_ HANDLE key, _In_ PCWSTR name, _In_ ULONG dflt)
{
	UNICODE_STRING vn;
	UCHAR buf[64];
	ULONG need = 0;
	PKEY_VALUE_PARTIAL_INFORMATION pi;

	/* 清零只是为了在分析器眼里"缓冲区已初始化"；真正的布局由 API 契约保证：
	 * ZwQueryValueKey 成功时按 KEY_VALUE_PARTIAL_INFORMATION 写回。 */
	RtlZeroMemory(buf, sizeof(buf));
	RtlInitUnicodeString(&vn, name);
	if (!NT_SUCCESS(ZwQueryValueKey(key, &vn, KeyValuePartialInformation,
					buf, sizeof(buf), &need)))
		return dflt;
	pi = (PKEY_VALUE_PARTIAL_INFORMATION)(PVOID)buf;
	/* C28199：分析器认为 buf 未被赋值，实际是 ZwQueryValueKey 按契约填的。 */
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

/* "10.200.0.1" → 0x0AC80001（与 iwan_cnt_rd32 同序：字节流顺序）。 */
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

	/* FALSE 时输出无意义；清零让分析器与调用方都不必猜。 */
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

	RtlInitUnicodeString(&path, IWAN_CNT_PARAM_PATH);
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

	/* 键名 T<十进制阶段号>：写死 switch 会让未列阶段静默消失。 */
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

/* ---- 支持的 OID ------------------------------------------------------ */

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

/* OID 的值一律按**主机序**写回（NDIS 的约定），宽度按 OID 定义。 */
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
	n++;			/* 连结尾的 NUL 一起给 */
	if (oid->DATA.QUERY_INFORMATION.InformationBufferLength < n) {
		oid->DATA.QUERY_INFORMATION.BytesNeeded = (ULONG)n;
		return NDIS_STATUS_BUFFER_TOO_SHORT;
	}
	RtlCopyMemory(buf, s, n);
	oid->DATA.QUERY_INFORMATION.BytesWritten = (ULONG)n;
	return NDIS_STATUS_SUCCESS;
}

/* ---- 指示、ARP 与回声 ------------------------------------------------ */

/*
 * 把一帧交回协议栈：缓冲与 MDL 的所有权转给 NDIS，归还回调里释放。
 * 每个 NBL 只装一帧，故单以太类型标志与帧类型信息一致。
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
	/* C6014 误报：下面的指示调用把 nbl 的所有权转给 NDIS，归还回调负责释放。 */
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
	InterlockedIncrement64(&a->echo_frames);
	InterlockedAdd64(&a->echo_bytes, (LONG64)len);
	/* 所有权在此转移：后续归还由 ReturnNetBufferLists 负责。 */
#pragma warning(suppress: 6014)
	NdisMIndicateReceiveNetBufferLists(
		a->adapter_handle, nbl, NDIS_DEFAULT_PORT_NUMBER, 1,
		NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE |
			(dispatch ? NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL : 0));
}

/* 对 EchoIp 的 ARP 请求代答。 */
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
	if (iwan_cnt_rd32(p + 38) != a->echo_ip)	/* target = 我们 */
		return;
	r = (UCHAR *)ExAllocatePool2(POOL_FLAG_NON_PAGED, 42, IWAN_CNT_TAG);
	if (r == NULL) {
		InterlockedIncrement64(&a->drops);
		return;
	}
	RtlZeroMemory(r, 42);
	RtlCopyMemory(r, p + 6, 6);		/* 目的 MAC = 请求方 */
	RtlCopyMemory(r + 6, a->mac, 6);	/* 源 MAC = 本卡 */
	iwan_cnt_wr16(r + 12, IWAN_CNT_ETH_ARP);
	iwan_cnt_wr16(r + 14, 1);		/* htype ethernet */
	iwan_cnt_wr16(r + 16, IWAN_CNT_ETH_IPV4);
	r[18] = 6;
	r[19] = 4;
	iwan_cnt_wr16(r + 20, 2);		/* op = reply */
	RtlCopyMemory(r + 22, a->mac, 6);	/* sha */
	iwan_cnt_wr32(r + 28, a->echo_ip);	/* spa */
	RtlCopyMemory(r + 32, p + 22, 6);	/* tha */
	RtlCopyMemory(r + 38, p + 28, 4);	/* tpa */
	InterlockedIncrement64(&a->arp_req);
	InterlockedIncrement64(&a->arp_rep);
#pragma warning(suppress: 6014)
	iwan_cnt_indicate(a, r, 42, IWAN_CNT_ETH_ARP, dispatch);
}

/* 交换一段 IPv4 头（可选交换 UDP 端口）并重算 IP 校验和。 */
static VOID
iwan_cnt_swap_ip4(_Inout_updates_bytes_(len) UCHAR *p, _In_ ULONG len,
		  _In_ BOOLEAN swap_ports)
{
	ULONG ihl;
	ULONG need;
	UCHAR t[4];
	UCHAR p0, p1;

	if (len < 20 || (p[0] >> 4) != 4)
		return;
	ihl = (ULONG)(p[0] & 0x0Fu) * 4;
	if (ihl < 20 || ihl > len)
		return;
	/* 先把要碰的最大偏移算成一个数：交换 4 字节地址 + 可能的 8 字节 UDP 头。 */
	need = ihl + ((swap_ports && p[9] == 17) ? 8u : 0u);
	if (need > len)
		return;
	RtlCopyMemory(t, p + 12, 4);
	RtlCopyMemory(p + 12, p + 16, 4);
	RtlCopyMemory(p + 16, t, 4);
	if (swap_ports && p[9] == 17) {
		p0 = p[ihl];
		p1 = p[ihl + 1];
		p[ihl] = p[ihl + 2];
		p[ihl + 1] = p[ihl + 3];
		p[ihl + 2] = p0;
		p[ihl + 3] = p1;
		/* IPv4 下 UDP 校验和 0 = 未计算，交换后清零最省事。 */
		iwan_cnt_wr16(p + ihl + 6, 0);
	}
	iwan_cnt_ip4_csum(p);
}

static VOID
iwan_cnt_echo(_Inout_ PIWAN_CNT_ADAPTER a,
	      _In_reads_bytes_(len) const UCHAR *p, _In_ ULONG len,
	      _In_ UINT16 ethertype, _In_ BOOLEAN dispatch)
{
	UCHAR *buf;
	UCHAR m0;
	ULONG i;

	if (len < IWAN_CNT_ETH_HDR)
		return;
	buf = (UCHAR *)ExAllocatePool2(POOL_FLAG_NON_PAGED, len, IWAN_CNT_TAG);
	if (buf == NULL) {
		InterlockedIncrement64(&a->drops);
		return;
	}
	RtlCopyMemory(buf, p, len);
	/* 回环线：交换以太头。交换后目的 = 源 = 本卡 MAC，协议栈按本机接收。 */
	for (i = 0; i < 6; i++) {
		m0 = buf[i];
		buf[i] = buf[6 + i];
		buf[6 + i] = m0;
	}
	if (a->echo_mode >= 2)
		iwan_cnt_swap_ip4(buf + IWAN_CNT_ETH_HDR,
				  len - IWAN_CNT_ETH_HDR, TRUE);
	if (a->inner_off != 0 && len > a->inner_off + 20)
		iwan_cnt_swap_ip4(buf + a->inner_off, len - a->inner_off, TRUE);
#pragma warning(suppress: 6014)
	iwan_cnt_indicate(a, buf, len, ethertype, dispatch);
}

/* ---- 小型端口：发送 / 归还 / 取消 ------------------------------------ */

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
				PVOID full;

				if (daddr == a->echo_ip)
					InterlockedIncrement64(
						&a->peer_in_frames);
				else if (saddr == a->echo_ip)
					InterlockedIncrement64(
						&a->peer_out_frames);
				else
					InterlockedIncrement64(
						&a->other_frames);
				full = NdisGetDataBuffer(nb, len, NULL, 1, 0);
				if (full != NULL)
					iwan_cnt_echo(a, (const UCHAR *)full,
						      len, et, dispatch);
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
	/* 发送路径同步完成，没有排队中的 NBL 可取消。 */
	UNREFERENCED_PARAMETER(MiniportAdapterContext);
	UNREFERENCED_PARAMETER(CancelId);
}

/* ---- 小型端口：OID --------------------------------------------------- */

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
		/* 名义链路速率，单位 100 bps：10 Gbps ⇒ 100,000,000。 */
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
		return iwan_cnt_oid_put_u64(OidRequest, (UINT64)a->echo_frames);
	case OID_GEN_XMIT_ERROR:
		return iwan_cnt_oid_put_u64(OidRequest, (UINT64)a->drops);
	case OID_GEN_RCV_ERROR:
		return iwan_cnt_oid_put_u64(OidRequest, (UINT64)0);
	case OID_GEN_BYTES_XMIT:
		return iwan_cnt_oid_put_u64(OidRequest, (UINT64)a->tx_bytes);
	case OID_GEN_BYTES_RCV:
		return iwan_cnt_oid_put_u64(OidRequest, (UINT64)a->echo_bytes);
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
		si->ifHCInUcastPkts = (UINT64)a->echo_frames;
		si->ifHCInOctets = (UINT64)a->echo_bytes;
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

/* ---- 小型端口：暂停 / 恢复 ------------------------------------------ */

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

/* ---- 小型端口：初始化 / 停止 ---------------------------------------- */

/*
 * 本函数里报的两条 C6014（适配器扩展 a、NBL 池 a->nbl_pool）都是驱动生命周期
 * 资产：a 由 HaltHandlerEx 释放，池由 HaltHandlerEx 释放（等不到在途归还时
 * 宁可泄漏池也不放）。分析器只看见"分配了、函数成功返回前没释放"。
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
	ULONG disarm = 1, off = 0;
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
	a->adapter_handle = MiniportAdapterHandle;

	if (iwan_cnt_open_params(&key)) {
		disarm = iwan_cnt_param_u32(key, L"Disarm", 1);
		a->echo_mode = iwan_cnt_param_u32(key, L"EchoMode", 1);
		off = iwan_cnt_param_u32(key, L"InnerOff", 0);
		if (iwan_cnt_param_str(key, L"EchoIp", tmp,
				       RTL_NUMBER_OF(tmp)))
			a->echo_ip = iwan_cnt_parse_ip(tmp);
		if (iwan_cnt_param_str(key, L"Mac", tmp, RTL_NUMBER_OF(tmp)))
			mac_given = iwan_cnt_parse_mac(tmp, a->mac);
		ZwClose(key);
	}
	if (a->echo_ip == 0)
		a->echo_ip = iwan_cnt_parse_ip(L"10.200.0.1");
	if (!mac_given) {
		a->mac[0] = 0x02;
		a->mac[1] = 0x00;
		a->mac[2] = 0x49;
		a->mac[3] = 0x57;
		a->mac[4] = 0x41;
		a->mac[5] = 0x4E;
	}
	a->inner_off = off;

	if (disarm != 0) {
		/* 保险丝合上：装得上、不工作。写成 0 才生效。 */
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
	/* 与 iwanmp 同口径：REVISION_1。这份 WDK 的结构体是单一定义，尾部的
	 * SupportedStatistics / SupportedOidList 也都能写；revision 只决定
	 * NDIS 认到哪个长度为止，而统计我们走自己的 OID_GEN_STATISTICS 处理。 */
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

	InterlockedExchange(&a->running, 1);
	iwan_cnt_trace(26, (LONG)a->echo_ip);
	DbgPrint("iwancnt: up, echo %u.%u.%u.%u mode %lu inner_off %lu\n",
		 (unsigned)((a->echo_ip >> 24) & 0xFF),
		 (unsigned)((a->echo_ip >> 16) & 0xFF),
		 (unsigned)((a->echo_ip >> 8) & 0xFF),
		 (unsigned)(a->echo_ip & 0xFF),
		 (unsigned long)a->echo_mode, (unsigned long)a->inner_off);
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
	/* 等在途回声帧归还；等不到就泄漏池，绝不释放可能再被引用的池。 */
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
		DbgPrint("iwancnt: halt 时仍有 %ld 帧未归还，池不释放\n",
			 (long)InterlockedCompareExchange(&a->inflight, 0, 0));
	}
	ExFreePoolWithTag(a, IWAN_CNT_TAG);
}

/* ---- 驱动入口 -------------------------------------------------------- */

static VOID
iwan_cnt_fill_ch(_Out_ PNDIS_MINIPORT_DRIVER_CHARACTERISTICS ch,
		 _In_ UCHAR minor)
{
	RtlZeroMemory(ch, sizeof(*ch));
	ch->Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
	ch->Header.Revision = NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;
	ch->Header.Size =
		NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;
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
}

NDIS_STATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
	    _In_ PUNICODE_STRING RegistryPath)
{
	NDIS_MINIPORT_DRIVER_CHARACTERISTICS ch;
	NDIS_HANDLE handle = NULL;
	NDIS_STATUS st;
	UCHAR minor;

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
	iwan_cnt_trace(30, (LONG)NdisGetVersion());

	minor = (UCHAR)(NdisGetVersion() & 0xFFu);
	if (minor < 20)
		minor = 20;
	iwan_cnt_fill_ch(&ch, minor);

	st = NdisMRegisterMiniportDriver(DriverObject, RegistryPath, NULL, &ch,
					 &handle);
	iwan_cnt_trace(31, (LONG)st);
	if (st != NDIS_STATUS_SUCCESS) {
		/* 注册失败：镜像会被卸载，返回失败是安全的。 */
		return st;
	}
	/* 注册成功之后绝不再返回失败、绝不注销：否则 NDIS 会持有指向已卸载
	 * 镜像的回调，开机直接起不来（iwanmp 踩过的坑）。 */
	DriverObject->DriverUnload = NULL;
	iwan_cnt_trace(32, 0);
	return NDIS_STATUS_SUCCESS;
}
