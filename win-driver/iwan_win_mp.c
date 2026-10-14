/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_mp.c — NDIS 小型端口：内层的那张虚拟网卡 + 驱动装载。
 *
 * 这一半负责"内层怎么进、怎么出"以及驱动生命周期：
 *
 *   内层出口（上行）：协议栈按路由把内层数据报交给本小型端口 →
 *      逐 NB 交给引擎 iwan_win_mp_encap_send() → 同步完成后立刻
 *      NdisMSendNetBufferListsComplete 归还 NBL。**不留任何在途 NBL**，
 *      所以 WFP 平面那套"注入在途占池、必须限流"的问题在这里不存在
 *      （引擎仍保留一个上限，防的是承载侧积压，不是自己）。
 *   内层入口（下行）：引擎解封出内层数据报 → iwan_win_mp_indicate_inner()
 *      起一个 NBL 指示向上；NBL 归还时（MiniportReturnNetBufferLists）
 *      释放缓冲。等价于 Linux 侧 netif_rx()，比注入少一次协议栈入口。
 *
 * 介质类型选 NdisMediumIP（裸 IP，不带以太头），与 Linux 侧内层设备
 * NOARP/无链路层地址的形态一致：内层地址由客户端配到这张适配器上，
 * 报文一律从 IP 首部开始。
 *
 * 生命周期上的两个要点：
 *   ① 本平面是 PnP 的（NDIS 小型端口），所以驱动卸载走 UnloadHandler，
 *      不是 DriverUnload —— 注册小型端口之后那个字段归 NDIS 管。因此
 *      iwan_win_mp_unload_hook() 要自己做完整套清理（数据面 + 会话 +
 *      控制设备 + 扩展内存）。
 *   ② 控制设备不能用 IoCreateDevice 建在 DriverEntry 里：那会给驱动对象
 *      挂上自己的设备对象、并换掉 MajorFunction，而 NdisMRegisterMiniport
 *      Driver 要求调用时驱动对象是"干净"的。正确顺序是"先注册小型端口
 *      （驱动对象干净）→ 再用 NDIS 的 NdisRegisterDeviceEx 建控制设备 →
 *      最后才换那四个 MajorFunction"。判别哪个设备是自己的用指针比较
 *      （NDIS 的设备对象上 Reserved 也非空，用 Reserved 判别会认错）。
 *   ③ 客体上注册这一步曾直接回 NDIS_STATUS_BAD_CHARACTERISTICS
 *      (0xC0010005)——驱动对象已经干净、特性表除版本号外与参考实现逐字段
 *      同形，因此把"声明的 NDIS 版本 / 特性表 revision"做成一张候选表逐个
 *      试（见 iwan_win_mp_register），每次尝试的状态写进注册表，一次装机
 *      就能读出到底哪一项不合规。
 *
 * 并发：发送路径与指示路径都可能处于 DISPATCH_LEVEL；本文件不等待、不加
 * 互斥、不碰可分页内存。整个平面只支持一个隧道适配器（与"一条会话绑一张
 * 网卡"、控制设备单例一致），所以 g_mp_ext 是单例指针，在 iwan_win_mp_init
 * 里建立、UnloadHandler 里撤销。
 */
#include "iwan_win.h"

/* 内层适配器上报的 MTU。真实值由客户端按会话协商结果写到这张适配器上
 * （netsh/Set-NetIPInterface，对应 Linux 的 dev->mtu）；这里只是上报上限。 */
#define IWAN_MP_INNER_MTU	1500u
#define IWAN_MP_LINK_SPEED	10000000000ULL

static IWAN_WIN_DEVICE_EXTENSION *g_mp_ext;	/* 隧道适配器上下文（单例） */

/* 卸载钩子：既是 MiniportUnloadHandler，也承担 WFP 平面里 DriverUnload
 * 的那部分清理（注册小型端口之后 DriverUnload 归 NDIS 管，不会调我们）。 */
static VOID iwan_win_mp_unload_hook(_In_ PDRIVER_OBJECT driver);

/* ---- 控制设备分发 ------------------------------------------------
 *
 * 控制设备由 NdisRegisterDeviceEx 建，注册时把下面这张表交给 NDIS：它按表
 * 建一个独立的驱动对象给这个设备用，所以既不用碰 NDIS 自己的 DriverObject，
 * 也不用在每条 IRP 上分辨"这个设备是谁的"。NDIS 自己那些设备（小型端口的
 * FDO、协议边绑定用的设备）由 NDIS 自己分发，与本表无关。
 *
 * 未登记的表项（例如 IRP_MJ_PNP）由 I/O 管理器回 STATUS_INVALID_DEVICE_REQUEST
 * —— 控制设备不在 PnP 栈里，正常收不到那些 IRP。
 */
static DRIVER_DISPATCH *g_mp_major[IRP_MJ_MAXIMUM_FUNCTION + 1];

/* 设备对象属性的对象类型常量不在 km\ndis.h 里（那一族在 SDK 的共享对象类型
 * 头里）。万一这个 WDK 版本没有它，就退回 NDIS 的"默认"类型：NdisRegisterDeviceEx
 * 按 Size/Revision 解释这张表，类型只作标记。 */
#ifndef NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES
#define NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES NDIS_OBJECT_TYPE_DEFAULT
#endif

static VOID
iwan_win_mp_fill_major(VOID)
{
	RtlZeroMemory(g_mp_major, sizeof(g_mp_major));
	g_mp_major[IRP_MJ_CREATE] = iwan_win_dispatch_create;
	g_mp_major[IRP_MJ_CLOSE] = iwan_win_dispatch_create;
	g_mp_major[IRP_MJ_DEVICE_CONTROL] = iwan_win_dispatch_ioctl;
}

/* ---- 小型端口：初始化 / 停止 / 暂停 / 恢复 ---------------------------- */

static NDIS_STATUS
iwan_win_mp_initialize(_In_ NDIS_HANDLE MiniportAdapterHandle,
		       _In_ NDIS_HANDLE MiniportDriverContext,
		       _In_ PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters)
{
	IWAN_WIN_DEVICE_EXTENSION *ext =
		(IWAN_WIN_DEVICE_EXTENSION *)MiniportDriverContext;
	NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES reg;
	NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES gen;
	NET_BUFFER_LIST_POOL_PARAMETERS pp;
	NDIS_STATUS st;

	UNREFERENCED_PARAMETER(MiniportInitParameters);

	iwan_win_mp_trace(20, 0);

	/* 一份扩展只服务一个适配器。判据是 mp_handle 而不是 g_mp_ext：后者
	 * 在 Halt 之后仍然存在（控制设备还要用它），只有卸载才清。 */
	if (ext->mp.mp_handle != NULL) {
		DbgPrint("iwanmp: 已经有一个隧道适配器，不再接受第二个\n");
		iwan_win_mp_trace(21, NDIS_STATUS_NOT_SUPPORTED);
		return NDIS_STATUS_NOT_SUPPORTED;
	}

	/* NBL 池在适配器启动时建、停止时销毁：NdisAllocateNetBufferListPool
	 * 要在拿到适配器句柄之后调用（这里正是有句柄的地方）。 */
	RtlZeroMemory(&pp, sizeof(pp));
	pp.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	pp.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	pp.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	pp.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
	pp.fAllocateNetBuffer = TRUE;
	pp.ContextSize = IWAN_MP_NBL_CTX_SIZE;
	pp.PoolTag = IWAN_TAG_PKT;
	ext->mp.nbl_pool = NdisAllocateNetBufferListPool(MiniportAdapterHandle, &pp);
	if (ext->mp.nbl_pool == NULL) {
		iwan_win_mp_trace(21, NDIS_STATUS_RESOURCES);
		DbgPrint("iwanmp: NBL 池分配失败\n");
		return NDIS_STATUS_RESOURCES;
	}

	RtlZeroMemory(&reg, sizeof(reg));
	reg.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;
	reg.Header.Revision =
		NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
	reg.Header.Size =
		NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
	reg.MiniportAdapterContext = ext;
	reg.AttributeFlags = NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND |
			     NDIS_MINIPORT_ATTRIBUTES_SURPRISE_REMOVE_OK;
	reg.CheckForHangTimeInSeconds = 0;
	reg.InterfaceType = NdisInterfaceInternal;
	st = NdisMSetMiniportAttributes(MiniportAdapterHandle,
					(PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&reg);
	if (st != NDIS_STATUS_SUCCESS)
		goto fail;

	RtlZeroMemory(&gen, sizeof(gen));
	gen.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;
	gen.Header.Revision = NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
	gen.Header.Size =
		NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
	gen.MediaType = NdisMediumIP;	/* 裸 IP：内层没有以太头，也没有 ARP */
	gen.PhysicalMediumType = NdisPhysicalMediumUnspecified;
	gen.MtuSize = IWAN_MP_INNER_MTU;
	gen.MaxXmitLinkSpeed = IWAN_MP_LINK_SPEED;
	gen.XmitLinkSpeed = IWAN_MP_LINK_SPEED;
	gen.MaxRcvLinkSpeed = IWAN_MP_LINK_SPEED;
	gen.RcvLinkSpeed = IWAN_MP_LINK_SPEED;
	gen.MediaConnectState = MediaConnectStateConnected;
	gen.MediaDuplexState = MediaDuplexStateFull;
	gen.LookaheadSize = IWAN_MP_INNER_MTU;
	gen.MacOptions = NDIS_MAC_OPTION_NO_LOOPBACK |
			 NDIS_MAC_OPTION_TRANSFERS_NOT_PEND |
			 NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA;
	gen.SupportedPacketFilters = NDIS_PACKET_TYPE_DIRECTED |
				     NDIS_PACKET_TYPE_MULTICAST |
				     NDIS_PACKET_TYPE_ALL_MULTICAST |
				     NDIS_PACKET_TYPE_BROADCAST;
	gen.MaxMulticastListSize = 32;
	gen.MacAddressLength = 0;	/* NdisMediumIP：没有链路层地址 */
	gen.AccessType = NET_IF_ACCESS_BROADCAST;
	gen.DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
	gen.ConnectionType = NET_IF_CONNECTION_DEDICATED;
	gen.IfType = IF_TYPE_PROP_VIRTUAL;
	gen.IfConnectorPresent = FALSE;
	gen.SupportedStatistics = NDIS_STATISTICS_XMIT_OK_SUPPORTED |
				  NDIS_STATISTICS_RCV_OK_SUPPORTED;
	gen.SupportedPauseFunctions = NdisPauseFunctionsUnsupported;
	gen.AutoNegotiationFlags = 0;
	gen.SupportedOidList = NULL;
	gen.SupportedOidListLength = 0;
	gen.DataBackFillSize = 0;
	gen.ContextBackFillSize = 0;
	st = NdisMSetMiniportAttributes(MiniportAdapterHandle,
					(PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&gen);
	if (st != NDIS_STATUS_SUCCESS)
		goto fail;

	ext->mp.mp_handle = MiniportAdapterHandle;
	g_mp_ext = ext;
	InterlockedExchange(&ext->mp.mp_running, 1);
	iwan_win_mp_trace(22, 0);
	DbgPrint("iwanmp: 内层适配器已就绪（NdisMediumIP，MTU %lu）\n",
		 (unsigned long)IWAN_MP_INNER_MTU);
	return NDIS_STATUS_SUCCESS;

fail:
	iwan_win_mp_trace(21, (LONG)st);
	NdisFreeNetBufferListPool(ext->mp.nbl_pool);
	ext->mp.nbl_pool = NULL;
	return st;
}

static VOID
iwan_win_mp_halt(_In_ NDIS_HANDLE MiniportAdapterHandle,
		 _In_ NDIS_HALT_ACTION HaltAction)
{
	IWAN_WIN_DEVICE_EXTENSION *ext = g_mp_ext;

	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(HaltAction);

	if (ext == NULL)
		return;
	/* 先关门再放承载：数据面两条路径都以 mp_running 为闸门 */
	InterlockedExchange(&ext->mp.mp_running, 0);
	ext->mp.mp_handle = NULL;
	/* 注意：这里**不能**清 g_mp_ext。Halt 只表示适配器停了，扩展内存还
	 * 归控制设备用（它要到 UnloadHandler 才释放）；清掉的话，适配器停掉
	 * 之后任何一个 IOCTL 都会解引用空指针。会话是否还活着由 sess.valid
	 * 表示，控制面按它拒绝即可。 */
	iwan_win_mp_release_carrier(ext);
	if (ext->mp.nbl_pool != NULL) {
		NdisFreeNetBufferListPool(ext->mp.nbl_pool);
		ext->mp.nbl_pool = NULL;
	}
	DbgPrint("iwanmp: 内层适配器已停止\n");
}

static NDIS_STATUS
iwan_win_mp_pause(_In_ NDIS_HANDLE MiniportAdapterHandle,
		  _In_ PNDIS_MINIPORT_PAUSE_PARAMETERS PauseParameters)
{
	IWAN_WIN_DEVICE_EXTENSION *ext = g_mp_ext;

	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(PauseParameters);

	if (ext != NULL)
		InterlockedExchange(&ext->mp.mp_running, 0);
	return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
iwan_win_mp_restart(_In_ NDIS_HANDLE MiniportAdapterHandle,
		    _In_ PNDIS_MINIPORT_RESTART_PARAMETERS RestartParameters)
{
	IWAN_WIN_DEVICE_EXTENSION *ext = g_mp_ext;

	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(RestartParameters);

	if (ext != NULL)
		InterlockedExchange(&ext->mp.mp_running, 1);
	return NDIS_STATUS_SUCCESS;
}

/* ---- 小型端口：发送（内层 → 外层） ----------------------------------- */

/* 把一个 NBL 链当一包处理：逐 NB 交给引擎，最后整条链一次完成。
 * 按平台约定，发送路径不得改写 NBL 链的 NEXT_NBL（那会拆散分片的 NBL）。 */
static VOID
iwan_win_mp_send_nbls(_In_ NDIS_HANDLE MiniportAdapterHandle,
		      _In_ PNET_BUFFER_LIST NetBufferLists,
		      _In_ NDIS_PORT_NUMBER PortNumber,
		      _In_ ULONG SendFlags)
{
	IWAN_WIN_DEVICE_EXTENSION *ext = g_mp_ext;
	PNET_BUFFER_LIST nbl;
	BOOLEAN l4_offloaded;

	UNREFERENCED_PARAMETER(PortNumber);
	UNREFERENCED_PARAMETER(SendFlags);

	if (ext == NULL) {
		NdisMSendNetBufferListsComplete(MiniportAdapterHandle, NetBufferLists, 0);
		return;
	}

	for (nbl = NetBufferLists; nbl != NULL; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl)) {
		NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO ci;
		PNET_BUFFER nb;
		NDIS_STATUS st = NDIS_STATUS_SUCCESS;

		ci.Value = NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo);
		l4_offloaded = (ci.Transmit.TcpChecksum ||
				ci.Transmit.UdpChecksum) ? TRUE : FALSE;

		for (nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb != NULL;
		     nb = NET_BUFFER_NEXT_NB(nb)) {
			UINT8 hdr[IWAN_INNER_IP4_LEN];
			const UINT8 *p;
			ULONG len = NET_BUFFER_DATA_LENGTH(nb);
			BOOLEAN ok;

			if (len < IWAN_INNER_IP4_LEN) {
				st = NDIS_STATUS_FAILURE;
				continue;
			}
			p = (const UINT8 *)NdisGetDataBuffer(nb, IWAN_INNER_IP4_LEN,
							     hdr, 1, 0);
			if (p == NULL || (p[0] >> 4) != 4) {
				/* 不是内层 IPv4：本适配器只承载 IPv4 隧道
				 * （v6 的邻居发现见第二阶段），明确失败，
				 * 让协议栈看到丢包而不是静默。 */
				st = NDIS_STATUS_FAILURE;
				IWAN_MP_STAT_INC(ext, tx_bad_inner);
				continue;
			}
			if (NdisGetDataBuffer(nb, len, NULL, 1, 0) != NULL) {
				/* 连续：零拷贝直接交给引擎 */
				p = (const UINT8 *)NdisGetDataBuffer(nb, len, NULL, 1, 0);
				ok = iwan_win_mp_encap_send(ext, p, len, l4_offloaded);
			} else {
				UINT8 *tmp = (UINT8 *)IWAN_ALLOC(len, IWAN_TAG_PKT);

				if (tmp == NULL) {
					IWAN_MP_STAT_INC(ext, tx_err);
					ok = FALSE;
				} else {
					p = (const UINT8 *)NdisGetDataBuffer(nb, len,
									     tmp, 1, 0);
					ok = p != NULL &&
					     iwan_win_mp_encap_send(ext, p, len,
								    l4_offloaded);
					ExFreePoolWithTag(tmp, IWAN_TAG_PKT);
				}
			}
			if (!ok)
				st = NDIS_STATUS_FAILURE;
		}
		NET_BUFFER_LIST_STATUS(nbl) = st;
	}
	NdisMSendNetBufferListsComplete(MiniportAdapterHandle, NetBufferLists, 0);
}

static VOID
iwan_win_mp_cancel_send(_In_ NDIS_HANDLE MiniportAdapterHandle,
			_In_ PVOID CancelId)
{
	/* 本小型端口从不在发送路径上挂起：收下就同步完成，所以没有可取消
	 * 的发送。留一个空实现是为了让契约完整（NDIS 不会调它）。 */
	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(CancelId);
}

/* ---- 小型端口：指示向上 / 归还（外层 → 内层） ------------------------- */

BOOLEAN
iwan_win_mp_indicate_inner(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			   _In_reads_bytes_(len) UINT8 *inner, _In_ ULONG len)
{
	NET_BUFFER_LIST *nbl;
	PMDL mdl;
	UINT8 ver;

	if (ext->mp.mp_handle == NULL || ext->mp.mp_running == 0 || len == 0) {
		ExFreePoolWithTag(inner, IWAN_TAG_PKT);
		return FALSE;
	}
	ver = (UINT8)(inner[0] >> 4);
	if (ver != 4 && ver != 6) {
		ExFreePoolWithTag(inner, IWAN_TAG_PKT);
		return FALSE;
	}

	mdl = IoAllocateMdl(inner, len, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		ExFreePoolWithTag(inner, IWAN_TAG_PKT);
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(mdl);

	nbl = NdisAllocateNetBufferAndNetBufferList(ext->mp.nbl_pool,
						    IWAN_MP_NBL_CTX_SIZE, 0,
						    mdl, 0, len);
	if (nbl == NULL) {
		IoFreeMdl(mdl);
		ExFreePoolWithTag(inner, IWAN_TAG_PKT);
		return FALSE;
	}
	nbl->SourceHandle = ext->mp.mp_handle;
	nbl->NblFlags |= (ver == 4) ? NDIS_NBL_FLAGS_IS_IPV4 : NDIS_NBL_FLAGS_IS_IPV6;

	/* 不带 RESOURCES：所有权交给 NDIS，归还时释放缓冲 */
	NdisMIndicateReceiveNetBufferLists(ext->mp.mp_handle, nbl,
					   NDIS_DEFAULT_PORT_NUMBER, 1,
					   NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE);
	return TRUE;
}

static VOID
iwan_win_mp_return_nbls(_In_ NDIS_HANDLE MiniportAdapterHandle,
			_In_ PNET_BUFFER_LIST NetBufferLists,
			_In_ ULONG ReturnFlags)
{
	PNET_BUFFER_LIST nbl;

	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(ReturnFlags);

	for (nbl = NetBufferLists; nbl != NULL; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl)) {
		PNET_BUFFER nb;

		for (nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb != NULL;
		     nb = NET_BUFFER_NEXT_NB(nb)) {
			PMDL mdl = NET_BUFFER_FIRST_MDL(nb);
			PVOID va = MmGetMdlVirtualAddress(mdl);

			/* 指示时缓冲与 MDL 一一对应（offset 0、整包），
			 * 所以直接反推即可，不需要另存映射。 */
			IoFreeMdl(mdl);
			ExFreePoolWithTag(va, IWAN_TAG_PKT);
		}
		NdisFreeNetBufferList(nbl);
	}
}

/* ---- 小型端口：OID --------------------------------------------------- */

/* 按请求缓冲的长度写 4 或 8 字节（NDIS 6 里两者都合法） */
static NDIS_STATUS
iwan_win_mp_oid_put_u64(_Inout_ PNDIS_OID_REQUEST oid, _In_ UINT64 v)
{
	ULONG need = (oid->DATA.QUERY_INFORMATION.InformationBufferLength >= 8) ?
		     8u : 4u;
	PUCHAR buf = (PUCHAR)oid->DATA.QUERY_INFORMATION.InformationBuffer;

	if (oid->DATA.QUERY_INFORMATION.InformationBufferLength < need) {
		oid->DATA.QUERY_INFORMATION.BytesNeeded = need;
		return NDIS_STATUS_BUFFER_TOO_SHORT;
	}
	if (need == 8)
		*(UINT64 UNALIGNED *)buf = v;
	else
		*(UINT32 UNALIGNED *)buf = (UINT32)v;
	oid->DATA.QUERY_INFORMATION.BytesWritten = need;
	return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
iwan_win_mp_oid_string(_Inout_ PNDIS_OID_REQUEST oid, _In_ const char *s)
{
	size_t n = 0;
	PUCHAR buf = (PUCHAR)oid->DATA.QUERY_INFORMATION.InformationBuffer;

	while (s[n] != '\0')
		n++;
	n++;				/* 连结尾的 NUL 一起给 */
	if (oid->DATA.QUERY_INFORMATION.InformationBufferLength < n) {
		oid->DATA.QUERY_INFORMATION.BytesNeeded = (ULONG)n;
		return NDIS_STATUS_BUFFER_TOO_SHORT;
	}
	RtlCopyMemory(buf, s, n);
	oid->DATA.QUERY_INFORMATION.BytesWritten = (ULONG)n;
	return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
iwan_win_mp_oid_request(_In_ NDIS_HANDLE MiniportAdapterHandle,
			_In_ PNDIS_OID_REQUEST OidRequest)
{
	IWAN_WIN_DEVICE_EXTENSION *ext = g_mp_ext;
	NDIS_STATUS st;

	UNREFERENCED_PARAMETER(MiniportAdapterHandle);

	if (OidRequest->RequestType == NdisRequestSetInformation) {
		switch (OidRequest->DATA.SET_INFORMATION.Oid) {
		case OID_GEN_CURRENT_PACKET_FILTER:
		case OID_GEN_CURRENT_LOOKAHEAD:
		case OID_PNP_SET_POWER:
			/* 一律接受：本适配器不加过滤，电源状态也不影响收发 */
			return NDIS_STATUS_SUCCESS;
		default:
			return NDIS_STATUS_NOT_SUPPORTED;
		}
	}
	if (OidRequest->RequestType != NdisRequestQueryInformation)
		return NDIS_STATUS_NOT_SUPPORTED;

	switch (OidRequest->DATA.QUERY_INFORMATION.Oid) {
	case OID_GEN_MAXIMUM_TOTAL_SIZE:
	case OID_GEN_MAXIMUM_FRAME_SIZE:
	case OID_GEN_TRANSMIT_BLOCK_SIZE:
	case OID_GEN_RECEIVE_BLOCK_SIZE:
	case OID_GEN_CURRENT_LOOKAHEAD:
		return iwan_win_mp_oid_put_u64(OidRequest, IWAN_MP_INNER_MTU);
	case OID_GEN_TRANSMIT_BUFFER_SPACE:
	case OID_GEN_RECEIVE_BUFFER_SPACE:
		return iwan_win_mp_oid_put_u64(OidRequest, 0x400000u);
	case OID_GEN_VENDOR_ID:
		return iwan_win_mp_oid_put_u64(OidRequest, 0xFFFFFF00u);
	case OID_GEN_VENDOR_DESCRIPTION:
		return iwan_win_mp_oid_string(OidRequest, "iWAN tunnel");
	case OID_GEN_DRIVER_VERSION:
		return iwan_win_mp_oid_put_u64(OidRequest, 0x0100u);
	case OID_GEN_MEDIA_CONNECT_STATUS:
		return iwan_win_mp_oid_put_u64(OidRequest, NdisMediaStateConnected);
	case OID_GEN_CURRENT_PACKET_FILTER:
		return iwan_win_mp_oid_put_u64(OidRequest,
			NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_BROADCAST |
			NDIS_PACKET_TYPE_ALL_MULTICAST);
	case OID_GEN_XMIT_OK:
		return iwan_win_mp_oid_put_u64(OidRequest, ext != NULL ?
			(UINT64)ext->sess.stats.tx_pkts : 0);
	case OID_GEN_RCV_OK:
		return iwan_win_mp_oid_put_u64(OidRequest, ext != NULL ?
			(UINT64)ext->sess.stats.rx_delivered : 0);
	case OID_PNP_QUERY_POWER:
		st = NDIS_STATUS_SUCCESS;
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
		return st;
	default:
		return NDIS_STATUS_NOT_SUPPORTED;
	}
}

static VOID
iwan_win_mp_cancel_oid(_In_ NDIS_HANDLE MiniportAdapterHandle,
		       _In_ PVOID RequestId)
{
	/* 同理：OID 请求全部同步完成，没有可取消的 */
	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(RequestId);
}

static VOID
iwan_win_mp_pnp_event(_In_ NDIS_HANDLE MiniportAdapterContext,
		      _In_ PNET_DEVICE_PNP_EVENT NetDevicePnPEvent)
{
	UNREFERENCED_PARAMETER(MiniportAdapterContext);
	UNREFERENCED_PARAMETER(NetDevicePnPEvent);
}

static VOID
iwan_win_mp_shutdown(_In_ NDIS_HANDLE MiniportAdapterContext,
		     _In_ NDIS_SHUTDOWN_ACTION ShutdownAction)
{
	IWAN_WIN_DEVICE_EXTENSION *ext = g_mp_ext;

	UNREFERENCED_PARAMETER(MiniportAdapterContext);
	UNREFERENCED_PARAMETER(ShutdownAction);

	if (ext != NULL)
		InterlockedExchange(&ext->mp.mp_running, 0);
}

/* ---- 注册 / 注销 ----------------------------------------------------- */

/* 控制面取扩展：本平面没有设备扩展（NdisRegisterDeviceEx 建的控制设备
 * 不带扩展），扩展是 DriverEntry 分配的唯一那一份。 */
IWAN_WIN_DEVICE_EXTENSION *
iwan_win_mp_device_ext(VOID)
{
	return g_mp_ext;
}

/* ---- 注册：按 NDIS 的最小版本要求试探 -------------------------------- */

/* DirectOid / SynchronousOid 三个 handler：本平面一个 OID 都不主动发，
 * 一律回"不支持"。它们只在 REVISION_2/3 的特性表里出现（选老 revision
 * 时字段根本不存在），写在这里是为了让候选配置能覆盖三种 revision。 */
static NDIS_STATUS
iwan_win_mp_direct_oid(_In_ NDIS_HANDLE MiniportAdapterHandle,
		       _In_ PNDIS_OID_REQUEST OidRequest)
{
	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(OidRequest);
	return NDIS_STATUS_NOT_SUPPORTED;
}

static VOID
iwan_win_mp_cancel_direct_oid(_In_ NDIS_HANDLE MiniportAdapterHandle,
			      _In_ PVOID RequestId)
{
	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(RequestId);
}

static NDIS_STATUS
iwan_win_mp_sync_oid(_In_ NDIS_HANDLE MiniportAdapterHandle,
		     _In_ PNDIS_OID_REQUEST OidRequest)
{
	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(OidRequest);
	return NDIS_STATUS_NOT_SUPPORTED;
}

/* 按（声明的 NDIS 次版本、特性表 revision）填一张特性表。handler 集合
 * 与 revision 严格对应：选了高 revision 就必须给齐那一档的字段。 */
static VOID
iwan_win_mp_fill_ch(_Out_ PNDIS_MINIPORT_DRIVER_CHARACTERISTICS ch,
		    _In_ UCHAR minor, _In_ UCHAR revision)
{
	RtlZeroMemory(ch, sizeof(*ch));
	ch->Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
	ch->Header.Revision = revision;
	switch (revision) {
	case NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3:
		ch->Header.Size =
			NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3;
		ch->DirectOidRequestHandler = iwan_win_mp_direct_oid;
		ch->CancelDirectOidRequestHandler = iwan_win_mp_cancel_direct_oid;
		ch->SynchronousOidRequestHandler = iwan_win_mp_sync_oid;
		break;
	case NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2:
		ch->Header.Size =
			NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
		ch->DirectOidRequestHandler = iwan_win_mp_direct_oid;
		ch->CancelDirectOidRequestHandler = iwan_win_mp_cancel_direct_oid;
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
	ch->InitializeHandlerEx = iwan_win_mp_initialize;
	ch->HaltHandlerEx = iwan_win_mp_halt;
	ch->UnloadHandler = iwan_win_mp_unload_hook;
	ch->PauseHandler = iwan_win_mp_pause;
	ch->RestartHandler = iwan_win_mp_restart;
	ch->OidRequestHandler = iwan_win_mp_oid_request;
	ch->SendNetBufferListsHandler = iwan_win_mp_send_nbls;
	ch->ReturnNetBufferListsHandler = iwan_win_mp_return_nbls;
	ch->CancelSendHandler = iwan_win_mp_cancel_send;
	ch->DevicePnPEventNotifyHandler = iwan_win_mp_pnp_event;
	ch->ShutdownHandlerEx = iwan_win_mp_shutdown;
	ch->CancelOidRequestHandler = iwan_win_mp_cancel_oid;
}

/* 候选表：先照参考实现（Wintun）的形状声明"本机运行时的 NDIS 次版本 +
 * 最新 revision"，再逐个降级。每次尝试的状态写进 T40 起的键，命中即用
 * 那一张配置完成注册。这样一次装机就能把"哪一项不合规"钉死，不必一轮
 * 改一个值（每一轮都是十分钟的构建 + 换包 + 重启设备）。
 *
 * 为什么怀疑是版本而不是别的字段：客体（Windows 11 24H2 一档，NDIS
 * 6.89）回的是 NDIS_STATUS_BAD_CHARACTERISTICS，而这份特性表除版本号
 * 外与参考实现逐字段同形。新版 Windows 对微型端口声明的最低 NDIS 版本
 * 有下限，旧驱动被拒就是这个码。 */
static const UINT16 iwan_win_mp_minors[] = {
	0u,	/* 占位：用运行时的次版本 */
	85u,
	80u,
	60u,
	50u,
	30u
};

static NDIS_STATUS
iwan_win_mp_register(_In_ PDRIVER_OBJECT driver,
		     _In_ PUNICODE_STRING registry_path,
		     _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	UINT16 runtime = (UINT16)(NdisGetVersion() & 0xFFFFu);
	ULONG i, k, stage = 40;
	NDIS_STATUS last = NDIS_STATUS_BAD_CHARACTERISTICS;

	for (i = 0; i < RTL_NUMBER_OF(iwan_win_mp_minors); i++) {
		UINT16 minor = (i == 0) ? runtime : iwan_win_mp_minors[i];

		for (k = 0; k < 2; k++) {
			NDIS_MINIPORT_DRIVER_CHARACTERISTICS ch;
			UCHAR rev = (k == 0) ?
				NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1 :
				NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3;
			NDIS_STATUS st;

			iwan_win_mp_fill_ch(&ch, (UCHAR)minor, rev);
			st = NdisMRegisterMiniportDriver(driver, registry_path,
							 ext, &ch,
							 &ext->mp.mp_handle);
			iwan_win_mp_trace(stage++, (LONG)st);
			last = st;
			if (st == NDIS_STATUS_SUCCESS) {
				/* 39 = 命中：低 8 位是 revision，次 8 位是
				 * 声明的次版本 */
				iwan_win_mp_trace(39, (LONG)((minor << 8) | rev));
				return NDIS_STATUS_SUCCESS;
			}
		}
	}
	return last;
}

NTSTATUS
iwan_win_mp_init(_In_ PDRIVER_OBJECT driver,
		 _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		 _In_ PUNICODE_STRING registry_path)
{
	NDIS_STATUS st, stp;

	/* 让后续的池分配走 NX（不执行）内存：内核态指针被改写利用的门槛
	 * 更高，这条更接近"默认安全"。 */
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
	KeInitializeSpinLock(&ext->mp.lock);

	/* 单例在注册之前就挂上：MiniportInitializeEx 可能在任何时刻被调用，
	 * 而且控制设备的 IRP 只有在这之后才可能出现。 */
	g_mp_ext = ext;

	/* 阶段 30 记的是"环境"：T30 = NdisGetVersion()（形如 0x00060059 表示
	 * NDIS 6.89）。注册失败时要能区分"驱动写错了"与"这台机器的 NDIS
	 * 比驱动声明的版本还旧"，这一条是唯一的判据。 */
	iwan_win_mp_trace(30, (LONG)NdisGetVersion());

	/* 两半的注册顺序本身也是待验证的事实：先协议边，再小型端口。协议边
	 * 一注册就会开始收帧，那时小型端口还没起来也不要紧——收帧回调只往
	 * 引擎里递一个内层数据报，引擎在会话未建立时什么都不做。
	 * 两份结果分开落键：协议边 60+（版本阶梯）、小型端口 40+（版本/修订
	 * 阶梯），总账落 12/13。 */
	stp = iwan_win_proto_init(ext);
	st = iwan_win_mp_register(driver, registry_path, ext);
	iwan_win_mp_trace(12, (LONG)(stp == NDIS_STATUS_SUCCESS ? st : stp));
	if (stp != NDIS_STATUS_SUCCESS || st != NDIS_STATUS_SUCCESS) {
		/* 失败路径必须把已经成功的那一半注销掉。留一个"已注册但
		 * DriverEntry 失败"的半个驱动，NDIS 会一直认为它还在：客体实测
		 * 这种状态下后续的 devcon remove / pnputil /delete-driver 会永久
		 * 挂住（整机失去响应）。 */
		if (st == NDIS_STATUS_SUCCESS) {
			NdisMDeregisterMiniportDriver(ext->mp.mp_handle);
			ext->mp.mp_handle = NULL;
		}
		if (stp == NDIS_STATUS_SUCCESS)
			iwan_win_proto_fini(ext);
		iwan_win_mp_trace(10, (LONG)st);
		g_mp_ext = NULL;
		DbgPrint("iwanmp: 注册失败（协议边 0x%08lx，小型端口 0x%08lx）\n",
			 (unsigned long)stp, (unsigned long)st);
		return STATUS_UNSUCCESSFUL;
	}
	iwan_win_mp_trace(13, STATUS_SUCCESS);
	DbgPrint("iwanmp: 已装载，%ws\n", IWAN_WIN_DRV_VERSION_STR_MP);
	return STATUS_SUCCESS;
}

/* 控制设备必须在小型端口注册之后建：NdisRegisterDeviceEx 要句柄，而且
 * NdisMRegisterMiniportDriver 要求调用时 DriverObject 是干净的（客体实测
 * 已经挂了自己的设备就回 NDIS_STATUS_BAD_CHARACTERISTICS = 0xC0010005）。
 * 属性表里带自己的 MajorFunctions，NDIS 据此给这个设备建独立的驱动对象，
 * 于是不必碰 NDIS 自己的 DriverObject。 */
NTSTATUS
iwan_win_mp_open_control(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	NDIS_DEVICE_OBJECT_ATTRIBUTES attr;
	NDIS_HANDLE handle = NULL;
	PDEVICE_OBJECT devobj = NULL;
	UNICODE_STRING dev_name, dos_name, sddl;
	NDIS_STATUS st;

	if (ext == NULL || ext->mp.mp_handle == NULL)
		return STATUS_INVALID_DEVICE_STATE;

	/* 与 WFP 平面同一条 SDDL：只有 System 与 Administrators 能打开。
	 * 用户态客户端因此需要管理员权限（与 Linux 侧需要 root 一致）。 */
	RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
	RtlInitUnicodeString(&dev_name, IWAN_WIN_DEVICE_NAME_MP);
	RtlInitUnicodeString(&dos_name, IWAN_WIN_DOS_NAME_MP);
	iwan_win_mp_fill_major();

	RtlZeroMemory(&attr, sizeof(attr));
	attr.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
	attr.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
	attr.Header.Size = NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
	attr.DeviceName = &dev_name;
	attr.SymbolicName = &dos_name;
	attr.MajorFunctions = g_mp_major;
	attr.ExtensionSize = 0;			/* 扩展在我们自己手里 */
	attr.DefaultSDDLString = &sddl;
	attr.DeviceClassGuid = &iwan_win_devclass_guid;

	st = NdisRegisterDeviceEx(ext->mp.mp_handle, &attr, &devobj, &handle);
	if (st != NDIS_STATUS_SUCCESS) {
		iwan_win_mp_trace(5, (LONG)st);
		DbgPrint("iwanmp: NdisRegisterDeviceEx 失败 0x%08lx\n",
			 (unsigned long)st);
		return STATUS_UNSUCCESSFUL;
	}

	ext->mp.ctrl_devobj = devobj;
	ext->mp.ctrl_handle = handle;
	DbgPrint("iwanmp: 控制设备 %wZ 就绪\n", &dev_name);
	return STATUS_SUCCESS;
}

VOID
iwan_win_mp_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	if (ext == NULL)
		return;
	iwan_win_proto_fini(ext);		/* 先断承载收发 */
	if (ext->mp.ctrl_handle != NULL) {
		NdisDeregisterDeviceEx(ext->mp.ctrl_handle);
		ext->mp.ctrl_handle = NULL;
		ext->mp.ctrl_devobj = NULL;
	}
	if (ext->mp.mp_handle != NULL) {
		NdisMDeregisterMiniportDriver(ext->mp.mp_handle);
		ext->mp.mp_handle = NULL;
	}
	if (ext->mp.nbl_pool != NULL) {
		NdisFreeNetBufferListPool(ext->mp.nbl_pool);
		ext->mp.nbl_pool = NULL;
	}
	g_mp_ext = NULL;
}

/* UnloadHandler：NDIS 在驱动卸载时调用（不是 DriverUnload —— 那个字段注册
 * 小型端口之后归 NDIS 管）。这里要做完整套退出：数据面 → 会话 → 扩展内存。
 * 控制设备由 NdisDeregisterDeviceEx 注销（符号链接它自己会删），扩展是我们
 * 分配的，也要在这里还掉。 */
static VOID
iwan_win_mp_unload_hook(_In_ PDRIVER_OBJECT driver)
{
	IWAN_WIN_DEVICE_EXTENSION *ext = g_mp_ext;

	UNREFERENCED_PARAMETER(driver);

	if (ext != NULL) {
		iwan_win_mp_fini(ext);
		iwan_win_session_teardown(ext);
		iwan_win_ctrl_fini(ext);
		ExFreePoolWithTag(ext, IWAN_TAG_SESS);
	}
	driver->DeviceObject = NULL;	/* 防御：DriverUnload 若也被调用则不重复 */
	DbgPrint("iwanmp: 已卸载\n");
}
