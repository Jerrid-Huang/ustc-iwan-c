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
 *      iwan_win_mp_unload() 要自己做完整套清理（数据面 + 会话 + 控制设备）。
 *   ② NdisMRegisterMiniportDriver 会把 DriverObject 的几个 MajorFunction
 *      换成 NDIS 自己的（它要处理自己的设备对象）。我们的控制设备是
 *      非 PnP 的裸设备，所以要先把 NDIS 的入口存下来，再装上自己的分发：
 *      自己的设备走控制面 IOCTL，其它设备（NDIS 的 FDO）原样转交。
 *      判别用 DeviceObject->Reserved：NDIS 在自己的设备对象上塞了上下文，
 *      我们的设备它是 NULL（IoCreateDevice 会清零）。
 *
 * 并发：发送路径与指示路径都可能处于 DISPATCH_LEVEL；本文件不等待、不加
 * 互斥、不碰可分页内存。整个平面只支持一个隧道适配器（与"一条会话绑一张
 * 网卡"、控制设备单例一致），所以 g_mp_ext 是单例指针，在 InitializeEx
 * 里建立、HaltEx 里撤销。
 */
#include "iwan_win.h"

/* 内层适配器上报的 MTU。真实值由客户端按会话协商结果写到这张适配器上
 * （netsh/Set-NetIPInterface，对应 Linux 的 dev->mtu）；这里只是上报上限。 */
#define IWAN_MP_INNER_MTU	1500u
#define IWAN_MP_LINK_SPEED	10000000000ULL

static IWAN_WIN_DEVICE_EXTENSION *g_mp_ext;	/* 隧道适配器上下文（单例） */
static PDEVICE_OBJECT g_mp_devobj;		/* 控制设备对象（单例） */

/* 卸载钩子：既是 MiniportUnloadHandler，也承担 WFP 平面里 DriverUnload
 * 的那部分清理（注册小型端口之后 DriverUnload 归 NDIS 管，不会调我们）。 */
static VOID iwan_win_mp_unload_hook(_In_ PDRIVER_OBJECT driver);

/* NDIS 保存下来的原始入口（注册小型端口之后才有意义） */
static DRIVER_DISPATCH *g_ndis_create;
static DRIVER_DISPATCH *g_ndis_close;
static DRIVER_DISPATCH *g_ndis_ioctl;
static DRIVER_DISPATCH *g_ndis_pnp;

/* ---- 控制设备分发：自己的设备走控制面，其它交给 NDIS ---------------- */

static BOOLEAN
iwan_win_mp_is_foreign(_In_ PDEVICE_OBJECT devobj)
{
	/* NDIS 在自己的设备对象上用 Reserved 挂上下文；我们的控制设备是
	 * IoCreateDevice 建的裸设备，该字段为零。 */
	return devobj->Reserved != NULL;
}

static NTSTATUS
iwan_win_mp_dispatch_create(_In_ PDEVICE_OBJECT devobj, _Inout_ PIRP irp)
{
	if (iwan_win_mp_is_foreign(devobj) && g_ndis_create != NULL)
		return g_ndis_create(devobj, irp);
	return iwan_win_dispatch_create(devobj, irp);
}

static NTSTATUS
iwan_win_mp_dispatch_close(_In_ PDEVICE_OBJECT devobj, _Inout_ PIRP irp)
{
	if (iwan_win_mp_is_foreign(devobj) && g_ndis_close != NULL)
		return g_ndis_close(devobj, irp);
	return iwan_win_dispatch_create(devobj, irp);
}

static NTSTATUS
iwan_win_mp_dispatch_ioctl(_In_ PDEVICE_OBJECT devobj, _Inout_ PIRP irp)
{
	if (iwan_win_mp_is_foreign(devobj) && g_ndis_ioctl != NULL)
		return g_ndis_ioctl(devobj, irp);
	return iwan_win_dispatch_ioctl(devobj, irp);
}

static NTSTATUS
iwan_win_mp_dispatch_pnp(_In_ PDEVICE_OBJECT devobj, _Inout_ PIRP irp)
{
	if (iwan_win_mp_is_foreign(devobj) && g_ndis_pnp != NULL)
		return g_ndis_pnp(devobj, irp);
	/* 控制设备不在 PnP 栈里，正常不会收到这些；收到就成功收场 */
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
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

	if (g_mp_ext != NULL) {
		DbgPrint("iwanmp: 已经有一个隧道适配器，不再接受第二个\n");
		return NDIS_STATUS_NOT_AVAILABLE;
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
	DbgPrint("iwanmp: 内层适配器已就绪（NdisMediumIP，MTU %lu）\n",
		 (unsigned long)IWAN_MP_INNER_MTU);
	return NDIS_STATUS_SUCCESS;

fail:
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
	g_mp_ext = NULL;
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
		switch (OidRequest->Oid) {
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

	switch (OidRequest->Oid) {
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

NTSTATUS
iwan_win_mp_init(_In_ PDRIVER_OBJECT driver, _In_ PDEVICE_OBJECT devobj,
		 _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		 _In_ PUNICODE_STRING registry_path)
{
	NDIS_MINIPORT_DRIVER_CHARACTERISTICS ch;
	NDIS_STATUS st;

	/* 让后续的池分配走 NX（不执行）内存：内核态指针被改写利用的门槛
	 * 更高，这条更接近"默认安全"。 */
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
	KeInitializeSpinLock(&ext->mp.lock);

	RtlZeroMemory(&ch, sizeof(ch));
	ch.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
	ch.Header.Revision = NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;
	ch.Header.Size = NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;
	ch.MajorNdisVersion = 6;
	ch.MinorNdisVersion = 30;
	ch.MajorDriverVersion = 1;
	ch.MinorDriverVersion = 0;
	ch.Flags = 0;
	ch.InitializeHandlerEx = iwan_win_mp_initialize;
	ch.HaltHandlerEx = iwan_win_mp_halt;
	ch.UnloadHandler = iwan_win_mp_unload_hook;
	ch.PauseHandler = iwan_win_mp_pause;
	ch.RestartHandler = iwan_win_mp_restart;
	ch.OidRequestHandler = iwan_win_mp_oid_request;
	ch.SendNetBufferListsHandler = iwan_win_mp_send_nbls;
	ch.ReturnNetBufferListsHandler = iwan_win_mp_return_nbls;
	ch.CancelSendHandler = iwan_win_mp_cancel_send;
	ch.DevicePnPEventNotifyHandler = iwan_win_mp_pnp_event;
	ch.ShutdownHandlerEx = iwan_win_mp_shutdown;
	ch.CancelOidRequestHandler = iwan_win_mp_cancel_oid;

	st = NdisMRegisterMiniportDriver(driver, registry_path, ext, &ch,
					 &ext->mp.mp_handle);
	if (st != NDIS_STATUS_SUCCESS) {
		DbgPrint("iwanmp: NdisMRegisterMiniportDriver 失败 0x%08lx\n",
			 (unsigned long)st);
		return STATUS_UNSUCCESSFUL;
	}
	/* 注册之后 DriverObject 的几个入口归 NDIS：它要处理自己的设备对象。
	 * 先把它们存下来，再装上我们的分发（自己的控制设备走控制面，
	 * NDIS 的设备原样转交）。 */
	g_ndis_create = driver->MajorFunction[IRP_MJ_CREATE];
	g_ndis_close = driver->MajorFunction[IRP_MJ_CLOSE];
	g_ndis_ioctl = driver->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	g_ndis_pnp = driver->MajorFunction[IRP_MJ_PNP];
	driver->MajorFunction[IRP_MJ_CREATE] = iwan_win_mp_dispatch_create;
	driver->MajorFunction[IRP_MJ_CLOSE] = iwan_win_mp_dispatch_close;
	driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = iwan_win_mp_dispatch_ioctl;
	driver->MajorFunction[IRP_MJ_PNP] = iwan_win_mp_dispatch_pnp;

	/* 协议边最后注册：它一注册就会开始收帧，那时小型端口已经在了 */
	st = iwan_win_proto_init(ext);
	if (st != STATUS_SUCCESS) {
		NdisMDeregisterMiniportDriver(ext->mp.mp_handle);
		ext->mp.mp_handle = NULL;
		return st;
	}
	g_mp_devobj = devobj;
	DbgPrint("iwanmp: 已装载，%ws\n", IWAN_WIN_DRV_VERSION_STR_MP);
	return STATUS_SUCCESS;
}

VOID
iwan_win_mp_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	if (ext == NULL)
		return;
	iwan_win_proto_fini(ext);		/* 先断承载收发 */
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
 * 小型端口之后归 NDIS 管）。这里要做完整套退出：数据面 → 会话 → 控制设备。 */
static VOID
iwan_win_mp_unload_hook(_In_ PDRIVER_OBJECT driver)
{
	UNICODE_STRING link;
	IWAN_WIN_DEVICE_EXTENSION *ext = g_mp_ext;
	PDEVICE_OBJECT devobj = g_mp_devobj;

	UNREFERENCED_PARAMETER(driver);

	if (ext != NULL) {
		iwan_win_mp_fini(ext);
		iwan_win_session_teardown(ext);
		iwan_win_ctrl_fini(ext);
	}
	if (devobj != NULL) {
		RtlInitUnicodeString(&link, IWAN_WIN_DOS_NAME_MP);
		IoDeleteSymbolicLink(&link);
		IoDeleteDevice(devobj);
		g_mp_devobj = NULL;
	}
	driver->DeviceObject = NULL;	/* 防御：DriverUnload 若也被调用则不重复 */
	DbgPrint("iwanmp: 已卸载\n");
}
