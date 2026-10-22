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
/* 内层适配器对外声明的 MTU。取 1400 而不是 1500 有两条硬理由：
 *   ① 隧道开销：外层 IPv4+UDP 共 28 字节、帧头 8 字节，一条 1500 字节的
 *      承载只能装下 1464 字节内层。声明 1500 等于让协议栈交出装不下的报文，
 *      而数据面遇到装不下是**丢**（fail-closed，计 tx_bad_state）—— 表现为
 *      "小包能通、大包黑洞"，最难查的一类症状；
 *   ② 真实 MTU 由控制面决定：服务端在鉴权应答里给出 inner_mtu（通常 1400），
 *      控制面用 netsh 把本适配器的 MTU 设成那个值（src/common/route.c 的
 *      route_iface_up）。这里只是"控制面还没来得及设"时的保守缺省。 */
#define IWAN_MP_INNER_MTU	1400u
#define IWAN_MP_LINK_SPEED	10000000000ULL

static IWAN_WIN_DEVICE_EXTENSION *g_mp_ext;	/* 隧道适配器上下文（单例） */

/* 卸载钩子：既是 MiniportUnloadHandler，也承担 WFP 平面里 DriverUnload
 * 的那部分清理（注册小型端口之后 DriverUnload 归 NDIS 管，不会调我们）。 */
static
_Function_class_(MINIPORT_UNLOAD)
VOID iwan_win_mp_unload_hook(_In_ PDRIVER_OBJECT driver);

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

/* 表里填的是 iwan_win.h 中带 _Function_class_(DRIVER_DISPATCH) 的两个分发
 * 函数：声明、定义、赋值三处注解齐了，静态分析才认这条契约（C28023）。 */
static VOID
iwan_win_mp_fill_major(VOID)
{
	RtlZeroMemory(g_mp_major, sizeof(g_mp_major));
	g_mp_major[IRP_MJ_CREATE] = iwan_win_dispatch_create;
	g_mp_major[IRP_MJ_CLOSE] = iwan_win_dispatch_create;
	/* 用户态每关一次句柄，I/O 管理器就发 IRP_MJ_CLEANUP。这张表是独立
	 * 驱动对象的整表（先 RtlZeroMemory），不补就是往 NULL 槽分发。 */
	g_mp_major[IRP_MJ_CLEANUP] = iwan_win_dispatch_create;
	g_mp_major[IRP_MJ_DEVICE_CONTROL] = iwan_win_dispatch_ioctl;
}

/* ---- 小型端口：初始化 / 停止 / 暂停 / 恢复 ---------------------------- */

/* 读一个 Parameters 下的 DWORD（定义在文件后段：初始化路径要先用）。 */
static ULONG
iwan_win_mp_param_get(_In_ PCWSTR name, _In_ ULONG dflt);


/* 支持的 OID 清单：既回答 OID_GEN_SUPPORTED_LIST，也填进适配器通用属性
 * （gen.SupportedOidList）。两处必须与本文件的 OID 处理函数一一对应：
 * 清单里有、处理函数里没有（返回 NDIS_STATUS_NOT_SUPPORTED）才是真正的坑。 */
static const NDIS_OID iwan_win_mp_oids[] = {
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
	OID_PNP_QUERY_POWER,
	OID_PNP_SET_POWER
};

static
_Function_class_(MINIPORT_INITIALIZE)
NDIS_STATUS
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

	/* 一份扩展只服务一个适配器。判据必须是 adapter_handle（InitializeEx 与
	 * Halt 之间才非空），不能是 mp_driver_handle：注册在 DriverEntry 就把
	 * 后者填上了，用它判断会让第一次启动就以为"已经有适配器"。 */
	if (ext->mp.adapter_handle != NULL) {
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
	/* 内层适配器的"介质形状"是客体上唯一说不清的一块：NdisMediumIP +
	 * AccessType=BROADCAST + 无链路地址时，TCP/IP 仍然会为对端建邻居项
	 * 并要一个 6 字节链路地址，拿不到就 send 直接失败（ping 报
	 * \"General failure\"、UDP 报 WSAEINVAL），连 NDIS 都到不了 ——
	 * 计数上表现为 tx_pkts 恒 0。三种形状哪一种是 Windows 认的，改代码
	 * 猜不出来，所以做成注册表开关：改 Parameters 里的 DWORD 再
	 * pnputil /restart-device 就能试下一档，不必重启整机换映像。
	 *   MpAccess 0=广播（默认） 1=点对点
	 *   MpMacLen 0=无链路地址（默认） 6=给一个假 MAC
	 *   MpIfType 0=PROP_VIRTUAL（默认） 6=ETHERNET_CSMACD 131=TUNNEL */
	{
		ULONG mp_access = iwan_win_mp_param_get(L"MpAccess", 0);
		ULONG mp_maclen = iwan_win_mp_param_get(L"MpMacLen", 0);
		ULONG mp_iftype = iwan_win_mp_param_get(L"MpIfType", 0);

		iwan_win_mp_trace(90, (LONG)mp_access);
		iwan_win_mp_trace(91, (LONG)mp_maclen);
		iwan_win_mp_trace(92, (LONG)mp_iftype);
		if (mp_access == 1) {
			gen.AccessType = NET_IF_ACCESS_POINT_TO_POINT;
		} else if (mp_access == 2) {
			gen.AccessType = NET_IF_ACCESS_LOOPBACK;
		} else {
			gen.AccessType = NET_IF_ACCESS_BROADCAST;
		}
		if (mp_maclen == 6) {
			/* MAC 数组紧跟 MacAddressLength，但**它的字段名在 WDK 各版本里
			 * 不同**（本仓库能拿到的 ndis.h 快照截断在 15076 行，正好缺这个
			 * 结构），写错名字就是 C2039。这个数组是 UCHAR[32]、对齐 1，
			 * 按"长度字段之后"定位不会踩到别的东西；写歪的代价只是这一档
			 * 实验无效，不会影响别的档位。等拿到确定的名字再换回来。 */
			UCHAR fake[6];
			PUCHAR mac;

			fake[0] = 0x02;
			fake[1] = 0x00;
			fake[2] = 0x00;
			fake[3] = 0x00;
			fake[4] = 0x00;
			fake[5] = 0x01;
			mac = (PUCHAR)&gen +
			      offsetof(NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES,
				       MacAddressLength) + sizeof(USHORT);
			RtlCopyMemory(mac, fake, sizeof(fake));
			gen.MacAddressLength = 6;
		} else {
			gen.MacAddressLength = 0;
		}
		if (mp_iftype == 6) {
			gen.IfType = IF_TYPE_ETHERNET_CSMACD;
		} else if (mp_iftype == 131) {
			gen.IfType = IF_TYPE_TUNNEL;
		} else {
			gen.IfType = IF_TYPE_PROP_VIRTUAL;
		}
	}

	gen.DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
	gen.ConnectionType = NET_IF_CONNECTION_DEDICATED;
	gen.IfConnectorPresent = FALSE;
	gen.SupportedStatistics = NDIS_STATISTICS_XMIT_OK_SUPPORTED |
				  NDIS_STATISTICS_RCV_OK_SUPPORTED;
	gen.SupportedPauseFunctions = NdisPauseFunctionsUnsupported;
	gen.AutoNegotiationFlags = 0;
	gen.SupportedOidList = (PNDIS_OID)iwan_win_mp_oids;
	gen.SupportedOidListLength = sizeof(iwan_win_mp_oids);
	gen.DataBackFillSize = 0;
	gen.ContextBackFillSize = 0;
	st = NdisMSetMiniportAttributes(MiniportAdapterHandle,
					(PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&gen);
	if (st != NDIS_STATUS_SUCCESS)
		goto fail;

	ext->mp.adapter_handle = MiniportAdapterHandle;
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

static
_Function_class_(MINIPORT_HALT)
VOID
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
	ext->mp.adapter_handle = NULL;
	/* 注意：这里**不能**清 g_mp_ext。Halt 只表示适配器停了，扩展内存还
	 * 归控制设备用（它要到 UnloadHandler 才释放）；清掉的话，适配器停掉
	 * 之后任何一个 IOCTL 都会解引用空指针。会话是否还活着由 sess.valid
	 * 表示，控制面按它拒绝即可。 */
	iwan_win_mp_release_carrier(ext);
	/* 只销毁入向池（tx_pool 归协议边，见 iwan_win.h 的说明），而且必须先
	 * 等"已指示向上、还没归还"的 NBL 归零：NdisFreeNetBufferListPool 的
	 * 硬规则是池里不能还有在途 NBL，而什么时候归还由 NDIS/协议栈决定。
	 * 等不到就不放池 —— 泄漏一条池，好过让迟到的归还没进已释放的池。 */
	if (ext->mp.nbl_pool != NULL) {
		ULONG i;

		for (i = 0; i < 1000 && ext->mp.rx_inflight > 0; i++)
			KeStallExecutionProcessor(1000);	/* 最多约 1 秒 */
		if (ext->mp.rx_inflight > 0) {
			DbgPrint("iwanmp: 停止时仍有 %ld 条入向 NBL 未归还，池不释放\n",
				 (long)ext->mp.rx_inflight);
		} else {
			NdisFreeNetBufferListPool(ext->mp.nbl_pool);
			ext->mp.nbl_pool = NULL;
		}
	}
	DbgPrint("iwanmp: 内层适配器已停止\n");
}

static
_Function_class_(MINIPORT_PAUSE)
NDIS_STATUS
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

static
_Function_class_(MINIPORT_RESTART)
NDIS_STATUS
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
static
_Function_class_(MINIPORT_SEND_NET_BUFFER_LISTS)
VOID
iwan_win_mp_send_nbls(_In_ NDIS_HANDLE MiniportAdapterContext,
		      _In_ PNET_BUFFER_LIST NetBufferLists,
		      _In_ NDIS_PORT_NUMBER PortNumber,
		      _In_ ULONG SendFlags)
{
	/* 第一个形参是 MiniportAdapterContext（注册时填的是 ext），**不是**
	 * miniport 句柄。完成发送要的是 ext->mp.adapter_handle —— 历史上这里
	 * 把形参原样交给 NdisMSendNetBufferListsComplete，等于让 NDIS 拿扩展
	 * 内存当 miniport block 解引用：设备一起来、只要有一个内层包（新适配器
	 * 的 DAD/ARP/NCSI 探测都算）就在 DISPATCH_LEVEL 上炸。 */
	IWAN_WIN_DEVICE_EXTENSION *ext =
		(IWAN_WIN_DEVICE_EXTENSION *)MiniportAdapterContext;
	PNET_BUFFER_LIST nbl;
	BOOLEAN l4_offloaded;
	ULONG complete_flags;

	UNREFERENCED_PARAMETER(PortNumber);
	/* SendFlags 里的 DISPATCH 位不当作完成标志用：完成标志必须与调用点的
	 * 真实 IRQL 一致，用 KeGetCurrentIrql() 判最不会撒谎。 */
	UNREFERENCED_PARAMETER(SendFlags);

	if (ext == NULL || ext->mp.adapter_handle == NULL) {
		/* 正常不可达（NDIS 在 Halt 之后不再调发送处理函数）。此时没有任何
		 * 合法句柄可以完成，宁可不完成、交给 NDIS 的停止流程，也不能把上下文
		 * 或 NULL 当句柄交回去 —— 那必炸。 */
		DbgPrint("iwanmp: 发送处理函数在无句柄状态下被调用，NBL 未完成\n");
		return;
	}
	complete_flags = (KeGetCurrentIrql() == DISPATCH_LEVEL) ?
			 NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0;

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
			UINT32 tx;

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
			/* 先试零拷贝（整包连续），拿不到再拼一次。
			 * 注意 NdisGetDataBuffer 要调用两次是错的认识：真的调用
			 * 两次会让"连续"的判定与"取数据"落在不同的快照上，
			 * 而且白白多走一遍 MDL 链 —— 这里取一次就够。 */
			p = (const UINT8 *)NdisGetDataBuffer(nb, len, NULL, 1, 0);
			if (p != NULL) {
				tx = iwan_win_mp_encap_send(ext, p, len, l4_offloaded);
			} else {
				UINT8 *tmp = (UINT8 *)IWAN_ALLOC(len, IWAN_TAG_PKT);

				if (tmp == NULL) {
					IWAN_MP_STAT_INC(ext, tx_err);
					tx = IWAN_MP_TX_DROP;
				} else {
					p = (const UINT8 *)NdisGetDataBuffer(nb, len,
									     tmp, 1, 0);
					tx = (p != NULL) ?
					     iwan_win_mp_encap_send(ext, p, len,
								    l4_offloaded) :
					     IWAN_MP_TX_FAIL;
					ExFreePoolWithTag(tmp, IWAN_TAG_PKT);
				}
			}
			/* 丢包（背压、MTU、未解析邻居）对协议栈报成功：
			 * 报失败会让内层 sendto() 拿到 WSAEINVAL，应用以为是
			 * 自己的参数错了。只有报文本身不合法才真报失败。 */
			if (tx == IWAN_MP_TX_FAIL)
				st = NDIS_STATUS_FAILURE;
		}
		NET_BUFFER_LIST_STATUS(nbl) = st;
	}
	NdisMSendNetBufferListsComplete(ext->mp.adapter_handle, NetBufferLists,
					complete_flags);
}

static
_Function_class_(MINIPORT_CANCEL_SEND)
VOID
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
			   __drv_freesMem(_Out_) UINT8 *inner, _In_ ULONG len)
{
	NET_BUFFER_LIST *nbl;
	PMDL mdl;
	UINT8 ver;

	if (ext->mp.adapter_handle == NULL || ext->mp.mp_running == 0 || len == 0) {
		ExFreePoolWithTag(inner, IWAN_TAG_PKT);
		return FALSE;
	}
	ver = (UINT8)(inner[0] >> 4);
	/* 长度闸门按版本给：v4 最短 20、v6 最短 40。短于此的帧交给协议栈只会
	 * 被它再丢一次，还可能让上层解析越界。 */
	if ((ver == 4 && len < 20u) || (ver == 6 && len < 40u)) {
		ExFreePoolWithTag(inner, IWAN_TAG_PKT);
		return FALSE;
	}

	/* 在途上限（见 IWAN_MP_MAX_INNER_INFLIGHT 的长注释）：先加后判，
	 * 判不过就地回退，任何时刻计数都等于"已指示且尚未归还"的真实值。
	 * 计数必须在 IoAllocateMdl 之前立起来 —— 之后每一块池都要靠它被
	 * Halt 看见。 */
	if ((ULONG)InterlockedIncrement(&ext->mp.rx_inflight) >
	    IWAN_MP_MAX_INNER_INFLIGHT) {
		InterlockedDecrement(&ext->mp.rx_inflight);
		ExFreePoolWithTag(inner, IWAN_TAG_PKT);
		return FALSE;
	}

	mdl = IoAllocateMdl(inner, len, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		InterlockedDecrement(&ext->mp.rx_inflight);
		ExFreePoolWithTag(inner, IWAN_TAG_PKT);
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(mdl);

	/* 池是“NBL + NB + MDL 链接”的工厂：分配出来的 NBL 在指示之前归
	 * 本函数，NdisMIndicateReceiveNetBufferLists 之后归 NDIS，归还时由
	 * MiniportReturnNetBufferLists 释放。静态分析看不到这条 NDIS 的池
	 * 所有权约定，把“本该交出去”读成泄漏（C6014）—— 已逐条核对过：
	 * 指示成功恰好一次转交、失败路径各自释放，是误报。 */
	/* C6014 误报（分配点 nbl = NdisAllocate...）：nbl 的所有权在
	 * NdisMIndicateReceiveNetBufferLists 之后归 NDIS，归还时由
	 * MiniportReturnNetBufferLists 释放，这是 NDIS 的池约定，分析器看不到
	 * 这条转移。失败路径各自释放（见下面的 IoFreeMdl / ExFreePoolWithTag）。 */
#pragma warning(suppress: 6014)
	nbl = NdisAllocateNetBufferAndNetBufferList(ext->mp.nbl_pool,
						    IWAN_MP_NBL_CTX_SIZE, 0,
						    mdl, 0, len);
	if (nbl == NULL) {
		IoFreeMdl(mdl);
		ExFreePoolWithTag(inner, IWAN_TAG_PKT);
		InterlockedDecrement(&ext->mp.rx_inflight);
		return FALSE;
	}
	{
		/* context 区不保证清零，两个字段都要显式写（归还时按它释放）。 */
		IWAN_MP_TX_CTX *ctx =
			(IWAN_MP_TX_CTX *)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);

		ctx->buf = inner;
		ctx->mdl = mdl;
	}
	nbl->SourceHandle = ext->mp.adapter_handle;
	nbl->NblFlags |= (ver == 4) ? NDIS_NBL_FLAGS_IS_IPV4 : NDIS_NBL_FLAGS_IS_IPV6;
	/* 帧类型必须显式写进 NBL 的 info 槽，且是**网络字节序**（内存里就是
	 * 08 00 / 86 DD），与 Wintun 的 HTONS(NDIS_ETH_TYPE_IPV4) 同口径。
	 * 不写的后果：NDIS 在小型端口接收边界按"帧类型不受支持"丢弃 —— pktmon
	 * 记 DropReason Unsupported EtherType、DropLocation 0xE0001007，归属
	 * 就是本驱动；现场症状是隧道两头都在通（外层帧一来一回、rx_delivered
	 * 在涨），内层 ping 却 100% 丢包。 */
	NET_BUFFER_LIST_INFO(nbl, NetBufferListFrameType) =
		(PVOID)(ULONG_PTR)((ver == 4) ? 0x0008u : 0xDD86u);
	/* 计数已在入口取定（见上）：这里不再加，否则归还侧只减一次，
	 * 计数会永久偏大并把 Halt 卡在"永远不归零"的忙等里。 */

	/* 不带 RESOURCES：所有权交给 NDIS，归还时释放缓冲。IRQL 位必须如实
	 * 上报 —— 本函数从协议边的接收路径调用，通常就在 DISPATCH_LEVEL。
	 *
	 * SINGLE_ETHER_TYPE 必须带：它和上面写的 NetBufferListFrameType 是一
	 * 对 —— 该位声明"本次指示的 NBL 共用同一帧类型"，NDIS 才会去 info 槽
	 * 取类型；两者缺一，NDIS 就在小型端口接收边界以
	 * "Unsupported EtherType"（DropLocation 0xE0001007）丢弃。
	 * 介质是 NdisMediumIP（裸 IP、无以太头）并不免除这一步：参考实现
	 * Wintun 的 TunReceive 也是 NetBufferListFrameType 与
	 * NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE 两者都填。 */
	NdisMIndicateReceiveNetBufferLists(ext->mp.adapter_handle, nbl,
					   NDIS_DEFAULT_PORT_NUMBER, 1,
					   NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE |
					   ((KeGetCurrentIrql() == DISPATCH_LEVEL) ?
					    NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL : 0));
	/* 从这里起 NBL 归 NDIS：归还请求会走 iwan_win_mp_return_nbls，缓冲与
	 * MDL 也在那里释放。本函数的局部指针必须就地作废 —— 置空是这条
	 * 所有权转移的唯一记号（也顺手消掉静态分析的“泄漏”误报）。 */
	nbl = NULL;
	return TRUE;
}

static
_Function_class_(MINIPORT_RETURN_NET_BUFFER_LISTS)
VOID
iwan_win_mp_return_nbls(_In_ NDIS_HANDLE MiniportAdapterHandle,
			_In_ PNET_BUFFER_LIST NetBufferLists,
			_In_ ULONG ReturnFlags)
{
	PNET_BUFFER_LIST nbl;
	/* 本处理函数拿到的是 MiniportAdapterHandle，不是 MiniportAdapterContext，
	 * 所以取不到 ext：这里用单例取回（本小型端口按构造只服务一个适配器，
	 * InitializeEx 对第二个适配器直接拒绝）。rx_inflight 必须在销毁 NBL 池
	 * 之前减到零，Halt 靠它判断"还有没有已经指示上去、尚未归还的 NBL"。
	 * UnloadHandler 之后单例会被清空，此时归还仍必须完成（NBL 与缓冲是池
	 * 资产，漏掉就是泄漏），只有计数无处可减。 */
	IWAN_WIN_DEVICE_EXTENSION *ext = iwan_win_mp_device_ext();

	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(ReturnFlags);

	for (nbl = NetBufferLists; nbl != NULL; ) {
		/* 先取 NEXT 再释放：NdisFreeNetBufferList 会把这块内存交回池的空闲
		 * 链，之后循环增量再读 nbl->Next 读到的是复用后的垃圾（轻则同一个
		 * NBL 被二次释放、引用计数失衡，重则顺着野指针走到非法地址）。 */
		PNET_BUFFER_LIST next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		IWAN_MP_TX_CTX *ctx =
			(IWAN_MP_TX_CTX *)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);

		if (ext != NULL)
			InterlockedDecrement(&ext->mp.rx_inflight);

		/* 归还的只可能是本驱动指示上去的 NBL：每条 NBL 恰好一个 NB、
		 * 一个缓冲、一个 MDL（netvmini 同构）。多 NB 的 NBL 出现在这里
		 * 说明有人把别人的 NBL 还给了我们 —— 说出来，别静默漏掉缓冲。 */
		if (NET_BUFFER_NEXT_NB(NET_BUFFER_LIST_FIRST_NB(nbl)) != NULL)
			DbgPrint("iwanmp: 归还的 NBL 不止一个 NB，后续 NB 的缓冲会漏\n");
		if (ctx->mdl != NULL) {
			IoFreeMdl(ctx->mdl);
			ctx->mdl = NULL;
		}
		if (ctx->buf != NULL) {
			ExFreePoolWithTag(ctx->buf, IWAN_TAG_PKT);
			ctx->buf = NULL;
		}
		NdisFreeNetBufferList(nbl);
		nbl = next;
	}
}

/* ---- 小型端口：OID --------------------------------------------------- */

/* 按 OID 的**定义宽度**写。原先一律"缓冲够 8 就写 8"：对 4 字节的 OID
 * （LINK_SPEED、MTU、MEDIA_* 等）值虽然恰好落在低 4 字节，但 BytesWritten
 * 撒谎；对 2 字节的 OID_GEN_DRIVER_VERSION 更糟 —— 上层只读低 2 字节，
 * 报出去的 NDIS 版本号是错的。 */
static NDIS_STATUS
iwan_win_mp_oid_put_width(_Inout_ PNDIS_OID_REQUEST oid, _In_ UINT64 v,
			  _In_ ULONG width)
{
	PUCHAR buf = (PUCHAR)oid->DATA.QUERY_INFORMATION.InformationBuffer;

	if (oid->DATA.QUERY_INFORMATION.InformationBufferLength < width) {
		oid->DATA.QUERY_INFORMATION.BytesNeeded = width;
		return NDIS_STATUS_BUFFER_TOO_SHORT;
	}
	if (width == 8)
		*(UINT64 UNALIGNED *)buf = v;
	else if (width == 4)
		*(UINT32 UNALIGNED *)buf = (UINT32)v;
	else
		*(UINT16 UNALIGNED *)buf = (UINT16)v;
	oid->DATA.QUERY_INFORMATION.BytesWritten = width;
	return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
iwan_win_mp_oid_put_u64(_Inout_ PNDIS_OID_REQUEST oid, _In_ UINT64 v)
{
	return iwan_win_mp_oid_put_width(oid, v, 8);
}

static NDIS_STATUS
iwan_win_mp_oid_put_u32(_Inout_ PNDIS_OID_REQUEST oid, _In_ UINT32 v)
{
	return iwan_win_mp_oid_put_width(oid, v, 4);
}

static NDIS_STATUS
iwan_win_mp_oid_put_u16(_Inout_ PNDIS_OID_REQUEST oid, _In_ UINT16 v)
{
	return iwan_win_mp_oid_put_width(oid, v, 2);
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

static
_Function_class_(MINIPORT_OID_REQUEST)
NDIS_STATUS
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
	case OID_GEN_SUPPORTED_LIST: {
		ULONG bytes = sizeof(iwan_win_mp_oids);
		PUCHAR buf = (PUCHAR)OidRequest->DATA.QUERY_INFORMATION.
			InformationBuffer;

		if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength <
		    bytes) {
			OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytes;
			return NDIS_STATUS_BUFFER_TOO_SHORT;
		}
		RtlCopyMemory(buf, iwan_win_mp_oids, bytes);
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = bytes;
		return NDIS_STATUS_SUCCESS;
	}
	case OID_GEN_HARDWARE_STATUS:
		return iwan_win_mp_oid_put_u32(OidRequest, (UINT32)NdisHardwareStatusReady);
	case OID_GEN_MEDIA_SUPPORTED:
	case OID_GEN_MEDIA_IN_USE:
		/* 裸 IP 介质：没有以太头、没有 ARP/ND，地址与 MTU 由控制面设 */
		return iwan_win_mp_oid_put_u32(OidRequest, (UINT32)NdisMediumIP);
	case OID_GEN_PHYSICAL_MEDIUM:
		return iwan_win_mp_oid_put_u32(OidRequest,
					       (UINT32)NdisPhysicalMediumUnspecified);
	case OID_GEN_MAC_OPTIONS:
		return iwan_win_mp_oid_put_u32(OidRequest, 0u);
	case OID_GEN_LINK_SPEED:
		/* 这是 OID 语义要求的"名义链路速率"，单位 100 bps：
		 * 1 Gbps ⇒ 10,000,000。真实吞吐只能由测量给出，不在这里报。 */
		return iwan_win_mp_oid_put_u32(OidRequest, 10000000u);
	case OID_GEN_MAXIMUM_LOOKAHEAD:
	case OID_GEN_MAXIMUM_TOTAL_SIZE:
	case OID_GEN_MAXIMUM_FRAME_SIZE:
	case OID_GEN_TRANSMIT_BLOCK_SIZE:
	case OID_GEN_RECEIVE_BLOCK_SIZE:
	case OID_GEN_CURRENT_LOOKAHEAD:
		return iwan_win_mp_oid_put_u32(OidRequest, IWAN_MP_INNER_MTU);
	case OID_GEN_TRANSMIT_BUFFER_SPACE:
	case OID_GEN_RECEIVE_BUFFER_SPACE:
		return iwan_win_mp_oid_put_u32(OidRequest, 0x400000u);
	case OID_GEN_VENDOR_ID:
		return iwan_win_mp_oid_put_u32(OidRequest, 0xFFFFFF00u);
	case OID_GEN_VENDOR_DESCRIPTION:
		return iwan_win_mp_oid_string(OidRequest, "iWAN tunnel");
	case OID_GEN_DRIVER_VERSION:
		/* 语义是"本驱动符合的 NDIS 版本"：高字节主版本、低字节次版本。
		 * 运行时 6.89 → 0x0659；原先写 0x0100 等于对外宣称 1.0。 */
		return iwan_win_mp_oid_put_u16(OidRequest,
			(UINT16)(NdisGetVersion() & 0xFFFFu));
	case OID_GEN_MEDIA_CONNECT_STATUS:
		return iwan_win_mp_oid_put_u32(OidRequest, (UINT32)NdisMediaStateConnected);
	case OID_GEN_CURRENT_PACKET_FILTER:
		return iwan_win_mp_oid_put_u32(OidRequest,
			NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_BROADCAST |
			NDIS_PACKET_TYPE_ALL_MULTICAST);
	case OID_GEN_XMIT_OK:
		return iwan_win_mp_oid_put_u64(OidRequest, ext != NULL ?
			(UINT64)ext->sess.stats.tx_pkts : 0);
	case OID_GEN_RCV_OK:
		return iwan_win_mp_oid_put_u64(OidRequest, ext != NULL ?
			(UINT64)ext->sess.stats.rx_delivered : 0);
	case OID_GEN_XMIT_ERROR:
		return iwan_win_mp_oid_put_u64(OidRequest, ext != NULL ?
			(UINT64)(ext->sess.stats.tx_bad_inner +
				 ext->sess.stats.tx_bad_state +
				 ext->sess.stats.tx_err) : 0);
	case OID_GEN_RCV_ERROR:
		return iwan_win_mp_oid_put_u64(OidRequest, ext != NULL ?
			(UINT64)(ext->sess.stats.rx_bad_hdr +
				 ext->sess.stats.rx_bad_inner) : 0);
	case OID_PNP_QUERY_POWER:
		st = NDIS_STATUS_SUCCESS;
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
		return st;
	default:
		return NDIS_STATUS_NOT_SUPPORTED;
	}
}

static
_Function_class_(MINIPORT_CANCEL_OID_REQUEST)
VOID
iwan_win_mp_cancel_oid(_In_ NDIS_HANDLE MiniportAdapterHandle,
		       _In_ PVOID RequestId)
{
	/* 同理：OID 请求全部同步完成，没有可取消的 */
	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(RequestId);
}

static
_Function_class_(MINIPORT_DEVICE_PNP_EVENT_NOTIFY)
VOID
iwan_win_mp_pnp_event(_In_ NDIS_HANDLE MiniportAdapterContext,
		      _In_ PNET_DEVICE_PNP_EVENT NetDevicePnPEvent)
{
	UNREFERENCED_PARAMETER(MiniportAdapterContext);
	UNREFERENCED_PARAMETER(NetDevicePnPEvent);
}

static
_Function_class_(MINIPORT_SHUTDOWN)
VOID
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
static
_Function_class_(MINIPORT_DIRECT_OID_REQUEST)
NDIS_STATUS
iwan_win_mp_direct_oid(_In_ NDIS_HANDLE MiniportAdapterHandle,
		       _In_ PNDIS_OID_REQUEST OidRequest)
{
	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(OidRequest);
	return NDIS_STATUS_NOT_SUPPORTED;
}

static
_Function_class_(MINIPORT_CANCEL_DIRECT_OID_REQUEST)
VOID
iwan_win_mp_cancel_direct_oid(_In_ NDIS_HANDLE MiniportAdapterHandle,
			      _In_ PVOID RequestId)
{
	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(RequestId);
}

static
_Function_class_(MINIPORT_SYNCHRONOUS_OID_REQUEST)
NDIS_STATUS
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

/* ---- 保险丝：Parameters 下的两个开关 -----------------------------------
 * Disarm=1：什么都不注册，DriverEntry 直接失败（设备停在 Code 10，不碰 NDIS、
 *   不建控制设备）。蓝屏事故之后这台机器的默认状态，只有在确认要测的时候才
 *   由装具显式清掉，测完再打上。
 * NoProto=1：只注册小型端口，不注册协议边（外层承载收发缺席，内层网卡仍可
 *   单独验证：适配器出现、地址与 MTU 可设、SendNetBufferLists 被调用）。
 * 两者都只在**装载之前**读一次，运行期不可改 —— 它们是安全闸门，不是配置。
 * Disarm 的缺省值是 1（不是 0）：键不存在时必须落在"不合闸"这一侧。 */
/* 运行中映像的 PE TimeDateStamp：这是"客体上到底跑的哪一版"的唯一硬证据。
 * 客体上换映像的路径全被堵死（加载中的 .sys 覆盖会 Access denied，sc delete
 * 只是标记删除，delete-driver 要求重启），而文件 mtime/大小都可能属于被替换
 * 掉的旧文件。驱动映像本身非分页常驻，DriverEntry 处在 PASSIVE，直接读
 * DOS/NT 头是安全的；任何一步不成立都返回 0（0 表示"读不到"，不是"很旧的
 * 构建"）。 */
static ULONG
iwan_win_mp_build_stamp(_In_opt_ PDRIVER_OBJECT driver)
{
	const UCHAR *base;
	LONG lfanew;
	ULONG stamp = 0;

	if (driver == NULL || driver->DriverStart == NULL)
		return 0;
	base = (const UCHAR *)driver->DriverStart;

	/* e_magic 不是 MZ 时不要顺着 e_lfanew 乱读 —— 这里的指针来自内核，
	 * 读错位置就是一次 bugcheck，不值得为一行诊断冒这个险。 */
	if (base[0] != 'M' || base[1] != 'Z')
		return 0;
	RtlCopyMemory(&lfanew, base + 0x3C, sizeof(lfanew));
	if (lfanew <= 0 || lfanew > 0x1000)
		return 0;
	/* IMAGE_NT_HEADERS32/64 的 FileHeader 都在 Signature 之后 4 字节，
	 * TimeDateStamp 是 FileHeader 的第 2 个字段（+4）⇒ 合计 +8。 */
	RtlCopyMemory(&stamp, base + lfanew + 8, sizeof(stamp));
	return stamp;
}

static ULONG
iwan_win_mp_param_get(_In_ PCWSTR name, _In_ ULONG dflt)
{
	UNICODE_STRING path, vn;
	OBJECT_ATTRIBUTES oa;
	HANDLE key = NULL;
	/* 这块缓冲只被 ZwQueryValueKey 填前 len 字节，剩下的仍是未初始化内存；
	 * 显式清零既让分析器闭嘴（C28199），也避免把栈内容当成 Type/DataLength
	 * 去判（查不到值时那两个字段根本不存在）。 */
	UCHAR buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
	ULONG len = 0, out = dflt;

	RtlZeroMemory(buf, sizeof(buf));

	RtlInitUnicodeString(&path,
			     L"\\Registry\\Machine\\System\\CurrentControlSet"
			     L"\\Services\\iwanmp\\Parameters");
	InitializeObjectAttributes(&oa, &path,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				   NULL, NULL);
	if (!NT_SUCCESS(ZwOpenKey(&key, KEY_QUERY_VALUE, &oa)))
		return dflt;
	RtlInitUnicodeString(&vn, name);
	if (NT_SUCCESS(ZwQueryValueKey(key, &vn, KeyValuePartialInformation,
				       buf, sizeof(buf), &len))) {
		/* 逐字段拷到局部结构里再判：kvv 的内存是我们自己的、已清零，
		 * 分析器能一路跟到底（C28199）；直接给 buf 起别名它就只能
		 * 认定“可能未初始化”。字段语义完全相同。 */
		KEY_VALUE_PARTIAL_INFORMATION kv;

		RtlZeroMemory(&kv, sizeof(kv));
		RtlCopyMemory(&kv, buf,
			      len < sizeof(kv) ? len : (ULONG)sizeof(kv));
		if (kv.Type == REG_DWORD && kv.DataLength >= sizeof(ULONG) &&
		    kv.DataLength <= sizeof(ULONG) * 4u)
			RtlCopyMemory(&out, kv.Data, sizeof(ULONG));
	}
	ZwClose(key);
	return out;
}

/* 小型端口注册：候选表逐档试，命中即用，每一档结果落一个 T4x 键。
 *
 * 为什么又回到候选表：上一轮把它改成单次调用（运行时次版本 + REVISION_1），
 * 客体实测回 **0xC0010005（NDIS_STATUS_BAD_CHARACTERISTICS）**；而当初"阶梯第
 * 一档就命中"的结论是读到了上一次装机的陈旧键（该轮的键没删干净），
 * 不成立。一轮只能改一个值的话，每轮是十分钟构建 + 换包 + 重启设备，
 * 所以这里一次性把候选试完：每档的 NTSTATUS 落 T40+i，命中落 T39（低 8 位
 * 是 revision，次 8 位是声明的次版本），全部失败落 T38 = 尝试次数。
 * 失败后不留任何句柄：这一步一个注册都没成功，返回失败是干净的。 */
typedef struct {
	UCHAR minor;	/* 0xFF = 用运行时次版本 */
	UCHAR rev;
} IWAN_MP_CH_CAND;

static const IWAN_MP_CH_CAND iwan_win_mp_ch_cands[] = {
	{ 0xFF, NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3 },
	{ 0xFF, NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2 },
	{ 0xFF, NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1 },
	{ 0,    NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1 },
	{ 80,   NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1 },
	{ 60,   NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1 },
	{ 30,   NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1 },
	{ 20,   NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1 }
};
static NDIS_STATUS
iwan_win_mp_register(_In_ PDRIVER_OBJECT driver,
		     _In_ PUNICODE_STRING registry_path,
		     _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	UINT16 runtime = (UINT16)(NdisGetVersion() & 0xFFFFu);
	ULONG i;
	NDIS_STATUS last = NDIS_STATUS_BAD_CHARACTERISTICS;

	for (i = 0; i < RTL_NUMBER_OF(iwan_win_mp_ch_cands); i++) {
		NDIS_MINIPORT_DRIVER_CHARACTERISTICS ch;
		UCHAR rev = iwan_win_mp_ch_cands[i].rev;
		UCHAR minor = iwan_win_mp_ch_cands[i].minor;
		NDIS_STATUS st;

		if (minor == 0xFF)
			minor = (UCHAR)runtime;
		iwan_win_mp_fill_ch(&ch, minor, rev);
		st = NdisMRegisterMiniportDriver(driver, registry_path, ext, &ch,
						 &ext->mp.mp_driver_handle);
		iwan_win_mp_trace(40 + i, (LONG)st);
		last = st;
		if (st == NDIS_STATUS_SUCCESS) {
			iwan_win_mp_trace(39, (LONG)(((ULONG)minor << 8) | rev));
			return NDIS_STATUS_SUCCESS;
		}
	}
	iwan_win_mp_trace(38, (LONG)RTL_NUMBER_OF(iwan_win_mp_ch_cands));
	return last;
}

/* DriverEntry 的装载路径。这里的顺序与失败策略是被一次蓝屏事故定死的：
 *
 *   1. Disarm 先读、先判 —— 保险丝要能在任何 NDIS 调用之前生效；
 *   2. 小型端口注册失败 ⇒ 什么都还没留下，返回失败是干净的（设备 Code 10）；
 *   3. 小型端口注册成功之后，DriverEntry **再也不能返回失败**。半个注册状态
 *      （NDIS 认为驱动还在、DriverEntry 却失败）会让后续 devcon remove /
 *      pnputil /delete-driver 永久挂住，重启时表现为整机无法启动 ——
 *      客体上真实发生过，恢复只能靠 WinRE 离线删服务键与驱动文件；
 *   4. 协议边失败可以容忍：它缺席只意味着外层承载收发没起来，小型端口与
 *      控制设备照常工作，用户态能打开设备、能读诊断、能看是哪个 NTSTATUS。
 * 由此，失败路径**只在第 2 步之后才可能出现注销调用**，而那时一个注册都没成功。 */
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
	/* 阶段 31 = 运行中映像的 PE TimeDateStamp。装完机先读这一条，与 CI 工件
	 * 里 iwanmp.sys 的时间戳对照，就能判定"盘上这份到底是不是刚构建的那版"，
	 * 不必再靠反汇编猜。 */
	{
		ULONG stamp = iwan_win_mp_build_stamp(driver);
		iwan_win_mp_trace(31, (LONG)stamp);
		if (stamp == 0)
			DbgPrint("iwanmp: 读不到映像时间戳（DriverStart=%p）\n",
				 driver != NULL ? driver->DriverStart : NULL);
	}

	{
		/* 缺省值刻意是 1（保险丝合上）：键被删掉、装机写键失败、
		 * 或者镜像被别的路径装上时，驱动什么都不注册，停在 Code 37。
		 * 要它工作必须由装具显式写 Disarm=0 —— "默认不安全"在这里
		 * 是不可接受的，因为一次错误的注册会让整机起不来。 */
		ULONG disarm = iwan_win_mp_param_get(L"Disarm", 1);

		iwan_win_mp_trace(8, (LONG)disarm);
		if (disarm != 0) {
			iwan_win_mp_trace(9, (LONG)STATUS_UNSUCCESSFUL);
			g_mp_ext = NULL;
			DbgPrint("iwanmp: 保险丝已合上（Disarm=1），不注册任何东西\n");
			return STATUS_UNSUCCESSFUL;
		}
	}

	/* DriverObject 是否"干净"是两次装机都回 0xC0010005 之后的头号怀疑：
	 * 小型端口的卸载入口是特性表里的 UnloadHandler，而 DriverUnload 是
	 * 普通 WDM 驱动的字段；已经被占用的它可能就是"不是合法的
	 * 小型端口驱动"的判据。先如实记下再清掉（T7）。 */
	if (driver->DriverUnload != NULL) {
		iwan_win_mp_trace(7, 1);
		driver->DriverUnload = NULL;
	} else {
		iwan_win_mp_trace(7, 0);
	}

	/* NoMp=1：只注册协议边，不要小型端口。这是**诊断模式**，不是产品配置：
	 * 小型端口注册被拒（0xC0010005）之后，剩下的唯一问题是"协议边的
	 * 0xC0000001 是它自己的毛病，还是被小型端口那半边拖累的"。两者都是
	 * NdisRegisterXxxDriver 读同一个服务键，一次只留一半就能把责任分开：
	 *   · NoMp=1 下协议边注册成功（T69 有值）⇒ 小型端口那半边才是干扰源；
	 *   · 仍然 0xC0000001 ⇒ 服务键的 Ndi\Interfaces 形状不对，与谁先谁后无关。
	 * 跳过小型端口时 DriverEntry 的失败不变式照旧（一个注册都没做，返回
	 * 失败是干净的），只是这里的 switch 让"跳过"与"被拒"在 T 表上可辨。 */
	{
		ULONG nomp = iwan_win_mp_param_get(L"NoMp", 0);

		iwan_win_mp_trace(14, (LONG)nomp);
		if (nomp != 0) {
			DbgPrint("iwanmp: NoMp=1，跳过小型端口，只注册协议边\n");
			goto proto_edge;
		}
	}

	st = iwan_win_mp_register(driver, registry_path, ext);
	if (st != NDIS_STATUS_SUCCESS) {
		iwan_win_mp_trace(10, (LONG)st);
		g_mp_ext = NULL;
		DbgPrint("iwanmp: 小型端口注册失败 0x%08lx\n", (unsigned long)st);
		return STATUS_UNSUCCESSFUL;
	}
	iwan_win_mp_trace(11, (LONG)NDIS_STATUS_SUCCESS);

proto_edge:

	/* 协议边（外层承载收发）。失败不致命，理由见上面的第 4 条。 */
	if (iwan_win_mp_param_get(L"NoProto", 0) != 0) {
		stp = NDIS_STATUS_NOT_SUPPORTED;
		DbgPrint("iwanmp: NoProto=1，跳过协议边\n");
	} else {
		stp = iwan_win_proto_init(ext);
	}
	iwan_win_mp_trace(12, (LONG)stp);
	InterlockedExchange(&ext->mp.proto_registered,
			    (stp == NDIS_STATUS_SUCCESS) ? 1 : 0);
	iwan_win_mp_trace(13, (LONG)STATUS_SUCCESS);
	DbgPrint("iwanmp: 已装载，%ws（协议边 0x%08lx）\n",
		 IWAN_WIN_DRV_VERSION_STR_MP, (unsigned long)stp);
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

	if (ext == NULL || ext->mp.mp_driver_handle == NULL)
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

	st = NdisRegisterDeviceEx(ext->mp.mp_driver_handle, &attr, &devobj, &handle);
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
	if (ext->mp.mp_driver_handle != NULL) {
		NdisMDeregisterMiniportDriver(ext->mp.mp_driver_handle);
		ext->mp.mp_driver_handle = NULL;
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
static
_Function_class_(MINIPORT_UNLOAD)
VOID
iwan_win_mp_unload_hook(_In_ PDRIVER_OBJECT driver)
{
	IWAN_WIN_DEVICE_EXTENSION *ext = g_mp_ext;

	UNREFERENCED_PARAMETER(driver);

	if (ext != NULL) {
		/* 与 iwan_win_unload 同一道守卫：控制设备的在途 IRP 先排空，
		 * 之后才注销设备与释放扩展。 */
		if (ext->ctrl_remove_init != 0 &&
		    InterlockedExchange(&ext->ctrl_remove_waited, 1) == 0)
			IoReleaseRemoveLockAndWait(&ext->ctrl_remove_lock, ext);
		iwan_win_mp_fini(ext);
		iwan_win_session_teardown(ext);
		iwan_win_ctrl_fini(ext);
		ExFreePoolWithTag(ext, IWAN_TAG_SESS);
	}
	driver->DeviceObject = NULL;	/* 防御：DriverUnload 若也被调用则不重复 */
	DbgPrint("iwanmp: 已卸载\n");
}
