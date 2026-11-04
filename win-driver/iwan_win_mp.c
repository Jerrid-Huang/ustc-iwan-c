/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_mp.c - NDIS miniport: the inner virtual NIC + the driver load.
 *
 * This half owns "how the inner side goes in and out" plus the driver lifetime:
 *
 *   Inner egress (uplink): the stack hands inner datagrams to this miniport per route ->
 *      per NB into engine iwan_win_mp_encap_send() -> as soon as that completes synchronously,
 *      NdisMSendNetBufferListsComplete returns the NBL. **No in-flight NBL is kept**,
 *      so the WFP-plane pattern of "in-flight injection holds pool slots and must be throttled" does not exist here
 *      (the engine still keeps one cap, but what it guards is carrier-side backlog, not itself).
 *   Inner ingress (downlink): the engine decapsulates the inner datagram -> iwan_win_mp_indicate_inner()
 *      raises one NBL indication upward; when the NBL is returned (MiniportReturnNetBufferLists)
 *      the buffer is freed. Equivalent to Linux-side netif_rx(), one stack entry fewer than injection.
 *
 * Medium type is NdisMediumIP (raw IP, no Ethernet header), consistent with the Linux-side inner device
 * NOARP/no link-layer address: the inner address is configured onto this adapter by the client,
 * packets always start at the IP header.
 *
 * Two points about the lifetime:
 *   1) This plane is PnP (an NDIS miniport), so driver unload goes through UnloadHandler,
 *      not DriverUnload -- after the miniport is registered that field belongs to NDIS. Therefore
 *      iwan_win_mp_unload_hook() must do the whole teardown itself (data plane + sessions +
 *      control device + extension memory).
 *   2) The control device must not be created with IoCreateDevice in DriverEntry: that would attach
 *      its own device object to the driver object and replace MajorFunction, while NdisMRegisterMiniport
 *      Driver requires the driver object to be "clean" when called. The correct order is "register the miniport first
 *      (driver object clean) -> then create the control device with the NDIS NdisRegisterDeviceEx ->
 *      and only then replace those four MajorFunction entries". Identify which device is ours by comparing pointers
 *      (Reserved is non-NULL on NDIS device objects too, so deciding by Reserved misidentifies).
 *   3) On the guest this registration step once returned exactly NDIS_STATUS_BAD_CHARACTERISTICS
 *      (0xC0010005)-- the driver object was clean and the characteristics table was field for field
 *      identical to the reference except the version numbers, so "declared NDIS version / characteristics table revision" became a candidate table tried one
 *      entry at a time (see iwan_win_mp_register), with each attempt status written into the registry, so one install
 *      is enough to read out which entry is non-compliant.
 *
 * Concurrency: the send path and the indicate path may both be at DISPATCH_LEVEL; this file does not wait, does not take
 * a mutex, does not touch pageable memory. The whole plane supports only one tunnel adapter (consistent with "one session binds one
 * NIC" and the control device singleton), so g_mp_ext is a singleton pointer, set up in iwan_win_mp_init
 * and torn down in UnloadHandler.
 */
#include "iwan_win.h"

/* MTU reported by the inner adapter. The real value is written onto this adapter by the client per session negotiation
 * (netsh/Set-NetIPInterface, the counterpart of Linux dev->mtu); this is only the reported ceiling. */
/* MTU that the inner adapter declares to the outside. Choosing 1400 instead of 1500 has two hard reasons:
 *   1) Tunnel overhead: outer IPv4+UDP is 28 bytes in total, the frame header 8 bytes, so a 1500-byte
 *      carrier holds only 1464 bytes of inner. Declaring 1500 means handing the stack packets that do not fit,
 *      and the data plane **drops** what does not fit (fail-closed, counted as tx_bad_state) -- which shows up as
 *      "small packets pass, big packets black-hole", the hardest class of symptom to track down;
 *   2) The real MTU is decided by the control plane: the server returns inner_mtu in the auth reply (usually 1400),
 *      the control plane sets this adapter MTU to that value with netsh (src/common/route.c,
 *      route_iface_up). This is only the conservative default for "the control plane has not set it yet". */
#define IWAN_MP_INNER_MTU	1400u
#define IWAN_MP_LINK_SPEED	10000000000ULL

static IWAN_WIN_DEVICE_EXTENSION *g_mp_ext;	/* tunnel adapter context (singleton) */

/* Unload hook: it is the MiniportUnloadHandler and also carries, on the WFP plane, the part of the DriverUnload
 * cleanup (after the miniport is registered DriverUnload belongs to NDIS and is not called on us). */
static
_Function_class_(MINIPORT_UNLOAD)
VOID iwan_win_mp_unload_hook(_In_ PDRIVER_OBJECT driver);

/* ---- control device dispatch ------------------------------------------------
 *
 * The control device is created by NdisRegisterDeviceEx; at registration the table below is handed to NDIS, which uses it to
 * create a separate driver object for this device, so there is no need to touch the NDIS DriverObject
 * nor to tell, per IRP, "whose device is this". The devices NDIS owns (the miniport
 * FDO and the devices used for protocol edge binding) are dispatched by NDIS itself and are unrelated to this table.
 *
 * Unregistered table entries (for example IRP_MJ_PNP) are answered by the I/O manager with STATUS_INVALID_DEVICE_REQUEST
 * -- the control device is not on the PnP stack, so normally it cannot receive those IRPs.
 */
static DRIVER_DISPATCH *g_mp_major[IRP_MJ_MAXIMUM_FUNCTION + 1];

/* The object type constant for device object attributes is not in km\ndis.h (that family lives in the SDK shared object type
 * header). If this WDK version lacks it, fall back to the NDIS "default" type: NdisRegisterDeviceEx
 * it interprets this table by Size/Revision; the type is only a marker. */
#ifndef NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES
#define NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES NDIS_OBJECT_TYPE_DEFAULT
#endif

/* The table is filled with the two dispatch functions from iwan_win.h that carry the _Function_class_(DRIVER_DISPATCH)
 * annotation: only when present at declaration, definition and assignment does static analysis accept this contract (C28023). */
static VOID
iwan_win_mp_fill_major(VOID)
{
	RtlZeroMemory(g_mp_major, sizeof(g_mp_major));
	g_mp_major[IRP_MJ_CREATE] = iwan_win_dispatch_create;
	g_mp_major[IRP_MJ_CLOSE] = iwan_win_dispatch_create;
	/* Every time user mode closes a handle the I/O manager sends IRP_MJ_CLEANUP. This table is the
	 * whole table of a separate driver object (RtlZeroMemory first); leaving it out dispatches into a NULL slot. */
	g_mp_major[IRP_MJ_CLEANUP] = iwan_win_dispatch_create;
	g_mp_major[IRP_MJ_DEVICE_CONTROL] = iwan_win_dispatch_ioctl;
}

/* ---- miniport: initialize / halt / pause / restart ---------------------------- */

/* Read a DWORD under Parameters (defined later in the file: the init path needs it first). */
static ULONG
iwan_win_mp_param_get(_In_ PCWSTR name, _In_ ULONG dflt);


/* Supported OID list: it both answers OID_GEN_SUPPORTED_LIST and fills the adapter general attributes
 * (gen.SupportedOidList). Both places must correspond one to one with the OID handlers in this file:
 * an entry present in the list but missing from the handlers (returning NDIS_STATUS_NOT_SUPPORTED) is the real trap. */
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

	/* One extension serves exactly one adapter. The criterion must be adapter_handle, i.e. non-NULL only between InitializeEx and
	 * Halt itself, never mp_driver_handle: registration fills the latter already in DriverEntry, so
	 * using it for the test makes the very first start believe "an adapter already exists". */
	if (ext->mp.adapter_handle != NULL) {
		DbgPrint("iwanmp: a tunnel adapter already exists, no second one accepted\n");
		iwan_win_mp_trace(21, NDIS_STATUS_NOT_SUPPORTED);
		return NDIS_STATUS_NOT_SUPPORTED;
	}

	/* NBL pool is created when the adapter starts and destroyed when it stops: NdisAllocateNetBufferListPool
	 * must be called after the adapter handle is available (which is exactly here). */
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
		DbgPrint("iwanmp: NBL pool allocation failed\n");
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
	gen.MediaType = NdisMediumIP;	/* raw IP: the inner side has no Ethernet header and no ARP */
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
	/* The "medium shape" of the inner adapter is the one thing on the guest that cannot be pinned down: NdisMediumIP +
	 * AccessType=BROADCAST + no link address, TCP/IP still creates a neighbour entry for the peer
	 * and asks for a 6-byte link address; without it send just fails (ping reports
	 * \"General failure\", UDP reports WSAEINVAL), and not even NDIS is reached --
	 * in the counters this shows as tx_pkts stuck at 0. Which of the three shapes Windows accepts cannot be
	 * guessed from the code, so it is a registry switch: change the DWORD under Parameters and
	 * pnputil /restart-device is enough to try the next setting, no need to reboot the whole machine and change the image.
	 *   MpAccess 0=broadcast (default) 1=point-to-point
	 *   MpMacLen 0=no link address (default) 6=give a fake MAC
	 *   MpIfType 0=PROP_VIRTUAL (default) 6=ETHERNET_CSMACD 131=TUNNEL */
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
			/* MAC array directly follows MacAddressLength, but **its field name differs across WDK
			 * versions** (the ndis.h snapshot available in this repo is truncated at line 15076, exactly where this
			 * struct would be), and a wrong name is C2039. The array is UCHAR[32], alignment 1, so
			 * locating it as "right after the length field" cannot step on anything else; a wrong placement only makes this one
			 * experiment invalid, it cannot affect other settings. Switch back once the definite name is known. */
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
	DbgPrint("iwanmp: inner adapter ready (NdisMediumIP, MTU %lu)\n",
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
	/* close the gate before letting the carrier in: both data plane paths use mp_running as the gate */
	InterlockedExchange(&ext->mp.mp_running, 0);
	ext->mp.adapter_handle = NULL;
	/* Note: g_mp_ext **must not** be cleared here. Halt only means the adapter stopped, the extension memory still
	 * belongs to the control device (it is freed only in UnloadHandler); clearing it would mean that after the adapter stops
	 * any IOCTL would dereference a NULL pointer. The session is still alive if sess.valid
	 * is set, and the control plane can just reject on that. */
	iwan_win_mp_release_carrier(ext);
	/* Destroy only the inbound pool (tx_pool belongs to the protocol edge, see the note in iwan_win.h), and it must first
	 * wait until "indicated upward but not yet returned" NBLs drop to zero: NdisFreeNetBufferListPool
	 * has the hard rule that no in-flight NBL may remain in the pool, while when they are returned is up to NDIS/the stack.
	 * If that never happens, do not free the pool -- leaking one pool beats a late return landing in an already freed pool. */
	if (ext->mp.nbl_pool != NULL) {
		ULONG i;

		for (i = 0; i < 1000 && ext->mp.rx_inflight > 0; i++)
			KeStallExecutionProcessor(1000);	/* at most about 1 second */
		if (ext->mp.rx_inflight > 0) {
			DbgPrint("iwanmp: halt with %ld inbound NBLs still not returned, pool not freed\n",
				 (long)ext->mp.rx_inflight);
		} else {
			NdisFreeNetBufferListPool(ext->mp.nbl_pool);
			ext->mp.nbl_pool = NULL;
		}
	}
	DbgPrint("iwanmp: inner adapter halted\n");
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

/* ---- miniport: send (inner -> outer) ----------------------------------- */

/* Treat one NBL chain as one packet: hand each NB to the engine, then complete the whole chain once.
 * By platform convention the send path must not rewrite the NBL chain NEXT_NBL (that would break up fragmented NBLs). */
static
_Function_class_(MINIPORT_SEND_NET_BUFFER_LISTS)
VOID
iwan_win_mp_send_nbls(_In_ NDIS_HANDLE MiniportAdapterContext,
		      _In_ PNET_BUFFER_LIST NetBufferLists,
		      _In_ NDIS_PORT_NUMBER PortNumber,
		      _In_ ULONG SendFlags)
{
	/* The first formal parameter is MiniportAdapterContext (ext is what was registered), **not**
	 * miniport handle. Completing a send needs ext->mp.adapter_handle -- historically this code
	 * passed the formal parameter straight to NdisMSendNetBufferListsComplete, which made NDIS dereference extension
	 * memory as a miniport block: as soon as the device comes up, any single inner packet (the new adapter
	 * DAD/ARP/NCSI probes all count) blows up at DISPATCH_LEVEL. */
	IWAN_WIN_DEVICE_EXTENSION *ext =
		(IWAN_WIN_DEVICE_EXTENSION *)MiniportAdapterContext;
	PNET_BUFFER_LIST nbl;
	BOOLEAN l4_offloaded;
	ULONG complete_flags;

	UNREFERENCED_PARAMETER(PortNumber);
	/* SendFlags DISPATCH bit is not used as a completion flag: the completion flag must match the call site,
	 * and the real IRQL is best judged with KeGetCurrentIrql(), which is the least likely to lie. */
	UNREFERENCED_PARAMETER(SendFlags);

	if (ext == NULL || ext->mp.adapter_handle == NULL) {
		/* normally unreachable (NDIS stops calling the send handler after Halt). At this point no
		 * valid handle exists to complete with; better not to complete at all and leave it to the NDIS halt path than to hand back
		 * the context or NULL as a handle -- that is guaranteed to crash. */
		DbgPrint("iwanmp: send handler called with no handle, NBL not completed\n");
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
			/* The peek buffer is the larger of the two inner header sizes: the version nibble decides
			 * which one is needed, and a v6 header is 40 bytes (this buffer used to be 20, sized for v4). */
			UINT8 hdr[IWAN_INNER_IP6_LEN];
			const UINT8 *p;
			ULONG len = NET_BUFFER_DATA_LENGTH(nb);
			ULONG need;
			UINT32 tx;

			if (len < IWAN_INNER_IP4_LEN) {
				st = NDIS_STATUS_FAILURE;
				continue;
			}
			/* One contiguous read of min(len, 40) bytes is enough to decide the version and to
			 * sanity check the declared length of either family; the engine re-validates independently
			 * (iwan_win_inner_sane), this stage only has to keep obviously broken frames from
			 * being copied in full. */
			need = len < IWAN_INNER_IP6_LEN ? len : IWAN_INNER_IP6_LEN;
			p = (const UINT8 *)NdisGetDataBuffer(nb, need, hdr, 1, 0);
			if (p == NULL || iwan_win_inner_family(p, need) == 0 ||
			    !iwan_win_inner_sane(p, len)) {
				/* Neither inner version: fail explicitly and let the stack see a drop instead
				 * of silence. Inner v4 and v6 both enter the tunnel; only the OUTER v6 is still
				 * phase two (outer NS/NA, see the engine). */
				st = NDIS_STATUS_FAILURE;
				IWAN_MP_STAT_INC(ext, tx_bad_inner);
				continue;
			}
			/* try zero copy first (whole packet contiguous); assemble once only if that fails.
			 * The belief that NdisGetDataBuffer has to be called twice is wrong: really calling it
			 * twice makes the "contiguous" test and the "get data" land on different snapshots,
			 * and walks the MDL chain one extra time for nothing -- one call here is enough. */
			p = (const UINT8 *)NdisGetDataBuffer(nb, len, NULL, 1, 0);
			if (p != NULL) {
				tx = iwan_win_mp_encap_send_pkt(ext, p, len, l4_offloaded);
			} else {
				UINT8 *tmp = (UINT8 *)IWAN_ALLOC(len, IWAN_TAG_PKT);

				if (tmp == NULL) {
					IWAN_MP_STAT_INC(ext, tx_err);
					tx = IWAN_MP_TX_DROP;
				} else {
					p = (const UINT8 *)NdisGetDataBuffer(nb, len,
									     tmp, 1, 0);
					tx = (p != NULL) ?
					     iwan_win_mp_encap_send_pkt(ext, p,
									len,
									l4_offloaded) :
					     IWAN_MP_TX_FAIL;
					ExFreePoolWithTag(tmp, IWAN_TAG_PKT);
				}
			}
			/* a drop (backpressure, MTU, unresolved neighbour) is reported to the stack as success:
			 * reporting failure would make inner sendto() get WSAEINVAL and the application would think
			 * its own arguments were wrong. Only a genuinely malformed packet is reported as a failure. */
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
	/* This miniport never pends on the send path: it accepts and completes synchronously, so there is nothing to cancel
	 * in send. The empty implementation is kept so the contract is complete (NDIS never calls it). */
	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(CancelId);
}

/* ---- miniport: indicate upward / return (outer -> inner) ------------------------- */

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
	/* Length gate is per version: v4 minimum 20, v6 minimum 40. A frame shorter than that handed to the stack would only
	 * be dropped again by it, and could also make upper layers parse out of bounds. */
	if ((ver == 4 && len < 20u) || (ver == 6 && len < 40u)) {
		ExFreePoolWithTag(inner, IWAN_TAG_PKT);
		return FALSE;
	}

	/* In-flight cap (see the long comment on IWAN_MP_MAX_INNER_INFLIGHT): add first, then test,
	 * roll back in place when the test fails, so at any moment the count equals the true "indicated and not yet returned" value.
	 * The count must be raised before IoAllocateMdl: after that, every pool block must be visible in that count, and
	 * Halt checks it. */
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

	/* The pool is a factory for "NBL + NB + MDL link": the NBL it allocates belongs to
	 * this function until indication, to NDIS after NdisMIndicateReceiveNetBufferLists, and on return
	 * MiniportReturnNetBufferLists owns the free. Static analysis cannot see this NDIS pool
	 * ownership convention and reads "should have been handed over" as a leak (C6014) -- every case was checked:
	 * a successful indication transfers ownership exactly once and each failure path frees its own, so it is a false positive. */
	/* C6014 false positive (allocation site nbl = NdisAllocate...): ownership of nbl passes to NDIS after
	 * NdisMIndicateReceiveNetBufferLists returns, and on return to NDIS
	 * MiniportReturnNetBufferLists frees it, which is the NDIS pool convention the analyzer cannot see
	 * this transfer. Each failure path frees its own (see IoFreeMdl / ExFreePoolWithTag below). */
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
		/* context block is not guaranteed to be zeroed, both fields must be written explicitly (the return path frees based on them). */
		IWAN_MP_TX_CTX *ctx =
			(IWAN_MP_TX_CTX *)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);

		ctx->buf = inner;
		ctx->mdl = mdl;
	}
	nbl->SourceHandle = ext->mp.adapter_handle;
	nbl->NblFlags |= (ver == 4) ? NDIS_NBL_FLAGS_IS_IPV4 : NDIS_NBL_FLAGS_IS_IPV6;
	/* the frame type must be written explicitly into the NBL info slot, and in **network byte order** (in memory that is
	 * 08 00 / 86 DD), the same convention as Wintun HTONS(NDIS_ETH_TYPE_IPV4).
	 * the consequence of omitting it: NDIS drops at the miniport receive boundary as "frame type not supported" -- pktmon
	 * records DropReason Unsupported EtherType, DropLocation 0xE0001007, and the owner
	 * is this driver; the field symptom is that both tunnel ends look healthy (outer frames go back and forth, rx_delivered
	 * is climbing), yet inner ping loses 100 percent of its packets. */
	NET_BUFFER_LIST_INFO(nbl, NetBufferListFrameType) =
		(PVOID)(ULONG_PTR)((ver == 4) ? 0x0008u : 0xDD86u);
	/* the count was taken once at entry (see above): it is not added here, otherwise the return side would subtract only once
	 * and the count would stay permanently too high, pinning Halt in a busy-wait that never reaches zero. */

	/* No RESOURCES: ownership goes to NDIS, and the buffer is freed on return. The IRQL bits must be reported
	 * honestly -- this function is called from the protocol edge receive path, usually at DISPATCH_LEVEL.
	 *
	 * SINGLE_ETHER_TYPE must be set: it and the NetBufferListFrameType written above are a
	 * pair -- the bit declares "the NBLs indicated this time share one frame type", and only then does NDIS read the info slot
	 * for the type; missing either one, NDIS drops at the miniport receive boundary with
	 * "Unsupported EtherType" (DropLocation 0xE0001007).
	 * NdisMediumIP (raw IP, no Ethernet header) does not exempt you from this step: the reference implementation
	 * Wintun TunReceive also fills in both NetBufferListFrameType and
	 * NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE as well. */
	NdisMIndicateReceiveNetBufferLists(ext->mp.adapter_handle, nbl,
					   NDIS_DEFAULT_PORT_NUMBER, 1,
					   NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE |
					   ((KeGetCurrentIrql() == DISPATCH_LEVEL) ?
					    NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL : 0));
	/* from here on the NBL belongs to NDIS: return requests go through iwan_win_mp_return_nbls, and the buffer and
	 * MDL are freed there too. The local pointer of this function must be invalidated in place -- NULLing it is
	 * the only mark of this ownership transfer (which also incidentally silences the static analyzer "leak" false positive). */
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
	/* this handler receives MiniportAdapterHandle, not MiniportAdapterContext,
	 * so ext is not reachable: fetch it from the singleton here (by construction this miniport serves one adapter only,
	 * InitializeEx rejects a second adapter outright). rx_inflight must reach zero before the NBL pool
	 * is destroyed, and Halt uses it to tell whether any NBL is still indicated upward and not yet returned. When
	 * UnloadHandler runs, the singleton has already been cleared, and even then the return must still complete (NBLs and buffers are pool
	 * assets, and missing them is a leak); only the count has nowhere to be decremented. */
	IWAN_WIN_DEVICE_EXTENSION *ext = iwan_win_mp_device_ext();

	UNREFERENCED_PARAMETER(MiniportAdapterHandle);
	UNREFERENCED_PARAMETER(ReturnFlags);

	for (nbl = NetBufferLists; nbl != NULL; ) {
		/* read NEXT before freeing: NdisFreeNetBufferList hands this memory back to the pool free
		 * list, so a later loop increment reading nbl->Next reads reused garbage (at best the same
		 * NBL is freed twice and the refcount goes off balance, at worst a wild pointer leads to an invalid address). */
		PNET_BUFFER_LIST next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		IWAN_MP_TX_CTX *ctx =
			(IWAN_MP_TX_CTX *)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);

		if (ext != NULL)
			InterlockedDecrement(&ext->mp.rx_inflight);

		/* only NBLs indicated upward by this driver can come back: each NBL has exactly one NB,
		 * one buffer, one MDL (same shape as netvmini). An NBL with more than one NB appearing here
		 * means someone returned somebody else's NBL to us -- say so, do not silently leak the buffers. */
		if (NET_BUFFER_NEXT_NB(NET_BUFFER_LIST_FIRST_NB(nbl)) != NULL)
			DbgPrint("iwanmp: returned NBL has more than one NB, buffers of the extra NBs will leak\n");
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

/* ---- miniport: OID --------------------------------------------------- */

/* write by the OID **defined width**. Originally it was always "8 bytes of buffer, write 8": for a 4-byte OID
 * (LINK_SPEED, MTU, MEDIA_* and so on) the value does happen to land in the low 4 bytes, but BytesWritten
 * lies; for the 2-byte OID_GEN_DRIVER_VERSION it is worse -- upper layers read only the low 2 bytes,
 * so the reported NDIS version number is wrong. */
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
	n++;				/* include the terminating NUL */
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
			/* accept everything: this adapter does no filtering, and power state does not affect TX/RX */
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
		/* raw IP medium: no Ethernet header, no ARP/ND, address and MTU are set by the control plane */
		return iwan_win_mp_oid_put_u32(OidRequest, (UINT32)NdisMediumIP);
	case OID_GEN_PHYSICAL_MEDIUM:
		return iwan_win_mp_oid_put_u32(OidRequest,
					       (UINT32)NdisPhysicalMediumUnspecified);
	case OID_GEN_MAC_OPTIONS:
		return iwan_win_mp_oid_put_u32(OidRequest, 0u);
	case OID_GEN_LINK_SPEED:
		/* this is the "nominal link rate" required by OID semantics, unit 100 bps:
		 * 1 Gbps => 10,000,000. Real throughput can only come from measurement and is not reported here. */
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
		/* the semantics are "the NDIS version this driver conforms to": high byte major, low byte minor.
		 * runtime 6.89 -> 0x0659; the original 0x0100 claimed 1.0 to the outside. */
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
	/* same here: all OID requests complete synchronously, nothing to cancel */
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

/* ---- register / unregister ----------------------------------------------------- */

/* Control plane fetches the extension: this plane has no device extension (the control device created by NdisRegisterDeviceEx
 * carries none), and the extension is the single one allocated by DriverEntry. */
IWAN_WIN_DEVICE_EXTENSION *
iwan_win_mp_device_ext(VOID)
{
	return g_mp_ext;
}

/* ---- registration: probe by the NDIS minimum version requirement -------------------------------- */

/* DirectOid / SynchronousOid three handlers: this plane never initiates an OID of its own and
 * answers "not supported" to all. They appear only in the REVISION_2/3 characteristics tables (with an older revision
 * the fields do not exist at all); they are here so the candidate configurations cover all three revisions. */
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

/* Fill in one characteristics table per (declared NDIS minor version, characteristics table revision). The handler set
 * corresponds strictly to the revision: choosing a higher revision means all fields of that tier must be supplied. */
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

/* ---- fuses: the two switches under Parameters -----------------------------------
 * Disarm=1: register nothing, DriverEntry fails outright (the device stays at Code 10, NDIS is never touched,
 *   no control device is created). This is the default state of this machine after the bugcheck, cleared only when a test is confirmed
 *   by the installer and set again after the test.
 * NoProto=1: register the miniport only, not the protocol edge (outer carrier TX/RX is absent, the inner NIC can still
 *   be verified on its own: the adapter appears, address and MTU can be set, SendNetBufferLists is called).
 * Both are read once **before load** only and cannot be changed at runtime -- they are safety gates, not configuration.
 * Disarm defaults to 1 (not 0): when the key is absent it must land on the "not switched on" side. */
/* PE TimeDateStamp of the running image: this is the only hard evidence of "which build is actually running on the guest".
 * Every path to swap the image on the guest is blocked (overwriting a loaded .sys gives Access denied, sc delete
 * only marks it for deletion and delete-driver requires a reboot), while file mtime/size may well belong to a replaced
 * old file. The driver image itself is non-paged and resident, DriverEntry runs at PASSIVE, so reading the
 * DOS/NT headers directly is safe; if any step does not hold, return 0 (0 means "cannot read", not "a very old
 * build"). */
static ULONG
iwan_win_mp_build_stamp(_In_opt_ PDRIVER_OBJECT driver)
{
	const UCHAR *base;
	LONG lfanew;
	ULONG stamp = 0;

	if (driver == NULL || driver->DriverStart == NULL)
		return 0;
	base = (const UCHAR *)driver->DriverStart;

	/* e_magic is not MZ, do not follow e_lfanew and read anyway -- this pointer comes from the kernel,
	 * reading the wrong place is a bugcheck, not worth that risk for one line of diagnostics. */
	if (base[0] != 'M' || base[1] != 'Z')
		return 0;
	RtlCopyMemory(&lfanew, base + 0x3C, sizeof(lfanew));
	if (lfanew <= 0 || lfanew > 0x1000)
		return 0;
	/* IMAGE_NT_HEADERS32/64 have FileHeader 4 bytes after Signature,
	 * TimeDateStamp is the 2nd field of FileHeader (+4) => +8 in total. */
	RtlCopyMemory(&stamp, base + lfanew + 8, sizeof(stamp));
	return stamp;
}

static ULONG
iwan_win_mp_param_get(_In_ PCWSTR name, _In_ ULONG dflt)
{
	UNICODE_STRING path, vn;
	OBJECT_ATTRIBUTES oa;
	HANDLE key = NULL;
	/* This buffer is only filled with the first len bytes by ZwQueryValueKey, the rest stays uninitialized memory;
	 * explicit zeroing both silences the analyzer (C28199) and avoids treating stack content as Type/DataLength
	 * for the decision (when the value is not found those two fields do not exist at all). */
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
		/* Copy field by field into a local struct before deciding: the kvv memory is ours and already zeroed,
		 * so the analyzer can follow it all the way (C28199); aliasing buf directly leaves it able only to
		 * conclude "possibly uninitialized". The field semantics are exactly the same. */
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

/* Miniport registration: try the candidate table tier by tier, use the first hit, and drop one T4x key per tier.
 *
 * Why the candidate table is back: last round it was changed to a single call (runtime minor version + REVISION_1),
 * and the guest actually returned **0xC0010005 (NDIS_STATUS_BAD_CHARACTERISTICS)**; while the earlier "the first
 * tier hit" conclusion came from reading a stale key from the previous install (the keys of that round were not deleted cleanly),
 * so it does not hold. If only one value can change per round, and each round costs a ten-minute build + repackage + device restart,
 * all candidates are tried here in one go: each tier NTSTATUS goes to T40+i, a hit goes to T39 (low 8 bits
 * are the revision, the next 8 bits the declared minor version), and complete failure stores T38 = attempt count.
 * no handle is left behind after a failure: not one registration succeeded at this step, so returning failure is clean. */
typedef struct {
	UCHAR minor;	/* 0xFF = use runtime minor version */
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

/* DriverEntry load path. The order here and the failure policy were fixed by one bugcheck:
 *
 *   1. Disarm is read and judged first -- the fuse must take effect before any NDIS call;
 *   2. miniport registration fails => nothing has been left behind, returning failure is clean (device at Code 10);
 *   3. after miniport registration succeeds, DriverEntry **must never return failure again**. A half-registered state
 *      (NDIS thinks the driver is still there while DriverEntry failed) makes a later devcon remove /
 *      pnputil /delete-driver hang forever, and at reboot the whole machine fails to boot --
 *      this really happened on the guest, and recovery is only possible by deleting the service key and driver file offline from WinRE;
 *   4. a protocol edge failure is tolerable: its absence only means outer carrier TX/RX is not up, the miniport and
 *      control device work as usual, and user mode can open the device, read diagnostics and see which NTSTATUS it was.
 * Therefore the failure path **can only contain an unregister call after step 2**, and at that point not one registration has succeeded. */
NTSTATUS
iwan_win_mp_init(_In_ PDRIVER_OBJECT driver,
		 _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
		 _In_ PUNICODE_STRING registry_path)
{
	NDIS_STATUS st, stp;

	/* Make later pool allocations come from NX (non-executable) memory: the bar for exploiting a rewritten
	 * kernel-mode pointer is higher, and this is closer to "secure by default". */
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
	KeInitializeSpinLock(&ext->mp.lock);

	/* The singleton is installed before registration: MiniportInitializeEx may be called at any moment,
	 * and control device IRPs can only appear after that. */
	g_mp_ext = ext;

	/* Stage 30 records the "environment": T30 = NdisGetVersion() (the form 0x00060059 means
	 * NDIS 6.89). On registration failure this is what tells "the driver is written wrong" apart from "on this machine, NDIS
	 * being older than the version the driver declares", and this is the only criterion. */
	iwan_win_mp_trace(30, (LONG)NdisGetVersion());
	/* Stage 31 = PE TimeDateStamp of the running image. Read this first after an install and compare it with the CI artifact
	 * timestamp for iwanmp.sys, and you can tell "whether the file on disk is the build just produced",
	 * without guessing from a disassembly. */
	{
		ULONG stamp = iwan_win_mp_build_stamp(driver);
		iwan_win_mp_trace(31, (LONG)stamp);
		if (stamp == 0)
			DbgPrint("iwanmp: cannot read image timestamp (DriverStart=%p)\n",
				 driver != NULL ? driver->DriverStart : NULL);
	}

	{
		/* The default is deliberately 1 (fuse engaged): if the key is deleted, if writing it at install fails,
		 * or if the image was installed by some other path, the driver registers nothing and stays at Code 37.
		 * For it to work the installer must explicitly write Disarm=0 -- "insecure by default" is
		 * unacceptable here, because one wrong registration keeps the whole machine from booting. */
		ULONG disarm = iwan_win_mp_param_get(L"Disarm", 1);

		iwan_win_mp_trace(8, (LONG)disarm);
		if (disarm != 0) {
			iwan_win_mp_trace(9, (LONG)STATUS_UNSUCCESSFUL);
			g_mp_ext = NULL;
			DbgPrint("iwanmp: fuse engaged (Disarm=1), registering nothing\n");
			return STATUS_UNSUCCESSFUL;
		}
	}

	/* DriverObject being "clean" is the prime suspect after two installs both returned 0xC0010005:
	 * the miniport unload entry is UnloadHandler in the characteristics table, while DriverUnload is
	 * the field of an ordinary WDM driver; it being already occupied may be exactly the criterion of "not a valid
	 * miniport driver". Record it truthfully first, then clear it (T7). */
	if (driver->DriverUnload != NULL) {
		iwan_win_mp_trace(7, 1);
		driver->DriverUnload = NULL;
	} else {
		iwan_win_mp_trace(7, 0);
	}

	/* NoMp=1: register the protocol edge only, no miniport. This is a **diagnostics mode**, not a product configuration:
	 * after miniport registration is rejected (0xC0010005), the only remaining question is whether the protocol edge"
	 * 0xC0000001 is a problem of its own, or whether the miniport half drags it down". Both are
	 * NdisRegisterXxxDriver reading the same service key, so leaving only one half each time separates the blame:
	 *   - With NoMp=1 the protocol edge registers successfully (T69 has a value) => the miniport half is the culprit;
	 *   - still 0xC0000001 => the Ndi\Interfaces shape of the service key is wrong, independent of ordering.
	 * When the miniport is skipped the DriverEntry failure invariant stays the same (no registration was done, returning
	 * failure is clean), only the switch here makes "skipped" and "rejected" distinguishable on the T table. */
	{
		ULONG nomp = iwan_win_mp_param_get(L"NoMp", 0);

		iwan_win_mp_trace(14, (LONG)nomp);
		if (nomp != 0) {
			DbgPrint("iwanmp: NoMp=1, skipping miniport, registering protocol edge only\n");
			goto proto_edge;
		}
	}

	st = iwan_win_mp_register(driver, registry_path, ext);
	if (st != NDIS_STATUS_SUCCESS) {
		iwan_win_mp_trace(10, (LONG)st);
		g_mp_ext = NULL;
		DbgPrint("iwanmp: miniport registration failed 0x%08lx\n", (unsigned long)st);
		return STATUS_UNSUCCESSFUL;
	}
	iwan_win_mp_trace(11, (LONG)NDIS_STATUS_SUCCESS);

proto_edge:

	/* The protocol edge (outer carrier TX/RX). Failure is not fatal, for the reason in item 4 above. */
	if (iwan_win_mp_param_get(L"NoProto", 0) != 0) {
		stp = NDIS_STATUS_NOT_SUPPORTED;
		DbgPrint("iwanmp: NoProto=1, skipping protocol edge\n");
	} else {
		stp = iwan_win_proto_init(ext);
	}
	iwan_win_mp_trace(12, (LONG)stp);
	InterlockedExchange(&ext->mp.proto_registered,
			    (stp == NDIS_STATUS_SUCCESS) ? 1 : 0);
	iwan_win_mp_trace(13, (LONG)STATUS_SUCCESS);
	DbgPrint("iwanmp: loaded, %ws (protocol edge 0x%08lx)\n",
		 IWAN_WIN_DRV_VERSION_STR_MP, (unsigned long)stp);
	return STATUS_SUCCESS;
}

/* The control device must be created after miniport registration: NdisRegisterDeviceEx needs a handle, and
 * NdisMRegisterMiniportDriver requires DriverObject to be clean at call time (on the guest, when it
 * already had its own device attached it returned NDIS_STATUS_BAD_CHARACTERISTICS = 0xC0010005).
 * The attribute table carries its own MajorFunctions, and on that basis NDIS creates a separate driver object for this device,
 * so the NDIS DriverObject is never touched. */
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

	/* The same SDDL as the WFP plane: only System and Administrators can open it.
	 * The user-mode client therefore needs administrator rights (consistent with needing root on the Linux side). */
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
	attr.ExtensionSize = 0;			/* the extension stays in our own hands */
	attr.DefaultSDDLString = &sddl;
	attr.DeviceClassGuid = &iwan_win_devclass_guid;

	st = NdisRegisterDeviceEx(ext->mp.mp_driver_handle, &attr, &devobj, &handle);
	if (st != NDIS_STATUS_SUCCESS) {
		iwan_win_mp_trace(5, (LONG)st);
		DbgPrint("iwanmp: NdisRegisterDeviceEx failed 0x%08lx\n",
			 (unsigned long)st);
		return STATUS_UNSUCCESSFUL;
	}

	ext->mp.ctrl_devobj = devobj;
	ext->mp.ctrl_handle = handle;
	DbgPrint("iwanmp: control device %wZ ready\n", &dev_name);
	return STATUS_SUCCESS;
}

VOID
iwan_win_mp_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext)
{
	if (ext == NULL)
		return;
	iwan_win_proto_fini(ext);		/* tear down carrier TX/RX first */
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

/* UnloadHandler: NDIS calls this when the driver unloads (not DriverUnload -- that field belongs
 * to NDIS after the miniport is registered). The whole set of exits must happen here: data plane -> sessions -> extension memory.
 * The control device is unregistered by NdisDeregisterDeviceEx (the symbolic link is removed by itself), and the extension is ours
 * to allocate, so it must be returned here too. */
static
_Function_class_(MINIPORT_UNLOAD)
VOID
iwan_win_mp_unload_hook(_In_ PDRIVER_OBJECT driver)
{
	IWAN_WIN_DEVICE_EXTENSION *ext = g_mp_ext;

	UNREFERENCED_PARAMETER(driver);

	if (ext != NULL) {
		/* The same guard as iwan_win_unload: drain the control device in-flight IRPs first,
		 * and only then unregister the device and free the extension. */
		if (ext->ctrl_remove_init != 0 &&
		    InterlockedExchange(&ext->ctrl_remove_waited, 1) == 0)
			IoReleaseRemoveLockAndWait(&ext->ctrl_remove_lock, ext);
		iwan_win_mp_fini(ext);
		iwan_win_session_teardown(ext);
		iwan_win_ctrl_fini(ext);
		ExFreePoolWithTag(ext, IWAN_TAG_SESS);
	}
	driver->DeviceObject = NULL;	/* defensive: if DriverUnload is called as well, do not do it twice */
	DbgPrint("iwanmp: unloaded\n");
}
