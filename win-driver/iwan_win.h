/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win.h -- driver-internal header for the Windows kernel data plane.
 *
 * Correspondence with the Linux module (docs/win-wfp-data-plane.md):
 *   struct iwan_session   <->  IWAN_WIN_SESSION
 *   the /dev/iwan page    <->  IWAN_WIN_SESSION.shm (one non-paged pool page, read-only mapped to user mode)
 *   genetlink session attributes  <->  buffers of IOCTL_IWAN_SESSION_OPEN/CLOSE/GET
 *   nf_hook_ops + ndo_start_xmit  <->  WFP callout (see iwan_win_wfp.c)
 *
 * Hard constraints (same as on Linux):
 *   - no timers, DPCs, work items or threads in the driver -- liveness is judged by user mode polling the shared memory page;
 *   - the driver only writes the timestamps and counters in the shared memory page, user mode is read-only;
 *   - the time base of last_rx_ms is "monotonic milliseconds since boot" (corresponds to ktime_get_mono_fast_ns),
 *     0 means never received or already disconnected.
 *
 * Concurrency model (must be spelled out explicitly on the Windows side; on Linux the rtnl/netns lifetime covers it):
 *   - the control plane (open/close/query in this file) runs at PASSIVE_LEVEL, serialized by ctrl_mutex,
 *     so it may allocate pool memory, map/unmap user addresses and wait;
 *   - the data plane (WFP classify) runs at DISPATCH_LEVEL and takes ExAcquireRundownProtection first,
 *     once protection is held it only reads session state and only writes the shared memory page and the statistics counters;
 *   - before changing session state the control plane calls ExWaitForRundownProtectionRelease to drain the data plane,
 *     then ExReInitializeRundownProtection lets it through again -- so the data plane never sees
 *     a targets pointer that is being replaced, and there is no use-after-free.
 *   - the data plane does not exist at all before a session is established: callouts and filters are installed by IOCTL_OPEN
 *     and removed by IOCTL_CLOSE (iwan_win_wfp_start/stop). So sc start only verifies
 *     "the driver can load and the device can be opened"; taking over traffic is a separate later step -- on Linux
 *     "only when the route points at iwan0 can outbound packets be intercepted", the same form.
 */
#ifndef IWAN_WIN_H
#define IWAN_WIN_H

/* ntifs.h rather than ntddk.h: KeStackAttachProcess / KAPC_STATE are declared only there
 * (unmapping user-mode shared memory requires switching to the owner process address space). ntifs.h is
 * a superset of ntddk/wdm; the WDK docs also require "use it instead of ntddk.h when these APIs are needed". */
#include <ntifs.h>
#include <wdm.h>
#include <wdmsec.h>		/* IoCreateDeviceSecure */
#include <ndis.h>		/* NdisGetDataBuffer and the NET_BUFFER_* macros */
#include <fwpsk.h>		/* WFP kernel API */
#include <fwpmk.h>		/* WFP management API */

#include "iwan_win_abi.h"
#include "iwan_win_frame.h"	/* wire format, XOR, checksum, target matching (pure logic, can be diff-tested) */

/* pool tags: four permutations of 'I','W','A','N', to make !poolused attribution easy */
#define IWAN_TAG_SESS   'sneI'
#define IWAN_TAG_TARGET 'tgeI'
#define IWAN_TAG_PKT    'kpeI'
#define IWAN_TAG_SHM    'mheI'

/*
 * Non-paged pool allocation: ExAllocatePool2 is available from Win10 2004 on and zeroes by default; older targets fall back to
 * ExAllocatePoolWithTag -- that path does **not** zero (an old comment said "both paths zero explicitly",
 * which does not match the implementation). The two paths differ in semantics, so callers must themselves initialize "the fields
 * that would be read on the failure path", e.g. IWAN_INJECT_CTX.mdl, and must not rely on zeroing.
 * This project does not set NTDDI_VERSION explicitly (the vcxproj only sets TargetVersion=Windows10),
 * so which branch is actually taken depends on the default in the WDK headers; either is possible.
 */
#if defined(NTDDI_WIN10_VB) && (NTDDI_VERSION >= NTDDI_WIN10_VB)
#  define IWAN_ALLOC(size, tag) ExAllocatePool2(POOL_FLAG_NON_PAGED, (size), (tag))
#else
#  define IWAN_ALLOC(size, tag) ExAllocatePoolWithTag(NonPagedPool, (size), (tag))
#endif

#define IWAN_WIN_DRV_VERSION_STR L"iwan-win 0.1 (WFP callout, ABI 2)"
#define IWAN_WIN_DRV_VERSION_STR_MP L"iwan-win 0.1 (miniport + protocol, ABI 2)"


/* ---- Session --------------------------------------------------------- */

typedef struct _IWAN_WIN_SESSION {
	volatile LONG		valid;		/* set to 1 only after all fields are ready */

	/* control plane parameters (corresponds to IWAN_A_SID/TOK/ENC/KEY) */
	UINT16			sid;
	UINT32			tok;
	UINT8			enc;
	UINT8			key[8];

	/* outer endpoints (addresses/ports are in network byte order) */
	UINT32			outer_src;	/* v4 outer address, big-endian integer */
	UINT32			outer_dst;
	UINT32			outer_hop;	/* outer next hop (passed in by the control plane after a route lookup;
						 * 0 = not provided, treat the peer as on-link) */
	UINT16			sport;
	UINT16			dport;
	UINT8			outer_src6[16];
	UINT8			outer_dst6[16];

	/* binding (corresponds to IWAN_A_OIF/IP/IP6/CARRIER) */
	UINT32			flags;
	UINT32			oif_index;
	UINT8			outer_if_guid[16];	/* carrier NIC interface GUID (all 0 = not provided) */
	UINT8			peer_mac_fixed[6];	/* test knob: pin the next-hop MAC */
	UINT32			peer_mac_fixed_valid;	/* 0 = use ARP resolution as usual */
	UINT32			bind_ip;
	UINT8			bind_ip6[16];
	UINT32			carrier_index;	/* read-only reply: the NIC actually carrying traffic now */
	UINT32			carrier_mtu;

	/* inner */
	UINT32			inner_ip;
	UINT8			inner_ip6[16];
	UINT32			inner_mtu;
	UINT32			effective_mtu;	/* value validated against the carrier NIC MTU when the session is established */

	/* target set (longest prefix match) */
	UINT32			target_count;
	IWAN_WIN_TARGET		*targets;

	/* liveness state: the same storage as the shared memory page (corresponds to IWAN_A_LAST_KEEPALIVE_MS).
	 * The shm page is written exclusively by the driver; user mode maps it read-only (see iwan_win_shm_map_user). */
	IWAN_WIN_SHM		*shm;
	PMDL			shm_mdl;	/* NULL means there is currently no user-mode mapping */
	PVOID			shm_user_va;
	PEPROCESS		shm_owner;	/* owner process holding a reference; the mapping is only valid for it */

	/* statistics (counter names/order correspond to enum iwan_stats_attr) */
	IWAN_WIN_STATS		stats;
} IWAN_WIN_SESSION;

/* ---- Second plane: miniport + protocol driver ------------------------- */

/*
 * Relation to the WFP plane: the session control plane (IWAN_WIN_SESSION and iwan_win_session.c) and
 * the wire logic (iwan_win_frame.c) are fully shared; only "how packets get in and out" is swapped:
 *
 *   WFP plane (iwan.sys)             this plane (iwanmp.sys, --data-plane ndis)
 *   outbound: intercept at OUTBOUND_IPPACKET    miniport receives the inner datagram handed down by the stack
 *   outbound: FwpsInjectNetworkSendAsync        protocol driver hands the outer UDP directly to the carrier NIC
 *   inbound: intercept at INBOUND_TRANSPORT     protocol driver receives outer UDP from the carrier NIC
 *   inbound: FwpsInjectNetworkReceiveAsync      miniport indicates the inner datagram upward
 *
 * Three real differences: (1) RX and TX happen where they belong, no injection API is needed, so there is no "in-flight
 * NBL holds non-paged pool and must be throttled" problem, and the send is synchronous (the completion callback only returns memory);
 * (2) inbound is not re-injected into the stack but indicated up directly like Linux netif_rx, saving one
 * full-payload copy; (3) outbound only handles packets "routed to this adapter" (the inner routing table decides),
 * so target set matching is no longer needed.
 *
 * Carrier selection matches the Linux-side semantics: an explicit binding binds that one NIC; if unbound, look up
 * the FIB by outer destination address; once selected, all RX/TX for this session uses only that NIC.
 */
struct _IWAN_MP_BINDING;

/* Size of the outbound NBL context area: enough for IWAN_MP_TX_CTX (buffer address + MDL,
 * two pointers). The pool is created with this size, both sides (protocol edge send, miniport indicate) share the same number,
 * and the actual size of IWAN_MP_TX_CTX is asserted with C_ASSERT in iwan_win_proto.c. */
#define IWAN_MP_NBL_CTX_SIZE	16u

/* NBL context layout: outbound (protocol edge) and inbound indication (miniport) share the same pool and
 * the same context block, so there must be exactly one definition -- two separate layouts would diverge sooner or later.
 * On return, take the buffer and MDL from it and do not derive the address back from the MDL (an upper protocol driver may advance past the NB
 * and return it later; then the address in the MDL is an internal buffer address and ExFreePoolWithTag would corrupt the pool). */
typedef struct _IWAN_MP_TX_CTX {
	UINT8			*buf;		/* whole frame from IWAN_ALLOC (including the Ethernet header) */
	PMDL			mdl;
} IWAN_MP_TX_CTX;

/* Carrier-side link layer constants (the miniport side is NdisMediumIP, bare IP, no Ethernet header) */
#define IWAN_MP_ETH_HDR_LEN	14u
#define IWAN_MP_ETH_TYPE_IP4	0x0800u
#define IWAN_MP_ETH_TYPE_ARP	0x0806u
#define IWAN_MP_ETH_TYPE_IP6	0x86DDu

/* Upper bound on in-flight outer NBLs, both files must use the same number:
 *   - iwan_win_mpdata.c (engine) checks before encapsulation, drops and counts tx_bad_state when over the limit;
 *   - iwan_win_proto.c (protocol edge) catches it once more before handing to NDIS.
 * Every in-flight NBL holds non-paged pool (buffer + MDL + NBL) until the send completion callback; the inner side may be
 * far faster than the carrier, so without a limit it grows net at GB/s rates and exhausts non-paged pool in seconds -- the WFP plane
 * hard hang was exactly this mechanism; do not step into the same hole twice. */
#define IWAN_MP_MAX_OUTER_INFLIGHT 4096u

/* Expiry time for outer fragment reassembly: all fragments of a datagram must arrive within this window, otherwise new fragments
 * start from scratch (a retransmit from the peer does not carry old state). Linux ip_defrag uses a timeout of the same order,
 * in the 30 second range, but here there are few slots and the per-packet limit is small, so shorter is safer. */
#define IWAN_WIN_FRAG_TTL_MS	2000u

/* Upper bound on in-flight inner indications. Outbound had a gate while inbound originally had none; this is the only unbounded non-
 * paged pool allocation in the whole data plane: every indicated packet permanently holds an inner buffer (IWAN_ALLOC) + IoAllocateMdl +
 * a pool NBL, about 1.6-2 KB, without NDIS_RECEIVE_FLAGS_RESOURCES, so return can only wait for the upper
 * stack to call MiniportReturnNetBufferLists. When the send path occupies DISPATCH for long periods the return side is
 * starved, the net growth is linear at the inbound rate and exhausts non-paged pool within minutes -- the symptom is a whole-machine freeze,
 * too fast to write a BugCheck (Kernel-Power 41 + 6008), the same family as the WFP plane hard hang.
 * 4096 x 2 KB ~ 8 MB, the order of "queuing allowed, eating through memory not allowed"; over the limit drop packets and count
 * rx_nomem (the same outward reporting channel as allocation failure, readers need not distinguish). */
#define IWAN_MP_MAX_INNER_INFLIGHT 4096u

typedef struct _IWAN_MP_PLANE {
	/* miniport side. These two handles have **completely different lifetimes** and must never share one field:
	 *   mp_driver_handle: output of NdisMRegisterMiniportDriver, alive from DriverEntry
	 *     to UnloadHandler, used for both deregistration and NdisRegisterDeviceEx;
	 *   adapter_handle: the MiniportInitializeEx argument (MiniportAdapterHandle),
	 *     valid only between InitializeEx and Halt, used for both indication and completion.
	 * They once shared one field; the result was that the "serve only one adapter" check in MiniportInitializeEx
	 * was already true on the first start (registration had filled the field in early), and the adapter came up as Code 10. */
	NDIS_HANDLE		mp_driver_handle;
	NDIS_HANDLE		adapter_handle;	/* MiniportAdapterHandle */
	/* There are two NBL pools and their lifetimes must be separate. They once shared one; as soon as MiniportHaltEx destroyed it
	 * the protocol edge's still in-flight outer NBLs were destroyed together with the pool -- NDIS's hard rule is
	 * "every NBL in a pool must be freed before the pool", violating it gives 0x1E refcount imbalance
	 * and 0xD1 (a late return walks into a freed pool):
	 *   nbl_pool: for inbound indication, owned by the miniport, created in InitializeEx, destroyed after Halt drains it;
	 *   tx_pool : for outbound outer sends, owned by the protocol edge, created in proto_init, destroyed after proto_fini drains it.
	 * Both pools must reserve 16 bytes of context (IWAN_MP_TX_CTX = buffer + MDL). */
	NDIS_HANDLE		nbl_pool;
	NDIS_HANDLE		tx_pool;
	/* Number of inbound NBLs indicated up but not yet returned: Halt uses it to tell whether any in-flight
	 * NBL is still in the pool; if the wait times out it does not free the pool (leaking one pool is far better than letting a return land in a freed pool). */
	volatile LONG		rx_inflight;
	volatile LONG		mp_running;	/* Pause/Restart gate (1 = can receive and send) */
	volatile LONG		proto_registered;	/* the protocol edge has registered successfully at least once */

	/* control device (\Device\iwanmp): created by NdisRegisterDeviceEx, so it is
	 * an NDIS device and shares NDIS's DriverObject; deregistration must use the same handle. */
	PDEVICE_OBJECT		ctrl_devobj;
	NDIS_HANDLE		ctrl_handle;

	/* protocol edge. The binding table itself is driver-wide (see g_bindings in iwan_win_proto.c)
	 * and is not kept here: the protocol driver registers in DriverEntry, so it appears before the miniport (PnP)
	 * and disappears after it; hanging the table off the device extension would mismatch lifetimes. */
	NDIS_HANDLE		proto_handle;	/* handle from NdisRegisterProtocolDriver */
	KSPIN_LOCK		lock;		/* protects active/next hop/MAC/timestamps */
	struct _IWAN_MP_BINDING	*active;	/* carrier selected by the session; NULL = not selected */
	UINT32			active_ifindex;
	UINT32			next_hop_be;	/* outer next hop (v4, network byte order) */
	UINT8			local_mac[6];	/* local MAC of the selected carrier (filled into the source address when a frame is sent) */
	UINT8			peer_mac[6];	/* MAC of the next hop */
	volatile LONG		peer_mac_valid;
	volatile LONG		peer_mac_pending;	/* ARP request sent, waiting for a reply */
	UINT64			arp_ts_ms;	/* the moment peer_mac was resolved (used for aging) */
	UINT64			arp_last_ms;	/* the moment ARP was last sent (rate limiting, prevents request storms) */
	/* ARP diagnostics: when an outbound packet cannot be sent, one must first distinguish "request was not sent", "request was sent but no reply" and
	 * "a reply came but spa does not match". These three counters are only latched into
	 * T93/T94/T95 during IOCTL_GET (PASSIVE); the data plane only does atomic adds. */
	/* outer fragment reassembly slots: on Linux the outer path uses ip_defrag(), the WFP plane relies on tcpip's
	 * INBOUND_TRANSPORT (after reassembly) -- only this plane must reassemble on its own. The slot count and the per-packet
	 * limit are hardcoded (see iwan_win_frame.h), and this path is normally never used. */
	IWAN_WIN_FRAG_SLOT	frag[IWAN_WIN_FRAG_SLOTS];

	volatile LONG		arp_sent;
	volatile LONG		arp_rx;
	volatile LONG		arp_learn;

	/* carrier send progress: number of outer NBLs already handed to NDIS but not yet completed.
	 * Statistics always go into sess.stats (same names and meaning as the WFP plane), so tooling and user mode need no change. */
	volatile LONG		outer_outstanding;
} IWAN_MP_PLANE;

/* Statistics go through sess.stats, with the same names and meaning as IWAN_STAT_INC/ADD on the WFP plane -- user-mode
 * parsers, the shared page layout and the tooling STATS line need not change a single character for the new plane. */
#define IWAN_MP_STAT_INC(ext, f) \
	InterlockedIncrement64((volatile LONG64 *)&(ext)->sess.stats.f)
#define IWAN_MP_STAT_ADD(ext, f, v) \
	InterlockedExchangeAdd64((volatile LONG64 *)&(ext)->sess.stats.f, (LONG64)(v))

/* ---- Device extension -------------------------------------------------- */

typedef struct _IWAN_WIN_DEVICE_EXTENSION {
	IWAN_WIN_SESSION	sess;

	/* device object: callout registration is deferred until the session is established, when only ext is at hand,
	 * so the entry point stores it here (FwpsCalloutRegister needs it). */
	PDEVICE_OBJECT		devobj;

	KMUTEX			ctrl_mutex;	/* control plane serialization (PASSIVE_LEVEL) */
	EX_RUNDOWN_REF		rundown;	/* data plane reader protection */
	IO_REMOVE_LOCK		ctrl_remove_lock;	/* draining of in-flight control IRPs */
	volatile LONG		ctrl_remove_init;	/* 1 = initialized */
	volatile LONG		ctrl_remove_waited;	/* 1 = the unload path has entered the removed state */

	/* NBL pool: for injection (created by NdisAllocateNetBufferListPool, freed by wfp_fini;
	 * callouts must be deregistered and in-flight injections drained before freeing) */
	NDIS_HANDLE		nbl_pool;
	volatile LONG		inject_outstanding;

	/* data plane state of the second plane (iwanmp.sys). The WFP plane does not use it, but it sits in the same
	 * device extension: both planes share the session control plane, and sharing the extension struct saves one level of pointer. */
	IWAN_MP_PLANE		mp;

	/* WFP: engine handle, callout ids, injection handles */
	HANDLE			engine;
	UINT32			callout_id_out4;	/* FWPS_LAYER_OUTBOUND_IPPACKET_V4 */
	UINT32			callout_id_out6;	/* FWPS_LAYER_OUTBOUND_IPPACKET_V6 */
	UINT32			callout_id_in4;		/* FWPS_LAYER_INBOUND_TRANSPORT_V4 */
	UINT32			callout_id_in6;		/* FWPS_LAYER_INBOUND_TRANSPORT_V6 */
	HANDLE			inj_send4;
	HANDLE			inj_send6;
	HANDLE			inj_recv4;
	HANDLE			inj_recv6;
	/* whether the data plane is installed: 0 = not registered, 1 = installing/removing, 2 = registered.
	 * Registration is deferred until the session is established, and concurrent OPENs must still register only once, so
	 * a LONG + InterlockedCompareExchange acts as the gate. The data plane does not look at this field,
	 * it only looks at sess.valid. */
	volatile LONG		wfp_started;

	/* Diagnostic pass-through (bitmask, same bits and meaning as the Linux module's pass_through):
	 *   IWAN_WIN_PASS_TX  -- outbound: account the packet as "would be encapsulated", then swallow it;
	 *                        no encapsulation, no injection. The gap to the normal path is the encapsulation tax.
	 *   IWAN_WIN_PASS_RX  -- inbound: account the packet as "would be decapsulated" and let it continue;
	 *                        nothing is parsed. The gap to the normal path is the decapsulation tax.
	 * Read once per session from Parameters\PassThrough (REG_DWORD), default 0 = normal forwarding. Kept in the device
	 * extension rather than the session so that a measurement run does not depend on what the control plane sends. */
	UINT32			pass_through;

} IWAN_WIN_DEVICE_EXTENSION;

/* pass_through bits (deliberately the same numbers as IWAN_PASS_TX / IWAN_PASS_RX in kernel/iwan.h) */
#define IWAN_WIN_PASS_TX	1u
#define IWAN_WIN_PASS_RX	2u

/*
 * The control plane gets the extension from the device object.
 *
 * WFP plane: the device is created by DriverEntry with IoCreateDeviceSecure, so the extension is simply
 * the device extension.
 *
 * NDIS plane: the control device is created by NdisRegisterDeviceEx (when registering the miniport
 * the DriverObject must be clean, see iwan_win_mp_init); it carries no device extension --
 * the extension is the one we allocate ourselves, unique in the whole driver, so this returns the singleton.
 * The singleton is installed in iwan_win_mp_init and cleared in UnloadHandler; an IRP for the control device
 * can only arrive between the two.
 */
#ifdef IWAN_WIN_PLANE_MP
IWAN_WIN_DEVICE_EXTENSION *iwan_win_mp_device_ext(VOID);
#define IWAN_DEVEXT(devobj)	iwan_win_mp_device_ext()
#else
#define IWAN_DEVEXT(devobj) \
	((IWAN_WIN_DEVICE_EXTENSION *)(devobj)->DeviceExtension)
#endif

/* ---- Monotonic milliseconds (corresponds to iwan_now_ms) ----------------- */

/*
 * KeQueryInterruptTime() returns the 100ns interrupt time since boot and is unaffected by system time
 * adjustments -- the same semantics as Linux ktime_get_mono_fast_ns(). It is not cached in the driver,
 * it is read directly every time, to avoid introducing any notion of "timing".
 */
static __inline UINT64 iwan_win_now_ms(VOID)
{
	return (UINT64)(KeQueryInterruptTime() / 10000ULL);
}

/* ---- Session and control plane (iwan_win_session.c) --------------------- */

/* Control plane infrastructure: init/teardown of the mutex and rundown protection */
VOID iwan_win_ctrl_init(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
VOID iwan_win_ctrl_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* Control device dispatch (iwan_win_drv.c): shared by both planes. The NDIS plane wraps one more layer around it:
 * "if it is NDIS's own device object, pass it through unchanged" (see iwan_win_mp.c). */
/* Both planes share the same device class GUID (used only as a marker in the device object): the WFP plane passes it to
 * IoCreateDeviceSecure, the NDIS plane passes it to NdisRegisterDeviceEx. Defined in iwan_win_drv.c. */
extern const GUID iwan_win_devclass_guid;

/* Prototype and definition must carry the same function class: static analysis requires "declaration matches implementation"
 * (C28252/C28253), and DRIVER_DISPATCH is also the only basis on which it decides "this function may be stored in
 * MajorFunction[]" (C28023). Write it in both places, not just one. */
_Function_class_(DRIVER_DISPATCH)
NTSTATUS iwan_win_dispatch_create(_In_ PDEVICE_OBJECT devobj, _Inout_ PIRP irp);
_Function_class_(DRIVER_DISPATCH)
NTSTATUS iwan_win_dispatch_ioctl(_In_ PDEVICE_OBJECT devobj, _Inout_ PIRP irp);

NTSTATUS iwan_win_session_open(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			       _In_reads_bytes_(in_len) const IWAN_WIN_SESSION_OPEN *req,
			       _In_ ULONG in_len);
NTSTATUS iwan_win_session_close(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
NTSTATUS iwan_win_session_query_shm(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
				    _Out_ IWAN_WIN_SESSION_INFO *info);
VOID iwan_win_session_info(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			   _Out_ IWAN_WIN_SESSION_INFO *info);
VOID iwan_win_session_teardown(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* Whether the outer side uses v6: outer_dst6 not all zero means v6 (same criterion as the session attribute) */
BOOLEAN iwan_win_session_is_v6(_In_ const IWAN_WIN_SESSION *s);

/* Called only when a frame that "passed the outer filter and credential gate" arrives (data plane, DISPATCH_LEVEL):
 * writes the timestamp, sets UP and bumps counters. The caller must already hold rundown protection. */
VOID iwan_win_session_mark_rx(_Inout_ IWAN_WIN_SESSION *s, _In_ UINT32 is_ctrl);
/* Peer PT_CLOSE: zero the timestamp and set peer_state to closed (user mode uses this to judge openness) */
VOID iwan_win_session_mark_close(_Inout_ IWAN_WIN_SESSION *s);

/* Outbound rejection sample: write "why it was rejected" into the shared page diagnostic area (implemented in iwan_win_session.c,
 * shared by both data planes; called only on the reject path, may run at DISPATCH_LEVEL) */
VOID iwan_win_diag_tx(_Inout_ IWAN_WIN_SESSION *s, _In_ UINT32 reason,
		      _In_ ULONG len, _In_ ULONG tot, _In_ ULONG pkt0,
		      _In_reads_bytes_opt_(len) const UINT8 *pkt);

/* ---- WFP data plane (iwan_win_wfp.c) ----------------------------------- */

/* Preparation: open the BFE engine, create the NBL pool and the four injection handles. This step intercepts no packets. */
NTSTATUS iwan_win_wfp_init(_In_ PDEVICE_OBJECT devobj,
			   _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
/* Install/remove the data plane: callouts and filters for the four layers. start is idempotent; driven by IOCTL_OPEN
 * and IOCTL_CLOSE, so "loading the driver" and "taking over traffic" are two separately verifiable things. */
NTSTATUS iwan_win_wfp_start(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
VOID iwan_win_wfp_stop(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
VOID iwan_win_wfp_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* ---- Miniport + protocol driver plane (iwan_win_mp.c / iwan_win_proto.c) ----
 *
 * This plane is built by iwanmp.vcxproj with IWAN_WIN_PLANE_MP defined; it does not coexist with the WFP plane
 * in one binary: both must take over all RX and TX, putting them in one driver is both pointless and would entangle
 * the two lifetimes (PnP / non-PnP). User mode selects the plane by device name.
 */

/* Register the miniport and the protocol driver (iwan_win_mp.c). Called once from DriverEntry.
 *
 * There is a hard ordering constraint (measured on the target: otherwise NdisMRegisterMiniportDriver returns
 * NDIS_STATUS_BAD_CHARACTERISTICS = 0xC0010005 on the spot): when calling it the DriverObject must
 * still be "clean" -- it must have no device object of its own and no replaced MajorFunction.
 * So the control device is not created by DriverEntry with IoCreateDevice; instead, after registration it is handed to NDIS's
 * NdisRegisterDeviceEx (see iwan_win_mp_open_control). */
NTSTATUS iwan_win_mp_init(_In_ PDRIVER_OBJECT driver,
			  _Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			  _In_ PUNICODE_STRING registry_path);

/* Create the control device \Device\iwanmp (+ \DosDevices\iwanmp). Must be called after iwan_win_mp_init:
 * NdisRegisterDeviceEx needs the miniport handle, and the device it creates shares
 * NDIS's DriverObject, so the four MajorFunction entries are replaced with our dispatch here
 * (our own device goes to the control plane, NDIS devices are passed through unchanged). */
NTSTATUS iwan_win_mp_open_control(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* Load-time failure diagnostics (implemented in iwan_win_session.c, compiled only under IWAN_WIN_PLANE_MP):
 * write the stage number and status code into the Parameters subkey of the service key. When driver load fails there is no other channel
 * to look at -- the control device is not created yet and there is no kernel debugger on the target. Stage conventions:
 *   3-5   DriverEntry (3 data plane registration, 4 done, 5 control device)
 *   10-12 iwan_win_mp_init (10 miniport registration failed, 11 protocol edge registration failed, 12 done)
 *   20-22 MiniportInitializeEx (20 entry, 21 failure, 22 done)
 *   30    environment: T30 = NdisGetVersion() */
VOID iwan_win_mp_trace(_In_ ULONG stage, _In_ LONG status);

/* Protocol edge (iwan_win_proto.c): registers/unregisters NdisRegisterProtocolDriver.
 * init is called by iwan_win_mp_init, fini by iwan_win_mp_fini (neither runs in
 * the data plane, both at PASSIVE_LEVEL). */
NTSTATUS iwan_win_proto_init(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
VOID iwan_win_proto_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* Deregistration (called from iwan_win_unload). Stops the adapter first, then unbinds the protocol edge. */
VOID iwan_win_mp_fini(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* Session carrier selection: called by IOCTL_OPEN after the session is established; if selection fails the whole OPEN fails
 * (fail-closed: better to fail to establish a session than to put plaintext on the carrier network).
 * The criteria in order are: explicit oif_index -> the NIC owning bind_ip -> the FIB route for the outer destination. */
NTSTATUS iwan_win_mp_select_carrier(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);
VOID iwan_win_mp_trace_arp(_In_ IWAN_WIN_DEVICE_EXTENSION *ext);
/* Called from IOCTL_CLOSE: clear active and the next-hop MAC cache, so no state leaks between sessions. */
VOID iwan_win_mp_release_carrier(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext);

/* ---- Engine (iwan_win_mpdata.c): inner <-> outer, touches only bytes and stats --- */

/* Three states of outbound encapsulation: a drop is not a failure.
 *
 * Backpressure and over-limit must "pretend success" (IWAN_MP_TX_DROP). The reason is not aesthetic: the miniport writes
 * NDIS_STATUS_FAILURE back into the NBL, and the inner protocol stack turns that into sendto()'s
 * WSAEINVAL(10022) -- measured: with 4 threads streaming at full rate 77 percent of sendto calls came back this way,
 * the application sees "invalid argument" while the real cause is merely that the carrier could not keep up: dropping is
 * a normal outcome on UDP and should not be disguised as a programming error.
 *
 * Only "this packet itself is invalid" (neither IPv4 nor IPv6, or a header whose declared length contradicts the
 * frame) returns IWAN_MP_TX_FAIL;
 * everything else is DROPped and counted (tx_bad_state / ev_dropped / tx_err). */
#define IWAN_MP_TX_OK   0u	/* already handed to the carrier */
#define IWAN_MP_TX_DROP 1u	/* deliberately dropped, report success to the stack */
#define IWAN_MP_TX_FAIL 2u	/* invalid packet, report failure to the stack */

/* Fragmentation entry: an oversized v4 packet is sliced by the declared inner MTU and each piece is encapsulated (on Linux the stack
 * fragments it; here the driver does it). Return value semantics are the same as iwan_win_mp_encap_send. */
UINT32 iwan_win_mp_encap_send_pkt(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
				  _In_reads_bytes_(len) const UINT8 *inner,
				  _In_ ULONG len, _In_ BOOLEAN l4_offloaded);

UINT32 iwan_win_mp_encap_send(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			       _In_reads_bytes_(len) const UINT8 *inner,
			       _In_ ULONG len, _In_ BOOLEAN l4_offloaded);
/* Inbound: one outer IP datagram received from the carrier (starting at the IP header) -> decapsulate -> indicate up.
 * The buffer is allocated by this function and belongs to the miniport after a successful indication (freed when the NBL is returned). */
VOID iwan_win_mp_outer_recv(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
			    _In_reads_bytes_(len) const UINT8 *ip,
			    _In_ ULONG len);

/* ---- Exit points the protocol edge and miniport provide to the engine (implemented in proto.c / mp.c) ---- */

/* Fill the Ethernet header (source = MAC of the selected carrier, destination = next-hop MAC).
 * TRUE = filled in; FALSE = the neighbor is not resolved yet (this function has already sent a rate-limited ARP request),
 * and this packet should be dropped. Buffer ownership is unchanged: the caller (the engine) frees it itself on FALSE. */
BOOLEAN iwan_win_proto_fill_eth4(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
				 _Inout_ UINT8 *buf);

/* Hand the whole outer datagram frame (including the Ethernet header, buf allocated by IWAN_ALLOC) to the carrier NIC.
 * TRUE = handed to NDIS, ownership transferred (freed in the completion callback); FALSE = not sent,
 * the buffer has already been freed by this function (the caller must not reference it again). When the next-hop MAC is unknown it sends ARP and
 * returns FALSE.
 * v4 only: outer v6 neighbor discovery (NS/NA) is left to the second phase; for now, when the session is v6 the engine
 * rejects it outright and counts tx_bad_state, with no degraded path. */
/* Both outcomes make the caller lose eth: on TRUE ownership goes to NDIS with the NBL (freed in the completion
 * callback); on FALSE this function has already freed it. __drv_freesMem documents this "hand it over and let go"
 * convention as an annotation -- only as an annotation does static analysis stop reporting a caller leak. */
BOOLEAN iwan_win_proto_send_outer4(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
				   __drv_freesMem(_Out_) UINT8 *eth,
				   _In_ ULONG len);

/* Indicate a decapsulated inner datagram up (buf allocated by IWAN_ALLOC).
 * TRUE = indicated, ownership transferred (freed when the NBL is returned); FALSE = failure, and the buffer has already been
 * freed by this function (the caller must not reference it again and must not free it a second time). */
BOOLEAN iwan_win_mp_indicate_inner(_Inout_ IWAN_WIN_DEVICE_EXTENSION *ext,
				   __drv_freesMem(_Out_) UINT8 *inner,
				   _In_ ULONG len);

#endif /* IWAN_WIN_H */
