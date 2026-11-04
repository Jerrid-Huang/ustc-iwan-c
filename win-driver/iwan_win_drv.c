/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_drv.c - driver entry, device object and IOCTL dispatch.
 *
 * Corresponds to the Linux side: module init/exit + misc device registration + genetlink control plane entry.
 * Only the control plane is here: the packet path is entirely in the data plane files (callout of WFP plane iwan_win_wfp.c
 * / NDIS plane iwan_win_mp.c + iwan_win_proto.c), and it does not queue, start
 * threads or use timers -- matching the Linux module boundary that 'the kernel only carries data'.
 *
 * This file is shared by both planes, forked by IWAN_WIN_PLANE_MP. Three differences:
 *   (1) Device name: WFP plane \Device\iwan, NDIS plane \Device\iwanmp (the two planes
 *      can be installed on the same machine at once; user mode opens by name chosen with --data-plane);
 *   (2) Data plane 'attach/detach' hook: WFP is a callout filter, NDIS selects/releases the carrier;
 *   (3) Unload: WFP closes the BFE engine, NDIS only deregisters the miniport and protocol edge.
 */
#include "iwan_win.h"

/* Stage tracing for load-time failures: the NDIS plane writes the stage number into the service key; on the WFP plane it compiles to a no-op.
 * When the driver fails to start there is no user-mode channel at all (the control device is not even created); this is the only thing
 * visible at a glance -- see the description of iwan_win_mp_trace. */
#ifdef IWAN_WIN_PLANE_MP
#define MP_TRACE(stage, status)	iwan_win_mp_trace((stage), (status))
#else
#define MP_TRACE(stage, status)	((void)0)
#endif

#ifdef IWAN_WIN_PLANE_MP
#define IWAN_DRV_DEV_NAME	IWAN_WIN_DEVICE_NAME_MP
#define IWAN_DRV_DOS_NAME	IWAN_WIN_DOS_NAME_MP
#define IWAN_DRV_VERSION_STR	IWAN_WIN_DRV_VERSION_STR_MP
#else
#define IWAN_DRV_DEV_NAME	IWAN_WIN_DEVICE_NAME
#define IWAN_DRV_DOS_NAME	IWAN_WIN_DOS_NAME
#define IWAN_DRV_VERSION_STR	IWAN_WIN_DRV_VERSION_STR
#endif

#ifndef IWAN_WIN_PLANE_MP
/* WFP management session (fwpmk.h): used only in init/fini, process context, PASSIVE_LEVEL */
static HANDLE g_engine = NULL;
#endif

_Function_class_(DRIVER_DISPATCH)
NTSTATUS
iwan_win_dispatch_create(_In_ PDEVICE_OBJECT devobj, _Inout_ PIRP irp)
{
	UNREFERENCED_PARAMETER(devobj);
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

_Function_class_(DRIVER_DISPATCH)
NTSTATUS
iwan_win_dispatch_ioctl(_In_ PDEVICE_OBJECT devobj, _Inout_ PIRP irp)
{
	PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
	IWAN_WIN_DEVICE_EXTENSION *ext = IWAN_DEVEXT(devobj);
#ifdef IWAN_WIN_PLANE_MP
	/* IWAN_DEVEXT of the NDIS plane ignores the device object (the control device carries no extension; the extension is
	 * a singleton), so declare explicitly that it is unused, otherwise /W4 /WX gives C4100. */
	UNREFERENCED_PARAMETER(devobj);
#endif
	PVOID buf = irp->AssociatedIrp.SystemBuffer;
	ULONG in_len = sp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG out_len = sp->Parameters.DeviceIoControl.OutputBufferLength;
	NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
	ULONG info = 0;

	/* No extension = the data plane is not registered yet or already unregistered. The NDIS plane extension is allocated by DriverEntry
	 * and is normally never NULL; treat it as 'device not ready' rather than dereferencing NULL
	 * -- the control device still exists after the adapter Halt, and nothing should be guaranteed on that path. */
	if (ext == NULL) {
		irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_DEVICE_NOT_READY;
	}

	/* In-flight IOCTL counting: the unload path calls IoReleaseRemoveLockAndWait, ensuring the extension
	 * is not freed while someone is still using it. If acquisition fails (already in remove state), fail explicitly. */
	if (ext->ctrl_remove_init != 0 &&
	    !NT_SUCCESS(IoAcquireRemoveLock(&ext->ctrl_remove_lock, irp))) {
		irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_DEVICE_NOT_READY;
	}

	switch (sp->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_IWAN_SESSION_OPEN:
		/* Request and reply share the same METHOD_BUFFERED buffer: interpret it as a request first,
		 * then overwrite it with the reply once the session is established. targets come right after the struct. */
		if (buf == NULL || in_len < sizeof(IWAN_WIN_SESSION_OPEN) ||
		    out_len < sizeof(IWAN_WIN_SESSION_INFO)) {
			st = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		/* Attach the data plane before establishing the session: set valid only after attachment, so the first packet
		 * is not missed. On the WFP plane what is attached is the filter (start is idempotent); the NDIS plane
		 * has no 'filter' to attach, so it selects the carrier after session setup instead (next block). */
#ifndef IWAN_WIN_PLANE_MP
		st = iwan_win_wfp_start(ext);
		if (!NT_SUCCESS(st))
			break;
#endif
		st = iwan_win_session_open(ext,
					   (const IWAN_WIN_SESSION_OPEN *)buf, in_len);
		if (!NT_SUCCESS(st)) {
#ifndef IWAN_WIN_PLANE_MP
			/* Attached but session setup failed: detach only when no session is actually running.
			 * Detaching while an old session still exists would cut the tunnel in use. */
			if (!ext->sess.valid)
				iwan_win_wfp_stop(ext);
#endif
			break;
		}
#ifdef IWAN_WIN_PLANE_MP
		/* Select the carrier: one session uses only one NIC. If none can be selected, fail the whole OPEN
		 * -- without a carrier there is no outer, and silently continuing equals creating a session
		 * that cannot send packets (fail-closed). */
		st = iwan_win_mp_select_carrier(ext);
		if (!NT_SUCCESS(st)) {
			iwan_win_session_close(ext);
			break;
		}
#endif
		iwan_win_session_info(ext, (IWAN_WIN_SESSION_INFO *)buf);
#ifdef IWAN_WIN_PLANE_MP
		/* ARP diagnostic counters are persisted here: the data plane runs at DISPATCH and cannot touch Zw*. */
		iwan_win_mp_trace_arp(ext);
#endif
		info = sizeof(IWAN_WIN_SESSION_INFO);
		break;

	case IOCTL_IWAN_SESSION_CLOSE:
		st = iwan_win_session_close(ext);
		/* Session is torn down, the data plane has no reason to exist: the WFP plane detaches the filter (returns
		 * the system to 'driver installed but no tunnel running'), the NDIS plane releases the carrier. */
#ifdef IWAN_WIN_PLANE_MP
		iwan_win_mp_release_carrier(ext);
#else
		iwan_win_wfp_stop(ext);
#endif
		break;

	case IOCTL_IWAN_SESSION_GET:
		if (buf == NULL || out_len < sizeof(IWAN_WIN_SESSION_INFO)) {
			st = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		/* Validity and snapshot must be taken under the same lock: otherwise CLOSE can slip in between
		 * and we return an all-zero 'session info' with SUCCESS. */
		KeWaitForSingleObject(&ext->ctrl_mutex, Executive, KernelMode, FALSE, NULL);
		st = ext->sess.valid ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_STATE;
		if (NT_SUCCESS(st)) {
			iwan_win_session_info(ext, (IWAN_WIN_SESSION_INFO *)buf);
#ifdef IWAN_WIN_PLANE_MP
			iwan_win_mp_trace_arp(ext);
#endif
			info = sizeof(IWAN_WIN_SESSION_INFO);
		}
		KeReleaseMutex(&ext->ctrl_mutex, FALSE);
		break;

	case IOCTL_IWAN_SHM_QUERY:
		if (buf == NULL || out_len < sizeof(IWAN_WIN_SESSION_INFO)) {
			st = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		st = iwan_win_session_query_shm(ext,
						(IWAN_WIN_SESSION_INFO *)buf);
		if (NT_SUCCESS(st))
			info = sizeof(IWAN_WIN_SESSION_INFO);
		break;

	default:
		break;
	}

	if (ext->ctrl_remove_init != 0)
		IoReleaseRemoveLock(&ext->ctrl_remove_lock, irp);
	irp->IoStatus.Status = st;
	irp->IoStatus.Information = info;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return st;
}

static _Function_class_(DRIVER_UNLOAD)
VOID
iwan_win_unload(_In_ PDRIVER_OBJECT driver)
{
	PDEVICE_OBJECT devobj = driver->DeviceObject;
	UNICODE_STRING link;

	if (devobj != NULL) {
		IWAN_WIN_DEVICE_EXTENSION *ext = IWAN_DEVEXT(devobj);

		/* Enter remove state first, then wait for in-flight IOCTLs to finish, and only then tear down the data plane / delete the device.
		 * The guard ensures the two unload paths (DriverUnload and NDIS UnloadHandler)
		 * wait only once. */
		if (ext->ctrl_remove_init != 0 &&
		    InterlockedExchange(&ext->ctrl_remove_waited, 1) == 0)
			IoReleaseRemoveLockAndWait(&ext->ctrl_remove_lock, ext);

#ifdef IWAN_WIN_PLANE_MP
		iwan_win_mp_fini(ext);		/* deregister miniport and protocol edge first */
#else
		iwan_win_wfp_fini(ext);		/* stop the data plane first */
#endif
		iwan_win_session_teardown(ext);	/* then drain and free session state */
		iwan_win_ctrl_fini(ext);

		RtlInitUnicodeString(&link, IWAN_DRV_DOS_NAME);
		IoDeleteSymbolicLink(&link);
		IoDeleteDevice(devobj);
	}
#ifndef IWAN_WIN_PLANE_MP
	if (g_engine != NULL) {
		FwpmEngineClose(g_engine);
		g_engine = NULL;
	}
#endif
}

/*
 * A non-PnP device has no real device class, but IoCreateDeviceSecure / NdisRegisterDeviceEx
 * still need a GUID. The symbol GUID_DEVCLASS_UNKNOWN does not exist in the kernel headers (the first real
 * compile reports C2065), so use a project-fixed GUID -- it is only a marker inside the device object.
 * Both planes share the same GUID, so it is not static: the NDIS plane uses it in mp.c.
 */
const GUID iwan_win_devclass_guid = {
	0x6d1a9b21, 0x7c4e, 0x4e2b,
	{ 0x9f, 0x31, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x61 }
};

/*
 * The two planes have different DriverEntry shapes, and that is not a style issue:
 *
 *  - WFP plane: create the control device first (IoCreateDeviceSecure); the extension is the device extension,
 *    then register the filter (it can be registered without a device, but then the control plane has nowhere to keep state).
 *  - NDIS plane: the control device must be created by NdisRegisterDeviceEx **after** registration --
 *    NdisMRegisterMiniportDriver requires DriverObject to be clean at call time; on the guest,
 *    having attached its own device object returns NDIS_STATUS_BAD_CHARACTERISTICS
 *    (0xC0010005). The extension therefore must be allocated separately, and it outlives the control device: the miniport
 *    context is needed by MiniportInitializeEx, when the control device may not exist yet.
 */
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT driver, _In_ PUNICODE_STRING registry_path)
{
	IWAN_WIN_DEVICE_EXTENSION *ext;
	NTSTATUS st;

	/* Static analysis reports two C6014s in this function (ext / devobj 'leak'): both are driver
	 * lifetime assets -- ext follows the unload path (UnloadHandler / iwan_win_unload),
	 * devobj follows IoDeleteDevice; neither is freed when DriverEntry returns, and both
	 * failure paths roll back on their own. After checking item by item these are false positives; the suppression is at each allocation site
	 * (see the #pragma below). */

#ifdef IWAN_WIN_PLANE_MP
	/* C6014 false positive (allocation site ext = IWAN_ALLOC): ext is a driver lifetime asset,
	 * freed only on the unload path (UnloadHandler / iwan_win_unload), and rolled back in the fail label too.
	 * The analyzer only sees 'allocated, not freed before DriverEntry returns success'. */
#pragma warning(suppress: 6014)
	ext = (IWAN_WIN_DEVICE_EXTENSION *)IWAN_ALLOC(sizeof(*ext),
						      IWAN_TAG_SESS);
	if (ext == NULL) {
		MP_TRACE(3, STATUS_INSUFFICIENT_RESOURCES);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(ext, sizeof(*ext));
	iwan_win_ctrl_init(ext);

	/* DriverUnload is still set: unload goes through NDIS UnloadHandler, and that path clears
	 * driver->DeviceObject, so this function becomes a no-op (double safety). */
	driver->DriverUnload = iwan_win_unload;

	st = iwan_win_mp_init(driver, ext, registry_path);
	if (!NT_SUCCESS(st))
		goto fail;

	st = iwan_win_mp_open_control(ext);
	if (!NT_SUCCESS(st)) {
		/* Control device cannot be created = user mode cannot open it = useless to install, but **never roll back here**:
		 * the miniport (and maybe the protocol edge) is already registered; going back to deregister and then failing
		 * DriverEntry is exactly the mechanism of that incident where the whole machine would not boot -- with a half-registered
		 * state NDIS thinks the driver is still there, the unload path never completes, and the reboot hangs in boot.
		 * Here just leave it in the T5 key (iwan_win_mp_open_control already wrote it) and return success as usual:
		 * the adapter appears and IOCTLs fail with STATUS_DEVICE_NOT_READY,
		 * the reason is visible at a glance, and unload and reinstall both stay clean. */
		DbgPrint("iwan-win: control device not ready (see T5), load continues\n");
	}

	MP_TRACE(4, STATUS_SUCCESS);
	DbgPrint("iwan-win: loaded, %ws\n", IWAN_DRV_VERSION_STR);
	return STATUS_SUCCESS;

fail:
	driver->DriverUnload = NULL;
	iwan_win_ctrl_fini(ext);
	ExFreePoolWithTag(ext, IWAN_TAG_SESS);
	MP_TRACE(3, st);
	return st;
#else
	UNICODE_STRING dev_name, dos_name, sddl;
	PDEVICE_OBJECT devobj = NULL;

	/* Default SDDL: only System and Administrators can open the device. The user-mode client
	 * needs administrator rights (corresponding to root on the Linux side), consistent with Linux.
	 *
	 * Note the 7th parameter of IoCreateDeviceSecure is PCUNICODE_STRING, not PCWSTR:
	 * so neither can a literal be passed in directly (C4133), nor can the result of the wdmsec.h
	 * SDDL_DEVOBJ_* macros be fed to RtlInitUnicodeString again (that macro is itself an
	 * UNICODE_STRING, C4024/C2440). Build one ourselves, the least ambiguous. */
	RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
	RtlInitUnicodeString(&dev_name, IWAN_DRV_DEV_NAME);
	/* C6014 false positive (devobj): the device object is a driver lifetime asset, freed with
	 * IoDeleteDevice (unload and the two failure paths). The defect is reported on the last line of this call
	 * (the &devobj line); a single-line suppress cannot attach there, so disable it for this statement only. */
#pragma warning(push)
#pragma warning(disable: 6014)
	st = IoCreateDeviceSecure(driver, sizeof(IWAN_WIN_DEVICE_EXTENSION),
				  &dev_name, IWAN_WIN_DEVICE_TYPE,
				  FILE_DEVICE_SECURE_OPEN, FALSE, &sddl,
				  &iwan_win_devclass_guid, &devobj);
#pragma warning(pop)
	if (!NT_SUCCESS(st)) {
		MP_TRACE(1, st);
		return st;
	}

	RtlInitUnicodeString(&dos_name, IWAN_DRV_DOS_NAME);
	st = IoCreateSymbolicLink(&dos_name, &dev_name);
	if (!NT_SUCCESS(st)) {
		MP_TRACE(2, st);
		IoDeleteDevice(devobj);
		return st;
	}

	ext = IWAN_DEVEXT(devobj);
	RtlZeroMemory(ext, sizeof(*ext));
	iwan_win_ctrl_init(ext);

	driver->MajorFunction[IRP_MJ_CREATE] = iwan_win_dispatch_create;
	driver->MajorFunction[IRP_MJ_CLOSE] = iwan_win_dispatch_create;
	driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = iwan_win_dispatch_ioctl;
	driver->DriverUnload = iwan_win_unload;

	/* The WFP plane does not use the registry path (the NDIS plane hands it to
	 * NdisMRegisterMiniportDriver). Not writing this line is a hard C4100 error under /W4 /WX. */
	UNREFERENCED_PARAMETER(registry_path);
	st = iwan_win_wfp_init(devobj, ext);
	if (!NT_SUCCESS(st)) {
		MP_TRACE(3, st);
		driver->DriverUnload = NULL;
		IoDeleteSymbolicLink(&dos_name);
		IoDeleteDevice(devobj);
		return st;
	}

	devobj->Flags &= ~DO_DEVICE_INITIALIZING;

	MP_TRACE(4, STATUS_SUCCESS);
	DbgPrint("iwan-win: loaded, %ws\n", IWAN_DRV_VERSION_STR);
	return STATUS_SUCCESS;
#endif
}
