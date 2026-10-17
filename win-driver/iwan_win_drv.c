/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_drv.c — 驱动入口、设备对象与 IOCTL 分发。
 *
 * 对应 Linux 侧的：模块 init/exit + misc 设备注册 + genetlink 控制面入口。
 * 这里只有控制面：报文路径全在数据面文件里（WFP 平面 iwan_win_wfp.c 的
 * callout / NDIS 平面 iwan_win_mp.c + iwan_win_proto.c），且不排队、不起
 * 线程、不用定时器 —— 与 Linux 模块"内核只负责数据传输"的边界一致。
 *
 * 本文件被两个平面共用，靠 IWAN_WIN_PLANE_MP 分叉。三处不同：
 *   ① 设备名：WFP 平面 \Device\iwan，NDIS 平面 \Device\iwanmp（两个平面
 *      可以同时装在一台机器上，用户态按 --data-plane 选名字打开）；
 *   ② 数据面的"装上/摘掉"钩子：WFP 是 callout 过滤器，NDIS 是选/放承载；
 *   ③ 卸载：WFP 要关 BFE 引擎，NDIS 只要注销小型端口与协议边。
 */
#include "iwan_win.h"

/* 加载期失败的阶段追踪：NDIS 平面把阶段号写进服务键，WFP 平面编译成空操作。
 * 驱动起不来时用户态没有任何通道（控制设备都没建），这是唯一能一眼看到的
 * 现场 —— 见 iwan_win_mp_trace 的说明。 */
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
/* WFP 管理会话（fwpmk.h）：只在 init/fini 里用，进程上下文、PASSIVE_LEVEL */
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
	/* NDIS 平面的 IWAN_DEVEXT 忽略设备对象（控制设备不带扩展，扩展是
	 * 单例），所以这里要显式声明没用到它，否则 /W4 /WX 下是 C4100。 */
	UNREFERENCED_PARAMETER(devobj);
#endif
	PVOID buf = irp->AssociatedIrp.SystemBuffer;
	ULONG in_len = sp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG out_len = sp->Parameters.DeviceIoControl.OutputBufferLength;
	NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
	ULONG info = 0;

	/* 没有扩展 = 数据面还没注册或已经注销。NDIS 平面的扩展由 DriverEntry
	 * 分配，正常不会为空；这里按"设备还没就绪"处理，而不是解引用空指针
	 * —— 控制设备在适配器 Halt 之后仍然存在，那条路上什么都不该保证。 */
	if (ext == NULL) {
		irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_DEVICE_NOT_READY;
	}

	/* 在途 IOCTL 计数：卸载路径会 IoReleaseRemoveLockAndWait，保证扩展
	 * 不会在还有人用它的时候被释放。取不到（已进入移除态）就明确失败。 */
	if (ext->ctrl_remove_init != 0 &&
	    !NT_SUCCESS(IoAcquireRemoveLock(&ext->ctrl_remove_lock, irp))) {
		irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_DEVICE_NOT_READY;
	}

	switch (sp->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_IWAN_SESSION_OPEN:
		/* 请求与回复共用同一块 METHOD_BUFFERED 缓冲：先按请求解释，
		 * 会话建立成功后再覆盖成回复。targets 紧跟结构体之后。 */
		if (buf == NULL || in_len < sizeof(IWAN_WIN_SESSION_OPEN) ||
		    out_len < sizeof(IWAN_WIN_SESSION_INFO)) {
			st = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		/* 会话建立之前先把数据面装上：装上之后才置 valid，第一个报文
		 * 就不会漏。WFP 平面装上的是过滤器（start 幂等）；NDIS 平面
		 * 没有"过滤器"可装，改为会话建立之后选定承载（下一段）。 */
#ifndef IWAN_WIN_PLANE_MP
		st = iwan_win_wfp_start(ext);
		if (!NT_SUCCESS(st))
			break;
#endif
		st = iwan_win_session_open(ext,
					   (const IWAN_WIN_SESSION_OPEN *)buf, in_len);
		if (!NT_SUCCESS(st)) {
#ifndef IWAN_WIN_PLANE_MP
			/* 装好了却没建成会话：只有在确实没有会话在跑时才摘掉。
			 * 旧会话还在就摘，等于把正在用的隧道打断。 */
			if (!ext->sess.valid)
				iwan_win_wfp_stop(ext);
#endif
			break;
		}
#ifdef IWAN_WIN_PLANE_MP
		/* 选定承载：一条会话只走一张网卡。选不到就让整个 OPEN 失败
		 * —— 没有承载就没有外层，静默继续等于建了一条发不出包的
		 * 会话（fail-closed）。 */
		st = iwan_win_mp_select_carrier(ext);
		if (!NT_SUCCESS(st)) {
			iwan_win_session_close(ext);
			break;
		}
#endif
		iwan_win_session_info(ext, (IWAN_WIN_SESSION_INFO *)buf);
		info = sizeof(IWAN_WIN_SESSION_INFO);
		break;

	case IOCTL_IWAN_SESSION_CLOSE:
		st = iwan_win_session_close(ext);
		/* 会话已经拆完，数据面没有存在理由：WFP 平面摘掉过滤器（让
		 * 系统回到"装了驱动但没跑隧道"的状态），NDIS 平面放掉承载。 */
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
		/* 有效性与快照必须在同一把锁里取：否则 CLOSE 可以插在中间，
		 * 让我们以 SUCCESS 返回一份全零的"会话信息"。 */
		KeWaitForSingleObject(&ext->ctrl_mutex, Executive, KernelMode, FALSE, NULL);
		st = ext->sess.valid ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_STATE;
		if (NT_SUCCESS(st)) {
			iwan_win_session_info(ext, (IWAN_WIN_SESSION_INFO *)buf);
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

		/* 先进移除态、再等在途 IOCTL 做完，然后才拆数据面/删设备。
		 * 守卫保证两条卸载路径（DriverUnload 与 NDIS UnloadHandler）
		 * 只会等待一次。 */
		if (ext->ctrl_remove_init != 0 &&
		    InterlockedExchange(&ext->ctrl_remove_waited, 1) == 0)
			IoReleaseRemoveLockAndWait(&ext->ctrl_remove_lock, ext);

#ifdef IWAN_WIN_PLANE_MP
		iwan_win_mp_fini(ext);		/* 先注销小型端口与协议边 */
#else
		iwan_win_wfp_fini(ext);		/* 先停数据面 */
#endif
		iwan_win_session_teardown(ext);	/* 再排空并释放会话状态 */
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
 * 非 PnP 设备没有真实设备类，但 IoCreateDeviceSecure / NdisRegisterDeviceEx
 * 仍要一个 GUID。GUID_DEVCLASS_UNKNOWN 这个符号在内核头里并不存在（第一次
 * 真编译报 C2065），所以用一个本项目固定的 GUID —— 它只在设备对象里做标记用。
 * 两个平面共用同一个 GUID，所以它不是 static：NDIS 平面在 mp.c 里用。
 */
const GUID iwan_win_devclass_guid = {
	0x6d1a9b21, 0x7c4e, 0x4e2b,
	{ 0x9f, 0x31, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x61 }
};

/*
 * 两个平面的 DriverEntry 形状不同，不是风格问题：
 *
 *  - WFP 平面：先建控制设备（IoCreateDeviceSecure），扩展就是设备扩展，
 *    再注册过滤器（不带设备也能注册，但控制面就没地方放状态了）。
 *  - NDIS 平面：控制设备必须由 NdisRegisterDeviceEx 在注册**之后**建 ——
 *    NdisMRegisterMiniportDriver 要求调用时 DriverObject 是干净的，客体
 *    实测已挂自己的设备对象就回 NDIS_STATUS_BAD_CHARACTERISTICS
 *    (0xC0010005)。扩展因此要自己分配，而且它比控制设备活得久：小型端口
 *    上下文在 MiniportInitializeEx 就要用，控制设备那时可能还没建。
 */
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT driver, _In_ PUNICODE_STRING registry_path)
{
	IWAN_WIN_DEVICE_EXTENSION *ext;
	NTSTATUS st;

#ifdef IWAN_WIN_PLANE_MP
	ext = (IWAN_WIN_DEVICE_EXTENSION *)IWAN_ALLOC(sizeof(*ext),
						      IWAN_TAG_SESS);
	if (ext == NULL) {
		MP_TRACE(3, STATUS_INSUFFICIENT_RESOURCES);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(ext, sizeof(*ext));
	iwan_win_ctrl_init(ext);

	/* DriverUnload 仍然设置：卸载走 NDIS 的 UnloadHandler，那条路会把
	 * driver->DeviceObject 置空，于是这个函数变成空操作（双保险）。 */
	driver->DriverUnload = iwan_win_unload;

	st = iwan_win_mp_init(driver, ext, registry_path);
	if (!NT_SUCCESS(st))
		goto fail;

	st = iwan_win_mp_open_control(ext);
	if (!NT_SUCCESS(st)) {
		/* 控制设备建不出来 = 用户态打不开 = 装了也没用，但**绝不能在这里
		 * 回滚**：小型端口（也许还有协议边）已经注册成功，回头去注销再让
		 * DriverEntry 失败，正是整机无法启动那次事故的机理 —— 半个注册
		 * 状态下 NDIS 认为驱动还在，卸载路径永远等不到，重启就卡在引导。
		 * 这里只让它留在 T5 键里（iwan_win_mp_open_control 已写），照常
		 * 返回成功：适配器会出现、IOCTL 以 STATUS_DEVICE_NOT_READY 失败，
		 * 原因一眼可见，卸载与重装都还是干净的。 */
		DbgPrint("iwan-win: 控制设备未就绪（见 T5），装载继续\n");
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

	/* 默认 SDDL：只有 System 与 Administrators 能打开设备。用户态客户端
	 * 需要管理员权限（对应 Linux 侧需要 root），这与 Linux 一致。
	 *
	 * 注意 IoCreateDeviceSecure 的第 7 个参数是 PCUNICODE_STRING，不是 PCWSTR：
	 * 所以既不能直接把字面量递进去（C4133），也不能把 wdmsec.h 里的
	 * SDDL_DEVOBJ_* 宏结果再喂给 RtlInitUnicodeString（那个宏本身就是
	 * UNICODE_STRING，C4024/C2440）。自己建一个最不含糊。 */
	RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
	RtlInitUnicodeString(&dev_name, IWAN_DRV_DEV_NAME);
	st = IoCreateDeviceSecure(driver, sizeof(IWAN_WIN_DEVICE_EXTENSION),
				  &dev_name, IWAN_WIN_DEVICE_TYPE,
				  FILE_DEVICE_SECURE_OPEN, FALSE, &sddl,
				  &iwan_win_devclass_guid, &devobj);
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

	/* WFP 平面用不到注册表路径（NDIS 平面要把它转交给
	 * NdisMRegisterMiniportDriver）。不写这一行在 /W4 /WX 下是 C4100 硬错误。 */
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
