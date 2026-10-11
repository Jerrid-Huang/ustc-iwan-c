/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan_win_drv.c — 驱动入口、设备对象与 IOCTL 分发。
 *
 * 对应 Linux 侧的：模块 init/exit + misc 设备注册 + genetlink 控制面入口。
 * 这里只有控制面：报文路径全在 iwan_win_wfp.c 的 callout 里，且不排队、
 * 不起线程、不用定时器 —— 与 Linux 模块"内核只负责数据传输"的边界一致。
 */
#include "iwan_win.h"

/* WFP 管理会话（fwpmk.h）：只在 init/fini 里用，进程上下文、PASSIVE_LEVEL */
static HANDLE g_engine = NULL;

static NTSTATUS
iwan_win_dispatch_create(_In_ PDEVICE_OBJECT devobj, _Inout_ PIRP irp)
{
	UNREFERENCED_PARAMETER(devobj);
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

static NTSTATUS
iwan_win_dispatch_ioctl(_In_ PDEVICE_OBJECT devobj, _Inout_ PIRP irp)
{
	PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
	IWAN_WIN_DEVICE_EXTENSION *ext = IWAN_DEVEXT(devobj);
	PVOID buf = irp->AssociatedIrp.SystemBuffer;
	ULONG in_len = sp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG out_len = sp->Parameters.DeviceIoControl.OutputBufferLength;
	NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
	ULONG info = 0;

	switch (sp->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_IWAN_SESSION_OPEN:
		/* 请求与回复共用同一块 METHOD_BUFFERED 缓冲：先按请求解释，
		 * 会话建立成功后再覆盖成回复。targets 紧跟结构体之后。 */
		if (buf == NULL || in_len < sizeof(IWAN_WIN_SESSION_OPEN) ||
		    out_len < sizeof(IWAN_WIN_SESSION_INFO)) {
			st = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		st = iwan_win_session_open(ext,
					   (const IWAN_WIN_SESSION_OPEN *)buf, in_len);
		if (NT_SUCCESS(st)) {
			iwan_win_session_info(ext, (IWAN_WIN_SESSION_INFO *)buf);
			info = sizeof(IWAN_WIN_SESSION_INFO);
		}
		break;

	case IOCTL_IWAN_SESSION_CLOSE:
		st = iwan_win_session_close(ext);
		break;

	case IOCTL_IWAN_SESSION_GET:
		if (buf == NULL || out_len < sizeof(IWAN_WIN_SESSION_INFO)) {
			st = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		st = ext->sess.valid ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_STATE;
		if (NT_SUCCESS(st)) {
			iwan_win_session_info(ext, (IWAN_WIN_SESSION_INFO *)buf);
			info = sizeof(IWAN_WIN_SESSION_INFO);
		}
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

	irp->IoStatus.Status = st;
	irp->IoStatus.Information = info;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return st;
}

static VOID
iwan_win_unload(_In_ PDRIVER_OBJECT driver)
{
	PDEVICE_OBJECT devobj = driver->DeviceObject;
	UNICODE_STRING link;

	if (devobj != NULL) {
		IWAN_WIN_DEVICE_EXTENSION *ext = IWAN_DEVEXT(devobj);

		iwan_win_wfp_fini(ext);		/* 先停数据面 */
		iwan_win_session_teardown(ext);	/* 再排空并释放会话状态 */
		iwan_win_ctrl_fini(ext);

		RtlInitUnicodeString(&link, IWAN_WIN_DOS_NAME);
		IoDeleteSymbolicLink(&link);
		IoDeleteDevice(devobj);
	}
	if (g_engine != NULL) {
		FwpmEngineClose(g_engine);
		g_engine = NULL;
	}
}

/*
 * 非 PnP 设备没有真实设备类，但 IoCreateDeviceSecure 仍要一个 GUID。
 * GUID_DEVCLASS_UNKNOWN 这个符号在内核头里并不存在（第一次真编译报 C2065），
 * 所以用一个本项目固定的 GUID —— 它只在设备对象里做标记用。
 */
static const GUID iwan_win_devclass_guid = {
	0x6d1a9b21, 0x7c4e, 0x4e2b,
	{ 0x9f, 0x31, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x61 }
};

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT driver, _In_ PUNICODE_STRING registry_path)
{
	UNICODE_STRING dev_name, dos_name, sddl;
	PDEVICE_OBJECT devobj = NULL;
	IWAN_WIN_DEVICE_EXTENSION *ext;
	NTSTATUS st;

	UNREFERENCED_PARAMETER(registry_path);

	/* 默认 SDDL：只有 System 与 Administrators 能打开设备。用户态客户端
	 * 需要管理员权限（对应 Linux 侧需要 root），这与 Linux 一致。
	 *
	 * 注意 IoCreateDeviceSecure 的第 7 个参数是 PCUNICODE_STRING，不是 PCWSTR：
	 * 所以既不能直接把字面量递进去（C4133），也不能把 wdmsec.h 里的
	 * SDDL_DEVOBJ_* 宏结果再喂给 RtlInitUnicodeString（那个宏本身就是
	 * UNICODE_STRING，C4024/C2440）。自己建一个最不含糊。 */
	RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
	RtlInitUnicodeString(&dev_name, IWAN_WIN_DEVICE_NAME);
	st = IoCreateDeviceSecure(driver, sizeof(IWAN_WIN_DEVICE_EXTENSION),
				  &dev_name, IWAN_WIN_DEVICE_TYPE,
				  FILE_DEVICE_SECURE_OPEN, FALSE, &sddl,
				  &iwan_win_devclass_guid, &devobj);
	if (!NT_SUCCESS(st))
		return st;

	RtlInitUnicodeString(&dos_name, IWAN_WIN_DOS_NAME);
	st = IoCreateSymbolicLink(&dos_name, &dev_name);
	if (!NT_SUCCESS(st)) {
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

	/* WFP：注册 callout 与过滤器。没有它设备没有意义，所以失败就整体回滚。 */
	st = iwan_win_wfp_init(devobj, ext);
	if (!NT_SUCCESS(st)) {
		driver->DriverUnload = NULL;
		IoDeleteSymbolicLink(&dos_name);
		IoDeleteDevice(devobj);
		return st;
	}

	devobj->Flags &= ~DO_DEVICE_INITIALIZING;

	DbgPrint("iwan-win: loaded, %ws\n", IWAN_WIN_DRV_VERSION_STR);
	return STATUS_SUCCESS;
}
