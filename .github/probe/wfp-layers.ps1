# 枚举 WFP 层：对 id 0..150 调 FwpmLayerGetById0，打印 id -> 层名与层键。
# 目的：核对驱动里用 FWPS_LAYER_* 枚举值当 FwpmLayerGetById0 的 id 是否真的
# 命中"Outbound IP Packet v4 / Inbound Transport v4"这些层。
# 这个脚本不建会话、不装过滤器，所以不会把网络打死。
param([int]$Max = 150, [string]$Out = 'C:\iwan\wfp-layers.txt')
$ErrorActionPreference = 'Continue'

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class Wfp {
    [StructLayout(LayoutKind.Sequential)]
    public struct GUID { public uint D1; public ushort D2; public ushort D3;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=8)] public byte[] D4; }
    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_DISPLAY_DATA0 { public IntPtr name; public IntPtr description; }
    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_LAYER0 {
        public GUID layerKey; public GUID displayData_key_unused;
        public FWPM_DISPLAY_DATA0 displayData; public uint flags;
        public uint numFields; public IntPtr field; public GUID defaultSubLayerKey;
        public ushort layerId; }
    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_SESSION0 { public GUID sessionKey; public FWPM_DISPLAY_DATA0 displayData;
        public uint flags; public uint txnWaitTimeoutInMSec; public uint processId;
        public IntPtr sid; public IntPtr username; public int kernelMode; }
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmEngineOpen0(
        [MarshalAs(UnmanagedType.LPWStr)] string serverName, uint authnService,
        IntPtr authIdentity, ref FWPM_SESSION0 session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmLayerGetById0(
        IntPtr engine, ushort id, out IntPtr layer);
    [DllImport("fwpuclnt.dll")] public static extern void FwpmFreeMemory0(ref IntPtr p);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

$sess = New-Object Wfp+FWPM_SESSION0
$sess.flags = 0
$engine = [IntPtr]::Zero
$rc = [Wfp]::FwpmEngineOpen0($null, 10, [IntPtr]::Zero, [ref]$sess, [ref]$engine)   # 10 = RPC_C_AUTHN_WINNT
if ($rc -ne 0) { Write-Host "FwpmEngineOpen0 失败 rc=$rc"; exit 1 }
Write-Host "引擎已打开"

$lines = New-Object System.Collections.Generic.List[string]
for ($id = 0; $id -le $Max; $id++) {
    $p = [IntPtr]::Zero
    $rc = [Wfp]::FwpmLayerGetById0($engine, [uint16]$id, [ref]$p)
    if ($rc -ne 0 -or $p -eq [IntPtr]::Zero) { continue }
    $lyr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($p, [type]([Wfp+FWPM_LAYER0]))
    $name = if ($lyr.displayData.name -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::PtrToStringUni($lyr.displayData.name) } else { '?' }
    $d4 = ($lyr.layerKey.D4 | ForEach-Object { $_.ToString('x2') }) -join ''
    $line = "id={0,-4} layerId={1,-4} {2}  key={3:x8}-{4:x4}-{5:x4}-{6}" -f `
        $id, $lyr.layerId, $name, $lyr.layerKey.D1, $lyr.layerKey.D2, $lyr.layerKey.D3, $d4
    $lines.Add($line)
    Write-Host $line
    [Wfp]::FwpmFreeMemory0([ref]$p)
}
[Wfp]::FwpmEngineClose0($engine) | Out-Null
$lines | Set-Content -Path $Out -Encoding UTF8
Write-Host "`n共 $($lines.Count) 层，已写入 $Out"
