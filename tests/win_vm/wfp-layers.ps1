# 在客体上枚举 WFP 层：拿到权威的 id -> 层名 -> 层键，并核对驱动用的
# FWPS_LAYER_* 枚举值（out4=4 out6=6 in-transport4=12 in-transport6=14）
# 当 FWPM 的层 ID 用时到底指向哪一层。不建会话、不装过滤器，不会打死网络。
param([string]$Out = 'C:\iwan\wfp-layers.txt')
$ErrorActionPreference = 'Continue'

$cs = @'
using System;
using System.Runtime.InteropServices;
public static class Wfp {
    [StructLayout(LayoutKind.Sequential)]
    public struct GUID { public uint D1; public ushort D2; public ushort D3;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=8)] public byte[] D4; }
    [StructLayout(LayoutKind.Sequential)]
    public struct DD { public IntPtr name; public IntPtr description; }
    [StructLayout(LayoutKind.Sequential)]
    public struct LAYER { public GUID key; public DD dd; public uint flags;
        public uint numFields; public IntPtr field; public GUID sublayer; public ushort layerId; }
    [StructLayout(LayoutKind.Sequential)]
    public struct SESS { public GUID key; public DD dd; public uint flags; public uint tmo;
        public uint pid; public IntPtr sid; public IntPtr user; public int kernel; }
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmEngineOpen0(
        [MarshalAs(UnmanagedType.LPWStr)] string srv, uint auth, IntPtr id, ref SESS s, out IntPtr e);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmEngineOpen0(
        [MarshalAs(UnmanagedType.LPWStr)] string srv, uint auth, IntPtr id, IntPtr s, out IntPtr e);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmEngineClose0(IntPtr e);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmLayerGetById0(IntPtr e, ushort id, out IntPtr l);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmLayerCreateEnumHandle0(IntPtr e, IntPtr t, out IntPtr h);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmLayerEnum0(IntPtr e, IntPtr h, out IntPtr en, out uint n);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmLayerDestroyEnumHandle0(IntPtr e, IntPtr h);
    [DllImport("fwpuclnt.dll")] public static extern void FwpmFreeMemory0(ref IntPtr p);
}
'@
Add-Type -TypeDefinition $cs -ErrorAction Stop

function Key-Of($g) {
    $d4 = ($g.D4 | ForEach-Object { $_.ToString('x2') }) -join ''
    '0x{0:X8}, 0x{1:X4}, 0x{2:X4}, {{0x{3},0x{4},0x{5},0x{6},0x{7},0x{8},0x{9},0x{10}}}' -f `
        $g.D1, $g.D2, $g.D3, $g.D4[0], $g.D4[1], $g.D4[2], $g.D4[3], $g.D4[4], $g.D4[5], $g.D4[6], $g.D4[7]
}

$engine = [IntPtr]::Zero
foreach ($mode in @('session-null', 'session-flags0')) {
    foreach ($auth in @([uint32]4294967295, [uint32]10, [uint32]0)) {
        if ($mode -eq 'session-null') {
            $rc = [Wfp]::FwpmEngineOpen0($null, $auth, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$engine)
        } else {
            $s = New-Object Wfp+SESS; $s.flags = 0
            $rc = [Wfp]::FwpmEngineOpen0($null, $auth, [IntPtr]::Zero, [ref]$s, [ref]$engine)
        }
        Write-Host ("engineOpen {0} auth={1} rc={2}" -f $mode, $auth, $rc)
        if ($rc -eq 0) { break }
    }
    if ($rc -eq 0) { break }
}
if ($engine -eq [IntPtr]::Zero) { Write-Host '引擎打不开'; exit 1 }

$lines = New-Object System.Collections.Generic.List[string]
$h = [IntPtr]::Zero
if ([Wfp]::FwpmLayerCreateEnumHandle0($engine, [IntPtr]::Zero, [ref]$h) -eq 0) {
    $en = [IntPtr]::Zero; $n = 0
    if ([Wfp]::FwpmLayerEnum0($engine, $h, [ref]$en, [ref]$n) -eq 0) {
        $size = [System.Runtime.InteropServices.Marshal]::SizeOf([type]([Wfp+LAYER]))
        $map = @{}
        for ($i = 0; $i -lt $n; $i++) {
            $p = [IntPtr]::Add($en, $i * $size)
            $lyr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($p, [type]([Wfp+LAYER]))
            $name = if ($lyr.dd.name -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::PtrToStringUni($lyr.dd.name) } else { '?' }
            $map[[int]$lyr.layerId] = $name
            $lines.Add(("layerId={0,-4} {1,-44} {2}" -f $lyr.layerId, $name, (Key-Of $lyr.key)))
        }
        [Wfp]::FwpmFreeMemory0([ref]$en)
        Write-Host "`n=== 全部层（$n 个）==="
        $lines | ForEach-Object { Write-Host $_ }
        Write-Host "`n=== 驱动用的四个 id ==="
        foreach ($id in @(4, 6, 12, 14)) {
            $nm = if ($map.ContainsKey($id)) { $map[$id] } else { '<没有这个 id>' }
            Write-Host ("  id={0,-3} -> {1}" -f $id, $nm)
        }
    }
    [Wfp]::FwpmLayerDestroyEnumHandle0($engine, $h) | Out-Null
}
[Wfp]::FwpmEngineClose0($engine) | Out-Null
$lines | Set-Content -Path $Out -Encoding UTF8
Write-Host "已写入 $Out"
