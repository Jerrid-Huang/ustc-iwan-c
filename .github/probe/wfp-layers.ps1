# 在 CI 上核对 WFP 的层 ID 空间：FWPS_LAYER_* 枚举值（out4=4 out6=6 in-transport4=12
# in-transport6=14）能不能当 FWPM 的层 ID 用，以及它们各自指向哪个层。
# 顺带用 FwpmLayerEnum0 把全部内建层（id/名字/层键）打出来，作为权威对照。
$ErrorActionPreference = 'Continue'
Get-Service BFE | Select-Object Name, Status, StartType | Format-Table | Out-String -Width 120 | Write-Host

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
    public struct LAYER { public GUID key; public GUID reserved; public DD dd; public uint flags;
        public uint numFields; public IntPtr field; public GUID sublayer; public ushort layerId;
        public ushort reserved2; public ulong reserved3; }
    [StructLayout(LayoutKind.Sequential)]
    public struct SESS { public GUID key; public DD dd; public uint flags; public uint tmo;
        public uint pid; public IntPtr sid; public IntPtr user; public int kernel; }
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmEngineOpen0(
        [MarshalAs(UnmanagedType.LPWStr)] string srv, uint auth, IntPtr id, ref SESS s, out IntPtr e);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmEngineClose0(IntPtr e);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmLayerCreateEnumHandle0(IntPtr e, IntPtr tpl, out IntPtr h);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmLayerEnum0(IntPtr e, IntPtr h, out IntPtr entries, out uint count);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmLayerDestroyEnumHandle0(IntPtr e, IntPtr h);
    [DllImport("fwpuclnt.dll")] public static extern void FwpmFreeMemory0(ref IntPtr p);
}
'@
Add-Type -TypeDefinition $cs -ErrorAction Stop

function Key-Of($g) {
    $d4 = ($g.D4 | ForEach-Object { $_.ToString('x2') }) -join ''
    '{0:x8}-{1:x4}-{2:x4}-{3}' -f $g.D1, $g.D2, $g.D3, $d4
}

# 引擎打开：把几种 authnService 都试一遍（用户态常用 RPC_C_AUTHN_DEFAULT）
$engine = [IntPtr]::Zero
foreach ($auth in @(0xFFFFFFFF, 10, 0)) {
    $sess = New-Object Wfp+SESS
    $sess.flags = 0
    $rc = [Wfp]::FwpmEngineOpen0($null, [uint32]$auth, [IntPtr]::Zero, [ref]$sess, [ref]$engine)
    Write-Host ("FwpmEngineOpen0 auth={0} rc={1}" -f $auth, $rc)
    if ($rc -eq 0) { break }
}
if ($engine -eq [IntPtr]::Zero) { Write-Host '引擎打不开，后面的核对做不了'; exit 0 }

# 全量枚举，建 id -> 层 的权威表
$h = [IntPtr]::Zero
if ([Wfp]::FwpmLayerCreateEnumHandle0($engine, [IntPtr]::Zero, [ref]$h) -eq 0) {
    $entries = [IntPtr]::Zero; $count = 0
    if ([Wfp]::FwpmLayerEnum0($engine, $h, [ref]$entries, [ref]$count) -eq 0) {
        $size = [System.Runtime.InteropServices.Marshal]::SizeOf([type]([Wfp+LAYER]))
        $map = @{}
        Write-Host "`n=== 全部内建层（$count 个）==="
        for ($i = 0; $i -lt $count; $i++) {
            $p = [IntPtr]::Add($entries, $i * $size)
            $lyr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($p, [type]([Wfp+LAYER]))
            $name = if ($lyr.dd.name -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::PtrToStringUni($lyr.dd.name) } else { '?' }
            $map[[int]$lyr.layerId] = $name
            Write-Host ("  layerId={0,-4} {1,-42} key={2}" -f $lyr.layerId, $name, (Key-Of $lyr.key))
        }
        [Wfp]::FwpmFreeMemory0([ref]$entries)
        Write-Host "`n=== 驱动用的四个 id 指向谁 ==="
        foreach ($id in @(4, 6, 12, 14)) {
            $nm = if ($map.ContainsKey($id)) { $map[$id] } else { '<枚举里没有这个 id>' }
            Write-Host ("  id={0,-3} -> {1}" -f $id, $nm)
        }
    } else { Write-Host 'FwpmLayerEnum0 失败' }
    [Wfp]::FwpmLayerDestroyEnumHandle0($engine, $h) | Out-Null
} else { Write-Host 'FwpmLayerCreateEnumHandle0 失败' }

[Wfp]::FwpmEngineClose0($engine) | Out-Null
