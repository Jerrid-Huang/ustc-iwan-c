# 取 WFP 内建层键（FWPM_LAYER_* GUID）的权威数值。
#
# 为什么要它：驱动原来用 FwpmLayerGetById0(engine, FWPS_LAYER_*枚举值) 在运行时
# 反查层键，怀疑这个 id 空间与 FWPM 的层 ID 并不是一回事，于是装上了指向别处的
# "终止型 callout 过滤器" —— 那会变成全机流量的黑洞。层键是稳定的公开常量，
# 直接取出数值写死在驱动里，既不需要运行时查 BFE，也不再有这层猜测。
#
# 取法：fwpuclnt.lib 是对 fwpuclnt.dll 的导入库，这些 GUID 是 DLL 的**数据导出**，
# 因此按名字 GetExport 拿到的指针就指向那 16 个字节。
$ErrorActionPreference = 'Continue'

$cs = @'
using System;
using System.Runtime.InteropServices;
public static class Nat {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr LoadLibraryW([MarshalAs(UnmanagedType.LPWStr)] string n);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr h, string n);
}
'@
Add-Type -TypeDefinition $cs -ErrorAction Stop

$h = [Nat]::LoadLibraryW('fwpuclnt.dll')
Write-Host ("fwpuclnt.dll 句柄 = 0x{0:x}" -f [int64]$h)
if ($h -eq [IntPtr]::Zero) { Write-Host '载入失败'; exit 0 }

function Guid-Of([string]$symbol) {
    $p = [Nat]::GetProcAddress($h, $symbol)
    if ($p -eq [IntPtr]::Zero) { return "$symbol : <未导出>" }
    $b = New-Object byte[] 16
    [System.Runtime.InteropServices.Marshal]::Copy($p, $b, 0, 16)
    $d1 = [BitConverter]::ToUInt32($b, 0)
    $d2 = [BitConverter]::ToUInt16($b, 4)
    $d3 = [BitConverter]::ToUInt16($b, 6)
    $d4 = ($b[8..15] | ForEach-Object { $_.ToString('02x') }) -join ''
    '{0} = {1:x8}-{2:x4}-{3:x4}-{4}  ->  0x{1:X8}, 0x{2:X4}, 0x{3:X4}, {{0x{5},0x{6},0x{7},0x{8},0x{9},0x{10},0x{11},0x{12}}}' -f `
        $symbol, $d1, $d2, $d3, $d4, $b[8], $b[9], $b[10], $b[11], $b[12], $b[13], $b[14], $b[15]
}

$want = @(
    'FWPM_LAYER_OUTBOUND_IPPACKET_V4',
    'FWPM_LAYER_OUTBOUND_IPPACKET_V6',
    'FWPM_LAYER_INBOUND_TRANSPORT_V4',
    'FWPM_LAYER_INBOUND_TRANSPORT_V6',
    'FWPM_LAYER_INBOUND_IPPACKET_V4',
    'FWPM_LAYER_OUTBOUND_IPPACKET_V4_DISCARD',
    'FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD'
)
Write-Host "`n=== 层键（GUID 数值）==="
foreach ($s in $want) { Write-Host ('  ' + (Guid-Of $s)) }

# 顺带再试一次打开引擎（session 传 NULL 的变体），能开就给出 id -> 层名的对照
$cs2 = @'
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
        [MarshalAs(UnmanagedType.LPWStr)] string srv, uint auth, IntPtr id, IntPtr s, out IntPtr e);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmEngineClose0(IntPtr e);
    [DllImport("fwpuclnt.dll")] public static extern uint FwpmLayerGetById0(IntPtr e, ushort id, out IntPtr l);
    [DllImport("fwpuclnt.dll")] public static extern void FwpmFreeMemory0(ref IntPtr p);
}
'@
Add-Type -TypeDefinition $cs2 -ErrorAction Stop
$engine = [IntPtr]::Zero
$rc = [Wfp]::FwpmEngineOpen0($null, 10, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$engine)
Write-Host "`nFwpmEngineOpen0(NULL session) rc=$rc"
if ($rc -eq 0 -and $engine -ne [IntPtr]::Zero) {
    Write-Host '=== FWPS 枚举值当 FWPM id 用，反查到哪一层 ==='
    foreach ($id in @(4, 6, 12, 14)) {
        $p = [IntPtr]::Zero
        $r2 = [Wfp]::FwpmLayerGetById0($engine, [uint16]$id, [ref]$p)
        if ($r2 -eq 0 -and $p -ne [IntPtr]::Zero) {
            $lyr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($p, [type]([Wfp+LAYER]))
            $nm = if ($lyr.dd.name -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::PtrToStringUni($lyr.dd.name) } else { '?' }
            Write-Host ("  id={0,-3} layerId={1,-4} 名字={2}" -f $id, $lyr.layerId, $nm)
            [Wfp]::FwpmFreeMemory0([ref]$p)
        } else { Write-Host ("  id={0,-3} 查询失败 rc={1}" -f $id, $r2) }
    }
    [Wfp]::FwpmEngineClose0($engine) | Out-Null
}
