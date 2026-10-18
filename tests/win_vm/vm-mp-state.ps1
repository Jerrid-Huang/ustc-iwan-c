# 只读：把 iwanmp 的现场一次读全（设备节点、服务、内层适配器、trace 键、PnP 事件）。
#
# 用法：powershell -NoProfile -File vm-mp-state.ps1
param(
    [string]$InstanceId = '',
    [int]$EventMinutes = 10
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Sec($t) { "`n=== $t ===" }

# 设备实例 ID 不是固定的：devcon install 按 INF 的 Class 建节点，实际落在
# ROOT\NET\000x（早期脚本里写死 ROOT\IWANMP\0000 是猜的，一直没生效）。
function Get-IwanmpInstanceId {
    $d = Get-PnpDevice -ErrorAction SilentlyContinue |
         Where-Object { $_.HardwareID -contains 'iwanmp' } |
         Select-Object -First 1
    if ($d) { return $d.InstanceId }
    return ''
}
if (-not $InstanceId) { $InstanceId = Get-IwanmpInstanceId }

Sec '设备节点'
$devs = @(Get-PnpDevice -ErrorAction SilentlyContinue |
          Where-Object { $_.HardwareID -contains 'iwanmp' })
if ($devs.Count -gt 0) {
    $devs | Select-Object Status, Class, FriendlyName, InstanceId, Problem, ProblemDescription |
        Format-List
} else {
    '没有 HardwareID=iwanmp 的设备节点'
}

Sec '设备属性'
foreach ($k in 'DEVPKEY_Device_ProblemCode', 'DEVPKEY_Device_Service',
               'DEVPKEY_Device_DriverVersion', 'DEVPKEY_Device_DriverProvider') {
    if (-not $InstanceId) { break }
    $v = (Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName $k -ErrorAction SilentlyContinue).Data
    if ($null -ne $v) { "  $k = $v" }
}

Sec '服务'
Get-Service -Name iwanmp -ErrorAction SilentlyContinue |
    Select-Object Name, Status, ServiceType, StartType | Format-List
if (-not (Get-Service -Name iwanmp -ErrorAction SilentlyContinue)) { '没有 iwanmp 服务' }

Sec '内层适配器'
Get-NetAdapter -ErrorAction SilentlyContinue |
    Select-Object Name, InterfaceDescription, Status, ifIndex, LinkSpeed, MacAddress |
    Format-Table -AutoSize
foreach ($n in (Get-NetAdapter -ErrorAction SilentlyContinue).Name) {
    $mtu = (Get-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue).NlMtu
    $ips = (Get-NetIPAddress -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -join ','
    "  {0,-24} ifIndex={1,-4} mtu={2,-6} ipv4={3}" -f $n,
        (Get-NetAdapter -Name $n).ifIndex, $mtu, $ips
}

Sec '磁盘'
Get-PSDrive C | Select-Object @{n='FreeMB';e={[int]($_.Free/1MB)}}, @{n='UsedMB';e={[int]($_.Used/1MB)}} | Format-Table -AutoSize

Sec '分阶段 trace 键'
$pkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwanmp\Parameters'
$p = Get-ItemProperty $pkey -ErrorAction SilentlyContinue
if ($p) {
    foreach ($n in 'Stage', 'Status', 'Disarm', 'NoProto') {
        if ($p.PSObject.Properties.Name -contains $n) { "  {0,-10} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n }
    }
    $tkeys = @($p.PSObject.Properties.Name | Where-Object { $_ -match '^T\d+$' })
    foreach ($n in ($tkeys | Sort-Object { [int]($_.Substring(1)) })) {
        "  {0,-10} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n
    }
    if ($tkeys.Count -eq 0) { '  （没有任何 T 键：驱动还没被装载过）' }
} else {
    "没有 $pkey"
}

Sec 'DriverStore 里的 iwanmp 包'
(& pnputil.exe /enum-drivers | Out-String) -split "`r?`n`r?`n" |
    Where-Object { $_ -match 'iwanmp\.inf' } |
    ForEach-Object { ($_ -replace '\s+', ' ').Trim() }

Sec "最近 $EventMinutes 分钟的 Kernel-PnP 事件"
Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = (Get-Date).AddMinutes(-$EventMinutes) } `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'Kernel-PnP' } |
    Select-Object -First 8 |
    ForEach-Object { "{0} [{1}] {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ') }
