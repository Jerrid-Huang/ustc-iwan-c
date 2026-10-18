# 放开 iwanmp 的保险丝并重启设备节点 —— 这是真正"开始装载"的那一步。
#
# 分两级，默认只放一半（-NoProto 1）：
#   第一级（本脚本默认）：只注册小型端口，不注册协议边。用来验证
#     "适配器出现 + 地址与 MTU 可设 + 控制设备可用 + 不挂"；
#   第二级：-NoProto 0，协议边也起来（外层承载收发），才可能端到端收发。
# 无论哪一级，DriverEntry 在小型端口注册成功之后都不再返回失败。
#
# 用法：powershell -NoProfile -File vm-mp-arm.ps1 -NoProto 1
param(
    [string]$InstanceId = '',
    [int]$Disarm = 0,
    [int]$NoProto = 1,
    [int]$WaitSeconds = 6
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

$pkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwanmp\Parameters'
if (-not (Test-Path $pkey)) { throw "没有 $pkey（驱动包还没装上？）" }

Sec '清掉旧 trace 键（否则读到上一轮的值）'
$p = Get-ItemProperty $pkey
foreach ($n in @($p.PSObject.Properties.Name | Where-Object { $_ -match '^(T\d+|Stage|Status)$' })) {
    Remove-ItemProperty -Path $pkey -Name $n -ErrorAction SilentlyContinue
    "  删 $n"
}

Sec '设置闸门'
New-ItemProperty -Path $pkey -Name 'Disarm' -PropertyType DWord -Value $Disarm -Force | Out-Null
New-ItemProperty -Path $pkey -Name 'NoProto' -PropertyType DWord -Value $NoProto -Force | Out-Null
"  Disarm=$Disarm NoProto=$NoProto"

Sec '重启设备节点'
& pnputil.exe /restart-device "$InstanceId" 2>&1 | Out-String
Start-Sleep -Seconds $WaitSeconds

Sec '设备状态'
if (-not $InstanceId) { throw '找不到 HardwareID=iwanmp 的设备节点' }
Get-PnpDevice | Where-Object { $_.HardwareID -contains 'iwanmp' } |
    Select-Object Status, FriendlyName, InstanceId, Problem, ProblemDescription | Format-List
foreach ($k in 'DEVPKEY_Device_ProblemCode', 'DEVPKEY_Device_Service') {
    $v = (Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName $k -ErrorAction SilentlyContinue).Data
    if ($null -ne $v) { "  $k = $v" }
}

Sec '内层适配器'
Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -match 'iWAN' -or $_.Name -match 'iwanmp' } |
    Select-Object Name, InterfaceDescription, Status, ifIndex, LinkSpeed | Format-Table -AutoSize

Sec 'trace 键'
$p = Get-ItemProperty $pkey
foreach ($n in 'Stage', 'Status') {
    if ($p.PSObject.Properties.Name -contains $n) { "  {0,-8} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n }
}
$tkeys = @($p.PSObject.Properties.Name | Where-Object { $_ -match '^T\d+$' })
foreach ($n in ($tkeys | Sort-Object { [int]($_.Substring(1)) })) {
    "  {0,-8} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n
}

Sec '判据提示'
'T11/T13 = 0x00000000 表示注册成功；T30 是 NdisGetVersion()（6.89 -> 0x00060059）；'
'T40/T39 是小型端口那一半，T60/T69 是协议边那一半（NoProto=1 时 T60=0xC0000001）。'
