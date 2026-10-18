# 合上保险丝并把设备节点停掉 —— iwanmp 的"休眠状态"。
#
# 目标状态（每次测完都回到这里）：
#   * Parameters\Disarm=1（DriverEntry 在任何 NDIS 调用之前就退出）
#   * 设备节点 Disabled（PnP 根本不会启动它，重启也不会）
#   * 服务停掉（sc.exe stop 只是把已加载的映像卸掉，服务类型是 demand）
# 这样即使驱动里还藏着会把机器弄挂的缺陷，重启也永远是安全的。
#
# 用法：powershell -NoProfile -File vm-mp-disarm.ps1
param(
    [string]$InstanceId = ''
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
if (Test-Path $pkey) {
    Sec '合上保险丝'
    New-ItemProperty -Path $pkey -Name 'Disarm' -PropertyType DWord -Value 1 -Force | Out-Null
    Get-ItemProperty $pkey | Select-Object Disarm, NoProto | Format-List
} else {
    "没有 $pkey"
}

Sec '停服务'
& sc.exe stop iwanmp 2>&1 | Out-String
Start-Sleep -Seconds 2

Sec '停设备节点'
if (-not $InstanceId) { '找不到设备节点，跳过' }
else { & pnputil.exe /disable-device "$InstanceId" 2>&1 | Out-String }
Start-Sleep -Seconds 3

Sec '最终状态'
Get-PnpDevice | Where-Object { $_.HardwareID -contains 'iwanmp' } |
    Select-Object Status, FriendlyName, InstanceId, Problem, ProblemDescription | Format-List
Get-Service -Name iwanmp -ErrorAction SilentlyContinue | Select-Object Name, Status | Format-List
Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -match 'iWAN' } |
    Select-Object Name, Status, ifIndex | Format-Table -AutoSize

Sec '判据'
'设备 Status=Disabled/Error 且服务 Stopped -> 重启安全。'
