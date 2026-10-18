# 在 nano11 虚拟机里建 KM-TEST 环回承载网卡（内层地址挂它上面），并改名成 iWAN。
#
# 为什么需要它：内核数据面取代的是 TUN 模式，报文不进用户态，所以内层地址必须有
# 一个"本机地址"落在某张网卡上，协议栈才肯把内层包交给 WFP 出向层。按设计用
# Microsoft KM-TEST 环回适配器（netloop.inf，系统自带），不占真实网卡地址表，
# 也不会向外发 ARP —— 内层包在出向层就被 callout 吸收并封装了。
#
# 三条注意（README 里同样写了）：不给它配 IP、不设默认网关、名字固定叫 iWAN
# （IWAN_WIN_DEF_DEV），否则客户端按名字找不到它。
$ErrorActionPreference = 'Continue'
function Sec($t) { "`n=== $t ===" }

$devcon = 'C:\iwan\devcon.exe'
if (-not (Test-Path $devcon)) { throw "找不到 $devcon（由 CI 产物提供）" }
$netloop = Join-Path $env:WINDIR 'inf\netloop.inf'
if (-not (Test-Path $netloop)) { throw "找不到 $netloop" }

Sec '安装前：现有网卡'
Get-NetAdapter | Format-Table Name, InterfaceDescription, ifIndex, Status -AutoSize |
    Out-String -Width 170

Sec '是否已经有 KM-TEST 实例'
$existing = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'KM-TEST|Loopback' }
if ($existing) {
    '已有：'
    $existing | Format-Table Name, InterfaceDescription, ifIndex, Status -AutoSize | Out-String -Width 170
} else {
    '没有，开始装'
}

Sec 'devcon install netloop.inf *msloop'
& $devcon install $netloop '*msloop' 2>&1 | Out-String
Start-Sleep -Seconds 4

Sec '安装后：把 KM-TEST 网卡改名为 iWAN'
$km = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'KM-TEST|Loopback' }
if (-not $km) {
    '仍然没有 KM-TEST 网卡 —— devcon 或 netloop.inf 有问题，看上面输出'
} else {
    foreach ($a in $km) {
        if ($a.Name -ne 'iWAN') {
            "改名：$($a.Name) -> iWAN"
            Rename-NetAdapter -Name $a.Name -NewName 'iWAN' -ErrorAction Continue
        } else {
            "$($a.Name) 已经是目标名字"
        }
    }
}

Sec '最终状态（iWAN 名下的地址/网关应当为空）'
Get-NetAdapter | Format-Table Name, InterfaceDescription, ifIndex, Status -AutoSize |
    Out-String -Width 170
$iwan = Get-NetAdapter -Name 'iWAN' -ErrorAction SilentlyContinue
if ($iwan) {
    "iWAN ifIndex = $($iwan.ifIndex)  status = $($iwan.Status)"
    'IP：'
    Get-NetIPAddress -InterfaceIndex $iwan.ifIndex -ErrorAction SilentlyContinue |
        Select-Object IPAddress, PrefixLength, AddressFamily | Format-Table -AutoSize | Out-String
    '路由（应当没有默认路由走它）：'
    Get-NetRoute -InterfaceIndex $iwan.ifIndex -ErrorAction SilentlyContinue |
        Select-Object DestinationPrefix, NextHop | Format-Table -AutoSize | Out-String
} else {
    '没有 iWAN 网卡'
}
