# iwanmp 一站式上机装具：现场 -> 清干净 -> 装 -> 放开保险丝 -> 适配器/地址/MTU -> OPEN 探针 -> 全表读数
#
# 这个脚本存在的唯一理由是"跑的是哪一版"曾经要靠反汇编快照去猜：客体上
# .sys 被已加载的驱动钉住时 Copy-Item 报 Access denied，sc delete 只是标记
# 删除，pnputil /delete-driver 要求重启后才生效 —— 文件 mtime 完全不可信。
# 于是一路都用 PE TimeDateStamp 串起来：
#   源 .sys 的 stamp  ==  System32\drivers\iwanmp.sys 的 stamp（装对了）
#   驱动自己读出来落进 T31（见 win-driver/iwan_win_mp.c 的 iwan_win_mp_build_stamp）
# 两者不等就直接判失败，不再拿 trace 键去猜。
#
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-mp-full.ps1 `
#       -Sys C:\iwan\iwanmp.sys -Inf C:\iwan\iwanmp.inf -Carrier 7
#   只想看现场：-InspectOnly
#   装具已经装好、只要探针：-SkipInstall
param(
    [string]$Sys = 'C:\iwan\iwanmp.sys',
    [string]$Inf = 'C:\iwan\iwanmp.inf',
    [string]$Hwid = 'iwanmp',
    [int]$Carrier = 0,
    [int]$HoldSeconds = 4,
    [int]$WaitSeconds = 8,
    # 内层适配器的"介质形状"。客体上 NdisMediumIP + 广播 + 无链路地址时，
    # TCP/IP 仍会给对端建邻居项并索要 6 字节链路地址，拿不到就 send 直接
    # 失败（ping 报 General failure、UDP 报 WSAEINVAL），连 NDIS 都到不了。
    # 改注册表 + restart-device 就能换一档，不必重启整机换映像。
    #   MpAccess 0=广播 1=点对点 2=环回
    #   MpMacLen 0=无链路地址 6=给一个假 MAC
    #   MpIfType 0=PROP_VIRTUAL 6=ETHERNET_CSMACD 131=TUNNEL
    [int]$MpAccess = 0,
    [int]$MpMacLen = 0,
    [int]$MpIfType = 0,
    [switch]$InspectOnly,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Sec($t) { "`n=== $t ===" }
function PeStamp([string]$p) {
    if (-not (Test-Path $p)) { return [uint32]0 }
    $b = [System.IO.File]::ReadAllBytes($p)
    if ($b.Length -lt 0x40) { return [uint32]0 }
    if ($b[0] -ne 0x4D -or $b[1] -ne 0x5A) { return [uint32]0 }
    $lf = [BitConverter]::ToInt32($b, 0x3C)
    if ($lf -le 0 -or ($lf + 12) -gt $b.Length) { return [uint32]0 }
    return [BitConverter]::ToUInt32($b, $lf + 8)
}

$drv = 'C:\Windows\System32\drivers\iwanmp.sys'
$pkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwanmp\Parameters'
$traceKeys = '^(T\d+|Stage|Status)$'

function Get-IwanmpNodes {
    @(Get-PnpDevice -ErrorAction SilentlyContinue |
      Where-Object { $_.HardwareID -contains $Hwid })
}
function Show-Trace {
    if (-not (Test-Path $pkey)) { '  (没有 Parameters 键)'; return }
    $p = Get-ItemProperty $pkey
    foreach ($n in @($p.PSObject.Properties.Name | Where-Object { $_ -match $traceKeys } | Sort-Object)) {
        "  {0,-8} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n
    }
}
function Clear-Trace {
    if (-not (Test-Path $pkey)) { return }
    $p = Get-ItemProperty $pkey
    foreach ($n in @($p.PSObject.Properties.Name | Where-Object { $_ -match $traceKeys })) {
        Remove-ItemProperty -Path $pkey -Name $n -ErrorAction SilentlyContinue
    }
}
function Set-Param([string]$n, [int]$v) {
    if (-not (Test-Path $pkey)) { New-Item -Path $pkey -Force | Out-Null }
    New-ItemProperty -Path $pkey -Name $n -PropertyType DWord -Value $v -Force | Out-Null
}

Sec '0 现场'
$srcStamp = PeStamp $Sys
$dstStamp = PeStamp $drv
"  源     $Sys  len=" + (Get-Item $Sys -ErrorAction SilentlyContinue).Length + " stamp=0x{0:X8}" -f $srcStamp
"  已装   $drv  len=" + (Get-Item $drv -ErrorAction SilentlyContinue).Length + " stamp=0x{0:X8}" -f $dstStamp
"  服务   " + ((Get-Service -Name 'iwanmp' -ErrorAction SilentlyContinue).Status)
"  节点数 " + (Get-IwanmpNodes).Count
Show-Trace
if ($InspectOnly) { return }

if (-not $SkipInstall) {
    Sec '1 清干净'
    # 孤儿节点会一个接一个冒出来（devcon 装失败时留下的空壳没有 Service 值），
    # 所以要循环删到没有为止，而不是删一遍就以为干净了。
    for ($round = 0; $round -lt 6; $round++) {
        $nodes = Get-IwanmpNodes
        if ($nodes.Count -eq 0) { break }
        foreach ($d in $nodes) {
            "  remove-device $($d.InstanceId)"
            & pnputil.exe /remove-device $d.InstanceId 2>&1 | Out-String | ForEach-Object { "    $_" }
        }
    }
    "  清完节点数 " + (Get-IwanmpNodes).Count

    & sc.exe query iwanmp 2>&1 | Out-String | ForEach-Object { "  $_" }
    & sc.exe delete iwanmp 2>&1 | Out-String | ForEach-Object { "  $_" }

    foreach ($o in (& pnputil.exe /enum-drivers | Out-String) -split "`r`n`r`n") {
        if ($o -match ([regex]::Escape($Hwid) + '\.inf')) {
            $m = [regex]::Match($o, 'Published Name:\s*(\S+)')
            if ($m.Success) {
                "  delete-driver $($m.Groups[1].Value)"
                & pnputil.exe /delete-driver $m.Groups[1].Value /uninstall /force 2>&1 |
                    Out-String | ForEach-Object { "    $_" }
            }
        }
    }
    if (Test-Path $drv) {
        Remove-Item $drv -Force -ErrorAction SilentlyContinue
        "  删 $drv -> exists=" + (Test-Path $drv)
    }

    Sec '2 装（保险丝先合上）'
    Set-Param 'Disarm' 1
    Set-Param 'NoProto' 1
    & cmd.exe /c "`"$PSHOME\powershell.exe`" -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-mp-install.ps1 -SysPath $Sys -InfPath $Inf" 2>&1 |
        Out-String | ForEach-Object { "  $_" }
    $dstStamp = PeStamp $drv
    "  装后 stamp=0x{0:X8}" -f $dstStamp
    if ($dstStamp -ne $srcStamp -or $srcStamp -eq 0) {
        "  严重：装上的映像不是这一版（源 0x{0:X8} / 装 0x{1:X8}）—— 停下" -f $srcStamp, $dstStamp
        return
    }
}

Sec '2.5 协议组件户口（NetTrans）'
# 协议边要有绑定，光有服务不够：NDIS 眼里它必须是一个 NetTrans 组件。
# 第 1 步删掉了驱动包，组件注册可能指向已经不存在的服务；不补齐这一步，
# 后面 T71 恒为 0，整轮读数白跑（曾经就是这样白跑了一轮）。
# 位置也不能挪：装早了 DriverEntry 会被提前拉起（保险丝还是合着的，白白
# 烧掉一次 DriverEntry），装晚了本轮读数同样作废。
& cmd.exe /c "`"$PSHOME\powershell.exe`" -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-mp-proto.ps1 -SysSrc $drv" 2>&1 |
    Out-String | ForEach-Object { "  $_" }
$comp = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}' -ErrorAction SilentlyContinue |
          Where-Object { $_.PSChildName -match '^\{' } |
          Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ComponentId -eq 'iwanmp' })
"  组件实例数 " + $comp.Count
if ($comp.Count -eq 0) {
    # 组件残留导致 netcfg -l 空转时，先拆再装；只重试一次，避免无限循环。
    "  没装上，先 netcfg -u 再装一次"
    & cmd.exe /c "C:\Windows\System32\netcfg.exe -u iwanmp" 2>&1 | Out-String | ForEach-Object { "  $_" }
    & cmd.exe /c "`"$PSHOME\powershell.exe`" -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-mp-proto.ps1 -SysSrc $drv" 2>&1 |
        Out-String | ForEach-Object { "  $_" }
    $comp = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}' -ErrorAction SilentlyContinue |
              Where-Object { $_.PSChildName -match '^\{' } |
              Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ComponentId -eq 'iwanmp' })
    "  重试后组件实例数 " + $comp.Count
}
if ($comp.Count -eq 0) { throw 'NetTrans 组件没装上：协议边不可能有绑定' }
# 服务键的 Ndi\Interfaces 是两个 INF 共同写的：微型端口包与协议组件包
# 都把值写进 Services\iwanmp\Ndi\Interfaces，后装的那个逐值覆盖先装的。
# 实测这里被微型端口包改成了 upper=ndis5 / lower=ethernet，两种形状
# 都能工作，但必须把当轮的真实值记下来，否则「绑定来了又打不开」时
# 没法排除接口形状这一项。
$ik = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwanmp\Ndi\Interfaces'
if (Test-Path $ik) {
    $q = Get-ItemProperty $ik
    "  服务 Ndi: upper=" + ($q.UpperRange -join ',') + " lower=" + ($q.LowerRange -join ',')
} else { '  服务 Ndi\Interfaces: 缺失' }

Sec '3 放开保险丝（协议边也起）'
$node = (Get-IwanmpNodes | Select-Object -First 1).InstanceId
if (-not $node) { throw '找不到 HardwareID=iwanmp 的设备节点' }
Clear-Trace
Set-Param 'MpAccess' $MpAccess
Set-Param 'MpMacLen' $MpMacLen
Set-Param 'MpIfType' $MpIfType
Set-Param 'Disarm' 0
Set-Param 'NoProto' 0
"  媒介形状：MpAccess=$MpAccess MpMacLen=$MpMacLen MpIfType=$MpIfType"
& pnputil.exe /restart-device $node 2>&1 | Out-String | ForEach-Object { "  $_" }
Start-Sleep -Seconds $WaitSeconds
"  设备：" + ((Get-IwanmpNodes | Select-Object -First 1).Status)
$t31 = 0
if (Test-Path $pkey) { $t31 = [uint32](Get-ItemProperty $pkey).T31 }
"  运行中映像 T31=0x{0:X8}（源 0x{1:X8}）" -f $t31, $srcStamp
if ($t31 -ne $srcStamp) { "  警告：跑的不是这一版，后面的读数都不可信" }

Sec '4 适配器 / 地址 / MTU'
$ad = Get-NetAdapter -ErrorAction SilentlyContinue |
      Where-Object { $_.InterfaceDescription -like 'iWAN Tunnel Adapter*' -and $_.Status -ne 'Not Present' } |
      Select-Object -First 1
if (-not $ad) { '  没有隧道适配器（MiniportInitializeEx 没成功，看 T20/T21/T22）'; Show-Trace; return }
"  适配器 $($ad.Name) ifIndex=$($ad.ifIndex) status=$($ad.Status)"
if ($ad.Name -ne 'iwanmp') {
    & netsh.exe interface set interface name="$($ad.Name)" newname="iwanmp" 2>&1 | Out-String | ForEach-Object { "  $_" }
    Start-Sleep -Seconds 2
    $ad = Get-NetAdapter -Name 'iwanmp' -ErrorAction SilentlyContinue
    "  改名后 $($ad.Name) ifIndex=$($ad.ifIndex)"
}
# netsh 的 set address 对已存在的地址报 "The object already exists." 且不生效，
# 只有 add address 真的能把地址加上去。
# 判据必须是"这个地址在不在"，不是"有没有任何地址"：适配器起来时自带
# 169.254.x.x 的自动专用地址，按后一条判会静默跳过 add —— 然后 ping 打
# 的是那个不存在的内层地址，看起来像数据面坏了（踩过）。
$have = @(Get-NetIPAddress -InterfaceAlias 'iwanmp' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object { $_.IPAddress -eq '10.99.0.1' })
if ($have.Count -eq 0) {
    & netsh.exe interface ipv4 add address name="iwanmp" 10.99.0.1 255.255.255.0 2>&1 | Out-String | ForEach-Object { "  $_" }
    Start-Sleep -Seconds 1
}
$have = @(Get-NetIPAddress -InterfaceAlias 'iwanmp' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object { $_.IPAddress -eq '10.99.0.1' })
if ($have.Count -eq 0) { '  警告：10.99.0.1 没加上，后面的内层收发一定失败' }
& netsh.exe interface ipv4 set subinterface "iwanmp" mtu=1400 store=persistent 2>&1 | Out-String | ForEach-Object { "  $_" }
Get-NetIPAddress -InterfaceAlias 'iwanmp' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object IPAddress, PrefixLength | Format-Table -AutoSize | Out-String -Width 200

Sec '5 OPEN 探针'
if ($Carrier -le 0) { $Carrier = (Get-NetAdapter -Name 'Ethernet' -ErrorAction SilentlyContinue).ifIndex }
"  承载 ifIndex=$Carrier 保持 ${HoldSeconds}s"
# 两套编号并排打出来：驱动里绑定表存的是 NDIS 口径，控制面给的是 netio 口径，
# 探针用的又是 Get-NetAdapter 的 ifIndex。三者不等时，症状与"没绑上"完全一样。
foreach ($c in (Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetConnectionID })) {
    $ni = Get-NetAdapter -Name $c.NetConnectionID -ErrorAction SilentlyContinue
    "  索引对照 name=$($c.NetConnectionID) miniport=$($c.Index) netio=$(if ($ni) { $ni.ifIndex } else { '?' })"
}
Clear-Trace
# 承载网卡的接口 GUID：两套接口索引口径在客体上实测并不一致（以太网
# netio=7，协议边绑定报 23/26），按索引挑承载等于猜。控制面真实路径用
# ConvertInterfaceLuidToGuid 取同一份 GUID，这里照抄那个口径。
$cguid = (Get-NetAdapter -InterfaceIndex $Carrier -ErrorAction SilentlyContinue).InterfaceGuid
if ($cguid) { $cguid = $cguid.ToString() } else { $cguid = '' }
"  承载 GUID=$cguid"
& cmd.exe /c "`"$PSHOME\powershell.exe`" -NoProfile -ExecutionPolicy Bypass -File C:\iwan\mp-ab-probe.ps1 -HoldSeconds $HoldSeconds -OifIndex $Carrier -OuterIfGuid $cguid" 2>&1 |
    Out-String | ForEach-Object { "  $_" }

Sec '6 trace 全表'
Show-Trace
''
'  判读：'
'   T31 = 运行中映像时间戳（与第 3 步的源一致才说明这一版在跑）'
'   T69 = 协议边注册命中的声明次版本；T78/T79 = NDIS 调 BindAdapterEx 次数/被拒次数'
'   T71 = 链上绑定数；T72/T73 = open_complete 成败次数；T74/T75 = 前两个绑定 ifindex|opened|closed'
'   T76/T77 = 打开失败的 NTSTATUS / NdisOpenAdapterEx 当场返回；T83 > 0 表示等过在飞的打开'
'   T80 = 查不到可用绑定；T81 = 选中瞬间被解绑；T82 = 成功，值是选中的 ifindex'
'   T87 = 会话带没带承载 GUID（1=带，只按 GUID 查表）；T88 = 命中数<<8 | 解析成功数'
'   T90/T91/T92 = 本次小型端口用的 AccessType/MacAddressLength/IfType 档位'
