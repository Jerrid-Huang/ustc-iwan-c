# 在 nano11 客体上安装 iwanmp（NDIS 微型端口 + 协议驱动）驱动包。
#
# 三道坎都在这里一次性解决（历史教训，任何一道没过 install 就报错）：
#   1) 测试签名模式下 INF 包必须带**签过名的 .cat**，只给 .sys 签名不够；
#   2) 重装必须重打 DriverVer，否则 SetupAPI 不会把新 .sys 拷进 System32\drivers；
#   3) 包里必须显式写 CatalogFile=，否则报 "Driver package does not contain a
#      catalog file" (0xE000022F)。
#
# 本脚本额外做一件安全上的事：**在安装之前**就把保险丝合上
# （HKLM\SYSTEM\CurrentControlSet\Services\iwanmp\Parameters\Disarm=1）。
# 这样 root 枚举设备第一次被 PnP 启动时，DriverEntry 在任何 NDIS 调用之前
# 就直接失败（设备停在 Code 10），用来证明"装载这条路径本身不会把机器弄挂"。
# 要真正装载，用 vm-mp-arm.ps1 放开保险丝。
#
# 用法：powershell -NoProfile -File vm-mp-install.ps1 -InfPath C:\iwan\iwanmp.inf -SysPath C:\iwan\iwanmp.sys
param(
    [string]$InfPath = 'C:\iwan\iwanmp.inf',
    [string]$SysPath = 'C:\iwan\iwanmp.sys',
    [string]$Hwid = 'iwanmp',
    [string]$CertSubject = 'CN=iwan win-driver test',
    [string]$Stage = 'C:\iwan\mp-pkg',
    [string]$InstanceId = ''
)

$ErrorActionPreference = 'Stop'
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

if (-not (Test-Path $InfPath)) { throw "找不到 $InfPath" }
if (-not (Test-Path $SysPath)) { throw "找不到 $SysPath" }
if (-not (Test-Path 'C:\iwan\devcon.exe')) { throw '找不到 C:\iwan\devcon.exe' }

Sec '源文件'
Get-Item $InfPath, $SysPath | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
Get-FileHash $SysPath -Algorithm MD5 | Select-Object Hash, Path | Format-List

# 1) 证书（复用 vm-load.ps1 的那张自签代码签名证书）
Sec '证书'
$cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date) } |
        Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $CertSubject `
            -CertStoreLocation Cert:\LocalMachine\My -KeyUsage DigitalSignature `
            -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(3)
    '新建证书'
} else {
    '复用已有证书'
}
$cert | Select-Object Subject, Thumbprint | Format-List
foreach ($store in 'Root', 'TrustedPublisher') {
    $path = "Cert:\LocalMachine\$store"
    if (-not (Test-Path (Join-Path $path $cert.Thumbprint))) {
        $pub = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert.RawData)
        $storeObj = [System.Security.Cryptography.X509Certificates.X509Store]::new($store, 'LocalMachine')
        $storeObj.Open('ReadWrite')
        $storeObj.Add($pub)
        $storeObj.Close()
        "已把公钥加入 $store"
    } else {
        "$store 里已有"
    }
}

# 2) 暂存目录：只放包里的两个文件，目录文件才不会把无关文件也纳入成员表
Sec '暂存目录'
if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
New-Item -ItemType Directory -Path $Stage | Out-Null
$stageInf = Join-Path $Stage 'iwanmp.inf'
$stageSys = Join-Path $Stage 'iwanmp.sys'
$stageCat = Join-Path $Stage 'iwanmp.cat'

# 3) 重打 DriverVer + 补 CatalogFile（逐行重建，绝不用 -match 对数组做替换）
$stamp = (Get-Date).ToString('MM/dd/yyyy,HH:mm', [Globalization.CultureInfo]::InvariantCulture)
$lines = [System.IO.File]::ReadAllLines($InfPath)
$out = New-Object System.Collections.Generic.List[string]
$sawCat = $false
$verAt = -1
foreach ($l in $lines) {
    if ($l -match '^\s*DriverVer\s*=') {
        $verAt = $out.Count
        $out.Add("DriverVer       = $stamp")
    } elseif ($l -match '^\s*CatalogFile') {
        $sawCat = $true
        $out.Add('CatalogFile     = iwanmp.cat')
    } else {
        $out.Add($l)
    }
}
if (-not $sawCat) {
    if ($verAt -lt 0) { throw 'INF 里没有 DriverVer 行' }
    $out.Insert($verAt + 1, 'CatalogFile     = iwanmp.cat')
}
[System.IO.File]::WriteAllLines($stageInf, $out, (New-Object System.Text.ASCIIEncoding))
Copy-Item $SysPath $stageSys -Force
Sec '重打后的 [Version] 段'
Get-Content $stageInf | Select-Object -First 25 | Where-Object { $_ -match 'DriverVer|CatalogFile|Class|Provider' }

# 4) 目录文件 + 签名
Sec '目录文件与签名'
New-FileCatalog -Path $Stage -CatalogFilePath $stageCat -CatalogVersion 2 | Out-Null
$r1 = Set-AuthenticodeSignature -FilePath $stageSys -Certificate $cert -HashAlgorithm SHA256
"sys: $($r1.Status)"
$r2 = Set-AuthenticodeSignature -FilePath $stageCat -Certificate $cert -HashAlgorithm SHA256
"cat: $($r2.Status)"
Get-AuthenticodeSignature $stageSys, $stageCat | Select-Object Status, Path | Format-Table -AutoSize
if ((Get-AuthenticodeSignature $stageCat).Status -ne 'Valid') { throw '.cat 签名无效' }

# 5) 合上保险丝（必须在安装之前：第一次启动就要被挡住）
Sec '保险丝（安装前合上）'
$pkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwanmp\Parameters'
if (-not (Test-Path $pkey)) { New-Item -Path $pkey -Force | Out-Null }
New-ItemProperty -Path $pkey -Name 'Disarm' -PropertyType DWord -Value 1 -Force | Out-Null
Get-ItemProperty $pkey | Format-List

# 6) 清掉 DriverStore 里可能残留的旧 iwanmp 包（否则可能装回旧映像）
Sec 'DriverStore 清理'
$enum = & pnputil.exe /enum-drivers | Out-String
$blocks = $enum -split "`r?`n`r?`n"
$stale = @()
foreach ($b in $blocks) {
    if ($b -match 'iwanmp\.inf') {
        $m = [regex]::Match($b, 'Published Name\s*:\s*(\S+)')
        if ($m.Success) { $stale += $m.Groups[1].Value }
    }
}
if ($stale.Count -eq 0) {
    '没有残留包'
} else {
    foreach ($oem in $stale) {
        "删除 $oem"
        & pnputil.exe /delete-driver $oem /uninstall /force 2>&1 | Out-String
    }
}

# 7) 安装
Sec 'devcon install'
$dev = & C:\iwan\devcon.exe install $stageInf $Hwid 2>&1 | Out-String
$dev

Sec '设备状态'
$devs = @(Get-PnpDevice -ErrorAction SilentlyContinue |
          Where-Object { $_.HardwareID -contains 'iwanmp' })
$devs | Select-Object Status, Class, FriendlyName, InstanceId, Problem, ProblemDescription |
    Format-List
foreach ($d in $devs) {
    Get-PnpDeviceProperty -InstanceId $d.InstanceId -ErrorAction SilentlyContinue |
        Where-Object { $_.KeyName -match 'ProblemCode|DeviceDesc|Service|DriverVersion' } |
        Select-Object KeyName, Data | Format-Table -AutoSize
}

Sec '服务状态'
Get-Service -Name iwanmp -ErrorAction SilentlyContinue |
    Select-Object Name, Status, ServiceType, StartType | Format-List

Sec '分阶段 trace 键'
$p = Get-ItemProperty $pkey -ErrorAction SilentlyContinue
foreach ($n in 'Stage', 'Status', 'Disarm', 'NoProto') {
    if ($p.PSObject.Properties.Name -contains $n) { "  {0,-10} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n }
}
$tkeys = @($p.PSObject.Properties.Name | Where-Object { $_ -match '^T\d+$' })
foreach ($n in ($tkeys | Sort-Object { [int]($_.Substring(1)) })) {
    "  {0,-10} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n
}

Sec '最近的 Kernel-PnP 事件'
Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = (Get-Date).AddMinutes(-5) } `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'Kernel-PnP' } |
    Select-Object -First 6 |
    ForEach-Object { "{0} [{1}] {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ') }

Sec '结论提示'
'保险丝是合上的（Disarm=1）：设备应停在 Code 10，T8=1、T9=0xC0000001，'
'并且**没有** T10/T11/T30 之后的键 —— 这正说明 DriverEntry 在任何 NDIS 调用之前就退出了。'
