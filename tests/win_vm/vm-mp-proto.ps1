# 给协议组件（NetTrans，iwanmp-proto.inf）装户口。
#
# 两道坎与微型端口那次同源：
#   1) 测试签名模式下 INF 包必须有签过名的 .cat，否则 netcfg 报 0xe000022f
#      （ERROR_FILE_CATALOG_NOT_FOUND / "does not contain a catalog file"）。
#   2) CatalogFile= 必须显式写在 INF 里，目录才被认。
# 目录里必须至少有一个文件被收录，所以把同版本的 iwanmp.sys 一起放进 staging。
#
# 用法：powershell -File C:\iwan\vm-mp-proto.ps1 [-Uninstall]
param(
    [switch]$Uninstall,
    [string]$InfSrc = 'C:\iwan\iwanmp-proto.inf',
    [string]$SysSrc = 'C:\iwan\iwanmp.sys',
    [string]$Stage = 'C:\iwan\proto-pkg',
    [string]$Service = 'iwanmp',
    [string]$CertSubject = 'iwan win-driver test'
)

$ErrorActionPreference = 'Stop'

if ($Uninstall) {
    'netcfg -u:'
    & "$env:SystemRoot\System32\netcfg.exe" -u $Service 2>&1 | ForEach-Object { "  $_" }
    'done (uninstall)'
    exit 0
}

if (-not (Test-Path $InfSrc)) { throw "INF 不存在：$InfSrc" }
if (-not (Test-Path $SysSrc)) { throw "SYS 不存在：$SysSrc" }

$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -like "*CN=$CertSubject*" } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { throw "找不到证书 CN=$CertSubject" }
"cert: $($cert.Thumbprint)"

if (-not (Test-Path $Stage)) { New-Item -ItemType Directory -Path $Stage -Force | Out-Null }
Get-ChildItem $Stage -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse

$stageInf = Join-Path $Stage 'iwanmp-proto.inf'
$stageSys = Join-Path $Stage 'iwanmp.sys'
$stageCat = Join-Path $Stage 'iwanmp-proto.cat'

# 逐行重建 INF：重打 DriverVer、确保 CatalogFile= 存在（绝不对数组做 -match 替换）
$src = Get-Content -LiteralPath $InfSrc
$out = New-Object System.Collections.Generic.List[string]
$haveCatalog = $false
$verAt = -1
foreach ($l in $src) {
    if ($l -match '^\s*DriverVer\s*=') {
        $out.Add('DriverVer       = {0},1.0.0.0' -f (Get-Date -Format 'MM/dd/yyyy'))
        if ($verAt -lt 0) { $verAt = $out.Count - 1 }
        continue
    }
    if ($l -match '^\s*CatalogFile\s*=') {
        $out.Add('CatalogFile     = iwanmp-proto.cat')
        $haveCatalog = $true
        continue
    }
    $out.Add($l)
}
if (-not $haveCatalog) {
    if ($verAt -lt 0) { throw 'INF 里没有 DriverVer 行，无法定位 CatalogFile 插入点' }
    $out.Insert($verAt + 1, 'CatalogFile     = iwanmp-proto.cat')
}
Set-Content -LiteralPath $stageInf -Value $out -Encoding ASCII
Copy-Item -LiteralPath $SysSrc -Destination $stageSys -Force

"staged:"
Get-Content -LiteralPath $stageInf | Where-Object { $_ -match 'DriverVer|CatalogFile|Class|Provider' }

New-FileCatalog -Path $Stage -CatalogFilePath $stageCat -CatalogVersion 2 | Out-Null
$r1 = Set-AuthenticodeSignature -FilePath $stageSys -Certificate $cert -HashAlgorithm SHA256
$r2 = Set-AuthenticodeSignature -FilePath $stageCat -Certificate $cert -HashAlgorithm SHA256
"sign sys: $($r1.Status)"
"sign cat: $($r2.Status)"

'netcfg install:'
$stdout = & "$env:SystemRoot\System32\netcfg.exe" -v -l $stageInf -c p -i $Service 2>&1
foreach ($l in $stdout) { "  $l" }

'--- 组件实例键（Control\Network\{4D36E975} 下找 iwanmp）'
$base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}'
$found = 0
foreach ($g in Get-ChildItem $base -ErrorAction SilentlyContinue) {
    if ($g.PSChildName -notmatch '^\{') { continue }
    $p = Get-ItemProperty -Path $g.PSPath -ErrorAction SilentlyContinue
    if ($null -eq $p) { continue }
    if ($p.ComponentId -eq $Service) {
        $found++
        "hit: $($g.PSChildName) ComponentId=$($p.ComponentId) InfPath=$($p.InfPath) InfSection=$($p.InfSection)"
    }
}
"component instances: $found"

'--- 服务键 Ndi'
$sk = "HKLM:\SYSTEM\CurrentControlSet\Services\$Service\Ndi"
if (Test-Path $sk) {
    $p = Get-ItemProperty -Path $sk -ErrorAction SilentlyContinue
    foreach ($v in $p.PSObject.Properties) {
        if ($v.Name -like 'PS*') { continue }
        "  Ndi\$($v.Name) = $($v.Value)"
    }
    $ik = Join-Path $sk 'Interfaces'
    if (Test-Path $ik) {
        $q = Get-ItemProperty -Path $ik
        "  Ndi\Interfaces upper=$($q.UpperRange) lower=$($q.LowerRange)"
    }
}
'--- 首张以太网卡的 UpperBind 里有没有我们'
$cls = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0013'
$lk = Join-Path $cls 'Linkage'
if (Test-Path $lk) {
    $p = Get-ItemProperty -Path $lk -ErrorAction SilentlyContinue
    "  UpperBind: $($p.UpperBind -join ',')"
}
'done'
