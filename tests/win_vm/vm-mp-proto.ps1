# Register the protocol component (NetTrans, iwanmp-proto.inf).
#
# Two pitfalls, same root cause as the miniport round:
#   1) In test-signing mode the INF package must have a signed .cat, otherwise netcfg reports 0xe000022f
#      (ERROR_FILE_CATALOG_NOT_FOUND / "does not contain a catalog file").
#   2) CatalogFile= must be written explicitly in the INF for the catalog to be recognized.
# The catalog must contain at least one file, so the same-version iwanmp.sys is staged too.
#
# Usage: powershell -File C:\iwan\vm-mp-proto.ps1 [-Uninstall]
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

if (-not (Test-Path $InfSrc)) { throw "INF does not exist: $InfSrc" }
if (-not (Test-Path $SysSrc)) { throw "SYS does not exist: $SysSrc" }

$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -like "*CN=$CertSubject*" } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { throw "certificate not found CN=$CertSubject" }
"cert: $($cert.Thumbprint)"

if (-not (Test-Path $Stage)) { New-Item -ItemType Directory -Path $Stage -Force | Out-Null }
Get-ChildItem $Stage -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse

$stageInf = Join-Path $Stage 'iwanmp-proto.inf'
$stageSys = Join-Path $Stage 'iwanmp.sys'
$stageCat = Join-Path $Stage 'iwanmp-proto.cat'

# Rebuild the INF line by line: rewrite DriverVer, ensure CatalogFile= exists (never use -match replacement on an array)
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
    if ($verAt -lt 0) { throw 'no DriverVer line in the INF, cannot locate the CatalogFile insertion point' }
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

'--- component instance key (find iwanmp under Control\Network\{4D36E975})'
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

'--- service key Ndi'
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
'--- is our binding in the UpperBind of the first Ethernet adapter'
$cls = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0013'
$lk = Join-Path $cls 'Linkage'
if (Test-Path $lk) {
    $p = Get-ItemProperty -Path $lk -ErrorAction SilentlyContinue
    "  UpperBind: $($p.UpperBind -join ',')"
}
'done'
