# Install the iwanmp (NDIS miniport + protocol driver) driver package on the nano11 guest.
#
# Three hurdles are solved here once and for all (historical lessons; if any is missed install fails):
#   1) In test-signing mode the INF package must carry a **signed .cat**; signing only the .sys is not enough;
#   2) Reinstall must rewrite DriverVer, otherwise SetupAPI will not copy the new .sys into System32\drivers;
#   3) The package must explicitly set CatalogFile=, otherwise it reports "Driver package does not contain a
#      catalog file" (0xE000022F).
#
# This script also does one safety thing: it closes the fuse **before install**
# (HKLM\SYSTEM\CurrentControlSet\Services\iwanmp\Parameters\Disarm=1).
# That way, when PnP first starts the root-enumerated device, DriverEntry fails
# before any NDIS call (device stays at Code 10), proving the load path itself cannot crash the machine.
# To actually load, open the fuse with vm-mp-arm.ps1.
#
# Usage: powershell -NoProfile -File vm-mp-install.ps1 -InfPath C:\iwan\iwanmp.inf -SysPath C:\iwan\iwanmp.sys
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

# The device instance ID is not fixed: devcon install creates a node per the INF Class, and it lands
# in ROOT\NET\000x (early scripts hardcoded ROOT\IWANMP\0000, a guess that never worked).
function Get-IwanmpInstanceId {
    $d = Get-PnpDevice -ErrorAction SilentlyContinue |
         Where-Object { $_.HardwareID -contains 'iwanmp' } |
         Select-Object -First 1
    if ($d) { return $d.InstanceId }
    return ''
}
if (-not $InstanceId) { $InstanceId = Get-IwanmpInstanceId }

if (-not (Test-Path $InfPath)) { throw "not found: $InfPath" }
if (-not (Test-Path $SysPath)) { throw "not found: $SysPath" }
if (-not (Test-Path 'C:\iwan\devcon.exe')) { throw 'not found: C:\iwan\devcon.exe' }

Sec 'source files'
Get-Item $InfPath, $SysPath | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
Get-FileHash $SysPath -Algorithm MD5 | Select-Object Hash, Path | Format-List

# 1) Certificate (reuse the self-signed code-signing cert from vm-load.ps1)
Sec 'certificate'
$cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date) } |
        Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $CertSubject `
            -CertStoreLocation Cert:\LocalMachine\My -KeyUsage DigitalSignature `
            -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(3)
    'creating new certificate'
} else {
    'reusing existing certificate'
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
        "public key added to $store"
    } else {
        "$store already has it"
    }
}

# 2) Staging dir: hold only the two package files so the catalog does not pull unrelated files into the member table
Sec 'staging dir'
if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
New-Item -ItemType Directory -Path $Stage | Out-Null
$stageInf = Join-Path $Stage 'iwanmp.inf'
$stageSys = Join-Path $Stage 'iwanmp.sys'
$stageCat = Join-Path $Stage 'iwanmp.cat'

# 3) Rewrite DriverVer + add CatalogFile (rebuild line by line, never use -match to replace an array)
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
    if ($verAt -lt 0) { throw 'no DriverVer line in INF' }
    $out.Insert($verAt + 1, 'CatalogFile     = iwanmp.cat')
}
[System.IO.File]::WriteAllLines($stageInf, $out, (New-Object System.Text.ASCIIEncoding))
Copy-Item $SysPath $stageSys -Force
Sec 'rewritten [Version] section'
Get-Content $stageInf | Select-Object -First 25 | Where-Object { $_ -match 'DriverVer|CatalogFile|Class|Provider' }

# 4) Catalog file + signing
Sec 'catalog file and signing'
New-FileCatalog -Path $Stage -CatalogFilePath $stageCat -CatalogVersion 2 | Out-Null
$r1 = Set-AuthenticodeSignature -FilePath $stageSys -Certificate $cert -HashAlgorithm SHA256
"sys: $($r1.Status)"
$r2 = Set-AuthenticodeSignature -FilePath $stageCat -Certificate $cert -HashAlgorithm SHA256
"cat: $($r2.Status)"
Get-AuthenticodeSignature $stageSys, $stageCat | Select-Object Status, Path | Format-Table -AutoSize
if ((Get-AuthenticodeSignature $stageCat).Status -ne 'Valid') { throw 'invalid .cat signature' }

# 5) Close the fuse (must be before install: the first start must be blocked)
Sec 'fuse (closed before install)'
$pkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwanmp\Parameters'
if (-not (Test-Path $pkey)) { New-Item -Path $pkey -Force | Out-Null }
New-ItemProperty -Path $pkey -Name 'Disarm' -PropertyType DWord -Value 1 -Force | Out-Null
Get-ItemProperty $pkey | Format-List

# 6) Remove any stale old iwanmp package from the DriverStore (otherwise it may install the old image)
Sec 'DriverStore cleanup'
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
    'no stale packages'
} else {
    foreach ($oem in $stale) {
        "deleting $oem"
        & pnputil.exe /delete-driver $oem /uninstall /force 2>&1 | Out-String
    }
}

# 7) Install
Sec 'devcon install'
$dev = & C:\iwan\devcon.exe install $stageInf $Hwid 2>&1 | Out-String
$dev

Sec 'device state'
$devs = @(Get-PnpDevice -ErrorAction SilentlyContinue |
          Where-Object { $_.HardwareID -contains 'iwanmp' })
$devs | Select-Object Status, Class, FriendlyName, InstanceId, Problem, ProblemDescription |
    Format-List
foreach ($d in $devs) {
    Get-PnpDeviceProperty -InstanceId $d.InstanceId -ErrorAction SilentlyContinue |
        Where-Object { $_.KeyName -match 'ProblemCode|DeviceDesc|Service|DriverVersion' } |
        Select-Object KeyName, Data | Format-Table -AutoSize
}

Sec 'service state'
Get-Service -Name iwanmp -ErrorAction SilentlyContinue |
    Select-Object Name, Status, ServiceType, StartType | Format-List

Sec 'staged trace keys'
$p = Get-ItemProperty $pkey -ErrorAction SilentlyContinue
foreach ($n in 'Stage', 'Status', 'Disarm', 'NoProto') {
    if ($p.PSObject.Properties.Name -contains $n) { "  {0,-10} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n }
}
$tkeys = @($p.PSObject.Properties.Name | Where-Object { $_ -match '^T\d+$' })
foreach ($n in ($tkeys | Sort-Object { [int]($_.Substring(1)) })) {
    "  {0,-10} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n
}

Sec 'recent Kernel-PnP events'
Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = (Get-Date).AddMinutes(-5) } `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'Kernel-PnP' } |
    Select-Object -First 6 |
    ForEach-Object { "{0} [{1}] {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ') }

Sec 'conclusion hints'
'fuse is closed (Disarm=1): device should stay at Code 10, T8=1, T9=0xC0000001,'
'and there should be NO keys after T10/T11/T30 -- which proves DriverEntry exited before any NDIS call.'
