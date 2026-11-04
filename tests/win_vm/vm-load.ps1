# Sign and load iwan.sys in the nano11 VM -- only decides "can it install, can it start".
#
# Precondition: testsigning is already Yes (VM prepared), Administrator elevated.
# This script installs no toolchain and uses only built-in capabilities:
#   New-SelfSignedCertificate  create a code-signing certificate
#   Set-AuthenticodeSignature  embed an Authenticode signature into the .sys
#   sc.exe                     create and start as a "kernel service" (not PnP, no INF needed)
#
# Usage: powershell -NoProfile -File vm-load.ps1 -SysPath C:\iwan\iwan.sys
param(
    [string]$SysPath = 'C:\iwan\iwan.sys',
    [string]$ServiceName = 'iwan',
    [string]$CertSubject = 'CN=iwan win-driver test'
)

$ErrorActionPreference = 'Stop'

function Sec($t) { "`n=== $t ===" }

if (-not (Test-Path $SysPath)) { throw "cannot find $SysPath" }
$sys = (Resolve-Path $SysPath).Path
Sec "driver file"
Get-Item $sys | Select-Object FullName, Length, LastWriteTime | Format-List

# 1) Certificate: self-sign a code-signing cert; public key goes into Root + TrustedPublisher (test-signing requirement)
Sec 'certificate'
$cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date) } |
        Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $CertSubject `
            -CertStoreLocation Cert:\LocalMachine\My -KeyUsage DigitalSignature `
            -KeyLength 2048 -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddYears(3)
    'create new certificate'
} else {
    'reuse existing certificate'
}
$cert | Select-Object Subject, Thumbprint, NotAfter | Format-List
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
        "already in $store"
    }
}

# 2) embedded signature
Sec 'signature'
$res = Set-AuthenticodeSignature -FilePath $sys -Certificate $cert -HashAlgorithm SHA256
$res | Select-Object Status, StatusMessage | Format-List
Get-AuthenticodeSignature $sys | Select-Object Status, SignerCertificate | Format-List

# 3) create and start as a kernel service (WDM driver, demand start)
Sec 'service'
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    "service $ServiceName already exists (status $($existing.Status)), stopping and deleting first"
    sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 1
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}
sc.exe create $ServiceName type= kernel start= demand error= normal binPath= $sys | Out-String
sc.exe start $ServiceName | Out-String
Start-Sleep -Seconds 2

Sec 'service status'
sc.exe query $ServiceName | Out-String
Get-Service -Name $ServiceName -ErrorAction SilentlyContinue |
    Select-Object Name, Status, ServiceType | Format-List

# 4) On failure, dig out the SCM records (all load-failure reasons are here: NTSTATUS)
Sec 'recent SCM / kernel load records'
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    StartTime = (Get-Date).AddMinutes(-5)
} -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'Service Control Manager|Kernel-PnP|Kernel-Plugin' } |
    Select-Object -First 8 |
    ForEach-Object { "{0} [{1}] {2}" -f $_.TimeCreated, $_.ProviderName, ($_.Message -replace '\s+', ' ') }

# 5) Is the driver really running: device object, WFP callout
Sec 'device object and service process'
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    $svc = Get-CimInstance Win32_SystemDriver -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($svc) { $svc | Select-Object Name, State, Started, PathName | Format-List }
}

Sec 'does WFP contain our callout'
$wfp = Join-Path $env:TEMP 'wfp-state.xml'
netsh wfp show state file="$wfp" | Out-Null
if (Test-Path $wfp) {
    $txt = Get-Content $wfp -Raw
    "state file size $((Get-Item $wfp).Length) bytes"
    foreach ($kw in 'iwan', 'IWAN', 'Iwan') {
        $n = ([regex]::Matches($txt, $kw)).Count
        if ($n -gt 0) { "contains '$kw' $n times" }
    }
    Remove-Item $wfp -Force
} else {
    'netsh wfp show state produced no file'
}

Sec 'conclusion hints'
'Service State=Running and no SCM error -> driver loaded successfully; otherwise check the NTSTATUS in the SCM records above.'
