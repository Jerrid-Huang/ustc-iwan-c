<#
  testsign.ps1 - Test-sign the driver (admin required, usually one reboot).

  Production signing (EV certificate + Microsoft Hardware Dev Center) is out of scope for this round; test signing is enough to
  load iwan.sys on your own machine/VM.

  Steps and rationale:
    1) bcdedit /set testsigning on -- allow loading test-signed drivers, effective after reboot;
    2) create a self-signed code-signing certificate and install it into "Trusted Root" and "Trusted Publishers",
       otherwise the kernel will refuse to load;
    3) sign iwan.sys with signtool (sha256), then verify it again with signtool verify.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$Sys = "$PSScriptRoot\build\x64\Release\iwan.sys",
    [string]$Subject = 'CN=iWAN Test Signing'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Sys)) { throw "Driver file not found: $Sys" }

$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if (-not $signtool) {
    $cand = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse `
        -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'x64' } | Select-Object -First 1
    if (-not $cand) { throw "signtool.exe not found (install the Windows SDK and retry)" }
    $signtool = $cand.FullName
} else {
    $signtool = $signtool.Source
}

Write-Host "1/3 Enabling test signing (takes effect after reboot)"
& bcdedit /set testsigning on | Out-Null

Write-Host "2/3 Preparing a self-signed certificate"
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq $Subject } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject `
        -CertStoreLocation Cert:\LocalMachine\My -HashAlgorithm SHA256 `
        -KeyUsage DigitalSignature -KeyLength 2048
}
foreach ($store in 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher') {
    $found = Get-ChildItem $store | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
    if (-not $found) {
        Write-Host "  Installing certificate into $store"
        Export-Certificate -Cert $cert -FilePath "$env:TEMP\iwan-testsign.cer" | Out-Null
        Import-Certificate -FilePath "$env:TEMP\iwan-testsign.cer" -CertStoreLocation $store | Out-Null
    }
}

Write-Host "3/3 Signing and verifying"
& $signtool sign /v /fd sha256 /s My /n $Subject $Sys
& $signtool verify /v /pa $Sys

Write-Host ""
Write-Host "If this is the first time enabling testsigning, reboot before running install.ps1 again."
