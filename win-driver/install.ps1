<#
  install.ps1 - Install/update the Windows kernel data-plane driver (admin required).

  Counterpart of the Linux side `insmod kernel/iwan.ko`. The difference: the driver does not load itself:
  the service starts on demand (StartType=demand), brought up by the client or this script.

  Usage:
    .\install.ps1                      # use the default artifact path
    .\install.ps1 -Sys .\build\x64\Release\iwan.sys
    .\install.ps1 -NoStart             # register and copy only, do not start
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$Sys = "$PSScriptRoot\build\x64\Release\iwan.sys",
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
$svc = 'iwan'
$dst = Join-Path $env:SystemRoot 'System32\drivers\iwan.sys'

if (-not (Test-Path $Sys)) {
    throw "Driver file not found: $Sys (first run msbuild win-driver\iwan.vcxproj on a machine with the WDK installed)"
}

# WFP depends on the Base Filtering Engine
$bfe = Get-Service -Name BFE -ErrorAction SilentlyContinue
if ($bfe -and $bfe.Status -ne 'Running') {
    Write-Host "Starting Base Filtering Engine (WFP depends on it)..."
    Start-Service BFE
}

Write-Host "Copying driver to $dst"
Copy-Item -Force $Sys $dst

$existing = Get-Service -Name $svc -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Service already exists; updating its configuration instead"
    if ($existing.Status -eq 'Running') { & sc.exe stop $svc | Out-Null; Start-Sleep -Seconds 1 }
    & sc.exe config $svc type= kernel start= demand binPath= $dst | Out-Null
} else {
    & sc.exe create $svc type= kernel start= demand binPath= $dst `
        DisplayName= 'iWAN kernel data plane (WFP callout)' | Out-Null
}

if (-not $NoStart) {
    Write-Host "Starting service $svc"
    & sc.exe start $svc
    Start-Sleep -Milliseconds 500
    & sc.exe query $svc
    Write-Host ""
    Write-Host "Self-check: windev_probe.exe should report 'driver present? yes'"
    Write-Host "Client: iwan-client-oidc --connect --server <route> --data-plane kernel"
}
