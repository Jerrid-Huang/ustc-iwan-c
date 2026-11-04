<#
  uninstall.ps1 - Stop and uninstall the kernel data-plane driver (admin required).

  Counterpart of the Linux side `rmmod iwan`. Stop the service before deleting it, so the driver does not disappear while still referenced;
  a dynamic WFP session (FWPM_SESSION_FLAG_DYNAMIC) ensures filters are cleaned up when the engine handle closes,
  so no extra rule cleanup is needed here.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$KeepFile)

$ErrorActionPreference = 'Stop'
$svc = 'iwan'
$dst = Join-Path $env:SystemRoot 'System32\drivers\iwan.sys'

$existing = Get-Service -Name $svc -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -eq 'Running') {
        Write-Host "Stopping service $svc"
        & sc.exe stop $svc | Out-Null
        Start-Sleep -Seconds 1
    }
    Write-Host "Deleting service $svc"
    & sc.exe delete $svc | Out-Null
} else {
    Write-Host "Service $svc does not exist, skipping"
}

if (-not $KeepFile -and (Test-Path $dst)) {
    Write-Host "Deleting $dst"
    Remove-Item -Force $dst
}
Write-Host "Done. Check for leftovers: sc.exe query $svc should report that the service does not exist; device \\\\.\\iwan should fail to open."
