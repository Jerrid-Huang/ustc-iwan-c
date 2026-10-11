<#
  uninstall.ps1 — 停止并卸载内核数据面驱动（需要管理员）。

  与 Linux 侧 `rmmod iwan` 对应。删服务前先停，避免驱动在被引用时消失；
  动态 WFP 会话（FWPM_SESSION_FLAG_DYNAMIC）保证过滤器随引擎句柄关闭一起清掉，
  所以这里不需要额外清规则。
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
        Write-Host "停止服务 $svc"
        & sc.exe stop $svc | Out-Null
        Start-Sleep -Seconds 1
    }
    Write-Host "删除服务 $svc"
    & sc.exe delete $svc | Out-Null
} else {
    Write-Host "服务 $svc 不存在，跳过"
}

if (-not $KeepFile -and (Test-Path $dst)) {
    Write-Host "删除 $dst"
    Remove-Item -Force $dst
}
Write-Host "完成。确认残留：sc.exe query $svc 应报服务不存在；设备 \\\\.\\iwan 应打不开。"
