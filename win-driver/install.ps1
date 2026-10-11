<#
  install.ps1 — 安装/更新 Windows 内核数据面驱动（需要管理员）。

  与 Linux 侧 `insmod kernel/iwan.ko` 对应。区别是驱动不会自己加载：
  服务按需启动（StartType=demand），由客户端或本脚本拉起。

  用法：
    .\install.ps1                      # 用默认产物路径
    .\install.ps1 -Sys .\build\x64\Release\iwan.sys
    .\install.ps1 -NoStart             # 只注册与拷贝，不启动
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
    throw "找不到驱动文件：$Sys（先在装了 WDK 的机器上 msbuild win-driver\iwan.vcxproj）"
}

# WFP 依赖 Base Filtering Engine
$bfe = Get-Service -Name BFE -ErrorAction SilentlyContinue
if ($bfe -and $bfe.Status -ne 'Running') {
    Write-Host "启动 Base Filtering Engine（WFP 依赖它）..."
    Start-Service BFE
}

Write-Host "拷贝驱动到 $dst"
Copy-Item -Force $Sys $dst

$existing = Get-Service -Name $svc -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "服务已存在，改为更新配置"
    if ($existing.Status -eq 'Running') { & sc.exe stop $svc | Out-Null; Start-Sleep -Seconds 1 }
    & sc.exe config $svc type= kernel start= demand binPath= $dst | Out-Null
} else {
    & sc.exe create $svc type= kernel start= demand binPath= $dst `
        DisplayName= 'iWAN kernel data plane (WFP callout)' | Out-Null
}

if (-not $NoStart) {
    Write-Host "启动服务 $svc"
    & sc.exe start $svc
    Start-Sleep -Milliseconds 500
    & sc.exe query $svc
    Write-Host ""
    Write-Host "自检：windev_probe.exe 应当报告“驱动在位？是”"
    Write-Host "客户端：iwan-client-oidc --connect --server <线路> --data-plane kernel"
}
