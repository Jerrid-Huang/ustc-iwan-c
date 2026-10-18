# 临时诊断用：设置/读取注册表里的分步开关与注册进度。
#
#   -TestFlags 0x20000000  → 入向 callout 注册但不装过滤器
#   -TestFlags 0x40000000  → 入向过滤器照装，但分类函数立刻返回
#   -TestFlags 0x10000000  → 入向两层连 callout 都不注册
#   不传 -TestFlags 则只读当前值。
#
# WfpStage 是驱动写的"最后完成的注册步骤"（重启后仍在）：
#   1=入口 2=out4 层键 3=in4 层键 4=out6 层键 5=in6 层键
#   6=out4 注册完 7=in4 注册完 8=out6 注册完 9=in6 注册完 10=start 返回
#   20=stop 入口 30=会话已放行（数据面从这里开始真的处理报文）
param(
    [string]$TestFlags = '',
    [switch]$Clear
)
$ErrorActionPreference = 'Stop'
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwan'

if ($Clear) {
    Remove-ItemProperty -Path $key -Name TestFlags -ErrorAction SilentlyContinue
    Write-Host "已清除 TestFlags"
} elseif ($TestFlags -ne '') {
    $v = [uint32]$TestFlags
    New-ItemProperty -Path $key -Name TestFlags -PropertyType DWord -Value $v -Force | Out-Null
    Write-Host ("已设置 TestFlags = 0x{0:X8}" -f $v)
}

$cur = (Get-ItemProperty -Path $key -Name TestFlags -ErrorAction SilentlyContinue).TestFlags
if ($null -eq $cur) { Write-Host "TestFlags: （未设置 = 正常路径）" }
else { Write-Host ("TestFlags: 0x{0:X8}" -f [uint32]$cur) }

$stage = (Get-ItemProperty -Path $key -Name WfpStage -ErrorAction SilentlyContinue).WfpStage
if ($null -eq $stage) { Write-Host "WfpStage: （还没写过）" }
else { Write-Host ("WfpStage: {0}" -f [int]$stage) }
