"=== 引导时间 / 当前时间 ==="
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
(Get-Date).ToString('HH:mm:ss')
"=== 服务 ==="
Get-Service iwan -ErrorAction SilentlyContinue | Select-Object Name,Status | Format-Table -AutoSize
"=== 驱动阶段标记 ==="
$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwan'
foreach ($n in 'TestFlags','WfpStage','RunStage','RunWhat') {
    "{0,-9} = {1}" -f $n, (Get-ItemProperty $k -Name $n -ErrorAction SilentlyContinue).$n
}
"=== 蓝屏事件（Id=1001，最近 3 条）==="
$ev = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -MaxEvents 3 -ErrorAction SilentlyContinue
if ($ev) { $ev | ForEach-Object { "{0}  {1}" -f $_.TimeCreated, (($_.Message -replace "`r`n",' ') -replace '\s+',' ') } }
else { "（无）" }
