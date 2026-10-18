"=== powershell 进程 ==="
Get-Process powershell -ErrorAction SilentlyContinue |
    Select-Object Id, StartTime, @{n='CPU(s)';e={[math]::Round($_.CPU,1)}} | Format-Table -AutoSize
"=== 谁占着 \\.\iwan（用 handle 查不到就跳过）==="
"=== rx-out.txt ==="
if (Test-Path C:\iwan\rx-out.txt) { "大小 = {0}" -f (Get-Item C:\iwan\rx-out.txt).Length; Get-Content C:\iwan\rx-out.txt -Encoding UTF8 -Tail 20 } else { "（无）" }
"=== rx-err.txt ==="
if (Test-Path C:\iwan\rx-err.txt) { "大小 = {0}" -f (Get-Item C:\iwan\rx-err.txt).Length; Get-Content C:\iwan\rx-err.txt -Encoding UTF8 -Tail 10 } else { "（无）" }
$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwan'
foreach ($n in 'TestFlags','WfpStage','RunStage','RunWhat') {
    "{0,-9} = {1}" -f $n, (Get-ItemProperty $k -Name $n -ErrorAction SilentlyContinue).$n
}
