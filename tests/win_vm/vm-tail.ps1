# 一次读完：驱动阶段标记 + 脚本进度 + 测试输出尾部
$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwan'
"--- 驱动/脚本阶段 ---"
foreach ($n in 'TestFlags','WfpStage','RunStage','RunWhat') {
    "{0,-9} = {1}" -f $n, (Get-ItemProperty $k -Name $n -ErrorAction SilentlyContinue).$n
}
"服务状态 = {0}" -f (Get-Service iwan -ErrorAction SilentlyContinue).Status
"--- rx-out.txt 尾部 ---"
if (Test-Path C:\iwan\rx-out.txt) { Get-Content C:\iwan\rx-out.txt -Encoding UTF8 -Tail 22 } else { "（没有 rx-out.txt）" }
"--- rx-err.txt 尾部 ---"
if (Test-Path C:\iwan\rx-err.txt) { Get-Content C:\iwan\rx-err.txt -Encoding UTF8 -Tail 8 } else { "（没有 rx-err.txt）" }
