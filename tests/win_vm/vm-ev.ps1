"=== 最近的关键系统事件（41=掉电/挂起 1001=BugCheck 6008=非正常关机）==="
Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,1001,6008} -MaxEvents 8 -ErrorAction SilentlyContinue |
  ForEach-Object {
    $m = ($_.Message -replace "`r`n", ' ') -replace '\s+', ' '
    if ($m.Length -gt 100) { $m = $m.Substring(0, 100) }
    "{0}  Id={1}  {2}" -f $_.TimeCreated, $_.Id, $m
  }
"=== rx-stats.txt ==="
if (Test-Path C:\iwan\rx-stats.txt) { Get-Content C:\iwan\rx-stats.txt } else { "（没有）" }
"=== rx-out.txt 尾部 ==="
if (Test-Path C:\iwan\rx-out.txt) { Get-Content C:\iwan\rx-out.txt -Tail 12 } else { "（没有）" }
