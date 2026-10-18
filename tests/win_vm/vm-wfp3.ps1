# 直接看转储里 "iwan in4" 附近的原文，确认层字段的真实写法。
$txt = Get-Content 'C:\iwan\wfp.xml' -Raw
foreach ($n in 'iwan in4', 'iwan out4') {
    $i = $txt.IndexOf($n)
    "===== $n 在第 $i 字节 ====="
    if ($i -ge 0) { $txt.Substring([Math]::Max(0, $i - 200), 1200) }
}
