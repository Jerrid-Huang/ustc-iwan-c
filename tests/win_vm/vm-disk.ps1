# 看客体 C: 还剩多少，并列出候选清理目录的体积（只读，不删）。
Get-PSDrive C | ForEach-Object { "C: 已用 {0:N1} GB / 可用 {1:N1} GB" -f ($_.Used/1GB), ($_.Free/1GB) }
$dirs = @('C:\Users\administrator\AppData\Local\Temp', 'C:\Windows\Temp',
          'C:\Windows\SoftwareDistribution\Download', 'C:\Windows\Minidump',
          'C:\iwan', 'C:\Windows\LiveKernelReports', 'C:\ProgramData\Microsoft\Windows\WER')
foreach ($d in $dirs) {
    if (Test-Path $d) {
        $m = Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Sum Length
        "{0} -> {1} 个文件 {2:N1} MB" -f $d, $m.Count, ($m.Sum / 1MB)
    }
}
