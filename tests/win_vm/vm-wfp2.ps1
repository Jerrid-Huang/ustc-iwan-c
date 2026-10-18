# 会话开着（过滤器正在生效）时导出 WFP 实际状态，看我方过滤器真正挂在哪一层。
# 用正则切 <item>，不用 [xml]（后者在这种几十 MB 的转储上直接失败过）。
$xml = 'C:\iwan\wfp.xml'
if (Test-Path $xml) { Remove-Item $xml -Force -ErrorAction SilentlyContinue }
& powershell -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-sess-keep.ps1 | Out-Null
Start-Sleep -Seconds 2
netsh wfp show state file=$xml | Out-Null
if (-not (Test-Path $xml)) { '导不出来（netsh wfp 不可用？）'; exit 1 }
"导出完成：{0:N1} MB" -f ((Get-Item $xml).Length / 1MB)

$expect = @{
    'iwan out4' = '1e5c9fae-8a84-4135-a331-950b54229ecd'
    'iwan in4'  = '5926dfc8-e3cf-4426-a283-dc393f5d0f9d'
    'iwan out6' = 'a3b3ab6b-3564-488c-9117-f34e82142763'
    'iwan in6'  = '634a869f-fc23-4b90-b0c1-bf620a36ae6f'
}
$txt = Get-Content $xml -Raw
$i = 0
foreach ($c in ($txt -split '<item>')) {
    if ($c -match '<name>\s*(iwan [A-Za-z0-9_]+)\s*</name>') {
        $i++
        $nm = $Matches[1]
        $lk = if ($c -match '<layerKey>\{?([0-9a-fA-F\-]{36})\}?</layerKey>') { $Matches[1].ToLower() } `
              elseif ($c -match '<applicableLayer>\{?([0-9a-fA-F\-]{36})\}?</applicableLayer>') { $Matches[1].ToLower() } `
              else { '（没带层字段）' }
        $exp = $expect[$nm]
        $tag = if ($exp -and $lk -eq $exp) { '一致' } elseif ($exp) { '不一致 <== 注意' } else { '' }
        "{0} | 实际 {1} | 期望 {2} | {3}" -f $nm, $lk, $exp, $tag
    }
}
"共 {0} 条 iwan* 条目" -f $i
sc.exe stop iwan | Out-Null
