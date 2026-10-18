# 把 WFP 实际状态导出成 XML，打印我方四个过滤器/呼出真正落在哪一层。
# 这是"过滤器挂在哪层"的权威答案 —— 不靠枚举值猜、也不靠文档对。
$xml = 'C:\iwan\wfp.xml'
if (Test-Path $xml) { Remove-Item $xml -Force -ErrorAction SilentlyContinue }
netsh wfp show state file=$xml | Out-Null
if (-not (Test-Path $xml)) { '导不出来（netsh wfp 不可用？）'; exit 1 }
"导出完成：{0:N1} MB" -f ((Get-Item $xml).Length / 1MB)

$expect = @{
    'iwan out4' = '1e5c9fae-8a84-4135-a331-950b54229ecd'
    'iwan in4'  = '5926dfc8-e3cf-4426-a283-dc393f5d0f9d'
    'iwan out6' = 'a3b3ab6b-3564-488c-9117-f34e82142763'
    'iwan in6'  = '634a869f-fc23-4b90-b0c1-bf620a36ae6f'
}
[xml]$doc = Get-Content $xml -Raw
$seen = 0
foreach ($it in $doc.SelectNodes('//item')) {
    $nm = $it.SelectSingleNode('.//name')
    if ($nm -and $nm.InnerText -like 'iwan*') {
        $seen++
        $lk = $it.SelectSingleNode('./layerKey')
        $at = $it.SelectSingleNode('./action/type')
        $got = if ($lk) { $lk.InnerText.Trim('{}').ToLower() } else { '（无 layerKey 字段）' }
        $exp = $expect[$nm.InnerText]
        $verdict = if ($exp -and $got -eq $exp) { '一致' } elseif ($exp) { '不一致 <== 注意' } else { '' }
        "{0} | 实际层 {1} | 期望 {2} | {3} | action={4}" -f `
            $nm.InnerText, $got, $exp, $verdict, $(if ($at) { $at.InnerText } else { '-' })
    }
}
"共找到 {0} 条 iwan* 条目" -f $seen
