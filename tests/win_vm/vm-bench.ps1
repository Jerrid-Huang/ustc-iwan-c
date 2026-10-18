# Windows 客体侧吞吐打流/收流（内层净荷计量，口径对齐 tests/bench_proto.sh）。
#
# 为什么用 C#：客体上没有编译器，PowerShell 循环只能跑几千 pps（那是尺子不是
# 隧道），Add-Type 现场编译一段 C# 能到几十万 pps，且不需要额外工具链。
#
# 为什么要多线程：单线程 C# Send/ReceiveFrom 约 3 万 pps（实测 30228 pps /
# 290 Mbps），拿它量内核数据面只会量到尺子。**先量尺子再量隧道**：不开会话跑
# 一遍同参数的基准，就是这台客体用户态栈的上限。
#
# 用法（由宿主侧脚本调用，别手敲嵌套引号）：
#   powershell -File C:\iwan\vm-bench.ps1 -Mode sink -Port 9999 -Seconds 20 -Threads 4
#   powershell -File C:\iwan\vm-bench.ps1 -Mode gen -Dst 10.99.0.2 -Dport 9999 -Seconds 20 -Threads 4
#
# 输出一行可解析汇总（纯 ASCII，避免控制台编码把证据吃掉）：
#   BENCH role=sink pkts=N bytes=N elapsed_ms=N rate_pps=N rate_mbps=N srcs=N src0=IP:PORT
param(
    [string]$Mode  = 'sink',
    [string]$Bind  = '0.0.0.0',
    [int]   $Port  = 9999,
    [int]   $Sport = 0,
    [string]$Dst   = '10.99.0.2',
    [int]   $Dport = 9999,
    [int]   $Seconds = 20,
    [int]   $Bytes = 1200,
    [int]   $Threads = 4,
    [int]   $Pps = 0,
    [int]   $WarmupMs = 0
)

[Console]::OutputEncoding = [Text.Encoding]::UTF8

$cs = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;

public class IwanBench
{
    static long _pkts;
    static long _bytes;
    static long _deadlineMs;
    static volatile bool _stop;

    static bool Live(Stopwatch sw) { return !_stop && sw.ElapsedMilliseconds < _deadlineMs; }

    // 收：收到即丢，只数净荷。srcs 用来证明包确实来自驱动注入那条路
    // （内层源地址应当只有一个），而不是别的路径漏过来的。
    // 多个线程对同一个 UDP socket 并发 ReceiveFrom 是允许的（内核串行取包），
    // 这样接收侧不会成为尺子。
    public static string Sink(string bind, int port, int seconds, int threads)
    {
        Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        s.ReceiveBufferSize = 8 << 20;
        // 必须设收超时：否则没流量时 ReceiveFrom 永久阻塞，Live() 的时限检查
        // 只在两次收包之间才轮到 —— 收流器会一直挂到被杀，什么都不打印。
        s.ReceiveTimeout = 200;
        s.Bind(new IPEndPoint(IPAddress.Parse(bind), port));
        if (threads < 1) threads = 1;
        _pkts = 0; _bytes = 0; _stop = false;
        Stopwatch sw = Stopwatch.StartNew();
        _deadlineMs = (long)seconds * 1000;
        HashSet<string> srcs = new HashSet<string>();
        string src0 = "";
        Thread[] th = new Thread[threads];
        for (int i = 0; i < threads; i++)
        {
            th[i] = new Thread(delegate() {
                byte[] buf = new byte[65536];
                EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                while (Live(sw))
                {
                    int n;
                    try { n = s.ReceiveFrom(buf, ref from); }
                    catch (SocketException) { continue; }
                    Interlocked.Increment(ref _pkts);
                    Interlocked.Add(ref _bytes, n);
                    if (srcs.Count < 64) { lock (srcs) { srcs.Add(from.ToString()); } }
                }
            });
            th[i].IsBackground = true;
            th[i].Start();
        }
        // 头一个包单独看一眼来源：主线程也参与收，顺便记录 src0
        byte[] b0 = new byte[65536];
        EndPoint f0 = new IPEndPoint(IPAddress.Any, 0);
        while (Live(sw))
        {
            int n;
            try { n = s.ReceiveFrom(b0, ref f0); }
            catch (SocketException) { continue; }
            Interlocked.Increment(ref _pkts);
            Interlocked.Add(ref _bytes, n);
            if (src0.Length == 0) src0 = f0.ToString();
            lock (srcs) { srcs.Add(f0.ToString()); }
        }
        _stop = true;
        for (int i = 0; i < threads; i++) th[i].Join(2000);
        sw.Stop();
        s.Close();
        string extra = " srcs=" + srcs.Count + " src0=" + src0
                     + " threads=" + threads + " cpu=" + Environment.ProcessorCount;
        return Fmt("sink", Interlocked.Read(ref _pkts), Interlocked.Read(ref _bytes),
                   sw.Elapsed.TotalSeconds, extra);
    }

    // 发：缓冲区提前建好，循环里只做 Send。每个线程一个 socket（绑定 Sport 时
    // 只有第一个线程绑，其余用临时端口 —— 隧道闸门看的是外层目的端口，标定
    // 内层容量时不必强求同源端口）。
    public static string Gen(string bind, int sport, string dst, int dport, int seconds,
                             int size, int threads, int warmupMs, int pps)
    {
        // 限速（0 = 不限）：目标整机 Pps 按线程均分，粒度取约 1 ms 的突发
        // （最多 64 包）。先 Sleep 再自旋 —— 单靠 Sleep 会被 15.6 ms 的
        // 时钟粒度打成几百 pps，那样测到的就不是"给定速率下的容量"。
        int burst = 64;
        long periodTicks = 0;
        if (pps > 0)
        {
            int per = pps / threads; if (per < 1) per = 1;
            burst = per / 1000; if (burst < 1) burst = 1; if (burst > 64) burst = 64;
            periodTicks = Stopwatch.Frequency * (long)burst * (long)threads / pps;
        }
        if (threads < 1) threads = 1;
        if (warmupMs > 0) Thread.Sleep(warmupMs);
        _pkts = 0; _bytes = 0; _stop = false;
        Stopwatch sw = Stopwatch.StartNew();
        _deadlineMs = (long)seconds * 1000;
        Thread[] th = new Thread[threads];
        for (int i = 0; i < threads; i++)
        {
            int idx = i;
            th[i] = new Thread(delegate() {
                Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                s.SendBufferSize = 4 << 20;
        s.SendTimeout = 500;   // 发送缓冲满时也别永久阻塞
                if (sport != 0 && idx == 0)
                    s.Bind(new IPEndPoint(IPAddress.Parse(bind), sport));
                s.Connect(new IPEndPoint(IPAddress.Parse(dst), dport));
                byte[] buf = new byte[size];
                for (int k = 0; k < size; k++) buf[k] = (byte)(k & 0xFF);
                long p = 0, b = 0;
                long nextTick = sw.ElapsedTicks;
                while (Live(sw))
                {
                    if (periodTicks > 0)
                    {
                        long now = sw.ElapsedTicks;
                        if (now < nextTick)
                        {
                            long waitMs = (nextTick - now) * 1000 / Stopwatch.Frequency;
                            if (waitMs > 1) Thread.Sleep((int)(waitMs - 1));
                            while (sw.ElapsedTicks < nextTick) Thread.SpinWait(20);
                        }
                        nextTick += periodTicks;
                        if (nextTick < sw.ElapsedTicks) nextTick = sw.ElapsedTicks;
                    }
                    for (int k = 0; k < burst; k++)
                    {
                        try { s.Send(buf); }
                        catch (SocketException) { break; }
                        p++; b += size;
                    }
                }
                Interlocked.Add(ref _pkts, p);
                Interlocked.Add(ref _bytes, b);
                s.Close();
            });
            th[i].IsBackground = true;
            th[i].Start();
        }
        while (Live(sw)) Thread.Sleep(20);
        _stop = true;
        for (int i = 0; i < threads; i++) th[i].Join(3000);
        sw.Stop();
        string extra = " threads=" + threads + " cpu=" + Environment.ProcessorCount
                     + " payload=" + size + " pps_target=" + pps;
        return Fmt("gen", Interlocked.Read(ref _pkts), Interlocked.Read(ref _bytes),
                   sw.Elapsed.TotalSeconds, extra);
    }

    // 自环：同一进程内一边发一边收。用途是标定这台客机"内层用户态 -> 网卡 ->
    // 用户态"的上限，同时验证目标地址确实会回环（收不到就说明包被丢了，
    // 而不是尺子不准）。
    public static string Loop(string dst, int port, int seconds, int size, int threads)
    {
        Socket r = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        r.ReceiveBufferSize = 8 << 20;
        r.ReceiveTimeout = 200;
        r.Bind(new IPEndPoint(IPAddress.Any, port));
        if (threads < 1) threads = 1;
        _pkts = 0; _bytes = 0; _stop = false;
        Stopwatch sw = Stopwatch.StartNew();
        _deadlineMs = (long)seconds * 1000;
        Thread[] rt = new Thread[threads];
        for (int i = 0; i < threads; i++)
        {
            rt[i] = new Thread(delegate() {
                byte[] buf = new byte[65536];
                EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                while (Live(sw))
                {
                    int n;
                    try { n = r.ReceiveFrom(buf, ref from); }
                    catch (SocketException) { continue; }
                    Interlocked.Increment(ref _pkts);
                    Interlocked.Add(ref _bytes, n);
                }
            });
            rt[i].IsBackground = true; rt[i].Start();
        }
        long sp = 0, sb = 0;
        Thread[] st = new Thread[threads];
        for (int i = 0; i < threads; i++)
        {
            st[i] = new Thread(delegate() {
                Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                s.SendBufferSize = 4 << 20;
                s.SendTimeout = 500;
                s.Connect(new IPEndPoint(IPAddress.Parse(dst), port));
                byte[] buf = new byte[size];
                long p = 0, b = 0;
                while (Live(sw))
                {
                    for (int k = 0; k < 64; k++)
                    {
                        try { s.Send(buf); } catch (SocketException) { break; }
                        p++; b += size;
                    }
                }
                Interlocked.Add(ref sp, p); Interlocked.Add(ref sb, b);
                s.Close();
            });
            st[i].IsBackground = true; st[i].Start();
        }
        while (Live(sw)) Thread.Sleep(20);
        _stop = true;
        for (int i = 0; i < threads; i++) { rt[i].Join(2000); st[i].Join(2000); }
        sw.Stop();
        r.Close();
        string extra = " threads=" + threads + " cpu=" + Environment.ProcessorCount
                     + " payload=" + size + " dst=" + dst + ":" + port
                     + " recv_pkts=" + Interlocked.Read(ref _pkts)
                     + " recv_mbps=" + (sw.Elapsed.TotalSeconds > 0
                        ? (Interlocked.Read(ref _bytes) * 8.0 / sw.Elapsed.TotalSeconds / 1e6) : 0).ToString("F1");
        return Fmt("loop", sp, sb, sw.Elapsed.TotalSeconds, extra);
    }

    static string Fmt(string role, long pkts, long bytes, double sec, string extra)
    {
        double pps = sec > 0 ? pkts / sec : 0;
        double mbps = sec > 0 ? bytes * 8.0 / sec / 1e6 : 0;
        return string.Format(
            "BENCH role={0} pkts={1} bytes={2} elapsed_ms={3} rate_pps={4:F0} rate_mbps={5:F1}{6}",
            role, pkts, bytes, (long)(sec * 1000), pps, mbps, extra);
    }
}
'@

Add-Type -TypeDefinition $cs -Language CSharp | Out-Null

switch ($Mode) {
    'sink' { [IwanBench]::Sink($Bind, $Port, $Seconds, $Threads) }
    'gen'  { [IwanBench]::Gen($Bind, $Sport, $Dst, $Dport, $Seconds, $Bytes, $Threads, $WarmupMs, $Pps) }
    'loop' { [IwanBench]::Loop($Dst, $Dport, $Seconds, $Bytes, $Threads) }
    default { "unknown mode $Mode"; exit 2 }
}
