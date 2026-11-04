# Windows guest side throughput generator/sink (inner payload accounting, same units as tests/bench_proto.sh).
#
# Why C#: the guest has no compiler, and a PowerShell loop only reaches a few thousand pps (that is a ruler,
# not a tunnel); Add-Type compiles a C# snippet on the spot to hundreds of thousands of pps, with no extra toolchain.
#
# Why multithreaded: single-threaded C# Send/ReceiveFrom is about 30k pps (measured 30228 pps /
# 290 Mbps), so using it to measure the kernel data plane only measures the ruler. Measure the ruler first, then the tunnel:
# run the same-parameter baseline without a session to get this guest user-space stack's ceiling.
#
# Usage (called by host-side scripts; do not hand-type nested quotes):
#   powershell -File C:\iwan\vm-bench.ps1 -Mode sink -Port 9999 -Seconds 20 -Threads 4
#   powershell -File C:\iwan\vm-bench.ps1 -Mode gen -Dst 10.99.0.2 -Dport 9999 -Seconds 20 -Threads 4
#
# Print one parseable summary line (pure ASCII, so console encoding does not eat the evidence):
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

    // Receive: drop on arrival, count payload only. srcs proves packets really came from the driver injection path
    // (the inner source address should be a single one), not leaked from some other path.
    // Multiple threads calling ReceiveFrom on one UDP socket concurrently is allowed (the kernel serializes receives),
    // so the receive side does not become the ruler.
    public static string Sink(string bind, int port, int seconds, int threads)
    {
        Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        s.ReceiveBufferSize = 8 << 20;
        // Must set a receive timeout: otherwise ReceiveFrom blocks forever with no traffic, and the Live() deadline check
        // only runs between receives -- the sink hangs until killed and prints nothing.
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
        // Peek at the source of the first packet separately: the main thread also receives, and records src0 along the way
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

    // Send: buffers are built up front; the loop only calls Send. One socket per thread (when binding Sport,
    // only the first thread binds, the rest use ephemeral ports -- the tunnel gate looks at the outer destination port,
    // so inner capacity calibration does not need the same source port).
    public static string Gen(string bind, int sport, string dst, int dport, int seconds,
                             int size, int threads, int warmupMs, int pps)
    {
        // Rate limit (0 = unlimited): total Pps split evenly across threads, burst granularity about 1 ms
        // (max 64 packets). Sleep first, then spin -- Sleep alone is quantized to 15.6 ms and
        // collapses to a few hundred pps, so what is measured is no longer the capacity at the given rate.
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
        s.SendTimeout = 500;   // do not block forever when the send buffer is full either
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

    // Loopback: send and receive in the same process. Used to calibrate this guest
    // inner user space -> NIC -> user space ceiling, and to verify the target address really loops back
    // (if nothing arrives, packets were dropped, not the ruler being off).
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
