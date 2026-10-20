/* 内层打流器：比 vm-bench.ps1 里的 C# 版强一个量级。
 *
 * 为什么另写一个：C# 版每包一次 UdpClient.Send，4 线程只到 63k pps，
 * 而这个数正好压在"驱动的封装上限到底在哪"的判据上 —— 发生器先饱和，
 * 就测不出隧道的能力。这里每线程独占一个 socket、纯 sendto 紧循环。
 *
 * 交叉编译（宿主）：
 *   x86_64-w64-mingw32-gcc -O2 -std=c11 -Wall -Wextra -o tests/win_gen.exe tests/win_gen.c -lws2_32
 *
 * 用法（客体）：
 *   win_gen.exe -d 10.99.0.2 -p 45678 -B 10.99.0.1 -b 1200 -t 4 -S 10 [-r 200000]
 *     -r 0 表示不限速；每线程的源端口 = -s + 线程序号，避免同 5 元组互相排队。
 * 输出：
 *   GEN pkts=... bytes=... elapsed_ms=... rate_pps=... rate_mbps=... threads=... err=...
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *bindip;
    const char *dst;
    int dport;
    int sport;
    int bytes;
    int seconds;
    long long target_pps;   /* 0 = 不限 */
    int index;
    long long pkts;
    long long bytes_sent;
    long long err;
} GEN_THREAD;

static unsigned long long now_us(void)
{
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (unsigned long long)((double)c.QuadPart * 1e6 / (double)f.QuadPart);
}

static DWORD WINAPI gen_main(LPVOID arg)
{
    GEN_THREAD *g = (GEN_THREAD *)arg;
    SOCKET s;
    struct sockaddr_in dst;
    struct sockaddr_in src;
    char *buf;
    unsigned long long t0, t_end;
    long long sent = 0, errs = 0, bytes = 0;
    int i;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { g->err = -1; return 1; }

    {
        int sndbuf = 8 << 20;
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char *)&sndbuf, sizeof(sndbuf));
    }

    memset(&src, 0, sizeof(src));
    src.sin_family = AF_INET;
    src.sin_port = htons((unsigned short)(g->sport + g->index));
    /* 显式绑到内层源地址：绑 0.0.0.0 时内核每包重选源，
     * 在点对点媒介上会间歇返回 WSAEINVAL（10022），一半的包发不出去。 */
    if (inet_pton(AF_INET, g->bindip, &src.sin_addr) != 1) src.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, (struct sockaddr *)&src, sizeof(src)) == SOCKET_ERROR) { g->err = -2; closesocket(s); return 1; }

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((unsigned short)g->dport);
    inet_pton(AF_INET, g->dst, &dst.sin_addr);

    buf = (char *)malloc((size_t)g->bytes);
    if (!buf) { g->err = -3; closesocket(s); return 1; }
    for (i = 0; i < g->bytes; i++) buf[i] = (char)(i & 0xFF);

    t0 = now_us();
    t_end = t0 + (unsigned long long)g->seconds * 1000000ULL;

    while (now_us() < t_end) {
        int n = sendto(s, buf, g->bytes, 0, (struct sockaddr *)&dst, sizeof(dst));
        if (n == SOCKET_ERROR) {
            /* 第一次错误必须打出来：不然"发不出去"和"没发"在输出里长得一模一样 */
            if (errs == 0) printf("GEN thread %d first sendto error=%d\n", g->index, WSAGetLastError());
            errs++;
            continue;
        }
        sent++;
        bytes += n;
        if (g->target_pps > 0) {
            long long want_us;
            unsigned long long el = now_us() - t0;
            want_us = sent * 1000000LL / g->target_pps;
            if ((long long)el < want_us) {
                long long gap = want_us - (long long)el;
                if (gap > 2000) Sleep((DWORD)(gap / 1000));
                else if (gap > 200) Sleep(0);
            }
        }
    }

    g->pkts = sent;
    g->bytes_sent = bytes;
    g->err = errs;
    closesocket(s);
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    WSADATA wsa;
    GEN_THREAD *g;
    HANDLE *th;
    const char *dst = "10.99.0.2";
    const char *bindip = "10.99.0.1";
    int dport = 45678, sport = 40001, bytes = 1200, threads = 4, seconds = 10, i;
    long long target = 0;
    unsigned long long t0, t1;
    long long tot = 0, totb = 0, tote = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-d") && i + 1 < argc) dst = argv[++i];
        else if (!strcmp(argv[i], "-p") && i + 1 < argc) dport = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-s") && i + 1 < argc) sport = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-B") && i + 1 < argc) bindip = argv[++i];
        else if (!strcmp(argv[i], "-b") && i + 1 < argc) bytes = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t") && i + 1 < argc) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-S") && i + 1 < argc) seconds = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-r") && i + 1 < argc) target = _atoi64(argv[++i]);
    }
    if (bytes < 8) bytes = 8;
    if (threads < 1) threads = 1;
    if (threads > 32) threads = 32;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { printf("WSAStartup failed\n"); return 1; }

    g = (GEN_THREAD *)calloc((size_t)threads, sizeof(GEN_THREAD));
    th = (HANDLE *)calloc((size_t)threads, sizeof(HANDLE));
    if (!g || !th) { printf("alloc failed\n"); return 1; }

    printf("GEN start dst=%s:%d bind=%s bytes=%d threads=%d secs=%d target=%lld\n",
           dst, dport, bindip, bytes, threads, seconds, target);
    fflush(stdout);

    t0 = now_us();
    for (i = 0; i < threads; i++) {
        g[i].dst = dst; g[i].bindip = bindip; g[i].dport = dport; g[i].sport = sport;
        g[i].bytes = bytes; g[i].seconds = seconds;
        g[i].target_pps = target > 0 ? target / threads : 0;
        g[i].index = i;
        th[i] = CreateThread(NULL, 0, gen_main, &g[i], 0, NULL);
    }
    WaitForMultipleObjects((DWORD)threads, th, TRUE, INFINITE);
    t1 = now_us();

    for (i = 0; i < threads; i++) {
        tot += g[i].pkts;
        totb += g[i].bytes_sent;
        tote += g[i].err;
        if (g[i].err < 0) printf("GEN thread %d setup error %lld\n", i, g[i].err);
    }

    {
        double el = (double)(t1 - t0) / 1e6;
        if (el <= 0) el = 1e-6;
        printf("GEN pkts=%lld bytes=%lld elapsed_ms=%.0f rate_pps=%.0f rate_mbps=%.1f threads=%d target=%lld err=%lld\n",
               tot, totb, el * 1000.0, (double)tot / el, (double)totb * 8.0 / el / 1e6,
               threads, target, tote);
    }
    fflush(stdout);
    WSACleanup();
    return 0;
}
