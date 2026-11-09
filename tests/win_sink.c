/* Counting-only outer UDP peer: no handshake, decryption or deframing.
 * Bind an explicit peer address on the counting-NIC pair for bridge tests.
 * Calibrate this receiver separately; its final total includes the drain
 * window, so use the generator's active duration for traffic-period rates.
 *
 * Cross-compile:
 *   x86_64-w64-mingw32-gcc -O2 -std=c11 -Wall -Wextra -o tests/win_sink.exe tests/win_sink.c -lws2_32
 *
 * Usage (guest):
 *   win_sink.exe -p 45678 -S 20 [-B 0.0.0.0]
 * Output (one line every 2 seconds + final summary line):
 *   SINK pkts=... bytes=... elapsed_ms=... rate_pps=... rate_mbps=...
 *        len_min=... len_max=...
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in addr;
    char *buf;
    int port = 45678, seconds = 20, i;
    const char *bindip = "0.0.0.0";
    unsigned long long t0, t_end, t_last;
    long long pkts = 0, bytes = 0, errs = 0;
    int len_min = 0x7FFFFFFF, len_max = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-S") && i + 1 < argc) seconds = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-B") && i + 1 < argc) bindip = argv[++i];
    }
    if (seconds < 1) seconds = 1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { printf("WSAStartup failed\n"); return 1; }

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { printf("socket failed %d\n", WSAGetLastError()); return 1; }
    {
        int rcvbuf = 16 << 20;
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&rcvbuf, sizeof(rcvbuf));
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, bindip, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid bind address: %s\n", bindip);
        closesocket(s);
        WSACleanup();
        return 1;
    }
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("bind %s:%d failed %d\n", bindip, port, WSAGetLastError());
        return 1;
    }
    /* The timeout only lets the loop check the clock: no business logic depends on it */
    {
        DWORD to = 200;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
    }

    buf = (char *)malloc(2048);
    if (!buf) { printf("alloc failed\n"); return 1; }

    printf("SINK ready on %s:%d, window %ds\n", bindip, port, seconds);
    fflush(stdout);

    t0 = GetTickCount64();
    t_end = t0 + (unsigned long long)seconds * 1000ULL;
    t_last = t0;

    for (;;) {
        struct sockaddr_in from;
        int fromlen = (int)sizeof(from);
        int n = recvfrom(s, buf, 2048, 0, (struct sockaddr *)&from, &fromlen);
        unsigned long long now = GetTickCount64();

        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e != WSAETIMEDOUT) errs++;
        } else {
            pkts++;
            bytes += n;
            if (n < len_min) len_min = n;
            if (n > len_max) len_max = n;
        }
        if (now >= t_end) break;
        if (now - t_last >= 2000) {
            double el = (double)(now - t0) / 1000.0;
            printf("SINK t=%.0fs pkts=%lld pps=%.0f\n", el, pkts, (double)pkts / el);
            fflush(stdout);
            t_last = now;
        }
    }

    {
        double el = (double)(GetTickCount64() - t0) / 1000.0;
        if (el <= 0) el = 1e-3;
        if (pkts == 0) len_min = 0;
        printf("SINK pkts=%lld bytes=%lld elapsed_ms=%.0f rate_pps=%.0f rate_mbps=%.1f len_min=%d len_max=%d err=%lld\n",
               pkts, bytes, el * 1000.0, (double)pkts / el, (double)bytes * 8.0 / el / 1e6,
               len_min, len_max, errs);
        fflush(stdout);
    }

    closesocket(s);
    free(buf);
    WSACleanup();
    return 0;
}
