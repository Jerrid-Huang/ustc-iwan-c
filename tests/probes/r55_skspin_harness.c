/*
 * R55-SK-1 dynamic probe: drives the REAL production wait_events() with
 * injected flows against real loopback TCP client sockets, to prove:
 *
 *   RST:  a flow whose events=0 slot sits on an RST'd (POLLERR|POLLHUP)
 *         fd must NOT make wait_events return instantly every round (the
 *         zero-wait busy spin). After the fix it converges (fd closed,
 *         removed from the poll set) and wait_events sleeps again.
 *   FIN:  the clean-FIN control (client shutdown(SHUT_WR), events=0) must
 *         keep NOT waking (never spin) — pre- and post-fix identical.
 *   OUT:  a half-open client (SHUT_WR, still reading) with queued output
 *         must still receive that output through service_local_outputs —
 *         the fix must not drop f->output on the clean path.
 *
 * Links against iwan_core (same object the production harnesses use), so
 * this exercises the actual wait_events()/service_local_outputs() code.
 *
 * Usage: r55_skspin_harness  (measurement params via env, see below)
 *   IWAN_PROBE_WAIT_MS  default 500   wait_events timeout per round
 *   IWAN_PROBE_ROUNDS   default 10    wait_events rounds per phase
 *
 * exit 0 = all assertions held.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "socks_internal.h"
#include "tcpstack.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
    else         { printf("  ok:   %s\n", msg); } \
} while (0)

static unsigned env_uint(const char *name, unsigned dflt)
{
    const char *v = getenv(name);
    return v && *v ? (unsigned)strtoul(v, NULL, 10) : dflt;
}

/* one wait_events round; returns its real latency in ms */
static double we_latency(int listener, int udpfd, int timeout_ms)
{
    uint64_t t0 = now_ms();
    wait_events(listener, udpfd, -1, timeout_ms);
    return (double)(now_ms() - t0);
}

/* spin detector: run `rounds` wait_events calls of WAIT_MS; count how many
 * returned in < 2 ms (an instant return = poll did not sleep). */
static int count_instant(int listener, int udpfd, int wait_ms, int rounds)
{
    int instant = 0;
    for (int i = 0; i < rounds; i++) {
        double dt = we_latency(listener, udpfd, wait_ms);
        if (dt < 2.0)
            instant++;
    }
    return instant;
}

int main(void)
{
    int wait_ms = (int)env_uint("IWAN_PROBE_WAIT_MS", 500);
    int rounds = (int)env_uint("IWAN_PROBE_ROUNDS", 10);

    port_socket_init();

    static SocksConfig cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.inner_ip = 0xC6120002u;
    cfg.gateway = 0xC6120001u;
    cfg.mtu = 1500;
    cfg.listen_str = "probe";
    g_socks_cfg = &cfg;
    g_flows = calloc(MAX_FLOWS, sizeof *g_flows);
    if (!g_flows) { fprintf(stderr, "calloc failed\n"); return 2; }
    g_dns_evfd = -1;
    g_sockfd = -1;
    g_next_id = 1;

    int listener = port_socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    port_setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in la; memset(&la, 0, sizeof la);
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    la.sin_port = 0;
    port_bind(listener, (struct sockaddr *)&la, sizeof la);
    socklen_t ll = sizeof la;
    getsockname(listener, (struct sockaddr *)&la, &ll);
    port_listen(listener, 64);
    port_set_nonblock(listener, true);

    int udpfd = port_socket(AF_INET, SOCK_DGRAM, 0);
    Flow *f;
    struct sockaddr_in peer; memset(&peer, 0, sizeof peer);
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    peer.sin_port = 9;

    /* ================= phase A: RST spin ================= */
    printf("== A: RST'd client fd in an events=0 flow slot ==\n");
    {
        int cfd = port_socket(AF_INET, SOCK_STREAM, 0);
        connect(cfd, (struct sockaddr *)&la, sizeof la);
        int afd = accept(listener, NULL, NULL);
        port_set_nonblock(afd, true);
        /* register the flow in the post-RST-detection state: ST_CLOSING,
         * local_eof, events=0 -> wait_events registers fd with events=0 */
        f = flow_alloc(&peer);
        f->fd = afd;
        f->local_eof = true;
        f->state = ST_CLOSING;   /* deliberate: set_flow_state also refreshes
                                  * state_ms; state already ST_CLOSING here */
        /* now RST the peer */
        struct linger lg = {1, 0};
        setsockopt(cfd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
        close(cfd);
        usleep(200000);   /* let the RST arrive */
    }
    {
        /* pre-convergence: with the OLD code this returns instantly every
         * round (1000 rounds of poll(events=0) on this fd ≈ 0.3 ms). */
        double d0 = we_latency(listener, udpfd, wait_ms);
        int inst = count_instant(listener, udpfd, wait_ms, rounds);
        char buf[160];
        snprintf(buf, sizeof buf,
                 "RST: first wait_events latency %.0f ms, %d/%d rounds "
                 "returned instantly (spin)", d0, inst, rounds);
        CHECK(inst <= 1, buf);
        /* the convergence must have removed/closed the fd: subsequent
         * rounds must sleep the full timeout */
        double d1 = we_latency(listener, udpfd, wait_ms);
        printf("  RST: post-converge wait_events latency %.0f ms "
               "(expect ~%d ms; flow active=%d fd=%d)\n",
               d1, wait_ms, f->active, f->fd);
        CHECK(d1 >= (double)wait_ms * 0.9,
              "RST: wait_events sleeps again after converge (no spin)");
        /* clean the dead flow so the next phase's measurement is isolated */
        flow_free(f);
    }

    /* ================= phase B: clean-FIN control ================= */
    printf("== B: clean FIN (SHUT_WR) client fd in an events=0 flow slot ==\n");
    {
        int cfd = port_socket(AF_INET, SOCK_STREAM, 0);
        connect(cfd, (struct sockaddr *)&la, sizeof la);
        int afd = accept(listener, NULL, NULL);
        port_set_nonblock(afd, true);
        f = flow_alloc(&peer);
        f->fd = afd;
        f->local_eof = true;
        f->state = ST_CLOSING;
        shutdown(cfd, SHUT_WR);   /* clean FIN, client still reading */
        usleep(200000);
    }
    {
        /* clean FIN must never wake an events=0 slot => no instant returns */
        int inst = count_instant(listener, udpfd, wait_ms, rounds);
        char buf[160];
        snprintf(buf, sizeof buf, "clean FIN: %d/%d rounds returned "
                 "instantly (must be 0)", inst, rounds);
        CHECK(inst == 0, buf);
        flow_free(f);
    }

    /* ================= phase C: output delivery on half-open ================= */
    printf("== C: queued output reaches a half-open (SHUT_WR) client ==\n");
    {
        int cfd = port_socket(AF_INET, SOCK_STREAM, 0);
        connect(cfd, (struct sockaddr *)&la, sizeof la);
        int afd = accept(listener, NULL, NULL);
        port_set_nonblock(cfd, true);
        f = flow_alloc(&peer);
        f->fd = afd;
        f->local_eof = true;
        f->state = ST_CLOSING;
        shutdown(cfd, SHUT_WR);   /* client half-closes but keeps reading */
        usleep(100000);
        uint8_t payload[8192];
        for (size_t i = 0; i < sizeof payload; i++)
            payload[i] = (uint8_t)(i * 31 + 7);
        queue_flow_output(f, payload, sizeof payload);
        /* drain through the real service_local_outputs (no netstack conn:
         * output flush path only) */
        for (int i = 0; i < 50 && f->output.len > 0; i++)
            service_local_outputs();
        size_t got = 0;
        uint8_t rbuf[4096];
        for (;;) {
            ssize_t n = port_recv(cfd, rbuf, sizeof rbuf, 0);
            if (n > 0) { got += (size_t)n; continue; }
            break;
        }
        char buf[160];
        snprintf(buf, sizeof buf, "client received %zu/%zu queued bytes "
                 "(no f->output drop on clean half-open)", got,
                 sizeof payload);
        CHECK(got == sizeof payload && f->output.len == 0, buf);
        flow_free(f);
    }

    /* ============= phase C2: RST + queued output (realistic) ============= */
    printf("== C2: RST'd client with queued output (flush fails once) ==\n");
    {
        int cfd = port_socket(AF_INET, SOCK_STREAM, 0);
        connect(cfd, (struct sockaddr *)&la, sizeof la);
        int afd = accept(listener, NULL, NULL);
        port_set_nonblock(afd, true);
        f = flow_alloc(&peer);
        f->fd = afd;
        f->local_eof = true;
        f->state = ST_CLOSING;
        struct linger lg = {1, 0};
        setsockopt(cfd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
        close(cfd);
        usleep(200000);
        const uint8_t reply[] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
        queue_flow_output(f, reply, sizeof reply);   /* undeliverable */
        /* the real service_local_outputs flush fails hard (EPIPE on the
         * dead socket) and drains the queue; wait_events then converges */
        int spins = 0;
        for (int i = 0; i < 40; i++) {
            double dt = we_latency(listener, udpfd, wait_ms);
            if (dt < 2.0)
                spins++;
            service_local_outputs();
            if (f->fd < 0)
                break;
        }
        char buf[160];
        snprintf(buf, sizeof buf, "RST+output: converged (fd=%d out=%zu) "
                 "with %d instant rounds (bounded, not infinite)",
                 f->fd, f->output.len, spins);
        CHECK(f->fd == -1 && f->output.len == 0 && spins < 40, buf);
        double d_post = we_latency(listener, udpfd, wait_ms);
        printf("  C2: post-converge latency %.0f ms\n", d_post);
        flow_free(f);
    }

    /* ========== phase C3: RST + output, no flush = cap path ========== */
    printf("== C3: RST'd client, queued output, NO flush (bounded cap) ==\n");
    {
        int cfd = port_socket(AF_INET, SOCK_STREAM, 0);
        connect(cfd, (struct sockaddr *)&la, sizeof la);
        int afd = accept(listener, NULL, NULL);
        port_set_nonblock(afd, true);
        f = flow_alloc(&peer);
        f->fd = afd;
        f->local_eof = true;
        f->state = ST_CLOSING;
        struct linger lg = {1, 0};
        setsockopt(cfd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
        close(cfd);
        usleep(200000);
        const uint8_t reply[] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
        queue_flow_output(f, reply, sizeof reply);
        /* drive ONLY wait_events (no flush): the ERR|HUP counter must cap
         * at FLOW_ERR_ROUNDS_MAX rounds, then drop output + close fd.
         * FLOW_ERR_ROUNDS_MAX is private to socks.c; the scenario-wide
         * check is "bounded": give it well over any sane cap. */
        int spins = 0, converge_round = -1;
        for (int i = 0; i < 200; i++) {
            double dt = we_latency(listener, udpfd, wait_ms);
            if (dt < 2.0)
                spins++;
            if (f->fd < 0) { converge_round = i; break; }
        }
        char buf[160];
        snprintf(buf, sizeof buf, "RST+output(nof)   : converged at round "
                 "%d (spins=%d, fd=%d out=%zu) — bounded, not infinite",
                 converge_round, spins, f->fd, f->output.len);
        CHECK(converge_round >= 0 && f->fd == -1 && f->output.len == 0 &&
              spins <= 64, buf);
        double d_post = we_latency(listener, udpfd, wait_ms);
        printf("  C3: post-converge latency %.0f ms (sleeps again)\n",
               d_post);
        CHECK(d_post >= (double)wait_ms * 0.9,
              "C3: wait_events sleeps after the cap converged the flow");
        flow_free(f);
    }

    printf("%s\n", fails == 0 ? "PROBE PASS" : "PROBE FAIL");
    port_close(udpfd);
    port_close(listener);
    free(g_flows);
    return fails == 0 ? 0 : 1;
}
