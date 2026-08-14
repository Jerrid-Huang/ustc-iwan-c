#!/usr/bin/env python3
"""Throughput bench server: a discard sink (upload target) and a data
source (download origin) in one process.

Usage: bench_server.py --bind IP --sink-port P --source-port Q

The sink discards everything (its kernel TCP still ACKs, so the client's
sendall count equals the true tunneled throughput). The source streams
data continuously until the client disconnects.
"""
import argparse
import socketserver
import threading


class SinkHandler(socketserver.BaseRequestHandler):
    def handle(self):
        total = 0
        try:
            while True:
                d = self.request.recv(1 << 20)
                if not d:
                    break
                total += len(d)
        except OSError:
            pass
        print(f"sink conn: {total / 1e6:.1f} MB", flush=True)


class SourceHandler(socketserver.BaseRequestHandler):
    def handle(self):
        chunk = b"x" * (1 << 16)
        total = 0
        try:
            while True:
                self.request.sendall(chunk)
                total += len(chunk)
        except OSError:
            pass
        print(f"source conn: {total / 1e6:.1f} MB", flush=True)


# Fork per connection (Linux/macOS test tool only): 8-16 concurrent
# 1Gbit+ sinks in ONE python process hit the GIL (~162% CPU measured,
# capping aggregate at ~9.5Gbit/s and misattributed to the tunnel);
# separate processes remove the interpreter lock from the bench path.
if hasattr(socketserver, "ForkingTCPServer"):
    class BenchServer(socketserver.ForkingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
else:
    class BenchServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--sink-port", type=int, required=True)
    ap.add_argument("--source-port", type=int, required=True)
    args = ap.parse_args()
    for port, handler in ((args.sink_port, SinkHandler),
                          (args.source_port, SourceHandler)):
        srv = BenchServer((args.bind, port), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"bench server on {args.bind}:{port} ({handler.__name__})",
              flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
