#!/usr/bin/env python3
"""Threaded TCP echo server for the iWAN integration test.

Usage: echo_server.py --bind IP --port PORT
One thread per connection; echoes every received byte back verbatim.
"""
import argparse
import socket
import socketserver
import threading


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    break
                self.request.sendall(data)
        except OSError:
            pass
        finally:
            try:
                self.request.close()
            except OSError:
                pass


class ThreadedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler):
        # socketserver defaults to AF_INET, which cannot bind an IPv6
        # address; pick the family from the bind address instead.
        self.address_family = (socket.AF_INET6 if ":" in addr[0]
                               else socket.AF_INET)
        super().__init__(addr, handler)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--port", type=int, required=True)
    args = ap.parse_args()
    srv = ThreadedServer((args.bind, args.port), EchoHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"echo server on {args.bind}:{args.port}", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
