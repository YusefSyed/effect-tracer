#!/usr/bin/env python3
"""Local HTTP and DNS stubs for the toy agent. Started OUTSIDE the trace by
the bench harness; prints the ports it chose and serves until killed.

    python3 bench/stubs.py            -> prints "HTTP_PORT=... DNS_PORT=..."
"""

import socket
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f'{{"path":"{self.path}"}}'.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def dns_stub(sock):
    """Answer every A query with 127.0.0.1."""
    while True:
        try:
            data, addr = sock.recvfrom(512)
        except OSError:
            return
        if len(data) < 12:
            continue
        txid = data[:2]
        qd = data[12:]
        end = qd.find(b"\x00")
        if end < 0:
            continue
        question = qd[: end + 5]
        header = txid + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        answer = b"\xc0\x0c" + b"\x00\x01\x00\x01" + struct.pack(">IH", 60, 4) + bytes([127, 0, 0, 1])
        sock.sendto(header + question + answer, addr)


def main():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    print(f"HTTP_PORT={httpd.server_address[1]} DNS_PORT={udp.getsockname()[1]}", flush=True)
    threading.Thread(target=dns_stub, args=(udp,), daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
