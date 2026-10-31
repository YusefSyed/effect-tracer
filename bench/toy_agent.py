#!/usr/bin/env python3
"""The toy agent (bench workload W2): 200 file writes, 50 local HTTP calls,
20 subprocesses and 10 DNS lookups against the stubs from bench/stubs.py.

Environment: TOY_ROOT (work directory), TOY_HTTP_PORT, TOY_DNS_PORT.
Deterministic apart from pids; prints a one-line summary.
"""

import http.client
import os
import pathlib
import random
import socket
import struct
import subprocess
import sys


def dns_query(port, name, txid):
    q = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(q, ("127.0.0.1", port))
    data, _ = s.recvfrom(512)
    s.close()
    return data[:2] == q[:2]


def main():
    root = pathlib.Path(os.environ["TOY_ROOT"])
    http_port = int(os.environ["TOY_HTTP_PORT"])
    dns_port = int(os.environ["TOY_DNS_PORT"])
    out = root / "out"
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(7)

    # 200 file writes: 180 direct, 20 through subprocesses (10 shell redirects, 10 cat copies).
    for i in range(180):
        p = out / f"f{i:03d}.txt"
        with open(p, "w") as f:
            f.write(f"record {i} {rng.random()}\n")
    for i in range(10):
        subprocess.run(["/bin/sh", "-c", f"echo sub {i} > {out}/sub{i}.txt"], check=True)
    for i in range(10):
        with open(out / f"copy{i}.txt", "w") as f:
            subprocess.run(["/bin/cat", str(out / f"f{i:03d}.txt")], stdout=f, check=True)

    # 50 local HTTP calls, one connection each.
    ok = 0
    for i in range(50):
        c = http.client.HTTPConnection("127.0.0.1", http_port, timeout=10)
        c.request("GET", f"/item/{i}")
        r = c.getresponse()
        r.read()
        ok += r.status == 200
        c.close()

    # 10 DNS lookups to the local stub.
    answered = sum(dns_query(dns_port, f"host-{i}.toy.test", 100 + i) for i in range(10))

    # A unicode name, to exercise canonical JSON on non-ASCII paths.
    with open(out / "naïve-日本.txt", "w") as f:
        f.write("ok\n")

    print(f"toy agent: files={len(list(out.iterdir()))} http_ok={ok} dns_answered={answered}")
    return 0 if ok == 50 and answered == 10 else 1


if __name__ == "__main__":
    sys.exit(main())
