#!/usr/bin/env python3
"""Run the seeded-bypass corpus under the tracer and count catches.

    corpus.py --mode full|seccomp [--tracer BIN] [--out FILE.json]

A case counts as caught when the ledger holds the expected event (kind and
name predicate below) and verify_ledger.py exits 0 or 3 for that ledger.
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "verifier"))
import envinfo  # noqa: E402
import verify_ledger  # noqa: E402
from toy_run import Stubs  # noqa: E402

TITLES = {
    "c01": "subprocess shell redirect",
    "c02": "os.system redirect",
    "c03": "rename over an undeclared path",
    "c04": "O_TMPFILE then linkat",
    "c05": "shared writable mmap",
    "c06": "sendfile into a file",
    "c07": "/dev/shm write",
    "c08": "raw UDP sendto",
    "c09": "unix socket connect",
    "c10": "io_uring_setup attempt",
    "c11": "copy_file_range",
    "c12": "write through a symlink out of the root",
    "c13": "hard link of an outside file into the root",
    "c14": "truncate by path",
    "c15": "chmod",
    "c16": "unlink",
    "c17": "mkdir",
    "c18": "DNS query for an undeclared name",
    "c19": "TCP connect to an undeclared port",
    "c20": "exec of an undeclared binary",
    "x21": "write from a thread",
    "x22": "write from a forked child",
    "x23": "memfd_create",
    "x24": "splice into a file",
    "x25": "ftruncate after PR_SET_DUMPABLE 0",
    "x26": "connect after PR_SET_DUMPABLE 0",
}


def expectations(out, ports):
    """case id -> (kind, predicate on the event)"""
    under = lambda p: lambda e: e["name"].startswith(out + "/" + p)  # noqa: E731
    return {
        "c01": ("file.write", under("c01")),
        "c02": ("file.write", under("c02")),
        "c03": ("file.rename", under("c03")),
        "c04": ("file.link", under("c04")),
        "c05": ("file.map-write", under("c05")),
        "c06": ("file.write", lambda e: under("c06")(e) and e.get("detail", {}).get("via") == "sendfile"),
        "c07": ("file.write", lambda e: e["name"] == "/dev/shm/et-c07"),
        "c08": ("socket.send", lambda e: e["name"] == f"udp:127.0.0.1:{ports['udp']}"),
        "c09": ("socket.connect", lambda e: e["name"] == f"unix:{ports['unix']}"),
        "c10": ("coverage.gap", lambda e: e["name"] == "io_uring_setup" and e["outcome"] == "denied"),
        "c11": ("file.write", lambda e: under("c11")(e) and e.get("detail", {}).get("via") == "copy_file_range"),
        "c12": ("file.write", under("c12")),
        "c13": ("file.link", lambda e: e.get("detail", {}).get("from", "").startswith(out + "/c13-src")),
        "c14": ("file.write", lambda e: under("c14")(e) and e.get("detail", {}).get("via") == "truncate"),
        "c15": ("file.meta", under("c15")),
        "c16": ("file.delete", under("c16")),
        "c17": ("file.create", under("c17")),
        "c18": ("dns.query", lambda e: e["name"] == "exfil.undeclared.test"),
        "c19": ("socket.connect", lambda e: e["name"] == f"tcp:127.0.0.1:{ports['tcp']}"),
        "c20": ("process.exec", lambda e: e["name"].endswith("/env") and e["outcome"] == "committed"),
        "x21": ("file.write", under("x21")),
        "x22": ("file.write", under("x22")),
        "x23": ("file.create", lambda e: e["name"] == "memfd:leak23"),
        "x24": ("file.write", lambda e: under("x24")(e) and e.get("detail", {}).get("via") == "splice"),
        # Caught either as the event or, when the tracer may not read the
        # non-dumpable process (unprivileged tracer), as a declared gap.
        "x25": ("*", lambda e: (e["kind"] == "file.write" and under("x25")(e) and e.get("detail", {}).get("via") == "ftruncate")
                or (e["kind"] == "coverage.gap" and e["name"].startswith("ftruncate:"))),
        "x26": ("*", lambda e: (e["kind"] == "socket.connect" and e["name"] == f"tcp:127.0.0.1:{ports['tcp']}")
                or (e["kind"] == "coverage.gap" and e["name"].startswith("connect:"))),
    }


class Listeners:
    """Undeclared TCP, UDP and unix listeners, outside the trace."""

    def __init__(self, unix_path):
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen(8)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.unix.bind(unix_path)
        self.unix.listen(8)
        self.unix_path = unix_path
        self.alive = True
        self.t = threading.Thread(target=self.serve, daemon=True)
        self.t.start()

    def serve(self):
        import select
        while self.alive:
            r, _, _ = select.select([self.tcp, self.unix], [], [], 0.2)
            for s in r:
                try:
                    c, _ = s.accept()
                    c.close()
                except OSError:
                    pass

    def ports(self):
        return {"tcp": self.tcp.getsockname()[1], "udp": self.udp.getsockname()[1], "unix": self.unix_path}

    def close(self):
        self.alive = False
        self.t.join(timeout=2)
        for s in (self.tcp, self.udp, self.unix):
            s.close()


def prepare(out, root):
    shutil.rmtree(out, ignore_errors=True)
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(out)
    os.makedirs(root)
    for name in ("c05", "c13-src", "c14", "c15", "c16"):
        with open(os.path.join(out, name), "wb") as f:
            f.write(b"x" * 4096)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="full", choices=["full", "seccomp"])
    ap.add_argument("--tracer", default=os.path.join(os.path.dirname(HERE), "target", "release", "effect-tracer"))
    ap.add_argument("--out")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args(argv)
    work = tempfile.mkdtemp(prefix="et-corpus-")
    out = os.path.join(work, "undeclared")
    root = os.path.join(work, "root")
    stubs = Stubs()
    listeners = Listeners(os.path.join(work, "c09.sock"))
    ports = listeners.ports()
    ports["dns"] = stubs.dns
    exp = expectations(out, ports)
    rows = []
    try:
        for cid in sorted(exp):
            prepare(out, root)
            ledger = os.path.join(work, f"ledger-{cid}")
            env = dict(os.environ, ET_OUT=out, ET_ROOT=root, ET_TCP_PORT=str(ports["tcp"]), ET_UDP_PORT=str(ports["udp"]),
                       ET_DNS_PORT=str(stubs.dns), ET_UNIX=ports["unix"], PYTHONDONTWRITEBYTECODE="1")
            cmd = [a.tracer, "run", "--quiet", "--mode", a.mode, "--dns-port", str(stubs.dns), "--out", ledger, "--",
                   sys.executable, os.path.join(HERE, "bypass", "cases.py"), cid]
            r = subprocess.run(cmd, env=env, capture_output=True, text=True)
            kind, pred = exp[cid]
            hit = None
            same_kind = []
            try:
                with open(os.path.join(ledger, "events.jsonl")) as f:
                    for line in f:
                        ev = json.loads(line)
                        if kind in ("*", ev["kind"]) and pred(ev):
                            hit = {"seq": ev["seq"], "kind": ev["kind"], "name": ev["name"], "outcome": ev["outcome"],
                                   "comm": ev["proc"].get("comm"), "detail": ev.get("detail")}
                            break
                        if kind != "*" and ev["kind"] == kind and ev["proc"].get("comm") != "effect-tracer":
                            same_kind.append(ev["name"])
            except OSError:
                pass
            try:
                verify_ledger.verify(ledger)
                vcode = 0
            except verify_ledger.Failure as fl:
                vcode = fl.code
            row = {"id": cid, "title": TITLES[cid], "expected": kind, "caught": hit is not None and vcode in (0, 3),
                   "event": hit, "verify": vcode, "caseExit": r.returncode, "caseStdout": r.stdout.strip()[-120:]}
            if r.returncode != 0:
                row["caseStderr"] = r.stderr[-800:]
            if hit is None and same_kind:
                # what the ledger did record under the expected kind, e.g. ip:host:port
                # when the socket type could not be read
                row["sameKindRecorded"] = same_kind[:5]
            if cid == "c10" and hit is None and "errno=1" in r.stdout:
                row["note"] = "io_uring_setup returned EPERM (denied by the seccomp filter) but the attempt is not recorded in this mode"
            rows.append(row)
            mark = "CAUGHT" if row["caught"] else "missed"
            print(f"{cid} {mark:6} {TITLES[cid]:45} {hit['name'] if hit else '-'}", flush=True)
    finally:
        listeners.close()
        stubs.close()
    main20 = [r for r in rows if r["id"].startswith("c")]
    extra = [r for r in rows if r["id"].startswith("x")]
    summary = {
        "schema": "effect-tracer-bench-corpus/1",
        "env": envinfo.info(a.tracer),
        "mode": a.mode,
        "corpus": "bench/bypass/cases.py (20 cases c01-c20, plus x21-x24 reported separately)",
        "caught": sum(r["caught"] for r in main20),
        "total": len(main20),
        "extraCaught": sum(r["caught"] for r in extra),
        "extraTotal": len(extra),
        "allLedgersVerified": all(r["verify"] in (0, 3) for r in rows),
        "rows": rows,
    }
    if a.out:
        with open(a.out, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"wrote {a.out}")
    if not a.keep:
        shutil.rmtree(work, ignore_errors=True)
    print(f"caught {summary['caught']}/{summary['total']} (+{summary['extraCaught']}/{summary['extraTotal']} extra), mode {a.mode}, all ledgers verified: {summary['allLedgersVerified']}")
    return 0 if summary["caught"] == summary["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
