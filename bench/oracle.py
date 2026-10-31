#!/usr/bin/env python3
"""bpftrace as an independent oracle for a traced run (root only).

The toy agent (W2) runs under effect-tracer inside a fresh cgroup v2 while
a bpftrace script, filtered on that cgroup, counts the same effects at the
syscall layer (tracepoint:syscalls:*, sched:*): successful write-intent
opens, mkdirat, unlinkat, renames, connects, sendto with a destination,
copy_file_range, execs, forks and exits. The ledger's events are counted
into the same buckets and the two are compared run by run. bpftrace and
effect-tracer share no code, and the oracle sits at a different layer
(syscall tracepoints, not LSM hooks or ptrace stops).

    oracle.py --mode ebpf|full|seccomp [--runs N] [--tracer BIN] [--out FILE.json]
"""

import argparse
import collections
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import envinfo  # noqa: E402
import toy_run  # noqa: E402

BT = r"""
tracepoint:syscalls:sys_enter_openat /cgroup == cgroupid("CG") && ((args->flags & 3) || (args->flags & 0x240))/ { @o[tid] = 1; }
tracepoint:syscalls:sys_exit_openat /@o[tid]/ { if (args->ret >= 0) { @c["open.write"] = count(); } delete(@o[tid]); }
tracepoint:syscalls:sys_exit_mkdirat /cgroup == cgroupid("CG") && args->ret == 0/ { @c["mkdir"] = count(); }
tracepoint:syscalls:sys_exit_unlinkat /cgroup == cgroupid("CG") && args->ret == 0/ { @c["unlink"] = count(); }
tracepoint:syscalls:sys_exit_renameat2 /cgroup == cgroupid("CG") && args->ret == 0/ { @c["rename"] = count(); }
tracepoint:syscalls:sys_exit_renameat /cgroup == cgroupid("CG") && args->ret == 0/ { @c["rename"] = count(); }
tracepoint:syscalls:sys_exit_connect /cgroup == cgroupid("CG") && (args->ret == 0 || args->ret == -115)/ { @c["connect"] = count(); }
tracepoint:syscalls:sys_enter_sendto /cgroup == cgroupid("CG") && args->addr != 0/ { @s[tid] = 1; }
tracepoint:syscalls:sys_exit_sendto /@s[tid]/ { if (args->ret >= 0) { @c["sendto.addr"] = count(); } delete(@s[tid]); }
tracepoint:syscalls:sys_exit_copy_file_range /cgroup == cgroupid("CG") && args->ret >= 0/ { @c["copy_file_range"] = count(); }
tracepoint:sched:sched_process_exec /cgroup == cgroupid("CG")/ { @c["exec"] = count(); }
tracepoint:sched:sched_process_fork /cgroup == cgroupid("CG")/ { @c["fork"] = count(); }
tracepoint:sched:sched_process_exit /cgroup == cgroupid("CG") && pid == tid/ { @c["exit"] = count(); }
"""


def ledger_buckets(ledger):
    c = collections.Counter()
    first_exec = True
    with open(os.path.join(ledger, "events.jsonl")) as f:
        for line in f:
            e = json.loads(line)
            k, d, ok = e["kind"], e.get("detail", {}), e["outcome"] == "committed"
            # the sh wrapper's own exec and its write to cgroup.procs happen
            # before it is in the cgroup, so the oracle cannot see them
            if e["name"].startswith("/sys/fs/cgroup/") or not ok:
                continue
            if k == "process.exec" and first_exec:
                first_exec = False
                continue
            if k in ("file.write", "file.create", "file.read") and d.get("via") is None and not e["name"].startswith("memfd:"):
                if d.get("dir"):
                    c["mkdir"] += 1
                else:
                    c["open.write"] += 1
            elif k == "file.write" and d.get("via") == "copy_file_range":
                c["copy_file_range"] += 1
            elif k == "file.delete":
                c["unlink"] += 1
            elif k == "file.rename":
                c["rename"] += 1
            elif k == "socket.connect":
                c["connect"] += 1
            elif k == "socket.send":
                c["sendto.addr"] += 1
            elif k == "process.exec":
                c["exec"] += 1
            elif k == "process.fork":
                c["fork"] += 1
            elif k == "process.exit":
                c["exit"] += 1
    return c


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="ebpf", choices=["full", "seccomp", "ebpf"])
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--tracer", default=os.path.join(os.path.dirname(HERE), "target", "release", "effect-tracer"))
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    stubs = toy_run.Stubs()
    work = tempfile.mkdtemp(prefix="et-oracle-")
    cg = f"/sys/fs/cgroup/et-oracle-{os.getpid()}"
    os.makedirs(cg, exist_ok=True)
    rows = []
    try:
        for i in range(a.runs):
            root = os.path.join(work, "root")
            ledger = os.path.join(work, "ledger")
            subprocess.run(["rm", "-rf", root, ledger], check=True)
            os.makedirs(root)
            script = BT.replace("CG", cg)
            bt = subprocess.Popen(["bpftrace", "-e", script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            assert bt.stdout is not None
            line = bt.stdout.readline()  # "Attaching N probes..."
            if "Attaching" not in line:
                raise SystemExit(f"bpftrace did not start: {line}{bt.stdout.read()}")
            time.sleep(0.5)
            env = dict(os.environ, TOY_ROOT=root, TOY_HTTP_PORT=str(stubs.http), TOY_DNS_PORT=str(stubs.dns),
                       PYTHONDONTWRITEBYTECODE="1")
            agent = f"echo $$ > {cg}/cgroup.procs && exec {sys.executable} {os.path.join(HERE, 'toy_agent.py')}"
            cmd = [a.tracer, "run", "--quiet", "--mode", a.mode, "--dns-port", str(stubs.dns), "--out", ledger,
                   "--", "/bin/sh", "-c", agent]
            r = subprocess.run(cmd, env=env, capture_output=True, text=True)
            bt.send_signal(signal.SIGINT)
            out = bt.communicate(timeout=30)[0]
            oracle = collections.Counter({m.group(1): int(m.group(2)) for m in re.finditer(r'@c\[(.*?)\]: (\d+)', out)})
            tracer = ledger_buckets(ledger)
            keys = sorted(set(oracle) | set(tracer))
            diff = {k: {"oracle": oracle.get(k, 0), "ledger": tracer.get(k, 0)} for k in keys if oracle.get(k, 0) != tracer.get(k, 0)}
            rows.append({"run": i, "agentExit": r.returncode, "oracle": dict(oracle), "ledger": dict(tracer), "differences": diff})
            print(f"run {i}: exit {r.returncode}, {sum(oracle.values())} oracle / {sum(tracer.values())} ledger, differences: {diff or 'none'}")
    finally:
        stubs.close()
        try:
            os.rmdir(cg)
        except OSError:
            pass
    summary = {
        "schema": "effect-tracer-bench-oracle/1",
        "env": envinfo.info(a.tracer),
        "oracle": "bpftrace on syscall and sched tracepoints, filtered to the run's cgroup (script in bench/oracle.py)",
        "workload": "W2 toy agent",
        "mode": a.mode,
        "runs": a.runs,
        "runsAgreeing": sum(1 for r in rows if not r["differences"]),
        "rows": rows,
    }
    if a.out:
        with open(a.out, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
