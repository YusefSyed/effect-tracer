#!/usr/bin/env python3
"""Run the toy agent (W2) under a tracer mode, verify the ledger, check it
against the declared manifest, and report. Also the clean-run loop.

    toy_run.py --mode full|seccomp|none [--runs N] [--tracer BIN] [--out FILE.json]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "verifier"))
import check_manifest  # noqa: E402
import envinfo  # noqa: E402
import verify_ledger  # noqa: E402


class Stubs:
    def __init__(self):
        self.p = subprocess.Popen([sys.executable, os.path.join(HERE, "stubs.py")], stdout=subprocess.PIPE, text=True)
        line = self.p.stdout.readline().strip()
        kv = dict(part.split("=") for part in line.split())
        self.http = int(kv["HTTP_PORT"])
        self.dns = int(kv["DNS_PORT"])

    def close(self):
        self.p.terminate()
        self.p.wait(timeout=10)


def manifest_for(root, stubs):
    return {
        "roots": [root],
        "hosts": [f"tcp:127.0.0.1:{stubs.http}", f"udp:127.0.0.1:{stubs.dns}"],
        "dnsSuffixes": [".toy.test"],
        "exes": ["python3", "python3.11", "python3.12", "python3.13", "sh", "dash", "bash", "cat"],
    }


def one_run(mode, tracer, stubs, workdir, ignore):
    root = os.path.join(workdir, "root")
    ledger = os.path.join(workdir, "ledger")
    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(ledger, ignore_errors=True)
    os.makedirs(root)
    env = dict(os.environ, TOY_ROOT=root, TOY_HTTP_PORT=str(stubs.http), TOY_DNS_PORT=str(stubs.dns),
               PYTHONDONTWRITEBYTECODE="1")
    agent = [sys.executable, os.path.join(HERE, "toy_agent.py")]
    if mode == "none":
        cmd = agent
    else:
        cmd = [tracer, "run", "--quiet", "--mode", mode, "--dns-port", str(stubs.dns), "--out", ledger, "--"] + agent
    t0 = time.perf_counter()
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    wall = time.perf_counter() - t0
    result = {"mode": mode, "wallS": round(wall, 4), "agentExit": r.returncode, "agentStdout": r.stdout.strip()[-200:]}
    if r.returncode != 0:
        result["stderr"] = r.stderr[-2000:]
    if mode != "none":
        try:
            rep = verify_ledger.verify(ledger)
            result["verify"] = 0
            result["events"] = rep["events"]
            result["coverage"] = rep["coverage"]
            result["kinds"] = rep["kinds"]
        except verify_ledger.Failure as f:
            result["verify"] = f.code
            result["verifyError"] = str(f)
        counts, undeclared = check_manifest.check(ledger, manifest_for(root, stubs), ignore)
        result["manifest"] = counts
        result["undeclared"] = undeclared
        try:
            with open(os.path.join(ledger, "ledger.json")) as f:
                lj = json.load(f)
            result["stats"] = lj.get("stats")
        except (OSError, ValueError):
            pass
    return result


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="full", choices=["full", "seccomp", "none"])
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--tracer", default=os.path.join(os.path.dirname(HERE), "target", "release", "effect-tracer"))
    ap.add_argument("--out", help="write the aggregate JSON here")
    ap.add_argument("--keep", action="store_true", help="keep the last ledger directory and print its path")
    a = ap.parse_args(argv)
    with open(os.path.join(HERE, "ignore.json")) as f:
        ignore = json.load(f)
    stubs = Stubs()
    workdir = tempfile.mkdtemp(prefix="et-toy-")
    runs = []
    try:
        for i in range(a.runs):
            res = one_run(a.mode, a.tracer, stubs, workdir, ignore)
            runs.append(res)
            flag = "" if res.get("verify", 0) == 0 and not res.get("undeclared") and res["agentExit"] == 0 else "  <-- problem"
            print(f"run {i + 1}/{a.runs}: wall={res['wallS']}s events={res.get('events')} undeclared={len(res.get('undeclared', []))} verify={res.get('verify')}{flag}", flush=True)
    finally:
        stubs.close()
    summary = {
        "schema": "effect-tracer-bench-clean-runs/1",
        "env": envinfo.info(a.tracer),
        "workload": "W2 toy agent (bench/toy_agent.py): 200 file writes, 50 local HTTP calls, 20 subprocesses, 10 DNS lookups to a local stub",
        "manifest": "roots=[work root], hosts=[http stub, dns stub], dnsSuffixes=[.toy.test], exes=[python3, sh, cat]",
        "ignoreList": "bench/ignore.json",
        "mode": a.mode,
        "runs": len(runs),
        "runsWithUndeclaredEvents": sum(1 for r in runs if r.get("undeclared")),
        "totalUndeclaredEvents": sum(len(r.get("undeclared", [])) for r in runs),
        "totalIgnoredEvents": sum(r.get("manifest", {}).get("ignored", 0) for r in runs),
        "runsVerified": sum(1 for r in runs if r.get("verify") == 0),
        "runsCoverageComplete": sum(1 for r in runs if r.get("coverage") == "complete"),
        "agentFailures": sum(1 for r in runs if r["agentExit"] != 0),
        "wallMedianS": sorted(r["wallS"] for r in runs)[len(runs) // 2],
        "perRun": runs,
    }
    if a.out:
        with open(a.out, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"wrote {a.out}")
    if a.keep:
        print(f"ledger kept at {os.path.join(workdir, 'ledger')}")
    else:
        shutil.rmtree(workdir, ignore_errors=True)
    print(json.dumps({k: v for k, v in summary.items() if k not in ("perRun", "env")}, indent=2))
    bad = summary["totalUndeclaredEvents"] or summary["agentFailures"] or summary["runsVerified"] != len(runs) and a.mode != "none"
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
