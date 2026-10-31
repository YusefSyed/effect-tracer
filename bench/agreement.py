#!/usr/bin/env python3
"""Event-for-event agreement between two tracer modes on the toy agent (W2).

Runs the toy agent under mode A and mode B, alternating, N times each, with
the same work root and stubs, and compares the multisets of
(kind, name, outcome) per run, leaving out the tracer's own run.start and
run.end. Prints every difference and writes a JSON summary.

    agreement.py --a full --b ebpf [--runs N] [--tracer BIN] [--out FILE.json]
"""

import argparse
import collections
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import envinfo  # noqa: E402
import toy_run  # noqa: E402


def multiset(ledger):
    c = collections.Counter()
    with open(os.path.join(ledger, "events.jsonl")) as f:
        for line in f:
            e = json.loads(line)
            if e["kind"] in ("run.start", "run.end"):
                continue
            c[(e["kind"], e["name"], e["outcome"])] += 1
    return c


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", default="full", choices=["full", "seccomp", "ebpf"])
    ap.add_argument("--b", default="ebpf", choices=["full", "seccomp", "ebpf"])
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--tracer", default=os.path.join(os.path.dirname(HERE), "target", "release", "effect-tracer"))
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    ignore = json.load(open(os.path.join(HERE, "ignore.json")))
    stubs = toy_run.Stubs()
    work = tempfile.mkdtemp(prefix="et-agree-")
    rows = []
    try:
        for i in range(a.runs):
            sets = {}
            for mode in (a.a, a.b):
                wd = os.path.join(work, "w")  # same paths for both modes
                os.makedirs(wd, exist_ok=True)
                r = toy_run.one_run(mode, a.tracer, stubs, wd, ignore)
                if r.get("verify") != 0 or r.get("agentExit") != 0:
                    print(f"run {i} mode {mode}: verify={r.get('verify')} exit={r.get('agentExit')}", file=sys.stderr)
                sets[mode] = multiset(os.path.join(wd, "ledger"))
            only_a = sets[a.a] - sets[a.b]
            only_b = sets[a.b] - sets[a.a]
            same = sum((sets[a.a] & sets[a.b]).values())
            row = {
                "run": i,
                "eventsA": sum(sets[a.a].values()),
                "eventsB": sum(sets[a.b].values()),
                "matched": same,
                "onlyA": [list(k) + [v] for k, v in sorted(only_a.items())],
                "onlyB": [list(k) + [v] for k, v in sorted(only_b.items())],
            }
            rows.append(row)
            print(f"run {i}: {a.a} {row['eventsA']} events, {a.b} {row['eventsB']}, matched {same}, "
                  f"only {a.a} {sum(only_a.values())}, only {a.b} {sum(only_b.values())}")
            for k, v in sorted(only_a.items()):
                print(f"   only {a.a}: {v} x {k}")
            for k, v in sorted(only_b.items()):
                print(f"   only {a.b}: {v} x {k}")
    finally:
        stubs.close()
    summary = {
        "schema": "effect-tracer-bench-agreement/1",
        "env": envinfo.info(a.tracer),
        "workload": "W2 toy agent (bench/toy_agent.py)",
        "modes": [a.a, a.b],
        "compared": "multiset of (kind, name, outcome) per run, run.start/run.end left out",
        "runs": a.runs,
        "runsIdentical": sum(1 for r in rows if not r["onlyA"] and not r["onlyB"]),
        "rows": rows,
    }
    if a.out:
        with open(a.out, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
