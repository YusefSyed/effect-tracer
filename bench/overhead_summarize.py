#!/usr/bin/env python3
"""Merge hyperfine JSON files from bench/overhead.sh into one bench record.

    overhead_summarize.py OUTDIR --tracer BIN --runs N --warmup M --out FILE.json
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import envinfo  # noqa: E402

WORKLOADS = {
    "W0": "/bin/true: the fixed cost of starting the tracer (for --mode ebpf, loading and attaching the BPF programs)",
    "W1": "dd if=/dev/zero of=/dev/null bs=1 count=500k (about 1,024,000 syscalls; the ptrace worst case)",
    "W2": "toy agent: 200 file writes, 50 local HTTP calls, 20 subprocesses, 10 DNS lookups",
    "W3": "offline pip install of requests (--no-index --force-reinstall --no-deps) into a venv",
    "W4": "pytest, 200 small tests (bench/w4_tests/test_w4.py)",
}


def p95(times):
    s = sorted(times)
    idx = max(0, int(round(0.95 * len(s) + 0.5)) - 1)
    return s[min(idx, len(s) - 1)]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--tracer", required=True)
    ap.add_argument("--runs", type=int, required=True)
    ap.add_argument("--warmup", type=int, required=True)
    ap.add_argument("--pin", type=int)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    record = {
        "schema": "effect-tracer-bench-overhead/1",
        "env": envinfo.info(a.tracer),
        "hyperfine": {"runs": a.runs, "warmup": a.warmup, "shell": "none (-N)"},
        "modes": {"none": "untraced", "ptrace": "--mode full: a stop at every syscall entry and exit", "ptrace+seccomp": "--mode seccomp: stops only at effect syscalls",
                  "<mode>@cpuN": "the same, with the tracer and the whole tree on CPU N (--pin-cpu N; taskset -c N for none)"},
        "pinCpu": a.pin,
        "workloads": {},
    }
    lines = ["| workload | mode | median s | p95 s | x untraced | x untraced, same CPU | stops | tracer CPU ms |", "|---|---|---|---|---|---|---|---|"]
    for w, desc in WORKLOADS.items():
        path = os.path.join(a.outdir, f"{w}.json")
        if not os.path.exists(path):
            continue
        with open(path) as f:
            data = json.load(f)
        base = None
        entry = {"description": desc, "command": data["results"][0]["command"], "modes": {}}
        for r in data["results"]:
            name = r["command"]
            m = {
                "meanS": r["mean"], "medianS": r["median"], "minS": r["min"], "maxS": r["max"], "p95S": p95(r["times"]),
                "userS": r["user"], "systemS": r["system"], "runs": len(r["times"]), "exitCodes": sorted(set(r.get("exit_codes", []))),
            }
            lp = os.path.join(a.outdir, f"{w}-{name}-ledger.json")
            if os.path.exists(lp):
                with open(lp) as f:
                    lj = json.load(f)
                st = lj.get("stats", {})
                m["lastRunStops"] = st.get("stops")
                m["lastRunTracerCpuMs"] = st.get("tracerCpuMs")
                m["lastRunEvents"] = st.get("events")
                m["lastRunCoverage"] = lj.get("coverage", {}).get("status")
            entry["modes"][name] = m
        if "none" in entry["modes"]:
            base = entry["modes"]["none"]["medianS"]
            for name, m in entry["modes"].items():
                m["ratioMedian"] = round(m["medianS"] / base, 3) if base else None
                m["overheadPercentMedian"] = round((m["medianS"] / base - 1) * 100, 1) if base else None
                # against the untraced run placed the same way (pinned rows
                # compare with none@cpuN, unpinned rows with none)
                same = "none" + name[name.index("@"):] if "@" in name else "none"
                if same in entry["modes"]:
                    sb = entry["modes"][same]["medianS"]
                    m["ratioMedianSamePlacement"] = round(m["medianS"] / sb, 3) if sb else None
        record["workloads"][w] = entry
        for name, m in entry["modes"].items():
            lines.append(f"| {w} | {name} | {m['medianS']:.4f} | {m['p95S']:.4f} | {m.get('ratioMedian', '')} | {m.get('ratioMedianSamePlacement', '')} | {m.get('lastRunStops') or ''} | {m.get('lastRunTracerCpuMs') if m.get('lastRunTracerCpuMs') is not None else ''} |")
    record["markdownTable"] = "\n".join(lines)
    with open(a.out, "w") as f:
        json.dump(record, f, indent=2)
    print("\n".join(lines))
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
