#!/usr/bin/env python3
"""Compare a ledger against a declared manifest and an ignore list.

    check_manifest.py LEDGER_DIR MANIFEST.json [--ignore IGNORE.json] [--json]

Manifest keys: roots (path prefixes for file.* events), hosts (exact
socket names such as "tcp:127.0.0.1:8080", or with a "*" port), dnsSuffixes
(".toy.test"), exes (basenames or full paths allowed for process.exec).
Structural events (run.*, process.fork, process.exit) are never undeclared.
Everything else that matches neither the manifest nor the ignore list is
reported as undeclared. Exit 0 when nothing is undeclared, else 1.
"""

import argparse
import fnmatch
import json
import os
import sys

STRUCTURAL = {"run.start", "run.end", "process.fork", "process.exit"}


def load(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def host_matches(name, hosts):
    for h in hosts:
        if h == name:
            return True
        if h.endswith(":*") and name.startswith(h[:-1]):
            return True
    return False


def classify(ev, manifest, ignore):
    """Return 'structural', 'declared', 'ignored' or 'undeclared'."""
    kind, name = ev["kind"], ev["name"]
    if kind in STRUCTURAL:
        return "structural"
    if kind.startswith("file."):
        for root in manifest.get("roots", []):
            if name == root or name.startswith(root.rstrip("/") + "/"):
                return "declared"
    elif kind.startswith("socket."):
        if host_matches(name, manifest.get("hosts", [])):
            return "declared"
    elif kind == "dns.query":
        if any(name.endswith(s) for s in manifest.get("dnsSuffixes", [])):
            return "declared"
    elif kind == "process.exec":
        base = os.path.basename(name)
        if name in manifest.get("exes", []) or base in manifest.get("exes", []):
            return "declared"
    for rule in ignore.get("rules", []):
        if rule.get("kind", "*") in ("*", kind) and fnmatch.fnmatchcase(name, rule["name"]):
            if "outcome" in rule and rule["outcome"] != ev.get("outcome"):
                continue
            return "ignored"
    return "undeclared"


def check(ledger_dir, manifest, ignore):
    counts = {"structural": 0, "declared": 0, "ignored": 0, "undeclared": 0}
    undeclared = []
    with open(os.path.join(ledger_dir, "events.jsonl"), "rb") as f:
        for line in f:
            ev = json.loads(line.decode("utf-8"))
            c = classify(ev, manifest, ignore)
            counts[c] += 1
            if c == "undeclared":
                undeclared.append({"seq": ev["seq"], "kind": ev["kind"], "name": ev["name"],
                                   "outcome": ev["outcome"], "comm": ev["proc"].get("comm")})
    return counts, undeclared


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("ledger")
    ap.add_argument("manifest")
    ap.add_argument("--ignore")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    manifest = load(a.manifest)
    ignore = load(a.ignore) if a.ignore else {"rules": []}
    counts, undeclared = check(a.ledger, manifest, ignore)
    if a.json:
        print(json.dumps({"counts": counts, "undeclared": undeclared}, indent=2))
    else:
        print(f"declared={counts['declared']} ignored={counts['ignored']} structural={counts['structural']} undeclared={counts['undeclared']}")
        for u in undeclared:
            print(f"  undeclared #{u['seq']} {u['kind']} {u['name']} {u['outcome']} ({u['comm']})")
    return 0 if not undeclared else 1


if __name__ == "__main__":
    sys.exit(main())
