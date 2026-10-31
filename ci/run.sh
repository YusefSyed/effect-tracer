#!/usr/bin/env bash
# What CI runs after the build: clean runs of the toy agent and the bypass
# corpus in both modes. Run it locally the same way (needs a Linux kernel
# with ptrace; inside Docker, --cap-add SYS_PTRACE or --privileged).
set -euo pipefail
cd "$(dirname "$0")/.."
TRACER=${TRACER:-target/release/effect-tracer}
[ -x "$TRACER" ] || cargo build --release --locked
STAMP=$(date -u +%Y-%m-%dT%H%M%SZ)
OUT=bench/runs/ci-$STAMP
mkdir -p "$OUT"
export PYTHONDONTWRITEBYTECODE=1
python3 bench/toy_run.py --tracer "$TRACER" --mode full --runs "${CLEAN_RUNS:-5}" --out "$OUT/clean-full.json"
python3 bench/toy_run.py --tracer "$TRACER" --mode seccomp --runs "${CLEAN_RUNS:-5}" --out "$OUT/clean-seccomp.json"
python3 bench/corpus.py --tracer "$TRACER" --mode full --out "$OUT/corpus-full.json"
# In seccomp mode io_uring_setup is denied in the kernel before any stop, so
# c10 is EPERM but unlogged: 19 of 20 expected, with the note on the row.
python3 bench/corpus.py --tracer "$TRACER" --mode seccomp --out "$OUT/corpus-seccomp.json" || true
python3 - "$OUT/corpus-seccomp.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
missed = [r for r in d["rows"] if r["id"].startswith("c") and not r["caught"]]
assert all(r["id"] == "c10" and "note" in r for r in missed), f"unexpected misses in seccomp mode: {[r['id'] for r in missed]}"
print(f"seccomp corpus: {d['caught']}/{d['total']} caught, c10 denied but unlogged as expected")
PY
echo "ci/run.sh: all checks passed; results in $OUT"
