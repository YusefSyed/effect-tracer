#!/usr/bin/env bash
# Overhead measurement with hyperfine: workloads W1-W4, modes none, ptrace
# (full) and ptrace+seccomp, each also pinned to one CPU (PIN, default 2). Writes hyperfine's JSON per workload plus the
# last-run ledger stats into bench/runs/overhead-<stamp>/, then summarises
# into bench/overhead-<stamp>.json via bench/overhead_summarize.py.
#
#   bench/overhead.sh [RUNS=10] [WARMUP=2]      (WORKLOADS="W2 W3" for a subset)
# Dry run of the harness itself: RUNS=1 WARMUP=0 W1_COUNT=20k bench/overhead.sh 1 0
#
# Setup it needs once (network): WHEELS dir from `pip download requests`,
# a venv for W3; both are created here when missing.
set -euo pipefail
cd "$(dirname "$0")/.."
RUNS=${1:-10}; WARMUP=${2:-2}
TRACER=${TRACER:-$PWD/target/release/effect-tracer}
PIN=${PIN:-2}
STAMP=$(date -u +%Y-%m-%dT%H%M%SZ)
OUTDIR=$PWD/bench/runs/overhead-$STAMP
mkdir -p "$OUTDIR"
export PYTHONDONTWRITEBYTECODE=1
WHEELS=${WHEELS:-/tmp/et-wheels}
VENV=${VENV:-/tmp/et-w3venv}
[ -d "$WHEELS" ] || python3 -m pip download -q -d "$WHEELS" requests==2.32.3
[ -x "$VENV/bin/pip" ] || python3 -m venv "$VENV"
python3 bench/stubs.py > /tmp/et-stubs.out & STUBS=$!
sleep 1
eval "$(head -1 /tmp/et-stubs.out)"
trap 'kill $STUBS 2>/dev/null || true' EXIT
export TOY_ROOT=/tmp/et-w2-root TOY_HTTP_PORT=$HTTP_PORT TOY_DNS_PORT=$DNS_PORT
mkdir -p "$TOY_ROOT"
W4=/tmp/et-w4; rm -rf "$W4"; mkdir -p "$W4"; cp bench/w4_tests/test_w4.py "$W4/"

declare -A CMD
CMD[W1]="dd if=/dev/zero of=/dev/null bs=1 count=${W1_COUNT:-500k} status=none"
CMD[W2]="python3 $PWD/bench/toy_agent.py"
CMD[W3]="$VENV/bin/pip install -q --no-index --find-links $WHEELS --force-reinstall --no-deps requests"
CMD[W4]="python3 -m pytest -q -p no:cacheprovider $W4"

for W in ${WORKLOADS:-W1 W2 W3 W4}; do
  echo "=== $W: ${CMD[$W]}"
  # The @cpuN rows run the tracer and the whole tree on one CPU
  # (--pin-cpu; taskset for the untraced row), so each stop is a switch
  # on that CPU instead of a cross-CPU wakeup.
  hyperfine -N --warmup "$WARMUP" --runs "$RUNS" --export-json "$OUTDIR/$W.json" \
    -n none "${CMD[$W]}" \
    -n ptrace "$TRACER run --quiet --force --dns-port $DNS_PORT --out /tmp/et-ov-$W-full -- ${CMD[$W]}" \
    -n ptrace+seccomp "$TRACER run --quiet --force --mode seccomp --dns-port $DNS_PORT --out /tmp/et-ov-$W-seccomp -- ${CMD[$W]}" \
    -n "none@cpu$PIN" "taskset -c $PIN ${CMD[$W]}" \
    -n "ptrace@cpu$PIN" "$TRACER run --quiet --force --pin-cpu $PIN --dns-port $DNS_PORT --out /tmp/et-ov-$W-full-pin -- ${CMD[$W]}" \
    -n "ptrace+seccomp@cpu$PIN" "$TRACER run --quiet --force --pin-cpu $PIN --mode seccomp --dns-port $DNS_PORT --out /tmp/et-ov-$W-seccomp-pin -- ${CMD[$W]}"
  cp /tmp/et-ov-$W-full/ledger.json "$OUTDIR/$W-ptrace-ledger.json"
  cp /tmp/et-ov-$W-seccomp/ledger.json "$OUTDIR/$W-ptrace+seccomp-ledger.json"
  cp /tmp/et-ov-$W-full-pin/ledger.json "$OUTDIR/$W-ptrace@cpu$PIN-ledger.json"
  cp /tmp/et-ov-$W-seccomp-pin/ledger.json "$OUTDIR/$W-ptrace+seccomp@cpu$PIN-ledger.json"
done
python3 bench/overhead_summarize.py "$OUTDIR" --tracer "$TRACER" --runs "$RUNS" --warmup "$WARMUP" --pin "$PIN" --out "bench/overhead-$STAMP.json"
