#!/usr/bin/env bash
# Overhead of --mode ebpf, same workloads and hyperfine settings as
# bench/overhead.sh. W0 (/bin/true) measures the fixed cost of loading and
# attaching the BPF programs, which every traced run pays once.
#
#   bench/overhead_ebpf.sh [RUNS=10] [WARMUP=2]      (as root)
set -euo pipefail
cd "$(dirname "$0")/.."
RUNS=${1:-10}; WARMUP=${2:-2}
TRACER=${TRACER:-$PWD/target/release/effect-tracer}
STAMP=$(date -u +%Y-%m-%dT%H%M%SZ)
OUTDIR=$PWD/bench/runs/overhead-ebpf-$STAMP
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
CMD[W0]="/bin/true"
CMD[W1]="dd if=/dev/zero of=/dev/null bs=1 count=${W1_COUNT:-500k} status=none"
CMD[W2]="python3 $PWD/bench/toy_agent.py"
CMD[W3]="$VENV/bin/pip install -q --no-index --find-links $WHEELS --force-reinstall --no-deps requests"
CMD[W4]="python3 -m pytest -q -p no:cacheprovider $W4"

for W in W0 W1 W2 W3 W4; do
  echo "=== $W: ${CMD[$W]}"
  hyperfine -N --warmup "$WARMUP" --runs "$RUNS" --export-json "$OUTDIR/$W.json" \
    -n none "${CMD[$W]}" \
    -n ebpf "$TRACER run --quiet --force --mode ebpf --dns-port $DNS_PORT --out /tmp/et-ov-$W-ebpf -- ${CMD[$W]}"
  cp /tmp/et-ov-$W-ebpf/ledger.json "$OUTDIR/$W-ebpf-ledger.json"
done
python3 bench/overhead_summarize.py "$OUTDIR" --tracer "$TRACER" --runs "$RUNS" --warmup "$WARMUP" --out "bench/overhead-ebpf-$STAMP.json"
