#!/usr/bin/env bash
# Build the BPF object against this kernel's BTF and load every program
# through bpftool, printing the verifier's complaint if one is refused.
set -euo pipefail
out=${1:-target/bpf}
mkdir -p "$out"
[ -s "$out/vmlinux.h" ] || bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$out/vmlinux.h"
arch=$(uname -m); case $arch in aarch64) arch=arm64;; x86_64) arch=x86;; esac
clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_$arch -I"$out" -c bpf/effects.bpf.c -o "$out/effects.bpf.o"
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
rm -rf /sys/fs/bpf/et-check
if bpftool prog loadall "$out/effects.bpf.o" /sys/fs/bpf/et-check > "$out/load.log" 2>&1; then
  echo "loaded: $(ls /sys/fs/bpf/et-check | tr '\n' ' ')"
else
  grep -vE "^libbpf: (prog|map) .*(created|pinned)" "$out/load.log" | grep -E "^[^0-9]" | tail -25
  exit 1
fi
rm -rf /sys/fs/bpf/et-check
