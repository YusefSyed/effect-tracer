# Changelog

All dates are 2026.

## 0.1.1 (Oct 31)

- A netlink `SOCK_RAW` socket (what glibc's `getaddrinfo` opens to list
  interfaces) is recorded as `socket.netlink` instead of a raw-socket
  `coverage.gap`, so programs that resolve a hostname through glibc no longer
  end with coverage `partial`.
- Demo recording and `SECURITY.md` added.

## 0.1.0 (Oct 31)

- ptrace backend with `--mode full` and `--mode seccomp`.
- Hash-chained, Ed25519-signed ledger; standard-library Python verifier with
  a tamper test suite.
- Seeded-bypass corpus (20 cases plus 6 extra), clean-run and overhead
  benchmarks; CI on `ubuntu-24.04`.
- Branch `m3-ebpf`: eBPF backend (BPF LSM hooks, root only), unreleased.
