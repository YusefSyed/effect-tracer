# effect-tracer

Records the file writes, socket connects, DNS queries and execs a Linux
process tree makes through syscalls, into a hash-chained, Ed25519-signed
ledger that a 300-line standard-library Python script can verify. Built on
ptrace, so it needs no root, no kernel headers and no eBPF.

```
$ effect-tracer run --out ledger -- sh -c 'echo hi > /tmp/x; cat /tmp/x; rm /tmp/x'
#1 run.start 7a4f… committed pid=1574 effect-tracer
#2 process.exec /usr/bin/dash committed pid=1576 sh
#3 file.write /tmp/x committed pid=1576 sh
#4 process.fork /usr/bin/dash committed pid=1576 sh via="vfork" childPid=1577
#5 process.exec /usr/bin/cat committed pid=1577 cat
hi
#6 process.exit /usr/bin/cat committed pid=1577 cat exitCode=0
#7 process.fork /usr/bin/dash committed pid=1576 sh via="vfork" childPid=1578
#8 process.exec /usr/bin/rm committed pid=1578 rm
#9 file.delete /tmp/x committed pid=1578 rm
#10 process.exit /usr/bin/rm committed pid=1578 rm exitCode=0
#11 process.exit /usr/bin/dash committed pid=1576 sh exitCode=0
#12 run.end 7a4f… committed pid=1574 effect-tracer
$ python3 verifier/verify_ledger.py ledger
OK: 12 events, run 7a4f…, mechanism ptrace, coverage complete, signed by keyid c4bf5567…
```

The use it was built for: running an agent, a build or a test suite and
being able to say afterwards, with a signature, exactly which files it
wrote, which hosts it talked to and which programs it ran, or that the run
had a blind spot (`coverage: partial`) and why.

## What is in the box

| piece | where |
|---|---|
| the tracer (Rust, `nix` + `libc`) | `src/` |
| ledger format | [LEDGER.md](LEDGER.md) |
| how the ptrace core works, step by step | [EXPLAIN.md](EXPLAIN.md) |
| stdlib Python verifier with its own Ed25519 | `verifier/verify_ledger.py`, tamper suite in `verifier/test_verify_ledger.py` |
| benchmarks: method, corpus, results | [BENCH.md](BENCH.md), numbers in `bench/*.json` |
| GitHub Actions example | `examples/action.yml` |

## Install

Linux 5.6 or newer (x86_64 or aarch64; the published runs are aarch64, x86_64 builds are untested), Rust 1.80+.

```
cargo install --git https://github.com/YusefSyed/effect-tracer --tag v0.1.0 --locked
```

No root is needed: the tracer only traces its own children. Inside
Docker, add `--cap-add SYS_PTRACE`. Without it the tracer still runs under
Docker's default seccomp profile, but that profile denies `pidfd_getfd`,
so the tracer cannot read a socket's type: connects and sends are recorded
as `ip:host:port` with `detail.transportUnknown`, and DNS questions are
still parsed. The corpus in such a container
(`bench/corpus-2026-10-31-*-docker-default.json`) scores 18 of 20 in full
mode, the two misses being c08 and c19 recorded as `ip:` where the strict
check expects `udp:` and `tcp:`. The CI workflow targets GitHub's
`ubuntu-24.04` runners without sudo; it has run locally in a container,
not yet on GitHub.

## Use

```
effect-tracer run [--out DIR] [--mode full|seccomp] [--dns-port N]... [--clear-argv] [--trace-reads] [--key FILE] [--pin-cpu [CPU|auto]] [--run-as UID[:GID]] [--quiet] -- COMMAND ARGS...
effect-tracer show DIR
effect-tracer keygen --out FILE
python3 verifier/verify_ledger.py DIR [--pubkey HEX] [--json]
```

- `--mode full` (default) stops the tracee at every syscall entry and exit;
  every syscall in the effect table is seen, at the highest cost.
- `--mode seccomp` installs the same filter but with `SECCOMP_RET_TRACE` on
  the effect syscalls only, and the filter tests arguments inside the
  kernel: a read-only `openat`, a private or read-only `mmap`, an ordinary
  `socket` never stop at all. `read`, `write`, `futex` and friends run at
  native speed. The ledger is the same as in full mode, except that an
  `io_uring_setup` attempt is denied inside the kernel without being
  written down.
- `--dns-port` adds a UDP port to treat as DNS (53 is always one).
- `--key` signs with a persistent key from `keygen` instead of a fresh key
  per run; pin it at verification with `--pubkey`.
- `--pin-cpu` puts the tracer and the whole tree on one CPU (the one the
  tracer starts on, or the number given). Every ptrace stop then switches
  tasks on that CPU instead of waking another, which is much faster for
  serial work (a build step, a test run, an agent) and slower for
  parallel work (`make -j`). Recorded in `run.start`.
- `--run-as UID[:GID]` (tracer as root) runs the command as another user,
  so it can read neither the key file nor the tracer's memory. Without it
  the tracee runs as your own user; see "Trust boundary" in
  [LEDGER.md](LEDGER.md) for what the signature then does and does not
  prove.
- The exit code is the command's own; tracer failures exit 3.

The ledger directory holds `events.jsonl` (the chain), `checkpoint.json`
(the signature over its head) and `ledger.json` (an unsigned summary the
verifier checks against the chain). Verifier exit codes: 0 intact and
complete, 1 tampered, 2 unreadable, 3 intact but incomplete coverage.

## How it works, in one paragraph

The command is forked; the child installs a seccomp filter under
`PR_SET_NO_NEW_PRIVS` and waits on a pipe until the parent has done
`PTRACE_SEIZE` with `TRACESYSGOOD | TRACECLONE | TRACEFORK | TRACEVFORK |
TRACEEXEC | TRACEEXIT | EXITKILL | TRACESECCOMP`. Every task in the tree is
then attached before it runs. At each stop `PTRACE_GET_SYSCALL_INFO`
(Linux 5.3+) gives the syscall number and arguments at entry and the
return value at exit, architecture-neutrally. Path arguments are read with
`process_vm_readv` and resolved through `/proc/<tid>/fd` and `cwd`; sockets
are inspected through `pidfd_getfd`. Each event is one canonical JSON line
whose `prev` is the SHA-256 leaf hash of the line before; the tracer's own
`run.start` and `run.end` (with the coverage verdict) are inside the chain,
and the chain head is signed with Ed25519. `EXITKILL` means a tracer that
dies takes the tree with it, so there is never an unobserved tail. The
io_uring syscalls return EPERM from the filter in both modes and in every
ABI the kernel accepts (native, 32-bit compat, x32), because a ring, once
set up, does I/O without syscalls. [EXPLAIN.md](EXPLAIN.md)
walks through all of it.

## Numbers

Every number below is read from a file in `bench/` whose `env` block names
the kernel, machine, tracer version and date; [BENCH.md](BENCH.md) has the
method. These runs: release build, kernel `6.12.76-linuxkit` aarch64
(Docker Desktop 4.86.0's VM on an Apple M5), Debian 12 container, Python
3.11.2, 2026-10-31.

### Seeded bypasses caught

`bench/corpus-2026-10-31-full.json`, `bench/corpus-2026-10-31-seccomp.json`:
20 ways to produce an effect outside a declared root, one tracer run each.

| mode | caught | note |
|---|---|---|
| `--mode full` | 20 of 20, plus 6 of 6 extra (thread, forked child, memfd, splice, and an ftruncate and a connect after `PR_SET_DUMPABLE 0`) | every ledger verified |
| `--mode seccomp` | 19 of 20, plus 6 of 6 extra | `io_uring_setup` denied by the filter but not recorded (kernel-side EPERM before any stop) |

With the tracer itself unprivileged (`bench/corpus-2026-10-31-*-unprivileged.json`,
uid 65534) the scores are the same. The two non-dumpable cases come out as
declared gaps (`ftruncate: descriptor name unreadable`, `connect: sockaddr
unreadable`) and turn those ledgers' coverage to `partial` (verifier exit
3). An unprivileged tracer may not read a non-dumpable process's
descriptors or memory, and the ledger says so instead of dropping the
event.

The cases: subprocess and `os.system` shell redirects, rename over an
undeclared path, `O_TMPFILE` + `linkat`, shared writable `mmap`,
`sendfile`, `/dev/shm`, raw UDP `sendto`, unix socket connect,
`io_uring_setup`, `copy_file_range`, a write through a symlink that leaves
the root, a hard link of an outside file into the root, `truncate`,
`chmod`, `unlink`, `mkdir`, a DNS query for an undeclared name, a TCP
connect to an undeclared port, exec of an undeclared binary.

### False positives on clean runs

`bench/clean-runs-2026-10-31-full.json`, `bench/clean-runs-2026-10-31-seccomp.json`:
the toy agent (200 file writes, 50 local HTTP calls, 20 subprocesses, 10 DNS
lookups to a local stub) run 30 times per mode against a declared manifest
and the published ignore list `bench/ignore.json`.

| mode | runs | undeclared events | ignored events | ledgers verified, coverage complete |
|---|---|---|---|---|
| `--mode full` | 30 | 0 | 0 | 30 of 30 |
| `--mode seccomp` | 30 | 0 | 0 | 30 of 30 |

Each run records 356 events in both modes (221 `file.write`, 50 `socket.connect`, 10
`socket.send`, 10 `dns.query`, 21 `process.exec`, 20 `process.fork`, 21
`process.exit`, 1 `file.create`, plus `run.start` and `run.end`).

### Overhead

hyperfine, 2 warmups and 10 runs per command, medians, release build. W1 is
`dd bs=1 count=500k` (about a million one-byte syscalls, the ptrace worst
case), W2 the toy agent, W3 an offline `pip install requests` into a venv,
W4 a 200-test pytest suite. W1 comes from
`bench/overhead-2026-10-31T051602Z.json` and W2-W4 from
`bench/overhead-2026-10-31T053837Z.json`, whose rows were re-run on a
quiet machine (BENCH.md says why). Each cell is the median and its ratio to
the untraced run; pinned cells are compared with an untraced run pinned to
the same CPU.

| workload | untraced | `--mode seccomp` | `--mode full` | `--mode seccomp --pin-cpu` | `--mode full --pin-cpu` |
|---|---|---|---|---|---|
| W1 dd, 1M tiny syscalls | 0.264 s | 0.295 s (1.12x) | 78.6 s (298x) | 0.241 s (0.99x) | 5.59 s (23.0x) |
| W2 toy agent | 0.064 s | 0.105 s (1.65x) | 0.502 s (7.90x) | 0.073 s (1.25x) | 0.099 s (1.71x) |
| W3 pip install | 0.268 s | 0.297 s (1.11x) | 1.370 s (5.12x) | 0.283 s (1.04x) | 0.358 s (1.32x) |
| W4 pytest, 200 tests | 0.194 s | 0.360 s (1.86x) | 1.589 s (8.20x) | 0.229 s (1.18x) | 0.310 s (1.59x) |

Stops per run: W1 7 (seccomp) and 2,048,104 (full); W2 829 and about
11,780; W3 about 420 and 28,700; W4 3,289 and about 35,760. Every traced
command exited 0, and its last run's ledger has complete coverage.

What it says: on a VM, most of ptrace's cost is not the tracer's work but
the kernel waking the tracer on another CPU at every stop. W1's two million
stops take 78.6 s spread across CPUs and 5.6 s on one CPU, about 2.6
microseconds per stop. With `--pin-cpu`, seccomp mode costs 0-25 percent on
these serial workloads, and full mode 32-71 percent on W2-W4 (W1, which is
nothing but syscalls, is still 23x). Unpinned, seccomp mode costs 11-86
percent. Pinning is a flag, not the default, because it would serialise a
parallel build. An earlier unpinned run on the same machine
(`bench/overhead-2026-10-31T041430Z.json`) gave 1.21x / 1.66x / 1.22x /
1.69x for seccomp mode and 311x / 7.8x / 4.9x / 7.7x for full mode.

## Limits

Stated in every ledger (`ledger.json.limits`) and in [EXPLAIN.md](EXPLAIN.md) section 9:

- **io_uring** is denied (EPERM from the seccomp filter, inherited by every
  descendant, in the native ABI and in 32-bit compat and x32 alike), not
  observed; in seccomp mode the attempt is not even recorded.
- **non-dumpable processes**: a program that calls `PR_SET_DUMPABLE 0`
  (ssh-agent, gpg-agent) or execs a binary its user cannot read hides its
  descriptor names and memory from an unprivileged tracer. Each effect the
  tracer cannot name is a `coverage.gap` and the run reads `partial`.
  Running the tracer as root (with `--run-as` for the tree) avoids it.
- **foreign ABIs**: 32-bit and x32 syscalls are recorded as gaps, not
  decoded.
- **trust boundary**: the tracer signs. A tracee running as the same user
  can read a `--key` file, so a pinned key proves something only when the
  tree runs as another user (`--run-as`). A per-run key proves the files
  were not edited after the run, not who made them. The tracer marks itself
  non-dumpable, so a same-user tracee cannot read the key out of its
  memory.
- **mmap**: a shared writable mapping is recorded when mapped; later stores
  through it are not syscalls.
- **reads** are not recorded unless `--trace-reads`.
- **namespaces**: paths are resolved in the tracer's mount namespace;
  `mount`, `chroot`, `pivot_root`, `setns`, `unshare` are recorded as
  `coverage.gap` and turn the verdict to `partial`.
- **root and capabilities**: a tracee with `CAP_SYS_ADMIN` can still load
  BPF, mount, or ptrace something outside the tree. Those are gaps, written
  down, not prevented. This is a ledger, not a sandbox; confinement is a
  separate planned mode.
- **ptrace visibility**: the tracee can see `TracerPid` and the filter in
  `/proc/self/status`; `PR_SET_NO_NEW_PRIVS` means setuid binaries run
  without privilege under it.
- **seccomp mode and DNS**: QNAMEs are read from `sendto`, `sendmsg` and
  `sendmmsg`; a resolver that uses plain `write` on a UDP socket is seen as
  the connect only.
- **inherited descriptors**: a write is recorded when the file is opened
  for writing inside the tree; writes through descriptors inherited from
  outside it (a redirected stdout) are not.
- **a program that daemonises** keeps the tracer alive until its last task
  exits.
- **inbound connections**: `listen` is recorded; `accept` and `accept4` are
  not in the effect table, so a connection the tree accepts is not an event.
- **descriptor passing**: a descriptor received over a Unix socket
  (`SCM_RIGHTS`) is not tied to a path; writes through it are not recorded.
- **extended attributes**: the `setxattr` family is not in the effect table.
- **DNS over TCP**: DNS marking needs a UDP or raw IP socket; a resolver
  that uses TCP is seen as the connect only.

## CI and the Action example

`.github/workflows/ci.yml` builds, runs the Rust tests (the integration
test traces a shell script on the runner), the verifier tamper suite, then
`ci/run.sh`: clean runs and the corpus in both modes, with the corpus
results uploaded as artifacts. `examples/action.yml` shows a job that runs
`npm ci` under the tracer, verifies the ledger, and fails on anything the
manifest did not declare.

## Related work and what was borrowed

strace's `--seccomp-bpf` (the stop-only-on-interesting-syscalls trick),
Reverie (ptrace + seccomp tracer architecture in Rust), Tetragon (process
`exec_id` lineage and JSON event shape), gVisor's seccheck (point naming),
and RFC 9162 (leaf hashing). None of their code is used.

## Roadmap

- eBPF backend (aya; LSM hooks + `sys_exit`, cgroup filter) with the same
  ledger, validated event-for-event against this one and a bpftrace oracle.
- DSSE / in-toto Statement envelope around the checkpoint.
- A Landlock confinement mode, so the ledger can also say what was refused.
- Decoding 32-bit ABI syscalls instead of flagging them.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
