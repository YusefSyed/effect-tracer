# Benchmarks: method, environment, results

Every number quoted in README.md comes from a JSON file in `bench/`. This
file says how each one is produced so it can be reproduced or disputed.

## Environment

| item | value |
|---|---|
| host | Apple M5 MacBook Pro, 10 cores, 32 GB, macOS 26 |
| Docker Desktop | 4.86.0 (engine 29.7.2), VM 10 CPU / 8 GB (lowered from 20 GB for this work) |
| container | `rust:1-bookworm`, `--privileged --memory 4g --cpus 6`; Debian 12, Python 3.11.2, hyperfine 1.15.0 |
| kernel | `6.12.76-linuxkit` aarch64 (Docker Desktop's VM kernel) |
| tracer | release build, `cargo 1.99.1`; version and build profile in the JSON `env` block |

Container numbers are a VM-on-a-laptop measurement. The `env` block of each
JSON records kernel, machine, CPU count, memory, tracer version and date,
plus `hostNote` when the run was made elsewhere (a stock-kernel cloud box is
the better place for the overhead table; see README).

## Workloads

| id | command | why |
|---|---|---|
| W1 | `dd if=/dev/zero of=/dev/null bs=1 count=500k status=none` | about 1,024,000 syscalls doing nothing else: the ptrace worst case (Brendan Gregg's strace example) |
| W2 | `python3 bench/toy_agent.py` | an agent-shaped mix: 200 file writes, 50 local HTTP calls, 20 subprocesses, 10 DNS lookups against `bench/stubs.py` |
| W3 | `pip install --no-index --find-links WHEELS --force-reinstall --no-deps requests` in a venv | a package install: many small file writes and opens, no network |
| W4 | `python3 -m pytest -q -p no:cacheprovider bench/w4_tests` | 200 small tests with some file I/O |

Modes: `none` (untraced), `ptrace` (`--mode full`: a stop at every syscall
entry and exit), `ptrace+seccomp` (`--mode seccomp`: a seccomp filter traps
only the effect syscalls to the tracer, after testing their arguments in
the kernel, plus one stop for their exit).

## Overhead: `bench/overhead.sh` -> `bench/overhead-<stamp>.json`

hyperfine, `-N` (no shell), 2 warmups, 10 runs per command, three commands
per workload. The JSON holds hyperfine's full result (mean, median, min,
max, every timing, user and system CPU) plus, per traced mode, the stats of
the last run's ledger: ptrace stops, tracer CPU ms, events, coverage. p95 is
the nearest-rank 95th percentile of the 10 timings. The markdown table in
README is `markdownTable` from that JSON.

Stop rule from the plan: if ptrace+seccomp costs more than 50 percent on W2
after four hours of tuning, the eBPF path becomes the default. The table
says which side of that line v0.1 landed.

## False positives: `bench/toy_run.py --runs 30` -> `bench/clean-runs-<date>-<mode>.json`

Thirty traced runs of W2 against a declared manifest (roots = the work
directory; hosts = the HTTP and DNS stub ports; dnsSuffixes = `.toy.test`;
exes = python3, sh, cat) and the published ignore list `bench/ignore.json`.
Reported: runs with any undeclared event, total undeclared events, total
ignored events, runs verified, runs with complete coverage.

## Catch rate: `bench/corpus.py` -> `bench/corpus-<date>-<mode>.json`

Twenty seeded bypasses, one tracer invocation each (`bench/bypass/cases.py`):

| id | case | expected event |
|---|---|---|
| c01 | subprocess shell redirect | file.write by `sh` |
| c02 | `os.system` redirect | file.write by `sh` |
| c03 | rename over an undeclared path | file.rename |
| c04 | `O_TMPFILE` then `linkat` via `/proc/self/fd` | file.link |
| c05 | shared writable `mmap` | file.map-write |
| c06 | `sendfile` into a file | file.write via sendfile |
| c07 | `/dev/shm` write | file.write `/dev/shm/...` |
| c08 | raw UDP `sendto` | socket.send `udp:` |
| c09 | unix socket connect | socket.connect `unix:` |
| c10 | `io_uring_setup` attempt | coverage.gap denied |
| c11 | `copy_file_range` | file.write via copy_file_range |
| c12 | write through a symlink that leaves the root | file.write with the resolved target |
| c13 | hard link of an outside file into the root | file.link with `from` outside |
| c14 | `truncate` by path | file.write via truncate |
| c15 | `chmod` | file.meta |
| c16 | `unlink` | file.delete |
| c17 | `mkdir` | file.create |
| c18 | DNS query for an undeclared name | dns.query |
| c19 | TCP connect to an undeclared port | socket.connect `tcp:` |
| c20 | exec of an undeclared binary | process.exec |

Six more are reported separately (x21 thread write, x22 forked-child write,
x23 memfd_create, x24 splice, x25 ftruncate and x26 connect after
`PR_SET_DUMPABLE 0`). A case counts as caught when the expected
event is in the ledger and the ledger verifies. The seccomp-mode row for c10
is expected to be "denied, unlogged": the filter returns EPERM inside the
kernel before any ptrace stop.

## Results

### 2026-10-31, container on the Mac (release build, kernel 6.12.76-linuxkit aarch64, 10 CPUs visible, 7.9 GB VM)

Catch rate (`bench/corpus-2026-10-31-full.json`, `bench/corpus-2026-10-31-seccomp.json`):

| mode | c01-c20 | x21-x26 | ledgers verified |
|---|---|---|---|
| ptrace (full) | 20/20 | 6/6 | all |
| ptrace+seccomp | 19/20 (c10 denied, unlogged) | 6/6 | all |

x25 and x26 call `prctl(PR_SET_DUMPABLE, 0)` and then `ftruncate` or
`connect`. They count as caught when the ledger holds either the event or
a declared gap for it. As root the tracer sees through non-dumpable and
records the events. As uid 65534 (`setpriv --reuid 65534`,
`bench/corpus-2026-10-31-{full,seccomp}-unprivileged.json`) the scores are
the same, 20/20 + 6/6 and 19/20 + 6/6. x25 and x26 become
`ftruncate: descriptor name unreadable` and `connect: sockaddr unreadable`,
and those two ledgers verify with exit 3 (coverage partial). Before this
change the same calls left no event and coverage `complete`. That was a
reviewer's finding from reading the code; these cases are its test.

The same corpus in an unprivileged container with Docker's default seccomp
profile and no added capability (`bench/corpus-2026-10-31-full-docker-default.json`,
`...-seccomp-docker-default.json`): 18/20 full, 17/20 seccomp, 6/6 extra,
all ledgers verified. That profile denies `pidfd_getfd`, so c08 and c19 are
in the ledger as `ip:127.0.0.1:<port>` (listed per row in
`sameKindRecorded`) and fail the strict `udp:`/`tcp:` check. With
`--cap-add SYS_PTRACE` the same container scores 20/20 and 19/20.

False positives (`bench/clean-runs-2026-10-31-full.json`, `bench/clean-runs-2026-10-31-seccomp.json`):

| mode | runs | runs with undeclared events | undeclared events | ignored events | verified + complete |
|---|---|---|---|---|---|
| ptrace (full) | 30 | 0 | 0 | 0 | 30/30 |
| ptrace+seccomp | 30 | 0 | 0 | 0 | 30/30 |

Per run: 356 events; full mode about 11,760 ptrace stops, seccomp mode 829
(from the `stats` block of each run's ledger, recorded in `perRun`).
The wall clocks in those files were taken on a laptop under load and are not
overhead numbers.

Overhead (`bench/overhead-2026-10-31T041430Z.json`; run 04:14-04:31Z with
the Mac otherwise quiet: VM load average 0.36 at the start; another
container's short job overlapped only W1's untraced rows, which were
rechecked alone afterwards at 0.2450 s against 0.2427 s):

| workload | mode | median s | p95 s | x untraced | stops (last run) | tracer CPU ms (last run) |
|---|---|---|---|---|---|---|
| W1 | none | 0.2427 | 0.2484 | 1.0 | | |
| W1 | ptrace | 75.6065 | 76.8300 | 311.478 | 2048102 | 19300 |
| W1 | ptrace+seccomp | 0.2942 | 0.2982 | 1.212 | 7 | 1 |
| W2 | none | 0.0663 | 0.0725 | 1.0 | | |
| W2 | ptrace | 0.5188 | 0.5943 | 7.826 | 11782 | 121 |
| W2 | ptrace+seccomp | 0.1100 | 0.1211 | 1.66 | 829 | 16 |
| W3 | none | 0.2889 | 0.3579 | 1.0 | | |
| W3 | ptrace | 1.4176 | 1.5410 | 4.907 | 28833 | 314 |
| W3 | ptrace+seccomp | 0.3525 | 0.4013 | 1.22 | 427 | 10 |
| W4 | none | 0.2236 | 0.3304 | 1.0 | | |
| W4 | ptrace | 1.7203 | 1.9354 | 7.692 | 35754 | 377 |
| W4 | ptrace+seccomp | 0.3779 | 0.4171 | 1.69 | 3289 | 54 |

What the table says:

- W1 is the bound. In full mode each of about a million syscalls costs two
  stops, about 37 microseconds per stop on this VM, of which the tracer's
  own CPU is about 9 (19.3 s over 2,048,102 stops). The rest is the kernel
  switching to the tracer on another CPU and back.
- Seccomp mode leaves W1 almost alone (7 stops: the exec and exit events).
- On W2 and W4 seccomp mode is over the plan's 50 percent line. Nearly all of
  W4's stops are pytest's output capture: 1,204 `ftruncate` calls on its own
  temporary files (two stops each). The tracer's CPU explains about a third
  of the extra time; the rest is again cross-CPU wakeups. That is what
  `--pin-cpu` addresses, and why the harness now also measures every mode
  pinned (rows `@cpuN`, compared with an untraced run pinned the same way).

Pinned rows, second and third runs. `bench/overhead-2026-10-31T051602Z.json`
ran all six commands per workload from 05:16Z (VM load 0.02 at the start).
During its W2-W4 rows a file search on the host used about five CPUs:
W2's untraced median rose from 0.066 s to 0.112 s, and W3 seccomp came out
faster than W3 untraced. Its W1 rows are long enough not to care and are
the ones used. W2-W4 were re-run at 05:38Z with the host quiet
(`WORKLOADS="W2 W3 W4"`, `bench/overhead-2026-10-31T053837Z.json`, VM
load 1.02).

| workload | mode | median s | p95 s | x untraced | x untraced, same CPU | stops (last run) | tracer CPU ms (last run) |
|---|---|---|---|---|---|---|---|
| W1 | none | 0.2639 | 0.2673 | 1.0 | 1.0 | | |
| W1 | ptrace | 78.5516 | 108.9540 | 297.689 | 297.689 | 2048104 | 20217 |
| W1 | ptrace+seccomp | 0.2946 | 0.2978 | 1.116 | 1.116 | 7 | 1 |
| W1 | none@cpu2 | 0.2431 | 0.2472 | 0.921 | 1.0 | | |
| W1 | ptrace@cpu2 | 5.5894 | 5.7261 | 21.182 | 22.994 | 2048104 | 3858 |
| W1 | ptrace+seccomp@cpu2 | 0.2405 | 0.2572 | 0.911 | 0.989 | 7 | 1 |
| W2 | none | 0.0635 | 0.0648 | 1.0 | 1.0 | | |
| W2 | ptrace | 0.5018 | 0.5266 | 7.899 | 7.899 | 11782 | 117 |
| W2 | ptrace+seccomp | 0.1048 | 0.1063 | 1.649 | 1.649 | 829 | 15 |
| W2 | none@cpu2 | 0.0582 | 0.0613 | 0.916 | 1.0 | | |
| W2 | ptrace@cpu2 | 0.0993 | 0.1020 | 1.563 | 1.706 | 11776 | 26 |
| W2 | ptrace+seccomp@cpu2 | 0.0729 | 0.0795 | 1.147 | 1.253 | 829 | 6 |
| W3 | none | 0.2678 | 0.2955 | 1.0 | 1.0 | | |
| W3 | ptrace | 1.3703 | 1.5995 | 5.117 | 5.117 | 28846 | 266 |
| W3 | ptrace+seccomp | 0.2969 | 0.3000 | 1.109 | 1.109 | 431 | 7 |
| W3 | none@cpu2 | 0.2713 | 0.2791 | 1.013 | 1.0 | | |
| W3 | ptrace@cpu2 | 0.3580 | 0.3986 | 1.337 | 1.32 | 28631 | 55 |
| W3 | ptrace+seccomp@cpu2 | 0.2826 | 0.3012 | 1.055 | 1.042 | 411 | 4 |
| W4 | none | 0.1938 | 0.1983 | 1.0 | 1.0 | | |
| W4 | ptrace | 1.5893 | 2.6457 | 8.202 | 8.202 | 35760 | 342 |
| W4 | ptrace+seccomp | 0.3600 | 0.3665 | 1.858 | 1.858 | 3289 | 47 |
| W4 | none@cpu2 | 0.1948 | 0.1979 | 1.005 | 1.0 | | |
| W4 | ptrace@cpu2 | 0.3100 | 0.3135 | 1.6 | 1.591 | 35766 | 78 |
| W4 | ptrace+seccomp@cpu2 | 0.2292 | 0.2481 | 1.183 | 1.177 | 3289 | 20 |

The stop rule: unpinned, seccomp mode costs 65 percent on W2, over the
plan's 50 percent line. Pinned, it costs 25 percent against an untraced
run on the same CPU, and 15 percent against the default untraced run. For
serial workloads, v0.1 lands under the line with `--pin-cpu` and over it
without. That is the case the planned eBPF backend is for.

### M3: the eBPF backend (`--mode ebpf`, built with `--features ebpf`)

Same container, release build, run as root. Clean runs, corpus and
agreement are light and were run while another job held the machine;
they are counts, not timings.

- Agreement (`bench/agreement.py --a full --b ebpf --runs 30` ->
  `bench/agreement-2026-10-31-full-vs-ebpf.json`): each run traces the toy
  agent under both backends with identical paths and compares the
  multisets of (kind, name, outcome) without run.start/run.end. 30/30 runs
  identical, 354 events each.
- Oracle (`bench/oracle.py --mode ebpf|full --runs 10` ->
  `bench/oracle-2026-10-31-{ebpf,full}.json`): bpftrace 0.17 on
  `tracepoint:syscalls:*` and `sched:*`, filtered on a fresh cgroup the
  agent joins, counts successful write-intent opens, mkdirat, unlinkat,
  renames, connects, sendto with a destination, copy_file_range, execs,
  forks and exits in the same run as the tracer. 10/10 runs agree in both
  modes: open.write 201, connect 50, exec 21, exit 21, fork 20,
  copy_file_range 20, sendto 10, mkdir 1. Two by-construction exclusions,
  both in the wrapper before it joins the cgroup: its exec and its write
  to cgroup.procs.
- Corpus (`bench/corpus-2026-10-31-ebpf.json`): 19/20 + 6/6 (x25 and x26, the non-dumpable cases, are ordinary events here: the kernel side does not care). c04 fails with
  EXDEV in this container in every mode, also with `TMPDIR=/dev/shm`. ptrace
  records the failed `linkat`; the LSM hook is never reached.
- Clean runs (`bench/clean-runs-2026-10-31-ebpf.json`): 30 runs, 0
  undeclared, 0 ignored, 30/30 verified with complete coverage.
- Fixed cost: `effect-tracer run --mode ebpf -- /bin/true` took 1.80-1.82 s
  wall and 0.12-0.17 s CPU, three runs. The overhead harness for this mode is
  `bench/overhead_ebpf.sh`; its W0 row (/bin/true) measures the same thing.
- Overhead (`bench/overhead_ebpf.sh 10 2` at 05:40Z, VM load 0.73,
  `bench/overhead-ebpf-2026-10-31T054013Z.json`). Medians: W0 none 0.0002,
  ebpf 1.8102; W1 0.2438 / 2.1261; W2 0.0662 / 1.8772; W3 0.2697 / 2.0822;
  W4 0.1940 / 2.0256. Run cost = ebpf median minus the W0 ebpf median, over
  the untraced median: W1 1.30x, W2 1.01x, W3 1.01x, W4 1.11x. W1's extra
  0.072 s over 1,024,000 syscalls is about 70 ns per syscall for the two raw
  tracepoint programs.
- An earlier run of the same harness at 05:36Z (not published, not cited)
  used a binary whose loop found the root's exit only at a 50 ms poll
  timeout. That added an uneven tail to every run and made W2 minus W0 come
  out smaller than untraced W2. The loop now also polls a pidfd of the root.
