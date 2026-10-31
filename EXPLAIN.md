# How the tracer works, in the order the kernel sees it

This is the walkthrough of the ptrace core, written so it can be explained
at a whiteboard without the code open. Function names in brackets point at
`src/sys/tracer.rs` unless another file is named.

## In sixty seconds

A process can only change the world through syscalls (and through a few
things the tracer names as gaps). effect-tracer forks the command, installs
a seccomp filter in the child before it execs, attaches to it with
`PTRACE_SEIZE`, and from then on the kernel stops every task in that tree at
each interesting syscall. At each stop the tracer asks the kernel what the
syscall is (`PTRACE_GET_SYSCALL_INFO`), reads the arguments it needs out of
the tracee's memory, waits for the matching exit stop to learn whether the
kernel accepted the call, and appends one canonical JSON line to a ledger.
Every line carries the hash of the previous line; at the end the tracer signs
the last hash with an Ed25519 key. A 300-line stdlib Python script re-checks
all of it. If the tracer dies, `PTRACE_O_EXITKILL` kills the whole tree, so
nothing ever runs unobserved and un-ledgered.

## 1. The handshake: fork, filter, pipe, seize [`run`, `child_exec`]

1. The parent builds the seccomp program and the argv before forking, so
   the child allocates nothing (a forked child of a Rust program must stay
   async-signal-safe until exec).
2. `pipe2(O_CLOEXEC)`, then `fork()`.
3. The child: `prctl(PR_SET_NO_NEW_PRIVS)` and `seccomp(SET_MODE_FILTER)`
   [`seccomp::install`]. NO_NEW_PRIVS is what lets an unprivileged process
   install a filter, and it also means setuid binaries do not gain privilege
   under the tracee. The filter is inherited by every descendant and cannot
   be removed. Then the child blocks on `read()` of the pipe.
4. The parent: `PTRACE_SEIZE(child, options)`, then `PTRACE_INTERRUPT`, then
   `waitpid` until it sees the `PTRACE_EVENT_STOP`. Only now does it write a
   byte into the pipe: the child's `read` returns, it closes the pipe and
   calls `execv` of the path the parent already resolved on `PATH`.
5. From the first `PTRACE_SYSCALL` (or `PTRACE_CONT` in seccomp mode) on, the
   loop owns the tree.

Why the pipe: without it the child could exec before the tracer attached,
and the first syscalls of the real program would be lost. Why resolve `PATH`
in the parent: otherwise the child's own `execvp` search shows up in the
ledger as failed execs of paths that do not exist.

## 2. Why SEIZE and these options

`PTRACE_SEIZE` is the modern attach: unlike `PTRACE_ATTACH` it does not send
SIGSTOP, so it does not disturb the tracee's job control, and it turns on
the `PTRACE_EVENT_STOP` and `PTRACE_LISTEN` machinery that lets a tracer keep
a group-stopped tracee stopped instead of silently resuming it. The options,
passed in the SEIZE call itself:

| option | what it buys |
|---|---|
| `TRACESYSGOOD` | syscall stops arrive as `SIGTRAP \| 0x80`, so a real SIGTRAP (a breakpoint, a debugger) is not mistaken for a syscall stop |
| `TRACECLONE`, `TRACEFORK`, `TRACEVFORK` | every new task is attached automatically, with the same options, before it runs a single instruction; the parent gets an event carrying the child's id |
| `TRACEEXEC` | exec is reported as an event (with the former thread id), not as a legacy SIGTRAP after exec |
| `TRACEEXIT` | the exit status is readable while the task still exists |
| `EXITKILL` | the kernel SIGKILLs every tracee when the tracer exits for any reason |
| `TRACESECCOMP` | a filter rule `SECCOMP_RET_TRACE` becomes a `PTRACE_EVENT_SECCOMP` stop |

## 3. The loop [`event_loop`, `resume`]

`waitpid(-1, __WALL)` returns the next stopped or finished task of any kind
(`__WALL` is what makes threads visible, not just children). Each status is
one of:

- syscall stop (`PtraceSyscall`): ask `PTRACE_GET_SYSCALL_INFO`; entry or exit.
- event stop (`PtraceEvent`): STOP, SECCOMP, EXEC, FORK/VFORK/CLONE, EXIT.
- signal-delivery stop (`Stopped`): resume and inject the same signal, so
  the program behaves as if untraced.
- gone (`Exited`, `Signaled`): drop the task; remember the root's status.

The resume rule is the only state machine: in full mode always
`PTRACE_SYSCALL`; in seccomp mode `PTRACE_CONT`, except that a task that
just had a seccomp stop is resumed once with `PTRACE_SYSCALL` so its exit
stop arrives (strace's `--seccomp-bpf` does the same). `ESRCH` on resume
means the task died between stops and is not an error.

Group-stops: with SEIZE a job-control stop (SIGSTOP, SIGTSTP, SIGTTIN,
SIGTTOU) arrives as `PTRACE_EVENT_STOP` with that signal. The tracer answers
`PTRACE_LISTEN`, which keeps the tracee stopped until a SIGCONT, exactly as
the shell asked. A `PTRACE_EVENT_STOP` with SIGTRAP is the other case: our
own INTERRUPT, or a new child's first stop. Those are resumed.

## 4. `PTRACE_GET_SYSCALL_INFO` [`get_syscall_info`]

Since Linux 5.3 a tracer can ask for a `struct ptrace_syscall_info` instead
of poking registers. The 24-byte header has `op` (1 entry, 2 exit, 3
seccomp), `arch` (the audit architecture of the ABI in use), instruction
and stack pointers. Then:

- entry: `nr` (u64) and six `args` (u64 each);
- exit: `rval` (i64) and `is_error`;
- seccomp: `nr`, `args`, and the filter's `ret_data` (u16 in a u32).

The tracer reads a 128-byte buffer and takes fields by offset (24, 32..80,
80). This is why the same binary runs on x86_64 and aarch64 with no
register code: only the syscall number tables differ [`syscalls.rs`].

## 5. Pairing entry and exit [`on_entry`, `on_exit`, `build_partial`, `emit_partial`]

At entry the tracer classifies the number [`syscalls::lookup`] and, if it
is an effect syscall, decodes a `Partial` event: kind, name, details,
everything but the outcome. Paths are read then, because an `unlink` target
no longer exists at exit. The partial is stored on the task (per tid; each
thread has its own syscall in flight). At the exit stop the return value
decides the outcome: `>= 0` committed, `-EPERM`/`-EACCES` denied, any
other negative value failed with the errno name. One exception: a
non-blocking `connect` returning `EINPROGRESS` is committed, since the
kernel is carrying the attempt on.

For opens the name is refined at exit: with the returned fd in hand,
`readlink /proc/<tid>/fd/<fd>` gives the kernel's own absolute path, which
resolves symlinks, `..`, relative paths and `dirfd` for free. That is why
writing through a symlink that leaves the declared root (corpus case c12)
is recorded under the real target.

## 6. Names without the file system lying to us [`resolve_path`, `paths.rs`, `procinfo.rs`]

A path argument is read from the tracee with `process_vm_readv`
[`mem.rs`], page by page so a string that crosses into an unmapped page
still yields what exists. Relative paths are joined onto
`readlink /proc/<tid>/cwd` or onto the `dirfd`'s own `readlink
/proc/<tid>/fd/N`, then normalised lexically. `/proc/self/fd/N` and
`/dev/fd/N` arguments (the `O_TMPFILE` + `linkat` trick, case c04) are
resolved through the fd they name.

Sockets: `connect`/`bind`/`sendto` carry a `sockaddr` in memory, decoded
into `tcp:host:port`, `udp:...`, `unix:/path` or `unix:@abstract`
[`sockets.rs`]. The transport comes from the socket itself: `pidfd_open` +
`pidfd_getfd` (Linux 5.6) duplicates the tracee's fd into the tracer, where
`getsockopt(SO_TYPE)` and `getpeername`/`getsockname` answer honestly even
for inherited fds. Docker's default seccomp profile denies `pidfd_getfd`
to a container without `CAP_SYS_PTRACE`; then the type is unknown, the
name says `ip:` instead of `tcp:` or `udp:`, the event carries
`transportUnknown`, and a send to a DNS port is still parsed as DNS (a
payload that does not parse is ignored). DNS: a UDP `connect` or `sendto` to port 53 (or a
`--dns-port`) marks the fd as a resolver socket; the payload of that
`sendto`/`sendmsg`/`sendmmsg` (and, in full mode, `write`) is parsed for its
first question, which becomes `dns.query` with the QNAME.

## 7. The seccomp program [`seccomp.rs`]

Classic BPF, about twenty instructions plus one block per syscall of
interest:

```
ld  arch                    ; seccomp_data.arch
jeq NATIVE ? native : +0    ; a foreign ABI (i386, AArch32) falls through:
  ld nr
  jeq 425|426|427 ? ret ERRNO|EPERM   ; io_uring is 425-427 there too
  ret TRACE|1               ; anything else: tell the tracer, decode nothing
native:
ld  nr
[x86_64] jge 0x40000000 ? same three checks with the x32 bit, then ret TRACE|1
jeq io_uring_setup    ? ret ERRNO|EPERM
jeq io_uring_enter    ? ret ERRNO|EPERM
jeq io_uring_register ? ret ERRNO|EPERM
jeq openat ? ld args[2]; jset O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|__O_TMPFILE ? ret TRACE : ret ALLOW
jeq mmap   ? ld args[2]; jset PROT_WRITE ? ld args[3]; jset MAP_SHARED ? ret TRACE : ret ALLOW
jeq socket ? ld args[0]; jeq AF_PACKET ? ret TRACE; ld args[1]; and 0xf; jeq SOCK_RAW ? ret TRACE : ret ALLOW
jeq unlinkat ? ret TRACE            ; and so on, one block per effect syscall (seccomp mode only)
...
ret ALLOW
```

The argument tests are what make seccomp mode cheap on real programs: a
Python start-up opens several hundred files read-only and maps as many
private pages, and none of those is an effect. Classic BPF can read the low
32 bits of each argument (`seccomp_data.args`), so the decision is made in
the kernel and the tracee never stops. The tracer applies the same
classification at the stop, so the two modes write the same ledger.

Two facts make the io_uring rule the right tool. First, io_uring submits
I/O through a shared ring; once a ring exists, a process can write files and
send packets with no syscall per operation, which blinds any syscall-based
tracer (the "Curing" rootkit of 2025 blinded Falco and Tetragon this way).
Second, the filter runs inside the kernel on every syscall of every
descendant, before the syscall body, and NO_NEW_PRIVS pins it: the denial
does not depend on the tracer being fast or even alive. In full mode the
tracer also sees the entry and exit stops around the denied call, because
the kernel reports the ptrace syscall-entry stop before it runs seccomp
("do seccomp after ptrace" in `syscall_trace_enter`), so the attempt is
ledgered as `coverage.gap io_uring_setup denied`. In seccomp mode the ERRNO
rule returns before any stop, so the attempt is denied but not written: a
stated limit, and the one case out of twenty the corpus reports as missed in
that mode.

Why `SECCOMP_RET_TRACE` for the effect set rather than tracing everything:
W1 (`dd` with a million one-byte reads and writes) costs two stops per
syscall in full mode and zero in seccomp mode, because `read` and `write`
are not effects by themselves. The ledger stays the same for every workload
whose effects go through the listed syscalls; the price is that plain
`write` on a resolver socket is not seen for DNS names in that mode.

## 8. The ledger [`ledger.rs`, `canon.rs`, `verifier/verify_ledger.py`]

Every event is serialised canonically: sorted keys, no whitespace, no
floats, serde_json's string escaping, which Python's `json.dumps(obj,
sort_keys=True, separators=(",", ":"), ensure_ascii=False)` reproduces byte
for byte. The leaf hash is `SHA-256(0x00 || line)`; the `0x00` is RFC
9162's domain separator so a leaf can never be confused with an interior
node of a tree built later. Each line carries `prev`, the previous leaf
hash; the first carries 64 zeros. The chain is therefore a commitment to the
whole ordered history: edit, drop, insert or reorder a line and every later
`prev` is wrong.

The tracer's own `run.start` (identity, options, kernel) and `run.end`
(coverage, exit status, stats) are events inside the chain. That is the
point: the coverage verdict is signed, not written beside the signature.
At the end the tracer signs the canonical body `{headHash, runId, schema,
signedAt, treeSize}` with Ed25519 and writes `checkpoint.json` with the
public key and its key id (SHA-256 of the SPKI DER). The signature proves
that nothing changed since the tracer signed; who held the key is a
separate question, answered by pinning (`--pubkey`). The test suite plays
the attacker: it rewrites an event, rechains and signs the new head with
its own key (an RFC 8032 signer in the test), and the result passes
everything except the pin. Who can hold the key is the trust boundary in
LEDGER.md: a tracee running as the tracer's user can read a key file, so
pinning means something when the tree runs as another user (`--run-as`).

`ledger.json` is a convenience copy; the verifier checks it against the
chain and fails if it disagrees, so a tampered summary cannot be used to
misreport coverage.

## 9. What it does not see, on purpose [`limits`]

- io_uring: denied, not observed (above), in every ABI. The first version
  sent any foreign-ABI syscall to the tracer before the deny list, so a
  64-bit program could have reached `io_uring_setup` through `int 0x80` on
  an x86_64 kernel with IA32 emulation. The foreign branch now has its own
  deny list.
- Non-dumpable processes: an unprivileged tracer may not read
  `/proc/<pid>/fd/N` or the memory of a process that set
  `PR_SET_DUMPABLE 0`. Every effect whose descriptor name, sockaddr,
  msghdr or `open_how` cannot be read becomes `coverage.gap` (for example
  `ftruncate: descriptor name unreadable`), never a silent drop, so the run
  reads `partial`. Root has `CAP_SYS_PTRACE` and sees through it.
- The tracer's own key: see LEDGER.md, "Trust boundary". The tracer makes
  itself non-dumpable after forking, and `process_vm_readv` by a tracee is
  a gap.
- `mmap(MAP_SHARED, PROT_WRITE)` is recorded when mapped; later stores
  through the mapping are ordinary memory writes with no syscall.
- Reads are off unless `--trace-reads`; the ledger is about effects.
- Paths are resolved in the tracer's mount namespace; `mount`, `chroot`,
  `pivot_root`, `setns`, `unshare` are recorded as gaps because after them
  the names could mean something else.
- The tracee can tell it is traced (`TracerPid`) and that a filter is
  installed. Nothing here is hidden from the program; it is a ledger, not
  a sandbox.
- A tracee that keeps `CAP_SYS_ADMIN` can load BPF, mount, or ptrace a
  process outside the tree. These are gaps, recorded not prevented.
  Confinement (Landlock) is a separate, later feature.
- A daemonising child keeps the tracer alive until it exits; the tree is
  traced to its last task.

### The race a ptrace tracer cannot close (TOCTOU)

At a syscall-entry stop only the stopped thread is frozen. A sibling thread
in the same process keeps running, and the kernel copies a path or a
`sockaddr` out of user memory only after the tracer resumes the call. So a
second thread can rewrite the buffer between "tracer read it" and "kernel
read it". This is the classic ptrace time-of-check/time-of-use gap, and it
is why ptrace-based *sandboxes* are considered unsafe.

What the tracer does about it: for opens, the recorded name is taken at the
exit stop from `/proc/<tid>/fd/<fd>`, which is the kernel's own answer about
the file it actually opened, so a swapped path cannot hide which file was
opened for writing. For `connect` the transport and peer come from
`getpeername` on a duplicate of the fd after the call, again the kernel's
answer. For `unlink`, `rename`, `mkdir` and similar calls there is no fd to
ask, and the recorded name is what the buffer held at entry. A ledger, not a
sandbox: the race can mislabel such an event, it cannot make an effect
vanish from the syscall stream. Closing it fully needs a hook that sees the
kernel's resolved object (an LSM hook), which is the eBPF backend's job.

## 10. Why ptrace, and not an LSM or eBPF, for v0.1

There are four ways to watch a process tree change the world on Linux:

| | ptrace (this tool) | eBPF on tracepoints/kprobes | BPF-LSM hooks | auditd |
|---|---|---|---|---|
| privilege | none (own children) | root or `CAP_BPF`+`CAP_PERFMON` | root, and `bpf` in the active LSM list (often a boot flag) | root, system-wide config |
| sees | syscall arguments in user memory | syscall args, kernel structs | the kernel's resolved object (inode, socket) at the permission check | syscall records |
| TOCTOU on paths | yes (above) | yes on tracepoints; no on LSM | no: the hook runs on the object the kernel will use | yes on strings |
| tree attribution | exact, by auto-attach | needs a cgroup or pid filter that follows forks | same | by audit rules, system-wide |
| cost | two context switches per stop | runs in the kernel, no stop | same | daemon + kernel queue |
| can deny | no (seccomp does that part) | no | yes | no |
| runs on stock CI runners | yes, any Linux 5.6+ container with `SYS_PTRACE` | needs sudo and BTF | needs BPF-LSM enabled, rarely true on hosted runners | needs root |

The v0.1 choice is about who can run it, not speed: a developer or a CI job
can wrap a command with no root, no kernel flag and no BTF, and the tree is
owned by construction because the kernel attaches every child before it
runs. The price is overhead (measured in BENCH.md) and the TOCTOU window
above. The planned second backend is eBPF with LSM hooks (`file_open`,
`path_unlink`, `socket_connect`, `bprm_check_security`) plus a cgroup
filter, writing the same ledger format, so the two can be checked event for
event against each other.

Landlock is the other Linux LSM worth naming: it confines (deny writes
outside a root) without root, but it reports nothing, so it is a later
"enforce" mode, not an observer.

## 11. What seccomp mode cannot log

Seccomp mode makes the tracee stop only when the BPF filter says so. The
filter sees the syscall number and the six register arguments, never memory
behind a pointer. That sets its limits:

| case | full mode | seccomp mode | why |
|---|---|---|---|
| io_uring attempt | denied, logged as `coverage.gap` | denied, **not logged** | the ERRNO rule returns before any ptrace stop; in full mode the syscall-entry stop happens before seccomp runs |
| DNS name sent with plain `write`/`writev` on a connected resolver socket | logged as `dns.query` | connect logged, **name not logged** | the write family is not trapped; trapping it would cost a stop per write in every program |
| read-only opens | logged with `--trace-reads` | logged with `--trace-reads` | without the flag the filter lets `O_RDONLY` opens through in the kernel |
| filtering by path or address | n/a | impossible in the filter | BPF cannot dereference a pointer; the tracer decides at the stop |
| a syscall missing from the effect table | stops, then ignored | runs with no stop | both modes ledger only what `syscalls.rs` lists |

The last row is the one to say out loud: both modes are complete only for
the syscalls the table lists, so a new kernel syscall that writes files is
missed until it is added. Full mode at least stops on it, so recording
unknown numbers as gaps would be a small change there; seccomp mode would
need the filter inverted (allow a list of known-harmless numbers, trap the
rest), which costs stops on every syscall the list forgets. That is why
`run.start` records the mode and the corpus is run in both.

## 12. Questions worth having an answer for

**Why ptrace and not eBPF for v0.1?** ptrace needs no privilege, no BTF, no
kernel headers and no CI runner with sudo, and it owns the tree by
construction (auto-attach), so attribution is exact. eBPF is faster and
invisible to the tracee; it is the planned second backend, with this ledger
format unchanged. Section 10 has the full comparison.

**Why deny io_uring instead of tracing it?** Once a ring exists, reads,
writes, connects and sends are submission-queue entries in shared memory.
`io_uring_enter` can submit thousands at once, and with SQPOLL a kernel
thread submits them with no syscall from the tracee at all. A syscall
tracer cannot see inside the ring, so the honest options are deny or
declare the run partial. Denying with EPERM is safe in practice because programs
that use io_uring already have to fall back to normal syscalls where it is
disabled: Docker's default seccomp profile blocks it, and many distributions
turn it off with the `kernel.io_uring_disabled` sysctl.

**Can a child escape between fork and attach?** No. With
`PTRACE_O_TRACEFORK/VFORK/CLONE` the kernel attaches the new task before it
runs and reports it stopped; the tracer may see the child's first stop
before the parent's fork event, which is why unknown task ids are registered
on sight and filled in later.

**Where does the overhead come from?** Each stop is two context switches
(tracee to tracer and back) plus the ptrace calls. Full mode pays it twice
per syscall; seccomp mode only for effect syscalls plus their exit. The
measured surprise (BENCH.md): on this VM a stop costs about 37
microseconds, but the tracer's own CPU is only about 9 of them. The rest is
the scheduler: the tracee stops on one CPU, the tracer is woken on another
(an inter-processor interrupt, expensive in a VM), and the resume wakes the
tracee back across. Put both on one CPU (`--pin-cpu`) and a stop becomes a
plain switch on that CPU: W1's two million stops drop from 78.6 s to 5.6 s,
about 2.6 microseconds per stop. That is the right default for a serial command
and the wrong one for `make -j`, so it is a flag, not a default.

**Why not drop the exit stop?** The outcome (committed, denied, failed) is
only known at exit, and a ledger that cannot tell a denied write from a
real one is not worth signing. Seccomp mode already skips the entry stop
(the seccomp stop replaces it); the exit is the price of the outcome.

**How do you know you did not miss a syscall?** In full mode the kernel
stops the task at every syscall entry and exit; the only ways out are the
gaps listed in section 9, each of which is either denied or written as a
`coverage.gap`, which turns `run.end` coverage to `partial`. That
includes effects the tracer stopped on but could not name (a non-dumpable
tracee hides its descriptors from an unprivileged tracer). A tracer crash
cannot leave a tree running (EXITKILL) and cannot leave a signed ledger
(there is no `run.end` and no checkpoint).

**What happens on exec of a multithreaded program?** The exec'ing thread
takes over the leader's id and the other threads vanish. The EXEC event
carries the former thread id, which the tracer removes from its table
before recording the exec under the leader.

**A 32-bit program on a 64-bit kernel?** Its syscalls carry a different
`arch` in seccomp_data and different numbers. The filter denies io_uring
in that ABI too and routes everything else to the tracer with
`ret_data = 1`; the tracer records a gap and lets the call proceed. In
full mode the entry stop comes first, and the tracer reads the `arch` field
of `ptrace_syscall_info` so it does not decode a compat number against the
native table (i386 257 is not x86_64 `openat`). Decoding compat calls is
future work, and the coverage verdict says so.

**Why canonical JSON instead of a binary format?** So a verifier in any
language can rebuild the exact bytes from the parsed object, and so a human
can read the ledger with `cat`. The hash commits to bytes; canonical form
is what makes bytes reproducible.
