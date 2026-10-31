//! The ptrace loop: spawn the root under PTRACE_SEIZE, follow every fork,
//! clone and exec, decode effect syscalls at their entry and exit stops, and
//! append events to the ledger. See EXPLAIN.md for the walkthrough.

use std::collections::{HashMap, HashSet};
use std::ffi::{c_void, CString};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use nix::errno::Errno;
use nix::sys::ptrace::{self, Options};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use serde_json::{json, Map, Value};

use super::syscalls::{self, Sys};
use super::{dns, mem, paths, procinfo, seccomp, sockets};
use crate::ledger::{self, Ledger};
use crate::{canon, timefmt, Mode, RunArgs, VERSION};

const PTRACE_GET_SYSCALL_INFO: u32 = 0x420e;
const PTRACE_LISTEN: u32 = 0x4208;

const INFO_ENTRY: u8 = 1;
const INFO_EXIT: u8 = 2;
const INFO_SECCOMP: u8 = 3;

const MAX_GAP_REASONS: usize = 64;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

fn raw_ptrace(req: u32, tid: i32, addr: usize, data: usize) -> i64 {
    // SAFETY: a plain ptrace request; addr and data are what the request expects.
    unsafe {
        libc::ptrace(
            req as _,
            tid as libc::pid_t,
            addr as *mut c_void,
            data as *mut c_void,
        ) as i64
    }
}

enum SyscallInfo {
    Entry {
        nr: i64,
        args: [u64; 6],
    },
    Exit {
        rval: i64,
    },
    Seccomp {
        nr: i64,
        args: [u64; 6],
        ret_data: u32,
    },
    Other(u8),
}

/// PTRACE_GET_SYSCALL_INFO (Linux 5.3+): architecture-neutral access to the
/// syscall number, arguments and return value at a stop.
fn get_syscall_info(tid: i32) -> Option<SyscallInfo> {
    let mut buf = [0u8; 128];
    let r = raw_ptrace(
        PTRACE_GET_SYSCALL_INFO,
        tid,
        buf.len(),
        buf.as_mut_ptr() as usize,
    );
    if r < 0 {
        return None;
    }
    let u64_at = |o: usize| u64::from_ne_bytes(buf[o..o + 8].try_into().unwrap());
    let args_at = |base: usize| {
        let mut a = [0u64; 6];
        for (i, slot) in a.iter_mut().enumerate() {
            *slot = u64_at(base + 8 * i);
        }
        a
    };
    let arch = u32::from_ne_bytes(buf[4..8].try_into().unwrap());
    Some(match buf[0] {
        // A foreign-ABI number means something else in the native table
        // (i386 257 is x86_64 openat), so it is not decoded: nr -1 matches
        // nothing, and the seccomp stop that follows records the gap.
        INFO_ENTRY if arch != syscalls::NATIVE_AUDIT_ARCH => SyscallInfo::Entry {
            nr: -1,
            args: [0; 6],
        },
        INFO_ENTRY => SyscallInfo::Entry {
            nr: u64_at(24) as i64,
            args: args_at(32),
        },
        INFO_EXIT => SyscallInfo::Exit {
            rval: u64_at(24) as i64,
        },
        INFO_SECCOMP => SyscallInfo::Seccomp {
            nr: u64_at(24) as i64,
            args: args_at(32),
            ret_data: u32::from_ne_bytes(buf[80..84].try_into().unwrap()),
        },
        op => SyscallInfo::Other(op),
    })
}

/// An event decoded at syscall entry, waiting for the outcome at exit.
struct Partial {
    kind: &'static str,
    name: String,
    detail: Map<String, Value>,
    /// Replace `name` with the path behind the returned fd on success.
    refine_from_fd: bool,
    /// On success, remember this fd as a resolver socket.
    mark_dns_fd: Option<i32>,
    /// Further events sharing the outcome (for example a dns.query under a
    /// socket.send).
    extra: Vec<(&'static str, String, Map<String, Value>)>,
}

struct Pending {
    partial: Option<Partial>,
}

struct Task {
    tgid: i32,
    pending: Option<Pending>,
    /// In seccomp mode: resume with PTRACE_SYSCALL once more to get the exit stop.
    expect_exit: bool,
}

struct Proc {
    ppid: i32,
    exec_id: String,
    parent_exec_id: String,
    comm: String,
    exe: String,
    gen: u32,
    start: u64,
    dns_fds: HashSet<i32>,
    pidfd: Option<OwnedFd>,
    exited: bool,
}

pub struct Tracer {
    args: RunArgs,
    ledger: Ledger,
    tasks: HashMap<i32, Task>,
    procs: HashMap<i32, Proc>,
    boot_id: String,
    dns_ports: HashSet<u16>,
    stops: u64,
    events: u64,
    procs_seen: u64,
    gaps: Vec<String>,
    gap_set: HashSet<String>,
    root: i32,
    root_status: Option<WaitStatus>,
    interrupted_handled: bool,
    fatal: Option<String>,
    self_ref: Value,
    pinned_cpu: Option<usize>,
}

pub(crate) fn exec_id(boot_id: &str, pid: i32, start: u64, gen: u32) -> String {
    let short: String = boot_id.chars().take(8).collect();
    format!("{short}:{pid}:{start}:{gen}")
}

pub(crate) fn errno_name(e: i32) -> String {
    format!("{:?}", Errno::from_raw(e))
}

/// Search PATH the way execvp does, without executing anything.
pub(crate) fn resolve_on_path(cmd: &str) -> String {
    if cmd.contains('/') {
        return cmd.to_string();
    }
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string());
    for dir in path.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let candidate = format!("{dir}/{cmd}");
        if let Ok(md) = std::fs::metadata(&candidate) {
            use std::os::unix::fs::PermissionsExt;
            if md.is_file() && md.permissions().mode() & 0o111 != 0 {
                return candidate;
            }
        }
    }
    cmd.to_string()
}

pub(crate) fn child_exec(
    rfd: i32,
    wfd: i32,
    prog: &[libc::sock_filter],
    exe: &CString,
    argv: &[*const libc::c_char],
    run_as: Option<(u32, u32)>,
) -> ! {
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        libc::close(wfd);
        if let Some((uid, gid)) = run_as {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                let m = b"effect-tracer: --run-as: could not switch user\n";
                libc::write(2, m.as_ptr() as *const c_void, m.len());
                libc::_exit(126);
            }
        }
        if seccomp::install(prog).is_err() {
            let m = b"effect-tracer: seccomp filter install failed\n";
            libc::write(2, m.as_ptr() as *const c_void, m.len());
            libc::_exit(126);
        }
        let mut b = [0u8; 1];
        loop {
            let r = libc::read(rfd, b.as_mut_ptr() as *mut c_void, 1);
            if r == 1 {
                break;
            }
            if r < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            libc::_exit(125);
        }
        libc::close(rfd);
        libc::execv(exe.as_ptr(), argv.as_ptr());
        let m = b"effect-tracer: exec failed: ";
        libc::write(2, m.as_ptr() as *const c_void, m.len());
        let err = libc::strerror(*libc::__errno_location());
        libc::write(2, err as *const c_void, libc::strlen(err));
        libc::write(2, b"\n".as_ptr() as *const c_void, 1);
        libc::_exit(127);
    }
}

/// Restrict this process to one CPU; the child forked next inherits the
/// mask, and so does every task in its tree unless it changes its own.
pub(crate) fn pin_to_cpu(spec: &str) -> Result<usize> {
    let cpu = if spec == "auto" {
        // SAFETY: sched_getcpu takes no arguments.
        let c = unsafe { libc::sched_getcpu() };
        if c < 0 {
            bail!("sched_getcpu: {}", Errno::last());
        }
        c as usize
    } else {
        spec.parse::<usize>()
            .with_context(|| format!("--pin-cpu takes a CPU number or auto, not {spec:?}"))?
    };
    if cpu >= libc::CPU_SETSIZE as usize {
        bail!("--pin-cpu {cpu}: out of range");
    }
    // SAFETY: cpu_set_t is plain data; CPU_ZERO/CPU_SET only touch it.
    let rc = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set)
    };
    if rc != 0 {
        bail!("sched_setaffinity to CPU {cpu}: {}", Errno::last());
    }
    Ok(cpu)
}

/// `--run-as UID[:GID]`: the ids the root (and so the tree) runs as. Only
/// root can switch users; the point is a tracee that cannot read the
/// tracer's key file or memory.
pub(crate) fn parse_run_as(spec: &Option<String>) -> Result<Option<(u32, u32)>> {
    let Some(spec) = spec else { return Ok(None) };
    let (u, g) = match spec.split_once(':') {
        Some((u, g)) => (u, g),
        None => (spec.as_str(), spec.as_str()),
    };
    let uid: u32 = u
        .parse()
        .with_context(|| format!("--run-as: bad uid {u:?}"))?;
    let gid: u32 = g
        .parse()
        .with_context(|| format!("--run-as: bad gid {g:?}"))?;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("--run-as needs the tracer to run as root");
    }
    if uid == 0 {
        bail!("--run-as 0 would leave the tracee able to read the key; pick another uid");
    }
    Ok(Some((uid, gid)))
}

/// Run the command under the tracer. Returns the root's exit code.
pub fn run(args: RunArgs) -> Result<u8> {
    let run_as = parse_run_as(&args.run_as)?;
    let key = match &args.key {
        Some(p) => ledger::load_key(p)?,
        None => SigningKey::generate(&mut rand::rngs::OsRng),
    };
    let run_id = hex::encode(rand::random::<[u8; 16]>());
    let ledger = Ledger::create(&args.out, args.force, key, run_id.clone(), !args.quiet)?;

    let deny = syscalls::deny_list();
    let rules = if args.mode == Mode::Seccomp {
        syscalls::trace_rules(args.trace_reads)
    } else {
        Vec::new()
    };
    let prog = seccomp::build(&deny, &rules);

    let cargv: Vec<CString> = args
        .command
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<_, _>>()
        .context("a command argument holds a NUL byte")?;
    let mut argv_ptrs: Vec<*const libc::c_char> = cargv.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    // Resolve the executable here so the ledger does not record our own
    // PATH search as failed execs of the root.
    let exe_path = CString::new(resolve_on_path(&args.command[0]).as_bytes())
        .context("the command path holds a NUL byte")?;

    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid two-int array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("pipe2: {}", Errno::last());
    }
    // SAFETY: installing plain signal handlers.
    unsafe {
        let handler: extern "C" fn(libc::c_int) = on_signal;
        let handler = handler as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }

    let pinned_cpu = match &args.pin_cpu {
        Some(spec) => Some(pin_to_cpu(spec)?),
        None => None,
    };

    let started_at = timefmt::now_rfc3339();
    let started_mono = timefmt::mono_ns();
    let wall_start = std::time::Instant::now();

    // SAFETY: the child only runs async-signal-safe code until exec.
    let child = unsafe { libc::fork() };
    if child < 0 {
        bail!("fork: {}", Errno::last());
    }
    if child == 0 {
        child_exec(fds[0], fds[1], &prog, &exe_path, &argv_ptrs, run_as);
    }
    // SAFETY: closing our copy of the read end; then making the tracer
    // non-dumpable (after the fork, so the child does not inherit it), so a
    // same-uid process without CAP_SYS_PTRACE cannot read its memory, where
    // the signing key is.
    unsafe {
        libc::close(fds[0]);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }

    let root = Pid::from_raw(child);
    let opts = Options::PTRACE_O_TRACESYSGOOD
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_TRACEEXEC
        | Options::PTRACE_O_TRACEEXIT
        | Options::PTRACE_O_EXITKILL
        | Options::PTRACE_O_TRACESECCOMP;
    ptrace::seize(root, opts).context("PTRACE_SEIZE")?;
    ptrace::interrupt(root).context("PTRACE_INTERRUPT")?;
    loop {
        match waitpid(root, Some(WaitPidFlag::__WALL)).context("waitpid for the first stop")? {
            WaitStatus::PtraceEvent(_, _, ev) if ev == libc::PTRACE_EVENT_STOP => break,
            WaitStatus::Exited(_, code) => {
                bail!("the child exited with {code} before tracing started")
            }
            WaitStatus::Signaled(_, sig, _) => {
                bail!("the child died with {sig:?} before tracing started")
            }
            _ => {
                let _ = ptrace::cont(root, None);
            }
        }
    }
    // SAFETY: writing one byte to our pipe and closing it.
    unsafe {
        let go = *b"g";
        libc::write(fds[1], go.as_ptr() as *const c_void, 1);
        libc::close(fds[1]);
    }

    let me = std::process::id() as i32;
    let self_ref = json!({
        "pid": me, "tid": me, "ppid": procinfo::ppid(me).unwrap_or(0),
        "execId": "tracer", "parentExecId": "", "comm": "effect-tracer",
        "exe": procinfo::exe(me).unwrap_or_default(),
    });
    let mut dns_ports: HashSet<u16> = args.dns_ports.iter().copied().collect();
    dns_ports.insert(53);
    let mut t = Tracer {
        args,
        ledger,
        tasks: HashMap::new(),
        procs: HashMap::new(),
        boot_id: procinfo::boot_id(),
        dns_ports,
        stops: 0,
        events: 0,
        procs_seen: 0,
        gaps: Vec::new(),
        gap_set: HashSet::new(),
        root: child,
        root_status: None,
        interrupted_handled: false,
        fatal: None,
        self_ref,
        pinned_cpu,
    };
    t.ensure_task(child);
    let start_detail = t.run_start_detail(&run_id, &started_at, started_mono);
    t.emit_self("run.start", run_id.clone(), start_detail.clone());
    t.resume(child, None);
    let loop_result = t.event_loop();

    let mut status = if let Err(e) = &loop_result {
        t.gap(format!("tracer error: {e:#}"));
        "failed"
    } else if t.fatal.is_some() {
        "failed"
    } else if t.gaps.is_empty() {
        "complete"
    } else {
        "partial"
    };
    if t.interrupted_handled && status == "complete" {
        status = "partial";
    }
    let exit = match t.root_status {
        Some(WaitStatus::Exited(_, code)) => json!({"code": code}),
        Some(WaitStatus::Signaled(_, sig, _)) => json!({"signal": format!("{sig:?}")}),
        _ => json!({"unknown": true}),
    };
    let code: u8 = match t.root_status {
        Some(WaitStatus::Exited(_, code)) => (code & 0xff) as u8,
        Some(WaitStatus::Signaled(_, sig, _)) => (128 + sig as i32) as u8,
        _ => 3,
    };
    let end_detail = json!({
        "coverage": {"status": status, "reasons": t.gaps},
        "exit": exit,
        "stats": {
            "events": t.events + 1,
            "stops": t.stops,
            "processes": t.procs_seen,
            "tracerCpuMs": tracer_cpu_ms(),
            "wallMs": wall_start.elapsed().as_millis() as u64,
        },
        "finishedAt": timefmt::now_rfc3339(),
    });
    t.emit_self(
        "run.end",
        run_id,
        end_detail.as_object().cloned().unwrap_or_default(),
    );
    let mut summary = start_detail;
    if let Value::Object(m) = end_detail {
        summary.extend(m);
    }
    summary.insert("limits".into(), limits());
    let Tracer { ledger, fatal, .. } = t;
    ledger.finish(summary)?;
    if let Some(f) = fatal {
        bail!("{f}");
    }
    loop_result?;
    Ok(code)
}

pub(crate) fn tracer_cpu_ms() -> u64 {
    // SAFETY: rusage is a plain struct getrusage fills in.
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut ru);
        let us = (ru.ru_utime.tv_sec as u64) * 1_000_000
            + ru.ru_utime.tv_usec as u64
            + (ru.ru_stime.tv_sec as u64) * 1_000_000
            + ru.ru_stime.tv_usec as u64;
        us / 1000
    }
}

/// Known blind spots, stated in every ledger.
pub fn limits() -> Value {
    json!([
        "io_uring_setup, io_uring_enter and io_uring_register return EPERM from the seccomp filter in every mode and every ABI (native, 32-bit compat, x32); the attempt is recorded as coverage.gap in --mode full only",
        "an effect whose descriptor name or argument memory the tracer may not read (a non-dumpable tracee under an unprivileged tracer) is recorded as coverage.gap, which makes coverage partial when the call succeeds",
        "the ledger is signed by the tracer; a tracee running as the tracer's uid can read a --key file, so pin a key only when the tree runs under --run-as or as another user",
        "syscalls of a foreign ABI (32-bit compat, x32) are recorded as coverage.gap, not decoded",
        "a shared writable mmap is recorded when it is mapped; later stores through the mapping are not",
        "reads are not recorded unless --trace-reads is given",
        "paths are resolved in the tracer's mount namespace; mount, chroot, pivot_root, setns and unshare are coverage gaps",
        "the tracee can see it is traced (TracerPid in /proc/self/status) and seccomp filters in /proc/self/status",
        "a tracee that keeps CAP_SYS_ADMIN can still load BPF, mount or ptrace; those calls are recorded as gaps, not prevented",
        "in --mode seccomp, DNS payloads are read from sendto, sendmsg and sendmmsg only; plain write on a resolver socket is not stopped",
        "setuid binaries do not gain privilege under the tracee (PR_SET_NO_NEW_PRIVS)",
        "a write is recorded when the file is opened for writing inside the tree; writes through descriptors inherited from outside the tree (a redirected stdout) are not"
    ])
}

impl Tracer {
    fn run_start_detail(
        &self,
        run_id: &str,
        started_at: &str,
        started_mono: u64,
    ) -> Map<String, Value> {
        let (release, machine) = procinfo::uname();
        let mut ports: Vec<u16> = self.dns_ports.iter().copied().collect();
        ports.sort_unstable();
        let v = json!({
            "runId": run_id,
            "producer": {"name": "effect-tracer", "version": VERSION},
            "mechanism": self.args.mode.label(),
            "kernel": {"release": release, "machine": machine},
            "bootId": self.boot_id,
            "root": {
                "argv": self.args.command,
                "cwd": std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default(),
            },
            "options": {
                "mode": format!("{:?}", self.args.mode).to_lowercase(),
                "clearArgv": self.args.clear_argv,
                "traceReads": self.args.trace_reads,
                "dnsPorts": ports,
                "pinCpu": self.pinned_cpu,
                "runAs": self.args.run_as,
                "seccompDeny": ["io_uring_setup", "io_uring_enter", "io_uring_register"],
            },
            "startedAt": started_at,
            "startedMonoNs": started_mono.to_string(),
        });
        v.as_object().cloned().unwrap_or_default()
    }

    fn gap(&mut self, reason: String) {
        if self.gap_set.len() >= MAX_GAP_REASONS {
            return;
        }
        if self.gap_set.insert(reason.clone()) {
            self.gaps.push(reason);
        }
    }

    // ----- process and task tables -----

    fn ensure_task(&mut self, tid: i32) {
        if self.tasks.contains_key(&tid) {
            return;
        }
        let tgid = procinfo::tgid(tid).unwrap_or(tid);
        self.ensure_proc(tgid, None);
        self.tasks.insert(
            tid,
            Task {
                tgid,
                pending: None,
                expect_exit: false,
            },
        );
    }

    fn ensure_proc(&mut self, tgid: i32, parent: Option<i32>) {
        if self.procs.contains_key(&tgid) {
            return;
        }
        let ppid = parent.or_else(|| procinfo::ppid(tgid)).unwrap_or(0);
        let (parent_exec_id, dns_fds) = match self.procs.get(&ppid) {
            Some(p) => (p.exec_id.clone(), p.dns_fds.clone()),
            None if ppid == std::process::id() as i32 => ("tracer".to_string(), HashSet::new()),
            None => (String::new(), HashSet::new()),
        };
        let start = procinfo::starttime(tgid).unwrap_or(0);
        self.procs.insert(
            tgid,
            Proc {
                ppid,
                exec_id: exec_id(&self.boot_id, tgid, start, 0),
                parent_exec_id,
                comm: procinfo::comm(tgid),
                exe: procinfo::exe(tgid).unwrap_or_default(),
                gen: 0,
                start,
                dns_fds,
                pidfd: None,
                exited: false,
            },
        );
        self.procs_seen += 1;
    }

    fn tgid_of(&self, tid: i32) -> i32 {
        self.tasks.get(&tid).map(|t| t.tgid).unwrap_or(tid)
    }

    fn proc_ref(&self, tid: i32) -> Value {
        let tgid = self.tgid_of(tid);
        match self.procs.get(&tgid) {
            Some(p) => json!({
                "pid": tgid, "tid": tid, "ppid": p.ppid,
                "execId": p.exec_id, "parentExecId": p.parent_exec_id,
                "comm": p.comm, "exe": p.exe,
            }),
            None => {
                json!({"pid": tgid, "tid": tid, "ppid": 0, "execId": "", "parentExecId": "", "comm": "", "exe": ""})
            }
        }
    }

    fn is_dns_fd(&self, tid: i32, fd: i32) -> bool {
        let tgid = self.tgid_of(tid);
        self.procs
            .get(&tgid)
            .map(|p| p.dns_fds.contains(&fd))
            .unwrap_or(false)
    }

    /// Duplicate a tracee fd into this process (pidfd_getfd, Linux 5.6+).
    fn dup_fd(&mut self, tid: i32, fd: i32) -> Option<OwnedFd> {
        let tgid = self.tgid_of(tid);
        let p = self.procs.get_mut(&tgid)?;
        if p.pidfd.is_none() {
            // SAFETY: pidfd_open takes a pid and flags.
            let r = unsafe {
                libc::syscall(
                    syscalls::NR_PIDFD_OPEN as libc::c_long,
                    tgid as libc::c_long,
                    0 as libc::c_long,
                )
            };
            if r < 0 {
                return None;
            }
            // SAFETY: r is a fresh fd we own.
            p.pidfd = Some(unsafe { OwnedFd::from_raw_fd(r as i32) });
        }
        let pidfd = p.pidfd.as_ref()?.as_raw_fd();
        // SAFETY: pidfd_getfd takes a pidfd, a target fd and flags.
        let r = unsafe {
            libc::syscall(
                syscalls::NR_PIDFD_GETFD as libc::c_long,
                pidfd as libc::c_long,
                fd as libc::c_long,
                0 as libc::c_long,
            )
        };
        if r < 0 {
            None
        } else {
            // SAFETY: r is a fresh fd we own.
            Some(unsafe { OwnedFd::from_raw_fd(r as i32) })
        }
    }

    fn sock_info_of(&mut self, tid: i32, fd: i32) -> Option<sockets::SockInfo> {
        let d = self.dup_fd(tid, fd)?;
        sockets::sock_info(d.as_raw_fd())
    }

    fn peer_name(&mut self, tid: i32, fd: i32) -> Option<String> {
        let d = self.dup_fd(tid, fd)?;
        let info = sockets::sock_info(d.as_raw_fd());
        let a = sockets::peer_addr(d.as_raw_fd())?;
        Some(sockets::render(sockets::label(info, &a), &a))
    }

    fn local_name(&mut self, tid: i32, fd: i32) -> Option<String> {
        let d = self.dup_fd(tid, fd)?;
        let info = sockets::sock_info(d.as_raw_fd());
        let a = sockets::local_addr(d.as_raw_fd())?;
        Some(sockets::render(sockets::label(info, &a), &a))
    }

    // ----- names -----

    fn read_path(&mut self, tid: i32, ptr: u64) -> String {
        if ptr == 0 {
            return String::new();
        }
        match mem::read_cstr(tid, ptr, 4096) {
            Some(b) => String::from_utf8_lossy(&b).into_owned(),
            None => {
                self.gap(format!(
                    "could not read a path argument from pid {}",
                    self.tgid_of(tid)
                ));
                "?".to_string()
            }
        }
    }

    /// Resolve a (dirfd, path) pair to an absolute, lexically normalised path.
    fn resolve_path(&mut self, tid: i32, dirfd: i32, ptr: u64) -> String {
        let s = self.read_path(tid, ptr);
        if s == "?" {
            return s;
        }
        if let Some(fd) = paths::proc_fd_number(&s) {
            if let Some(p) = procinfo::fd_path(tid, fd) {
                return p;
            }
        }
        if s.starts_with('/') {
            return paths::normalize(&s);
        }
        let base = if dirfd == libc::AT_FDCWD {
            procinfo::cwd(tid)
        } else {
            procinfo::fd_path(tid, dirfd as i64)
        };
        let base = match base {
            Some(b) => b,
            None => {
                self.gap(format!(
                    "could not resolve dirfd {dirfd} in pid {}",
                    self.tgid_of(tid)
                ));
                return format!("?/{s}");
            }
        };
        if s.is_empty() {
            base
        } else {
            paths::join(&base, &s)
        }
    }

    // ----- the loop -----

    fn event_loop(&mut self) -> Result<()> {
        loop {
            if self.fatal.is_some() {
                self.kill_all();
            }
            if INTERRUPTED.load(Ordering::SeqCst) && !self.interrupted_handled {
                self.interrupted_handled = true;
                self.gap("interrupted by a signal to the tracer".into());
                self.kill_all();
            }
            let st = match waitpid(None, Some(WaitPidFlag::__WALL)) {
                Ok(s) => s,
                Err(Errno::ECHILD) => break,
                Err(Errno::EINTR) => continue,
                Err(e) => bail!("waitpid: {e}"),
            };
            self.stops += 1;
            match st {
                WaitStatus::PtraceSyscall(pid) => self.on_syscall_stop(pid.as_raw()),
                WaitStatus::PtraceEvent(pid, sig, ev) => self.on_event(pid.as_raw(), sig, ev),
                WaitStatus::Stopped(pid, sig) => {
                    self.ensure_task(pid.as_raw());
                    self.resume(pid.as_raw(), Some(sig));
                }
                WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _) => {
                    self.on_gone(pid.as_raw(), st)
                }
                WaitStatus::Continued(_) | WaitStatus::StillAlive => {}
            }
        }
        Ok(())
    }

    fn kill_all(&mut self) {
        let tids: Vec<i32> = self.tasks.keys().copied().collect();
        for tid in tids {
            // SAFETY: sending SIGKILL to a known tracee.
            unsafe {
                libc::kill(tid, libc::SIGKILL);
            }
        }
    }

    fn resume(&mut self, tid: i32, sig: Option<Signal>) {
        let use_syscall = self.args.mode == Mode::Full
            || self.tasks.get(&tid).map(|t| t.expect_exit).unwrap_or(false);
        let pid = Pid::from_raw(tid);
        let r = if use_syscall {
            ptrace::syscall(pid, sig)
        } else {
            ptrace::cont(pid, sig)
        };
        if let Err(e) = r {
            if e != Errno::ESRCH {
                self.gap(format!("could not resume task {tid}: {e}"));
            }
        }
    }

    fn on_syscall_stop(&mut self, tid: i32) {
        self.ensure_task(tid);
        match get_syscall_info(tid) {
            Some(SyscallInfo::Entry { nr, args }) => self.on_entry(tid, nr, args),
            Some(SyscallInfo::Seccomp { nr, args, .. }) => self.on_entry(tid, nr, args),
            Some(SyscallInfo::Exit { rval }) => {
                if let Some(t) = self.tasks.get_mut(&tid) {
                    t.expect_exit = false;
                }
                self.on_exit(tid, rval);
            }
            Some(SyscallInfo::Other(op)) => {
                self.gap(format!("unexpected syscall_info op {op} for task {tid}"));
                if let Some(t) = self.tasks.get_mut(&tid) {
                    t.pending = None;
                    t.expect_exit = false;
                }
            }
            None => {
                self.gap(format!(
                    "PTRACE_GET_SYSCALL_INFO failed for task {tid}: {}",
                    Errno::last()
                ));
                if let Some(t) = self.tasks.get_mut(&tid) {
                    t.pending = None;
                    t.expect_exit = false;
                }
            }
        }
        self.resume(tid, None);
    }

    fn on_entry(&mut self, tid: i32, nr: i64, args: [u64; 6]) {
        let sys = syscalls::lookup(nr);
        let partial = sys.and_then(|s| self.build_partial(tid, s, &args));
        if let Some(t) = self.tasks.get_mut(&tid) {
            t.pending = sys.map(|_| Pending { partial });
        }
    }

    fn on_exit(&mut self, tid: i32, rval: i64) {
        let pending = self.tasks.get_mut(&tid).and_then(|t| t.pending.take());
        if let Some(Pending { partial: Some(p) }) = pending {
            self.emit_partial(tid, p, rval);
        }
    }

    fn on_event(&mut self, tid: i32, sig: Signal, ev: i32) {
        match ev {
            libc::PTRACE_EVENT_STOP => {
                let known = self.tasks.contains_key(&tid);
                let group_stop = known
                    && matches!(
                        sig,
                        Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU
                    );
                if group_stop {
                    // Stay stopped until SIGCONT, as the job control asked.
                    if raw_ptrace(PTRACE_LISTEN, tid, 0, 0) < 0 {
                        self.resume(tid, None);
                    }
                } else {
                    self.ensure_task(tid);
                    self.resume(tid, None);
                }
            }
            libc::PTRACE_EVENT_SECCOMP => {
                self.ensure_task(tid);
                match get_syscall_info(tid) {
                    Some(SyscallInfo::Seccomp { ret_data, .. })
                        if ret_data == seccomp::TRACE_DATA_COMPAT =>
                    {
                        self.gap(format!(
                            "foreign-ABI syscall in pid {} was not decoded",
                            self.tgid_of(tid)
                        ));
                        self.resume(tid, None);
                    }
                    Some(SyscallInfo::Seccomp { nr, args, .. }) => {
                        self.on_entry(tid, nr, args);
                        if let Some(t) = self.tasks.get_mut(&tid) {
                            t.expect_exit = true;
                        }
                        self.resume(tid, None);
                    }
                    _ => {
                        self.gap(format!("seccomp stop without syscall info for task {tid}"));
                        self.resume(tid, None);
                    }
                }
            }
            libc::PTRACE_EVENT_EXEC => {
                self.on_exec(tid);
                self.resume(tid, None);
            }
            libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE => {
                match ptrace::getevent(Pid::from_raw(tid)) {
                    Ok(new) => self.on_clone(tid, new as i32, ev),
                    Err(e) => self.gap(format!("could not read the new child of {tid}: {e}")),
                }
                self.resume(tid, None);
            }
            libc::PTRACE_EVENT_EXIT => {
                let status = ptrace::getevent(Pid::from_raw(tid)).unwrap_or(0) as i32;
                self.on_exit_event(tid, status);
                self.resume(tid, None);
            }
            _ => self.resume(tid, None),
        }
    }

    fn on_exec(&mut self, tid: i32) {
        let former = ptrace::getevent(Pid::from_raw(tid))
            .map(|v| v as i32)
            .unwrap_or(tid);
        if former != tid {
            self.tasks.remove(&former);
        }
        self.ensure_task(tid);
        if let Some(t) = self.tasks.get_mut(&tid) {
            t.tgid = tid;
            t.pending = None;
        }
        self.ensure_proc(tid, None);
        let exe = procinfo::exe(tid).unwrap_or_else(|| "?".to_string());
        let argv = procinfo::cmdline(tid);
        let mut detail = Map::new();
        detail.insert("argc".into(), json!(argv.len()));
        if self.args.clear_argv {
            detail.insert("argv".into(), json!(argv));
        } else {
            let joined: Vec<u8> = argv
                .iter()
                .flat_map(|a| a.as_bytes().iter().copied().chain(std::iter::once(0u8)))
                .collect();
            detail.insert("argvSha256".into(), json!(canon::sha256_hex(&joined)));
        }
        let boot = self.boot_id.clone();
        if let Some(p) = self.procs.get_mut(&tid) {
            p.gen += 1;
            p.exe = exe.clone();
            p.comm = procinfo::comm(tid);
            p.exec_id = exec_id(&boot, tid, p.start, p.gen);
            p.dns_fds.clear();
        }
        self.emit(tid, "process.exec", exe, "committed", detail);
    }

    fn on_clone(&mut self, parent_tid: i32, new_tid: i32, ev: i32) {
        let parent_tgid = self.tgid_of(parent_tid);
        let is_thread = ev == libc::PTRACE_EVENT_CLONE
            && procinfo::tgid(new_tid)
                .map(|t| t != new_tid)
                .unwrap_or(false);
        if is_thread {
            self.tasks.entry(new_tid).or_insert(Task {
                tgid: parent_tgid,
                pending: None,
                expect_exit: false,
            });
        } else {
            self.ensure_proc(new_tid, Some(parent_tgid));
            self.tasks.entry(new_tid).or_insert(Task {
                tgid: new_tid,
                pending: None,
                expect_exit: false,
            });
        }
        let via = match ev {
            libc::PTRACE_EVENT_FORK => "fork",
            libc::PTRACE_EVENT_VFORK => "vfork",
            _ => "clone",
        };
        let mut detail = Map::new();
        detail.insert("via".into(), json!(via));
        if is_thread {
            detail.insert("thread".into(), json!(true));
            detail.insert("childTid".into(), json!(new_tid));
        } else {
            detail.insert("childPid".into(), json!(new_tid));
            if let Some(c) = self.procs.get(&new_tid) {
                detail.insert("childExecId".into(), json!(c.exec_id));
            }
        }
        let exe = self
            .procs
            .get(&parent_tgid)
            .map(|p| p.exe.clone())
            .unwrap_or_default();
        self.emit(parent_tid, "process.fork", exe, "committed", detail);
    }

    fn on_exit_event(&mut self, tid: i32, status: i32) {
        let tgid = self.tgid_of(tid);
        if tid != tgid {
            return;
        }
        let already = self.procs.get(&tgid).map(|p| p.exited).unwrap_or(true);
        if already {
            return;
        }
        let mut detail = Map::new();
        if libc::WIFEXITED(status) {
            detail.insert("exitCode".into(), json!(libc::WEXITSTATUS(status)));
        } else if libc::WIFSIGNALED(status) {
            detail.insert(
                "signal".into(),
                json!(Signal::try_from(libc::WTERMSIG(status))
                    .map(|s| format!("{s:?}"))
                    .unwrap_or_else(|_| libc::WTERMSIG(status).to_string())),
            );
        }
        let exe = self
            .procs
            .get(&tgid)
            .map(|p| p.exe.clone())
            .unwrap_or_default();
        if let Some(p) = self.procs.get_mut(&tgid) {
            p.exited = true;
        }
        self.emit(tid, "process.exit", exe, "committed", detail);
    }

    fn on_gone(&mut self, tid: i32, st: WaitStatus) {
        let tgid = self.tgid_of(tid);
        self.tasks.remove(&tid);
        if tid == self.root {
            self.root_status = Some(st);
        }
        if !self.tasks.values().any(|t| t.tgid == tgid) {
            self.procs.remove(&tgid);
        }
    }

    // ----- events -----

    fn emit_self(&mut self, kind: &'static str, name: String, detail: Map<String, Value>) {
        let proc_ref = self.self_ref.clone();
        self.append(proc_ref, kind, name, "committed", detail);
    }

    fn emit(
        &mut self,
        tid: i32,
        kind: &'static str,
        name: String,
        outcome: &str,
        detail: Map<String, Value>,
    ) {
        let proc_ref = self.proc_ref(tid);
        self.append(proc_ref, kind, name, outcome, detail);
        self.events += 1;
    }

    fn append(
        &mut self,
        proc_ref: Value,
        kind: &str,
        name: String,
        outcome: &str,
        detail: Map<String, Value>,
    ) {
        let mut ev = Map::new();
        ev.insert(
            "monoNs".into(),
            Value::String(timefmt::mono_ns().to_string()),
        );
        ev.insert("proc".into(), proc_ref);
        ev.insert("kind".into(), Value::String(kind.to_string()));
        ev.insert("name".into(), Value::String(name));
        ev.insert("outcome".into(), Value::String(outcome.to_string()));
        if !detail.is_empty() {
            ev.insert("detail".into(), Value::Object(detail));
        }
        if let Err(e) = self.ledger.append(ev) {
            if self.fatal.is_none() {
                self.fatal = Some(format!("ledger write failed: {e:#}"));
            }
        }
    }

    fn emit_partial(&mut self, tid: i32, p: Partial, rval: i64) {
        let outcome =
            // A non-blocking connect returning EINPROGRESS goes ahead in the
            // kernel; that holds for a connect recorded as a gap too.
            if rval >= 0
                || (rval == -(libc::EINPROGRESS as i64)
                    && p.detail.get("syscall").and_then(Value::as_str) == Some("connect"))
            {
                "committed"
            } else if rval == -(libc::EPERM as i64) || rval == -(libc::EACCES as i64) {
                "denied"
            } else {
                "failed"
            };
        let mut name = p.name;
        if p.refine_from_fd && rval >= 0 {
            if let Some(real) = procinfo::fd_path(tid, rval) {
                name = real;
            }
        }
        let mut detail = p.detail;
        if rval < 0 {
            detail.insert("errno".into(), json!(errno_name((-rval) as i32)));
        }
        if p.kind == "coverage.gap" && outcome == "committed" {
            let tgid = self.tgid_of(tid);
            self.gap(format!("{name} succeeded in pid {tgid}"));
        }
        self.emit(tid, p.kind, name, outcome, detail);
        for (k, n, d) in p.extra {
            self.emit(tid, k, n, outcome, d);
        }
        if rval >= 0 {
            if let Some(fd) = p.mark_dns_fd {
                let tgid = self.tgid_of(tid);
                if let Some(pr) = self.procs.get_mut(&tgid) {
                    pr.dns_fds.insert(fd);
                }
            }
        }
    }

    // ----- decoding -----

    fn build_partial(&mut self, tid: i32, sys: Sys, a: &[u64; 6]) -> Option<Partial> {
        let sysname = syscalls::name(sys);
        let mk = |kind: &'static str, name: String, detail: Map<String, Value>| Partial {
            kind,
            name,
            detail,
            refine_from_fd: false,
            mark_dns_fd: None,
            extra: Vec::new(),
        };
        // An effect whose descriptor name or argument memory cannot be read
        // (a non-dumpable tracee refuses /proc/<pid>/fd and
        // process_vm_readv to an unprivileged tracer) is a gap, never a
        // silent drop: if the call succeeds, coverage reads partial.
        let unreadable = |what: &str| {
            let mut d = Map::new();
            d.insert("syscall".into(), json!(sysname));
            d.insert("unreadable".into(), json!(what));
            Partial {
                kind: "coverage.gap",
                name: format!("{sysname}: {what} unreadable"),
                detail: d,
                refine_from_fd: false,
                mark_dns_fd: None,
                extra: Vec::new(),
            }
        };
        let mut detail = Map::new();
        detail.insert("syscall".into(), json!(sysname));
        match sys {
            Sys::Open | Sys::Openat | Sys::Openat2 | Sys::Creat => {
                let (dirfd, pathp, flags) = match sys {
                    Sys::Open => (libc::AT_FDCWD, a[0], a[1] as i32),
                    Sys::Creat => (
                        libc::AT_FDCWD,
                        a[0],
                        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                    ),
                    Sys::Openat => (a[0] as i32, a[1], a[2] as i32),
                    _ => match mem::read_u64(tid, a[2]) {
                        Some(f) => (a[0] as i32, a[1], f as i32),
                        None => return Some(unreadable("open_how")),
                    },
                };
                if flags & libc::O_PATH != 0 {
                    return None;
                }
                let tmpfile = flags & libc::O_TMPFILE == libc::O_TMPFILE;
                let writes = (flags & libc::O_ACCMODE) != libc::O_RDONLY
                    || flags & (libc::O_CREAT | libc::O_TRUNC) != 0
                    || tmpfile;
                if !writes && !self.args.trace_reads {
                    return None;
                }
                let name = self.resolve_path(tid, dirfd, pathp);
                let kind = if !writes {
                    "file.read"
                } else if tmpfile
                    || (flags & (libc::O_CREAT | libc::O_EXCL)) == (libc::O_CREAT | libc::O_EXCL)
                {
                    "file.create"
                } else {
                    "file.write"
                };
                detail.insert("flags".into(), json!(open_flag_names(flags)));
                if tmpfile {
                    detail.insert("tmpfile".into(), json!(true));
                }
                let mut p = mk(kind, name, detail);
                p.refine_from_fd = true;
                Some(p)
            }
            Sys::Unlink | Sys::Rmdir | Sys::Unlinkat => {
                let (dirfd, pathp, dir) = match sys {
                    Sys::Unlinkat => (a[0] as i32, a[1], a[2] as i32 & libc::AT_REMOVEDIR != 0),
                    Sys::Rmdir => (libc::AT_FDCWD, a[0], true),
                    _ => (libc::AT_FDCWD, a[0], false),
                };
                let name = self.resolve_path(tid, dirfd, pathp);
                if dir {
                    detail.insert("dir".into(), json!(true));
                }
                Some(mk("file.delete", name, detail))
            }
            Sys::Rename | Sys::Renameat | Sys::Renameat2 => {
                let (from, to) = match sys {
                    Sys::Rename => (
                        self.resolve_path(tid, libc::AT_FDCWD, a[0]),
                        self.resolve_path(tid, libc::AT_FDCWD, a[1]),
                    ),
                    _ => (
                        self.resolve_path(tid, a[0] as i32, a[1]),
                        self.resolve_path(tid, a[2] as i32, a[3]),
                    ),
                };
                detail.insert("from".into(), json!(from));
                if sys == Sys::Renameat2 {
                    let f = a[4] as u32;
                    let mut names = Vec::new();
                    if f & 1 != 0 {
                        names.push("RENAME_NOREPLACE");
                    }
                    if f & 2 != 0 {
                        names.push("RENAME_EXCHANGE");
                    }
                    if f & 4 != 0 {
                        names.push("RENAME_WHITEOUT");
                    }
                    if !names.is_empty() {
                        detail.insert("flags".into(), json!(names));
                    }
                }
                Some(mk("file.rename", to, detail))
            }
            Sys::Link | Sys::Linkat => {
                let (from, to) = match sys {
                    Sys::Link => (
                        self.resolve_path(tid, libc::AT_FDCWD, a[0]),
                        self.resolve_path(tid, libc::AT_FDCWD, a[1]),
                    ),
                    _ => {
                        let flags = a[4] as i32;
                        let from = if flags & libc::AT_EMPTY_PATH != 0 {
                            procinfo::fd_path(tid, a[0] as i32 as i64)
                                .unwrap_or_else(|| "?".to_string())
                        } else {
                            self.resolve_path(tid, a[0] as i32, a[1])
                        };
                        (from, self.resolve_path(tid, a[2] as i32, a[3]))
                    }
                };
                detail.insert("from".into(), json!(from));
                Some(mk("file.link", to, detail))
            }
            Sys::Symlink | Sys::Symlinkat => {
                let target = self.read_path(tid, a[0]);
                let name = match sys {
                    Sys::Symlink => self.resolve_path(tid, libc::AT_FDCWD, a[1]),
                    _ => self.resolve_path(tid, a[1] as i32, a[2]),
                };
                detail.insert("symlink".into(), json!(true));
                detail.insert("target".into(), json!(target));
                Some(mk("file.link", name, detail))
            }
            Sys::Mkdir | Sys::Mkdirat | Sys::Mknod | Sys::Mknodat => {
                let (name, mode) = match sys {
                    Sys::Mkdir | Sys::Mknod => (self.resolve_path(tid, libc::AT_FDCWD, a[0]), a[1]),
                    _ => (self.resolve_path(tid, a[0] as i32, a[1]), a[2]),
                };
                if matches!(sys, Sys::Mkdir | Sys::Mkdirat) {
                    detail.insert("dir".into(), json!(true));
                }
                detail.insert("mode".into(), json!(format!("{:o}", mode & 0o7777)));
                Some(mk("file.create", name, detail))
            }
            Sys::Truncate | Sys::Ftruncate => {
                let name = if sys == Sys::Truncate {
                    self.resolve_path(tid, libc::AT_FDCWD, a[0])
                } else {
                    match procinfo::fd_path(tid, a[0] as i32 as i64) {
                        Some(n) => n,
                        None => return Some(unreadable("descriptor name")),
                    }
                };
                detail.insert("via".into(), json!(sysname));
                detail.insert("length".into(), json!(a[1]));
                Some(mk("file.write", name, detail))
            }
            Sys::Chmod | Sys::Fchmod | Sys::Fchmodat | Sys::Fchmodat2 => {
                let (name, mode) = match sys {
                    Sys::Chmod => (self.resolve_path(tid, libc::AT_FDCWD, a[0]), a[1]),
                    Sys::Fchmod => match procinfo::fd_path(tid, a[0] as i32 as i64) {
                        Some(n) => (n, a[1]),
                        None => return Some(unreadable("descriptor name")),
                    },
                    _ => (self.resolve_path(tid, a[0] as i32, a[1]), a[2]),
                };
                detail.insert("mode".into(), json!(format!("{:o}", mode & 0o7777)));
                Some(mk("file.meta", name, detail))
            }
            Sys::Chown | Sys::Lchown | Sys::Fchown | Sys::Fchownat => {
                let (name, uid, gid) = match sys {
                    Sys::Fchown => match procinfo::fd_path(tid, a[0] as i32 as i64) {
                        Some(n) => (n, a[1], a[2]),
                        None => return Some(unreadable("descriptor name")),
                    },
                    Sys::Fchownat => (self.resolve_path(tid, a[0] as i32, a[1]), a[2], a[3]),
                    _ => (self.resolve_path(tid, libc::AT_FDCWD, a[0]), a[1], a[2]),
                };
                detail.insert("uid".into(), json!(uid as u32 as i64));
                detail.insert("gid".into(), json!(gid as u32 as i64));
                Some(mk("file.meta", name, detail))
            }
            Sys::Utimensat => {
                let name = if a[1] == 0 {
                    match procinfo::fd_path(tid, a[0] as i32 as i64) {
                        Some(n) => n,
                        None => return Some(unreadable("descriptor name")),
                    }
                } else {
                    self.resolve_path(tid, a[0] as i32, a[1])
                };
                Some(mk("file.meta", name, detail))
            }
            Sys::Mmap => {
                let prot = a[2] as i32;
                let flags = a[3] as i32;
                let fd = a[4] as i32;
                if prot & libc::PROT_WRITE == 0 || flags & libc::MAP_SHARED == 0 || fd < 0 {
                    return None;
                }
                let name = match procinfo::fd_path(tid, fd as i64) {
                    Some(n) => n,
                    None => return Some(unreadable("descriptor name")),
                };
                if !name.starts_with('/') {
                    return None;
                }
                detail.insert("length".into(), json!(a[1]));
                Some(mk("file.map-write", name, detail))
            }
            Sys::Sendfile | Sys::CopyFileRange | Sys::Splice => {
                let out = match sys {
                    Sys::Sendfile => a[0],
                    _ => a[2],
                } as i32;
                let target = match procinfo::fd_path(tid, out as i64) {
                    Some(n) => n,
                    None => return Some(unreadable("descriptor name")),
                };
                detail.insert("via".into(), json!(sysname));
                if target.starts_with("socket:") {
                    let peer = self.peer_name(tid, out).unwrap_or(target);
                    Some(mk("socket.send", peer, detail))
                } else if target.starts_with("pipe:") || target.starts_with("anon_inode:") {
                    None
                } else {
                    Some(mk("file.write", target, detail))
                }
            }
            Sys::MemfdCreate => {
                let n = self.read_path(tid, a[0]);
                detail.insert("anonymous".into(), json!(true));
                Some(mk("file.create", format!("memfd:{n}"), detail))
            }
            Sys::Execve | Sys::Execveat => {
                let name = match sys {
                    Sys::Execve => self.resolve_path(tid, libc::AT_FDCWD, a[0]),
                    _ => {
                        let flags = a[4] as i32;
                        let p = self.read_path(tid, a[1]);
                        if p.is_empty() && flags & libc::AT_EMPTY_PATH != 0 {
                            procinfo::fd_path(tid, a[0] as i32 as i64)
                                .unwrap_or_else(|| "?".to_string())
                        } else {
                            self.resolve_path(tid, a[0] as i32, a[1])
                        }
                    }
                };
                Some(mk("process.exec", name, detail))
            }
            Sys::Socket => {
                let domain = a[0] as i32;
                let typ = (a[1] as i32) & 0xf;
                if domain == libc::AF_PACKET || typ == libc::SOCK_RAW {
                    detail.insert("domain".into(), json!(domain));
                    detail.insert("type".into(), json!(typ));
                    detail.insert("protocol".into(), json!(a[2] as i32));
                    detail.insert(
                        "reason".into(),
                        json!("raw or packet sockets carry payloads the tracer does not decode"),
                    );
                    Some(mk("coverage.gap", "raw-socket".to_string(), detail))
                } else {
                    None
                }
            }
            Sys::Connect | Sys::Bind => {
                let fd = a[0] as i32;
                let len = (a[2] as usize).min(128);
                let bytes = match mem::read(tid, a[1], len) {
                    Some(b) => b,
                    None => return Some(unreadable("sockaddr")),
                };
                let addr = sockets::parse_sockaddr(&bytes)?;
                let info = self.sock_info_of(tid, fd);
                let label = sockets::label(info, &addr);
                let name = sockets::render(label, &addr);
                if label == "ip" {
                    detail.insert("transportUnknown".into(), json!(true));
                }
                let kind = if sys == Sys::Connect {
                    "socket.connect"
                } else {
                    "socket.bind"
                };
                let mut p = mk(kind, name, detail);
                // "ip": the socket type could not be read (pidfd_getfd
                // denied, as in Docker's default profile). Treat it as a
                // possible resolver; a payload that is not DNS is ignored.
                if sys == Sys::Connect
                    && (label == "udp" || label == "ip")
                    && addr
                        .port()
                        .map(|pt| self.dns_ports.contains(&pt))
                        .unwrap_or(false)
                {
                    p.mark_dns_fd = Some(fd);
                }
                Some(p)
            }
            Sys::Listen => {
                let fd = a[0] as i32;
                let name = self.local_name(tid, fd).unwrap_or_else(|| "?".to_string());
                detail.insert("backlog".into(), json!(a[1] as i32));
                Some(mk("socket.listen", name, detail))
            }
            Sys::Sendto => {
                let fd = a[0] as i32;
                let payload = mem::read(tid, a[1], (a[2] as usize).min(512));
                let addr = if a[4] != 0 && a[5] > 0 {
                    match mem::read(tid, a[4], (a[5] as usize).min(128)) {
                        Some(b) => Some(b),
                        None => return Some(unreadable("destination")),
                    }
                } else {
                    None
                };
                self.send_partial(tid, fd, sysname, a[2], addr, payload, detail)
            }
            Sys::Sendmsg => {
                let fd = a[0] as i32;
                let (addr, payload, len) = match read_msghdr(tid, a[1]) {
                    Some(v) => v,
                    None => return Some(unreadable("msghdr")),
                };
                self.send_partial(tid, fd, sysname, len, addr, payload, detail)
            }
            Sys::Sendmmsg => {
                let fd = a[0] as i32;
                let vlen = (a[2] as usize).min(8);
                let mut first: Option<Partial> = None;
                for i in 0..vlen {
                    let (addr, payload, len) = match read_msghdr(tid, a[1] + (i as u64) * 64) {
                        Some(v) => v,
                        None if i == 0 => return Some(unreadable("msghdr")),
                        None => break,
                    };
                    let mut d = Map::new();
                    d.insert("syscall".into(), json!(sysname));
                    if let Some(p) = self.send_partial(tid, fd, sysname, len, addr, payload, d) {
                        match first.as_mut() {
                            None => first = Some(p),
                            Some(f) => {
                                f.extra.push((p.kind, p.name, p.detail));
                                f.extra.extend(p.extra);
                            }
                        }
                    }
                }
                first
            }
            Sys::Write | Sys::Writev | Sys::Pwrite64 | Sys::Pwritev | Sys::Pwritev2 => {
                let fd = a[0] as i32;
                if !self.is_dns_fd(tid, fd) {
                    return None;
                }
                let payload = match sys {
                    Sys::Write | Sys::Pwrite64 => mem::read(tid, a[1], (a[2] as usize).min(512)),
                    _ => first_iov(tid, a[1], a[2]),
                }?;
                let (q, t) = dns::parse_query(&payload)?;
                detail.insert("qtype".into(), json!(dns::qtype_name(t)));
                Some(mk("dns.query", q, detail))
            }
            Sys::IoUringSetup | Sys::IoUringEnter | Sys::IoUringRegister => {
                detail.insert("reason".into(), json!("io_uring submits I/O without a syscall per operation; the seccomp filter returns EPERM"));
                Some(mk("coverage.gap", sysname.to_string(), detail))
            }
            Sys::ProcessVmWritev => {
                detail.insert(
                    "reason".into(),
                    json!("writes into another process's memory"),
                );
                Some(mk("coverage.gap", sysname.to_string(), detail))
            }
            Sys::ProcessVmReadv => {
                detail.insert(
                    "reason".into(),
                    json!(
                        "reads another process's memory (a same-uid tracer's signing key, for one)"
                    ),
                );
                Some(mk("coverage.gap", sysname.to_string(), detail))
            }
            Sys::Ptrace => {
                detail.insert(
                    "reason".into(),
                    json!("a tracee that traces another process acts through it"),
                );
                Some(mk("coverage.gap", sysname.to_string(), detail))
            }
            Sys::Bpf => {
                detail.insert(
                    "reason".into(),
                    json!("a BPF program can observe or alter I/O without syscalls"),
                );
                Some(mk("coverage.gap", sysname.to_string(), detail))
            }
            Sys::Mount
            | Sys::Umount2
            | Sys::MoveMount
            | Sys::Fsmount
            | Sys::PivotRoot
            | Sys::Chroot
            | Sys::Setns
            | Sys::Unshare => {
                detail.insert(
                    "reason".into(),
                    json!("changes the namespace the tracer resolves paths in"),
                );
                Some(mk("coverage.gap", sysname.to_string(), detail))
            }
            Sys::InitModule
            | Sys::FinitModule
            | Sys::DeleteModule
            | Sys::KexecLoad
            | Sys::KexecFileLoad => {
                detail.insert("reason".into(), json!("loads or replaces kernel code"));
                Some(mk("coverage.gap", sysname.to_string(), detail))
            }
        }
    }

    /// socket.send (with a destination) or dns.query (on a known resolver fd).
    #[allow(clippy::too_many_arguments)]
    fn send_partial(
        &mut self,
        tid: i32,
        fd: i32,
        sysname: &'static str,
        len: u64,
        addr_bytes: Option<Vec<u8>>,
        payload: Option<Vec<u8>>,
        mut detail: Map<String, Value>,
    ) -> Option<Partial> {
        let query = payload.as_deref().and_then(dns::parse_query);
        if let Some(bytes) = addr_bytes {
            let addr = sockets::parse_sockaddr(&bytes)?;
            let info = self.sock_info_of(tid, fd);
            let label = sockets::label(info, &addr);
            let name = sockets::render(label, &addr);
            detail.insert("bytes".into(), json!(len));
            if label == "ip" {
                detail.insert("transportUnknown".into(), json!(true));
            }
            let is_dns = (label == "udp" || label == "ip")
                && addr
                    .port()
                    .map(|p| self.dns_ports.contains(&p))
                    .unwrap_or(false);
            let mut extra = Vec::new();
            if is_dns {
                if let Some((q, t)) = query {
                    let mut d = Map::new();
                    d.insert("syscall".into(), json!(sysname));
                    d.insert("qtype".into(), json!(dns::qtype_name(t)));
                    d.insert("server".into(), json!(name));
                    extra.push(("dns.query", q, d));
                }
            }
            Some(Partial {
                kind: "socket.send",
                name,
                detail,
                refine_from_fd: false,
                mark_dns_fd: None,
                extra,
            })
        } else if self.is_dns_fd(tid, fd) {
            let (q, t) = query?;
            detail.insert("qtype".into(), json!(dns::qtype_name(t)));
            Some(Partial {
                kind: "dns.query",
                name: q,
                detail,
                refine_from_fd: false,
                mark_dns_fd: None,
                extra: Vec::new(),
            })
        } else {
            None
        }
    }
}

/// (msg_name bytes, first iov payload, total length) of a struct msghdr.
type MsgParts = (Option<Vec<u8>>, Option<Vec<u8>>, u64);

fn read_msghdr(tid: i32, hdr: u64) -> Option<MsgParts> {
    let h = mem::read(tid, hdr, 56)?;
    if h.len() < 56 {
        return None;
    }
    let u64_at = |o: usize| u64::from_ne_bytes(h[o..o + 8].try_into().unwrap());
    let name_ptr = u64_at(0);
    let name_len = u32::from_ne_bytes(h[8..12].try_into().unwrap());
    let iov_ptr = u64_at(16);
    let iov_len = u64_at(24);
    let addr = if name_ptr != 0 && name_len > 0 {
        mem::read(tid, name_ptr, (name_len as usize).min(128))
    } else {
        None
    };
    let (payload, total) = match iov_total(tid, iov_ptr, iov_len) {
        Some((p, t)) => (p, t),
        None => (None, 0),
    };
    Some((addr, payload, total))
}

/// First iovec payload (up to 512 bytes) and the total length of an iovec array.
fn iov_total(tid: i32, iov_ptr: u64, iov_len: u64) -> Option<(Option<Vec<u8>>, u64)> {
    if iov_ptr == 0 || iov_len == 0 {
        return None;
    }
    let n = (iov_len as usize).min(16);
    let raw = mem::read(tid, iov_ptr, 16 * n)?;
    let mut total = 0u64;
    let mut first: Option<Vec<u8>> = None;
    for i in 0..(raw.len() / 16) {
        let base = u64::from_ne_bytes(raw[i * 16..i * 16 + 8].try_into().unwrap());
        let len = u64::from_ne_bytes(raw[i * 16 + 8..i * 16 + 16].try_into().unwrap());
        total = total.saturating_add(len);
        if first.is_none() && len > 0 {
            first = mem::read(tid, base, (len as usize).min(512));
        }
    }
    Some((first, total))
}

fn first_iov(tid: i32, iov_ptr: u64, iov_len: u64) -> Option<Vec<u8>> {
    iov_total(tid, iov_ptr, iov_len)?.0
}

pub(crate) fn open_flag_names(flags: i32) -> Vec<&'static str> {
    let mut v = Vec::new();
    match flags & libc::O_ACCMODE {
        libc::O_RDONLY => v.push("O_RDONLY"),
        libc::O_WRONLY => v.push("O_WRONLY"),
        libc::O_RDWR => v.push("O_RDWR"),
        _ => {}
    }
    let table = [
        (libc::O_CREAT, "O_CREAT"),
        (libc::O_EXCL, "O_EXCL"),
        (libc::O_TRUNC, "O_TRUNC"),
        (libc::O_APPEND, "O_APPEND"),
        (libc::O_NOFOLLOW, "O_NOFOLLOW"),
        (libc::O_CLOEXEC, "O_CLOEXEC"),
        (libc::O_DIRECT, "O_DIRECT"),
        (libc::O_SYNC, "O_SYNC"),
    ];
    for (bit, name) in table {
        if flags & bit == bit {
            v.push(name);
        }
    }
    if flags & libc::O_TMPFILE == libc::O_TMPFILE {
        v.push("O_TMPFILE");
    } else if flags & libc::O_DIRECTORY != 0 {
        v.push("O_DIRECTORY");
    }
    v
}
