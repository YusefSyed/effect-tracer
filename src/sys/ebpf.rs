//! The eBPF backend (`--mode ebpf`, built with `--features ebpf`).
//!
//! `bpf/effects.bpf.c` hooks LSM points (file_open, path_*, socket_*,
//! bprm_committed_creds), the sched_process_{fork,exec,exit} tracepoints and
//! raw_tp/sys_exit. A lineage map that follows fork limits it to the traced
//! tree. This side loads the object with aya, starts the command, and turns
//! ring-buffer records into the same ledger events the ptrace backend
//! writes. Needs root (CAP_BPF + CAP_SYS_ADMIN for LSM programs) and a
//! kernel with BPF LSM active and BTF.

use std::collections::HashMap;
use std::ffi::{c_void, CString};
use std::os::fd::AsRawFd;

use anyhow::{anyhow, bail, Context, Result};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::{BtfTracePoint, Lsm, RawTracePoint};
use aya::{Btf, Ebpf, EbpfLoader};
use ed25519_dalek::SigningKey;
use nix::errno::Errno;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use serde_json::{json, Map, Value};

use super::{dns, procinfo, seccomp, sockets, syscalls, tracer};
use crate::ledger::{self, Ledger};
use crate::{canon, timefmt, RunArgs, VERSION};

static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/effects.bpf.o"));

const K_OPEN: u32 = 1;
const K_UNLINK: u32 = 2;
const K_RMDIR: u32 = 3;
const K_MKDIR: u32 = 4;
const K_RENAME: u32 = 5;
const K_LINK: u32 = 6;
const K_SYMLINK: u32 = 7;
const K_TRUNCATE: u32 = 8;
const K_CHMOD: u32 = 9;
const K_CONNECT: u32 = 10;
const K_BIND: u32 = 11;
const K_SEND: u32 = 12;
const K_EXEC: u32 = 13;
const K_FORK: u32 = 14;
const K_EXIT: u32 = 15;
const K_GAP: u32 = 16;
const K_WRITE_VIA: u32 = 17;
const K_MEMFD: u32 = 18;
const K_MAP_WRITE: u32 = 19;

/// Mirror of `struct event` in bpf/effects.bpf.c.
#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    ts: u64,
    kind: u32,
    tgid: u32,
    tid: u32,
    ppid: u32,
    start_ns: u64,
    ret: i64,
    flags: u32,
    mode: u32,
    aux: u32,
    family: u16,
    port: u16,
    sotype: u32,
    path_len: u32,
    name_len: u32,
    path2_len: u32,
    name2_len: u32,
    data_len: u32,
    addr: [u8; 16],
    comm: [u8; 16],
    path: [u8; 256],
    name: [u8; 256],
    path2: [u8; 256],
    name2: [u8; 256],
    data: [u8; 512],
}

/// (program, hook) for every LSM program in the object.
const LSM_HOOKS: &[(&str, &str)] = &[
    ("et_file_open", "file_open"),
    ("et_unlink", "path_unlink"),
    ("et_rmdir", "path_rmdir"),
    ("et_mkdir", "path_mkdir"),
    ("et_symlink", "path_symlink"),
    ("et_link", "path_link"),
    ("et_rename", "path_rename"),
    ("et_truncate", "path_truncate"),
    ("et_file_truncate", "file_truncate"),
    ("et_chmod", "path_chmod"),
    ("et_connect", "socket_connect"),
    ("et_bind", "socket_bind"),
    ("et_sendmsg", "socket_sendmsg"),
    ("et_bprm", "bprm_committed_creds"),
    ("et_mount", "sb_mount"),
    ("et_bpf", "bpf"),
    ("et_ptrace", "ptrace_access_check"),
    ("et_mmap", "mmap_file"),
];

const TP_BTF: &[(&str, &str)] = &[
    ("et_exec", "sched_process_exec"),
    ("et_fork", "sched_process_fork"),
    ("et_exit", "sched_process_exit"),
];

fn cstr(b: &[u8], len: u32) -> String {
    let n = (len as usize).min(b.len());
    let s = &b[..n];
    let end = s.iter().position(|c| *c == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).into_owned()
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// A syscall number as the BPF side stores it (`c_long` is i64 on the
/// 64-bit targets this backend supports).
#[allow(clippy::unnecessary_cast)]
fn nr(n: libc::c_long) -> i64 {
    n as i64
}

fn load(args: &RunArgs, token: &[u8; 16]) -> Result<Ebpf> {
    let btf = Btf::from_sys_fs().context("reading /sys/kernel/btf/vmlinux")?;
    let trace_reads: u32 = args.trace_reads as u32;
    let mut bpf = EbpfLoader::new()
        .btf(Some(&btf))
        .set_global("trace_reads", &trace_reads, true)
        .set_global("root_token", token, true)
        .set_global("nr_sendfile", &nr(libc::SYS_sendfile), true)
        .set_global("nr_copy_file_range", &nr(libc::SYS_copy_file_range), true)
        .set_global("nr_splice", &nr(libc::SYS_splice), true)
        .set_global("nr_memfd_create", &nr(libc::SYS_memfd_create), true)
        .set_global("nr_io_uring_setup", &nr(libc::SYS_io_uring_setup), true)
        .set_global("nr_io_uring_enter", &nr(libc::SYS_io_uring_enter), true)
        .set_global(
            "nr_io_uring_register",
            &nr(libc::SYS_io_uring_register),
            true,
        )
        .load(OBJECT)
        .context("loading the BPF object (needs root and BPF LSM)")?;
    for (prog, hook) in LSM_HOOKS {
        let p: &mut Lsm = bpf
            .program_mut(prog)
            .ok_or_else(|| anyhow!("{prog} missing from the object"))?
            .try_into()?;
        p.load(hook, &btf).with_context(|| format!("load {prog}"))?;
        p.attach()
            .with_context(|| format!("attach {prog} to lsm/{hook}"))?;
    }
    for (prog, tp) in TP_BTF {
        let p: &mut BtfTracePoint = bpf
            .program_mut(prog)
            .ok_or_else(|| anyhow!("{prog} missing from the object"))?
            .try_into()?;
        p.load(tp, &btf).with_context(|| format!("load {prog}"))?;
        p.attach().with_context(|| format!("attach {prog}"))?;
    }
    for (prog, tp) in [("et_sys_enter", "sys_enter"), ("et_sys_exit", "sys_exit")] {
        let p: &mut RawTracePoint = bpf
            .program_mut(prog)
            .ok_or_else(|| anyhow!("{prog} missing from the object"))?
            .try_into()?;
        p.load()?;
        p.attach(tp)
            .with_context(|| format!("attach raw_tp/{tp}"))?;
    }
    Ok(bpf)
}

struct Proc {
    exec_id: String,
    parent_exec_id: String,
    ppid: u32,
    comm: String,
    exe: String,
    gen: u32,
    start: u64,
}

struct Backend {
    args: RunArgs,
    ledger: Ledger,
    procs: HashMap<u32, Proc>,
    boot_id: String,
    clk_tck: u64,
    me: u32,
    root: u32,
    self_ref: Value,
    events: u64,
    procs_seen: u64,
    gaps: Vec<String>,
    fatal: Option<String>,
}

impl Backend {
    fn proc_for(&mut self, e: &Event) -> &mut Proc {
        let tgid = e.tgid;
        if !self.procs.contains_key(&tgid) {
            let start = e.start_ns / (1_000_000_000 / self.clk_tck);
            let parent_exec_id = if e.ppid == self.me || tgid == self.root {
                "tracer".to_string()
            } else {
                self.procs
                    .get(&e.ppid)
                    .map(|p| p.exec_id.clone())
                    .unwrap_or_default()
            };
            let comm = cstr(&e.comm, 16);
            self.procs.insert(
                tgid,
                Proc {
                    exec_id: tracer::exec_id(&self.boot_id, tgid as i32, start, 0),
                    parent_exec_id,
                    ppid: e.ppid,
                    comm,
                    exe: String::new(),
                    gen: 0,
                    start,
                },
            );
            self.procs_seen += 1;
        }
        self.procs.get_mut(&tgid).unwrap()
    }

    fn proc_ref(&mut self, e: &Event) -> Value {
        let tid = e.tid;
        let p = self.proc_for(e);
        json!({
            "pid": e.tgid, "tid": tid, "ppid": p.ppid,
            "execId": p.exec_id, "parentExecId": p.parent_exec_id,
            "comm": p.comm, "exe": p.exe,
        })
    }

    fn append(
        &mut self,
        proc_ref: Value,
        ts: u64,
        kind: &str,
        name: String,
        outcome: &str,
        detail: Map<String, Value>,
    ) {
        let mut ev = Map::new();
        ev.insert("monoNs".into(), Value::String(ts.to_string()));
        ev.insert("proc".into(), proc_ref);
        ev.insert("kind".into(), Value::String(kind.to_string()));
        ev.insert("name".into(), Value::String(name));
        ev.insert("outcome".into(), Value::String(outcome.to_string()));
        if !detail.is_empty() {
            ev.insert("detail".into(), Value::Object(detail));
        }
        if let Err(err) = self.ledger.append(ev) {
            if self.fatal.is_none() {
                self.fatal = Some(format!("ledger write failed: {err:#}"));
            }
        }
    }

    fn emit(
        &mut self,
        e: &Event,
        kind: &str,
        name: String,
        outcome: &str,
        detail: Map<String, Value>,
    ) {
        let r = self.proc_ref(e);
        self.append(r, e.ts, kind, name, outcome, detail);
        self.events += 1;
    }

    fn emit_self(&mut self, kind: &str, name: String, detail: Map<String, Value>) {
        let r = self.self_ref.clone();
        self.append(r, timefmt::mono_ns(), kind, name, "committed", detail);
    }

    fn outcome(e: &Event, detail: &mut Map<String, Value>, connect: bool) -> &'static str {
        let r = e.ret;
        if r < 0 {
            detail.insert("errno".into(), json!(tracer::errno_name((-r) as i32)));
        }
        if r >= 0 || (connect && r == -(libc::EINPROGRESS as i64)) {
            "committed"
        } else if r == -(libc::EPERM as i64) || r == -(libc::EACCES as i64) {
            "denied"
        } else {
            "failed"
        }
    }

    fn sock_name(e: &Event) -> String {
        let addr = match e.family as i32 {
            libc::AF_INET => sockets::SockAddr::Inet {
                host: std::net::Ipv4Addr::new(e.addr[0], e.addr[1], e.addr[2], e.addr[3])
                    .to_string(),
                port: e.port,
                v6: false,
            },
            libc::AF_INET6 => sockets::SockAddr::Inet {
                host: std::net::Ipv6Addr::from(e.addr).to_string(),
                port: e.port,
                v6: true,
            },
            libc::AF_UNIX => {
                let raw = &e.path[..(e.path_len as usize).min(e.path.len())];
                let path = if raw.first() == Some(&0) {
                    let name = &raw[1..];
                    let end = name
                        .iter()
                        .rposition(|c| *c != 0)
                        .map(|i| i + 1)
                        .unwrap_or(0);
                    format!("@{}", String::from_utf8_lossy(&name[..end]))
                } else {
                    cstr(raw, raw.len() as u32)
                };
                sockets::SockAddr::Unix { path }
            }
            f => sockets::SockAddr::Other { family: f as u16 },
        };
        let info = Some(sockets::SockInfo {
            typ: e.sotype as i32,
        });
        sockets::render(sockets::label(info, &addr), &addr)
    }

    fn on_event(&mut self, e: &Event) {
        let mut d = Map::new();
        match e.kind {
            K_OPEN => {
                let flags = e.flags as i32;
                let tmpfile = flags & libc::O_TMPFILE == libc::O_TMPFILE;
                let writes = (flags & libc::O_ACCMODE) != libc::O_RDONLY
                    || flags & (libc::O_CREAT | libc::O_TRUNC) != 0
                    || tmpfile;
                let kind = if !writes {
                    "file.read"
                } else if tmpfile
                    || (flags & (libc::O_CREAT | libc::O_EXCL)) == (libc::O_CREAT | libc::O_EXCL)
                {
                    "file.create"
                } else {
                    "file.write"
                };
                d.insert("flags".into(), json!(tracer::open_flag_names(flags)));
                d.insert("hook".into(), json!("file_open"));
                if tmpfile {
                    d.insert("tmpfile".into(), json!(true));
                }
                let o = Self::outcome(e, &mut d, false);
                self.emit(e, kind, cstr(&e.path, e.path_len), o, d);
            }
            K_UNLINK | K_RMDIR => {
                if e.kind == K_RMDIR {
                    d.insert("dir".into(), json!(true));
                }
                let name = join(&cstr(&e.path, e.path_len), &cstr(&e.name, e.name_len));
                let o = Self::outcome(e, &mut d, false);
                self.emit(e, "file.delete", name, o, d);
            }
            K_MKDIR => {
                d.insert("dir".into(), json!(true));
                d.insert("mode".into(), json!(format!("{:o}", e.mode & 0o7777)));
                let name = join(&cstr(&e.path, e.path_len), &cstr(&e.name, e.name_len));
                let o = Self::outcome(e, &mut d, false);
                self.emit(e, "file.create", name, o, d);
            }
            K_SYMLINK => {
                d.insert("symlink".into(), json!(true));
                d.insert("target".into(), json!(cstr(&e.path2, e.path2_len)));
                let name = join(&cstr(&e.path, e.path_len), &cstr(&e.name, e.name_len));
                let o = Self::outcome(e, &mut d, false);
                self.emit(e, "file.link", name, o, d);
            }
            K_LINK => {
                d.insert("from".into(), json!(cstr(&e.path2, e.path2_len)));
                let name = join(&cstr(&e.path, e.path_len), &cstr(&e.name, e.name_len));
                let o = Self::outcome(e, &mut d, false);
                self.emit(e, "file.link", name, o, d);
            }
            K_RENAME => {
                d.insert(
                    "from".into(),
                    json!(join(&cstr(&e.path, e.path_len), &cstr(&e.name, e.name_len))),
                );
                let name = join(&cstr(&e.path2, e.path2_len), &cstr(&e.name2, e.name2_len));
                let o = Self::outcome(e, &mut d, false);
                self.emit(e, "file.rename", name, o, d);
            }
            K_TRUNCATE => {
                d.insert(
                    "via".into(),
                    json!(if e.aux == 1 { "ftruncate" } else { "truncate" }),
                );
                let o = Self::outcome(e, &mut d, false);
                self.emit(e, "file.write", cstr(&e.path, e.path_len), o, d);
            }
            K_CHMOD => {
                d.insert("mode".into(), json!(format!("{:o}", e.mode & 0o7777)));
                let o = Self::outcome(e, &mut d, false);
                self.emit(e, "file.meta", cstr(&e.path, e.path_len), o, d);
            }
            K_CONNECT | K_BIND => {
                let o = Self::outcome(e, &mut d, e.kind == K_CONNECT);
                let kind = if e.kind == K_CONNECT {
                    "socket.connect"
                } else {
                    "socket.bind"
                };
                self.emit(e, kind, Self::sock_name(e), o, d);
            }
            K_SEND => {
                let payload = &e.data[..(e.data_len as usize).min(e.data.len())];
                let query = dns::parse_query(payload);
                if e.flags == 1 {
                    // a send on a connected resolver socket: only the question matters
                    if let Some((q, t)) = query {
                        d.insert("qtype".into(), json!(dns::qtype_name(t)));
                        let o = Self::outcome(e, &mut d, false);
                        self.emit(e, "dns.query", q, o, d);
                    }
                    return;
                }
                let name = Self::sock_name(e);
                d.insert("bytes".into(), json!(e.aux));
                let mut qd = Map::new();
                let o = Self::outcome(e, &mut d, false);
                self.emit(e, "socket.send", name.clone(), o, d);
                if let Some((q, t)) = query {
                    qd.insert("qtype".into(), json!(dns::qtype_name(t)));
                    qd.insert("server".into(), json!(name));
                    let o = Self::outcome(e, &mut qd, false);
                    self.emit(e, "dns.query", q, o, qd);
                }
            }
            K_EXEC => {
                let exe = cstr(&e.path, e.path_len);
                let argv_bytes = &e.data[..(e.data_len as usize).min(e.data.len())];
                let argv: Vec<String> = argv_bytes
                    .split(|b| *b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                d.insert("argc".into(), json!(argv.len()));
                let complete = e.aux as usize == argv_bytes.len();
                if !complete {
                    d.insert("argvTruncated".into(), json!(true));
                }
                if self.args.clear_argv {
                    d.insert("argv".into(), json!(argv));
                } else if complete {
                    let joined: Vec<u8> = argv
                        .iter()
                        .flat_map(|a| a.as_bytes().iter().copied().chain(std::iter::once(0u8)))
                        .collect();
                    d.insert("argvSha256".into(), json!(canon::sha256_hex(&joined)));
                }
                let boot = self.boot_id.clone();
                let comm = cstr(&e.comm, 16);
                let tgid = e.tgid as i32;
                let p = self.proc_for(e);
                p.gen += 1;
                p.exe = exe.clone();
                p.comm = comm;
                p.exec_id = tracer::exec_id(&boot, tgid, p.start, p.gen);
                self.emit(e, "process.exec", exe, "committed", d);
            }
            K_FORK => {
                let thread = e.aux == 1;
                d.insert("childPid".into(), json!(e.mode));
                if thread {
                    d.insert("thread".into(), json!(true));
                }
                let (exe, exec_id, comm) = {
                    let p = self.proc_for(e);
                    (p.exe.clone(), p.exec_id.clone(), p.comm.clone())
                };
                if !thread {
                    let child = e.flags;
                    self.procs.insert(
                        child,
                        Proc {
                            exec_id: String::new(),
                            parent_exec_id: exec_id,
                            ppid: e.tgid,
                            comm,
                            exe: exe.clone(),
                            gen: 0,
                            start: 0,
                        },
                    );
                    self.procs_seen += 1;
                    let start = (e.ret.max(0) as u64) / (1_000_000_000 / self.clk_tck);
                    let boot = self.boot_id.clone();
                    if let Some(c) = self.procs.get_mut(&child) {
                        c.start = start;
                        c.exec_id = tracer::exec_id(&boot, child as i32, start, 0);
                    }
                }
                self.emit(e, "process.fork", exe, "committed", d);
            }
            K_EXIT => {
                let code = e.flags as i32;
                if code & 0x7f == 0 {
                    d.insert("exitCode".into(), json!((code >> 8) & 0xff));
                } else {
                    d.insert("signal".into(), json!(code & 0x7f));
                }
                let exe = self.proc_for(e).exe.clone();
                self.emit(e, "process.exit", exe, "committed", d);
            }
            K_WRITE_VIA => {
                let via = match e.aux {
                    1 => "sendfile",
                    2 => "copy_file_range",
                    _ => "splice",
                };
                d.insert("via".into(), json!(via));
                let o = Self::outcome(e, &mut d, false);
                self.emit(e, "file.write", cstr(&e.path, e.path_len), o, d);
            }
            K_MEMFD => {
                let o = Self::outcome(e, &mut d, false);
                self.emit(
                    e,
                    "file.create",
                    format!("memfd:{}", cstr(&e.name, e.name_len)),
                    o,
                    d,
                );
            }
            K_MAP_WRITE => {
                let o = Self::outcome(e, &mut d, false);
                self.emit(e, "file.map-write", cstr(&e.path, e.path_len), o, d);
            }
            K_GAP => {
                let what = match e.flags {
                    1 => "mount",
                    2 => "bpf",
                    3 => "ptrace",
                    4 => "io_uring_setup",
                    5 => "io_uring_enter",
                    6 => "io_uring_register",
                    _ => "unknown",
                };
                let o = Self::outcome(e, &mut d, false);
                if o == "committed" {
                    self.gaps
                        .push(format!("{what} succeeded in pid {}", e.tgid));
                }
                self.emit(e, "coverage.gap", what.to_string(), o, d);
            }
            _ => {}
        }
    }
}

fn counter(c: &Array<&MapData, i64>, i: u32) -> i64 {
    c.get(&i, 0).unwrap_or(0)
}

pub fn limits() -> Value {
    json!([
        "needs root and a kernel with BPF LSM active (lsm=...,bpf) and BTF",
        "io_uring_setup, io_uring_enter and io_uring_register return EPERM from the seccomp filter; the attempt is recorded as coverage.gap (denied)",
        "a syscall that fails before it reaches an LSM hook (for example EXDEV from linkat on overlayfs) leaves no event: nothing happened",
        "a failed execve is not recorded (the exec event comes from sched_process_exec)",
        "argv longer than 512 bytes is recorded as argvTruncated without a digest",
        "an event is lost if one syscall reaches two hooks that both wait for its outcome (counted in stats.pendingOverwrites, which makes coverage partial)",
        "the ring buffer can drop events under load (counted in stats.ringbufDrops, which makes coverage partial)",
        "paths are as the kernel resolves them in the caller's mount namespace; mount, bpf and ptrace attach by the tree are coverage gaps",
        "a write is recorded when the file is opened for writing inside the tree; writes through descriptors inherited from outside the tree are not",
        "the ledger is signed by the tracer; run the tree with --run-as so it cannot read a --key file or the tracer's memory"
    ])
}

pub fn run(args: RunArgs) -> Result<u8> {
    let run_as = tracer::parse_run_as(&args.run_as)?;
    let key = match &args.key {
        Some(p) => ledger::load_key(p)?,
        None => SigningKey::generate(&mut rand::rngs::OsRng),
    };
    let run_id = hex::encode(rand::random::<[u8; 16]>());
    // A random comm for the tracer during the fork that starts the tree.
    let mut token = [0u8; 16];
    let tok = format!("et{}", &hex::encode(rand::random::<[u8; 8]>())[..13]);
    token[..tok.len()].copy_from_slice(tok.as_bytes());
    let mut bpf = load(&args, &token)?;

    let mut ports: Vec<u16> = args.dns_ports.clone();
    ports.push(53);
    ports.sort_unstable();
    ports.dedup();
    {
        let mut m: BpfHashMap<_, u16, u8> =
            BpfHashMap::try_from(bpf.map_mut("dns_ports").unwrap())?;
        for p in &ports {
            m.insert(p, 1, 0)?;
        }
    }

    let ledger = Ledger::create(&args.out, args.force, key, run_id.clone(), !args.quiet)?;
    let prog = seccomp::build(&syscalls::deny_list(), &[]);
    let cargv: Vec<CString> = args
        .command
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<_, _>>()
        .context("a command argument holds a NUL byte")?;
    let mut argv_ptrs: Vec<*const libc::c_char> = cargv.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let exe_path = CString::new(tracer::resolve_on_path(&args.command[0]).as_bytes())
        .context("the command path holds a NUL byte")?;
    let pinned_cpu = match &args.pin_cpu {
        Some(spec) => Some(tracer::pin_to_cpu(spec)?),
        None => None,
    };
    // Orphans of the tree are reparented to us, so they are reaped here.
    // SAFETY: a plain prctl.
    unsafe {
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    }

    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid two-int array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("pipe2: {}", Errno::last());
    }
    let started_at = timefmt::now_rfc3339();
    let started_mono = timefmt::mono_ns();
    let wall_start = std::time::Instant::now();
    let mut old_comm = [0u8; 17];
    // SAFETY: PR_GET_NAME/PR_SET_NAME read or write at most 16 bytes.
    unsafe {
        libc::prctl(libc::PR_GET_NAME, old_comm.as_mut_ptr(), 0, 0, 0);
        libc::prctl(libc::PR_SET_NAME, token.as_ptr(), 0, 0, 0);
    }
    // SAFETY: the child only runs async-signal-safe code until exec.
    let child = unsafe { libc::fork() };
    if child < 0 {
        bail!("fork: {}", Errno::last());
    }
    if child == 0 {
        tracer::child_exec(fds[0], fds[1], &prog, &exe_path, &argv_ptrs, run_as);
    }
    // SAFETY: as above; then closing our copy of the read end.
    unsafe {
        libc::prctl(libc::PR_SET_NAME, old_comm.as_ptr(), 0, 0, 0);
        libc::close(fds[0]);
        // as in the ptrace backend: keep a same-uid tree out of our memory
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    {
        let cfg: Array<_, u32> = Array::try_from(bpf.map("cfg").unwrap())?;
        if cfg.get(&1, 0).unwrap_or(0) != 1 {
            // SAFETY: killing the child we just forked.
            unsafe {
                libc::kill(child, libc::SIGKILL);
            }
            bail!("the BPF fork hook did not adopt the root process");
        }
    }

    let me = std::process::id();
    let (release, machine) = procinfo::uname();
    let self_ref = json!({
        "pid": me, "tid": me, "ppid": procinfo::ppid(me as i32).unwrap_or(0),
        "execId": "tracer", "parentExecId": "", "comm": "effect-tracer",
        "exe": procinfo::exe(me as i32).unwrap_or_default(),
    });
    let start_detail = json!({
        "runId": run_id,
        "producer": {"name": "effect-tracer", "version": VERSION},
        "mechanism": "ebpf",
        "kernel": {"release": release, "machine": machine},
        "bootId": procinfo::boot_id(),
        "root": {
            "argv": args.command,
            "cwd": std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default(),
        },
        "options": {
            "mode": "ebpf",
            "clearArgv": args.clear_argv,
            "traceReads": args.trace_reads,
            "dnsPorts": ports,
            "seccompDeny": ["io_uring_setup", "io_uring_enter", "io_uring_register"],
            "pinCpu": pinned_cpu,
            "runAs": args.run_as,
        },
        "startedAt": started_at,
        "startedMonoNs": started_mono.to_string(),
    });
    let start_detail = start_detail.as_object().cloned().unwrap_or_default();
    // SAFETY: sysconf has no preconditions.
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
    let mut b = Backend {
        args,
        ledger,
        procs: HashMap::new(),
        boot_id: procinfo::boot_id(),
        clk_tck,
        me,
        root: child as u32,
        self_ref,
        events: 0,
        procs_seen: 0,
        gaps: Vec::new(),
        fatal: None,
    };
    b.emit_self("run.start", run_id.clone(), start_detail.clone());
    // SAFETY: writing one byte to our pipe and closing it.
    unsafe {
        let go = *b"g";
        libc::write(fds[1], go.as_ptr() as *const c_void, 1);
        libc::close(fds[1]);
    }

    let mut rb = RingBuf::try_from(bpf.take_map("rb").unwrap())?;
    let counters_map = bpf.map("counters").unwrap();
    let counters: Array<&MapData, i64> = Array::try_from(counters_map)?;
    let mut root_status: Option<WaitStatus> = None;
    let mut bad_records = 0u64;
    // A pidfd for the root becomes readable when it exits, so the loop wakes
    // then instead of at the next poll timeout.
    // SAFETY: pidfd_open takes a pid and flags; -1 just means no pidfd.
    let root_pidfd = unsafe {
        libc::syscall(
            syscalls::NR_PIDFD_OPEN as libc::c_long,
            child as libc::c_long,
            0 as libc::c_long,
        )
    } as i32;
    loop {
        let mut pfds = [
            libc::pollfd {
                fd: rb.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if root_status.is_none() {
                    root_pidfd
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // Once the root is gone, only orphans of the tree can still run;
        // check on them often.
        let timeout = if root_status.is_none() { 50 } else { 5 };
        // SAFETY: two valid pollfds (a negative fd is ignored by poll).
        unsafe {
            libc::poll(pfds.as_mut_ptr(), 2, timeout);
        }
        while let Some(item) = rb.next() {
            if item.len() < std::mem::size_of::<Event>() {
                bad_records += 1;
                continue;
            }
            // SAFETY: the record is at least one Event long; Event is plain data.
            let ev: Event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const Event) };
            drop(item);
            b.on_event(&ev);
        }
        // reap the root and any orphan reparented to us
        loop {
            match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) | Err(_) => break,
                Ok(st) => {
                    if st.pid() == Some(Pid::from_raw(child)) {
                        root_status = Some(st);
                    }
                }
            }
        }
        if root_status.is_some() && counter(&counters, 1) <= 0 {
            while let Some(item) = rb.next() {
                if item.len() >= std::mem::size_of::<Event>() {
                    // SAFETY: as above.
                    let ev: Event =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const Event) };
                    drop(item);
                    b.on_event(&ev);
                }
            }
            break;
        }
    }

    if root_pidfd >= 0 {
        // SAFETY: closing the pidfd opened above.
        unsafe {
            libc::close(root_pidfd);
        }
    }
    let drops = counter(&counters, 0);
    let overwrites = counter(&counters, 2);
    if drops > 0 {
        b.gaps
            .push(format!("{drops} events dropped by the ring buffer"));
    }
    if overwrites > 0 {
        b.gaps.push(format!(
            "{overwrites} events displaced before their syscall returned"
        ));
    }
    if bad_records > 0 {
        b.gaps
            .push(format!("{bad_records} short ring-buffer records"));
    }
    let status = if b.fatal.is_some() {
        "failed"
    } else if b.gaps.is_empty() {
        "complete"
    } else {
        "partial"
    };
    let (exit, code) = match root_status {
        Some(WaitStatus::Exited(_, c)) => (json!({"code": c}), (c & 0xff) as u8),
        Some(WaitStatus::Signaled(_, sig, _)) => (
            json!({"signal": format!("{sig:?}")}),
            (128 + sig as i32) as u8,
        ),
        _ => (json!({"unknown": true}), 3),
    };
    let end_detail = json!({
        "coverage": {"status": status, "reasons": b.gaps},
        "exit": exit,
        "stats": {
            "events": b.events + 1,
            "processes": b.procs_seen,
            "ringbufDrops": drops,
            "pendingOverwrites": overwrites,
            "tracerCpuMs": tracer::tracer_cpu_ms(),
            "wallMs": wall_start.elapsed().as_millis() as u64,
        },
        "finishedAt": timefmt::now_rfc3339(),
    });
    b.emit_self(
        "run.end",
        run_id,
        end_detail.as_object().cloned().unwrap_or_default(),
    );
    let mut summary = start_detail;
    if let Value::Object(m) = end_detail {
        summary.extend(m);
    }
    summary.insert("limits".into(), limits());
    let Backend { ledger, fatal, .. } = b;
    ledger.finish(summary)?;
    if let Some(f) = fatal {
        bail!("{f}");
    }
    Ok(code)
}
