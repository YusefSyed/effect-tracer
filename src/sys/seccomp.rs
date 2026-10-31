//! The seccomp-bpf program installed in the tracee before exec.
//!
//! Layout (one BPF instruction per line):
//!
//! ```text
//! ld  arch
//! jeq NATIVE_ARCH ? native : foreign
//! foreign: ld nr; jeq 425|426|427 ? ret ERRNO|EPERM; ret TRACE|1
//!                                         (32-bit ABI: io_uring denied, the rest
//!                                          goes to the tracer as a gap)
//! native: ld nr
//! [x86_64] jge 0x40000000 ? x32 branch    (same as foreign, numbers | 0x40000000)
//! jeq <denied nr>  ? ret ERRNO|EPERM      (io_uring_setup, _enter, _register)
//! jeq <traced nr>  ? <rule block>         (only in --mode seccomp)
//! ret ALLOW
//! ```
//!
//! A rule block is `ret TRACE` for a syscall that is always an effect, or a
//! test of the call's own arguments for the ones that usually are not: an
//! `openat` without write flags, an `mmap` that is not shared and writable,
//! a `socket` that is not raw. Those run at native speed with no stop at
//! all. The tracer applies the same classification at the stop, so the
//! ledger is identical in both modes.
//!
//! The filter is installed with `PR_SET_NO_NEW_PRIVS`, so it is inherited by
//! every descendant and cannot be removed. In `--mode full` the rule list is
//! empty and the program only denies io_uring; the tracer sees every syscall
//! through PTRACE_SYSCALL stops instead.

use libc::{sock_filter, sock_fprog};

use super::syscalls::NATIVE_AUDIT_ARCH;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
#[cfg(target_arch = "x86_64")]
const BPF_JGE_K: u16 = 0x35;
const BPF_JSET_K: u16 = 0x45;
const BPF_AND_K: u16 = 0x54;
const BPF_RET_K: u16 = 0x06;

pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

/// `ret_data` value that marks a syscall from a foreign ABI.
pub const TRACE_DATA_COMPAT: u32 = 1;

const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

/// Low 32 bits of `seccomp_data.args[i]` (little-endian targets).
fn arg_offset(arg: u8) -> u32 {
    16 + 8 * arg as u32
}

/// One test on a syscall argument's low 32 bits.
#[derive(Clone, Debug)]
pub enum Cond {
    /// `(arg & mask) != 0`
    MaskNonZero { arg: u8, mask: u32 },
    /// `(arg & mask) == value`
    MaskedEq { arg: u8, mask: u32, value: u32 },
}

/// Trace `nr` when any alternative holds; an alternative holds when all of
/// its conditions hold. No alternatives: always trace.
#[derive(Clone, Debug)]
pub struct Rule {
    pub nr: i64,
    pub alternatives: Vec<Vec<Cond>>,
}

impl Rule {
    #[cfg(test)]
    pub fn always(nr: i64) -> Rule {
        Rule {
            nr,
            alternatives: Vec::new(),
        }
    }
}

fn stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

fn compile_rule(rule: &Rule) -> Vec<sock_filter> {
    if rule.alternatives.is_empty() {
        return vec![stmt(BPF_RET_K, SECCOMP_RET_TRACE)];
    }
    let mut out: Vec<sock_filter> = Vec::new();
    for alt in &rule.alternatives {
        let mut instrs: Vec<sock_filter> = Vec::new();
        let mut jumps: Vec<usize> = Vec::new();
        for c in alt {
            match *c {
                Cond::MaskNonZero { arg, mask } => {
                    instrs.push(stmt(BPF_LD_W_ABS, arg_offset(arg)));
                    jumps.push(instrs.len());
                    instrs.push(jump(BPF_JSET_K, mask, 0, 0));
                }
                Cond::MaskedEq { arg, mask, value } => {
                    instrs.push(stmt(BPF_LD_W_ABS, arg_offset(arg)));
                    if mask != u32::MAX {
                        instrs.push(stmt(BPF_AND_K, mask));
                    }
                    jumps.push(instrs.len());
                    instrs.push(jump(BPF_JEQ_K, value, 0, 0));
                }
            }
        }
        instrs.push(stmt(BPF_RET_K, SECCOMP_RET_TRACE));
        let n = instrs.len();
        for j in jumps {
            // A failed condition skips the rest of this alternative.
            instrs[j].jf = (n - j - 1) as u8;
        }
        out.extend(instrs);
    }
    out.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    assert!(out.len() < 250, "rule block too long for an 8-bit jump");
    out
}

/// io_uring_setup, io_uring_enter and io_uring_register in the 32-bit ABIs
/// (i386 on x86_64, AArch32 on arm64). They took the generic numbers, so
/// they equal the native ones; named separately because they are matched
/// in the foreign-ABI branch.
const COMPAT_IO_URING: [u32; 3] = [425, 426, 427];
/// x32 (x86_64 only) marks its syscall numbers with this bit.
#[cfg(target_arch = "x86_64")]
const X32_BIT: u32 = 0x4000_0000;

/// A foreign-ABI branch: io_uring is denied as in the native ABI, every
/// other call goes to the tracer marked TRACE_DATA_COMPAT. `bit` is or-ed
/// into the numbers (0, or the x32 bit).
fn foreign_branch(p: &mut Vec<sock_filter>, bit: u32) {
    for nr in COMPAT_IO_URING {
        p.push(jump(BPF_JEQ_K, nr | bit, 0, 1));
        p.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
    }
    p.push(stmt(BPF_RET_K, SECCOMP_RET_TRACE | TRACE_DATA_COMPAT));
}

/// Build the program. `deny` get EPERM; `trace` rules get SECCOMP_RET_TRACE.
/// The io_uring denial holds in every ABI the kernel accepts from this
/// task, foreign ones included.
pub fn build(deny: &[i64], trace: &[Rule]) -> Vec<sock_filter> {
    let mut p: Vec<sock_filter> = Vec::with_capacity(deny.len() * 2 + trace.len() * 4 + 24);
    p.push(stmt(BPF_LD_W_ABS, OFF_ARCH));
    let mut foreign = Vec::new();
    foreign.push(stmt(BPF_LD_W_ABS, OFF_NR));
    foreign_branch(&mut foreign, 0);
    p.push(jump(BPF_JEQ_K, NATIVE_AUDIT_ARCH, foreign.len() as u8, 0));
    p.extend(foreign);
    p.push(stmt(BPF_LD_W_ABS, OFF_NR));
    #[cfg(target_arch = "x86_64")]
    {
        let mut x32 = Vec::new();
        foreign_branch(&mut x32, X32_BIT);
        p.push(jump(BPF_JGE_K, X32_BIT, 0, x32.len() as u8));
        p.extend(x32);
    }
    for nr in deny {
        p.push(jump(BPF_JEQ_K, *nr as u32, 0, 1));
        p.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
    }
    for rule in trace {
        let block = compile_rule(rule);
        p.push(jump(BPF_JEQ_K, rule.nr as u32, 0, block.len() as u8));
        p.extend(block);
    }
    p.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    assert!(p.len() <= 4096, "BPF_MAXINSNS");
    p
}

/// Install the program in the calling process. Async-signal-safe: no
/// allocation, two syscalls. Returns the errno on failure.
pub fn install(prog: &[sock_filter]) -> Result<(), i32> {
    // SAFETY: plain prctl and seccomp calls with a valid program pointer that
    // outlives the call.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(*libc::__errno_location());
        }
        let fprog = sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_ptr() as *mut sock_filter,
        };
        if libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER as libc::c_long,
            0 as libc::c_long,
            &fprog as *const sock_fprog,
        ) != 0
        {
            return Err(*libc::__errno_location());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::syscalls;
    use super::*;

    /// A tiny interpreter for the instruction kinds the program uses.
    fn run(prog: &[sock_filter], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
        let mut pc = 0usize;
        let mut acc = 0u32;
        loop {
            let i = &prog[pc];
            match i.code {
                BPF_LD_W_ABS => {
                    acc = match i.k {
                        OFF_NR => nr,
                        OFF_ARCH => arch,
                        k if (16..64).contains(&k) && (k - 16) % 8 == 0 => {
                            args[((k - 16) / 8) as usize] as u32
                        }
                        _ => panic!("bad offset {}", i.k),
                    };
                    pc += 1;
                }
                BPF_JEQ_K => {
                    pc += 1 + if acc == i.k {
                        i.jt as usize
                    } else {
                        i.jf as usize
                    }
                }
                BPF_JSET_K => {
                    pc += 1 + if acc & i.k != 0 {
                        i.jt as usize
                    } else {
                        i.jf as usize
                    }
                }
                0x35 => {
                    pc += 1 + if acc >= i.k {
                        i.jt as usize
                    } else {
                        i.jf as usize
                    }
                }
                BPF_AND_K => {
                    acc &= i.k;
                    pc += 1;
                }
                BPF_RET_K => return i.k,
                _ => panic!("unknown opcode {:#x}", i.code),
            }
            assert!(pc < prog.len(), "fell off the program");
        }
    }

    const EPERM: u32 = SECCOMP_RET_ERRNO | libc::EPERM as u32;
    const A0: [u64; 6] = [0; 6];

    #[test]
    fn program_routes_each_class() {
        let deny = vec![425i64, 426, 427];
        let trace = vec![Rule::always(56), Rule::always(203), Rule::always(35)];
        let p = build(&deny, &trace);
        assert_eq!(run(&p, 425, NATIVE_AUDIT_ARCH, A0), EPERM);
        assert_eq!(run(&p, 427, NATIVE_AUDIT_ARCH, A0), EPERM);
        assert_eq!(run(&p, 56, NATIVE_AUDIT_ARCH, A0), SECCOMP_RET_TRACE);
        assert_eq!(run(&p, 35, NATIVE_AUDIT_ARCH, A0), SECCOMP_RET_TRACE);
        assert_eq!(run(&p, 63, NATIVE_AUDIT_ARCH, A0), SECCOMP_RET_ALLOW);
        assert_eq!(
            run(&p, 56, 0x4000_0028, A0),
            SECCOMP_RET_TRACE | TRACE_DATA_COMPAT
        );
        // A foreign ABI (here i386's audit arch) cannot reach io_uring
        // either; anything else from it goes to the tracer as a gap.
        assert_eq!(run(&p, 425, 0x4000_0003, A0), EPERM);
        assert_eq!(run(&p, 426, 0x4000_0028, A0), EPERM);
        assert_eq!(run(&p, 427, 0x4000_0028, A0), EPERM);
        assert_eq!(
            run(&p, 3, 0x4000_0003, A0),
            SECCOMP_RET_TRACE | TRACE_DATA_COMPAT
        );
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(run(&p, 0x4000_0000 | 425, NATIVE_AUDIT_ARCH, A0), EPERM);
            assert_eq!(
                run(&p, 0x4000_0001, NATIVE_AUDIT_ARCH, A0),
                SECCOMP_RET_TRACE | TRACE_DATA_COMPAT
            );
        }
        // Full mode: no rules, io_uring still denied, everything else allowed.
        let p2 = build(&deny, &[]);
        assert_eq!(run(&p2, 425, NATIVE_AUDIT_ARCH, A0), EPERM);
        assert_eq!(run(&p2, 56, NATIVE_AUDIT_ARCH, A0), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn argument_rules_skip_harmless_calls() {
        let p = build(&syscalls::deny_list(), &syscalls::trace_rules(false));
        let openat = libc::SYS_openat as u32;
        let mmap = libc::SYS_mmap as u32;
        let socket = libc::SYS_socket as u32;
        let rd = |flags: i32| [0, 0, flags as u64, 0, 0, 0];
        assert_eq!(
            run(
                &p,
                openat,
                NATIVE_AUDIT_ARCH,
                rd(libc::O_RDONLY | libc::O_CLOEXEC)
            ),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            run(
                &p,
                openat,
                NATIVE_AUDIT_ARCH,
                rd(libc::O_RDONLY | libc::O_DIRECTORY)
            ),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            run(
                &p,
                openat,
                NATIVE_AUDIT_ARCH,
                rd(libc::O_WRONLY | libc::O_CREAT)
            ),
            SECCOMP_RET_TRACE
        );
        assert_eq!(
            run(
                &p,
                openat,
                NATIVE_AUDIT_ARCH,
                rd(libc::O_RDONLY | libc::O_CREAT)
            ),
            SECCOMP_RET_TRACE
        );
        assert_eq!(
            run(&p, openat, NATIVE_AUDIT_ARCH, rd(libc::O_RDWR)),
            SECCOMP_RET_TRACE
        );
        assert_eq!(
            run(
                &p,
                openat,
                NATIVE_AUDIT_ARCH,
                rd(libc::O_TMPFILE | libc::O_WRONLY)
            ),
            SECCOMP_RET_TRACE
        );
        let mm = |prot: i32, flags: i32| [0, 4096, prot as u64, flags as u64, 3, 0];
        assert_eq!(
            run(
                &p,
                mmap,
                NATIVE_AUDIT_ARCH,
                mm(libc::PROT_READ, libc::MAP_SHARED)
            ),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            run(
                &p,
                mmap,
                NATIVE_AUDIT_ARCH,
                mm(libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE)
            ),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            run(
                &p,
                mmap,
                NATIVE_AUDIT_ARCH,
                mm(libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED)
            ),
            SECCOMP_RET_TRACE
        );
        let so = |dom: i32, typ: i32| [dom as u64, typ as u64, 0, 0, 0, 0];
        assert_eq!(
            run(
                &p,
                socket,
                NATIVE_AUDIT_ARCH,
                so(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC)
            ),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            run(
                &p,
                socket,
                NATIVE_AUDIT_ARCH,
                so(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC)
            ),
            SECCOMP_RET_TRACE
        );
        assert_eq!(
            run(
                &p,
                socket,
                NATIVE_AUDIT_ARCH,
                so(libc::AF_PACKET, libc::SOCK_DGRAM)
            ),
            SECCOMP_RET_TRACE
        );
        assert_eq!(
            run(&p, libc::SYS_unlinkat as u32, NATIVE_AUDIT_ARCH, A0),
            SECCOMP_RET_TRACE
        );
        assert_eq!(
            run(&p, libc::SYS_read as u32, NATIVE_AUDIT_ARCH, A0),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(run(&p, 425, NATIVE_AUDIT_ARCH, A0), EPERM);
        // --trace-reads: every openat stops.
        let p2 = build(&syscalls::deny_list(), &syscalls::trace_rules(true));
        assert_eq!(
            run(&p2, openat, NATIVE_AUDIT_ARCH, rd(libc::O_RDONLY)),
            SECCOMP_RET_TRACE
        );
    }

    #[test]
    fn full_table_fits() {
        let p = build(&syscalls::deny_list(), &syscalls::trace_rules(false));
        assert!(p.len() < 400);
        for nr in syscalls::trace_list() {
            let r = run(&p, nr as u32, NATIVE_AUDIT_ARCH, [0, 0, 0, 0, 0, 0]);
            assert!(r == SECCOMP_RET_TRACE || r == SECCOMP_RET_ALLOW, "nr {nr}");
        }
    }
}
