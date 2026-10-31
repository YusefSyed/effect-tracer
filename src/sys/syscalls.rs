//! The syscalls the tracer cares about, by number, for x86_64 and aarch64.
//!
//! Numbers come from the `libc` crate where it defines them; the newer
//! unified numbers (same on every 64-bit architecture since Linux 5.x) are
//! literals with their kernel names in comments.

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[allow(dead_code)] // the legacy variants exist on x86_64 only
pub enum Sys {
    Open,
    Openat,
    Openat2,
    Creat,
    Unlink,
    Unlinkat,
    Rmdir,
    Rename,
    Renameat,
    Renameat2,
    Link,
    Linkat,
    Symlink,
    Symlinkat,
    Mkdir,
    Mkdirat,
    Mknod,
    Mknodat,
    Truncate,
    Ftruncate,
    Chmod,
    Fchmod,
    Fchmodat,
    Fchmodat2,
    Chown,
    Lchown,
    Fchown,
    Fchownat,
    Utimensat,
    Mmap,
    Sendfile,
    CopyFileRange,
    Splice,
    MemfdCreate,
    Execve,
    Execveat,
    Socket,
    Connect,
    Bind,
    Listen,
    Sendto,
    Sendmsg,
    Sendmmsg,
    Write,
    Writev,
    Pwrite64,
    Pwritev,
    Pwritev2,
    IoUringSetup,
    IoUringEnter,
    IoUringRegister,
    ProcessVmWritev,
    ProcessVmReadv,
    Ptrace,
    Bpf,
    Mount,
    Umount2,
    MoveMount,
    Fsmount,
    PivotRoot,
    Chroot,
    Setns,
    Unshare,
    InitModule,
    FinitModule,
    DeleteModule,
    KexecLoad,
    KexecFileLoad,
}

// Unified numbers (identical on x86_64 and aarch64).
pub const NR_IO_URING_SETUP: i64 = 425;
pub const NR_IO_URING_ENTER: i64 = 426;
pub const NR_IO_URING_REGISTER: i64 = 427;
pub const NR_MOVE_MOUNT: i64 = 429;
pub const NR_FSMOUNT: i64 = 432;
pub const NR_PIDFD_OPEN: i64 = 434;
pub const NR_OPENAT2: i64 = 437;
pub const NR_PIDFD_GETFD: i64 = 438;
pub const NR_FCHMODAT2: i64 = 452;

#[cfg(target_arch = "aarch64")]
pub const NR_KEXEC_FILE_LOAD: i64 = 294;
#[cfg(target_arch = "x86_64")]
pub const NR_KEXEC_FILE_LOAD: i64 = 320;

#[cfg(target_arch = "aarch64")]
pub const NATIVE_AUDIT_ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64
#[cfg(target_arch = "x86_64")]
pub const NATIVE_AUDIT_ARCH: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64

#[allow(clippy::unnecessary_cast)] // c_long is i64 here; the cast documents the intent
macro_rules! common_table {
    () => {
        &[
            (libc::SYS_openat as i64, Sys::Openat),
            (NR_OPENAT2, Sys::Openat2),
            (libc::SYS_unlinkat as i64, Sys::Unlinkat),
            (libc::SYS_renameat as i64, Sys::Renameat),
            (libc::SYS_renameat2 as i64, Sys::Renameat2),
            (libc::SYS_linkat as i64, Sys::Linkat),
            (libc::SYS_symlinkat as i64, Sys::Symlinkat),
            (libc::SYS_mkdirat as i64, Sys::Mkdirat),
            (libc::SYS_mknodat as i64, Sys::Mknodat),
            (libc::SYS_truncate as i64, Sys::Truncate),
            (libc::SYS_ftruncate as i64, Sys::Ftruncate),
            (libc::SYS_fchmod as i64, Sys::Fchmod),
            (libc::SYS_fchmodat as i64, Sys::Fchmodat),
            (NR_FCHMODAT2, Sys::Fchmodat2),
            (libc::SYS_fchown as i64, Sys::Fchown),
            (libc::SYS_fchownat as i64, Sys::Fchownat),
            (libc::SYS_utimensat as i64, Sys::Utimensat),
            (libc::SYS_mmap as i64, Sys::Mmap),
            (libc::SYS_sendfile as i64, Sys::Sendfile),
            (libc::SYS_copy_file_range as i64, Sys::CopyFileRange),
            (libc::SYS_splice as i64, Sys::Splice),
            (libc::SYS_memfd_create as i64, Sys::MemfdCreate),
            (libc::SYS_execve as i64, Sys::Execve),
            (libc::SYS_execveat as i64, Sys::Execveat),
            (libc::SYS_socket as i64, Sys::Socket),
            (libc::SYS_connect as i64, Sys::Connect),
            (libc::SYS_bind as i64, Sys::Bind),
            (libc::SYS_listen as i64, Sys::Listen),
            (libc::SYS_sendto as i64, Sys::Sendto),
            (libc::SYS_sendmsg as i64, Sys::Sendmsg),
            (libc::SYS_sendmmsg as i64, Sys::Sendmmsg),
            (libc::SYS_write as i64, Sys::Write),
            (libc::SYS_writev as i64, Sys::Writev),
            (libc::SYS_pwrite64 as i64, Sys::Pwrite64),
            (libc::SYS_pwritev as i64, Sys::Pwritev),
            (libc::SYS_pwritev2 as i64, Sys::Pwritev2),
            (NR_IO_URING_SETUP, Sys::IoUringSetup),
            (NR_IO_URING_ENTER, Sys::IoUringEnter),
            (NR_IO_URING_REGISTER, Sys::IoUringRegister),
            (libc::SYS_process_vm_writev as i64, Sys::ProcessVmWritev),
            (libc::SYS_process_vm_readv as i64, Sys::ProcessVmReadv),
            (libc::SYS_ptrace as i64, Sys::Ptrace),
            (libc::SYS_bpf as i64, Sys::Bpf),
            (libc::SYS_mount as i64, Sys::Mount),
            (libc::SYS_umount2 as i64, Sys::Umount2),
            (NR_MOVE_MOUNT, Sys::MoveMount),
            (NR_FSMOUNT, Sys::Fsmount),
            (libc::SYS_pivot_root as i64, Sys::PivotRoot),
            (libc::SYS_chroot as i64, Sys::Chroot),
            (libc::SYS_setns as i64, Sys::Setns),
            (libc::SYS_unshare as i64, Sys::Unshare),
            (libc::SYS_init_module as i64, Sys::InitModule),
            (libc::SYS_finit_module as i64, Sys::FinitModule),
            (libc::SYS_delete_module as i64, Sys::DeleteModule),
            (libc::SYS_kexec_load as i64, Sys::KexecLoad),
            (NR_KEXEC_FILE_LOAD, Sys::KexecFileLoad),
        ]
    };
}

#[cfg(target_arch = "aarch64")]
pub const TABLE: &[(i64, Sys)] = common_table!();

#[cfg(target_arch = "x86_64")]
pub const LEGACY_TABLE: &[(i64, Sys)] = &[
    (libc::SYS_open as i64, Sys::Open),
    (libc::SYS_creat as i64, Sys::Creat),
    (libc::SYS_unlink as i64, Sys::Unlink),
    (libc::SYS_rmdir as i64, Sys::Rmdir),
    (libc::SYS_rename as i64, Sys::Rename),
    (libc::SYS_link as i64, Sys::Link),
    (libc::SYS_symlink as i64, Sys::Symlink),
    (libc::SYS_mkdir as i64, Sys::Mkdir),
    (libc::SYS_mknod as i64, Sys::Mknod),
    (libc::SYS_chmod as i64, Sys::Chmod),
    (libc::SYS_chown as i64, Sys::Chown),
    (libc::SYS_lchown as i64, Sys::Lchown),
];

#[cfg(target_arch = "x86_64")]
pub const COMMON_TABLE: &[(i64, Sys)] = common_table!();

/// All entries for this architecture.
pub fn table() -> Vec<(i64, Sys)> {
    #[cfg(target_arch = "aarch64")]
    {
        TABLE.to_vec()
    }
    #[cfg(target_arch = "x86_64")]
    {
        let mut v = COMMON_TABLE.to_vec();
        v.extend_from_slice(LEGACY_TABLE);
        v
    }
}

/// Map a syscall number to its class, if the tracer cares about it.
pub fn lookup(nr: i64) -> Option<Sys> {
    #[cfg(target_arch = "aarch64")]
    {
        TABLE.iter().find(|(n, _)| *n == nr).map(|(_, s)| *s)
    }
    #[cfg(target_arch = "x86_64")]
    {
        COMMON_TABLE
            .iter()
            .chain(LEGACY_TABLE.iter())
            .find(|(n, _)| *n == nr)
            .map(|(_, s)| *s)
    }
}

/// Syscalls the seccomp filter returns EPERM for, in every mode.
pub fn deny_list() -> Vec<i64> {
    vec![NR_IO_URING_SETUP, NR_IO_URING_ENTER, NR_IO_URING_REGISTER]
}

/// Syscalls the seccomp filter traps to the tracer in `--mode seccomp`.
/// The plain write family is left out: it only matters for DNS payloads on
/// already-known resolver sockets, and tracing it would cost a stop per
/// write.
pub fn trace_list() -> Vec<i64> {
    let deny = deny_list();
    table()
        .into_iter()
        .filter(|(nr, s)| {
            !deny.contains(nr)
                && !matches!(
                    s,
                    Sys::Write | Sys::Writev | Sys::Pwrite64 | Sys::Pwritev | Sys::Pwritev2
                )
        })
        .map(|(nr, _)| nr)
        .collect()
}

/// The seccomp rules for `--mode seccomp`: every effect syscall, with an
/// argument test where the call is usually harmless, so that read-only
/// opens, private or read-only mappings and ordinary sockets never stop.
pub fn trace_rules(trace_reads: bool) -> Vec<super::seccomp::Rule> {
    use super::seccomp::{Cond, Rule};
    let tmpfile_bit = (libc::O_TMPFILE & !libc::O_DIRECTORY) as u32; // __O_TMPFILE
    let write_mask =
        (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC) as u32 | tmpfile_bit;
    trace_list()
        .into_iter()
        .map(|nr| {
            let alternatives = match lookup(nr) {
                Some(Sys::Openat) if !trace_reads => vec![vec![Cond::MaskNonZero {
                    arg: 2,
                    mask: write_mask,
                }]],
                Some(Sys::Open) if !trace_reads => vec![vec![Cond::MaskNonZero {
                    arg: 1,
                    mask: write_mask,
                }]],
                Some(Sys::Mmap) => vec![vec![
                    Cond::MaskNonZero {
                        arg: 2,
                        mask: libc::PROT_WRITE as u32,
                    },
                    Cond::MaskNonZero {
                        arg: 3,
                        mask: libc::MAP_SHARED as u32,
                    },
                ]],
                Some(Sys::Socket) => vec![
                    vec![Cond::MaskedEq {
                        arg: 0,
                        mask: u32::MAX,
                        value: libc::AF_PACKET as u32,
                    }],
                    vec![Cond::MaskedEq {
                        arg: 1,
                        mask: 0xf,
                        value: libc::SOCK_RAW as u32,
                    }],
                ],
                _ => Vec::new(),
            };
            Rule { nr, alternatives }
        })
        .collect()
}

/// Kernel name of a syscall class.
pub fn name(s: Sys) -> &'static str {
    match s {
        Sys::Open => "open",
        Sys::Openat => "openat",
        Sys::Openat2 => "openat2",
        Sys::Creat => "creat",
        Sys::Unlink => "unlink",
        Sys::Unlinkat => "unlinkat",
        Sys::Rmdir => "rmdir",
        Sys::Rename => "rename",
        Sys::Renameat => "renameat",
        Sys::Renameat2 => "renameat2",
        Sys::Link => "link",
        Sys::Linkat => "linkat",
        Sys::Symlink => "symlink",
        Sys::Symlinkat => "symlinkat",
        Sys::Mkdir => "mkdir",
        Sys::Mkdirat => "mkdirat",
        Sys::Mknod => "mknod",
        Sys::Mknodat => "mknodat",
        Sys::Truncate => "truncate",
        Sys::Ftruncate => "ftruncate",
        Sys::Chmod => "chmod",
        Sys::Fchmod => "fchmod",
        Sys::Fchmodat => "fchmodat",
        Sys::Fchmodat2 => "fchmodat2",
        Sys::Chown => "chown",
        Sys::Lchown => "lchown",
        Sys::Fchown => "fchown",
        Sys::Fchownat => "fchownat",
        Sys::Utimensat => "utimensat",
        Sys::Mmap => "mmap",
        Sys::Sendfile => "sendfile",
        Sys::CopyFileRange => "copy_file_range",
        Sys::Splice => "splice",
        Sys::MemfdCreate => "memfd_create",
        Sys::Execve => "execve",
        Sys::Execveat => "execveat",
        Sys::Socket => "socket",
        Sys::Connect => "connect",
        Sys::Bind => "bind",
        Sys::Listen => "listen",
        Sys::Sendto => "sendto",
        Sys::Sendmsg => "sendmsg",
        Sys::Sendmmsg => "sendmmsg",
        Sys::Write => "write",
        Sys::Writev => "writev",
        Sys::Pwrite64 => "pwrite64",
        Sys::Pwritev => "pwritev",
        Sys::Pwritev2 => "pwritev2",
        Sys::IoUringSetup => "io_uring_setup",
        Sys::IoUringEnter => "io_uring_enter",
        Sys::IoUringRegister => "io_uring_register",
        Sys::ProcessVmWritev => "process_vm_writev",
        Sys::ProcessVmReadv => "process_vm_readv",
        Sys::Ptrace => "ptrace",
        Sys::Bpf => "bpf",
        Sys::Mount => "mount",
        Sys::Umount2 => "umount2",
        Sys::MoveMount => "move_mount",
        Sys::Fsmount => "fsmount",
        Sys::PivotRoot => "pivot_root",
        Sys::Chroot => "chroot",
        Sys::Setns => "setns",
        Sys::Unshare => "unshare",
        Sys::InitModule => "init_module",
        Sys::FinitModule => "finit_module",
        Sys::DeleteModule => "delete_module",
        Sys::KexecLoad => "kexec_load",
        Sys::KexecFileLoad => "kexec_file_load",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn numbers_are_unique_and_classified() {
        let t = table();
        let nrs: HashSet<i64> = t.iter().map(|(n, _)| *n).collect();
        assert_eq!(nrs.len(), t.len(), "duplicate syscall number in the table");
        for (nr, s) in &t {
            assert_eq!(lookup(*nr), Some(*s));
        }
        assert_eq!(lookup(-1), None);
    }

    #[test]
    fn trace_list_excludes_denied_and_plain_writes() {
        let tl = trace_list();
        for nr in deny_list() {
            assert!(!tl.contains(&nr));
        }
        assert!(!tl.contains(&{ libc::SYS_write }));
        assert!(tl.contains(&{ libc::SYS_openat }));
        assert!(tl.contains(&{ libc::SYS_connect }));
    }
}
