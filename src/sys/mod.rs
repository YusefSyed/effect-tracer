//! Linux-only pieces: the syscall table, the seccomp filter, /proc helpers,
//! tracee memory reads, path and socket decoding, DNS parsing and the ptrace
//! loop itself.

pub mod dns;
#[cfg(feature = "ebpf")]
pub mod ebpf;
pub mod mem;
pub mod paths;
pub mod procinfo;
pub mod seccomp;
pub mod sockets;
pub mod syscalls;
pub mod tracer;
