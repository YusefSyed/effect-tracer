//! effect-tracer: records the side effects of a Linux process tree (file
//! writes, socket connects, DNS queries, execs) into a hash-chained,
//! Ed25519-signed ledger using ptrace.
//!
//! The ledger format and the Python verifier are documented in LEDGER.md.

mod canon;
mod ledger;
#[cfg(target_os = "linux")]
mod sys;
mod timefmt;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "effect-tracer",
    version,
    about = "Record the file, socket, DNS and process effects of a Linux process tree into a signed ledger."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a command under the tracer and write a ledger directory.
    Run(RunArgs),
    /// Generate an Ed25519 signing key for `run --key`.
    Keygen {
        /// Where to write the 32-byte hex seed (created with mode 0600).
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the events of a ledger directory, one per line.
    Show {
        /// Ledger directory written by `run --out`.
        dir: PathBuf,
    },
}

/// How the tracer stops the tracee.
#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum Mode {
    /// Stop at every syscall entry and exit (PTRACE_SYSCALL).
    Full,
    /// Stop only at the effect syscalls selected by a seccomp filter
    /// (SECCOMP_RET_TRACE), then once more at their exit.
    Seccomp,
    /// No stops: BPF LSM hooks and tracepoints (root; build with
    /// `--features ebpf`).
    Ebpf,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::Full => "ptrace",
            Mode::Seccomp => "ptrace+seccomp",
            Mode::Ebpf => "ebpf",
        }
    }
}

#[derive(Args, Clone, Debug)]
pub struct RunArgs {
    /// Ledger directory to create.
    #[arg(long, default_value = "ledger")]
    pub out: PathBuf,
    /// Replace an existing ledger directory.
    #[arg(long)]
    pub force: bool,
    /// Tracing mechanism.
    #[arg(long, value_enum, default_value_t = Mode::Full)]
    pub mode: Mode,
    /// Record exec argv in clear instead of a SHA-256 digest.
    #[arg(long)]
    pub clear_argv: bool,
    /// Record read-only opens as file.read events.
    #[arg(long)]
    pub trace_reads: bool,
    /// Extra UDP ports treated as DNS (53 is always included).
    #[arg(long = "dns-port")]
    pub dns_ports: Vec<u16>,
    /// Hex seed file from `keygen`; default: a fresh key for this run.
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// Do not echo events to stderr.
    #[arg(long)]
    pub quiet: bool,
    /// Run the tracer and the traced tree on one CPU (`auto`: the CPU the
    /// tracer starts on). Each ptrace stop then switches tasks on one CPU
    /// instead of waking another one; faster for serial workloads, slower
    /// for parallel ones.
    #[arg(long, value_name = "CPU|auto", num_args = 0..=1, default_missing_value = "auto")]
    pub pin_cpu: Option<String>,
    /// Run the command as UID[:GID] (the tracer must be root). The tree then
    /// cannot read the key file or the tracer's memory; see LEDGER.md,
    /// "Trust boundary".
    #[arg(long, value_name = "UID[:GID]")]
    pub run_as: Option<String>,
    /// Command to run.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen { out } => match ledger::keygen(&out) {
            Ok(pk) => {
                println!("public key: {pk}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("effect-tracer: {e:#}");
                ExitCode::from(2)
            }
        },
        Cmd::Show { dir } => match ledger::show(&dir) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("effect-tracer: {e:#}");
                ExitCode::from(2)
            }
        },
        Cmd::Run(args) => run(args),
    }
}

#[cfg(target_os = "linux")]
fn run(args: RunArgs) -> ExitCode {
    let result = if args.mode == Mode::Ebpf {
        run_ebpf(args)
    } else {
        sys::tracer::run(args)
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("effect-tracer: {e:#}");
            ExitCode::from(3)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_args: RunArgs) -> ExitCode {
    eprintln!(
        "effect-tracer: the ptrace tracer runs on Linux only (this build targets {})",
        std::env::consts::OS
    );
    ExitCode::from(2)
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn run_ebpf(args: RunArgs) -> anyhow::Result<u8> {
    sys::ebpf::run(args)
}

#[cfg(all(target_os = "linux", not(feature = "ebpf")))]
fn run_ebpf(_args: RunArgs) -> anyhow::Result<u8> {
    anyhow::bail!("--mode ebpf needs a build with `cargo build --features ebpf`")
}
