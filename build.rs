//! With `--features ebpf`, compile bpf/effects.bpf.c into OUT_DIR. The
//! object is built against this machine's kernel BTF (vmlinux.h from
//! bpftool) and relies on CO-RE relocations to run on other kernels.
//! Without the feature this does nothing, so the ptrace build needs no
//! clang or bpftool.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=bpf/effects.bpf.c");
    if env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return;
    }
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let vmlinux = out.join("vmlinux.h");
    let btf = env::var("EFFECT_TRACER_BTF").unwrap_or_else(|_| "/sys/kernel/btf/vmlinux".into());
    let dump = Command::new("bpftool")
        .args(["btf", "dump", "file", &btf, "format", "c"])
        .output()
        .expect("bpftool not found (needed for --features ebpf)");
    assert!(
        dump.status.success(),
        "bpftool btf dump failed: {}",
        String::from_utf8_lossy(&dump.stderr)
    );
    std::fs::write(&vmlinux, dump.stdout).unwrap();
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        other => panic!("no BPF target arch mapping for {other}"),
    };
    let obj = out.join("effects.bpf.o");
    let st = Command::new(env::var("CLANG").unwrap_or_else(|_| "clang".into()))
        .args(["-O2", "-g", "-Wall", "-target", "bpf"])
        .arg(format!("-D__TARGET_ARCH_{arch}"))
        .arg("-I")
        .arg(&out)
        .args(["-c", "bpf/effects.bpf.c", "-o"])
        .arg(&obj)
        .status()
        .expect("clang not found (needed for --features ebpf)");
    assert!(st.success(), "clang failed on bpf/effects.bpf.c");
}
