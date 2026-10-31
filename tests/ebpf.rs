//! Integration test for `--mode ebpf`. Needs root and an active BPF LSM;
//! where the programs cannot be loaded (CI without sudo, a kernel without
//! `bpf` in its LSM list) it says so and passes.
#![cfg(all(target_os = "linux", feature = "ebpf"))]

use std::fs;
use std::process::Command;

use serde_json::Value;

#[test]
fn ebpf_records_the_same_kinds_as_ptrace() {
    let base = std::env::temp_dir().join(format!("effect-tracer-test-ebpf-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let out = base.join("ledger");
    let o = Command::new(env!("CARGO_BIN_EXE_effect-tracer"))
        .args(["run", "--quiet", "--mode", "ebpf", "--out"])
        .arg(&out)
        .args(["--", "/bin/sh", "-c"])
        .arg("echo hi > \"$T/a\"; mv \"$T/a\" \"$T/b\"; rm \"$T/b\"; mkdir \"$T/d\"; /bin/true")
        .env("T", &base)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&o.stderr);
    if stderr.contains("loading the BPF object") || stderr.contains("attach") {
        eprintln!("skipped: BPF LSM programs cannot be loaded here: {stderr}");
        return;
    }
    assert!(o.status.success(), "tracer failed: {stderr}");
    let kinds: Vec<(String, String)> = fs::read_to_string(out.join("events.jsonl"))
        .unwrap()
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            (
                v["kind"].as_str().unwrap().to_string(),
                v["name"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let has = |k: &str, n: &str| kinds.iter().any(|(kk, nn)| kk == k && nn.contains(n));
    assert!(has("file.write", "/a"), "{kinds:?}");
    assert!(has("file.rename", "/b"), "{kinds:?}");
    assert!(has("file.delete", "/b"), "{kinds:?}");
    assert!(has("file.create", "/d"), "{kinds:?}");
    assert!(has("process.exec", "true"), "{kinds:?}");
    assert!(has("process.fork", ""), "{kinds:?}");
    let lj: Value =
        serde_json::from_str(&fs::read_to_string(out.join("ledger.json")).unwrap()).unwrap();
    assert_eq!(lj["mechanism"], "ebpf");
    assert_eq!(lj["coverage"]["status"], "complete");
    let _ = fs::remove_dir_all(base);
}
