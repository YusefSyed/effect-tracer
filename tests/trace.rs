//! Integration test: run the built binary on a small shell script and check
//! the ledger it writes. Linux only (ptrace).
#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};

fn leaf(line: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(line);
    hex::encode(h.finalize())
}

fn run_ledger(tag: &str, script: &str) -> (PathBuf, Vec<Value>, Value, Value) {
    let base =
        std::env::temp_dir().join(format!("effect-tracer-test-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let out = base.join("ledger");
    let status = Command::new(env!("CARGO_BIN_EXE_effect-tracer"))
        .args(["run", "--quiet", "--out"])
        .arg(&out)
        .arg("--")
        .args(["/bin/sh", "-c", script])
        .env("T", &base)
        .status()
        .expect("spawn tracer");
    assert!(status.success(), "tracer exit {status}");
    let text = fs::read_to_string(out.join("events.jsonl")).unwrap();
    let mut prev = "0".repeat(64);
    let mut events = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let v: Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["seq"].as_u64().unwrap(), i as u64 + 1);
        assert_eq!(
            v["prev"].as_str().unwrap(),
            prev,
            "chain broken at line {}",
            i + 1
        );
        prev = leaf(line.as_bytes());
        events.push(v);
    }
    let cp: Value =
        serde_json::from_str(&fs::read_to_string(out.join("checkpoint.json")).unwrap()).unwrap();
    assert_eq!(cp["headHash"].as_str().unwrap(), prev);
    assert_eq!(cp["treeSize"].as_u64().unwrap(), events.len() as u64);
    let lj: Value =
        serde_json::from_str(&fs::read_to_string(out.join("ledger.json")).unwrap()).unwrap();
    (base, events, cp, lj)
}

fn has(events: &[Value], kind: &str, name_contains: &str) -> bool {
    events
        .iter()
        .any(|e| e["kind"] == kind && e["name"].as_str().unwrap_or("").contains(name_contains))
}

#[test]
fn records_exec_write_rename_delete_and_signs() {
    let (base, events, cp, lj) = run_ledger(
        "basic",
        "echo hi > \"$T/a.txt\"; mv \"$T/a.txt\" \"$T/b.txt\"; rm \"$T/b.txt\"; mkdir \"$T/d\"; /bin/true",
    );
    assert_eq!(events.first().unwrap()["kind"], "run.start");
    assert_eq!(events.last().unwrap()["kind"], "run.end");
    assert!(
        has(&events, "process.exec", "/bin/sh")
            || has(&events, "process.exec", "dash")
            || has(&events, "process.exec", "bash")
    );
    assert!(
        has(&events, "process.exec", "true"),
        "exec of /bin/true missing"
    );
    assert!(
        has(&events, "file.write", "a.txt"),
        "shell redirect missing"
    );
    assert!(has(&events, "file.rename", "b.txt"), "rename missing");
    assert!(has(&events, "file.delete", "b.txt"), "unlink missing");
    assert!(has(&events, "file.create", "/d"), "mkdir missing");
    assert!(has(&events, "process.fork", ""), "fork missing");
    assert!(has(&events, "process.exit", ""), "exit missing");
    assert_eq!(
        events.last().unwrap()["detail"]["coverage"]["status"],
        "complete"
    );
    assert_eq!(cp["schema"], "effect-tracer-checkpoint/1");
    assert_eq!(lj["schema"], "effect-tracer-ledger/1");
    assert_eq!(lj["coverage"]["status"], "complete");
    let _ = fs::remove_dir_all(base);
}

#[test]
fn netlink_route_socket_is_named_not_a_coverage_gap() {
    // glibc getaddrinfo opens socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE); before
    // v0.1.1 that read as a raw-socket gap and every hostname lookup made the run partial.
    let (base, events, _cp, lj) = run_ledger(
        "netlink",
        "python3 -c 'import socket; s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0); s.close()'",
    );
    assert!(has(&events, "socket.netlink", "route"), "netlink socket not recorded");
    assert!(
        !has(&events, "coverage.gap", "raw-socket"),
        "netlink socket still read as a raw-socket gap"
    );
    assert_eq!(lj["coverage"]["status"], "complete");
    let _ = fs::remove_dir_all(base);
}

#[test]
fn exit_code_passes_through() {
    let base = std::env::temp_dir().join(format!("effect-tracer-test-exit-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let status = Command::new(env!("CARGO_BIN_EXE_effect-tracer"))
        .args(["run", "--quiet", "--out"])
        .arg(base.join("ledger"))
        .args(["--", "/bin/sh", "-c", "exit 7"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(7));
    let _ = fs::remove_dir_all(base);
}

#[test]
fn pin_cpu_applies_to_the_whole_tree() {
    let base = std::env::temp_dir().join(format!("effect-tracer-test-pin-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let out = base.join("ledger");
    let status = Command::new(env!("CARGO_BIN_EXE_effect-tracer"))
        .args(["run", "--quiet", "--pin-cpu", "0", "--out"])
        .arg(&out)
        .args(["--", "/bin/sh", "-c"])
        .arg("sh -c 'grep Cpus_allowed_list /proc/self/status' > \"$T/cpus\"")
        .env("T", &base)
        .status()
        .unwrap();
    assert!(status.success(), "tracer exit {status}");
    let cpus = fs::read_to_string(base.join("cpus")).unwrap();
    assert_eq!(cpus.split_whitespace().last(), Some("0"), "{cpus}");
    let first = fs::read_to_string(out.join("events.jsonl")).unwrap();
    let start: Value = serde_json::from_str(first.lines().next().unwrap()).unwrap();
    assert_eq!(start["detail"]["options"]["pinCpu"], 0);
    let _ = fs::remove_dir_all(base);
}
