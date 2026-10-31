//! Reads from /proc for a traced task.

use std::fs;

fn read_to_string(pid: i32, what: &str) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/{what}")).ok()
}

/// `readlink /proc/<pid>/<what>`, lossily decoded.
pub fn readlink(pid: i32, what: &str) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/{what}"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// The path (or `socket:[ino]`, `pipe:[ino]`, `anon_inode:...`) behind an fd.
pub fn fd_path(pid: i32, fd: i64) -> Option<String> {
    if fd < 0 {
        return None;
    }
    readlink(pid, &format!("fd/{fd}"))
}

pub fn cwd(pid: i32) -> Option<String> {
    readlink(pid, "cwd")
}

pub fn exe(pid: i32) -> Option<String> {
    readlink(pid, "exe")
}

pub fn comm(pid: i32) -> String {
    read_to_string(pid, "comm")
        .map(|s| s.trim_end().to_string())
        .unwrap_or_else(|| "?".to_string())
}

/// argv of the current image.
pub fn cmdline(pid: i32) -> Vec<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let mut v: Vec<String> = raw
        .split(|b| *b == 0)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    if v.last().map(|s| s.is_empty()).unwrap_or(false) {
        v.pop();
    }
    v
}

/// Thread-group id of a task.
pub fn tgid(pid: i32) -> Option<i32> {
    let s = read_to_string(pid, "status")?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Fields of /proc/<pid>/stat after the `(comm)` field: index 0 is the state.
fn stat_fields(pid: i32) -> Option<Vec<String>> {
    let s = read_to_string(pid, "stat")?;
    let close = s.rfind(')')?;
    Some(
        s[close + 1..]
            .split_whitespace()
            .map(|f| f.to_string())
            .collect(),
    )
}

pub fn ppid(pid: i32) -> Option<i32> {
    stat_fields(pid)?.get(1)?.parse().ok()
}

/// Process start time in clock ticks since boot (field 22 of stat).
pub fn starttime(pid: i32) -> Option<u64> {
    stat_fields(pid)?.get(19)?.parse().ok()
}

pub fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// (release, machine) from uname.
pub fn uname() -> (String, String) {
    // SAFETY: utsname is a plain struct uname fills in.
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) != 0 {
            return ("unknown".into(), "unknown".into());
        }
        #[allow(clippy::unnecessary_cast)] // c_char is i8 on x86_64 and u8 on aarch64
        let cs = |a: &[libc::c_char]| {
            let bytes: Vec<u8> = a
                .iter()
                .take_while(|c| **c != 0)
                .map(|c| *c as u8)
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        };
        (cs(&u.release), cs(&u.machine))
    }
}
