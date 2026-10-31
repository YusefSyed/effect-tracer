//! Lexical path normalisation and dirfd-relative resolution helpers.

/// Collapse `.`, `..` and repeated slashes. Does not touch the filesystem.
pub fn normalize(p: &str) -> String {
    let absolute = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.is_empty() {
                    if !absolute {
                        parts.push("..");
                    }
                } else if parts.last() == Some(&"..") {
                    parts.push("..");
                } else {
                    parts.pop();
                }
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// Join a relative path onto a base directory and normalise.
pub fn join(base: &str, rel: &str) -> String {
    if rel.starts_with('/') {
        normalize(rel)
    } else {
        normalize(&format!("{base}/{rel}"))
    }
}

/// `/proc/self/fd/N`, `/proc/<pid>/fd/N` or `/dev/fd/N` -> Some(N).
pub fn proc_fd_number(p: &str) -> Option<i64> {
    let rest = if let Some(r) = p.strip_prefix("/proc/self/fd/") {
        r
    } else if let Some(r) = p.strip_prefix("/dev/fd/") {
        r
    } else {
        let r = p.strip_prefix("/proc/")?;
        let (pid, tail) = r.split_once('/')?;
        if pid.chars().all(|c| c.is_ascii_digit()) {
            tail.strip_prefix("fd/")?
        } else {
            return None;
        }
    };
    rest.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises() {
        assert_eq!(normalize("/a/b/../c/./d//"), "/a/c/d");
        assert_eq!(normalize("/../x"), "/x");
        assert_eq!(normalize("a/../../b"), "../b");
        assert_eq!(normalize("."), ".");
        assert_eq!(join("/work", "out/../x.txt"), "/work/x.txt");
        assert_eq!(join("/work", "/etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn proc_fd() {
        assert_eq!(proc_fd_number("/proc/self/fd/7"), Some(7));
        assert_eq!(proc_fd_number("/proc/1234/fd/3"), Some(3));
        assert_eq!(proc_fd_number("/dev/fd/0"), Some(0));
        assert_eq!(proc_fd_number("/proc/sys/fd/3"), None);
        assert_eq!(proc_fd_number("/work/fd/3"), None);
    }
}
