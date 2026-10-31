//! Reads from a tracee's memory with process_vm_readv, page by page so a
//! partially mapped range still yields what is readable.

use std::ffi::c_void;

const PAGE: usize = 4096;

/// Read up to `len` bytes at `addr`. Returns what could be read before the
/// first fault, or None if nothing could be.
pub fn read(pid: i32, addr: u64, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; len];
    let mut got = 0usize;
    while got < len {
        let cur = addr as usize + got;
        let page_end = (cur / PAGE + 1) * PAGE;
        let chunk = std::cmp::min(len - got, page_end - cur);
        let local = libc::iovec {
            iov_base: buf[got..].as_mut_ptr() as *mut c_void,
            iov_len: chunk,
        };
        let remote = libc::iovec {
            iov_base: cur as *mut c_void,
            iov_len: chunk,
        };
        // SAFETY: both iovecs describe valid memory of the stated lengths.
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n <= 0 {
            break;
        }
        got += n as usize;
        if (n as usize) < chunk {
            break;
        }
    }
    if got == 0 {
        None
    } else {
        buf.truncate(got);
        Some(buf)
    }
}

/// Read a NUL-terminated string of at most `max` bytes.
pub fn read_cstr(pid: i32, addr: u64, max: usize) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut off = 0usize;
    while off < max {
        let cur = addr as usize + off;
        let page_end = (cur / PAGE + 1) * PAGE;
        let chunk = std::cmp::min(std::cmp::min(256, page_end - cur), max - off);
        let part = read(pid, cur as u64, chunk)?;
        if let Some(nul) = part.iter().position(|b| *b == 0) {
            out.extend_from_slice(&part[..nul]);
            return Some(out);
        }
        let n = part.len();
        out.extend_from_slice(&part);
        off += n;
        if n < chunk {
            break;
        }
    }
    Some(out)
}

pub fn read_u64(pid: i32, addr: u64) -> Option<u64> {
    let b = read(pid, addr, 8)?;
    if b.len() < 8 {
        return None;
    }
    Some(u64::from_ne_bytes(b[..8].try_into().ok()?))
}
