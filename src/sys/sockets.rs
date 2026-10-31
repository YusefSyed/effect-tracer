//! sockaddr decoding and socket introspection through a duplicated fd.

use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SockAddr {
    Inet { host: String, port: u16, v6: bool },
    Unix { path: String },
    Other { family: u16 },
}

impl SockAddr {
    pub fn port(&self) -> Option<u16> {
        match self {
            SockAddr::Inet { port, .. } => Some(*port),
            _ => None,
        }
    }
}

/// Decode the bytes of a sockaddr of the given length.
pub fn parse_sockaddr(b: &[u8]) -> Option<SockAddr> {
    if b.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([b[0], b[1]]);
    match family as i32 {
        libc::AF_INET => {
            if b.len() < 8 {
                return None;
            }
            let port = u16::from_be_bytes([b[2], b[3]]);
            let host = Ipv4Addr::new(b[4], b[5], b[6], b[7]).to_string();
            Some(SockAddr::Inet {
                host,
                port,
                v6: false,
            })
        }
        libc::AF_INET6 => {
            if b.len() < 24 {
                return None;
            }
            let port = u16::from_be_bytes([b[2], b[3]]);
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[8..24]);
            Some(SockAddr::Inet {
                host: Ipv6Addr::from(a).to_string(),
                port,
                v6: true,
            })
        }
        libc::AF_UNIX => {
            let p = &b[2..];
            let path = if p.is_empty() {
                String::new()
            } else if p[0] == 0 {
                let name = &p[1..];
                let end = name
                    .iter()
                    .rposition(|c| *c != 0)
                    .map(|i| i + 1)
                    .unwrap_or(0);
                format!("@{}", String::from_utf8_lossy(&name[..end]))
            } else {
                let end = p.iter().position(|c| *c == 0).unwrap_or(p.len());
                String::from_utf8_lossy(&p[..end]).into_owned()
            };
            Some(SockAddr::Unix { path })
        }
        _ => Some(SockAddr::Other { family }),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SockInfo {
    pub typ: i32,
}

fn getsockopt_int(fd: RawFd, opt: i32) -> Option<i32> {
    let mut v: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: v and len are valid out-pointers of the stated size.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &mut v as *mut i32 as *mut c_void,
            &mut len,
        )
    };
    if r == 0 {
        Some(v)
    } else {
        None
    }
}

/// Domain, type and protocol of a socket fd the tracer holds.
pub fn sock_info(fd: RawFd) -> Option<SockInfo> {
    Some(SockInfo {
        typ: getsockopt_int(fd, libc::SO_TYPE)?,
    })
}

/// Transport label for the event name.
pub fn label(info: Option<SockInfo>, addr: &SockAddr) -> &'static str {
    if let SockAddr::Unix { .. } = addr {
        return "unix";
    }
    match info.map(|i| i.typ) {
        Some(libc::SOCK_STREAM) => "tcp",
        Some(libc::SOCK_DGRAM) => "udp",
        Some(libc::SOCK_RAW) => "raw",
        Some(libc::SOCK_SEQPACKET) => "seqpacket",
        _ => "ip",
    }
}

pub fn render(label: &str, a: &SockAddr) -> String {
    match a {
        SockAddr::Inet {
            host,
            port,
            v6: false,
        } => format!("{label}:{host}:{port}"),
        SockAddr::Inet {
            host,
            port,
            v6: true,
        } => format!("{label}:[{host}]:{port}"),
        SockAddr::Unix { path } => format!("unix:{path}"),
        SockAddr::Other { family } if *family == libc::AF_NETLINK as u16 => "netlink".to_string(),
        SockAddr::Other { family } => format!("af{family}"),
    }
}

fn name_via(
    fd: RawFd,
    f: unsafe extern "C" fn(RawFd, *mut libc::sockaddr, *mut libc::socklen_t) -> i32,
) -> Option<SockAddr> {
    let mut storage = [0u8; 128];
    let mut len = storage.len() as libc::socklen_t;
    // SAFETY: storage is 128 bytes, enough for any sockaddr; len is in/out.
    let r = unsafe { f(fd, storage.as_mut_ptr() as *mut libc::sockaddr, &mut len) };
    if r != 0 {
        return None;
    }
    parse_sockaddr(&storage[..(len as usize).min(storage.len())])
}

pub fn local_addr(fd: RawFd) -> Option<SockAddr> {
    name_via(fd, libc::getsockname)
}

pub fn peer_addr(fd: RawFd) -> Option<SockAddr> {
    name_via(fd, libc::getpeername)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_inet_and_unix() {
        let mut v4 = Vec::new();
        v4.extend_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        v4.extend_from_slice(&8080u16.to_be_bytes());
        v4.extend_from_slice(&[127, 0, 0, 1]);
        v4.extend_from_slice(&[0; 8]);
        assert_eq!(
            parse_sockaddr(&v4),
            Some(SockAddr::Inet {
                host: "127.0.0.1".into(),
                port: 8080,
                v6: false
            })
        );
        assert_eq!(
            render("tcp", &parse_sockaddr(&v4).unwrap()),
            "tcp:127.0.0.1:8080"
        );

        let mut un = Vec::new();
        un.extend_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
        un.extend_from_slice(b"/tmp/x.sock\0\0\0");
        assert_eq!(
            render("x", &parse_sockaddr(&un).unwrap()),
            "unix:/tmp/x.sock"
        );

        let mut ab = Vec::new();
        ab.extend_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
        ab.extend_from_slice(b"\0abstract");
        assert_eq!(render("x", &parse_sockaddr(&ab).unwrap()), "unix:@abstract");
    }
}
