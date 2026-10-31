//! Minimal DNS question parsing: enough to name the first QNAME of a query
//! datagram. No compression pointers in questions, no answers.

/// Returns (qname, qtype) for a DNS query message.
pub fn parse_query(b: &[u8]) -> Option<(String, u16)> {
    if b.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([b[2], b[3]]);
    if flags & 0x8000 != 0 {
        return None; // a response
    }
    if (flags >> 11) & 0xf != 0 {
        return None; // not a standard query
    }
    let qdcount = u16::from_be_bytes([b[4], b[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut i = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let l = *b.get(i)? as usize;
        i += 1;
        if l == 0 {
            break;
        }
        if l & 0xc0 != 0 || l > 63 {
            return None;
        }
        let seg = b.get(i..i + l)?;
        labels.push(String::from_utf8_lossy(seg).into_owned());
        i += l;
        if labels.len() > 127 {
            return None;
        }
    }
    let qtype = u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]);
    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Some((name, qtype))
}

pub fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut v = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&[0, 1]);
        v
    }

    #[test]
    fn parses_a_query() {
        assert_eq!(
            parse_query(&query("example.com", 1)),
            Some(("example.com".into(), 1))
        );
        assert_eq!(
            parse_query(&query("a.b.c.test", 28)),
            Some(("a.b.c.test".into(), 28))
        );
        assert_eq!(qtype_name(28), "AAAA");
    }

    #[test]
    fn rejects_responses_and_junk() {
        let mut r = query("example.com", 1);
        r[2] |= 0x80;
        assert_eq!(parse_query(&r), None);
        assert_eq!(parse_query(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(parse_query(&[0u8; 5]), None);
    }
}
