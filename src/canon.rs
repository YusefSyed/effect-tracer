//! Canonical JSON and the leaf hash.
//!
//! Rules: object keys sorted bytewise, no whitespace, integers only (floats
//! are rejected), strings escaped the way serde_json escapes them (only `"`,
//! `\` and control characters; non-ASCII stays raw UTF-8). Python's
//! `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
//! produces the same bytes, which is what `verifier/verify_ledger.py` checks.
//!
//! Leaf hash: `SHA-256(0x00 || line)` over the line bytes without the
//! trailing newline, as in RFC 9162 leaf hashing.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The `prev` value of the first event.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Serialise a JSON value canonically.
pub fn canonical(v: &Value) -> Result<String, String> {
    let mut out = String::with_capacity(256);
    write(v, &mut out)?;
    Ok(out)
}

fn write(v: &Value, out: &mut String) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_f64() {
                return Err("floats are not allowed in canonical JSON".to_string());
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => out.push_str(&serde_json::to_string(s).map_err(|e| e.to_string())?),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(x, out)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).map_err(|e| e.to_string())?);
                out.push(':');
                write(&m[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Hex SHA-256 of arbitrary bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Hex leaf hash of one ledger line (without its newline).
pub fn leaf_hash_hex(line: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(line);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let v = json!({"b": 1, "a": {"z": [1, 2, {"y": "x"}], "m": null}, "c": true});
        assert_eq!(
            canonical(&v).unwrap(),
            r#"{"a":{"m":null,"z":[1,2,{"y":"x"}]},"b":1,"c":true}"#
        );
    }

    #[test]
    fn escapes_like_python() {
        let v = json!({"s": "quote\" back\\ nl\n tab\t bell\u{7} uni é 日本 \u{2028}"});
        assert_eq!(
            canonical(&v).unwrap(),
            "{\"s\":\"quote\\\" back\\\\ nl\\n tab\\t bell\\u0007 uni é 日本 \u{2028}\"}"
        );
    }

    #[test]
    fn rejects_floats() {
        assert!(canonical(&json!({"x": 1.5})).is_err());
    }

    #[test]
    fn leaf_hash_has_domain_separator() {
        assert_ne!(leaf_hash_hex(b"abc"), sha256_hex(b"abc"));
        assert_eq!(
            leaf_hash_hex(b""),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }
}
