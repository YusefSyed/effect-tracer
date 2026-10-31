//! The ledger directory: `events.jsonl` (hash-chained canonical JSON lines),
//! `checkpoint.json` (Ed25519 signature over the chain head) and
//! `ledger.json` (an unsigned convenience summary).

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};

use crate::canon;
use crate::timefmt;

pub const LEDGER_SCHEMA: &str = "effect-tracer-ledger/1";
pub const CHECKPOINT_SCHEMA: &str = "effect-tracer-checkpoint/1";

/// DER prefix of a SubjectPublicKeyInfo for an Ed25519 key (RFC 8410).
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Key id: hex SHA-256 of the SPKI DER encoding of the public key.
pub fn keyid(vk: &VerifyingKey) -> String {
    let mut der = SPKI_PREFIX.to_vec();
    der.extend_from_slice(vk.as_bytes());
    canon::sha256_hex(&der)
}

/// Generate a signing key, write its 32-byte hex seed to `out` and return
/// the hex public key.
pub fn keygen(out: &Path) -> Result<String> {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(out)
        .with_context(|| format!("create {}", out.display()))?;
    f.write_all(hex::encode(key.to_bytes()).as_bytes())?;
    f.write_all(b"\n")?;
    Ok(hex::encode(key.verifying_key().as_bytes()))
}

/// Load a signing key written by `keygen`.
pub fn load_key(path: &Path) -> Result<SigningKey> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let bytes = hex::decode(text.trim()).context("key file is not hex")?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("key file must hold a 32-byte seed"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// An open ledger being written.
pub struct Ledger {
    dir: PathBuf,
    out: BufWriter<File>,
    seq: u64,
    head: String,
    key: SigningKey,
    run_id: String,
    print: bool,
}

impl Ledger {
    pub fn create(
        dir: &Path,
        force: bool,
        key: SigningKey,
        run_id: String,
        print: bool,
    ) -> Result<Ledger> {
        if dir.exists() {
            if force {
                fs::remove_dir_all(dir).with_context(|| format!("remove {}", dir.display()))?;
            } else {
                bail!(
                    "{} already exists (use --force to replace it)",
                    dir.display()
                );
            }
        }
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(dir.join("events.jsonl"))
            .context("create events.jsonl")?;
        Ok(Ledger {
            dir: dir.to_path_buf(),
            out: BufWriter::with_capacity(1 << 16, f),
            seq: 0,
            head: canon::GENESIS.to_string(),
            key,
            run_id,
            print,
        })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().as_bytes())
    }

    pub fn keyid(&self) -> String {
        keyid(&self.key.verifying_key())
    }

    /// Append one event. `seq` and `prev` are set here; everything else is
    /// the caller's. Returns the sequence number.
    pub fn append(&mut self, mut ev: Map<String, Value>) -> Result<u64> {
        self.seq += 1;
        ev.insert("seq".to_string(), json!(self.seq));
        ev.insert("prev".to_string(), Value::String(self.head.clone()));
        if self.print {
            eprintln!("{}", human_line(&ev));
        }
        let line = canon::canonical(&Value::Object(ev)).map_err(|e| anyhow!(e))?;
        self.out.write_all(line.as_bytes())?;
        self.out.write_all(b"\n")?;
        self.head = canon::leaf_hash_hex(line.as_bytes());
        Ok(self.seq)
    }

    /// Flush, sign the chain head and write `checkpoint.json` and
    /// `ledger.json`. `summary` holds the run-level fields for ledger.json.
    pub fn finish(mut self, summary: Map<String, Value>) -> Result<()> {
        self.out.flush()?;
        self.out.get_ref().sync_all()?;
        let signed_at = timefmt::now_rfc3339();
        let body = json!({
            "schema": CHECKPOINT_SCHEMA,
            "runId": self.run_id,
            "treeSize": self.seq,
            "headHash": self.head,
            "signedAt": signed_at,
        });
        let body_bytes = canon::canonical(&body).map_err(|e| anyhow!(e))?;
        let sig = self.key.sign(body_bytes.as_bytes());
        let mut cp = body.as_object().cloned().unwrap_or_default();
        cp.insert("keyid".into(), Value::String(self.keyid()));
        cp.insert("publicKey".into(), Value::String(self.public_key_hex()));
        cp.insert(
            "signature".into(),
            Value::String(hex::encode(sig.to_bytes())),
        );
        write_atomic(&self.dir.join("checkpoint.json"), &Value::Object(cp))?;

        let mut lj = summary;
        lj.insert("schema".into(), Value::String(LEDGER_SCHEMA.into()));
        lj.insert("runId".into(), Value::String(self.run_id.clone()));
        lj.insert("treeSize".into(), json!(self.seq));
        lj.insert("headHash".into(), Value::String(self.head.clone()));
        lj.insert("keyid".into(), Value::String(self.keyid()));
        lj.insert("publicKey".into(), Value::String(self.public_key_hex()));
        write_atomic(&self.dir.join("ledger.json"), &Value::Object(lj))?;
        Ok(())
    }
}

fn write_atomic(path: &Path, v: &Value) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    let text = canon::canonical(v).map_err(|e| anyhow!(e))?;
    {
        let mut f = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(text.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

/// One readable line for an event (used for `--print` and `show`).
pub fn human_line(ev: &Map<String, Value>) -> String {
    let s = |k: &str| ev.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let seq = ev.get("seq").and_then(Value::as_u64).unwrap_or(0);
    let pid = ev
        .get("proc")
        .and_then(|p| p.get("pid"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let comm = ev
        .get("proc")
        .and_then(|p| p.get("comm"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut extra = String::new();
    if let Some(Value::Object(d)) = ev.get("detail") {
        for k in [
            "errno", "via", "from", "thread", "childPid", "qtype", "exitCode", "signal",
        ] {
            if let Some(v) = d.get(k) {
                extra.push_str(&format!(" {k}={}", v));
            }
        }
    }
    format!(
        "#{seq} {} {} {} pid={pid} {comm}{extra}",
        s("kind"),
        s("name"),
        s("outcome")
    )
}

/// Print the events of a ledger directory.
pub fn show(dir: &Path) -> Result<()> {
    let f = File::open(dir.join("events.jsonl"))
        .with_context(|| format!("open {}", dir.join("events.jsonl").display()))?;
    for line in BufReader::new(f).lines() {
        let line = line?;
        let v: Value = serde_json::from_str(&line).context("events.jsonl holds a non-JSON line")?;
        match v {
            Value::Object(m) => println!("{}", human_line(&m)),
            _ => bail!("events.jsonl holds a non-object line"),
        }
    }
    Ok(())
}
