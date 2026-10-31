#!/usr/bin/env python3
"""Verify an effect-tracer ledger directory with the Python standard library.

Usage: verify_ledger.py DIR [--pubkey HEX] [--json] [--quiet]

Exit codes
  0  chain intact, checkpoint signature valid, run complete, coverage complete
  1  integrity failure: broken chain, non-canonical line, wrong head or size,
     bad signature, key pin mismatch, summary files that disagree
  2  unreadable or malformed input, or a usage error
  3  chain and signature are fine but the run is not complete: coverage
     partial or failed, the tracer did not finish, or there is no checkpoint

What it checks, in order: every line of events.jsonl parses as a JSON object,
re-serialises to the same bytes (canonical form), carries seq 1..n and a prev
equal to the leaf hash SHA-256(0x00 || previous line); the first event is
run.start and the last is run.end; checkpoint.json names the same run, the
same tree size and the computed head hash, its keyid is the SHA-256 of the
SPKI DER of its public key, and its Ed25519 signature (RFC 8032, verified here
in pure Python) covers the canonical checkpoint body; ledger.json, if present,
agrees with the chain; finally the run.end coverage status.

An embedded public key proves only that the ledger is self-consistent. To
know who signed it, pass --pubkey with the key you expect.
"""

import argparse
import hashlib
import json
import os
import sys

GENESIS = "0" * 64
LEDGER_SCHEMA = "effect-tracer-ledger/1"
CHECKPOINT_SCHEMA = "effect-tracer-checkpoint/1"
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
REQUIRED = ("seq", "prev", "monoNs", "proc", "kind", "name", "outcome")


# ---------------------------------------------------------------- Ed25519 --
# RFC 8032 section 5.1, written out with Python integers. Verification only.

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % _P
    bb = (y1 + x1) * (y2 + x2) % _P
    cc = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, pt):
    acc = (0, 1, 1, 0)
    while s:
        if s & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        s >>= 1
    return acc


def _eq(a, b):
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _decompress(raw):
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def ed25519_verify(public, msg, signature):
    """True when `signature` (64 bytes) by `public` (32 bytes) covers `msg`."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + msg).digest(), "little") % _Q
    return _eq(_mul(s, _G), _add(r, _mul(h, a)))


# ------------------------------------------------------------------ helpers --


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def leaf_hash(line_bytes):
    return hashlib.sha256(b"\x00" + line_bytes).hexdigest()


def keyid_of(public):
    return hashlib.sha256(SPKI_PREFIX + public).hexdigest()


class Failure(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def load_json(path, what):
    try:
        with open(path, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    except FileNotFoundError:
        raise Failure(2, f"{what} missing: {path}")
    except (ValueError, UnicodeDecodeError) as e:
        raise Failure(2, f"{what} is not valid JSON: {e}")


# ------------------------------------------------------------------- checks --


def verify(directory, pubkey_hex=None):
    """Return a report dict; raise Failure on any problem."""
    report = {"dir": directory, "events": 0, "warnings": []}
    events_path = os.path.join(directory, "events.jsonl")
    try:
        with open(events_path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        raise Failure(2, f"events.jsonl missing in {directory}")
    if not raw:
        raise Failure(2, "events.jsonl is empty")
    if not raw.endswith(b"\n"):
        raise Failure(1, "events.jsonl does not end with a newline (truncated?)")

    lines = raw[:-1].split(b"\n")
    prev = GENESIS
    first = last = None
    last_mono = -1
    kinds = {}
    for i, line in enumerate(lines, start=1):
        try:
            ev = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise Failure(2, f"line {i} is not valid JSON: {e}")
        if not isinstance(ev, dict):
            raise Failure(2, f"line {i} is not a JSON object")
        for k in REQUIRED:
            if k not in ev:
                raise Failure(2, f"line {i} lacks the {k} field")
        if canonical(ev) != line:
            raise Failure(1, f"line {i} is not in canonical form")
        if ev["seq"] != i:
            raise Failure(1, f"line {i} carries seq {ev['seq']}")
        if ev["prev"] != prev:
            raise Failure(1, f"chain broken at line {i}: prev does not match the previous leaf hash")
        try:
            mono = int(ev["monoNs"])
        except (TypeError, ValueError):
            raise Failure(2, f"line {i} has a non-integer monoNs")
        if mono < last_mono:
            report["warnings"].append(f"line {i}: monoNs goes backwards")
        last_mono = mono
        kinds[ev["kind"]] = kinds.get(ev["kind"], 0) + 1
        if first is None:
            first = ev
        last = ev
        prev = leaf_hash(line)

    head = prev
    n = len(lines)
    report["events"] = n
    report["headHash"] = head
    report["kinds"] = kinds

    if first.get("kind") != "run.start":
        raise Failure(1, "the first event is not run.start")
    run_id = first.get("detail", {}).get("runId")
    if not isinstance(run_id, str) or not run_id:
        raise Failure(2, "run.start carries no runId")
    report["runId"] = run_id
    report["mechanism"] = first.get("detail", {}).get("mechanism")
    finished = last.get("kind") == "run.end"

    cp_path = os.path.join(directory, "checkpoint.json")
    if not os.path.exists(cp_path):
        if finished:
            raise Failure(1, "run.end is present but checkpoint.json is missing")
        raise Failure(3, "no checkpoint.json: the tracer did not finish, so the ledger is unsigned and incomplete")
    cp = load_json(cp_path, "checkpoint.json")
    if not isinstance(cp, dict):
        raise Failure(2, "checkpoint.json is not an object")
    if not finished:
        raise Failure(1, "checkpoint.json exists but the last event is not run.end")
    for k in ("schema", "runId", "treeSize", "headHash", "signedAt", "keyid", "publicKey", "signature"):
        if k not in cp:
            raise Failure(2, f"checkpoint.json lacks {k}")
    if cp["schema"] != CHECKPOINT_SCHEMA:
        raise Failure(2, f"unknown checkpoint schema {cp['schema']!r}")
    if cp["runId"] != run_id:
        raise Failure(1, "checkpoint.json names a different runId than run.start")
    if cp["treeSize"] != n:
        raise Failure(1, f"checkpoint treeSize {cp['treeSize']} but events.jsonl holds {n} events")
    if cp["headHash"] != head:
        raise Failure(1, "checkpoint headHash does not match the computed chain head")
    try:
        public = bytes.fromhex(cp["publicKey"])
        signature = bytes.fromhex(cp["signature"])
    except ValueError:
        raise Failure(2, "checkpoint publicKey or signature is not hex")
    if keyid_of(public) != cp["keyid"]:
        raise Failure(1, "checkpoint keyid is not the SHA-256 of the public key's SPKI DER")
    if pubkey_hex is not None and pubkey_hex.lower() != cp["publicKey"].lower():
        raise Failure(1, "checkpoint public key does not match --pubkey")
    body = {k: cp[k] for k in ("schema", "runId", "treeSize", "headHash", "signedAt")}
    if not ed25519_verify(public, canonical(body), signature):
        raise Failure(1, "checkpoint signature does not verify")
    report["keyid"] = cp["keyid"]
    report["publicKey"] = cp["publicKey"]
    report["signedAt"] = cp["signedAt"]
    report["pinned"] = pubkey_hex is not None

    lj_path = os.path.join(directory, "ledger.json")
    if os.path.exists(lj_path):
        lj = load_json(lj_path, "ledger.json")
        if not isinstance(lj, dict):
            raise Failure(2, "ledger.json is not an object")
        if lj.get("schema") != LEDGER_SCHEMA:
            raise Failure(2, f"unknown ledger schema {lj.get('schema')!r}")
        for k, want in (("runId", run_id), ("treeSize", n), ("headHash", head), ("publicKey", cp["publicKey"])):
            if lj.get(k) != want:
                raise Failure(1, f"ledger.json {k} disagrees with the signed chain")
        end_cov = last.get("detail", {}).get("coverage", {})
        if lj.get("coverage") != end_cov:
            raise Failure(1, "ledger.json coverage disagrees with the signed run.end event")
    else:
        report["warnings"].append("ledger.json missing (optional)")

    cov = last.get("detail", {}).get("coverage", {})
    status = cov.get("status")
    report["coverage"] = status
    report["reasons"] = cov.get("reasons", [])
    report["exit"] = last.get("detail", {}).get("exit")
    if status != "complete":
        raise Failure(3, f"coverage is {status!r}: " + "; ".join(report["reasons"] or ["no reason recorded"]))
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify an effect-tracer ledger directory.")
    ap.add_argument("dir")
    ap.add_argument("--pubkey", help="hex Ed25519 public key the checkpoint must carry")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    try:
        report = verify(args.dir, args.pubkey)
        code = 0
        report["ok"] = True
    except Failure as f:
        report = {"dir": args.dir, "ok": False, "error": str(f), "code": f.code}
        code = f.code
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif not args.quiet:
        if code == 0:
            print(f"OK: {report['events']} events, run {report['runId']}, mechanism {report['mechanism']}, "
                  f"coverage complete, signed by keyid {report['keyid'][:16]}..."
                  + ("" if report["pinned"] else " (unpinned: pass --pubkey to check who signed)"))
            for w in report["warnings"]:
                print(f"warning: {w}")
        else:
            print(f"FAIL ({code}): {report['error']}")
    return code


if __name__ == "__main__":
    sys.exit(main())
