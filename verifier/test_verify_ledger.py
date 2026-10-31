#!/usr/bin/env python3
"""Tamper tests for verify_ledger.py (stdlib unittest).

Run: python3 -m unittest verifier/test_verify_ledger.py
The fixture ledger in verifier/fixtures/basic was produced by the tracer;
each test copies it, breaks one thing, and expects the matching exit code.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verify_ledger as vl  # noqa: E402

FIXTURE = os.path.join(HERE, "fixtures", "basic")


def read_lines(d):
    with open(os.path.join(d, "events.jsonl"), "rb") as f:
        return f.read()[:-1].split(b"\n")


def write_lines(d, lines):
    with open(os.path.join(d, "events.jsonl"), "wb") as f:
        f.write(b"\n".join(lines) + b"\n")


def rechain(lines):
    """Recompute seq and prev for edited lines (what a tamperer would do)."""
    out = []
    prev = vl.GENESIS
    for i, line in enumerate(lines, start=1):
        ev = json.loads(line)
        ev["seq"] = i
        ev["prev"] = prev
        b = vl.canonical(ev)
        out.append(b)
        prev = vl.leaf_hash(b)
    return out


def _compress(pt):
    x, y, z, _ = pt
    zi = vl._inv(z)
    x, y = x * zi % vl._P, y * zi % vl._P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_sign(seed, msg):
    """RFC 8032 signing on the verifier's own curve arithmetic: test-only,
    so the suite can play an attacker with a key of their own."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    public = _compress(vl._mul(a, vl._G))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % vl._Q
    big_r = _compress(vl._mul(r, vl._G))
    k = int.from_bytes(hashlib.sha512(big_r + public + msg).digest(), "little") % vl._Q
    return public, big_r + ((r + k * a) % vl._Q).to_bytes(32, "little")


class TamperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="et-verify-")
        self.d = os.path.join(self.tmp, "ledger")
        shutil.copytree(FIXTURE, self.d)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def code(self, *extra):
        return vl.main([self.d, "--quiet", *extra])

    def test_fixture_verifies(self):
        self.assertEqual(self.code(), 0)
        report = vl.verify(self.d)
        self.assertEqual(report["coverage"], "complete")
        self.assertGreater(report["events"], 3)

    def test_pin_accepts_the_right_key_and_rejects_another(self):
        with open(os.path.join(self.d, "checkpoint.json")) as f:
            cp = json.load(f)
        self.assertEqual(self.code("--pubkey", cp["publicKey"]), 0)
        self.assertEqual(self.code("--pubkey", "00" * 32), 1)

    def test_edit_one_event(self):
        lines = read_lines(self.d)
        ev = json.loads(lines[1])
        ev["name"] = ev["name"] + "-edited"
        lines[1] = vl.canonical(ev)
        write_lines(self.d, lines)
        self.assertEqual(self.code(), 1)

    def test_edit_and_rechain_fails_on_head(self):
        lines = read_lines(self.d)
        ev = json.loads(lines[1])
        ev["outcome"] = "failed"
        lines[1] = vl.canonical(ev)
        write_lines(self.d, rechain(lines))
        self.assertEqual(self.code(), 1)

    def test_delete_a_middle_event(self):
        lines = read_lines(self.d)
        del lines[2]
        write_lines(self.d, lines)
        self.assertEqual(self.code(), 1)
        write_lines(self.d, rechain(lines))
        self.assertEqual(self.code(), 1)

    def test_append_a_forged_event(self):
        lines = read_lines(self.d)
        forged = json.loads(lines[-2])
        forged["name"] = "/etc/forged"
        lines.insert(len(lines) - 1, vl.canonical(forged))
        write_lines(self.d, rechain(lines))
        self.assertEqual(self.code(), 1)

    def test_swap_two_events(self):
        lines = read_lines(self.d)
        lines[1], lines[2] = lines[2], lines[1]
        write_lines(self.d, lines)
        self.assertEqual(self.code(), 1)

    def test_truncate_drops_run_end(self):
        lines = read_lines(self.d)
        write_lines(self.d, lines[:-1])
        self.assertEqual(self.code(), 1)
        os.remove(os.path.join(self.d, "checkpoint.json"))
        self.assertEqual(self.code(), 3)

    def test_non_canonical_line(self):
        lines = read_lines(self.d)
        ev = json.loads(lines[1])
        lines[1] = json.dumps(ev, sort_keys=True, separators=(", ", ": ")).encode()
        write_lines(self.d, lines)
        self.assertEqual(self.code(), 1)

    def test_bad_signature(self):
        p = os.path.join(self.d, "checkpoint.json")
        with open(p) as f:
            cp = json.load(f)
        sig = bytearray(bytes.fromhex(cp["signature"]))
        sig[5] ^= 0x01
        cp["signature"] = sig.hex()
        with open(p, "wb") as f:
            f.write(vl.canonical(cp) + b"\n")
        self.assertEqual(self.code(), 1)

    def test_resigned_by_another_key_is_caught_only_by_the_pin(self):
        # An attacker rewrites an event, rechains, and signs the new head
        # with a key of their own: a self-consistent ledger that passes
        # unpinned. Only --pubkey with the real key exposes it.
        lines = [json.loads(x) for x in read_lines(self.d)]
        for ev in lines:
            if ev["kind"] == "file.write":
                ev["name"] = "/tmp/nothing-to-see"
        lines = rechain([vl.canonical(ev) for ev in lines])
        write_lines(self.d, lines)
        head = vl.leaf_hash(lines[-1])
        cpp = os.path.join(self.d, "checkpoint.json")
        with open(cpp) as f:
            cp = json.load(f)
        original = cp["publicKey"]
        cp["headHash"] = head
        body = {k: cp[k] for k in ("schema", "runId", "treeSize", "headHash", "signedAt")}
        public, sig = ed25519_sign(b"\x07" * 32, vl.canonical(body))
        cp["publicKey"], cp["signature"], cp["keyid"] = public.hex(), sig.hex(), vl.keyid_of(public)
        with open(cpp, "wb") as f:
            f.write(vl.canonical(cp) + b"\n")
        ljp = os.path.join(self.d, "ledger.json")
        with open(ljp) as f:
            lj = json.load(f)
        for k in ("headHash", "publicKey", "keyid"):
            if k in lj:
                lj[k] = cp[k]
        with open(ljp, "wb") as f:
            f.write(vl.canonical(lj) + b"\n")
        self.assertNotEqual(public.hex(), original)
        self.assertEqual(self.code(), 0)
        self.assertEqual(self.code("--pubkey", public.hex()), 0)
        self.assertEqual(self.code("--pubkey", original), 1)

    def test_signer_matches_rfc8032(self):
        # the test signer reproduces RFC 8032 section 7.1, test 1
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        public, sig = ed25519_sign(seed, b"")
        self.assertEqual(public.hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        self.assertTrue(sig.hex().startswith("e5564300c360ac729086e2cc806e828a"))

    def test_ledger_json_coverage_disagrees(self):
        p = os.path.join(self.d, "ledger.json")
        with open(p) as f:
            lj = json.load(f)
        lj["coverage"] = {"status": "complete", "reasons": ["forged"]}
        with open(p, "wb") as f:
            f.write(vl.canonical(lj) + b"\n")
        self.assertEqual(self.code(), 1)

    def test_malformed_json_line(self):
        lines = read_lines(self.d)
        lines[1] = b"{not json"
        write_lines(self.d, lines)
        self.assertEqual(self.code(), 2)

    def test_ed25519_rfc8032_vector(self):
        # RFC 8032 section 7.1, test 2 (one-byte message).
        pk = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        msg = bytes.fromhex("72")
        sig = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        self.assertTrue(vl.ed25519_verify(pk, msg, sig))
        self.assertFalse(vl.ed25519_verify(pk, b"\x73", sig))
        self.assertFalse(vl.ed25519_verify(pk, msg, sig[:-1] + b"\x01"))


if __name__ == "__main__":
    unittest.main()
