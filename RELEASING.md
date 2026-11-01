# Releasing

How a release of effect-tracer is cut, what the release workflow produces,
and how anyone can check what they downloaded.

## What a release contains

`.github/workflows/release.yml` runs on every `v*` tag (and by hand through
`workflow_dispatch`, which does everything except create the GitHub
release). For the tag `vX.Y.Z` it produces:

| asset | what it is |
|---|---|
| `effect-tracer-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` | release binary (plus `LICENSE`, `README.md`, `LEDGER.md`), built on `ubuntu-24.04` |
| `effect-tracer-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz` | the same, built on `ubuntu-24.04-arm` |
| `effect-tracer-vX.Y.Z-<target>.cdx.json` | CycloneDX 1.5 SBOM for that binary, one per target, from `cargo cyclonedx --describe binaries` |
| `vex.openvex.json` | OpenVEX statements for the dependency tree at this release |
| `verify_ledger.py` | the stdlib Python ledger verifier, as shipped in `verifier/` |
| `release-signing-key.pub`, `allowed_signers` | the public half of the release key, as committed in this repository |
| `MANIFEST.txt` | `sha256sum` lines for every asset above |
| `MANIFEST.txt.sig` | OpenSSH signature over `MANIFEST.txt`, namespace `file`, made with the release key |

Before anything is packaged the workflow builds with `--locked`, runs the
Rust tests under ptrace on each architecture, the verifier tamper suite and
`ci/run.sh` (clean runs and the bypass corpus in both modes), and runs
`cargo audit --deny warnings` against the RustSec database. Any advisory
fails the release. An advisory with no upgrade available has to be ignored
by id in the workflow *and* get a statement in `vex.openvex.json` saying
why the binary is or is not affected; the two are meant to be read
together.

At v0.1.2 the audit found no advisory for any of the 70 locked crates, so
`vex.openvex.json` is a valid OpenVEX document with an empty `statements`
list; its `tooling` field says so.

The archives are built with fixed ordering, ownership and mtime (the
commit's timestamp), so rebuilding the same commit on the same toolchain
gives the same bytes.

## Verify a release

You need `ssh-keygen` (OpenSSH 8.2 or newer) and `sha256sum` (`shasum -a
256` on macOS). The trust anchor is `allowed_signers` in this repository,
so verify from a clone of the repository, not from a copy of the file that
came with the download.

```
git clone https://github.com/YusefSyed/effect-tracer
cd effect-tracer
mkdir release
# the assets you want, plus the manifest and its signature; for example:
V=v0.1.2
for f in MANIFEST.txt MANIFEST.txt.sig effect-tracer-$V-x86_64-unknown-linux-gnu.tar.gz; do
  curl -fsSLo release/$f https://github.com/YusefSyed/effect-tracer/releases/download/$V/$f
done
# (or: gh release download $V -D release)

# 1. the manifest is signed by the release key
ssh-keygen -Y verify -f allowed_signers -I effect-tracer-release -n file \
  -s release/MANIFEST.txt.sig < release/MANIFEST.txt
# -> Good "file" signature for effect-tracer-release with ED25519 key SHA256:hxiDDsLKUbG2BO4GePgzO/+xwPshP++WE3rw0QNelsc

# 2. every file you downloaded matches the manifest
(cd release && sha256sum --ignore-missing -c MANIFEST.txt)
# -> one "OK" line per file present; `--ignore-missing` skips assets you did not download
```

If step 1 says anything other than `Good "file" signature`, or step 2
prints `FAILED`, do not run the binary.

Release key fingerprint: `SHA256:hxiDDsLKUbG2BO4GePgzO/+xwPshP++WE3rw0QNelsc`
(Ed25519). The same key is in `release-signing-key.pub`. If the key is
ever rotated, the new public key is added as a second line of
`allowed_signers` and the old line stays, so older releases keep
verifying.

The signature covers the manifest, and the manifest covers the SBOMs, the
VEX document and the verifier script as well as the binaries, so the same
two commands tell you those were not altered either.

## Cutting a release

1. Bump `version` in `Cargo.toml` and the `effect-tracer` entry in
   `Cargo.lock`, add a dated section `## X.Y.Z (Mon D)` to `CHANGELOG.md`
   (the workflow copies that section into the release notes), update the
   changelog list and the install pin in `README.md`, and revisit
   `vex.openvex.json`: bump its `version`, refresh `timestamp`, and add or
   retire statements to match the current `cargo audit` output.
2. Push the branch and run the workflow by hand (`gh workflow run release.yml
   --ref <branch>`). It must be green; download the `release-vX.Y.Z`
   artifact and run the two verify commands above against it.
3. Merge to `main`, then tag and push the tag:

   ```
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

   The tag run creates a **draft** release with the assets and notes.
   Read the release page, then publish it (`gh release edit vX.Y.Z
   --draft=false`).

## The signing key

The private key is an Ed25519 OpenSSH key held only in the repository
secret `RELEASE_SIGNING_KEY`; it never touches the checkout. The workflow
writes it to the runner's temporary directory with mode 0600, checks that
it matches the committed `release-signing-key.pub`, signs, and deletes it.
To rotate: generate a new key, replace the secret, replace
`release-signing-key.pub`, append (do not replace) the new line in
`allowed_signers`, and say so in `CHANGELOG.md`.
