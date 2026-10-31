# The ledger format (`effect-tracer-ledger/1`)

A run writes one directory:

| file | signed? | what |
|---|---|---|
| `events.jsonl` | yes, through the chain | one canonical JSON event per line; each line carries the leaf hash of the previous line in `prev` |
| `checkpoint.json` | is the signature | Ed25519 signature over the chain head, with the public key and its key id |
| `ledger.json` | no | a convenience summary (run identity, coverage, stats, limits); the verifier checks it against the chain |

## Canonical JSON

Every line of `events.jsonl` and the signed checkpoint body are canonical:
object keys sorted bytewise, no whitespace, integers only (no floats),
strings escaped as serde_json escapes them (`"`, `\`, control characters;
non-ASCII stays as UTF-8). Python reproduces the bytes with
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`,
which is how `verifier/verify_ledger.py` checks that each line is canonical.
Large values that could lose precision in JavaScript (nanosecond clocks) are
strings.

## The chain

```
leaf(line)  = SHA-256(0x00 || line_bytes_without_newline)      (RFC 9162 leaf hashing)
prev(1)     = 64 zero hex digits
prev(n)     = leaf(line n-1)
headHash    = leaf(last line)
```

Each event includes its own `prev`, so changing, removing, inserting or
reordering any line changes every later `prev` and the head. A tamperer who
recomputes the chain still cannot produce the signed head without the key.

## Events

```json
{"seq":7,"monoNs":"2297793295582","proc":{"pid":2169,"tid":2169,"ppid":2168,"execId":"796b48ab:2169:229708:1","parentExecId":"tracer","comm":"python3","exe":"/usr/bin/python3.11"},"kind":"file.write","name":"/work/out/f001.txt","outcome":"committed","detail":{"flags":["O_WRONLY","O_CREAT","O_TRUNC","O_CLOEXEC"],"syscall":"openat"},"prev":"7304…cdc"}
```

| field | meaning |
|---|---|
| `seq` | 1-based line number |
| `monoNs` | tracer's CLOCK_MONOTONIC at the event, nanoseconds, as a string |
| `proc` | the task that did it: `pid` (thread group), `tid`, `ppid`, `execId` (`bootid8:pid:starttime:execgen`), `parentExecId`, `comm`, `exe` |
| `kind` | see the table below |
| `name` | the object: an absolute path, `tcp:host:port`, `udp:host:port`, `unix:/path`, a DNS name, an exe path, a syscall name |
| `outcome` | `committed` (the kernel accepted it), `denied` (EPERM or EACCES), `failed` (any other error, `detail.errno` says which) |
| `detail` | per-kind extras: `syscall`, `flags`, `from`, `via`, `errno`, `qtype`, `argvSha256` or `argv`, `childPid`, `exitCode`, `reason` |
| `prev` | leaf hash of the previous line |

| kind | emitted on |
|---|---|
| `file.write` | open with write intent (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`), `truncate`, `ftruncate`, `sendfile`, `copy_file_range`, `splice` into a file |
| `file.create` | `O_TMPFILE` or `O_CREAT|O_EXCL` opens, `mkdir`, `mknod`, `memfd_create` (`memfd:<name>`) |
| `file.delete` | `unlink`, `unlinkat`, `rmdir` |
| `file.rename` | `rename*`; `name` is the new path, `detail.from` the old |
| `file.link` | `link*` (hard), `symlink*` (`detail.symlink`, `detail.target`) |
| `file.meta` | `chmod*`, `chown*`, `utimensat` |
| `file.map-write` | `mmap` with `PROT_WRITE` and `MAP_SHARED` on a file |
| `file.read` | read-only opens, only with `--trace-reads` |
| `socket.connect` | `connect`; a non-blocking connect returning EINPROGRESS counts as committed |
| `socket.bind`, `socket.listen` | `bind`, `listen` |
| `socket.send` | `sendto`/`sendmsg`/`sendmmsg` with an explicit destination, or `sendfile`/`splice` into a socket |
| `dns.query` | a parsed DNS question sent over UDP to port 53 or a `--dns-port`; `name` is the QNAME |
| `socket.netlink` | `socket(AF_NETLINK, SOCK_RAW, proto)`; `name` is the netlink family (`route` for `NETLINK_ROUTE`, which glibc's `getaddrinfo` opens to list interfaces); `detail.protocol` is the number |
| `process.exec` | `PTRACE_EVENT_EXEC` (argv digested unless `--clear-argv`); failed `execve` calls appear with `outcome: failed` |
| `process.fork` | `PTRACE_EVENT_FORK/VFORK/CLONE`; threads carry `detail.thread: true` |
| `process.exit` | `PTRACE_EVENT_EXIT` of a thread-group leader |
| `coverage.gap` | something the tracer cannot see through: `io_uring_*` (denied), `process_vm_writev`, `ptrace`, `bpf`, mount-namespace calls, module loading, raw and packet sockets (netlink is `socket.netlink`, not a gap), foreign-ABI syscalls, internal read failures |
| `run.start`, `run.end` | the tracer's own bracketing events: identity, options, kernel; coverage, exit status, stats |

Coverage lives in `run.end`, inside the chain: `complete` when no gap was
committed and no internal error occurred, `partial` when something ran
unobserved (every reason is listed), `failed` when the tracer itself failed.
`PTRACE_O_EXITKILL` kills the whole tree if the tracer dies, so a tree never
continues unobserved; such a run has no `run.end` and no checkpoint.

## Checkpoint

```json
{"headHash":"…","keyid":"…","publicKey":"…","runId":"…","schema":"effect-tracer-checkpoint/1","signature":"…","signedAt":"2026-10-31T03:35:00Z","treeSize":356}
```

The signed message is the canonical JSON of `{headHash, runId, schema, signedAt, treeSize}`
(the checkpoint without `keyid`, `publicKey`, `signature`). The key id is the
SHA-256 of the SubjectPublicKeyInfo DER of the public key (RFC 8410:
`302a300506032b6570032100` followed by the 32 key bytes).

A fresh key is generated for each run unless `--key FILE` names a seed
written by `effect-tracer keygen`. An embedded key proves integrity since
signing, nothing about who signed. To know that, pin the key:
`verify_ledger.py DIR --pubkey HEX`.

## Trust boundary

The signature is the tracer's, and it is worth what the tracer's key is
worth:

| setup | the traced program can | so a verified, pinned ledger proves |
|---|---|---|
| per-run key, no pin | nothing that survives the run | the files were not changed after the tracer signed; not who signed |
| `--key FILE`, tree runs as the same user | read the seed file (a read-only open, not recorded without `--trace-reads`) and later sign a forged ledger | nothing about the program's own honesty |
| `--key FILE` owned by root with mode 0600, tracer as root, `--run-as UID` | neither read the seed nor attach to the tracer | the ledger came from the tracer holding that key |

The tracer makes itself non-dumpable right after it forks the command
(`PR_SET_DUMPABLE 0`). A process of the same user without `CAP_SYS_PTRACE`
therefore cannot read the tracer's memory with `ptrace` or
`process_vm_readv`, where a per-run key lives. A tracee calling
`process_vm_readv` on anything is a `coverage.gap`. Verifying unpinned, as
the Action example does on its first run, checks the chain and the
signature's consistency only. Pin a key you control once you have one.

## Verification

`verifier/verify_ledger.py DIR [--pubkey HEX] [--json]` uses the Python
standard library only (its own RFC 8032 Ed25519 verification included) and
exits:

| code | meaning |
|---|---|
| 0 | chain intact, checkpoint valid, run finished, coverage complete |
| 1 | integrity failure: broken chain, non-canonical line, wrong head or size, bad signature, key pin mismatch, summary disagrees with the chain |
| 2 | unreadable or malformed input |
| 3 | chain and signature fine but the run is not complete: coverage partial or failed, or no checkpoint because the tracer did not finish |

`verifier/test_verify_ledger.py` holds the tamper suite (edit, delete,
insert, swap, truncate, non-canonical line, bad signature, a ledger an attacker
rewrote and re-signed with their own key (the test signs with RFC 8032;
only the pin catches it), summary mismatch, malformed line) against a real fixture.
