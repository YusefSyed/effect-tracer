# Security policy

effect-tracer is a recorder, not a sandbox: it writes down what a process tree
did and signs the record. A bug that lets an effect go unrecorded while the
ledger still says `coverage: complete`, or that lets a modified ledger pass
`verify_ledger.py`, is a security bug.

## Reporting

Use GitHub's private vulnerability reporting on this repository
(Security tab, "Report a vulnerability"), or email yusef.syed@mail.utoronto.ca
with "effect-tracer" in the subject. Please include the kernel version, the
tracer mode (`full` or `seccomp`), a command that reproduces it, and the ledger
directory if you can share it.

You will get an acknowledgement within 7 days. Fixes ship as a tagged release
with a changelog entry that credits the reporter unless they ask otherwise.
Coordinated disclosure of 90 days from the report is the default; earlier if a
fix is out sooner.

## Scope

In scope: the tracer binary, the seccomp filter, the ledger format and the
Python verifier. Out of scope: the known limits listed in the README (mmap
stores, mount namespaces, inbound connections, fd passing, xattrs, DNS over
TCP), which the ledger already reports as `coverage.gap` where it can see them.
