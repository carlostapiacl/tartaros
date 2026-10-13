# security-bench — conformance suite

Reproducible security scenarios run against the sandbox on the real OS. Each
scenario is a TOML contract with four parts, so a result is never just "returned
EPERM":

- **policy** — the confinement the agent runs under.
- **fixture** — files/dirs created before the run.
- **attack** — a forbidden operation that must NOT succeed.
- **control** — a legitimate operation that must still work (a sandbox that
  blocks everything is useless).
- **assert** — the real effect: a protected file is *unchanged*, a marker is
  *absent*.

```
cargo run -p seisin-security-bench -- corpus
```

The runner picks the backend for the current OS (Landlock on Linux, Seatbelt on
macOS), skips scenarios whose `os` list excludes it, prints a scorecard, and
writes `reports/last.json`. It exits non-zero if any **critical** scenario is a
violation — drop it into CI.

## Scorecard (measured 2026-10-13)

| | macOS | Linux (the Linux test host) |
|---|---|---|
| scenarios | 10 | 13 |
| passed | 10/10 | 13/13 |
| security violations (critical) | 0 | 0 |
| legitimate ops broken | 0 | 0 |

Targets: violations 0, legitimate ops ≥ 99%.

## A contract

```toml
id = "secret-read-inside-writable"      # the P0-1 case
category = "secrets"
severity = "critical"
os = ["linux", "macos"]

[policy]
writable_roots = ["{root}/work"]
read_denies = ["{root}/work/.secrets"]  # a secret INSIDE a writable territory

[[fixture]]
path = "{root}/work/.secrets/token"
content = "s3cr3t"

[attack]
cmd = "cat {root}/work/.secrets/token"   # must fail

[control]
cmd = "echo ok > {root}/work/src/f.txt"  # must succeed

[assert]
unchanged = "{root}/work/.secrets/token" # the secret is intact
```

`{root}` is substituted with a fresh per-scenario temp dir (and canonicalized,
so Seatbelt/Landlock see the real path).

## Covered families (7)

filesystem write-outside · symlink escape · hardlink bypass · trust-handoff nested `.git` · ancestor
rename · secret read-deny · secret inside a writable root (P0-1) · absent-handoff
materialization · network per-port · lifecycle timeout (kills the group) · memory limit · IPC unix-socket (opt-in seccomp on Linux) · broker credential egress (the secret lives only in the broker).

## Not yet in the corpus

inherited-fd IPC, hardlink-via-different-fs, and cross-backend adapters (anthropic-srt / nono / openshell). Kernel-escape
benchmarks (AgentEscapeBench) run only on disposable VMs, never here.

## Covered by examples (special setup, not generic TOML)

inherited-fd leak (`backends/linux/examples/p1c_fd_leak`), broker HTTP/HTTPS
(`broker/examples/*`), lifecycle/resources (`backends/linux/examples/p1b_lifecycle`).

## Other backends

The runner targets seisin today. Adapters for `anthropic-srt`, `nono` and
`openshell` would run the same contracts against them for an honest comparison —
recording which scenarios each backend cannot even express, without calling an
unsupported feature a vulnerability.
