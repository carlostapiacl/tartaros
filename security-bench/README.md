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
cargo run -p tartaros-bench -- corpus
```

The runner picks the backend for the current OS (Landlock on Linux, Seatbelt on
macOS), skips scenarios whose `os` list excludes it, prints a scorecard, and
writes `reports/last.json`. It exits non-zero if any **critical** scenario is a
violation — drop it into CI.

The runner exits non-zero on any violation, broken control or infra error — a
green run means every scenario actually executed and passed.

## Mutation testing — a conformance that cannot fool itself

```
cargo run -p tartaros-bench -- corpus --mutate
```

Passing scenarios prove attacks are blocked — but not that the *suite* would
notice if a protection were removed. `--mutate` deliberately weakens the policy
one protection at a time (`drop-read-denies`, `grant-network`,
`drop-isolate-net`, `drop-isolate-pids`, `raise-proc-limit`, `raise-mem-limit`)
and re-runs every scenario that relies on it. Removing a protection **must** make
at least one attack succeed (flip to VIOLATION); a mutation that flips nothing is
a blind spot — the corpus never actually tested that enforcement — and the run
exits non-zero. The mutations weaken the policy the runner passes, never the
backend, so the real enforcement is exercised. Measured on the Linux test host: 0 blind spots.

## Scorecard (measured 2026-10-13, the Linux test host Linux 6.8)

| | Linux (the Linux test host) |
|---|---|
| scenarios | 18/18 pass |
| security violations (critical) | 0 |
| legitimate ops broken | 0 |
| mutation blind spots | 0 |

macOS runs the cross-platform subset. Targets: violations 0, blind spots 0,
legitimate ops ≥ 99%.

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

## Cross-backend comparison

A first honest comparison vs **nono 0.79** (fairly configured, measured on the Linux test host)
is in [`comparison/RESULTS.md`](comparison/RESULTS.md): parity on write-outside,
TartarOS's trust-handoff advantage on nested `.git/hooks`, and nono cannot express a
deny inside an allow on Linux. Includes a mid-measurement correction (a /tmp-default
false positive) — a difference in defaults is never sold as a vulnerability.
Reproduce with `comparison/nono-scenarios.sh` on a Landlock host (not the dev Mac).
srt and OpenShell comparisons pending.
