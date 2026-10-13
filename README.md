# TartarOS

### NOTHING ESCAPES THE BOUNDARY.

**Secure Agent Runtime · Built in Rust.** The sandbox that confines AI coding
agents — and protects what the others leave open: the **trust-handoff set**.

Most agent sandboxes confine what the agent *does*. They do not protect the
files a trusted tool *outside* the box later runs, loads, or scans — git hooks,
`.claude/settings.json`, shell rc files, CI config. That gap is where the 2026
wave of agent sandbox escapes lived (Pillar Security "Trust Handoff Flaw", CSA,
CVE-2026-26268). TartarOS closes it, on macOS and Linux, with a policy you can
verify — and adds process, resource and network confinement that holds **even
when the agent runs as root**.

> Status: **early but real** (`v0.1.0-alpha`). This repo is the open enforcement
> layer: the policy model and the OS backends. A separate policy engine and
> multi-agent orchestration build on top of it, and intent analysis is a
> separate concern — both consume this layer rather than being part of it.

## What makes it different (measured, not claimed)

Reproducible with [`security-bench/`](security-bench/). Measured on a Linux host
(Linux 6.8) and macOS 15.7, 2026-10-13. The genuine differentiators versus the
measured competitors (Codex `0.162.1`, nono, `@anthropic-ai/sandbox-runtime`):

- **Trust-handoff protected at *any* depth, path-based** — a nested `.git/hooks`
  or `.claude/settings.json` is non-writable however deep, and an ancestor rename
  cannot relocate it out from under its deny. Discovery walks to a bounded depth;
  anything deeper is denied wholesale (fail-safe), so a handoff path is never left
  writable just by being far down. The nearest comparison,
  sandbox-runtime, path-protects nested hooks on Linux only up to a depth cap
  (default 3); nono uses cryptographic attestation rather than path protection.
- **Deny-inside-allow on Linux** — expressed as a carved Landlock allow-list.
  nono cannot even express this policy (it refuses to start).
- **The sandbox protects its *own* config by default** — the trust-handoff set
  includes the files a trusted tool would re-read; we do not leave our own
  settings writable for the agent to poison.

The rest of the hardening below (root-proof cgroup caps, `cgroup.kill` teardown,
`--isolate-pids`, `--isolate-net`, `--seccomp-strict`) is strong but **not**
claimed as unique: nono and sandbox-runtime close network egress and process
caps by their own means (seccomp socket-family / network-namespace; cgroup
`pids.max`). We do **not** claim "more secure than X in every scenario," and we
do not sell a competitor's default or scope choice as a vulnerability.

## Capabilities

| dimension | Linux | macOS |
|---|---|---|
| FS writes + trust-handoff (nested `.git`, ancestor rename) | ✅ | ✅ |
| FS reads of on-disk secrets (`~/.ssh`, `~/.aws`, `.env`) | ✅ carved read grant | ✅ `(deny file-read*)` |
| Network: default-deny + per-port (TCP) | ✅ Landlock (ABI v4+, port-based) | ✅ |
| Network: complete off, all protocols (`--isolate-net`) | ✅ empty netns (TCP/UDP/ICMP/raw) | ❌ |
| Secret broker (capability, not raw token) | ✅ HTTP+HTTPS, client auth, TTL+quota, host allow-list | ✅ |
| Resource: memory / processes / CPU | ✅ RLIMIT + cgroup (`memory.max`, `pids.max`), root-proof | 🟡 RLIMIT only |
| Lifecycle: timeout + reliable teardown | ✅ `cgroup.kill` (reaps escaped daemons) | 🟡 `kill(-pgid)` best-effort |
| Process isolation (`--isolate-pids`) | ✅ PID + mount namespace | ❌ (no primitive) |
| First-hand effect log (collectors, record modes) | ✅ | ✅ |

**Conformance:** 21/21 security scenarios pass on Linux (a Linux host (kernel 6.8)), 0
violations; macOS (Seatbelt) passes the cross-platform subset. The suite also
runs a mutation mode (`--mutate`) that proves it would catch a removed
protection, and marks scenarios UNSUPPORTED on a host that lacks a required
capability rather than silently passing.

## Honest limits

- **macOS teardown is best-effort.** A daemon that calls `setsid()` leaves the
  process group and `kill(-pgid)` misses it; macOS has no `cgroup.kill` or job
  object to match Linux's guarantee. Use Linux for strict teardown.
- **macOS cross-process environment read:** re-measured on macOS 15.7 (Darwin
  24.6) with a validated direct `KERN_PROCARGS2` probe — another same-user
  process's environment is **not** exposed (the OS returns only the executable
  path; a process reads the full environment only for itself). It does not
  reproduce on current macOS. A targeted `(deny sysctl-read (sysctl-name
  "kern.procargs2"))` remains available as defense-in-depth for older macOS.
- **Resource caps on a cgroup-less host degrade to RLIMIT** (bypassable by root)
  and TartarOS warns on stderr rather than pretending to confine.

## CLI

```
tartaros run \
  --write ./repo --read-deny ~/.ssh \
  --port 8080 --isolate-pids \
  --max-procs 256 --max-mem 2147483648 --max-cpu 600 \
  --timeout 600 --log effects.jsonl -- <cmd>
```

### Threat-model profiles

`--profile` selects a named tier instead of hand-picking flags — and states
honestly what it does and does not guarantee:

| profile | adds | guarantee |
|---|---|---|
| `local-agent` | trust-handoff + network-deny (default) | confines a trusted-but-fallible agent's mistakes |
| `hostile-code` | + PID/mount isolation, AF_UNIX lockdown | confines actively-malicious code on a **shared kernel** (a kernel LPE still crosses it) |
| `multi-tenant` | + egress-free network namespace | **kernel isolation NOT provided** — shared kernel; real tenant separation needs a microVM backend (not yet built). Maximum single-kernel hardening only. |

A profile only tightens; explicit flags still extend it, and its caveat is
printed on `run` and in `explain`. TartarOS never claims multi-tenant isolation
from Landlock/Seatbelt alone.

`tartaros explain [options]` prints exactly what a policy grants without running
anything, so a security team can audit a profile before deploying it. A policy
can also be declared once in a TOML file and applied with `--config`. See
[`cli/README.md`](cli/README.md).

## Architecture

Two layers — the walls (this repo) and intent analysis
(a separate intent-analysis layer) — both reading from the
kernel, outside the agent. Full picture in [`ARCHITECTURE.md`](ARCHITECTURE.md).

```
          your policy  ─────────────┐
                                     ▼
      ┌───────────────────────────────────────────┐
      │  tartaros-core                              │
      │  Backend trait · Policy · trust-handoff set │
      └───────────────┬───────────────┬────────────┘
                      ▼               ▼
            backends/macos     backends/linux
            Seatbelt           Landlock + seccomp + cgroup v2 + namespaces
```

The differentiator (`core/`) is new code. The backends reuse proven,
permissively-licensed plumbing; see `THIRD_PARTY_NOTICES.md`.

## Conformance

Reproducible scenarios (attack + legitimate control + real-effect assertion)
live in [`security-bench/`](security-bench/) — run them against the OS backend
for a PASS/VIOLATION scorecard that exits non-zero on any failure.

## Build & install

```
cargo build --release -p tartaros-cli            # target/release/tartaros
tartaros version                                 # version + active backend
tartaros help                                    # full usage
```

For a dependency-free drop-in (distroless / minimal containers), build a fully
static Linux binary — no glibc version to match:

```
rustup target add x86_64-unknown-linux-musl
cargo build --release -p tartaros-cli --target x86_64-unknown-linux-musl
# -> static-pie, ldd reports "not a dynamic executable"
```

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
Reused third-party code is attributed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
