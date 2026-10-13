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

> Status: **early but real.** This repo is the open enforcement layer that
> [seisin](../seisin) builds on. The policy engine and multi-agent
> orchestration that make it a product live in seisin itself; intent analysis
> lives in a separate intent-analysis layer.

## What makes it different (measured, not claimed)

Reproducible with [`security-bench/`](security-bench/). Measured on the Linux test host
(Linux 6.8) and macOS 15.7, 2026-10-13. Against Codex `0.162.1`, nono `0.79`,
`@anthropic-ai/sandbox-runtime`:

- **Trust-handoff protected at any depth** — a nested `.git/hooks` is not
  writable, and renaming an ancestor cannot relocate a protected path out from
  under its deny. The others leave nested hooks writable.
- **Deny-inside-allow on Linux** — expressed as a carved Landlock allow-list.
  nono cannot even express this policy (it refuses to start).
- **Root-proof resource caps** — a fork bomb, a memory balloon or a CPU spin is
  contained even as root: processes via a cgroup v2 `pids.max` (the kernel
  rejects the fork, not RLIMIT), memory via `memory.max`, CPU via RLIMIT_CPU.
- **Nothing outlives the box** — on timeout or exit the whole run is torn down
  with `cgroup.kill`, which reaps even a daemon that double-forked and `setsid`'d
  out of the process group.
- **The agent cannot see the host** (`--isolate-pids`) — a private PID + mount
  namespace: it sees only its own subtree (host 293 → 4 pids), cannot enumerate,
  inspect or signal host processes.

We do **not** claim "more secure than X in every scenario." The claims are the
narrow, measured ones above, and the honest limits are listed below.

## Capabilities

| dimension | Linux | macOS |
|---|---|---|
| FS writes + trust-handoff (nested `.git`, ancestor rename) | ✅ | ✅ |
| FS reads of on-disk secrets (`~/.ssh`, `~/.aws`, `.env`) | ✅ carved read grant | ✅ `(deny file-read*)` |
| Network: default-deny + per-port | ✅ Landlock (ABI v4+, port-based) | ✅ |
| Secret broker (capability, not raw token) | ✅ HTTP + HTTPS capability endpoint, client auth | ✅ |
| Resource: memory / processes / CPU | ✅ RLIMIT + cgroup (`memory.max`, `pids.max`), root-proof | 🟡 RLIMIT only |
| Lifecycle: timeout + reliable teardown | ✅ `cgroup.kill` (reaps escaped daemons) | 🟡 `kill(-pgid)` best-effort |
| Process isolation (`--isolate-pids`) | ✅ PID + mount namespace | ❌ (no primitive) |
| First-hand effect log (collectors, record modes) | ✅ | ✅ |

**Conformance:** 17/17 security scenarios pass on Linux (the Linux test host), 0 violations.
macOS runs the cross-platform subset.

## Honest limits

- **macOS teardown is best-effort.** A daemon that calls `setsid()` leaves the
  process group and `kill(-pgid)` misses it; macOS has no `cgroup.kill` or job
  object to match Linux's guarantee. Use Linux for strict teardown.
- **macOS environment disclosure is a platform limit.** `KERN_PROCARGS2` reads of
  another process's environment succeed under Seatbelt (Codex, nono and
  sandbox-runtime leak it the same way); mitigation is operational — one macOS
  user per agent. (A targeted `(deny sysctl-read (sysctl-name "kern.procargs2"))`
  is under evaluation.)
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

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
Reused third-party code is attributed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
