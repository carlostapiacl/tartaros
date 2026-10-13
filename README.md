# seisin-sandbox

**The agent sandbox that protects what the others leave open: the trust-handoff set.**

Most agent sandboxes confine what the agent *does*. They do not protect the
files a trusted tool *outside* the box later runs, loads, or scans — git hooks,
`.claude/settings.json`, shell rc files, CI config. That gap is where the 2026
wave of agent sandbox escapes lived (Pillar Security "Trust Handoff Flaw", CSA,
CVE-2026-26268). seisin-sandbox closes it, on macOS and Linux, with a policy you
can verify.

> Status: **early.** This repo is the open plumbing layer that
> [seisin](../seisin) builds on. The policy engine and multi-agent orchestration
> that make it a product live in seisin itself.

## What makes it different (measured, not claimed)

Run the benchmark in [`bench/`](bench/) and you can reproduce these. Against
Codex `0.162.1`, nono `0.79`, and `@anthropic-ai/sandbox-runtime` (measured
2026-10-13, macOS 15.7.9 + Linux 6.8):

- **Nested `.git/hooks` protected at any depth**, not just the first level — the
  others leave a nested repo's hooks writable, so a planted hook runs outside the
  box on the next `git commit`.
- **Deny survives an ancestor rename** — renaming a parent directory must not
  relocate a protected path out from under its deny.
- **Deny-inside-allow enforced on Linux** — a nested `.git/hooks` is not
  writable and its ancestor cannot be renamed, under Landlock, via a carved
  allow-list. nono cannot even express this policy (it refuses to start);
  measured on the Linux test host (kernel 6.8).
- **Clean process lifecycle** — correct exit status on signal death.

We do **not** claim "more secure than X in every scenario." The claim is the
narrow, measured one above.

### What is done, and what is not

seisin-sandbox today is **the filesystem write / trust-handoff core** — the
differentiator — on macOS and Linux. The other dimensions a complete sandbox
needs are not built yet:

| dimension | status |
|---|---|
| FS writes + trust-handoff (nested `.git`, ancestor rename) | **done, measured** (both OS) |
| FS reads of on-disk secrets (`~/.ssh`, `~/.aws`, `.env`) | **done**: `Policy::read_denies` carves secret dirs out of the read grant (Linux live-verified on the Linux test host: ~/.ssh unreadable, rest readable); macOS via `(deny file-read*)` |
| Network confinement | macOS: default-denied + per-port `local_ports` (live-verified). **Linux: per-port via Landlock (ABI v4+, live-verified on the Linux test host; port-based not host-based)** |
| Secret broker (capability instead of raw token) | **prototype, live-verified (the Linux test host)**: HTTP gateway injects the secret; and an HTTPS **capability endpoint** (agent speaks plain HTTP to the broker, broker does the TLS) — real APIs, no MITM; direct egress blocked |
| Cross-process env read (another process's secrets) | macOS: platform limit (see below). **Linux: not closed yet** — we grant broad read, so `/proc/<pid>/environ` is readable; closing it means restricting reads or a PID namespace |
| Process lifecycle beyond exit code (timeouts, reaping) | **minimal** |

### Honest limits

- **macOS environment disclosure is a platform limit, not something any Seatbelt
  profile fixes.** We measured (2026-10-13) that `KERN_PROCARGS2` reads of another
  process's environment still succeed under our profile with no `kern.proc.*`
  allow and `process-info` restricted to self — so Seatbelt does not mediate it
  at all. Codex, nono and sandbox-runtime leak it the same way. seisin's
  mitigation is operational: run each agent under its own macOS user (so the
  syscall's same-user limit blocks it), which the policy layer orchestrates.
  Linux closes it in the backend via the PID namespace.

## Architecture

Two layers — the walls (this repo) and intent analysis (a separate intent-analysis layer) — both reading from the kernel, outside the agent. Full picture and diagram in [`ARCHITECTURE.md`](ARCHITECTURE.md).

```
          your policy  ─────────────┐
                                     ▼
      ┌───────────────────────────────────────────┐
      │  seisin-sandbox-core                       │
      │  Backend trait · Policy · trust-handoff set │
      └───────────────┬───────────────┬────────────┘
                      ▼               ▼
            backends/macos     backends/linux   (+ srt adapter)
            Seatbelt           Landlock [+bwrap]
```

The differentiator (`core/`) is new code. The backends reuse proven,
permissively-licensed plumbing; see `THIRD_PARTY_NOTICES.md`.

## Conformance

Reproducible security scenarios (attack + legitimate control + real-effect assertion) live in [`security-bench/`](security-bench/) — run them against the OS backend to get a scorecard. macOS 5/5, Linux 6/6, 0 violations (2026-10-13).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
Reused third-party code is attributed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
