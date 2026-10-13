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
- **No cross-process environment disclosure (Linux)** — a confined process
  cannot read another process's environment, via the PID namespace.
- **Clean process lifecycle** — correct exit status on signal death, a single
  SIGINT, descendants reaped.

We do **not** claim "more secure than X in every scenario." The claim is the
narrow, measured one above.

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

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
Reused third-party code is attributed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
