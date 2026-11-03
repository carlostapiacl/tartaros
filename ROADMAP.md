# Roadmap

What comes next, and why it matters to the person running the agent. Each item
lands in [`CHANGELOG.md`](CHANGELOG.md) together with a corpus scenario that proves
it. The rule doesn't change: a capability ships with its test, or it doesn't ship.

## Now — next release

- [ ] **Linux without user namespaces.** *The same protection on a stock
      Ubuntu.* Ubuntu 23.10 and later restrict unprivileged user namespaces by
      default, so tartaros falls back to the Landlock carve there. Measured as a
      non-root user on such a host: 2 corpus attacks get through (an ancestor
      rename around a read deny inside a root, an absent top-level `.mcp.json`)
      and 8 legitimate controls break. Closing those two with the carve alone
      withholds whole roots and breaks more controls, so the next step needs
      another mechanism; until then they are in
      [`docs/limits.md`](docs/limits.md) with their workarounds.
- [ ] **Measured toolchain compatibility.** *A sandbox that doesn't break my
      tools.* A `compat` corpus that runs real tools confined on both OS and
      publishes the result: Go binaries using macOS TLS (`gh`, `terraform`),
      `git` over SSH, Playwright/Chromium, interactive TUIs, `java`/`dotnet`
      builds, package-manager caches, git worktrees, and Claude Code / Codex on
      Linux (Claude Code on macOS is already measured). Each tool gets a pass/fail
      row and the exact grant it needs.
- [ ] **Denial attribution on Linux at run time.** *Tell me what was blocked
      and why, as it happens.* `tartaros why` already answers from the policy on
      every backend. Next is tagging each real denial in the effect log with its
      rule, as macOS does: Landlock audit records on kernels that have them, an
      EPERM-correlating probe on older ones.
- [ ] **Disk quota for writable roots.** *An agent shouldn't be able to fill my
      disk.* A size cap per writable root (a size-limited tmpfs or loop mount,
      or project quotas where the filesystem supports them).

## Next

- [ ] **microVM backend, phase 2 (Firecracker).** *A real VM, not a shared
      kernel.* Phase 1 is validated: the policy compiles to an OCI bundle and the
      corpus passes 20/20 under gVisor (`runsc`). Phase 2 adds a guest kernel and
      rootfs, virtio-fs shares, the egress broker over vsock, and VM-size resource
      caps. See [`docs/microvm-backend.md`](docs/microvm-backend.md).
- [ ] **Path-scoped unix sockets on Linux.** `network.allowUnixSockets` with
      paths works on macOS; Linux refuses the policy (exit 78) because its
      seccomp filter for `AF_UNIX` is all or nothing. Use Landlock's unix-socket
      right where the kernel has it, keep refusing where it doesn't, and have
      `explain` and `why` say which case applies.
- [ ] **Learn mode.** *Don't make me write the policy by hand.* Run once in
      observe mode, collect what the agent touched from the effect log, and
      propose the smallest policy that would have allowed it.
- [ ] **Windows, native (not WSL): what's left.** *The same sandbox on every
      machine.* `tartaros run` already dispatches to the native backend, and
      egress goes through the broker (see [`docs/limits.md`](docs/limits.md)).
      Still missing: effect-log collectors, so `--log` records on Windows, and
      HTTPS through Schannel under the `sandbox-user` tier, which Windows refuses
      to the restricted token today.
- [ ] **Not-yet-existing handoff paths under the bind-mount strategy (Linux).**
      Protect a `.claude/settings.json` or a nested repo's hooks that the agent
      creates during the run, without placeholder residue in the working tree.
- [ ] **Create-at-root on hosts with no user namespaces at all.** An
      install-time AppArmor profile or a minimal packaged helper.
- [ ] **More trust-handoff paths.** Shell rc files, editor task files
      (`.vscode/tasks.json`), virtualenv interpreters, `git` fsmonitor, and CI
      configuration beyond `.github/workflows`.
- [ ] **Strict teardown on macOS.** Reap daemons that leave the process group
      (`setsid`) the way `cgroup.kill` does on Linux.

## Later

- [ ] **Policy as capabilities, not paths.** Evolve `Policy` from paths toward
      named capabilities (a repo, a registry, an API) that compile per backend.
- [ ] **Landlock ABI probe** (best of V1–V6) instead of a fixed ABI, with
      `Refer`/`Truncate` hardening where the kernel offers it.
- [ ] **More cross-sandbox comparisons.** OpenShell, and the sandbox-runtime
      column of `comparison/compare.sh` running in CI.

## Shipped

Signed releases, workspace snapshots with rollback (`run --snapshot`,
`tartaros rollback`) and `tartaros why` shipped in 0.1.0-alpha.18. An SBOM
with each binary, `--mutate` coverage for trust-handoff, and
chmod/chown/utimes/xattrs held outside the roots on Linux without namespaces
shipped in 0.1.0-alpha.19. The details are in the [changelog](CHANGELOG.md).

## How to help

The fastest way in is a **new corpus scenario**: one TOML file with an attack, a
legitimate control, and an assertion on the real effect. A scenario that fails
today is the best bug report there is. See [`security-bench/`](security-bench/).
Results from other kernels and distros are just as welcome.

The full history of what was built, measured and corrected along the way is in
[`docs/journal/2026-10-development-log.md`](docs/journal/2026-10-development-log.md).
