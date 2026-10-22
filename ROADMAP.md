# Roadmap

What comes next, and why it matters to the person running the agent. Each item
lands in [`CHANGELOG.md`](CHANGELOG.md) together with a corpus scenario that proves
it. The rule doesn't change: a capability ships with its test, or it doesn't ship.

## Now — next release

- [ ] **Measured toolchain compatibility.** *A sandbox that doesn't break my
      tools.* A `compat` corpus that runs real tools confined on both OS and
      publishes the result: Go binaries using macOS TLS (`gh`, `terraform`),
      `git` over SSH, Playwright/Chromium, interactive TUIs, `java`/`dotnet`
      builds, package-manager caches, git worktrees, and Claude Code / Codex on
      Linux (Claude Code on macOS is already measured). Each tool gets a pass/fail
      row and the exact grant it needs.
- [ ] **"Which rule denied me" on Linux.** *Tell me what was blocked and why.*
      macOS already tags every denial with its rule. Linux: Landlock audit
      records on kernels that have them, an EPERM-correlating probe on older ones,
      and `tartaros why` to print the rule behind a denial.
- [ ] **Disk quota for writable roots.** *An agent shouldn't be able to fill my
      disk.* A size cap per writable root (a size-limited tmpfs or loop mount,
      or project quotas where the filesystem supports them).
- [ ] **Mutation coverage for trust-handoff.** `--mutate` already proves the
      corpus catches a removed read-deny, network, namespace, resource or env-scrub
      protection. Add the same proof for the trust-handoff set, so removing it
      must flip every `trust-handoff-*` scenario.
- [ ] **Signed releases.** Prebuilt binaries for macOS and Linux (static musl),
      with checksums, signatures and an SBOM.

## Next

- [ ] **microVM backend, phase 2 (Firecracker).** *A real VM, not a shared
      kernel.* Phase 1 is validated: the policy compiles to an OCI bundle and the
      corpus passes 20/20 under gVisor (`runsc`). Phase 2 adds a guest kernel and
      rootfs, virtio-fs shares, the egress broker over vsock, and VM-size resource
      caps. See [`docs/microvm-backend.md`](docs/microvm-backend.md).
- [ ] **Workspace checkpoints and rollback.** *Let me undo what the agent did.*
      Snapshot the writable roots before a run and restore them in one command
      (overlay upper-dir on Linux, APFS clone on macOS).
- [ ] **Learn mode.** *Don't make me write the policy by hand.* Run once in
      observe mode, collect what the agent touched from the effect log, and
      propose the smallest policy that would have allowed it.
- [ ] **Windows, native (not WSL) — wire `tartaros run`.** *The same sandbox on
      every machine.* The backend exists and is held to the corpus (AppContainer
      and a dedicated-user tier with a write-restricted runner; see
      [`docs/limits.md`](docs/limits.md)); next is dispatching `tartaros run` to it
      on Windows, Windows effect-log collectors, and an egress broker channel.
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

## How to help

The fastest way in is a **new corpus scenario**: one TOML file with an attack, a
legitimate control, and an assertion on the real effect. A scenario that fails
today is the best bug report there is. See [`security-bench/`](security-bench/).
Results from other kernels and distros are just as welcome.

The full history of what was built, measured and corrected along the way is in
[`docs/journal/2026-10-development-log.md`](docs/journal/2026-10-development-log.md).
