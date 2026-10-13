# Roadmap — tartaros

Principle: the policy is the product; backends reuse proven Apache-2.0 plumbing.
Build only where measurement shows no existing backend can enforce the policy.

## M0 — repo (done)
- [x] Apache-2.0 + NOTICE + THIRD_PARTY_NOTICES
- [x] `core`: Backend trait, Policy, trust-handoff set (design, compiles)
- [x] Codex Seatbelt generator vendored (verbatim, attributed)
- [x] backend stubs that fail-closed; `bench/` described

## M1 — macOS backend (first real code)
- [x] `Policy::trust_handoff_rules`: expands the set under each writable root at
      ANY depth (walks nested `.git`), denies top-level config even if absent,
      does not follow symlinks out of root — 3 unit tests
- [x] Seatbelt generator in `backends/macos` (own code, informed by vendored
      Codex profile), denies emitted last so they win, roots canonicalized
- [x] ancestor-rename protection applied to the whole trust-handoff set
- [x] no `kern.proc.*` sysctl allow emitted
- [x] live smoke (`examples/smoke.rs`) PASSES where Codex/nono failed: nested
      `.git/hooks` denied (direct + ancestor rename), hook does not run outside,
      control writes work, exit 143 on signal
- [x] measured the macOS env-leak: **platform limit, not profile-fixable.** Under
      our profile (no `kern.proc.*`, process-info self-only) KERN_PROCARGS2 still
      reads another process's env — Seatbelt does not mediate it. Documented in
      README "Honest limits"; mitigation is per-agent macOS user (policy layer).
- [x] integration tests (`tests/trust_handoff.rs`, macOS): 6 live checks green,
      including git running under the profile
- [ ] shell rc / CI-config handoff paths beyond `.github/workflows`

## M2 — Linux backend
- [x] `Policy::linux_write_allowlist`: **carves** the deny out of the allow
      (grant safe subtrees, exclude the protected branch) — makes expressible
      what nono refuses. Unit test with nested `.git`. The TartarOS Linux edge.
- [x] `validate` ACCEPTS deny-inside-allow by restructuring (nono rejects)
- [x] wired the Landlock ruleset from the allow-list (`landlock` 0.4.5), target-
      gated so macOS still builds; read+exec everywhere, write only in the carve;
      restrict_self in the child via pre_exec
- [x] **measured on the Linux test host (kernel 6.8, via Docker rust image): ALL PASS** —
      nested `.git/hooks` denied, `.git/objects` still writable, ancestor rename
      denied, control writes work, exit 143. The deny-in-allow that nono refuses.
      (Landlock syscalls work under Docker's default seccomp, Docker 29.)
- [ ] bwrap fallback for paths where direct-file-creation in an on-path dir
      matters, with Codex's flock mount registry (our report #4)
- [ ] ABI probe (V1..V6 best-of) instead of fixed V1; Refer/Truncate hardening

## M3 — integration + release
- [ ] `srt` adapter (wrap @anthropic-ai/sandbox-runtime)
- [ ] seisin consumes tartaros through the backend abstraction
- [ ] make the repo public

## M4 — the other dimensions (field-detected)
- [x] **effect-log framework** (`core::effect`): `EffectEvent` (axis/action/
      target/direction/outcome/source), `EffectSink`+`JsonlSink`, `Collector`
      trait; `core::catalog` classifies secrets and endpoints. Neutral JSONL
      format — not a dependency either way. Tests green.
- [x] **first collector**: `collect::NetworkCollector` — captures the process
      tree's outbound connects (port scans show as many outside events) from
      `/proc/net/tcp`; parser + classification unit-tested; live read Linux
- [x] collectors: `SecretCollector` (fd→secret), `ProcessCollector` (exfil-tool
      exec + foreign `/proc/<pid>/environ` read), `McpCollector` (ungranted MCP,
      v1 cmdline heuristic) — classifiers unit-tested; `proc` helpers shared
- [x] **secret read-deny**: `Policy::read_denies` + `linux_read_allowlist`
      (symmetric read carve) and macOS `(deny file-read*)`; Linux live-verified
      on the Linux test host (~/.ssh unreadable, /etc + /usr/bin readable). Secret dimension now
      complete: observe (collector) + deny-read + broker (capability)
- [ ] file-write event capture (enforced already; emit on deny)
- [x] **observed session live on the Linux test host**: `LandlockBackend::spawn` + `collect::
      observe_until_exit` drive the collectors while a confined agent runs; real
      effect log captured first-hand (secret read of ~/.ssh + curl exec), filtered
      by `RecordMode`. `NetworkCollector` now walks the process tree (child
      sockets attributed)
- [ ] macOS siblings (lsof for net, fd for secret) 
- [x] **ports per role**: `Policy::local_ports` opens only granted loopback
      ports (macOS live-verified: 8001 reachable, 8787 blocked); unit-tested.
      `NetworkCollector::for_policy` ties observation to the same territory
- [x] **logging modes**: `RecordMode` (Off/DeniedOnly/OutsideOnly/Boundary/All)
      + axis filter, via `FilterSink`; tested
- [x] **Linux per-port network enforcement** via Landlock `AccessNet`/`NetPort`
      (adopts nono #2080); live-verified on the Linux test host: granted 8001 connects, 8787 and
      external blocked. Honest limit: port-based not host-based (loopback vs
      external same port needs the proxy); needs kernel >= 6.7
- [ ] domain allow-list via proxy (external hosts beyond IP)
- [x] **secret reads**: read-deny of secret dirs — see M4 above (done, both OS)
- [x] **secret broker (the single gateway)**: `broker` crate — HTTP forward
      proxy injects the secret; agent reaches ONLY the broker port, authenticates
      upstream without ever holding the token, direct egress blocked. Live-
      verified end-to-end on the Linux test host; every forward logged as an effect.
- [x] **HTTPS via capability endpoint** (no MITM): agent speaks plain HTTP to the
      broker at `/<prefix>/…`, broker does the real HTTPS (`ureq`) and injects
      the secret. Live-verified on the Linux test host (reached https://example.com via broker;
      direct 443 blocked). The agent never does TLS nor holds the token
- [x] fix: Linux carve only excludes denies that EXIST (Landlock is inode-based;
      absent trust-handoff files are a macOS/Seatbelt strength, not Landlock's)
- [ ] **close the Linux env-leak**: restrict /proc or PID namespace
- [ ] **resources, not paths**: evolve `Policy` toward capabilities

## M5 — intent layer (the intent layer) on the effect log
- [ ] feed the intent layer from the effect log (allowed + denied)
- [ ] the missing core: infer goal + deviation per session (1 LLM call)

## Security findings (external review 2026-10-13)

- [x] **P0 read_denies neutralized by write rule** — a read-denied path inside a
      writable root was readable because write rules granted `all` (incl. read)
      and Landlock unions permissions. **Reproduced and fixed on the Linux test host**: write
      rules now grant write-only; read is governed solely by the read carve.
      Repro kept: `backends/linux/examples/p0_readdeny_in_writable`.
- [x] **P0 fail-closed on missing Landlock capabilities**: probes `landlock_fs_
      supported` / `landlock_net_supported` (HardRequirement) and refuses to run
      when FS confinement is absent, or when net is requested but unavailable.
      Verified: Docker/linuxkit (no Landlock) now refuses ("refusing to run
      unconfined"); the Linux test host (Landlock present) still runs and enforces.
- [x] **P1 broker client auth**: `Broker::with_auth(token)` requires
      `X-Tartaros-Auth: <token>` per run; a process without it gets 403. Verified
      on the Linux test host (with token 200, without 403). Destination/method scoping per
      capability remains to extend.
- [x] **P1 absent trust-handoff paths on Linux — MITIGATED (opt-in).**
      `Policy::materialize_absent_handoff` pre-creates empty read-only
      placeholders for absent top-level trust-handoff configs so Landlock (inode-
      based) carves them; the agent can no longer create e.g. `.claude/settings.
      json`. VERIFIED on the Linux test host (without: EVIL config created; with: blocked; normal
      writes in existing subdirs still work). Cost: new TOP-LEVEL entries in a
      root containing a protected path aren't creatable (inherent carve tradeoff).
- [x] **P1 /proc isolation / cross-process env read on Linux — MITIGATED.**
      Primary: the kernel already blocks it — with Yama `ptrace_scope=1` (Ubuntu
      default, confirmed on the Linux test host) an unrelated process's `/proc/<pid>/environ` is
      not readable (measured: leak blocked even with no sandbox rule). Defense-in-
      depth: `isolate_process_info` excludes `/proc` from the read grant (covers
      `ptrace_scope=0`); measured that sh/cat/ls/curl/git/python3 still run and the
      full suite (smoke/net/readdeny/P0) stays green. PID namespace stays out
      (`unshare` not portable under Docker).

## Security findings (external review #2, 2026-10-13)
- [x] **P0-A broker auth now mandatory by default**: `serve` fails closed without
      a token; `insecure_no_auth()` is an explicit test-only opt-in. Verified.
- [x] **P0-B capability restricts actions**: each `Capability` declares allowed
      `methods` (405 otherwise, no silent GET), redirects disabled, response
      capped (10 MB), path traversal (`..`) rejected. Verified on the Linux test host (POST→405).
- [x] **P1-A materialization hardened**: fails closed on any error, refuses a
      symlinked ancestor, creates with O_EXCL, verifies result. Verified (symlink
      rejected).
- [x] **P1-B process supervision**: own process group (`setpgid`), wall-clock
      `timeout` kills the group (exit 124), `setrlimit` for memory/processes/CPU,
      descendants reaped on exit. Verified on the Linux test host (timeout 2s, grandchild not
      alive, memory cap hit). cgroups v2 can extend this later.

## M6 — security-bench (conformance suite) — STARTED
- [x] runner: loads TOML contracts, runs attack + legitimate control under the
      OS backend, checks real-effect assertions, prints scorecard + reports/last.json,
      exits non-zero on a critical violation (CI-ready)
- [x] corpus v1 (10 scenarios): fs write-outside, symlink escape, nested .git hook,
      ancestor rename, secret read-deny, secret inside writable (P0-1), materialize
      absent handoff, network per-port, lifecycle timeout, memory limit. Runner
      extended with servers, timeout/rlimit policy, expect_exit, symlink fixtures.
      **macOS 7/7, Linux 10/10, 0 violations, 0 legitimate ops broken**
- [x] added: hardlink bypass, IPC unix-socket (opt-in seccomp `deny_unix_sockets`
      on Linux — found + fixed + verified; macOS blocks it natively)
- [x] added: broker credential-egress contract (secret only in the broker; direct
      egress blocked, via-broker works) — the Linux test host 13/13
- [x] **inherited-fd leak closed**: the Linux backend closes all non-stdio fds
      (`close_range`) just before exec — an fd the orchestrator left open no longer
      bypasses path-based confinement. Verified on the Linux test host (`p1c_fd_leak`: child can't
      read the inherited fd; smoke/net unaffected). **macOS too**: fds closed in
      sandbox-exec's pre_exec; verified (`fd_leak` PASS, tests green).
- [x] cross-backend comparison vs nono 0.79 (fair config, the Linux test host): parity on
      write-outside, trust-handoff advantage on nested .git, nono can't express
      deny-in-allow. `comparison/RESULTS.md` + reproducible script. Includes a
      /tmp-default false-positive correction (honest methodology).
- [x] comparison vs anthropic-srt 0.0.78 (a Linux host): PARITY on
      write-outside and .claude/settings.json — no srt disadvantage reproduced, none
      claimed (honest).
- [x] **automated competitor comparison** (`comparison/compare.sh`, review P2):
      runs the same scenarios under TartarOS (CLI) and nono, prints the table.
      Reproducible on the Linux test host; no commercial claim without a measured row.
- [x] SRT column added to compare.sh (activates when node+bwrap+srt present).
      TartarOS+nono path verified automated on the Linux test host; srt measured manually (parity).
- [ ] comparison vs OpenShell (NVIDIA); make the srt column run in CI env
- [ ] adapters for anthropic-srt / nono / openshell (honest comparison)

## Both-OS parity (loop)
- [x] FD-1 inherited-fd leak closed on macOS and Linux.
- [x] P1-B process supervision (timeout → kill group, setrlimit, reaping) now on
      macOS too (was Linux-only). Verified: macOS timeout 2s → exit 124, bench 11/11.

## M7 — CLI (adoptability)
- [x] `tartaros run [opts] -- cmd`: policy via flags, OS backend, exit code
      passthrough; `--log` emits the effect log of a real run (Linux). Verified on
      macOS (confines) and the Linux test host (confines + read-deny + effect log of ~/.ssh read).
- [x] **config file (TOML policy)**: `--config role.toml` — one policy declared
      once, applied equivalently on macOS and Linux (B2B P2). `~` expands to $HOME;
      flags override. Verified on both (control ok, secret read-deny rc=1).
- [x] **`explain` subcommand**: prints what a policy grants (role, roots,
      read-denies, trust-handoff set at any depth, the Seatbelt profile / Landlock
      allow-lists) without running — auditable "política verificable". Verified
      on macOS and Linux.
- [x] **macOS effect-log collectors complete**: network (lsof -i), secret (lsof),
      process (ps) — `--log` fully at parity on both OS. Verified on macOS: secret
      read of ~/.ssh and an out-of-territory connect both captured.
- [ ] per-role profile discovery; OpenShell comparison; cgroups v2

## Security findings (external review #3, 2026-10-13)
- [x] **P0 unified supervisor**: `--log` now runs through `run_observed`, which uses
      the SAME supervisor (timeout, limits, process-group reaping) as `run`. Enabling
      the log never changes the guarantees. Verified: timeout 2s -> exit 124 with AND
      without --log, on macOS and Linux.
- [x] **P1 bench CI gate**: fails on ANY violation, broken control, or INFRA_ERROR
      (invalid/unreadable contract), not just critical violations. Reports PASS/
      VIOLATION/CONTROL_BROKE/INFRA_ERROR/SKIPPED. Exit 0 only if all ran and passed.
- [x] **P1 macOS fd-close**: closes fds up to the real RLIMIT_NOFILE (not a fixed
      1024 cap), so high-numbered inherited fds are closed too.
- [x] **P1 observed vs guaranteed**: documented that the effect log is sampled
      (may miss short-lived events) while enforcement is guaranteed.

## CI
- [x] GitHub Actions workflow written (build + unit tests + integration + security-
      bench, Linux & macOS; Landlock auto-detected). Correct and committed.
- [ ] BLOCKED: Actions returns startup_failure on this account's private repos
      (account-level issue since 2026-10-12, not the YAML). Verify green once cleared,
      or mirror to a runner that works.

## Resource limits — measured finding (2026-10-13)
- `--max-mem` (RLIMIT_AS): enforced (verified — allocation past the cap fails).
- `--max-procs` (RLIMIT_NPROC): **best-effort only.** Measured on the Linux test host: running as
  root it did NOT contain a 150-fork storm — root/CAP_SYS_RESOURCE bypasses
  RLIMIT_NPROC. Confirms the review: setrlimit is insufficient for multi-tenant.
- [ ] **cgroups v2 (`pids.max`, `memory.max`)** for a guaranteed per-sandbox cap
      regardless of uid/caps — the real multi-tenant fix. (next)