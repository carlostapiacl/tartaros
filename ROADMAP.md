# Roadmap — seisin-sandbox

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
      what nono refuses. Unit test with nested `.git`. The seisin Linux edge.
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
- [ ] seisin consumes seisin-sandbox through the backend abstraction
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
      `X-Seisin-Auth: <token>` per run; a process without it gets 403. Verified
      on the Linux test host (with token 200, without 403). Destination/method scoping per
      capability remains to extend.
- [~] **P1 absent trust-handoff paths on Linux** (inode limit): deferred. Real
      fix needs dynamic monitoring (fanotify/FUSE); no portable static fix.
      macOS/Seatbelt already covers absent paths. Documented limitation.
- [x] **P1 /proc isolation / cross-process env read on Linux — MITIGATED.**
      Primary: the kernel already blocks it — with Yama `ptrace_scope=1` (Ubuntu
      default, confirmed on the Linux test host) an unrelated process's `/proc/<pid>/environ` is
      not readable (measured: leak blocked even with no sandbox rule). Defense-in-
      depth: `isolate_process_info` excludes `/proc` from the read grant (covers
      `ptrace_scope=0`); measured that sh/cat/ls/curl/git/python3 still run and the
      full suite (smoke/net/readdeny/P0) stays green. PID namespace stays out
      (`unshare` not portable under Docker).
