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
- [ ] **effect log**: record allowed AND denied events (files, ports/net,
      secrets, MCP), per role, with timestamps — the bridge to the intent layer
- [ ] **ports/network per role**: 127.0.0.1:<port> granular (not all-localhost);
      domain allow-list via proxy
- [ ] **secret reads**: read-deny of secret dirs (~/.ssh, ~/.aws, keydirs)
- [ ] **secret broker**: give the capability, not the raw value
- [ ] **close the Linux env-leak**: restrict /proc or PID namespace
- [ ] **resources, not paths**: evolve `Policy` toward capabilities

## M5 — intent layer (the intent layer) on the effect log
- [ ] feed the intent layer from the effect log (allowed + denied)
- [ ] the missing core: infer goal + deviation per session (1 LLM call)
