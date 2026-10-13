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
- [ ] measure the macOS env-leak (KERN_PROCARGS2) under our profile — is it
      actually blockable by Seatbelt, or a platform limit? (honest open question)
- [ ] shell rc / CI-config handoff paths beyond `.github/workflows`

## M2 — Linux backend
- [ ] Landlock via `rust-landlock`; `validate` rejects deny-overlapping-allow
- [ ] bwrap path for deny-on-absent, with Codex's flock mount registry
- [ ] bench on a real Landlock kernel (the Linux test host)

## M3 — integration + release
- [ ] `srt` adapter (wrap @anthropic-ai/sandbox-runtime)
- [ ] seisin consumes seisin-sandbox through the backend abstraction
- [ ] make the repo public
