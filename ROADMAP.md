# Roadmap — seisin-sandbox

Principle: the policy is the product; backends reuse proven Apache-2.0 plumbing.
Build only where measurement shows no existing backend can enforce the policy.

## M0 — repo (done)
- [x] Apache-2.0 + NOTICE + THIRD_PARTY_NOTICES
- [x] `core`: Backend trait, Policy, trust-handoff set (design, compiles)
- [x] Codex Seatbelt generator vendored (verbatim, attributed)
- [x] backend stubs that fail-closed; `bench/` described

## M1 — macOS backend (first real code)
- [ ] `Policy::trust_handoff_rules`: expand the set under each writable root, at
      any depth (walk nested `.git/HEAD`), resolve shell rc / CI paths
- [ ] adapt the vendored Seatbelt generator to `core::Policy`
- [ ] extend ancestor-rename protection to the WHOLE trust-handoff set
- [ ] drop the `kern.proc.*` sysctl allow (KERN_PROCARGS2 leak)
- [ ] port the bench and show it passes where Codex/nono/srt fail (macOS)

## M2 — Linux backend
- [ ] Landlock via `rust-landlock`; `validate` rejects deny-overlapping-allow
- [ ] bwrap path for deny-on-absent, with Codex's flock mount registry
- [ ] bench on a real Landlock kernel (the Linux test host)

## M3 — integration + release
- [ ] `srt` adapter (wrap @anthropic-ai/sandbox-runtime)
- [ ] seisin consumes seisin-sandbox through the backend abstraction
- [ ] make the repo public
