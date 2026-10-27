# Third-party notices

tartaros reuses source from other open-source projects. Each is listed
here with its upstream origin, the exact commit it was taken from, the files
involved, its license, and the modifications made. All reused code keeps its
original license; this file satisfies the attribution and "state your changes"
requirements of the Apache License 2.0 (§4).

---

## OpenAI Codex

- **Upstream:** https://github.com/openai/codex
- **Commit:** `f82e36592278a0a782fb0d0fc97e5fa10e832ac2`
- **License:** Apache License 2.0 (see `LICENSE`)
- **Upstream NOTICE:** "OpenAI Codex — Copyright 2025 OpenAI"

### Files vendored

Under `backends/macos/vendor/codex/`, taken from `codex-rs/sandboxing/src/`:

| file | upstream path | purpose |
|---|---|---|
| `seatbelt.rs` | `codex-rs/sandboxing/src/seatbelt.rs` | generates the macOS Seatbelt (sandbox-exec) profile from a policy |
| `seatbelt_base_policy.sbpl` | same dir | deny-by-default base profile (process-info, sysctl, mach whitelists) |
| `seatbelt_network_policy.sbpl` | same dir | network allow rules |
| `seatbelt_preferences_policy.sbpl` | same dir | preferences access |
| `seatbelt_read_only_platform_defaults.sbpl` | same dir | read-only platform defaults |

### Modifications

- **As of the initial import: none.** The files are vendored verbatim as
  reference for the macOS backend. They are NOT yet compiled into any crate
  (they live under `vendor/` and are outside the module tree).
- When adapted for tartaros (re-wiring to `tartaros-core`'s policy
  type, removing the `kern.proc.*` sysctl allow that leaks other processes'
  environment, and extending ancestor-rename protection to the full
  trust-handoff set), each changed file will carry a prominent notice at its top
  stating it was modified from the Codex original, and the change will be
  summarized here.

### Not vendored (read as reference only, never copied)

- `phylum-dev/birdcage` (GPL-3.0) and `netblue30/firejail` (GPL-2.0): copyleft,
  studied only. No code taken.
- `containers/bubblewrap` (LGPL): used as an external binary if needed, not
  vendored.

## Code ported from sandbox-runtime

- `broker/src/sigv4.rs` — the SigV4 canonical request and signer, ported to Rust
  from `anthropics/sandbox-runtime` `src/sandbox/aws-sigv4.ts` (Apache-2.0):
  canonical URI (S3 as sent, other services normalized and encoded once more),
  canonical query, trimmed header values, the signing-key chain. Modified: Rust,
  ring for HMAC/SHA-256, and only the header-signed shape is re-signed (the
  others are refused by the broker).

## Conformance contracts derived from other test suites

Part of `security-bench/corpus/` re-expresses guarantees asserted in other
sandboxes' public test suites, as original attack + control + effect contracts (no
upstream test code was copied). Each keeps a `source` field; the full list is in
[`security-bench/SOURCES.md`](security-bench/SOURCES.md).

- `anthropics/sandbox-runtime` — Apache-2.0
- `nolabs-ai/nono` — Apache-2.0
- `openai/codex` — Apache-2.0
- `containers/bubblewrap` — LGPL-2.1-or-later (guarantee described only)
