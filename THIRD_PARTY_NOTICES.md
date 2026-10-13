# Third-party notices

seisin-sandbox reuses source from other open-source projects. Each is listed
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
- When adapted for seisin-sandbox (re-wiring to `seisin-sandbox-core`'s policy
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
