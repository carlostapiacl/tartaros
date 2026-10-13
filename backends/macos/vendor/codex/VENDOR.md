# Vendored from OpenAI Codex

Source: https://github.com/openai/codex @ `f82e36592278a0a782fb0d0fc97e5fa10e832ac2`
License: Apache-2.0 (see repo root `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`).

These files are the macOS Seatbelt profile generator and its `.sbpl` fragments,
from `codex-rs/sandboxing/src/`. **Vendored verbatim, as reference.** They are
NOT compiled (they live outside any crate's module tree) and still reference
Codex's own crates (`codex_protocol`, `codex_network_proxy`, …).

The macOS backend (`../../src/lib.rs`) will adapt this generator to
`tartaros_core::Policy`. When a file here is modified, it gets a notice at
its top saying so, per Apache-2.0 §4(b), and the change is logged in
`THIRD_PARTY_NOTICES.md`.
