//! macOS backend — Seatbelt (sandbox-exec) profile generation.
//!
//! This will adapt the profile generator vendored under `vendor/codex/`
//! (from OpenAI Codex, Apache-2.0; see THIRD_PARTY_NOTICES.md), re-wired to
//! `seisin_sandbox_core::Policy` and hardened in two ways the original is not:
//!   1. protect the full trust-handoff set at any depth, with ancestor-rename
//!      safety (Codex only covers the first level);
//!   2. remove the `kern.proc.*` sysctl allow so a confined process cannot read
//!      another process's environment via KERN_PROCARGS2.
//!
//! Not implemented yet — this is where we start.

use seisin_sandbox_core::{Backend, Policy, PolicyError, RunError, RunOutcome};

pub struct SeatbeltBackend;

impl Backend for SeatbeltBackend {
    fn name(&self) -> &str {
        "macos-seatbelt"
    }

    fn validate(&self, _policy: &Policy) -> Result<(), PolicyError> {
        Err(PolicyError { reason: "macos-seatbelt backend not implemented yet".into() })
    }

    fn run(&self, _policy: &Policy, _command: &[String]) -> Result<RunOutcome, RunError> {
        Err(RunError { reason: "macos-seatbelt backend not implemented yet".into() })
    }
}
