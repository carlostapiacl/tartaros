//! microVM backend — **design stage** (see `docs/microvm-backend.md`). This is the
//! extension point for true multi-tenant isolation: each agent in its own guest
//! kernel, so a guest kernel exploit stays inside the VM (the one honest ceiling
//! the Landlock/Seatbelt backends declare in `SECURITY.md`).
//!
//! It implements `core::Backend` so the UNCHANGED `core::Policy`, CLI, effect-log
//! format and conformance corpus plug in underneath it. Guest execution (gVisor
//! phase M-µ1, then Firecracker M-µ2) is not implemented yet, so `run` **fails
//! closed**: it refuses to run rather than ever running an agent under-confined.
//! Shipping this crate now fixes the trait wiring and the honest refusal; the
//! enforcement lands against the verification contract in the design doc, on a
//! runtime-capable host.

use std::path::Path;
use tartaros_core::{Backend, Policy, PolicyError, RunError, RunOutcome};

/// What guest-isolation runtime this host offers. Used for an honest refusal
/// message now, and to select gVisor (no KVM) vs Firecracker (KVM) later.
#[derive(Debug, Default, Clone, Copy)]
pub struct RuntimeProbe {
    /// gVisor `runsc` on PATH — the phase-1 engine (works without KVM).
    pub runsc: bool,
    /// `firecracker` on PATH — the phase-2 microVM engine.
    pub firecracker: bool,
    /// `/dev/kvm` present — required by Firecracker / Cloud Hypervisor.
    pub kvm: bool,
}

impl RuntimeProbe {
    /// Could this host run SOME guest-isolation engine? (gVisor needs no KVM.)
    pub fn any(&self) -> bool {
        self.runsc || (self.firecracker && self.kvm)
    }
}

/// Probe the host for a guest-isolation runtime (read-only: PATH lookups + a
/// `/dev/kvm` existence check). Never executes anything.
pub fn probe_runtime() -> RuntimeProbe {
    let on_path = |bin: &str| {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).exists()))
            .unwrap_or(false)
    };
    RuntimeProbe {
        runsc: on_path("runsc"),
        firecracker: on_path("firecracker"),
        kvm: Path::new("/dev/kvm").exists(),
    }
}

pub struct MicrovmBackend;

impl Backend for MicrovmBackend {
    fn name(&self) -> &str {
        "microvm"
    }

    fn validate(&self, _policy: &Policy) -> Result<(), PolicyError> {
        // The generic policy maps cleanly to VM shares/config (writable roots ->
        // rw virtio-fs, handoff/secrets -> ro shares, caps -> VM size; see the
        // design), so there is nothing to reject at the policy LEVEL. Whether this
        // host can actually run a guest is decided in `run`, which fails closed.
        Ok(())
    }

    fn run(&self, _policy: &Policy, _command: &[String]) -> Result<RunOutcome, RunError> {
        let p = probe_runtime();
        Err(RunError {
            reason: format!(
                "microVM backend is design-stage and not yet executable — guest execution \
                 is unimplemented (see docs/microvm-backend.md). It fails CLOSED: it never \
                 runs an agent under-confined. Runtime probe on this host: runsc={} \
                 firecracker={} kvm={}.",
                p.runsc, p.firecracker, p.kvm
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_microvm() {
        assert_eq!(MicrovmBackend.name(), "microvm");
    }

    #[test]
    fn validate_accepts_any_policy() {
        // Policy-level acceptance (executability is a run-time, host-level concern).
        assert!(MicrovmBackend.validate(&Policy::default()).is_ok());
    }

    #[test]
    fn run_fails_closed_until_implemented() {
        // Must never pretend to run: design-stage => refuse, with the probe in the
        // message. This is the fail-closed contract, verifiable today.
        let e = MicrovmBackend
            .run(&Policy::default(), &["true".into()])
            .unwrap_err();
        assert!(e.reason.contains("design-stage"));
        assert!(e.reason.contains("fails CLOSED"));
    }

    #[test]
    fn probe_runs_without_panicking() {
        let p = probe_runtime();
        // `any()` is just a boolean view over the probe; calling it must not panic.
        let _ = p.any();
    }
}
