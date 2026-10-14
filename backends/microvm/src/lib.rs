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

use std::path::{Path, PathBuf};
use tartaros_core::{Backend, Policy, PolicyError, RunError, RunOutcome};

/// How a host path is exposed to the guest. A VM shares explicit paths (default:
/// nothing visible), so the policy's broad "read all but the denies" model is
/// inverted into an explicit share list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The agent's workspace: shared read-write (edits land on the host in place).
    ReadWrite,
    /// A trust-handoff path inside a writable root: shared read-only, so the guest
    /// can read it (git, the agent's own config) but cannot poison it.
    ReadOnly,
    /// A secret (`read_denies`) that falls inside a writable root: NOT shared, so
    /// it is invisible in the guest (stronger than Landlock's path deny).
    Excluded,
}

/// One host path and how the guest sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub host_path: PathBuf,
    pub mode: Mode,
}

/// Backend-agnostic mapping from a `core::Policy` to the guest share plan — the
/// core of any VM backend (gVisor virtio-fs / 9p, Firecracker virtio-fs). Reuses
/// `trust_handoff_rules()` so the handoff set and its any-depth semantics are
/// identical to the shared-kernel backends. Pure and fully unit-testable without a
/// runtime: writable roots are rw; the handoff paths within them are pinned ro;
/// `read_denies` under a root are excluded (invisible), which also covers paths
/// that do not exist yet (a VM share is by directory, not inode). Deepest path
/// wins, so a handoff ro-pin inside a rw root and a secret exclusion compose.
pub fn mount_plan(policy: &Policy) -> Vec<Share> {
    let mut shares: Vec<Share> = Vec::new();
    for root in &policy.writable_roots {
        shares.push(Share { host_path: root.clone(), mode: Mode::ReadWrite });
    }
    // Trust-handoff paths under the roots: read-only overrides within the rw share.
    for r in policy.trust_handoff_rules() {
        shares.push(Share { host_path: r.path, mode: Mode::ReadOnly });
    }
    // Secrets that fall inside a writable root must be hidden, not merely ro.
    for deny in &policy.read_denies {
        if policy.writable_roots.iter().any(|root| deny.starts_with(root)) {
            shares.push(Share { host_path: deny.clone(), mode: Mode::Excluded });
        }
    }
    shares
}

/// Does the policy ask for any egress? A VM gives the guest no NIC by default
/// (= all protocols off); only an explicit allow/port needs a host-side bridge.
pub fn guest_wants_egress(policy: &Policy) -> bool {
    matches!(policy.network, Some(tartaros_core::Network::Allowed))
        || !policy.local_ports.is_empty()
        || !policy.allow_domains.is_empty()
}

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

    #[test]
    fn mount_plan_classifies_rw_ro_excluded() {
        let mut p = Policy::default();
        p.writable_roots = vec![PathBuf::from("/ws")];
        p.read_denies = vec![PathBuf::from("/ws/secret"), PathBuf::from("/outside/secret")];
        let plan = mount_plan(&p);
        let has = |path: &str, mode: Mode| {
            plan.iter().any(|s| s.host_path == PathBuf::from(path) && s.mode == mode)
        };
        // the workspace root is shared read-write
        assert!(has("/ws", Mode::ReadWrite));
        // a trust-handoff config under the root is pinned read-only
        assert!(has("/ws/.mcp.json", Mode::ReadOnly));
        // a secret INSIDE the root is excluded (invisible in the guest)
        assert!(has("/ws/secret", Mode::Excluded));
        // a secret OUTSIDE any root is simply never shared (default-invisible)
        assert!(!plan.iter().any(|s| s.host_path == PathBuf::from("/outside/secret")));
    }

    #[test]
    fn egress_is_off_by_default() {
        assert!(!guest_wants_egress(&Policy::default()));
        let mut p = Policy::default();
        p.allow_domains = vec!["example.com".into()];
        assert!(guest_wants_egress(&p));
    }
}
