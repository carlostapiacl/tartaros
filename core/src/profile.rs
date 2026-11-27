//! `--profile`: preset threat models a policy starts from.

use crate::Network;
use crate::Policy;

/// A named threat model: a baseline of confinement for a stated assumption about
/// the code being run. Explicit policy fields still override the baseline. The
/// point is honesty about what each tier does and does NOT guarantee — above all,
/// that TartarOS runs on a SHARED kernel, so no profile short of a microVM backend
/// provides true multi-tenant isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// The agent is trusted but fallible: confine mistakes and the trust-handoff
    /// set. Network default-deny, no namespace isolation. The everyday dev case.
    LocalAgent,
    /// The code may be actively malicious (single tenant): add PID isolation, an
    /// AF_UNIX lockdown and /proc isolation on top of local-agent. Still a shared
    /// kernel — a kernel exploit is out of scope for this tier.
    HostileCode,
    /// Untrusted multi-tenant workloads. TartarOS applies maximum single-kernel
    /// hardening (hostile-code + a fully isolated, egress-free network namespace)
    /// but does NOT provide kernel-level tenant isolation: a kernel LPE crosses
    /// the boundary. Real tenant separation needs a microVM backend
    /// (Firecracker/Kata), which is not implemented. Fail honest, not silent.
    MultiTenant,
}

impl Profile {
    pub fn parse(s: &str) -> Option<Profile> {
        match s {
            "local-agent" => Some(Profile::LocalAgent),
            "hostile-code" => Some(Profile::HostileCode),
            "multi-tenant" => Some(Profile::MultiTenant),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Profile::LocalAgent => "local-agent",
            Profile::HostileCode => "hostile-code",
            Profile::MultiTenant => "multi-tenant",
        }
    }

    /// Apply the profile's baseline to a policy. Only tightens; never grants.
    /// Call this BEFORE applying explicit flags so the operator can still relax
    /// or extend it. Network stays default-denied in every profile.
    pub fn apply(self, p: &mut Policy) {
        if p.network.is_none() {
            p.network = Some(Network::Denied);
        }
        match self {
            Profile::LocalAgent => {}
            // isolate_pids already gives the agent a /proc that shows only its own
            // namespace, so host processes/env are invisible — stronger than the
            // Landlock /proc read-deny (isolate_process_info), and it keeps the
            // agent's own /proc/self readable. It fails closed if namespaces are
            // unavailable, so there is no silent fallback to drop to.
            Profile::HostileCode => {
                p.isolate_pids = true;
                p.deny_unix_sockets = true;
                p.harden_syscalls = true;
                p.strict = true;
            }
            Profile::MultiTenant => {
                p.isolate_pids = true;
                p.deny_unix_sockets = true;
                p.isolate_network = true;
                p.harden_syscalls = true;
                p.strict = true;
            }
        }
    }

    /// One-line statement of what this tier confines.
    pub fn tier(self) -> &'static str {
        match self {
            Profile::LocalAgent => "confines a trusted-but-fallible agent (mistakes + trust-handoff)",
            Profile::HostileCode => "confines actively-malicious code on a single, shared kernel",
            Profile::MultiTenant => "maximum single-kernel hardening — NOT kernel-isolated",
        }
    }

    /// An honest caveat printed on run and in `explain`, or `None` when the tier's
    /// guarantee needs no asterisk. Never lets a tier overclaim.
    pub fn caveat(self) -> Option<&'static str> {
        match self {
            Profile::LocalAgent => None,
            Profile::HostileCode => Some(
                "shared kernel: a kernel-level exploit (LPE) can still cross this boundary. \
                 For untrusted multi-tenant workloads a microVM backend is required.",
            ),
            Profile::MultiTenant => Some(
                "multi-tenant KERNEL ISOLATION IS NOT PROVIDED. TartarOS confines via \
                 Landlock/seccomp/namespaces on a SHARED kernel; a kernel exploit crosses \
                 tenants. Real tenant separation requires a microVM backend \
                 (Firecracker/Kata), not yet implemented. This profile applies maximum \
                 single-kernel hardening ONLY.",
            ),
        }
    }
}
