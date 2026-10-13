//! Landlock capability probes (fail-closed, P0-2): can THIS kernel actually
//! enforce the filesystem / TCP-network rules? Used to refuse running
//! under-confined and to report per-host enforcement. Linux-only.

/// Probe (fail-closed, P0-2): can this kernel enforce Landlock filesystem rules?
/// Builds a ruleset with HardRequirement — it errors if the capability is absent.
/// Creates no restriction (never calls restrict_self); the fd is dropped.
pub(crate) fn landlock_fs_supported() -> bool {
    use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
        .and_then(|r| r.create())
        .is_ok()
}

/// Probe (fail-closed, P0-2): can this kernel enforce Landlock TCP network rules
/// (ABI v4, Linux >= 6.7)?
pub(crate) fn landlock_net_supported() -> bool {
    use landlock::{AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr};
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessNet::ConnectTcp | AccessNet::BindTcp)
        .and_then(|r| r.create())
        .is_ok()
}

