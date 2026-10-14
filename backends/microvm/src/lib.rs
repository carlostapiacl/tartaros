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
use tartaros_core::{Access, Backend, Policy, PolicyError, RunError, RunOutcome};

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
    // Writable roots: read-write.
    for root in &policy.writable_roots {
        shares.push(Share { host_path: root.clone(), mode: Mode::ReadWrite });
    }
    // Re-allowed read branches — these may sit OUTSIDE the writable roots (deny a
    // broad dir, open one branch within it). A VM shares only what is listed, so a
    // legitimately-readable branch must be shared read-only or it is invisible and
    // breaks a legitimate read. (A deeper read-deny inside it is masked below.)
    for allow in &policy.read_allows {
        shares.push(Share { host_path: allow.clone(), mode: Mode::ReadOnly });
    }
    // Trust-handoff paths under the roots: read-only overrides within the rw share.
    for r in policy.trust_handoff_rules() {
        shares.push(Share { host_path: r.path, mode: Mode::ReadOnly });
    }
    // User-declared write-denies (`fs_rules` with `Access::Deny`): a path inside a
    // writable root that must stay READABLE but never writable — the deny-inside-
    // allow carve for writes. In the VM model that is a read-only bind.
    for r in &policy.fs_rules {
        if r.access == Access::Deny {
            shares.push(Share { host_path: r.path.clone(), mode: Mode::ReadOnly });
        }
    }
    // Secrets that fall inside ANY visible share (a writable root or a re-allowed
    // read branch) must be hidden, not merely ro. A read-deny that is only the
    // parent of a re-allowed branch (deny vault, allow vault/mine) is NOT inside a
    // share, so it is simply never shared — correct, and it does not mask the branch.
    for deny in &policy.read_denies {
        let inside_writable = policy.writable_roots.iter().any(|root| deny.starts_with(root));
        let inside_allow = policy.read_allows.iter().any(|a| deny.starts_with(a));
        if inside_writable || inside_allow {
            shares.push(Share { host_path: deny.clone(), mode: Mode::Excluded });
        }
    }
    shares
}

/// Emit an OCI runtime `config.json` (opencontainers/runtime-spec) for this policy
/// and command — the bundle a gVisor `runsc` (or any OCI runtime) consumes. This is
/// a STANDARD spec, so it is deterministic and unit-testable without a runtime:
/// - `process.args` = the command; `cwd` = the first writable root; no-new-privs.
/// - `mounts` from [`mount_plan`]: rw bind for a writable root, ro bind for a
///   trust-handoff path, and an empty read-only tmpfs masking an excluded secret
///   (so it is invisible even though it sits inside a shared rw dir).
/// - `linux.resources` from the caps; `linux.namespaces` omit the network namespace
///   reference so the guest gets a fresh, empty one (no egress) unless the policy
///   opts in (bridged host-side — not represented here).
/// `rootfs` is the guest root the runtime overlays the mounts onto (built per the
/// design's image step). `user` selects the guest identity ([`GuestUser`]) — the
/// knob that closes the uid-0-in-guest gap: `Direct` (gVisor-native non-root, no
/// userns), `Mapped` (OCI/runc userns form), or `Root` (legacy). Returned
/// pretty-printed.
pub fn to_oci_config(
    policy: &Policy,
    command: &[String],
    rootfs: &str,
    user: &GuestUser,
) -> String {
    use serde_json::json;

    let cwd = policy
        .writable_roots
        .first()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/".into());

    // Standard OCI runtime-spec default mounts. A runtime (runc/runsc) does NOT add
    // these for us: without them the guest has no /proc, /dev/null, /dev/shm, … so
    // ordinary tools break — AND the maskedPaths/readonlyPaths below (all under
    // /proc, /sys) would have no filesystem to apply to, making that hardening
    // inert. They come first so the policy's path binds nest on top of a real base.
    let mut mounts = vec![
        json!({ "destination": "/proc", "type": "proc", "source": "proc" }),
        json!({ "destination": "/dev", "type": "tmpfs", "source": "tmpfs",
                "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] }),
        json!({ "destination": "/dev/pts", "type": "devpts", "source": "devpts",
                "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"] }),
        json!({ "destination": "/dev/shm", "type": "tmpfs", "source": "shm",
                "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"] }),
        json!({ "destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue",
                "options": ["nosuid", "noexec", "nodev"] }),
        json!({ "destination": "/sys", "type": "sysfs", "source": "sysfs",
                "options": ["nosuid", "noexec", "nodev", "ro"] }),
        json!({ "destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup",
                "options": ["nosuid", "noexec", "nodev", "relatime", "ro"] }),
    ];
    // Emit the policy binds/masks parent-before-child: a deeper override (a secret
    // mask inside a shared dir, a write-deny inside a writable root) MUST come after
    // the shallower share it overrides, since the runtime applies mounts in order
    // and a longer path wins. Sorting by destination depth guarantees this
    // regardless of the order the shares were classified in.
    let mut plan = mount_plan(policy);
    plan.sort_by_key(|s| s.host_path.components().count());
    for s in plan {
        let dest = s.host_path.to_string_lossy().into_owned();
        let m = match s.mode {
            // A bind mount needs an EXISTING source: the runtime (runc/runsc) opens
            // the source at sandbox creation and aborts the whole sandbox if it is
            // missing. The trust-handoff set is protect-even-if-absent, so many of
            // its paths (e.g. a not-yet-created `.claude/agents`) do not exist on
            // disk — binding them would crash the guest. Skip an absent bind source;
            // there is nothing to protect yet, and the ro-root + masks still hold.
            // (A not-yet-existing handoff path under the rw share is the documented
            // microVM "future handoff" residual, closed later by materialization.)
            Mode::ReadWrite | Mode::ReadOnly => {
                if !s.host_path.exists() {
                    continue;
                }
                let ro = matches!(s.mode, Mode::ReadOnly);
                json!({
                    "destination": dest, "type": "bind",
                    "source": dest, "options": ["rbind", if ro { "ro" } else { "rw" }]
                })
            }
            // Mask the secret so the guest cannot see the host contents, even
            // though the enclosing dir is shared. A tmpfs is a *directory*
            // filesystem and cannot mount over a regular file (runsc/runc:
            // "mountpoint isn't a directory"), so a secret FILE is masked by a
            // read-only bind of `/dev/null` (the content is gone — the guest reads
            // empty, never the secret), and a secret DIRECTORY (or a not-yet-existing
            // path) by an empty ro tmpfs. Note the file case reads as EMPTY rather
            // than erroring — the secrecy property (no leak) holds either way.
            Mode::Excluded => {
                if s.host_path.is_file() {
                    json!({ "destination": dest, "type": "bind",
                            "source": "/dev/null", "options": ["bind", "ro"] })
                } else {
                    json!({ "destination": dest, "type": "tmpfs",
                            "source": "tmpfs", "options": ["ro", "nosuid", "nodev", "size=0"] })
                }
            }
        };
        mounts.push(m);
    }

    let mut resources = serde_json::Map::new();
    if let Some(m) = policy.max_memory_bytes {
        resources.insert("memory".into(), json!({ "limit": m }));
    }
    if let Some(n) = policy.max_processes {
        resources.insert("pids".into(), json!({ "limit": n }));
    }

    // Namespaces: a fresh pid/mount/ipc/uts, and ALWAYS a fresh empty network
    // namespace (no `path`, so the runtime creates an isolated one with loopback
    // only). This is fail-closed: omitting the netns when egress is wanted would
    // make an OCI runtime share the HOST network — full, unbrokered egress, the
    // opposite of what a domain-scoped policy promises. The scoped-egress path (a
    // host-side broker bridged into this netns) is not built yet, so until it is,
    // an egress policy under the microVM backend simply gets no network rather than
    // the host's. `guest_wants_egress` is still exposed so the eventual bridge knows
    // whether to wire one in.
    let mut namespaces = vec![
        json!({"type": "pid"}),
        json!({"type": "mount"}),
        json!({"type": "ipc"}),
        json!({"type": "uts"}),
        json!({"type": "network"}),
    ];
    // Only the OCI/runc `Mapped` form carries a user namespace + uid/gid mappings.
    // `Direct` relies on gVisor's guest-uid == host-uid bind ownership (no userns,
    // which this gVisor rejects); `Root` is the legacy posture.
    let mapping = match user {
        GuestUser::Mapped(u) => Some(*u),
        _ => None,
    };
    if mapping.is_some() {
        namespaces.push(json!({"type": "user"}));
    }
    let uid_mappings = mapping.map(|u| {
        json!([{ "containerID": u.guest_uid, "hostID": u.host_uid, "size": 1u32 }])
    });
    let gid_mappings = mapping.map(|u| {
        json!([{ "containerID": u.guest_gid, "hostID": u.host_gid, "size": 1u32 }])
    });

    // Drop ALL capabilities (every OCI set empty). Without this the runtime applies
    // its DEFAULT capability set — which still includes CAP_NET_RAW, CAP_MKNOD,
    // CAP_SETUID/SETGID, CAP_CHOWN, CAP_DAC_OVERRIDE, … — leaving the guest process
    // more privileged than our Landlock backend, which drops the bounding set to
    // empty (namespace::drop_all_capabilities). A confined agent needs none of them.
    let no_caps = json!({
        "bounding": [], "effective": [], "inheritable": [], "permitted": [], "ambient": []
    });

    // Standard OCI masked/readonly paths: hide host-info leak channels under /proc
    // and /sys and freeze the sensitive /proc control files. Same intent as the
    // Linux backend's /proc isolation, expressed in the config the runtime enforces.
    let masked_paths = json!([
        "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list",
        "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi", "/sys/firmware"
    ]);
    let readonly_paths = json!([
        "/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys",
        "/proc/sysrq-trigger"
    ]);

    // Cap the open-file ceiling, matching the Linux backend's hard RLIMIT_NOFILE
    // (an unbounded fd table is a cheap local-DoS lever).
    let rlimits = json!([
        { "type": "RLIMIT_NOFILE", "hard": 65536u64, "soft": 65536u64 }
    ]);

    // The guest process identity inside the guest.
    let process_user = match user {
        GuestUser::Root => json!({ "uid": 0, "gid": 0 }),
        GuestUser::Direct { uid, gid } => json!({ "uid": uid, "gid": gid }),
        GuestUser::Mapped(u) => json!({ "uid": u.guest_uid, "gid": u.guest_gid }),
    };

    let mut linux = serde_json::Map::new();
    linux.insert("resources".into(), json!(resources));
    linux.insert("namespaces".into(), json!(namespaces));
    linux.insert("maskedPaths".into(), masked_paths);
    linux.insert("readonlyPaths".into(), readonly_paths);
    if let Some(m) = uid_mappings {
        linux.insert("uidMappings".into(), m);
    }
    if let Some(m) = gid_mappings {
        linux.insert("gidMappings".into(), m);
    }

    let config = json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": process_user,
            "cwd": cwd,
            "args": command,
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "noNewPrivileges": true,
            "capabilities": no_caps,
            "rlimits": rlimits,
        },
        "root": { "path": rootfs, "readonly": true },
        "mounts": mounts,
        "linux": linux,
    });
    serde_json::to_string_pretty(&config).unwrap_or_default()
}

/// How the guest process's identity maps to the host. Closing the uid-0-in-guest
/// gap: the guest runs as a **non-root** uid *inside the guest*, and a user
/// namespace maps that guest uid/gid to the **launcher's host uid/gid** so the
/// read-write workspace binds (owned by the host uid) stay writable. Without the
/// mapping a non-root guest uid could not write them; without a non-root guest uid
/// the guest is root in its own namespace (least-privilege violation). The mapping
/// is runtime-sensitive (runc vs gVisor treat bind ownership under a userns
/// differently), so it is emitted here but **validated against the runtime**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserMapping {
    /// The uid the process has *inside* the guest (non-root, e.g. 1000).
    pub guest_uid: u32,
    /// The gid the process has *inside* the guest.
    pub guest_gid: u32,
    /// The launcher's uid on the host (what the workspace files are owned by).
    pub host_uid: u32,
    /// The launcher's gid on the host.
    pub host_gid: u32,
}

impl UserMapping {
    /// Map a fixed non-root guest id (1000) onto the given host uid/gid — the
    /// common case (run the agent as a stable in-guest user owning the workspace).
    pub fn to_host(host_uid: u32, host_gid: u32) -> Self {
        Self { guest_uid: 1000, guest_gid: 1000, host_uid, host_gid }
    }
}

/// Which identity the guest process runs as — the knob that closes (or declares) the
/// uid-0-in-guest gap. Two non-root forms exist because the runtimes disagree:
///
/// - [`GuestUser::Direct`] runs as a non-root uid with **no user namespace**. gVisor
///   (`runsc`) maps a bind's ownership guest-uid == host-uid directly, so a workspace
///   **owned by that host uid** is writable by a non-root guest of the same id. This
///   is the form gVisor accepts and is validated against `runsc` (the launcher runs
///   as that non-root uid in production).
/// - [`GuestUser::Mapped`] is the OCI/runc-correct form: a non-root guest uid behind
///   a **user namespace** mapped to the host owner. runc honours it; **this gVisor
///   build rejects any userns spec** (`gofer: fork/exec … invalid argument`), so it
///   is emitted for runc-class runtimes, not gVisor — validated finding, see
///   `docs/microvm-backend.md`.
/// - [`GuestUser::Root`] is the legacy uid-0-in-guest posture: still kernel-isolated,
///   but not least-privilege. Kept for back-compat and honest comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestUser {
    Root,
    Direct { uid: u32, gid: u32 },
    Mapped(UserMapping),
}

impl Default for GuestUser {
    fn default() -> Self {
        GuestUser::Root
    }
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
    fn mount_plan_maps_write_denies_and_read_allows() {
        use tartaros_core::FsRule;
        let mut p = Policy::default();
        p.writable_roots = vec![PathBuf::from("/ws")];
        // a write-deny inside the writable root: must stay readable but ro
        p.fs_rules = vec![FsRule {
            path: PathBuf::from("/ws/protected"),
            access: Access::Deny,
            even_if_absent: true,
        }];
        // deny a broad dir outside the root, re-allow one branch, deny a deeper leaf
        p.read_denies = vec![PathBuf::from("/vault"), PathBuf::from("/vault/mine/secret")];
        p.read_allows = vec![PathBuf::from("/vault/mine")];
        let plan = mount_plan(&p);
        let has = |path: &str, mode: Mode| {
            plan.iter().any(|s| s.host_path == PathBuf::from(path) && s.mode == mode)
        };
        // write-deny -> read-only (readable, never writable)
        assert!(has("/ws/protected", Mode::ReadOnly), "write-deny must be a ro bind");
        // re-allowed branch -> read-only share (visible)
        assert!(has("/vault/mine", Mode::ReadOnly), "read-allow must be shared ro");
        // deeper deny inside the re-allowed branch -> excluded (masked)
        assert!(has("/vault/mine/secret", Mode::Excluded), "deeper deny masks over allow");
        // the broad parent deny is NOT inside any share -> never shared, not masked
        // (masking it would hide the re-allowed branch)
        assert!(
            !plan.iter().any(|s| s.host_path == PathBuf::from("/vault")),
            "a parent-only deny must not be emitted as a mask"
        );
    }

    #[test]
    fn egress_is_off_by_default() {
        assert!(!guest_wants_egress(&Policy::default()));
        let mut p = Policy::default();
        p.allow_domains = vec!["example.com".into()];
        assert!(guest_wants_egress(&p));
    }

    #[test]
    fn oci_config_maps_policy() {
        // Real temp workspace: a bind mount needs an existing source, so the ws root,
        // the secret, and an EXISTING handoff file must be on disk to be emitted.
        let ws = std::env::temp_dir().join(format!("mv-oci-{}", std::process::id()));
        let _ = std::fs::create_dir_all(ws.join("secret"));
        std::fs::write(ws.join(".mcp.json"), "{}").unwrap(); // existing handoff file
        let ws_s = ws.to_string_lossy().into_owned();

        let mut p = Policy::default();
        p.writable_roots = vec![ws.clone()];
        p.read_denies = vec![ws.join("secret")];
        p.max_memory_bytes = Some(512 * 1024 * 1024);
        p.max_processes = Some(64);
        let cmd = vec!["/bin/sh".to_string(), "-c".to_string(), "echo hi".to_string()];
        let v: serde_json::Value =
            serde_json::from_str(&to_oci_config(&p, &cmd, "/var/lib/tartaros/rootfs", &GuestUser::Root)).unwrap();

        // the command and cwd
        assert_eq!(v["process"]["args"], serde_json::json!(cmd));
        assert_eq!(v["process"]["cwd"], ws_s);
        assert_eq!(v["process"]["noNewPrivileges"], true);

        // hardening: every capability set is empty (drop all caps), rlimit set, and
        // the standard /proc masked/readonly paths are present — so the guest is no
        // more privileged than the Landlock backend.
        for set in ["bounding", "effective", "inheritable", "permitted", "ambient"] {
            assert_eq!(
                v["process"]["capabilities"][set].as_array().unwrap().len(),
                0,
                "capability set {set} must be empty"
            );
        }
        let rl = v["process"]["rlimits"].as_array().unwrap();
        assert!(rl.iter().any(|r| r["type"] == "RLIMIT_NOFILE" && r["hard"] == 65536));
        let masked = v["linux"]["maskedPaths"].as_array().unwrap();
        assert!(masked.iter().any(|p| p == "/proc/kcore"));
        assert!(masked.iter().any(|p| p == "/sys/firmware"));
        let ro = v["linux"]["readonlyPaths"].as_array().unwrap();
        assert!(ro.iter().any(|p| p == "/proc/sys"));
        assert!(ro.iter().any(|p| p == "/proc/sysrq-trigger"));

        let mounts = v["mounts"].as_array().unwrap();
        let find = |dest: &str| mounts.iter().find(|m| m["destination"] == dest).cloned();
        // standard OCI default mounts present, so the bundle runs and the /proc,/sys
        // masked/readonly hardening actually has a filesystem to apply to.
        assert_eq!(find("/proc").unwrap()["type"], "proc");
        assert_eq!(find("/dev").unwrap()["type"], "tmpfs");
        let shm = find("/dev/shm").unwrap();
        assert!(shm["options"].as_array().unwrap().iter().any(|o| o == "nodev"));
        assert_eq!(find("/sys").unwrap()["type"], "sysfs");
        assert!(find("/sys").unwrap()["options"].as_array().unwrap().iter().any(|o| o == "ro"));
        let cg = find("/sys/fs/cgroup").unwrap();
        assert!(cg["options"].as_array().unwrap().iter().any(|o| o == "ro"));
        // workspace root: rw bind
        let ws_m = find(&ws_s).unwrap();
        assert_eq!(ws_m["type"], "bind");
        assert!(ws_m["options"].as_array().unwrap().iter().any(|o| o == "rw"));
        // secret: masked by a ro tmpfs (invisible)
        let sec = find(&ws.join("secret").to_string_lossy()).unwrap();
        assert_eq!(sec["type"], "tmpfs");
        assert!(sec["options"].as_array().unwrap().iter().any(|o| o == "ro"));
        // an EXISTING handoff path: ro bind
        let mcp = find(&ws.join(".mcp.json").to_string_lossy()).unwrap();
        assert!(mcp["options"].as_array().unwrap().iter().any(|o| o == "ro"));
        // an ABSENT handoff path (e.g. .claude/agents) is NOT emitted as a bind —
        // a missing bind source would make the runtime abort the whole sandbox.
        assert!(
            find(&ws.join(".claude/agents").to_string_lossy()).is_none(),
            "absent handoff path must not become a bind mount"
        );

        // resources
        assert_eq!(v["linux"]["resources"]["memory"]["limit"], 512 * 1024 * 1024);
        assert_eq!(v["linux"]["resources"]["pids"]["limit"], 64);

        // default-deny egress -> a fresh (pathless) network namespace is requested
        let ns = v["linux"]["namespaces"].as_array().unwrap();
        assert!(ns.iter().any(|n| n["type"] == "network"));
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn oci_config_always_isolates_network_even_when_egress_wanted() {
        // Fail-closed: even when the policy wants egress, the generated config MUST
        // still isolate the network namespace. Omitting it would make an OCI runtime
        // share the HOST network (unbrokered egress) — the opposite of the scoping
        // promise. The scoped-egress bridge is future work; until then, no network.
        let mut p = Policy::default();
        p.writable_roots = vec![PathBuf::from("/ws")];
        p.allow_domains = vec!["example.com".into()];
        assert!(guest_wants_egress(&p));
        let v: serde_json::Value =
            serde_json::from_str(&to_oci_config(&p, &["true".into()], "/rootfs", &GuestUser::Root)).unwrap();
        let ns = v["linux"]["namespaces"].as_array().unwrap();
        assert!(
            ns.iter().any(|n| n["type"] == "network"),
            "network namespace must always be isolated (never share host net)"
        );
    }

    #[test]
    fn legacy_root_user_is_uid0_no_userns() {
        // GuestUser::Root => the documented legacy posture: uid 0 inside the guest
        // and NO user namespace / uid mappings emitted.
        let mut p = Policy::default();
        p.writable_roots = vec![PathBuf::from("/ws")];
        let v: serde_json::Value =
            serde_json::from_str(&to_oci_config(&p, &["true".into()], "/rootfs", &GuestUser::Root)).unwrap();
        assert_eq!(v["process"]["user"]["uid"], 0);
        assert!(v["linux"].get("uidMappings").is_none());
        let ns = v["linux"]["namespaces"].as_array().unwrap();
        assert!(!ns.iter().any(|n| n["type"] == "user"), "no userns for Root");
    }

    #[test]
    fn direct_user_is_nonroot_without_userns() {
        // GuestUser::Direct => a non-root uid and NO user namespace (the gVisor-native
        // form validated against runsc). The workspace must be owned by this host uid.
        let mut p = Policy::default();
        p.writable_roots = vec![PathBuf::from("/ws")];
        let v: serde_json::Value = serde_json::from_str(
            &to_oci_config(&p, &["true".into()], "/rootfs", &GuestUser::Direct { uid: 2000, gid: 2000 }),
        )
        .unwrap();
        assert_eq!(v["process"]["user"]["uid"], 2000);
        assert_ne!(v["process"]["user"]["uid"], 0, "must not be root in guest");
        assert!(v["linux"].get("uidMappings").is_none(), "Direct emits no mappings");
        let ns = v["linux"]["namespaces"].as_array().unwrap();
        assert!(!ns.iter().any(|n| n["type"] == "user"), "Direct emits no userns");
        // caps still all dropped
        assert_eq!(v["process"]["capabilities"]["bounding"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn mapped_user_emits_userns_and_mappings() {
        // GuestUser::Mapped => the OCI/runc form: a non-root guest uid, a user
        // namespace, and uid/gid mappings pointing the guest id at the host owner.
        let mut p = Policy::default();
        p.writable_roots = vec![PathBuf::from("/ws")];
        let um = UserMapping::to_host(501, 20);
        let v: serde_json::Value = serde_json::from_str(
            &to_oci_config(&p, &["true".into()], "/rootfs", &GuestUser::Mapped(um)),
        )
        .unwrap();
        assert_eq!(v["process"]["user"]["uid"], 1000);
        assert_ne!(v["process"]["user"]["uid"], 0, "must not be root in guest");
        let ns = v["linux"]["namespaces"].as_array().unwrap();
        assert!(ns.iter().any(|n| n["type"] == "user"), "user namespace required");
        let um_json = &v["linux"]["uidMappings"][0];
        assert_eq!(um_json["containerID"], 1000);
        assert_eq!(um_json["hostID"], 501);
        assert_eq!(um_json["size"], 1);
        let gm_json = &v["linux"]["gidMappings"][0];
        assert_eq!(gm_json["hostID"], 20);
        assert_eq!(v["process"]["capabilities"]["bounding"].as_array().unwrap().len(), 0);
    }
}
