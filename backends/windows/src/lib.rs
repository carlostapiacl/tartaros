//! Native Windows backend: an AppContainer with no capabilities, grant-only NTFS
//! ACLs, a private desktop and a kill-on-close job object.
//!
//! An AppContainer is held by what its SID is GRANTED, not by what is denied, so
//! a protected path is one the container's grant does not reach (a protected DACL
//! without the container's ACE), never a deny ACE. The dedicated-user tier
//! (`Tier::SandboxUser`) instead protects with explicit deny ACEs, which bind a
//! user SID.
//!
//! Fail-closed: every policy field this backend cannot enforce yet is refused by
//! `validate`, never silently dropped.

use std::path::{Path, PathBuf};
use tartaros_core::{
    Access, Backend, Network, Policy, PolicyError, RunError, RunOutcome, HANDOFF_CONFIG_NAMES, HANDOFF_GIT_NAMES,
};

#[cfg(windows)]
mod sys;

#[cfg(windows)]
pub mod wfp;

/// What the container gets on one path. Applied in this order, so a deeper or
/// later rule (a protect inside a grant) wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// Writable root: read/write/delete below it, no DELETE on the root itself,
    /// never FILE_DELETE_CHILD.
    Write,
    /// Inheritable read/execute.
    Read,
    /// Read/execute on this file only (the program being launched).
    ExecFile,
    /// Ancestor of a protected path: the container cannot delete or rename it;
    /// its children keep the write grant.
    Pin,
    /// Trust-handoff / write-deny: protected DACL, container keeps read only.
    ProtectReadOnly,
    /// Read-deny: protected DACL, the container gets nothing.
    ProtectNoAccess,
}

/// The DACL changes a policy compiles to, in application order. Pure, so it can
/// be unit-tested on any OS.
/// One canonical spelling per path: symlinks resolved (a rule names what the
/// link points to, never the link entry), and on Windows without the `\\?\`
/// verbatim prefix, so every `starts_with` below compares like with like.
pub fn canon(p: &Path) -> PathBuf {
    let r = tartaros_core::resolve_best_effort(p);
    let s = r.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => r,
    }
}

pub fn acl_plan(policy: &Policy, program: Option<&Path>) -> Vec<(PathBuf, Grant)> {
    let canon_all = |v: &[PathBuf]| -> Vec<PathBuf> { v.iter().map(|p| canon(p)).collect() };
    let roots = canon_all(&policy.writable_roots);
    let allows = canon_all(&policy.read_allows);
    let read_denies_all = canon_all(&policy.read_denies);

    // Write-protected paths: the trust-handoff set plus explicit write-denies.
    // Only paths that exist get an ACE (an ACE cannot name a missing object);
    // absent ones are covered by `materialize_absent_handoff`, refused (explicit
    // write-denies, see `absent_write_denies`) or stay the documented residual.
    let mut protect: Vec<PathBuf> = policy
        .trust_handoff_rules()
        .into_iter()
        .chain(policy.fs_rules.iter().cloned())
        .filter(|r| r.access == Access::Deny)
        .map(|r| canon(&r.path))
        .filter(|p| p.exists())
        .collect();
    protect.sort();
    protect.dedup();
    // A protected handoff / write-deny whose real path (symlinks resolved by
    // `canon`) leaves every writable root is dropped: the container has no write
    // there to deny, and granting ProtectReadOnly on it would hand the container
    // read of a target outside the workspace (a `.vscode` or `.git/hooks` planted
    // as a symlink to a secret). A gitdir relocated under ANOTHER writable root
    // stays, because it is still under a root. read_denies are NOT filtered: a
    // deny on a path outside the roots (e.g. ~/.ssh) is exactly the point on the
    // sandbox-user tier, and grants nothing.
    protect.retain(|p| roots.iter().any(|r| p.starts_with(r)));
    let read_denies: Vec<PathBuf> = read_denies_all.iter().filter(|p| p.exists()).cloned().collect();

    let mut plan: Vec<(PathBuf, Grant)> = Vec::new();
    // A writable root that does not exist is ignored (as on Linux); one nested
    // inside a write-protected path gets no grant — the deny covers it.
    for r in roots.iter().filter(|r| r.exists()) {
        if !protect.iter().any(|p| r.starts_with(p)) {
            plan.push((r.clone(), Grant::Write));
        }
    }
    for r in allows.iter().filter(|r| r.exists()) {
        plan.push((r.clone(), Grant::Read));
    }
    if let Some(p) = program.map(canon) {
        if !roots.iter().chain(&allows).any(|r| p.starts_with(r)) {
            plan.push((p, Grant::ExecFile));
        }
    }

    // Pin every ancestor between its writable root and a protected or
    // read-denied path, so the path can't be moved away (and recreated
    // unprotected at its old name) — rule #3.
    let mut pins: Vec<PathBuf> = Vec::new();
    for p in protect.iter().chain(&read_denies) {
        if let Some(root) = roots.iter().find(|r| p.starts_with(r)) {
            let mut a = p.parent();
            while let Some(dir) = a {
                if dir == root.as_path() || !dir.starts_with(root) {
                    break;
                }
                // A dir inside a protected or read-denied path is already held by
                // that path's inherited DACL; a pin there (which keeps the write
                // grant) would reopen it.
                let covered = protect.iter().chain(&read_denies).any(|q| dir.starts_with(q));
                if !covered && !pins.iter().any(|q| q == dir) {
                    pins.push(dir.to_path_buf());
                }
                a = dir.parent();
            }
        }
    }
    // Shallow first: a child's protected DACL must be built from its parent's
    // final state.
    pins.sort_by_key(|p| p.components().count());
    plan.extend(pins.into_iter().map(|p| (p, Grant::Pin)));

    // A write-protected path inside a read-deny keeps no read either: the
    // read-only grant must never re-open what a read rule closed (deepest wins).
    for p in protect {
        let g = if read_denied(&read_denies_all, &allows, &p) { Grant::ProtectNoAccess } else { Grant::ProtectReadOnly };
        plan.push((p, g));
    }
    let mut denies = read_denies;
    denies.sort_by_key(|p| p.components().count());
    plan.extend(denies.into_iter().map(|p| (p, Grant::ProtectNoAccess)));
    plan
}

/// Whether the deepest read rule covering `p` is a deny.
fn read_denied(denies: &[PathBuf], allows: &[PathBuf], p: &Path) -> bool {
    let depth = |rules: &[PathBuf]| rules.iter().filter(|r| p.starts_with(r)).map(|r| r.components().count()).max();
    match (depth(denies), depth(allows)) {
        (Some(d), Some(a)) => d >= a,
        (Some(_), None) => true,
        _ => false,
    }
}

/// Absent trust-handoff names to hold with a placeholder for the run, as the
/// directories to create, parents first. An ACE cannot name a missing object
/// and NTFS has no per-name rule, so an absent `.git/hooks` or `.mcp.json` is
/// created for the run (and protected by the ACL plan like any existing one),
/// then removed if still empty.
///
/// Every placeholder is an empty DIRECTORY, even for a file name such as
/// `.mcp.json`: git does not track empty directories (an agent's `git add -A`
/// cannot commit one), nothing can parse it as configuration, and removing it
/// afterwards with `remove_dir` can never delete content.
///
/// Scope, to stay out of every subdirectory: the names directly in a writable
/// root or in a git repo's root, a repo's `.git/hooks`, a `.git` pointer's
/// gitdir `hooks`, and a nested name whose first component already exists
/// (`.claude/agents` when `.claude` does). `.git/config` is never held (a
/// directory there would break git). Nothing is created through a symlink or
/// outside a writable root. Not covered: a new name in an arbitrary
/// subdirectory, such as `sub/.gitattributes`.
pub fn placeholder_plan(policy: &Policy) -> Vec<PathBuf> {
    let roots: Vec<PathBuf> = policy.writable_roots.iter().filter(|r| r.is_dir()).cloned().collect();
    let names: Vec<&str> = HANDOFF_CONFIG_NAMES.iter().chain(HANDOFF_GIT_NAMES).copied().collect();
    let mut targets: Vec<PathBuf> = Vec::new();
    for rule in policy.trust_handoff_rules() {
        let p = rule.path;
        if rule.access != Access::Deny || std::fs::symlink_metadata(&p).is_ok() {
            continue;
        }
        let wanted = match names.iter().find(|n| p.ends_with(n)) {
            Some(&".git/config") => false,
            Some(n) => {
                let depth = Path::new(n).components().count();
                let base: PathBuf = p.ancestors().nth(depth).map(Path::to_path_buf).unwrap_or_default();
                let first = Path::new(n).components().next().map(|c| base.join(c.as_os_str()));
                roots.iter().any(|r| *r == base)
                    || base.join(".git").exists()
                    || (depth > 1 && first.is_some_and(|f| f.is_dir()))
            }
            // A `.git` pointer's gitdir surface: hold `hooks`, never `config`.
            None => p.file_name().is_some_and(|f| f == "hooks") && p.parent().is_some_and(|d| d.is_dir()),
        };
        if wanted {
            targets.push(p);
        }
    }
    let mut out: Vec<PathBuf> = Vec::new();
    'target: for t in targets {
        let Some(root) = roots.iter().find(|r| t.starts_with(r)) else { continue };
        // Every missing directory from the nearest existing ancestor down; none
        // may be reached through a link.
        let mut chain: Vec<PathBuf> = Vec::new();
        let mut a = Some(t.as_path());
        while let Some(dir) = a {
            match std::fs::symlink_metadata(dir) {
                Ok(m) if m.file_type().is_symlink() => continue 'target,
                Ok(m) if !m.is_dir() => continue 'target,
                Ok(_) => break,
                Err(_) => chain.push(dir.to_path_buf()),
            }
            if dir == root.as_path() {
                break;
            }
            a = dir.parent();
        }
        let mut b = Some(t.as_path());
        while let Some(dir) = b {
            if dir == root.as_path() {
                break;
            }
            if std::fs::symlink_metadata(dir).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
                continue 'target;
            }
            b = dir.parent();
        }
        for d in chain.into_iter().rev() {
            if !out.contains(&d) {
                out.push(d);
            }
        }
    }
    out
}

/// Explicit write-denies whose path does not exist yet. An ACE cannot name a
/// missing object and Windows has no per-name rule, so the run is refused rather
/// than left able to create them.
pub fn absent_write_denies(policy: &Policy) -> Vec<PathBuf> {
    policy
        .fs_rules
        .iter()
        .filter(|r| r.access == Access::Deny && !canon(&r.path).exists())
        .map(|r| r.path.clone())
        .collect()
}

/// Environment variables Windows programs need to start at all (Winsock fails
/// without `SystemRoot`, cmd without `COMSPEC`). None carries a credential.
/// `USERPROFILE`/`LOCALAPPDATA`/`APPDATA` are required by CreateProcess itself for
/// an AppContainer: it rewrites them to the container's folder, and fails with
/// ERROR_ENVVAR_NOT_FOUND (203) when they are missing (measured).
pub const WINDOWS_ENV_BASELINE: &[&str] = &[
    "SystemRoot", "windir", "SystemDrive", "COMSPEC", "PATHEXT", "OS",
    "USERPROFILE", "LOCALAPPDATA", "APPDATA",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "ProgramFiles",
    "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles",
];

/// How the agent is confined. The policy model is the same for both; what
/// differs is how much of it each tier can enforce without admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Default, no admin ever: an AppContainer. Reads are deny-by-default (only
    /// granted paths are readable), stricter than the neutral model.
    AppContainer,
    /// Admin once (`setup/sandbox-user.ps1 install`), unprivileged per run: a
    /// dedicated local user. Reads follow the neutral model (everything the
    /// setup made readable, minus per-run deny ACEs, which bind a user SID).
    SandboxUser,
}

impl Tier {
    /// `TARTAROS_WINDOWS_TIER=sandbox-user` selects the dedicated user; anything
    /// else (or unset) the AppContainer.
    pub fn from_env() -> Tier {
        match std::env::var("TARTAROS_WINDOWS_TIER").as_deref() {
            Ok("sandbox-user") => Tier::SandboxUser,
            _ => Tier::AppContainer,
        }
    }
}

const DELETE: u32 = 0x1_0000;
const FILE_GENERIC_READ: u32 = 0x12_0089;
const FILE_GENERIC_WRITE: u32 = 0x12_0116;
const FILE_GENERIC_EXECUTE: u32 = 0x12_00A0;
const FILE_ALL_ACCESS: u32 = 0x1F_01FF;
/// Write data/append/EA/attributes, delete, delete-child, change DACL or owner.
/// Not SYNCHRONIZE or READ_CONTROL: denying those breaks reads too.
const DENY_WRITE: u32 = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | DELETE | 0x4_0000 | 0x8_0000;

/// The ACEs the sandbox user gets on one path for `grant`, as SDDL ACE strings.
/// Unlike an AppContainer, a deny ACE binds a user SID, so protection is an
/// explicit deny (which wins over the inherited write grant) and the object's
/// DACL is never frozen. No FILE_DELETE_CHILD is ever granted: a child is only
/// deleted through its own DELETE, which a deny can withhold.
pub fn user_aces(grant: Grant, sid: &str) -> Vec<String> {
    let rwx = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;
    let rx = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    match grant {
        Grant::Write => vec![format!("A;;0x{rwx:x};;;{sid}"), format!("A;OICIIO;0x{:x};;;{sid}", rwx | DELETE)],
        Grant::Read => vec![format!("A;OICI;0x{rx:x};;;{sid}")],
        Grant::ExecFile => vec![format!("A;;0x{rx:x};;;{sid}")],
        // The ancestor itself cannot be deleted or renamed; its children keep
        // the inherited write grant.
        Grant::Pin => vec![format!("D;;0x{DELETE:x};;;{sid}")],
        Grant::ProtectReadOnly => vec![format!("D;OICI;0x{DENY_WRITE:x};;;{sid}")],
        Grant::ProtectNoAccess => vec![format!("D;OICI;0x{FILE_ALL_ACCESS:x};;;{sid}")],
    }
}

/// The Windows backend; the tier comes from [`Tier::from_env`] at each call.
pub struct WindowsBackend;

impl Backend for WindowsBackend {
    fn name(&self) -> &str {
        match Tier::from_env() {
            Tier::AppContainer => "windows-appcontainer",
            Tier::SandboxUser => "windows-sandbox-user",
        }
    }

    fn validate(&self, policy: &Policy) -> Result<(), PolicyError> {
        AppContainerBackend.validate(policy)
    }

    fn run(&self, policy: &Policy, command: &[String]) -> Result<RunOutcome, RunError> {
        match Tier::from_env() {
            Tier::AppContainer => AppContainerBackend.run(policy, command),
            Tier::SandboxUser => {
                self.validate(policy).map_err(|e| RunError { reason: e.reason })?;
                if command.is_empty() {
                    return Err(RunError { reason: "empty command".into() });
                }
                #[cfg(windows)]
                {
                    sys::run_sandbox_user(policy, command)
                }
                #[cfg(not(windows))]
                {
                    Err(RunError { reason: "the Windows backend only runs on Windows".into() })
                }
            }
        }
    }
}

pub struct AppContainerBackend;

impl Backend for AppContainerBackend {
    fn name(&self) -> &str {
        "windows-appcontainer"
    }

    fn validate(&self, policy: &Policy) -> Result<(), PolicyError> {
        if !cfg!(windows) {
            return Err(PolicyError { reason: "the Windows backend only runs on Windows".into() });
        }
        if policy.writable_roots.is_empty() {
            return Err(PolicyError { reason: "no writable roots".into() });
        }
        for r in policy.writable_roots.iter().chain(&policy.read_allows).chain(&policy.read_denies) {
            if !r.is_absolute() {
                return Err(PolicyError { reason: format!("path must be absolute: {}", r.display()) });
            }
        }
        policy.check_symlinked_roots().map_err(|reason| PolicyError { reason })?;
        let mut unsupported: Vec<&str> = Vec::new();
        match policy.network {
            None | Some(Network::Denied) => {}
            Some(Network::ProxyOnly(_)) | Some(Network::Allowed) => {
                unsupported.push("network other than denied (the egress broker channel is not built on Windows yet)")
            }
        }
        // Domain-scoped egress is the sandbox-user tier routed through a loopback
        // broker on a fixed port the setup allowed via WFP. It needs that tier and
        // a configured broker port; otherwise refuse rather than run open.
        let wants_domains = !policy.allow_domains.is_empty() || !policy.allowed_hosts.is_empty();
        if wants_domains {
            if Tier::from_env() != Tier::SandboxUser {
                unsupported.push("--allow-domain / allowed hosts (needs the sandbox-user tier: TARTAROS_WINDOWS_TIER=sandbox-user)");
            } else if configured_broker_port().is_none() {
                unsupported.push("--allow-domain / allowed hosts (run setup/sandbox-user.ps1 install -BrokerPort <port> once, elevated, to allow a broker channel)");
            }
        }
        // Arbitrary local-port grants are not enforceable here (WFP permits only the
        // one broker port); the broker's own port is not added to local_ports on
        // Windows, so a non-empty list is a user-requested --port we cannot honor.
        if !policy.local_ports.is_empty() {
            unsupported.push("--port local-port grants (only the egress broker's loopback port is reachable on Windows)");
        }
        if policy.isolate_pids {
            unsupported.push("--isolate-pids (no PID namespace; process listing not yet measured)");
        }
        if policy.isolate_process_info {
            unsupported.push("process-info isolation (not yet measured)");
        }
        if policy.harden_syscalls || policy.strict {
            unsupported.push("--seccomp-strict / strict (mitigation policies not built yet)");
        }
        if policy.deny_unix_sockets || !policy.allow_unix_socket_paths.is_empty() || !policy.unix_socket_subpaths.is_empty() {
            unsupported.push("AF_UNIX socket rules");
        }
        if !policy.glob_denies.is_empty() {
            unsupported.push("glob denies");
        }
        if !policy.allow_mach_lookup.is_empty() || !policy.allow_mach_register.is_empty() {
            unsupported.push("Mach services (macOS only)");
        }
        if policy.egress_netns.is_some() {
            unsupported.push("egress network namespace (Linux only)");
        }
        if policy.private_tmp || policy.browser {
            unsupported.push("private tmp / browser profile");
        }
        if !unsupported.is_empty() {
            return Err(PolicyError {
                reason: format!("unsupported on Windows (cannot be enforced here): {}", unsupported.join(", ")),
            });
        }
        // Network posture differs by tier, and this comment is the honest statement
        // of it. AppContainer: no network capability, so no socket reaches the
        // network OR loopback (measured). SandboxUser: egress is blocked by the
        // per-SID firewall rules the one-time setup installs, but those are not
        // re-checked here at run time, and the Windows firewall does not filter
        // loopback, so a service on 127.0.0.1 stays reachable on that tier
        // (measured). `isolate_network` (no external egress) therefore holds on
        // both; full loopback-off holds only on AppContainer. See docs/limits.md.
        Ok(())
    }

    fn run(&self, policy: &Policy, command: &[String]) -> Result<RunOutcome, RunError> {
        self.validate(policy).map_err(|e| RunError { reason: e.reason })?;
        if command.is_empty() {
            return Err(RunError { reason: "empty command".into() });
        }
        #[cfg(windows)]
        {
            sys::run(policy, command)
        }
        #[cfg(not(windows))]
        {
            Err(RunError { reason: "the Windows backend only runs on Windows".into() })
        }
    }
}

/// Entry point of `tartaros-wfp.exe` (admin setup helper). Returns a process
/// exit code. See `wfp` for what it installs.
#[cfg(windows)]
pub fn wfp_main(args: Vec<String>) -> i32 {
    let fail = |m: String| {
        eprintln!("tartaros-wfp: {m}");
        2
    };
    match args.first().map(String::as_str) {
        Some("install") => {
            let Some(sid) = args.get(1) else { return fail("usage: install <sid> [--allow-loopback-port <port>]".into()) };
            let port = match args.iter().position(|a| a == "--allow-loopback-port") {
                Some(i) => match args.get(i + 1).and_then(|p| p.parse::<u16>().ok()) {
                    Some(p) => Some(p),
                    None => return fail("--allow-loopback-port needs a port number".into()),
                },
                None => None,
            };
            match unsafe { wfp::install(sid, port) } {
                Ok(()) => 0,
                Err(e) => fail(e),
            }
        }
        Some("uninstall") => match unsafe { wfp::uninstall() } {
            Ok(()) => 0,
            Err(e) => fail(e),
        },
        Some("check") => {
            if unsafe { wfp::block_installed() } { 0 } else { 1 }
        }
        _ => fail("usage: tartaros-wfp install|uninstall|check".into()),
    }
}

/// Entry point of `tartaros-sbx-runner.exe`, the sandbox-user tier's second
/// hop (see `sys::sandbox_runner_main`). Never returns.
pub fn sandbox_runner_main() -> ! {
    #[cfg(windows)]
    {
        sys::sandbox_runner_main()
    }
    #[cfg(not(windows))]
    {
        eprintln!("tartaros-sbx-runner only runs on Windows");
        std::process::exit(125)
    }
}

/// The fixed loopback port the sandbox-user egress broker must bind, as stored
/// by `setup/sandbox-user.ps1 install -BrokerPort`. `None` means the setup
/// installed the default block-all (no domain egress); the CLI then refuses
/// `--allow-domain` on this host. The WFP permit for this exact port was
/// installed, with admin, at setup time, so the unprivileged run needs no admin.
pub fn configured_broker_port() -> Option<u16> {
    #[cfg(windows)]
    {
        sys::reg_dword_port("BrokerPort")
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Whether the current process runs elevated (an admin token). The bench uses it
/// for the `admin` requirement.
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        sys::is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn protect_through_a_symlink_out_of_root_is_dropped() {
        let tmp = std::env::temp_dir().join(format!("tt-sym-{}", std::process::id()));
        let w = tmp.join("work");
        let secret = tmp.join("secret");
        std::fs::create_dir_all(&w).unwrap();
        std::fs::create_dir_all(&secret).unwrap();
        // .vscode in the root is a symlink to a directory outside the root.
        std::os::unix::fs::symlink(&secret, w.join(".vscode")).unwrap();
        let p = Policy { writable_roots: vec![w.clone()], ..Default::default() };
        let plan = acl_plan(&p, None);
        let csecret = canon(&secret);
        // nothing in the plan grants or protects the external target
        assert!(!plan.iter().any(|(q, _)| *q == csecret || q.starts_with(&csecret)), "{plan:?}");
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn no_pin_inside_a_write_deny() {
        let tmp = std::env::temp_dir().join(format!("tt-pin-{}", std::process::id()));
        let w = tmp.join("work");
        std::fs::create_dir_all(w.join("proj/out/.mcp.json")).unwrap();
        let p = Policy {
            writable_roots: vec![w.clone(), w.join("proj/out")],
            fs_rules: vec![tartaros_core::FsRule { path: w.join("proj"), access: Access::Deny, even_if_absent: false }],
            ..Default::default()
        };
        let plan = acl_plan(&p, None);
        let c = |q: &Path| canon(q);
        assert!(!plan.iter().any(|(q, g)| *g == Grant::Pin && q.starts_with(c(&w.join("proj")))), "{plan:?}");
        assert!(!plan.iter().any(|(q, g)| *g == Grant::Write && *q == c(&w.join("proj/out"))));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn placeholders_hold_absent_names_only_where_they_matter() {
        let tmp = std::env::temp_dir().join(format!("tt-ph-{}", std::process::id()));
        let w = tmp.join("work");
        for d in ["repo/.git", "sub/src", "nested/.claude", "link-target"] {
            std::fs::create_dir_all(w.join(d)).unwrap();
        }
        std::fs::write(w.join(".gitmodules"), "x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(w.join("link-target"), w.join("lnk")).unwrap();
        let p = Policy { writable_roots: vec![w.clone()], ..Default::default() };
        let plan = placeholder_plan(&p);
        let has = |rel: &str| plan.contains(&w.join(rel));
        // top level, parents first
        assert!(has(".mcp.json") && has(".claude") && has(".claude/agents") && !has(".git/hooks"));
        let ci = plan.iter().position(|x| *x == w.join(".claude")).unwrap();
        let ai = plan.iter().position(|x| *x == w.join(".claude/agents")).unwrap();
        assert!(ci < ai);
        // existing names are left alone
        assert!(!has(".gitmodules"));
        // a repo's hooks and its root names
        assert!(has("repo/.git/hooks") && has("repo/.gitattributes"));
        assert!(!has("repo/.git/config"));
        // an existing first component pulls in its nested names, nothing else does
        assert!(has("nested/.claude/agents") && !has("nested/.mcp.json"));
        assert!(!has("sub/.gitattributes") && !has("sub/src/.gitattributes"));
        // never through a link
        assert!(!plan.iter().any(|x| x.starts_with(w.join("lnk"))));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn sandbox_user_protects_with_deny_aces() {
        let sid = "S-1-5-21-1-2-3-1001";
        let w = user_aces(Grant::Write, sid);
        // write grant: never FILE_DELETE_CHILD (0x40), DELETE only for children
        assert!(w.iter().all(|a| u32::from_str_radix(a.split(';').nth(2).unwrap().trim_start_matches("0x"), 16).unwrap() & 0x40 == 0));
        assert!(w[0].starts_with("A;;") && w[1].starts_with("A;OICIIO;"));
        assert!(user_aces(Grant::Pin, sid)[0].starts_with("D;;0x10000;"));
        let ro = &user_aces(Grant::ProtectReadOnly, sid)[0];
        assert!(ro.starts_with("D;OICI;"));
        let mask = u32::from_str_radix(ro.split(';').nth(2).unwrap().trim_start_matches("0x"), 16).unwrap();
        // write, delete and DACL change denied; read/synchronize untouched
        assert_eq!(mask & (0x2 | 0x10000 | 0x40000), 0x2 | 0x10000 | 0x40000);
        assert_eq!(mask & (0x1 | 0x10_0000 | 0x2_0000), 0);
        assert!(user_aces(Grant::ProtectNoAccess, sid)[0].starts_with("D;OICI;0x1f01ff;"));
    }

    use std::fs;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tartaros-win-plan-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    #[test]
    fn handoff_gets_pinned_ancestors_and_read_only_protect() {
        let root = tmp("pin");
        fs::create_dir_all(root.join("a/nested/.git/hooks")).unwrap();
        fs::write(root.join("a/nested/.git/config"), "").unwrap();
        let p = Policy { writable_roots: vec![root.clone()], ..Default::default() };
        let plan = acl_plan(&p, None);
        assert_eq!(plan[0], (root.clone(), Grant::Write));
        let pins: Vec<_> = plan.iter().filter(|(_, g)| *g == Grant::Pin).map(|(p, _)| p.clone()).collect();
        assert_eq!(pins, vec![root.join("a"), root.join("a/nested"), root.join("a/nested/.git")]);
        assert!(plan.contains(&(root.join("a/nested/.git/hooks"), Grant::ProtectReadOnly)));
        assert!(plan.contains(&(root.join("a/nested/.git/config"), Grant::ProtectReadOnly)));
        // the root itself is never pinned (it has its own no-DELETE grant)
        assert!(!pins.contains(&root));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn read_deny_comes_last_and_absent_paths_are_skipped() {
        let root = tmp("deny");
        fs::create_dir_all(root.join("secrets")).unwrap();
        let p = Policy {
            writable_roots: vec![root.clone()],
            read_denies: vec![root.join("secrets"), root.join("missing")],
            ..Default::default()
        };
        let plan = acl_plan(&p, None);
        assert_eq!(plan.last().unwrap(), &(root.join("secrets"), Grant::ProtectNoAccess));
        assert!(!plan.iter().any(|(p, _)| p.ends_with("missing")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn program_outside_grants_gets_exec_on_the_file_only() {
        let root = tmp("exec");
        let p = Policy { writable_roots: vec![root.clone()], ..Default::default() };
        let prog = PathBuf::from("/opt/tools/busybox.exe");
        let plan = acl_plan(&p, Some(&prog));
        assert!(plan.contains(&(prog, Grant::ExecFile)));
        let inside = root.join("bin/sh.exe");
        assert!(!acl_plan(&p, Some(&inside)).iter().any(|(_, g)| *g == Grant::ExecFile));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn nested_root_under_a_write_deny_gets_no_grant() {
        let root = tmp("nested");
        fs::create_dir_all(root.join("proj/out")).unwrap();
        let p = Policy {
            writable_roots: vec![root.clone(), root.join("proj/out")],
            fs_rules: vec![tartaros_core::FsRule { path: root.join("proj"), access: Access::Deny, even_if_absent: true }],
            ..Default::default()
        };
        let plan = acl_plan(&p, None);
        assert!(!plan.contains(&(root.join("proj/out"), Grant::Write)));
        assert!(plan.contains(&(root.join("proj"), Grant::ProtectReadOnly)));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn write_deny_inside_read_deny_keeps_no_read() {
        let root = tmp("rdwd");
        fs::create_dir_all(root.join("secrets/sub")).unwrap();
        let p = Policy {
            writable_roots: vec![root.clone()],
            read_denies: vec![root.join("secrets")],
            fs_rules: vec![tartaros_core::FsRule { path: root.join("secrets/sub"), access: Access::Deny, even_if_absent: true }],
            ..Default::default()
        };
        let plan = acl_plan(&p, None);
        assert!(plan.contains(&(root.join("secrets/sub"), Grant::ProtectNoAccess)));
        assert!(!plan.iter().any(|(_, g)| *g == Grant::ProtectReadOnly));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn read_deny_ancestors_are_pinned_and_missing_roots_ignored() {
        let root = tmp("rdpin");
        fs::create_dir_all(root.join("a/.secrets")).unwrap();
        let p = Policy {
            writable_roots: vec![root.clone(), root.join("missing")],
            read_denies: vec![root.join("a/.secrets")],
            ..Default::default()
        };
        let plan = acl_plan(&p, None);
        assert!(plan.contains(&(root.join("a"), Grant::Pin)));
        assert!(!plan.iter().any(|(p, _)| p.ends_with("missing")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_refuses_what_it_cannot_enforce() {
        let p = Policy {
            writable_roots: vec![std::env::temp_dir()],
            isolate_pids: true,
            ..Default::default()
        };
        assert!(AppContainerBackend.validate(&p).is_err());
    }
}
