//! seisin-sandbox-core — the policy model and backend interface.
//!
//! This crate is the differentiator: it defines *what* seisin-sandbox enforces
//! (the policy, including the trust-handoff set), independent of *how* a given
//! OS enforces it (the backends). Backends are swappable; the policy is not.

use std::path::{Path, PathBuf};

/// What a confined process may do with a filesystem path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    /// Deny wins over any overlapping allow.
    Deny,
}

/// One filesystem rule. A `Deny` over a path that falls inside a broader
/// `Write` is the carve-out the other sandboxes handle poorly (Landlock cannot
/// express it at all; Seatbelt/bwrap need ancestor protection to be safe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsRule {
    pub path: PathBuf,
    pub access: Access,
    /// Apply to this path even if it does not exist yet (a deny must hold for a
    /// path the agent may still create).
    pub even_if_absent: bool,
}

/// Whether the confined process may reach the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Denied,
    /// Only the given loopback proxy port.
    ProxyOnly(u16),
    Allowed,
}

/// Files a *trusted tool outside the sandbox* later runs, loads, or scans,
/// expressed relative to a directory. These are the real escape surface.
///
/// `.git/hooks` and `.git/config` are handled separately, per git repo found,
/// so they protect nested repos too.
pub const HANDOFF_CONFIG_NAMES: &[&str] = &[
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".vscode/tasks.json",
    ".envrc",
    ".github/workflows",
];

/// Within any git repository, the files a later `git` invocation executes or
/// reads from the host, outside the box.
pub const HANDOFF_GIT_NAMES: &[&str] = &[".git/hooks", ".git/config"];

/// How deep the walk for nested markers goes. A real tree rarely nests repos
/// deeper than this; the bound keeps a pathological tree from stalling us.
const MAX_WALK_DEPTH: usize = 40;

/// A complete, backend-independent confinement policy.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Roots the agent may write under.
    pub writable_roots: Vec<PathBuf>,
    /// Explicit filesystem rules; `Deny` always wins over an overlapping allow.
    pub fs_rules: Vec<FsRule>,
    pub network: Option<Network>,
    /// Deny any process-info / environment read of processes outside this
    /// sandbox (macOS `KERN_PROCARGS2`, Linux `/proc/<pid>`).
    pub isolate_process_info: bool,
}

impl Policy {
    /// Expand the trust-handoff set into concrete deny rules under every
    /// writable root, **at any depth** — this is what the measured competitors
    /// miss (they protect only the first level).
    ///
    /// For each git repository found (by a `.git` dir or file at any depth),
    /// `.git/hooks` and `.git/config` are denied, even if they do not exist yet.
    /// Top-level config handoff files are denied even if absent (the agent must
    /// not be able to create them); nested config handoff files are denied where
    /// they already exist.
    pub fn trust_handoff_rules(&self) -> Vec<FsRule> {
        let mut out = Vec::new();
        for root in &self.writable_roots {
            expand_root(root, &mut out);
        }
        dedup(&mut out);
        out
    }
}

fn deny(path: PathBuf, even_if_absent: bool) -> FsRule {
    FsRule { path, access: Access::Deny, even_if_absent }
}

fn expand_root(root: &Path, out: &mut Vec<FsRule>) {
    // Top-level config handoff files: deny even if absent.
    for name in HANDOFF_CONFIG_NAMES {
        out.push(deny(root.join(name), true));
    }
    walk(root, 0, true, out);
}

/// Recursive walk. At each directory, protect a repo's git handoff files if the
/// directory is a git repo, and protect any config handoff files that exist.
fn walk(dir: &Path, depth: usize, is_root: bool, out: &mut Vec<FsRule>) {
    if depth > MAX_WALK_DEPTH {
        return;
    }
    if is_git_repo(dir) {
        for name in HANDOFF_GIT_NAMES {
            out.push(deny(dir.join(name), true));
        }
    }
    if !is_root {
        for name in HANDOFF_CONFIG_NAMES {
            let p = dir.join(name);
            if p.exists() {
                out.push(deny(p, false));
            }
        }
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Do not follow symlinks (a symlink could point outside the root).
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_dir() || meta.file_type().is_symlink() {
            continue;
        }
        // Never descend into a .git directory: its internals are already denied.
        if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
            continue;
        }
        walk(&path, depth + 1, false, out);
    }
}

/// A git repo is a directory containing `.git` (a dir, or a file for submodules
/// and worktrees that reads `gitdir:`).
fn is_git_repo(dir: &Path) -> bool {
    let dotgit = dir.join(".git");
    dotgit.is_dir() || dotgit.is_file()
}

fn dedup(rules: &mut Vec<FsRule>) {
    rules.sort_by(|a, b| a.path.cmp(&b.path).then((a.access as u8).cmp(&(b.access as u8))));
    rules.dedup();
}

/// Outcome of running a command under a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOutcome {
    /// Process exit code, or 128 + signal when killed by a signal.
    pub exit_code: i32,
}

/// An OS-specific enforcement engine.
pub trait Backend {
    fn name(&self) -> &str;

    /// Reject a policy this backend cannot faithfully enforce, rather than
    /// running under-confined.
    fn validate(&self, policy: &Policy) -> Result<(), PolicyError>;

    /// Run `command` confined by `policy`.
    fn run(&self, policy: &Policy, command: &[String]) -> Result<RunOutcome, RunError>;
}

#[derive(Debug, Clone)]
pub struct PolicyError {
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RunError {
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn has_deny(rules: &[FsRule], p: &Path) -> bool {
        rules.iter().any(|r| r.access == Access::Deny && r.path == p)
    }

    #[test]
    fn protects_nested_git_hooks_at_any_depth() {
        let tmp = std::env::temp_dir().join(format!("sbx-th-{}", std::process::id()));
        let root = tmp.join("work");
        let nested = root.join("a").join("b").join("nested");
        fs::create_dir_all(nested.join(".git")).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();

        let policy = Policy { writable_roots: vec![root.clone()], ..Default::default() };
        let rules = policy.trust_handoff_rules();

        // top-level repo
        assert!(has_deny(&rules, &root.join(".git/hooks")));
        // deeply nested repo — the thing the others miss
        assert!(has_deny(&rules, &nested.join(".git/hooks")));
        assert!(has_deny(&rules, &nested.join(".git/config")));

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn top_level_config_denied_even_if_absent() {
        let tmp = std::env::temp_dir().join(format!("sbx-cfg-{}", std::process::id()));
        let root = tmp.join("work");
        fs::create_dir_all(&root).unwrap();

        let policy = Policy { writable_roots: vec![root.clone()], ..Default::default() };
        let rules = policy.trust_handoff_rules();

        let settings = root.join(".claude/settings.json");
        assert!(!settings.exists());
        let r = rules.iter().find(|r| r.path == settings).expect("settings.json must be denied");
        assert_eq!(r.access, Access::Deny);
        assert!(r.even_if_absent);

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn does_not_follow_symlinks_out_of_root() {
        // A symlinked dir inside root must not be walked (it could point out).
        let tmp = std::env::temp_dir().join(format!("sbx-sym-{}", std::process::id()));
        let root = tmp.join("work");
        let outside = tmp.join("outside");
        fs::create_dir_all(outside.join(".git")).unwrap();
        fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        let policy = Policy { writable_roots: vec![root.clone()], ..Default::default() };
        let rules = policy.trust_handoff_rules();
        // The symlinked outside repo's hooks must NOT appear.
        assert!(!has_deny(&rules, &root.join("link/.git/hooks")));

        fs::remove_dir_all(&tmp).ok();
    }
}
