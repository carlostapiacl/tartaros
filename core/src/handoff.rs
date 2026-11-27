//! The trust-handoff set: files a trusted tool outside the sandbox later runs or
//! loads, and the walk that protects them at any depth under each writable root.

use crate::Access;
use crate::FsRule;
use std::path::Path;
use std::path::PathBuf;
use crate::Policy;
use crate::paths::resolve_best_effort;

/// Files a *trusted tool outside the sandbox* later runs, loads, or scans,
/// expressed relative to a directory. These are the real escape surface.
///
/// `.git/hooks` and `.git/config` are handled separately, per git repo found,
/// so they protect nested repos too.
pub const HANDOFF_CONFIG_NAMES: &[&str] = &[
    // Agent/MCP config a trusted agent later loads and ACTS ON (launches an MCP
    // server, runs a slash-command, loads a skill/subagent) — passive RCE across
    // the trust boundary if the sandboxed agent can plant them.
    ".mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/commands",
    ".claude/agents",
    ".claude/skills",
    ".claude/hooks",
    // Codex CLI config/prompts a trusted Codex run later loads and acts on —
    // the same passive-RCE surface as .claude, protected as a whole directory.
    ".codex",
    // goose loads from the project: plugins (`.agents/plugins`, whose
    // `hooks/hooks.json` runs shell commands at session start), skills, agents
    // and recipes (`.agents/*`, `.goose/*`; a recipe declares extensions it
    // starts), all enabled by default. Whole directories, like `.codex`.
    // `.config/goose` holds the project plugin settings (`settings.json`,
    // `settings.local.json`) that decide which of them are on; under HOME it is
    // also the user config whose `config.yaml` lists the extensions goose starts.
    // Only that subdirectory: the rest of `.config/` is ordinary project files.
    ".agents",
    ".goose",
    ".config/goose",
    // Editor auto-run surfaces: tasks/launch/extensions and workspace files a
    // trusted editor runs or trusts on open. Protected as whole directories, since
    // the auto-run surface is more than three JSON files (extensions.json,
    // *.code-workspace, .idea/runConfigurations, …).
    ".vscode",
    ".idea",
    // Git hooks relocated via core.hooksPath (Husky and friends).
    ".husky",
    // Git handoff beyond hooks/config: clean/smudge filters, submodule URLs.
    ".gitattributes",
    ".gitmodules",
    // Shell-into-the-repo and commit-time runners.
    ".envrc",
    ".pre-commit-config.yaml",
    // CI that a host runner later executes.
    ".github/workflows",
];

/// Within any git repository, the files a later `git` invocation executes or
/// reads from the host, outside the box.
pub const HANDOFF_GIT_NAMES: &[&str] = &[".git/hooks", ".git/config", ".git/config.worktree"];

/// What git reads, per linked worktree, from `.git/worktrees/<name>/`:
/// `config.worktree` is config (`core.hooksPath`), and `commondir` names the
/// gitdir whose hooks and config the worktree uses. Either one, written, points
/// a trusted `git` in that worktree at hooks the agent planted.
pub const HANDOFF_WORKTREE_NAMES: &[&str] = &["config.worktree", "commondir"];

/// Directory handoff surfaces, as path SUFFIXES. If a writable root is named
/// *inside* one of these (e.g. a root under `<repo>/.git/hooks/`), the downward
/// walk from that root never sees the enclosing surface, so it would be granted
/// wholesale — letting the agent plant a hook through a root nobody should have
/// put there. These suffixes let the policy detect that upward and deny the root.
/// Only directories a trusted tool later *runs from* are listed; `.git/objects`,
/// `.git/refs`, … are deliberately absent (a root there is legitimate).
pub const HANDOFF_DIR_SUFFIXES: &[&str] = &[
    ".git/hooks",
    ".claude/commands", ".claude/agents", ".claude/skills", ".claude/hooks",
    ".codex", ".vscode", ".idea", ".husky", ".github/workflows",
    ".agents", ".goose", ".config/goose",
];

/// Per-USER startup/config files a trusted tool or the host's next shell later
/// runs or sources, when the workspace is (or becomes) HOME or a tool reads them
/// from the directory: shell rc files and per-user tool config with run-command
/// hooks (`.gitconfig` core.fsmonitor/core.pager, `.ripgreprc` pre-processor).
///
/// These are NOT in the default handoff set because protecting them breaks the
/// legitimate case of editing one's own dotfiles inside the sandbox (a dotfiles
/// repo is exactly a writable root full of these names). They are an OPT-IN:
/// `Policy::protect_home_handoff` adds them to the deny set, for when the
/// workspace is known not to be a dotfiles repo and the home-handoff surface is
/// in scope. Denied even if absent, like the config names.
pub const HANDOFF_HOME_NAMES: &[&str] = &[
    ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile",
    ".gitconfig", ".ripgreprc",
];

/// How deep the walk for nested markers goes. A real tree rarely nests repos
/// deeper than this; the bound keeps a pathological tree from stalling us.
/// Bound on the handoff-discovery walk (guards against pathological depth and
/// recursion blow-up). Real repositories are far shallower; a tree that exceeds
/// this is handled fail-safe (see `walk`) rather than silently left writable.
pub(crate) const MAX_WALK_DEPTH: usize = 64;


impl Policy {
    /// Whether the trust-handoff set applies. Always, except in a security-bench
    /// build that turns it off for `--mutate` (feature `mutation-testing`).
    pub fn trust_handoff_on(&self) -> bool {
        #[cfg(feature = "mutation-testing")]
        {
            !self.mutation_drop_trust_handoff
        }
        #[cfg(not(feature = "mutation-testing"))]
        {
            true
        }
    }

    /// The absent top-level trust-handoff config paths that
    /// `materialize_absent_handoff` would create (files, and dirs for the ones
    /// ending without an extension like `.github/workflows`).
    pub fn handoff_placeholders(&self) -> Vec<PathBuf> {
        if !self.trust_handoff_on() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let names = self.handoff_config_names();
        for root in &self.writable_roots {
            for name in &names {
                let p = root.join(name);
                if !p.exists() {
                    out.push(p);
                }
            }
            if self.protect_home_handoff {
                for name in HANDOFF_HOME_NAMES {
                    let p = root.join(name);
                    if !p.exists() {
                        out.push(p);
                    }
                }
            }
        }
        out
    }
}


pub(crate) fn deny(path: PathBuf, even_if_absent: bool) -> FsRule {
    FsRule { path, access: Access::Deny, even_if_absent }
}

/// Is this writable root named inside a directory handoff surface? True when a
/// STRICT ancestor of the root (its real path) ends with one of
/// `HANDOFF_DIR_SUFFIXES` (`<…>/.git/hooks`, `<…>/.vscode`, …). The root itself
/// is not a surface — a root that *is* exactly `.git/hooks` is handled by the
/// downward walk; here we catch a root planted *below* one.
pub(crate) fn root_inside_handoff_surface(root: &Path) -> bool {
    let real = resolve_best_effort(root);
    let mut anc = real.parent();
    while let Some(a) = anc {
        if HANDOFF_DIR_SUFFIXES.iter().any(|suf| a.ends_with(suf)) {
            return true;
        }
        anc = a.parent();
    }
    false
}

/// Carve the Landlock write allow-list for one root (see
/// [`Policy::linux_write_allowlist`]).
pub(crate) fn carve(dir: &Path, denied: &[PathBuf], out: &mut Vec<PathBuf>) {
    // This dir is itself a protected path: grant nothing here.
    if denied.iter().any(|d| d == dir) {
        return;
    }
    // Does any protected path lie strictly under this dir?
    let has_denied_below = denied.iter().any(|d| d.starts_with(dir) && d != dir);
    if !has_denied_below {
        // Safe subtree: grant the whole thing.
        out.push(dir.to_path_buf());
        return;
    }
    // A protected path is below: cannot grant this dir wholesale. Recurse into
    // children, granting the safe ones and carving the unsafe branch. Files
    // directly in this dir are not granted (the documented tradeoff).
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            // Never grant a symlink entry: the rule would be opened through the
            // link and land on its TARGET, which may be a denied path or lie
            // outside the territory. The target keeps whatever its own real path
            // is granted (reads and writes through the link check the target).
            continue;
        }
        if !meta.is_dir() {
            // A regular file here that is not itself denied stays writable.
            if !denied.iter().any(|d| d == &path) {
                out.push(path);
            }
            continue;
        }
        carve(&path, denied, out);
    }
}

pub(crate) fn expand_root(root: &Path, names: &[&str], home: bool, out: &mut Vec<FsRule>) {
    // Top-level config handoff files: deny even if absent.
    for name in names {
        out.push(deny(root.join(name), true));
    }
    // Opt-in home-handoff names, same treatment (deny even if absent).
    if home {
        for name in HANDOFF_HOME_NAMES {
            out.push(deny(root.join(name), true));
        }
    }
    walk(root, 0, true, names, home, out);
}

/// Recursive walk. At each directory, protect a repo's git handoff files if the
/// directory is a git repo, and protect any config handoff files that exist.
pub(crate) fn walk(dir: &Path, depth: usize, is_root: bool, names: &[&str], home: bool, out: &mut Vec<FsRule>) {
    if depth > MAX_WALK_DEPTH {
        // Fail-safe: beyond the discovery bound we cannot verify which
        // trust-handoff paths live below, so deny write to the whole subtree
        // instead of silently leaving it writable. The carve excludes it, so a
        // deep `.git/hooks` can never become writable just by being far down.
        out.push(deny(dir.to_path_buf(), true));
        return;
    }
    if is_git_repo(dir) {
        let dotgit = dir.join(".git");
        if dotgit.is_file() {
            // Worktree / submodule: `.git` is a FILE holding `gitdir: <path>`.
            // Rewriting it repoints the repo at attacker-controlled hooks, so deny
            // writing the pointer itself...
            out.push(deny(dotgit.clone(), true));
            // ...and follow the pointer: if the real gitdir falls under a writable
            // root, its hooks/config are a live handoff surface that nothing else
            // protects (that directory has no `.git` of its own, so the walk never
            // sees it as a repo). Deny them at the resolved location.
            if let Some(gitdir) = read_gitdir_pointer(&dotgit, dir) {
                out.push(deny(gitdir.join("hooks"), true));
                out.push(deny(gitdir.join("config"), true));
                // A linked worktree's gitdir is `<main>/.git/worktrees/<name>`.
                for name in HANDOFF_WORKTREE_NAMES {
                    out.push(deny(gitdir.join(name), true));
                }
                deny_git_modules_handoff(&gitdir.join("modules"), 0, out);
            }
        } else {
            for name in HANDOFF_GIT_NAMES {
                out.push(deny(dir.join(name), true));
            }
            // Submodule gitdirs live under `.git/modules/<name>/…`; their hooks and
            // config are the same handoff surface. Deny those (leaving objects/refs
            // writable so submodule operations still work).
            deny_git_modules_handoff(&dotgit.join("modules"), 0, out);
            deny_git_worktrees_handoff(&dotgit.join("worktrees"), out);
        }
    }
    // A handoff name whose first component is a symlink that resolves nowhere (a
    // cycle like `.claude -> .claude-x -> .claude`, or a dangling link) has no
    // inode to protect behind it. Deny the link entry itself, so it cannot be
    // dropped and replaced by a real directory, and where it points, so a
    // dangling target cannot be created: fail closed.
    for name in names.iter().chain(if home { HANDOFF_HOME_NAMES } else { &[] }) {
        let Some(first) = Path::new(name).components().next() else { continue };
        let link = dir.join(first);
        if unresolvable_link(&link) {
            out.push(deny(resolve_best_effort(&link), true));
            out.push(deny(link, true));
        }
    }
    if !is_root {
        // Nested config-handoff names are denied even when absent, like the
        // top-level ones: the agent must not be able to CREATE one a trusted tool
        // later runs. (On Linux an absent nested path can only be withheld where a
        // mount namespace is unavailable — the carve covers it; the bind-mount
        // strategy and macOS regex both cover absent paths.)
        for name in names {
            out.push(deny(dir.join(name), true));
        }
        if home {
            for name in HANDOFF_HOME_NAMES {
                out.push(deny(dir.join(name), true));
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
        walk(&path, depth + 1, false, names, home, out);
    }
}

/// Read a `.git` pointer file (`gitdir: <path>`) and resolve it to an absolute,
/// symlink-resolved directory. A relative pointer is taken from the repo dir.
pub(crate) fn read_gitdir_pointer(dotgit: &Path, repo_dir: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(dotgit).ok()?;
    let rest = text.lines().find_map(|l| l.trim().strip_prefix("gitdir:"))?;
    let raw = PathBuf::from(rest.trim());
    let abs = if raw.is_absolute() { raw } else { repo_dir.join(raw) };
    Some(resolve_best_effort(&abs))
}

/// Is `p` a symlink that does not resolve (dangling, or part of a cycle)?
pub fn unresolvable_link(p: &Path) -> bool {
    std::fs::symlink_metadata(p).map(|m| m.file_type().is_symlink()).unwrap_or(false) && std::fs::metadata(p).is_err()
}

/// A git repo is a directory containing `.git` (a dir, or a file for submodules
/// and worktrees that reads `gitdir:`).
fn is_git_repo(dir: &Path) -> bool {
    let dotgit = dir.join(".git");
    dotgit.is_dir() || dotgit.is_file()
}

/// Deny the handoff surface (`hooks/`, `config`) of every submodule gitdir under a
/// repo's `.git/modules`, recursively (bounded) for nested submodules. Only these
/// two are denied, so a submodule's objects/refs stay writable and `git submodule`
/// operations keep working. Each entry directly under a `modules` dir is a
/// submodule gitdir; its own nested submodules live under its `modules`.
pub(crate) fn deny_git_modules_handoff(modules_dir: &Path, depth: usize, out: &mut Vec<FsRule>) {
    if depth > MAX_WALK_DEPTH {
        out.push(deny(modules_dir.to_path_buf(), true));
        return;
    }
    let entries = match std::fs::read_dir(modules_dir) {
        Ok(e) => e,
        Err(_) => return, // no .git/modules (no submodules) or unreadable
    };
    for entry in entries.flatten() {
        let gitdir = entry.path();
        let meta = match std::fs::symlink_metadata(&gitdir) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_dir() || meta.file_type().is_symlink() {
            continue;
        }
        out.push(deny(gitdir.join("hooks"), true));
        out.push(deny(gitdir.join("config"), true));
        deny_git_modules_handoff(&gitdir.join("modules"), depth + 1, out);
    }
}

/// Deny what git reads per linked worktree (`HANDOFF_WORKTREE_NAMES`) under a
/// repo's `.git/worktrees/<name>/`, present or not. The rest of a worktree's
/// gitdir (`HEAD`, `index`, `logs`) stays writable, so work in it goes on.
fn deny_git_worktrees_handoff(worktrees_dir: &Path, out: &mut Vec<FsRule>) {
    let Ok(entries) = std::fs::read_dir(worktrees_dir) else { return };
    for entry in entries.flatten() {
        let gitdir = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&gitdir) else { continue };
        if !meta.is_dir() || meta.file_type().is_symlink() {
            continue;
        }
        for name in HANDOFF_WORKTREE_NAMES {
            out.push(deny(gitdir.join(name), true));
        }
    }
}

/// Every existing path at or under `dir` that matches `pattern`. No symlink is
/// followed (a link that matches is denied itself), a match is denied whole and
/// not entered, and past the depth bound the subtree is denied rather than left
/// unchecked. `.git` is entered: a pattern can name what is inside it.
pub(crate) fn any_depth_walk(dir: &Path, pattern: &str, depth: usize, out: &mut Vec<FsRule>) {
    if depth > MAX_WALK_DEPTH {
        out.push(deny(dir.to_path_buf(), true));
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if glob_matches(pattern, &path) {
            out.push(deny(path, false));
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if meta.is_dir() && !meta.file_type().is_symlink() {
            any_depth_walk(&path, pattern, depth + 1, out);
        }
    }
}

/// Whether `path` matches a glob pattern, component by component: `**` is any
/// number of components (none included), `*` and `?` stay within one. The same
/// meaning the macOS backend compiles to a regex, so `why` agrees with a run.
pub fn glob_matches(pattern: &str, path: &Path) -> bool {
    fn seg(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => seg(&p[1..], s) || (!s.is_empty() && seg(p, &s[1..])),
            (Some(b'?'), Some(_)) => seg(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a == b => seg(&p[1..], &s[1..]),
            _ => false,
        }
    }
    fn comps(p: &[&str], s: &[&str]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(&"**") => comps(&p[1..], s) || (!s.is_empty() && comps(p, &s[1..])),
            Some(c) => !s.is_empty() && seg(c.as_bytes(), s[0].as_bytes()) && comps(&p[1..], &s[1..]),
        }
    }
    let p: Vec<&str> = pattern.split('/').filter(|c| !c.is_empty()).collect();
    let text = path.to_string_lossy();
    let s: Vec<&str> = text.split('/').filter(|c| !c.is_empty()).collect();
    comps(&p, &s)
}

/// `<base>/**/<suffix>` with no other glob, split, or None. A trailing `/**` on
/// the suffix is dropped: a deny on a directory already holds everything in it.
pub fn any_depth_split(pattern: &str) -> Option<(PathBuf, String)> {
    let (base, suffix) = pattern.split_once("/**/")?;
    let suffix = suffix.strip_suffix("/**").unwrap_or(suffix);
    let glob = |t: &str| t.contains('*') || t.contains('?') || t.contains('[');
    if base.is_empty() || suffix.is_empty() || glob(base) || glob(suffix) {
        return None;
    }
    Some((PathBuf::from(base), suffix.to_string()))
}

pub(crate) fn dedup(rules: &mut Vec<FsRule>) {
    rules.sort_by(|a, b| a.path.cmp(&b.path).then((a.access as u8).cmp(&(b.access as u8))));
    rules.dedup();
}
