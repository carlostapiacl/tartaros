//! Compiling a `Policy` into what a backend enforces: the write and read
//! allow-lists, the trust-handoff rules under each writable root, `why`, and the
//! checks that refuse a policy before it runs.

use crate::Access;
use crate::FsRule;
use crate::handoff::HANDOFF_CONFIG_NAMES;
use crate::handoff::HANDOFF_GIT_NAMES;
use crate::handoff::HANDOFF_HOME_NAMES;
use crate::handoff::HANDOFF_WORKTREE_NAMES;
use std::path::Path;
use std::path::PathBuf;
use crate::Policy;
use crate::handoff::any_depth_walk;
use crate::handoff::carve;
use crate::handoff::dedup;
use crate::handoff::deny;
use crate::handoff::deny_git_modules_handoff;
use crate::handoff::expand_root;
use crate::handoff::glob_matches;
use crate::handoff::read_gitdir_pointer;
use crate::paths::resolve_best_effort;
use crate::handoff::root_inside_handoff_surface;
use crate::handoff::unresolvable_link;

impl Policy {
    /// Compile this policy's writable roots + denies into a Landlock-style
    /// **write allow-list**: a set of subtree roots the agent may write under,
    /// with every protected path carved out.
    ///
    /// Landlock cannot express "allow X but deny X/y" (nono refuses such a
    /// policy outright). TartarOS restructures instead: it grants the safe
    /// subtrees and excludes the branch that leads to each protected path. This
    /// is the TartarOS advantage on Linux.
    ///
    /// Tradeoff (honest): Landlock grants are hierarchical, so a directory that
    /// *contains* a protected path cannot itself be granted — the agent cannot
    /// create files **directly in** such a directory (its safe children are
    /// still fully writable). For paths where that matters, the Linux backend
    /// falls back to bwrap. `linux_write_allowlist` reports the allow set; the
    /// caller decides.
    pub fn linux_write_allowlist(&self) -> Vec<PathBuf> {
        self.linux_write_allowlist_except(&|_| false)
    }

    /// [`linux_write_allowlist`] without carving the denies `already_protected`
    /// says need no carve: the backend passes the ones on a read-only mount (an
    /// outer sandbox's read-only bind), which the kernel refuses to write, unlink
    /// or rename whatever Landlock grants. Carving them would withhold their
    /// parent, the whole root for a top-level `.bashrc`, for nothing.
    pub fn linux_write_allowlist_except(&self, already_protected: &dyn Fn(&Path) -> bool) -> Vec<PathBuf> {
        // Explicit write denies are kept even when the path does not exist yet:
        // the carve then withholds the nearest existing ancestor (only its
        // existing children are granted), so the absent path cannot be created.
        // The implicit trust-handoff names are kept only where they exist; for
        // absent ones see the note below.
        let explicit: Vec<PathBuf> = self
            .fs_rules
            .iter()
            .filter(|r| r.access == Access::Deny)
            .map(|r| resolve_best_effort(&r.path))
            .collect();
        let mut denied: Vec<PathBuf> = self.trust_handoff_rules().into_iter().map(|r| r.path).collect();
        // Landlock protects by inode: a path that does not exist cannot be
        // carved out of an allow (and an absent name can still be created inside
        // a granted dir). So on Linux we only carve denies that EXIST; absent
        // trust-handoff files are a macOS/Seatbelt strength (regex denies cover
        // not-yet-existing paths) that Landlock cannot match. Without this an
        // empty writable root would be made fully unwritable by absent denies.
        // Landlock matches inodes, so carve on the REAL paths: a deny written
        // through a symlinked directory must exclude the directory it resolves to.
        // A link that resolves nowhere is carved as the entry it is: its parent is
        // withheld, so the link cannot be removed or replaced.
        denied = denied.iter().map(|p| if unresolvable_link(p) { p.clone() } else { resolve_best_effort(p) }).collect();
        denied.retain(|p| p.exists() || unresolvable_link(p));
        denied.extend(explicit);
        denied.retain(|p| !already_protected(p));
        denied.sort();
        denied.dedup();

        let mut out = Vec::new();
        for root in &self.writable_roots {
            let root = resolve_best_effort(root);
            // A root nested inside a deny (`--write proj/out --write-deny proj`):
            // the deny wins, as on macOS and in sandbox-runtime.
            if denied.iter().any(|d| root.starts_with(d) && *d != root) {
                continue;
            }
            carve(&root, &denied, &mut out);
        }
        out
    }

    /// Read allow-list for Linux: everything is readable except the `read_denies`
    /// (secret dirs), carved out of a read grant on `/`. Same inode caveat as the
    /// write carve — only existing paths are carved.
    pub fn linux_read_allowlist(&self) -> Vec<PathBuf> {
        let mut denied: Vec<PathBuf> = self.read_denies.clone();
        // Defense-in-depth for cross-process env reads (P1-3): exclude /proc from
        // the read grant so `/proc/<pid>/environ` of another process is not
        // readable. NOTE: the primary protection is the kernel — with Yama
        // `ptrace_scope >= 1` (Ubuntu default) an unrelated process's environ is
        // already blocked; this also covers `ptrace_scope = 0`. Measured: ordinary
        // tools (sh, cat, ls, curl, git, python3) still run with /proc excluded.
        if self.isolate_process_info {
            denied.push(PathBuf::from("/proc"));
        }
        // Carve on the real paths (Landlock matches inodes): a deny written through
        // a symlinked directory, or whose last component is a symlink, must hide
        // the file it resolves to, not just the name it was given.
        denied = denied.iter().map(|p| resolve_best_effort(p)).collect();
        denied.retain(|p| p.exists());
        // A deny on a path that does not exist yet (`~/.aws/credentials` before a
        // login writes it) withholds its nearest existing ancestor instead: only
        // what is there now is granted, so whatever appears later stays unreadable.
        denied.extend(self.absent_read_denies().into_iter().map(|(_, first)| first));
        let mut out = if denied.is_empty() {
            vec![PathBuf::from("/")]
        } else {
            denied.sort();
            denied.dedup();
            let mut o = Vec::new();
            carve(Path::new("/"), &denied, &mut o);
            o
        };
        // Re-allow explicit read_allows: a Landlock read grant on a subtree that
        // lies inside a denied parent re-permits exactly that branch — but a MORE
        // SPECIFIC deny inside that branch must stay denied (deny runs/ → allow
        // runs/mine/ → deny runs/mine/settings.json). A flat grant of the branch
        // would re-open the deeper secret (security bug). So we carve the
        // re-allowed subtree too, excluding any denies that fall within it. The
        // deepest rule wins, matching the macOS specificity order.
        // Writable roots are re-allowed like explicit read_allows: a root inside a
        // read-deny must stay readable (writing to a dir the agent cannot read
        // back breaks ordinary work; sandbox-runtime does the same). Denies deeper
        // inside the root are still carved out below.
        let roots_in_denies = self.writable_roots.iter().filter(|r| {
            let r = resolve_best_effort(r);
            denied.iter().any(|d| r.starts_with(d) && r != *d)
        });
        let allows: Vec<&PathBuf> = self.read_allows.iter().chain(roots_in_denies).collect();
        for given in &allows {
            if !given.exists() {
                continue;
            }
            let a = &resolve_best_effort(given);
            // A re-allow only re-opens the branch it NAMES. If it reaches a denied
            // area only by following a symlink (the name itself is not inside any
            // deny), granting it would re-open a secret through a planted link.
            let named_inside = self.read_denies.iter().any(|d| given.starts_with(d) || given.starts_with(resolve_best_effort(d)));
            let lands_inside = denied.iter().any(|d| a.starts_with(d));
            if lands_inside && !named_inside {
                continue;
            }
            // Named inside a deny too (a deny on `/`, the granted model, holds
            // every name): a re-allow redirected by a symlink inside a writable
            // root (one the agent could have planted) still re-opens only what
            // another re-allow already covers by its own real path. So
            // `work/docs -> ~/.ssh` re-opens nothing, while system links such as
            // `/lib -> usr/lib` or macOS `/var -> private/var` are untouched.
            if lands_inside && self.link_in_writable_root(given) {
                let covered = allows.iter().any(|o| {
                    o.as_path() != given.as_path() && {
                        let r = resolve_best_effort(o);
                        r == **o && a.starts_with(&r)
                    }
                });
                if !covered {
                    continue;
                }
            }
            // Exact contradiction (the SAME path is both read-denied and
            // re-allowed): the deny wins, fail-safe. Equal depth is a tie, and a
            // security tool must resolve a tie to the more restrictive rule rather
            // than re-open the secret. Skip re-allowing it.
            if denied.iter().any(|d| d.as_path() == a.as_path()) {
                continue;
            }
            let inner: Vec<PathBuf> =
                denied.iter().filter(|d| d.starts_with(a) && d.as_path() != a.as_path()).cloned().collect();
            if inner.is_empty() {
                out.push(a.to_path_buf());
            } else {
                carve(a, &inner, &mut out);
            }
        }
        out
    }

    /// Does reaching `path` follow a symlink that sits inside a writable root,
    /// i.e. a link the agent could have planted?
    fn link_in_writable_root(&self, path: &Path) -> bool {
        let roots: Vec<PathBuf> = self.writable_roots.iter().map(|r| resolve_best_effort(r)).collect();
        let mut prefix = PathBuf::new();
        for c in path.components() {
            prefix.push(c);
            let is_link = std::fs::symlink_metadata(&prefix).map(|m| m.file_type().is_symlink()).unwrap_or(false);
            if is_link {
                let at = prefix.parent().map(resolve_best_effort).unwrap_or_default();
                if roots.iter().any(|r| at.starts_with(r)) {
                    return true;
                }
            }
        }
        false
    }

    /// Handoff surfaces reached through a SYMLINK whose name is a handoff segment
    /// (e.g. `proj/.claude -> ../dotfiles/claude`). The Seatbelt pattern rules match
    /// the literal `.claude/...` spelling, but the kernel canonicalises through the
    /// link, so the resolved target (`dotfiles/claude/commands`, with no handoff
    /// name in its real path) would be writable. These are found by a BOUNDED scan
    /// that inspects only directory-entry names and types (no per-path stat storm)
    /// and resolves just the matching symlinks. It inspects at most `cap` directories
    /// over all the roots: first the roots inside `project`, then the others, one
    /// directory from each in turn, so a huge cache listed first does not leave a small
    /// root unread. It returns the denies and the roots it did not finish. The
    /// non-symlinked surfaces stay fully covered by the patterns regardless, so an
    /// unfinished root (a huge writable root like a cache) degrades only this symlink
    /// edge, with a warning — it never hangs and never refuses a large root.
    pub fn symlinked_handoff_denies(&self, cap: usize, project: Option<&Path>) -> (Vec<PathBuf>, Vec<PathBuf>) {
        if !self.trust_handoff_on() {
            return (Vec::new(), Vec::new());
        }
        // Split each handoff name into (first segment, remainder) once.
        let names = self.handoff_config_names();
        let splits: Vec<(&str, Option<&str>)> = names
            .iter()
            .map(|n| match n.split_once('/') {
                Some((a, b)) => (a, Some(b)),
                None => (*n, None),
            })
            .collect();
        // The same directory reached twice (/var/folders and /private/var/folders)
        // would spend its share twice.
        let mut roots: Vec<PathBuf> = Vec::new();
        for root in &self.writable_roots {
            let root = resolve_best_effort(root);
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
        let project = project.map(resolve_best_effort);
        let (inside, outside): (Vec<PathBuf>, Vec<PathBuf>) = roots
            .into_iter()
            .partition(|r| project.as_ref().is_some_and(|p| r.starts_with(p)));

        let mut out: Vec<PathBuf> = Vec::new();
        let mut unfinished: Vec<PathBuf> = Vec::new();
        let mut budget = cap;
        for group in [inside, outside] {
            let mut walks: Vec<(PathBuf, Vec<PathBuf>)> =
                group.into_iter().map(|r| (r.clone(), vec![r])).collect();
            while budget > 0 && walks.iter().any(|(_, stack)| !stack.is_empty()) {
                for (_, stack) in &mut walks {
                    if budget == 0 {
                        break;
                    }
                    let Some(dir) = stack.pop() else { continue };
                    budget -= 1;
                    let entries = match std::fs::read_dir(&dir) {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    for entry in entries.flatten() {
                        let ft = match entry.file_type() {
                            Ok(t) => t,
                            Err(_) => continue,
                        };
                        if ft.is_symlink() {
                            let name = entry.file_name();
                            let name = name.to_string_lossy();
                            for (first, rest) in &splits {
                                if name == *first {
                                    let target = resolve_best_effort(&entry.path());
                                    out.push(match rest {
                                        Some(r) => target.join(r),
                                        None => target,
                                    });
                                }
                            }
                        } else if ft.is_dir() {
                            // Do not descend into a real `.git` dir (internals handled
                            // by the patterns) — and never follow a symlinked dir.
                            if entry.file_name() != ".git" {
                                stack.push(entry.path());
                            }
                        }
                    }
                }
            }
            unfinished.extend(walks.into_iter().filter(|(_, stack)| !stack.is_empty()).map(|(root, _)| root));
        }
        out.sort();
        out.dedup();
        (out, unfinished)
    }

    /// Resolved handoff surfaces (`hooks/`, `config`, submodule `modules/`) of a
    /// git checkout whose `.git` is a POINTER FILE (`gitdir: <path>`). A
    /// regex/pattern deny can't express these: the target directory has no `.git`
    /// of its own and its name is arbitrary, so it is found only by reading the
    /// pointer. The macOS backend (pattern-based) adds these as literal denies.
    ///
    /// Anchored at each writable ROOT — O(number of roots), NOT O(tree). The only
    /// relocated gitdir a pattern misses is a worktree/submodule *checkout* whose
    /// own `.git` is a pointer file; that `.git` sits at the checkout root, i.e. at
    /// a writable root. (A nested real `.git` dir, a submodule's
    /// `.git/modules/.../hooks`, and the main repo's `.git/hooks` are all covered
    /// any-depth by the pattern rules.) This is what Codex/srt do — resolve the
    /// workspace's gitdir — rather than walk the whole writable tree, which on a
    /// large root (a cache, `node_modules`) cost tens of seconds and a huge profile.
    pub fn gitdir_pointer_handoff(&self) -> Vec<PathBuf> {
        if !self.trust_handoff_on() {
            return Vec::new();
        }
        let mut out: Vec<PathBuf> = Vec::new();
        for root in &self.writable_roots {
            let dotgit = root.join(".git");
            if !dotgit.is_file() {
                continue; // a real `.git` dir (or none): patterns cover it
            }
            if let Some(gitdir) = read_gitdir_pointer(&dotgit, root) {
                out.push(gitdir.join("hooks"));
                out.push(gitdir.join("config"));
                out.extend(HANDOFF_WORKTREE_NAMES.iter().map(|n| gitdir.join(n)));
                let mut modules = Vec::new();
                deny_git_modules_handoff(&gitdir.join("modules"), 0, &mut modules);
                out.extend(modules.into_iter().map(|r| r.path));
            }
        }
        out.sort();
        out.dedup();
        out
    }

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
        if !self.trust_handoff_on() {
            return Vec::new();
        }
        let names = self.handoff_config_names();
        let mut out = Vec::new();
        for root in &self.writable_roots {
            expand_root(root, &names, self.protect_home_handoff, &mut out);
        }
        out.retain(|r| !self.handoff_exempted(&r.path));
        // Upward check: a writable root named INSIDE a handoff surface (e.g. under
        // `<repo>/.git/hooks/`) is denied wholesale — the downward walk can't see
        // the enclosing surface, so without this the root would be fully writable
        // and a hook could be planted through it. A sibling root under
        // `.git/objects` is untouched (not a handoff surface).
        for p in self.ancestor_handoff_denies() {
            out.push(deny(p, true));
        }
        dedup(&mut out);
        out
    }

    /// Which rule decides an access, from the policy alone (`tartaros why`): the
    /// question a denied agent cannot ask the kernel on every platform (Landlock
    /// reports nothing before 6.15). `(allowed, the rule)`. It follows the
    /// backends' precedence; what it cannot see (a path created later through a
    /// symlink, a host's missing capability) `explain` and the run say.
    /// `absent_held` is the backend's answer for a handoff path that does not
    /// exist: whether the run puts something there to deny (a placeholder).
    pub fn why(&self, path: &Path, write: bool, absent_held: &dyn Fn(&Path) -> bool) -> (bool, String) {
        let real = resolve_best_effort(path);
        if let Some(g) = self.glob_denies.iter().find(|g| (if write { g.write } else { g.read }) && glob_matches(&g.pattern, &real)) {
            return (false, format!("{}-denied by the pattern {}", if write { "write" } else { "read" }, g.pattern));
        }
        if !write {
            let mut decision: Option<(usize, bool, String)> = None;
            for d in &self.read_denies {
                let d = resolve_best_effort(d);
                if real.starts_with(&d) && decision.as_ref().is_none_or(|(n, _, _)| d.components().count() >= *n) {
                    decision = Some((d.components().count(), false, format!("read-denied by {}", d.display())));
                }
            }
            for a in &self.read_allows {
                let a = resolve_best_effort(a);
                if real.starts_with(&a) && decision.as_ref().is_some_and(|(n, allowed, _)| !*allowed && a.components().count() > *n) {
                    decision = Some((a.components().count(), true, format!("re-allowed by {} inside a read-deny", a.display())));
                }
            }
            return match decision {
                Some((_, allowed, why)) => (allowed, why),
                None => (true, "readable: only a read-deny stops a read".into()),
            };
        }
        let Some(root) = self.writable_roots.iter().map(|r| resolve_best_effort(r)).filter(|r| real.starts_with(r)).max_by_key(|r| r.components().count()) else {
            return (false, "outside every writable root".into());
        };
        for r in self.fs_rules.iter().filter(|r| r.access == Access::Deny) {
            let d = resolve_best_effort(&r.path);
            if real.starts_with(&d) {
                return (false, format!("write-denied by {}", d.display()));
            }
        }
        for r in self.any_depth_rules() {
            let d = resolve_best_effort(&r.path);
            if real.starts_with(&d) {
                return (false, format!("write-denied by {} (an any-depth deny)", d.display()));
            }
        }
        if root_inside_handoff_surface(&root) {
            return (false, format!("the writable root {} lies inside a trust-handoff surface", root.display()));
        }
        if self.handoff_exempted(&real) {
            let scratch = self.handoff_scratch.iter().any(|s| real.starts_with(resolve_best_effort(s)));
            let flag = if scratch { "--handoff-scratch, discarded after the run" } else { "--handoff-exempt" };
            return (true, format!("writable root {}; trust-handoff not protected here ({flag})", root.display()));
        }
        let rel: Vec<String> = real.strip_prefix(&root).unwrap_or(&real).components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
        let home: &[&str] = if self.protect_home_handoff { HANDOFF_HOME_NAMES } else { &[] };
        let config = self.handoff_config_names();
        let named = config.iter().chain(HANDOFF_GIT_NAMES).chain(home).find(|name| {
            let n: Vec<&str> = name.split('/').collect();
            rel.windows(n.len()).any(|w| w.iter().zip(&n).all(|(a, b)| a == b))
        });
        // macOS denies a handoff name at any depth by pattern; Linux and Windows
        // deny the concrete paths `trust_handoff_rules` expands to, which leave
        // out a new name in a nested directory (docs/limits.md).
        if cfg!(target_os = "macos") {
            if let Some(name) = named {
                return (false, format!("trust-handoff: {name} is protected at any depth under {}", root.display()));
            }
        } else if let Some(rule) = self.trust_handoff_rules().into_iter().find(|r| {
            let d = resolve_best_effort(&r.path);
            r.access == Access::Deny && real.starts_with(&d) && (std::fs::symlink_metadata(&d).is_ok() || absent_held(&d))
        }) {
            let name = named.copied().unwrap_or("a handoff path");
            return (false, format!("trust-handoff: {name}, denied at {}", resolve_best_effort(&rule.path).display()));
        } else if let Some(name) = named {
            return (true, format!("writable root {}; a new {name} in a subdirectory is not held on this platform (docs/limits.md)", root.display()));
        }
        (true, format!("writable root {}", root.display()))
    }

    /// `any_depth_denies` as concrete deny rules: every existing path under a
    /// writable root that matches the pattern (`glob_matches`, the macOS regex's
    /// meaning), `.git` included, and a writable root that is itself a match or
    /// inside one, whole.
    pub fn any_depth_rules(&self) -> Vec<FsRule> {
        let mut out = Vec::new();
        for (base, pattern) in &self.any_depth_denies {
            let base = resolve_best_effort(base);
            for root in &self.writable_roots {
                let root = resolve_best_effort(root);
                let start = if root.starts_with(&base) {
                    if root.ancestors().take_while(|a| a.starts_with(&base)).any(|a| glob_matches(pattern, a)) {
                        out.push(deny(root.clone(), false));
                        continue;
                    }
                    root
                } else if base.starts_with(&root) {
                    base.clone()
                } else {
                    continue;
                };
                any_depth_walk(&start, pattern, 0, &mut out);
            }
        }
        dedup(&mut out);
        out
    }

    /// Every directory where the trust-handoff set is not protected: the
    /// `handoff_exempt` dependency trees and the `handoff_scratch` roots. The one
    /// list every backend and every explanation reads, so the two kinds can never
    /// be opened in one place and enforced in another.
    pub fn handoff_open(&self) -> impl Iterator<Item = &PathBuf> {
        self.handoff_exempt.iter().chain(&self.handoff_scratch)
    }

    /// The trust-handoff config names this run protects: `HANDOFF_CONFIG_NAMES`
    /// without the ones `handoff_allow` opens. Every backend builds its rules
    /// from this list, so an opened name is open on all of them alike.
    pub fn handoff_config_names(&self) -> Vec<&'static str> {
        HANDOFF_CONFIG_NAMES.iter().copied().filter(|n| !self.handoff_allow.iter().any(|a| a == n)).collect()
    }

    /// `handoff_allow` names only entries of the config set. An unknown name is
    /// refused rather than ignored, and the git surfaces are refused with where to
    /// go instead.
    pub fn check_handoff_allow(&self) -> Result<(), String> {
        for a in &self.handoff_allow {
            if HANDOFF_CONFIG_NAMES.contains(&a.as_str()) {
                continue;
            }
            if HANDOFF_GIT_NAMES.contains(&a.as_str()) || a.starts_with(".git/") || a == ".git" {
                return Err(format!(
                    "--allow-handoff {a}: the git surfaces cannot be opened for the whole run; \
                     use --handoff-scratch for a throwaway root or --handoff-exempt for one directory"
                ));
            }
            if HANDOFF_HOME_NAMES.contains(&a.as_str()) {
                return Err(format!("--allow-handoff {a}: a home-handoff name; use --allow-home-handoff"));
            }
            return Err(format!(
                "--allow-handoff {a}: not a trust-handoff name (one of: {})",
                HANDOFF_CONFIG_NAMES.join(", ")
            ));
        }
        Ok(())
    }

    /// Whether `path` lies in a `handoff_exempt` directory (resolved).
    pub fn handoff_exempted(&self, path: &Path) -> bool {
        if self.handoff_exempt.is_empty() && self.handoff_scratch.is_empty() {
            return false;
        }
        let p = resolve_best_effort(path);
        self.handoff_open().any(|e| p.starts_with(resolve_best_effort(e)))
    }

    /// `handoff_exempt` refuses what would turn the exemption into a hole: a
    /// directory that is not strictly inside a writable root, is a writable root
    /// itself, lies inside a handoff surface (`.git/hooks/x`), or is named like
    /// one (`.claude`, `.git`). Err carries the reason (refused, exit 78).
    ///
    /// `handoff_scratch` is the other way round — it must BE a writable root — and
    /// refuses every root a later reader could trust: one that holds or sits in
    /// another writable root (the repo is one), holds `$HOME` or the directory the
    /// run starts in, is a git repository itself, or lies in a handoff surface.
    pub fn check_handoff_exempt(&self) -> Result<(), String> {
        self.check_handoff_allow()?;
        self.check_handoff_scratch(std::env::var_os("HOME").map(PathBuf::from).as_deref(), std::env::current_dir().ok().as_deref())?;
        for e in &self.handoff_exempt {
            if !e.is_absolute() {
                return Err(format!("handoff exemption {}: must be an absolute path", e.display()));
            }
            let real = resolve_best_effort(e);
            let Some(root) = self.writable_roots.iter().map(|r| resolve_best_effort(r)).find(|r| real.starts_with(r) && real != *r) else {
                return Err(format!("handoff exemption {}: must be strictly inside a writable root", e.display()));
            };
            if root_inside_handoff_surface(&real) {
                return Err(format!("handoff exemption {}: lies inside a trust-handoff surface", e.display()));
            }
            // Only below the root: a root that itself lives under, say, ~/.claude is fine.
            let below = real.strip_prefix(&root).unwrap_or(&real);
            let named = below.components().any(|c| {
                let s = c.as_os_str().to_string_lossy();
                HANDOFF_CONFIG_NAMES.iter().chain(HANDOFF_GIT_NAMES).any(|n| n.split('/').next() == Some(&*s))
            });
            if named {
                return Err(format!("handoff exemption {}: names a trust-handoff surface itself", e.display()));
            }
        }
        Ok(())
    }

    /// The `handoff_scratch` half of [`Policy::check_handoff_exempt`], with the
    /// home and the starting directory passed in so it can be tested.
    pub fn check_handoff_scratch(&self, home: Option<&Path>, cwd: Option<&Path>) -> Result<(), String> {
        let roots: Vec<PathBuf> = self.writable_roots.iter().map(|r| resolve_best_effort(r)).collect();
        for s in &self.handoff_scratch {
            let at = |why: &str| Err(format!("handoff scratch {}: {why}", s.display()));
            if !s.is_absolute() {
                return at("must be an absolute path");
            }
            let real = resolve_best_effort(s);
            if !roots.contains(&real) {
                return at("must be a writable root itself (pass it to --write too)");
            }
            if let Some(other) = roots.iter().find(|r| **r != real && (r.starts_with(&real) || real.starts_with(r))) {
                return at(&format!("overlaps the writable root {}: a scratch root holds only what is thrown away", other.display()));
            }
            if real.parent().is_none() {
                return at("is the filesystem root");
            }
            if let Some(h) = home.map(resolve_best_effort) {
                if h.starts_with(&real) {
                    return at("holds $HOME");
                }
            }
            if let Some(c) = cwd.map(resolve_best_effort) {
                if c.starts_with(&real) {
                    return at("holds the directory the run starts in, whose handoff files a tool reads after it");
                }
            }
            if std::fs::symlink_metadata(real.join(".git")).is_ok() {
                return at("is a git repository: its hooks and config outlive the run");
            }
            if root_inside_handoff_surface(&real) {
                return at("lies inside a trust-handoff surface");
            }
        }
        Ok(())
    }

    /// Writable roots that are named INSIDE a directory handoff surface
    /// (`<…>/.git/hooks/inner`, a root under `.vscode`, …). Such a root must not be
    /// granted writable — the downward walk from it never sees the enclosing
    /// surface. The macOS backend emits these as subpath denies; the Linux carve
    /// picks them up through [`trust_handoff_rules`]. Real (resolved) paths.
    pub fn ancestor_handoff_denies(&self) -> Vec<PathBuf> {
        if !self.trust_handoff_on() {
            return Vec::new();
        }
        self.writable_roots
            .iter()
            .filter(|r| root_inside_handoff_surface(r))
            .map(|r| resolve_best_effort(r))
            .collect()
    }
}


impl Policy {
    /// Explicit write denies whose (resolved) path does not exist yet. Landlock
    /// matches inodes, so these can only be enforced by the carve (withholding
    /// the nearest existing ancestor), never by a bind mount.
    pub fn absent_write_denies(&self) -> Vec<PathBuf> {
        self.fs_rules
            .iter()
            .filter(|r| r.access == Access::Deny)
            .map(|r| resolve_best_effort(&r.path))
            .filter(|p| std::fs::symlink_metadata(p).is_err())
            .collect()
    }

    /// Trust-handoff links that resolve nowhere (see [`unresolvable_link`]). A
    /// bind mount cannot cover one (there is nothing to bind), so the Linux
    /// backend carves the policy instead.
    pub fn unresolvable_handoff_links(&self) -> Vec<PathBuf> {
        self.trust_handoff_rules().into_iter().map(|r| r.path).filter(|p| unresolvable_link(p)).collect()
    }

    /// For each read deny whose path does not exist yet, its nearest existing
    /// ancestor: the Linux read carve withholds it (granting its existing children)
    /// and the backend lets it be listed only, so a file created there later, by
    /// the host or another process, cannot be read. Skipped when that ancestor is
    /// `/` or lies inside a writable root: the agent writes there, and withholding
    /// it would keep the agent from reading back what it just wrote.
    pub fn absent_read_deny_holders(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = self.absent_read_denies().into_iter().map(|(holder, _)| holder).collect();
        out.sort();
        out.dedup();
        out
    }

    /// Each absent read deny as (nearest existing ancestor, its first missing
    /// component): the carve is told the second is denied, so it grants the
    /// ancestor's existing children and never the ancestor itself.
    fn absent_read_denies(&self) -> Vec<(PathBuf, PathBuf)> {
        let roots: Vec<PathBuf> = self.writable_roots.iter().map(|r| resolve_best_effort(r)).collect();
        let mut out = Vec::new();
        for d in &self.read_denies {
            let mut first = resolve_best_effort(d);
            if std::fs::symlink_metadata(&first).is_ok() {
                continue;
            }
            let holder = loop {
                let Some(p) = first.parent() else { break None };
                if std::fs::symlink_metadata(p).is_ok() {
                    break Some(p.to_path_buf());
                }
                first = p.to_path_buf();
            };
            let Some(holder) = holder else { continue };
            if holder.parent().is_none() || !holder.is_dir() || roots.iter().any(|r| holder.starts_with(r)) {
                continue;
            }
            out.push((holder, first));
        }
        out
    }

    /// A writable root that is a symlink grants its TARGET. Refuse one whose target
    /// is not inside another (non-symlink) writable root: following it would grant
    /// a directory nobody named (e.g. a link planted by an earlier run).
    pub fn check_symlinked_roots(&self) -> Result<(), String> {
        let plain: Vec<PathBuf> = self
            .writable_roots
            .iter()
            .filter(|r| !std::fs::symlink_metadata(r).map(|m| m.file_type().is_symlink()).unwrap_or(false))
            .map(|r| resolve_best_effort(r))
            .collect();
        for r in &self.writable_roots {
            let is_link = std::fs::symlink_metadata(r).map(|m| m.file_type().is_symlink()).unwrap_or(false);
            if is_link {
                let target = resolve_best_effort(r);
                if !plain.iter().any(|p| target.starts_with(p)) {
                    return Err(format!(
                        "writable root {} is a symlink to {}, which is outside the other writable roots; \
                         name the real directory instead",
                        r.display(),
                        target.display()
                    ));
                }
            }
        }
        Ok(())
    }
}
