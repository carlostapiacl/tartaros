//! Unit tests of the policy model: the trust-handoff walk, the allow-lists, `why`.

use super::*;

#[test]
fn glob_matches_any_depth_and_one_segment() {
    let m = |p: &str, s: &str| glob_matches(p, Path::new(s));
    assert!(m("/r/**/.claude", "/r/.claude"));
    assert!(m("/r/**/.claude", "/r/a/b/.claude"));
    assert!(!m("/r/**/.claude", "/r/a/.claude/x"));
    assert!(m("/r/**/.claude/**", "/r/a/.claude/x/y"));
    assert!(m("/r/**/.git/worktrees/**/commondir", "/r/.git/worktrees/w/commondir"));
    assert!(!m("/r/**/.git/worktrees/**/commondir", "/r/.git/worktrees/w/HEAD"));
    assert!(m("/h/.codex/*.config.toml", "/h/.codex/a.config.toml"));
    assert!(!m("/h/.codex/*.config.toml", "/h/.codex/x/a.config.toml"));
    assert!(!m("/r/**/.claude", "/other/.claude"));
}

#[test]
fn any_depth_split_takes_only_a_literal_suffix() {
    assert_eq!(any_depth_split("/r/**/.claude/**"), Some((PathBuf::from("/r"), ".claude".into())));
    assert_eq!(any_depth_split("/r/**/.git/config"), Some((PathBuf::from("/r"), ".git/config".into())));
    assert_eq!(any_depth_split("/r/**/.git/modules/**/config"), None);
    assert_eq!(any_depth_split("**/node_modules"), None);
    assert_eq!(any_depth_split("/r/*/x/**/y"), None);
}

#[test]
fn any_depth_rules_deny_what_exists_and_a_root_inside_one() {
    let t = std::env::temp_dir().join(format!("tt-anydepth-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&t);
    for d in ["ws/.claude", "ws/a/b/.claude", "ws/c", "agents/.claude/sub"] {
        std::fs::create_dir_all(t.join(d)).unwrap();
    }
    let t = std::fs::canonicalize(&t).unwrap();
    let p = Policy {
        writable_roots: vec![t.join("ws"), t.join("agents/.claude/sub")],
        any_depth_denies: vec![(t.clone(), format!("{}/**/.claude", t.display()))],
        ..Default::default()
    };
    let got: Vec<PathBuf> = p.any_depth_rules().into_iter().map(|r| r.path).collect();
    assert!(got.contains(&t.join("ws/.claude")), "{got:?}");
    assert!(got.contains(&t.join("ws/a/b/.claude")), "{got:?}");
    assert!(got.contains(&t.join("agents/.claude/sub")), "a root inside a match is denied whole: {got:?}");
    assert!(!got.iter().any(|g| g.ends_with("c/.claude")), "only what exists: {got:?}");
    let _ = std::fs::remove_dir_all(t);
}

#[test]
fn any_depth_rules_follow_the_whole_pattern() {
    // Cases a suffix match missed: a suffix that crosses into a writable
    // root, a match inside `.git`, a `**` inside the suffix at any depth.
    let t = std::env::temp_dir().join(format!("tt-anydepth-p-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&t);
    for d in ["r/a/cache", "r/repo/.git/worktrees/w/extra", "r/b"] {
        std::fs::create_dir_all(t.join(d)).unwrap();
    }
    let t = std::fs::canonicalize(&t).unwrap();
    for f in ["r/a/cache/token", "r/repo/.git/HEAD", "r/repo/.git/worktrees/w/extra/commondir", "r/b/HEADER"] {
        std::fs::write(t.join(f), "x").unwrap();
    }
    let r = t.join("r");
    let pat = |p: &str| (r.clone(), format!("{}/{p}", r.display()));
    let p = Policy {
        writable_roots: vec![r.join("a/cache"), r.join("repo"), r.join("b")],
        any_depth_denies: vec![pat("**/cache/token"), pat("**/HEAD"), pat("**/.git/worktrees/**/commondir")],
        ..Default::default()
    };
    let got: Vec<PathBuf> = p.any_depth_rules().into_iter().map(|r| r.path).collect();
    for want in ["a/cache/token", "repo/.git/HEAD", "repo/.git/worktrees/w/extra/commondir"] {
        assert!(got.contains(&r.join(want)), "{want} not denied: {got:?}");
    }
    assert!(!got.contains(&r.join("b/HEADER")), "a name that only starts like the pattern: {got:?}");
    let _ = std::fs::remove_dir_all(t);
}

#[test]
fn a_linked_worktree_config_and_commondir_are_handoff() {
    let t = std::env::temp_dir().join(format!("tt-worktree-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&t);
    std::fs::create_dir_all(t.join("repo/.git/worktrees/w")).unwrap();
    let t = std::fs::canonicalize(&t).unwrap();
    let p = Policy { writable_roots: vec![t.join("repo")], ..Default::default() };
    let rules: Vec<PathBuf> = p.trust_handoff_rules().into_iter().map(|r| r.path).collect();
    for want in [".git/config.worktree", ".git/worktrees/w/config.worktree", ".git/worktrees/w/commondir"] {
        assert!(rules.contains(&t.join("repo").join(want)), "{want} not denied: {rules:?}");
    }
    assert!(!rules.contains(&t.join("repo/.git/worktrees/w/HEAD")));
    let _ = std::fs::remove_dir_all(t);
}

#[test]
fn a_scratch_root_drops_its_rules_and_refuses_what_a_later_reader_trusts() {
    let base = std::env::temp_dir().join(format!("tt-scratch-{}", std::process::id()));
    let repo = base.join("repo");
    let tmp = base.join("run/tmp");
    std::fs::create_dir_all(repo.join(".git/hooks")).unwrap();
    std::fs::create_dir_all(tmp.join("t/repo/.git/hooks")).unwrap();
    let mut p = Policy { writable_roots: vec![repo.clone(), tmp.clone()], ..Default::default() };
    let has = |p: &Policy, s: &str| p.trust_handoff_rules().iter().any(|r| r.path.to_string_lossy().ends_with(s));
    assert!(has(&p, "t/repo/.git/hooks"));
    p.handoff_scratch = vec![tmp.clone()];
    let home = base.join("home");
    assert!(p.check_handoff_scratch(Some(&home), Some(&repo)).is_ok());
    assert!(!has(&p, "t/repo/.git/hooks"), "the scratch root's rules are dropped");
    assert!(has(&p, "repo/.git/hooks"), "the repo's stay");
    let refused = |roots: Vec<PathBuf>, scratch: PathBuf, home: &Path, cwd: &Path| {
        let q = Policy { writable_roots: roots, handoff_scratch: vec![scratch], ..Default::default() };
        q.check_handoff_scratch(Some(home), Some(cwd)).is_err()
    };
    // Not a root; the repo; overlapping a root; holding $HOME; holding the start; relative.
    assert!(refused(vec![repo.clone()], tmp.clone(), &home, &repo));
    assert!(refused(vec![repo.clone()], repo.clone(), &home, &tmp));
    assert!(refused(vec![repo.clone(), base.clone()], base.clone(), &home, &tmp));
    assert!(refused(vec![tmp.clone()], tmp.clone(), &tmp.join("u"), &repo));
    assert!(refused(vec![tmp.clone()], tmp.clone(), &home, &tmp.join("w")));
    assert!(refused(vec![PathBuf::from("rel")], PathBuf::from("rel"), &home, &repo));
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn handoff_exemption_drops_the_rules_inside_it_and_keeps_the_repos() {
    let base = std::env::temp_dir().join(format!("tt-exempt-{}", std::process::id()));
    let repo = base.join("repo");
    std::fs::create_dir_all(repo.join(".git/hooks")).unwrap();
    std::fs::create_dir_all(repo.join("vendor/pkg/.git/hooks")).unwrap();
    let mut p = Policy { writable_roots: vec![repo.clone()], ..Default::default() };
    let has = |p: &Policy, s: &str| p.trust_handoff_rules().iter().any(|r| r.path.to_string_lossy().ends_with(s));
    assert!(has(&p, "vendor/pkg/.git/hooks"));
    p.handoff_exempt = vec![repo.join("vendor")];
    assert!(p.check_handoff_exempt().is_ok());
    assert!(!has(&p, "vendor/pkg/.git/hooks"));
    assert!(has(&p, "repo/.git/hooks"));
    for bad in [repo.clone(), repo.join(".vscode"), repo.join(".git/hooks/x"), base.join("outside"), PathBuf::from("rel")] {
        p.handoff_exempt = vec![bad.clone()];
        assert!(p.check_handoff_exempt().is_err(), "{} should be refused", bad.display());
    }
    let _ = std::fs::remove_dir_all(base);
}

use std::fs;

fn has_deny(rules: &[FsRule], p: &Path) -> bool {
    rules.iter().any(|r| r.access == Access::Deny && r.path == p)
}

fn get<'a>(env: &'a [(String, String)], k: &str) -> Option<&'a str> {
    env.iter().find(|(ek, _)| ek == k).map(|(_, v)| v.as_str())
}

#[test]
fn env_set_wins_over_inherit_env_and_passthrough() {
    // A masked credential: the launcher holds the real value, the agent must
    // see the sentinel whatever else the policy passes through.
    let launcher = vec![
        ("GH_TOKEN".to_string(), "ghp_real".to_string()),
        ("PATH".to_string(), "/bin".to_string()),
    ];
    let set = vec![("GH_TOKEN".to_string(), "fake_value_x".to_string())];
    for p in [
        Policy { inherit_env: true, env_set: set.clone(), ..Default::default() },
        Policy { env_passthrough: vec!["GH_TOKEN".into()], env_set: set.clone(), ..Default::default() },
        Policy { env_passthrough: vec!["GH_TOKEN=ghp_real".into()], env_set: set.clone(), ..Default::default() },
        Policy { env_set: set.clone(), ..Default::default() },
    ] {
        let env = p.child_env_from(&launcher).unwrap();
        let got: Vec<&String> = env.iter().filter(|(k, _)| k == "GH_TOKEN").map(|(_, v)| v).collect();
        assert_eq!(got, vec!["fake_value_x"], "{:?}", p.inherit_env);
        assert!(!env.iter().any(|(_, v)| v == "ghp_real"));
    }
}

#[test]
fn child_env_scrubs_secrets_keeps_allowlist_by_default() {
    let launcher = vec![
        ("PATH".into(), "/usr/bin".into()),
        ("HOME".into(), "/home/a".into()),
        ("LC_ALL".into(), "C".into()),
        ("AWS_SECRET_ACCESS_KEY".into(), "leak".into()),
        ("GITHUB_TOKEN".into(), "leak2".into()),
    ];
    let p = Policy::default(); // inherit_env = false
    let env = p.child_env_from(&launcher).expect("should scrub, not inherit");
    // allowlisted + LC_* survive; the agent stays functional
    assert_eq!(get(&env, "PATH"), Some("/usr/bin"));
    assert_eq!(get(&env, "HOME"), Some("/home/a"));
    assert_eq!(get(&env, "LC_ALL"), Some("C"));
    // secrets are gone
    assert_eq!(get(&env, "AWS_SECRET_ACCESS_KEY"), None);
    assert_eq!(get(&env, "GITHUB_TOKEN"), None);
}

#[test]
fn child_env_passthrough_and_explicit_set() {
    let launcher = vec![
        ("PATH".into(), "/usr/bin".into()),
        ("AWS_SECRET_ACCESS_KEY".into(), "from-launcher".into()),
    ];
    let p = Policy {
        // KEY carries the launcher's value through; KEY=VALUE sets explicitly;
        // a passthrough naming an absent var is a silent no-op.
        env_passthrough: vec![
            "AWS_SECRET_ACCESS_KEY".into(),
            "MY_FLAG=hello".into(),
            "NOT_PRESENT".into(),
        ],
        ..Default::default()
    };
    let env = p.child_env_from(&launcher).unwrap();
    assert_eq!(get(&env, "AWS_SECRET_ACCESS_KEY"), Some("from-launcher"));
    assert_eq!(get(&env, "MY_FLAG"), Some("hello"));
    assert_eq!(get(&env, "NOT_PRESENT"), None);
}

#[test]
fn child_env_inherit_opts_into_full_passthrough() {
    let launcher = vec![("AWS_SECRET_ACCESS_KEY".into(), "leak".into())];
    let p = Policy { inherit_env: true, ..Default::default() };
    // inherit_env passes secrets through (the caller opted in)
    let env = p.child_env_from(&launcher).unwrap();
    assert_eq!(get(&env, "AWS_SECRET_ACCESS_KEY"), Some("leak"));
}

#[test]
fn child_env_inherit_still_drops_loader_injection() {
    let launcher = vec![
        ("PATH".into(), "/usr/bin".into()),
        ("LD_PRELOAD".into(), "/evil.so".into()),
        ("DYLD_INSERT_LIBRARIES".into(), "/evil.dylib".into()),
        ("BASH_ENV".into(), "/evil.sh".into()),
        ("BASH_FUNC_ls%%".into(), "() { evil; }".into()),
        ("NODE_OPTIONS".into(), "--require /evil.js".into()),
        ("MY_APP_CONFIG".into(), "kept".into()),
    ];
    let p = Policy { inherit_env: true, ..Default::default() };
    let env = p.child_env_from(&launcher).unwrap();
    for k in ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "BASH_FUNC_ls%%", "NODE_OPTIONS"] {
        assert_eq!(get(&env, k), None, "{k} must not be inherited");
    }
    assert_eq!(get(&env, "PATH"), Some("/usr/bin"));
    assert_eq!(get(&env, "MY_APP_CONFIG"), Some("kept"));
    // naming one explicitly is operator intent and is honoured
    let p = Policy { inherit_env: true, env_passthrough: vec!["NODE_OPTIONS".into()], ..Default::default() };
    let env = p.child_env_from(&launcher).unwrap();
    assert_eq!(get(&env, "NODE_OPTIONS"), Some("--require /evil.js"));
}

#[test]
fn child_env_explicit_set_overrides_allowlist_value() {
    let launcher = vec![("PATH".into(), "/usr/bin".into())];
    let p = Policy { env_passthrough: vec!["PATH=/sandbox/bin".into()], ..Default::default() };
    let env = p.child_env_from(&launcher).unwrap();
    // the explicit --env PATH=... wins over the inherited allowlisted PATH,
    // and is not duplicated
    assert_eq!(get(&env, "PATH"), Some("/sandbox/bin"));
    assert_eq!(env.iter().filter(|(k, _)| k == "PATH").count(), 1);
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
fn home_handoff_is_opt_in() {
    let tmp = std::env::temp_dir().join(format!("sbx-home-{}", std::process::id()));
    let root = tmp.join("work");
    fs::create_dir_all(&root).unwrap();
    let bashrc = root.join(".bashrc");
    let gitconfig = root.join(".gitconfig");

    // Default: home-handoff names are NOT denied (a dotfiles repo stays editable).
    let off = Policy { writable_roots: vec![root.clone()], ..Default::default() };
    let off_rules = off.trust_handoff_rules();
    assert!(!off_rules.iter().any(|r| r.path == bashrc), ".bashrc must be writable by default");
    assert!(!off_rules.iter().any(|r| r.path == gitconfig), ".gitconfig must be writable by default");

    // Opt-in: the same names are denied, even if absent.
    let on = Policy { writable_roots: vec![root.clone()], protect_home_handoff: true, ..Default::default() };
    let on_rules = on.trust_handoff_rules();
    let denied = |p: &Path| on_rules.iter().any(|r| r.path == *p && r.access == Access::Deny && r.even_if_absent);
    assert!(denied(&bashrc), ".bashrc must be denied under protect_home_handoff");
    assert!(denied(&gitconfig), ".gitconfig must be denied under protect_home_handoff");
    // A non-handoff file stays writable even with the flag on.
    assert!(!on_rules.iter().any(|r| r.path == root.join("src.rs")));

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn symlinked_handoff_dir_is_resolved_but_scan_is_bounded() {
    let tmp = std::env::temp_dir().join(format!("sbx-slh-{}", std::process::id()));
    // proj/.claude is a symlink into a dotfiles tree inside the root.
    fs::create_dir_all(tmp.join("work/dotfiles/claude/commands")).unwrap();
    fs::create_dir_all(tmp.join("work/proj/src")).unwrap();
    let root = tmp.join("work").canonicalize().unwrap();
    std::os::unix::fs::symlink("../dotfiles/claude", root.join("proj/.claude")).unwrap();

    let policy = Policy { writable_roots: vec![root.clone()], ..Default::default() };
    let (denies, unfinished) = policy.symlinked_handoff_denies(10_000, None);
    assert!(unfinished.is_empty(), "a tiny tree must not hit the cap");
    let resolved_commands = resolve_best_effort(&root.join("dotfiles/claude/commands"));
    assert!(denies.iter().any(|p| p == &resolved_commands),
        "the symlink's resolved .claude/commands target must be denied");
    // A plain sub-directory is never pinned by this scan.
    assert!(!denies.iter().any(|p| p == &root.join("proj/src")));

    // The cap is honoured: cap 0 names the root and resolves nothing.
    let (empty, unfinished0) = policy.symlinked_handoff_denies(0, None);
    assert!(empty.is_empty());
    assert_eq!(unfinished0, vec![resolve_best_effort(&root)]);

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn symlink_scan_reads_the_project_first_and_then_takes_turns() {
    let tmp = std::env::temp_dir().join(format!("sbx-slt-{}", std::process::id()));
    // A cache with more directories than the budget, listed first.
    for i in 0..40 {
        fs::create_dir_all(tmp.join(format!("cache/d{i}"))).unwrap();
    }
    fs::create_dir_all(tmp.join("small/inner")).unwrap();
    fs::create_dir_all(tmp.join("repo/own/inner")).unwrap();
    fs::create_dir_all(tmp.join("dotfiles/a")).unwrap();
    fs::create_dir_all(tmp.join("dotfiles/b")).unwrap();
    let base = tmp.canonicalize().unwrap();
    std::os::unix::fs::symlink(base.join("dotfiles/a"), base.join("repo/own/inner/.claude")).unwrap();
    std::os::unix::fs::symlink(base.join("dotfiles/b"), base.join("small/inner/.claude")).unwrap();

    let policy = Policy {
        writable_roots: vec![base.join("cache"), base.join("small"), base.join("repo/own")],
        ..Default::default()
    };
    // Two directories for the project, and the rest split between two roots.
    let (denies, unfinished) = policy.symlinked_handoff_denies(8, Some(&base.join("repo")));
    assert!(denies.iter().any(|p| p.starts_with(base.join("dotfiles/a"))), "the project's own");
    assert!(denies.iter().any(|p| p.starts_with(base.join("dotfiles/b"))), "the small root after the cache");
    assert_eq!(unfinished, vec![base.join("cache")]);

    // A root reached by two spellings is walked, and reported, once.
    let twice = Policy {
        writable_roots: vec![base.join("cache"), base.join("repo/../cache")],
        ..Default::default()
    };
    assert_eq!(twice.symlinked_handoff_denies(1, None).1, vec![base.join("cache")]);

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn gitdir_pointer_handoff_resolves_root_pointer_not_the_tree() {
    let tmp = std::env::temp_dir().join(format!("sbx-ptr-{}", std::process::id()));
    // A worktree/submodule checkout: `.git` at the writable root is a POINTER
    // FILE to a relocated gitdir elsewhere. Also a config-handoff dir and a
    // plain sub-dir, to prove neither is enumerated here.
    fs::create_dir_all(tmp.join("work/src")).unwrap();
    fs::create_dir_all(tmp.join("work/.vscode")).unwrap();
    fs::create_dir_all(tmp.join("gitdir/hooks")).unwrap();
    let root = tmp.join("work").canonicalize().unwrap();
    let gitdir = tmp.join("gitdir").canonicalize().unwrap();
    fs::write(root.join(".git"), format!("gitdir: {}\n", gitdir.display())).unwrap();

    let policy = Policy { writable_roots: vec![root.clone()], ..Default::default() };
    let surfaces = policy.gitdir_pointer_handoff();
    // The relocated gitdir's hooks/config ARE resolved (a regex can't express
    // this arbitrary path).
    assert!(surfaces.iter().any(|p| p == &gitdir.join("hooks")),
        "the relocated gitdir's hooks must be resolved");
    assert!(surfaces.iter().any(|p| p == &gitdir.join("config")),
        "the relocated gitdir's config must be resolved");
    // Config-handoff dirs and plain sub-dirs are NOT enumerated here — the
    // pattern rules cover the former, and enumerating the latter is what made
    // the cost scale with the tree.
    assert!(!surfaces.iter().any(|p| p == &root.join(".vscode")),
        ".vscode is covered by the pattern rules, not enumerated here");
    assert!(!surfaces.iter().any(|p| p == &root.join("src")),
        "a plain sub-directory must never be pinned");

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn a_read_deny_on_an_absent_path_withholds_its_nearest_ancestor() {
    let tmp = std::env::temp_dir().join(format!("sbx-late-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("home/proj")).unwrap();
    fs::create_dir_all(tmp.join("work")).unwrap();
    let base = tmp.canonicalize().unwrap();
    let policy = Policy {
        writable_roots: vec![base.join("work"), base.join("home/proj")],
        // ~/.aws does not exist yet; work/later.txt is inside a root.
        read_denies: vec![base.join("home/.aws/credentials"), base.join("work/later.txt")],
        ..Default::default()
    };
    assert_eq!(policy.absent_read_deny_holders(), vec![base.join("home")]);
    let allow = policy.linux_read_allowlist();
    assert!(!allow.iter().any(|p| p == &base.join("home") || base.join("home").starts_with(p)),
        "home (and so a later .aws in it) must not be readable: {allow:?}");
    assert!(allow.contains(&base.join("home/proj")), "what is in home now stays readable: {allow:?}");
    assert!(allow.iter().any(|p| base.join("work").starts_with(p)), "the root stays readable: {allow:?}");
    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn a_handoff_link_that_resolves_nowhere_is_carved_as_the_link() {
    let tmp = std::env::temp_dir().join(format!("sbx-cyc-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let root = tmp.join("work");
    fs::create_dir_all(root.join("proj/src")).unwrap();
    fs::create_dir_all(root.join("other")).unwrap();
    let root = root.canonicalize().unwrap();
    // proj/.claude is a cycle; other/.vscode dangles at a target in the root.
    std::os::unix::fs::symlink(root.join("proj/.claude-x"), root.join("proj/.claude")).unwrap();
    std::os::unix::fs::symlink(root.join("proj/.claude"), root.join("proj/.claude-x")).unwrap();
    std::os::unix::fs::symlink(root.join("other/real"), root.join("other/.vscode")).unwrap();
    let policy = Policy { writable_roots: vec![root.clone()], ..Default::default() };
    let links = policy.unresolvable_handoff_links();
    assert!(links.contains(&root.join("proj/.claude")), "the cyclic link is a handoff entry: {links:?}");
    assert!(links.contains(&root.join("other/.vscode")), "the dangling link too: {links:?}");
    let allow = policy.linux_write_allowlist();
    // The links' directories are withheld, so neither link can be removed or
    // replaced, nor the dangling target created; their real children stay writable.
    assert!(!allow.contains(&root.join("proj")), "proj must not be granted: {allow:?}");
    assert!(!allow.contains(&root.join("other")), "other must not be granted: {allow:?}");
    assert!(allow.contains(&root.join("proj/src")), "proj/src stays writable: {allow:?}");
    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn a_writable_root_nested_inside_a_write_deny_is_not_granted() {
    // `--write proj --write proj/out --write-deny proj`: the deny wins over
    // the nested root, as on macOS; the outer root keeps its other entries.
    let tmp = std::env::temp_dir().join(format!("sbx-nrd-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("work/proj/out")).unwrap();
    fs::create_dir_all(tmp.join("work/docs")).unwrap();
    let work = tmp.join("work").canonicalize().unwrap();
    let policy = Policy {
        writable_roots: vec![work.clone(), work.join("proj/out")],
        fs_rules: vec![FsRule { path: work.join("proj"), access: Access::Deny, even_if_absent: false }],
        ..Default::default()
    };
    let allow = policy.linux_write_allowlist();
    assert!(!allow.iter().any(|g| g.starts_with(work.join("proj"))), "nothing under the deny: {allow:?}");
    assert!(allow.contains(&work.join("docs")), "the rest of the outer root stays writable: {allow:?}");
    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn writable_root_inside_handoff_surface_is_denied() {
    let tmp = std::env::temp_dir().join(format!("sbx-rih-{}", std::process::id()));
    // One root inside .git/hooks (a surface), a sibling under .git/objects (not).
    let inside = tmp.join("repo/.git/hooks/inner");
    let objects = tmp.join("repo/.git/objects");
    fs::create_dir_all(&inside).unwrap();
    fs::create_dir_all(&objects).unwrap();

    let policy = Policy {
        writable_roots: vec![inside.clone(), objects.clone()],
        ..Default::default()
    };
    let denied = policy.ancestor_handoff_denies();
    // The root beneath .git/hooks is denied; the one beneath .git/objects is not.
    assert!(denied.iter().any(|p| p == &resolve_best_effort(&inside)),
        "a root inside .git/hooks must be denied");
    assert!(!denied.iter().any(|p| p == &resolve_best_effort(&objects)),
        "a root inside .git/objects is legitimate and stays writable");

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn linux_allowlist_carves_out_nested_git() {
    let tmp = std::env::temp_dir().join(format!("sbx-carve-{}", std::process::id()));
    let root = tmp.join("work");
    // work/src (safe), work/a/nested/.git (protected), work/a/other (safe)
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("a/nested/.git/hooks")).unwrap();
    fs::create_dir_all(root.join("a/nested/.git/objects")).unwrap();
    fs::create_dir_all(root.join("a/other")).unwrap();
    // The allow-list is on real paths (Landlock matches inodes); compare on them.
    let root = root.canonicalize().unwrap();

    let policy = Policy { writable_roots: vec![root.clone()], ..Default::default() };
    let allow = policy.linux_write_allowlist();

    let granted = |p: &Path| allow.iter().any(|a| p.starts_with(a));
    // safe subtrees are writable
    assert!(granted(&root.join("src/x")));
    assert!(granted(&root.join("a/other/y")));
    // git internals that are NOT handoff files stay writable (git needs them)
    assert!(granted(&root.join("a/nested/.git/objects/ab")));
    // the protected handoff dirs are NOT writable
    assert!(!granted(&root.join("a/nested/.git/hooks/pre-commit")));
    assert!(!granted(&root.join("a/nested/.git/config")));

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

/// Does the allow-list grant `x` (the backend grants PathBeneath per entry, so
/// a path is allowed iff it is under or equal to a granted entry)?
fn granted(allow: &[PathBuf], x: &Path) -> bool {
    allow.iter().any(|a| x.starts_with(a))
}

#[test]
fn profiles_escalate_and_stay_honest() {
    // local-agent adds no namespace/IPC hardening and makes no claim to fix.
    let mut p = Policy::default();
    Profile::LocalAgent.apply(&mut p);
    assert!(!p.isolate_pids && !p.isolate_network && !p.deny_unix_sockets);
    assert!(Profile::LocalAgent.caveat().is_none());

    // hostile-code hides the host (PID ns) and locks down AF_UNIX, but keeps
    // the agent's own /proc readable (no blunt isolate_process_info).
    let mut h = Policy::default();
    Profile::HostileCode.apply(&mut h);
    assert!(h.isolate_pids && h.deny_unix_sockets && h.harden_syscalls && h.strict);
    assert!(!h.isolate_process_info, "isolate_pids supersedes the /proc read-deny");
    assert!(!h.isolate_network, "hostile-code is not offline by default");
    assert!(Profile::HostileCode.caveat().unwrap().contains("kernel"));

    // multi-tenant adds full egress-off AND must never claim kernel isolation.
    let mut m = Policy::default();
    Profile::MultiTenant.apply(&mut m);
    assert!(m.isolate_pids && m.deny_unix_sockets && m.isolate_network);
    let c = Profile::MultiTenant.caveat().unwrap();
    assert!(c.contains("NOT PROVIDED") && c.contains("microVM"));

    // profiles only tighten: an explicit network grant survives apply().
    let mut net = Policy { network: Some(Network::Allowed), ..Default::default() };
    Profile::HostileCode.apply(&mut net);
    assert_eq!(net.network, Some(Network::Allowed));

    assert_eq!(Profile::parse("hostile-code"), Some(Profile::HostileCode));
    assert_eq!(Profile::parse("nope"), None);
}

/// Monotonicity of the policy compiler: a MORE restrictive policy must never
/// allow an operation a LESS restrictive one forbade —
/// `P2 ⊆ P1 ⟹ Allowed(P2) ⊆ Allowed(P1)`. This is the invariant that a
/// carve bug (e.g. P0-1: a deny that accidentally widened the grant) breaks.
/// We check the two restriction axes of the write carve exhaustively on a
/// fixed tree: (a) adding any deny, (b) shrinking the writable roots. The read
/// carve uses the same `carve` primitive, rooted at `/`.
#[test]
fn compiler_is_monotone_under_restriction() {
    let tmp = std::env::temp_dir().join(format!("sbx-mono-{}", std::process::id()));
    let root = tmp.join("work");
    for d in ["a/sub/deep", "b", "c"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    for f in ["top.txt", "a/f1.txt", "a/sub/f2.txt", "a/sub/deep/f3.txt", "b/f4.txt"] {
        fs::write(root.join(f), b"x").unwrap();
    }

    // Candidate paths probed for the Allowed set — existing and absent.
    let candidates: Vec<PathBuf> = [
        "top.txt", "a", "a/f1.txt", "a/sub", "a/sub/f2.txt", "a/sub/deep",
        "a/sub/deep/f3.txt", "b", "b/f4.txt", "c",
        "a/new.txt", "a/sub/new", "a/sub/deep/new.txt", "c/new", // absent
    ]
    .iter()
    .map(|p| root.join(p))
    .collect();

    // Deny universe: a mix of dirs and a file inside the tree.
    let universe: Vec<PathBuf> = ["a", "a/sub", "a/sub/deep", "b", "a/f1.txt"]
        .iter()
        .map(|p| root.join(p))
        .collect();

    let write_allow = |denied: &[PathBuf]| -> Vec<PathBuf> {
        let mut out = Vec::new();
        carve(&root, denied, &mut out);
        out
    };
    let allowed_set = |allow: &[PathBuf]| -> Vec<bool> {
        candidates.iter().map(|x| granted(allow, x)).collect()
    };

    // (a) Adding ANY single deny to ANY base deny-set only shrinks Allowed.
    // Single-element monotonicity implies it for arbitrary added sets.
    let n = universe.len();
    for mask in 0u32..(1 << n) {
        let base: Vec<PathBuf> =
            (0..n).filter(|i| mask & (1 << i) != 0).map(|i| universe[i].clone()).collect();
        let base_allowed = allowed_set(&write_allow(&base));
        for extra in &universe {
            if base.iter().any(|d| d == extra) {
                continue;
            }
            let mut more = base.clone();
            more.push(extra.clone());
            let more_allowed = allowed_set(&write_allow(&more));
            for (i, x) in candidates.iter().enumerate() {
                assert!(
                    !(more_allowed[i] && !base_allowed[i]),
                    "non-monotone: adding deny {} made {} writable (base denies {:?})",
                    extra.display(), x.display(), base
                );
            }
        }
    }

    // (b) Shrinking the writable roots only shrinks Allowed.
    let p_big = Policy { writable_roots: vec![root.join("a"), root.join("b")], ..Default::default() };
    let p_small = Policy { writable_roots: vec![root.join("a")], ..Default::default() };
    let big = p_big.linux_write_allowlist();
    let small = p_small.linux_write_allowlist();
    for x in &candidates {
        assert!(
            !(granted(&small, x) && !granted(&big, x)),
            "non-monotone: dropping a writable root made {} writable",
            x.display()
        );
    }

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn deep_subtree_beyond_walk_depth_is_not_writable() {
    // A trust-handoff path deeper than the discovery walk must NOT be left
    // writable — the walk denies the over-depth subtree fail-safe.
    let tmp = std::env::temp_dir().join(format!("sbx-deep-{}", std::process::id()));
    let root = tmp.join("work");
    let mut deep = root.clone();
    for _ in 0..(MAX_WALK_DEPTH + 3) {
        deep = deep.join("d");
    }
    fs::create_dir_all(&deep).unwrap();
    fs::write(root.join("shallow.txt"), b"x").unwrap();
    let (root, deep) = (root.canonicalize().unwrap(), deep.canonicalize().unwrap());

    let policy = Policy { writable_roots: vec![root.clone()], ..Default::default() };
    let allow = policy.linux_write_allowlist();
    let granted = |x: &Path| allow.iter().any(|a| x.starts_with(a));

    // shallow work stays writable...
    assert!(granted(&root.join("shallow.txt")), "shallow file must be writable");
    // ...but the over-depth subtree is denied (fail-safe), so a planted
    // .git/hooks that deep could never become writable.
    assert!(!granted(&deep.join(".git/hooks/pre-commit")), "deep subtree must not be writable");

    fs::remove_dir_all(&tmp).ok();
}

/// Randomized property test (fuzz) of the write carve over many random
/// directory trees and random deny-sets. Asserts the two core invariants that
/// a carve bug (the P0-1 class) would break:
///   SAFETY: no path equal-to-or-under any deny is ever granted — not even
///           via an accidentally-granted ancestor of the deny.
///   MONOTONICITY: adding one more deny never grants a path that was denied.
/// Deterministic (fixed seed) so a failure reproduces; the tree, deny-set and
/// offending path are printed.
#[test]
fn carve_fuzz_invariants() {
    // xorshift64 — a tiny deterministic PRNG, no external deps.
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut rng = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    // Build a random tree under `dir` up to `depth`; collect every node path.
    fn build(dir: &Path, depth: u32, rng: &mut dyn FnMut() -> u64, nodes: &mut Vec<PathBuf>) {
        let n = (rng() % 4) as usize; // 0..=3 children
        for i in 0..n {
            let is_dir = depth > 0 && rng().is_multiple_of(2);
            let name = format!("{}{}", if is_dir { "d" } else { "f" }, i);
            let p = dir.join(&name);
            if is_dir {
                let _ = fs::create_dir_all(&p);
                nodes.push(p.clone());
                build(&p, depth - 1, rng, nodes);
            } else {
                let _ = fs::write(&p, b"x");
                nodes.push(p);
            }
        }
    }

    for iter in 0..120 {
        let tmp = std::env::temp_dir().join(format!("sbx-fuzz-{}-{}", std::process::id(), iter));
        let root = tmp.join("work");
        fs::create_dir_all(&root).unwrap();
        let mut nodes = Vec::new();
        build(&root, 4, &mut rng, &mut nodes);
        if nodes.is_empty() {
            fs::remove_dir_all(&tmp).ok();
            continue;
        }

        // Random deny subset.
        let deny: Vec<PathBuf> =
            nodes.iter().filter(|_| rng() % 3 == 0).cloned().collect();
        let mut out = Vec::new();
        carve(&root, &deny, &mut out);

        // SAFETY: nothing at/under a deny may be granted.
        for d in &deny {
            for x in &nodes {
                if x.starts_with(d) {
                    assert!(
                        !granted(&out, x),
                        "SAFETY broken (iter {iter}): {} granted though under deny {}",
                        x.display(), d.display()
                    );
                }
            }
        }

        // MONOTONICITY: adding one more deny never newly grants anything.
        if let Some(extra) = nodes.iter().find(|n| !deny.contains(n)) {
            let mut deny2 = deny.clone();
            deny2.push(extra.clone());
            let mut out2 = Vec::new();
            carve(&root, &deny2, &mut out2);
            for x in &nodes {
                assert!(
                    !(granted(&out2, x) && !granted(&out, x)),
                    "MONOTONICITY broken (iter {iter}): adding deny {} granted {}",
                    extra.display(), x.display()
                );
            }
        }

        fs::remove_dir_all(&tmp).ok();
    }
}

#[test]
#[cfg(target_os = "linux")] // carves the real "/" tree; Linux has real dirs
fn read_allow_does_not_reopen_a_deeper_deny() {
    // Specificity rule: deny a dir, re-allow a branch within it, then deny a
    // deeper path inside that branch. The deeper deny must still win — a flat
    // re-allow of the branch would re-open the secret (the reported bug).
    let tmp = std::env::temp_dir().join(format!("sbx-readcarve-{}", std::process::id()));
    let runs = tmp.join("runs");
    let mine = runs.join("mine");
    fs::create_dir_all(&mine).unwrap();
    fs::write(mine.join("otro"), b"ok").unwrap();
    fs::write(mine.join("settings.json"), b"SECRET").unwrap();
    fs::write(runs.join("ajeno"), b"other").unwrap();

    let p = Policy {
        read_denies: vec![runs.clone(), mine.join("settings.json")],
        read_allows: vec![mine.clone()],
        ..Default::default()
    };
    let allow = p.linux_read_allowlist();

    // The re-allowed branch is readable...
    assert!(granted(&allow, &mine.join("otro")), "re-allowed branch must be readable");
    // ...but the deeper deny within it is NOT (security property)...
    assert!(
        !granted(&allow, &mine.join("settings.json")),
        "a deny inside a re-allow must stay denied, got reopened: {allow:?}"
    );
    // ...and a sibling under the original deny stays denied.
    assert!(!granted(&allow, &runs.join("ajeno")), "sibling under the deny stays denied");

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn writable_root_inside_a_read_deny_stays_readable() {
    let base = std::env::temp_dir().join(format!("sbx-nested-root-{}", std::process::id()));
    let vault = base.join("vault");
    let w = vault.join("w");
    fs::create_dir_all(&w).unwrap();
    fs::write(vault.join("other.txt"), "x").unwrap();
    let p = Policy {
        writable_roots: vec![base.join("work"), w.clone()],
        read_denies: vec![vault.clone()],
        ..Default::default()
    };
    let reads = p.linux_read_allowlist();
    let w = resolve_best_effort(&w);
    let vault = resolve_best_effort(&vault);
    assert!(reads.iter().any(|r| r == &w), "the nested root is re-allowed");
    assert!(!reads.iter().any(|r| r == &vault || vault.join("other.txt").starts_with(r) && r.starts_with(&vault)), "the rest of the deny stays closed");
    fs::remove_dir_all(&base).ok();
}

#[test]
#[cfg(unix)]
fn granted_model_read_allow_through_a_symlink_reopens_nothing_new() {
    // Granted model: deny `/`, re-allow the system dirs, the root and `docs`.
    // `docs` is a symlink to the vault, which no other allow covers.
    let base = std::env::temp_dir().join(format!("sbx-granted-link-{}", std::process::id()));
    fs::create_dir_all(&base).unwrap();
    let base = resolve_best_effort(&base);
    let (work, vault, usr) = (base.join("work"), base.join("vault"), base.join("usr"));
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&vault).unwrap();
    fs::create_dir_all(usr.join("lib")).unwrap();
    std::os::unix::fs::symlink(&vault, work.join("docs")).unwrap();
    std::os::unix::fs::symlink(usr.join("lib"), base.join("lib")).unwrap();
    let p = Policy {
        writable_roots: vec![work.clone()],
        read_denies: vec![PathBuf::from("/")],
        read_allows: vec![usr.clone(), base.join("lib"), work.clone(), work.join("docs")],
        ..Default::default()
    };
    let reads = p.linux_read_allowlist();
    assert!(!reads.iter().any(|r| vault.starts_with(r) || r.starts_with(&vault)), "the vault stays closed: {reads:?}");
    assert!(reads.iter().any(|r| usr.join("lib").starts_with(r)), "a link into another allow still reads");
    fs::remove_dir_all(&base).ok();
}

#[test]
fn the_trace_context_reaches_the_agent_and_secrets_still_do_not() {
    let p = Policy::default();
    let launcher: Vec<(String, String)> = vec![
        ("TRACEPARENT".into(), "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".into()),
        ("TRACESTATE".into(), "vendor=x".into()),
        ("GITHUB_TOKEN".into(), "secret".into()),
    ];
    let env = p.child_env_from(&launcher).unwrap();
    let has = |k: &str| env.iter().any(|(n, _)| n == k);
    assert!(has("TRACEPARENT") && has("TRACESTATE"));
    assert!(!has("GITHUB_TOKEN"));
}

#[test]
fn the_agent_id_reaches_the_agent_and_secrets_still_do_not() {
    let p = Policy::default();
    let launcher: Vec<(String, String)> = vec![
        ("AGENT_ID".into(), "spiffe://example.org/agent/demo".into()),
        ("GITHUB_TOKEN".into(), "secret".into()),
    ];
    let env = p.child_env_from(&launcher).unwrap();
    let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(get("AGENT_ID"), Some("spiffe://example.org/agent/demo"), "passed through unchanged");
    assert!(get("GITHUB_TOKEN").is_none());
}

#[test]
fn handoff_allow_opens_only_the_names_it_lists() {
    let root = std::env::temp_dir().join(format!("tt-handoff-allow-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let p = Policy { writable_roots: vec![root.clone()], handoff_allow: vec![".goose".into()], ..Default::default() };
    assert!(p.check_handoff_allow().is_ok());
    let names = p.handoff_config_names();
    assert!(!names.contains(&".goose"));
    assert!(names.contains(&".agents") && names.contains(&".mcp.json"));
    let rules = p.trust_handoff_rules();
    assert!(!rules.iter().any(|r| r.path.ends_with(".goose")), "an allowed name gets no deny");
    assert!(rules.iter().any(|r| r.path.ends_with(".agents")), "every other name keeps its deny");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn handoff_allow_refuses_unknown_git_and_home_names() {
    let refused = |n: &str| Policy { handoff_allow: vec![n.into()], ..Default::default() }.check_handoff_allow();
    assert!(refused(".gose").unwrap_err().contains("not a trust-handoff name"));
    assert!(refused(".git/hooks").unwrap_err().contains("--handoff-scratch"));
    assert!(refused(".git").is_err());
    assert!(refused(".bashrc").unwrap_err().contains("--allow-home-handoff"));
    // validation runs with the other handoff checks every backend calls
    assert!(Policy { handoff_allow: vec![".gose".into()], ..Default::default() }.check_handoff_exempt().is_err());
}
