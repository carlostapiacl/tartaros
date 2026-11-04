//! An any-depth `denyWrite` in a settings file (`<root>/**/.claude/**`) is held,
//! not just accepted. Before 0.1.0-alpha.20 a pattern was taken as covered by the
//! trust-handoff set whenever it mentioned a handoff name, so
//! `**/.git/worktrees/**/commondir` and `**/.claude/**` passed `explain` and the
//! run wrote `.git/worktrees/w/commondir` and `.claude/notes.md` anyway.
//!
//! Both backends hold what exists when the run starts; macOS also holds a new
//! one (the pattern is a Seatbelt regex), Linux where the trust-handoff set holds
//! that name (docs/limits.md).
#![cfg(unix)]

use std::path::Path;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

fn writes(settings: &Path, files: &[&Path]) -> Vec<bool> {
    let script: String = files
        .iter()
        .map(|f| format!("if (echo y > '{}') 2>/dev/null; then echo W; else echo D; fi;", f.display()))
        .collect();
    let out = Command::new(BIN).args(["run", "--settings"]).arg(settings).args(["--", "sh", "-c", &script]).output().unwrap();
    assert!(out.status.success(), "run failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).lines().map(|l| l == "W").collect()
}

#[test]
fn an_any_depth_write_deny_holds_what_it_names_and_nothing_else() {
    let dir = std::env::temp_dir().join(format!("tartaros-any-depth-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = dir.join("ws");
    for d in [".claude", "sub/.claude", "repo/.git/worktrees/w", "src"] {
        std::fs::create_dir_all(ws.join(d)).unwrap();
    }
    let ws = std::fs::canonicalize(&ws).unwrap();
    for f in [".claude/notes.md", "sub/.claude/x", "repo/.git/worktrees/w/commondir", "repo/.git/worktrees/w/HEAD"] {
        std::fs::write(ws.join(f), "before\n").unwrap();
    }
    let w = ws.display();
    let settings = dir.join("settings.json");
    std::fs::write(
        &settings,
        format!(
            r#"{{"filesystem":{{"allowWrite":["{w}"],"denyWrite":["{w}/**/.claude","{w}/**/.claude/**","{w}/**/.git/worktrees/**/commondir"]}},"network":{{"allowedDomains":[]}}}}"#
        ),
    )
    .unwrap();

    let denied = [ws.join(".claude/notes.md"), ws.join("sub/.claude/x"), ws.join("repo/.git/worktrees/w/commondir")];
    let allowed = [ws.join("src/f"), ws.join("repo/.git/worktrees/w/HEAD"), ws.join("sub/notes.md")];
    let files: Vec<&Path> = denied.iter().chain(&allowed).map(|p| p.as_path()).collect();
    let got = writes(&settings, &files);
    for (f, wrote) in files.iter().zip(&got).take(denied.len()) {
        assert!(!wrote, "{} was written", f.display());
    }
    for (f, wrote) in files.iter().zip(&got).skip(denied.len()) {
        assert!(wrote, "{} was not written", f.display());
    }
    for f in &denied {
        assert_eq!(std::fs::read_to_string(f).unwrap(), "before\n", "{} changed", f.display());
    }

    // macOS: a new one, in a directory made during the run, is held too.
    #[cfg(target_os = "macos")]
    {
        let out = Command::new(BIN)
            .args(["run", "--settings"])
            .arg(&settings)
            .args(["--", "sh", "-c", &format!("mkdir -p '{w}/new' && mkdir '{w}/new/.claude'")])
            .output()
            .unwrap();
        assert!(!out.status.success(), "a new .claude was created");
        assert!(!ws.join("new/.claude").exists());
    }
    let _ = std::fs::remove_dir_all(dir);
}
