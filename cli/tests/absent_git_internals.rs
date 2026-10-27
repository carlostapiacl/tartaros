//! A repository whose `.git` has no `hooks` directory or no `config` (a go-git
//! or libgit2 checkout, `git init --template=`): the agent must not create them.
//! On Linux without a mount namespace the carve protects only what exists, and
//! before 0.1.0-alpha.18 `mkdir .git/hooks && echo x > .git/hooks/h` succeeded
//! there, `--materialize` included. The run must also leave `.git` as it found it.
#![cfg(unix)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

#[test]
fn a_missing_hooks_dir_or_config_cannot_be_created_and_nothing_is_left() {
    let dir = std::env::temp_dir().join(format!("tartaros-absent-git-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("src")).unwrap();
    let git = dir.join(".git");
    for script in [
        format!("mkdir -p '{0}/hooks' && echo x > '{0}/hooks/pre-commit'", git.display()),
        format!("printf '[core]\\n\\thooksPath = /tmp\\n' > '{}/config'", git.display()),
    ] {
        let out = Command::new(BIN).arg("run").arg("--write").arg(&dir).args(["--", "sh", "-c", &script]).output().unwrap();
        assert!(!out.status.success(), "{script} succeeded: {}", String::from_utf8_lossy(&out.stderr));
    }
    assert!(!git.join("hooks/pre-commit").exists());
    let mut left: Vec<String> = std::fs::read_dir(&git).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    left.sort();
    assert!(left.is_empty(), "the run left {left:?} in .git");
    let _ = std::fs::remove_dir_all(dir);
}
