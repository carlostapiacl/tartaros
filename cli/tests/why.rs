//! `tartaros why`: the rule that decides one access, read from the policy. It is
//! only worth asking if it says what the sandbox does, so each case is also a
//! real write under the same policy, and the two must agree.
#![cfg(unix)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

#[test]
fn why_says_what_the_sandbox_does() {
    let dir = std::env::temp_dir().join(format!("tartaros-why-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    let w = dir.to_str().unwrap();
    let policy = |c: &mut Command| {
        c.args(["--write", w, "--write-deny", &format!("{w}/src/secret"), "--handoff-exempt", &format!("{w}/vendor")]);
    };
    // (path, expected, a word the reason holds)
    let cases = [
        ("src/a", true, "writable root"),
        ("src/secret/x", false, "write-denied"),
        (".git/hooks/pre-commit", false, ".git/hooks"),
        ("pkg/.vscode/settings.json", false, ".vscode"),
        ("sub/.gitattributes", false, ".gitattributes"),
        ("vendor/pkg/.git/hooks/a", true, "--handoff-exempt"),
    ];
    for (rel, allowed, word) in cases {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut why = Command::new(BIN);
        why.args(["why", "write"]).arg(&path);
        policy(&mut why);
        let out = why.output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(if allowed { 0 } else { 1 }), "{rel}: {text}");
        assert!(text.contains(word), "{rel}: {text}");
        let mut run = Command::new(BIN);
        run.arg("run");
        policy(&mut run);
        run.args(["--", "sh", "-c", &format!("echo x > '{}'", path.display())]);
        let ran = run.output().unwrap();
        assert_eq!(ran.status.success(), allowed, "{rel}: why said {text}, the run said {}", String::from_utf8_lossy(&ran.stderr));
    }
    let out = Command::new(BIN).args(["why", "write", "/etc/tartaros-why"]).args(["--write", w]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("outside every writable root"));
    let out = Command::new(BIN).args(["why", "read", &format!("{w}/src/secret/k"), "--read-deny", &format!("{w}/src/secret")]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(Command::new(BIN).args(["why", "maybe", "/x"]).status().unwrap().code(), Some(2));
    let _ = std::fs::remove_dir_all(dir);
}
