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
    std::fs::create_dir_all(dir.join("src/secret")).unwrap();
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
        // Linux and Windows do not hold a new name in a nested directory
        // (docs/limits.md); `why` says that, and the run agrees either way.
        ("sub/.gitattributes", cfg!(not(target_os = "macos")), ".gitattributes"),
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
        // A Linux host that carves (no mount namespace) withholds more than the
        // policy says; `why` reports that instead, and must still match the run.
        let carved = text.contains("Linux: nothing new can be created");
        if !carved {
            assert_eq!(out.status.code(), Some(if allowed { 0 } else { 1 }), "{rel}: {text}");
            assert!(text.contains(word), "{rel}: {text}");
        }
        let mut run = Command::new(BIN);
        run.arg("run");
        policy(&mut run);
        run.args(["--", "sh", "-c", &format!("echo x > '{}'", path.display())]);
        let ran = run.output().unwrap();
        assert_eq!(ran.status.success(), out.status.success(), "{rel}: why said {text}, the run said {}", String::from_utf8_lossy(&ran.stderr));
    }
    // A write deny that does not exist yet: on Linux the carve withholds its
    // nearest existing ancestor, so a new file beside it is denied too, and
    // `why` has to say so (it reads the same carve).
    let fresh = dir.join("fresh");
    std::fs::create_dir_all(fresh.join("src")).unwrap();
    let f = fresh.to_str().unwrap();
    let target = fresh.join("src/new");
    let out = Command::new(BIN)
        .args(["why", "write"])
        .arg(&target)
        .args(["--write", f, "--write-deny", &format!("{f}/src/absent")])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let ran = Command::new(BIN)
        .args(["run", "--write", f, "--write-deny", &format!("{f}/src/absent"), "--"])
        .args(["sh", "-c", &format!("echo x > '{}'", target.display())])
        .output()
        .unwrap();
    assert_eq!(out.status.success(), ran.status.success(), "why said {text}, the run said {}", String::from_utf8_lossy(&ran.stderr));
    if cfg!(target_os = "linux") && !out.status.success() {
        assert!(text.contains("nothing new can be created"), "{text}");
    }
    let out = Command::new(BIN).args(["why", "write", "/etc/tartaros-why"]).args(["--write", w]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("outside every writable root"));
    let out = Command::new(BIN).args(["why", "read", &format!("{w}/src/secret/k"), "--read-deny", &format!("{w}/src/secret")]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(Command::new(BIN).args(["why", "maybe", "/x"]).status().unwrap().code(), Some(2));
    let _ = std::fs::remove_dir_all(dir);
}
