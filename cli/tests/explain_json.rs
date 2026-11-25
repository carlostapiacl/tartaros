//! `tartaros explain --json`: the same answer as the text, for a program. A
//! launcher reads the trust-handoff set and the egress allow-list from here
//! instead of parsing the text, and a value given with `--env KEY=VALUE` is
//! never in it (explain output lands in logs).

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

#[test]
fn explain_json_is_the_policy_as_data_with_no_env_values() {
    let dir = std::env::temp_dir().join(format!("tartaros-explain-json-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(BIN)
        .args(["explain", "--json", "--write"])
        .arg(&dir)
        .args(["--allow-domain", "example.com", "--env", "SECRETISH=hunter2-value", "--env", "KEEP"])
        .output()
        .expect("run tartaros");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {stdout}"));
    assert_eq!(v["egress_domains"][0], "example.com");
    assert!(v["writable_roots"][0].as_str().unwrap().contains("tartaros-explain-json"));
    let names: Vec<&str> = v["trust_handoff"]["names"].as_array().unwrap().iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&".claude/settings.json") && names.contains(&".mcp.json"), "{names:?}");
    assert_eq!(v["environment"]["passthrough"], serde_json::json!(["SECRETISH", "KEEP"]));
    assert!(!stdout.contains("hunter2-value"), "an --env value must never be printed: {stdout}");
    assert_eq!(v["tartaros"], env!("CARGO_PKG_VERSION"));
    let _ = std::fs::remove_dir_all(dir);
}

/// `handoffScratch` in a settings file — the path a launcher uses — reaches the
/// policy, says so in explain, and a run under it lets `git init` write its hooks
/// in the scratch root while the repo's own `.git/hooks` stays refused.
#[test]
#[cfg(target_os = "macos")]
fn a_settings_file_hands_a_scratch_root_through() {
    let base = std::env::temp_dir().join(format!("tartaros-scratch-settings-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let repo = base.join("repo");
    let tmp = base.join("run/tmp");
    std::fs::create_dir_all(repo.join(".git/hooks")).unwrap();
    std::fs::create_dir_all(&tmp).unwrap();
    let settings = base.join("settings.json");
    std::fs::write(&settings, serde_json::json!({
        "filesystem": { "allowWrite": [repo, tmp], "handoffScratch": [tmp] },
        "network": { "allowedDomains": [] },
    }).to_string()).unwrap();
    let out = Command::new(BIN).args(["explain", "--json", "--settings"]).arg(&settings).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stderr)));
    assert!(v["trust_handoff"]["scratch"][0].as_str().unwrap().ends_with("run/tmp"), "{v}");
    let script = format!("cd {} && /usr/bin/git init -q t 2>/dev/null && test -f t/.git/config", tmp.display());
    let run = |s: &str| Command::new(BIN).current_dir(&repo).args(["run", "--settings"]).arg(&settings)
        .args(["--", "/bin/sh", "-c", s]).output().unwrap();
    let ok = run(&script);
    assert!(ok.status.success(), "git init in the scratch root: {}", String::from_utf8_lossy(&ok.stderr));
    assert!(String::from_utf8_lossy(&ok.stderr).contains("--handoff-scratch"), "the opening is said at start");
    let no = run(&format!("echo x > {}", repo.join(".git/hooks/pre-commit").display()));
    assert!(!no.status.success());
    let _ = std::fs::remove_dir_all(base);
}
