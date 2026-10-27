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
