//! `--egress-log FILE`: the egress broker's decisions as JSON lines, without the
//! effect collectors `--log` turns on. A launcher reads the refused hosts from
//! here (seisin turns them into walls) instead of parsing stderr.
#![cfg(unix)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

#[test]
fn a_refused_host_is_a_json_line_in_the_egress_log() {
    if Command::new("curl").arg("--version").output().is_err() {
        eprintln!("skipped: no curl");
        return;
    }
    let dir = std::env::temp_dir().join(format!("tartaros-egress-log-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("egress.jsonl");
    let out = Command::new(BIN)
        .args(["run", "--write"])
        .arg(&dir)
        .args(["--allow-domain", "allowed.invalid", "--egress-log"])
        .arg(&log)
        .args(["--", "/bin/sh", "-c", "curl -s -o /dev/null --max-time 5 https://refused.invalid/; true"])
        .output()
        .expect("run tartaros");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let refused: Vec<serde_json::Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|v: &serde_json::Value| v["outcome"] == "denied")
        .collect();
    assert!(
        refused.iter().any(|v| v["axis"] == "network" && v["target"].as_str().is_some_and(|t| t.starts_with("refused.invalid"))),
        "no refusal of refused.invalid in {text:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}
