//! `--allow-request`: the requests an allowed domain gets. The broker logic is
//! tested against a TLS upstream in broker/src/mitm.rs; this is the CLI: the
//! rule shows in `explain`, and a rule for a host the policy does not allow, or
//! one written wrong, refuses the run before anything starts (78).

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

fn tartaros(args: &[&str]) -> std::process::Output {
    Command::new(BIN).args(args).output().expect("run tartaros")
}

#[test]
fn a_rule_is_in_explain_and_a_wrong_one_refuses_the_run() {
    let dir = std::env::temp_dir().join(format!("tartaros-rules-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.to_str().unwrap();
    let out = tartaros(&["explain", "--json", "--write", d, "--allow-domain", "api.github.com",
        "--allow-request", "GET,POST api.github.com/repos/acme/"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["request_rules"][0]["host"], "api.github.com");
    assert_eq!(v["request_rules"][0]["methods"], serde_json::json!(["GET", "POST"]));
    assert_eq!(v["request_rules"][0]["paths"], serde_json::json!(["/repos/acme/"]));
    for bad in [
        vec!["--allow-domain", "api.github.com", "--allow-request", "GET example.com"],
        vec!["--allow-domain", "api.github.com", "--allow-request", "get api.github.com"],
        vec!["--allow-domain", "api.github.com", "--allow-request", "GET api.github.com/a/../b"],
    ] {
        let mut a = vec!["run", "--write", d];
        a.extend(bad.iter().copied());
        a.extend(["--", "/usr/bin/true"]);
        let o = tartaros(&a);
        assert_eq!(o.status.code(), Some(78), "{bad:?}: {}", String::from_utf8_lossy(&o.stderr));
    }
    let _ = std::fs::remove_dir_all(dir);
}
