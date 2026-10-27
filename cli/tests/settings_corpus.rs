//! Differential corpus for `--settings` (adversarial review ADV-08).
//!
//! `--settings` maps a sandbox-runtime `settings.json` onto the generic policy.
//! The contract is **apply-fully-or-refuse**: a field the backend cannot enforce
//! must make the launch REFUSE (exit 78), never be silently dropped or widened
//! into an allow. This corpus drives the real CLI binary with `explain --settings`
//! over valid and invalid patterns and asserts the exit code, so a regression that
//! makes a non-translatable pattern "succeed" (silently permissive) fails the test.
//!
//! `explain` runs the same policy compilation as `run` (including the refuse
//! paths) without sandboxing anything, so this is host-agnostic and side-effect
//! free. The single-`*` glob case is genuinely OS-differential — macOS compiles it
//! to a Seatbelt regex (applied), Linux has no glob engine (refused) — and the
//! test asserts BOTH are non-permissive (applied-and-enforced, or refused).

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

/// Write `json` to a uniquely-named settings file and run `explain --settings` on
/// it; return the process exit code (or -1 if it was killed by a signal).
fn explain_settings(tag: &str, json: &str) -> i32 {
    let dir = std::env::temp_dir().join(format!(
        "tartaros-settings-{}-{}",
        std::process::id(),
        tag
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("settings.json");
    std::fs::write(&file, json).unwrap();
    let out = Command::new(BIN)
        .args(["explain", "--settings"])
        .arg(&file)
        .output()
        .expect("run tartaros");
    out.status.code().unwrap_or(-1)
}

/// A writable root used in the fixtures (kept inside the OS temp dir so it is a
/// clean, concrete literal path with no metacharacters of its own).
fn ws() -> PathBuf {
    std::env::temp_dir().join("tartaros-ws")
}

// ---- APPLIED (exit 0): a translatable field is enforced, not refused ----

#[test]
fn applied_literal_write_root() {
    let json = format!(r#"{{"filesystem":{{"allowWrite":["{}"]}}}}"#, ws().display());
    assert_eq!(explain_settings("lit", &json), 0, "a concrete allowWrite path must apply");
}

#[test]
fn applied_single_char_class_is_the_literal() {
    // `.vscod[e]` style: a single-char class is the literal char, so the whole
    // pattern IS a concrete path and must apply (not be treated as a glob).
    let p = ws();
    let p = p.display().to_string();
    let json = format!(r#"{{"filesystem":{{"allowWrite":["{p}"],"denyWrite":["{p}/.vscod[e]/tasks.json"]}}}}"#);
    assert_eq!(explain_settings("class", &json), 0, "a single-char class unwraps to a literal and must apply");
}

#[test]
fn applied_anydepth_covered_by_handoff() {
    // An any-depth pattern that the built-in trust-handoff set already covers is a
    // no-op (already denied at any depth), so it applies cleanly.
    let p = ws();
    let p = p.display().to_string();
    let json = format!(r#"{{"filesystem":{{"allowWrite":["{p}"],"denyWrite":["**/.git/hooks"]}}}}"#);
    assert_eq!(explain_settings("handoff", &json), 0, "**/.git/hooks is covered by the handoff set");
}

#[test]
fn applied_literal_deny_read() {
    let p = ws();
    let p = p.display().to_string();
    let json = format!(r#"{{"filesystem":{{"allowWrite":["{p}"],"denyRead":["{p}/secret"]}}}}"#);
    assert_eq!(explain_settings("denyread", &json), 0, "a concrete denyRead path must apply");
}

// ---- REFUSED (exit 78): a non-translatable field must refuse, never widen ----

#[test]
fn refused_anydepth_not_covered() {
    // An any-depth glob NOT covered by the handoff set has no inode to match on
    // Linux and no general engine — taken literally it would protect nothing, so
    // it must be refused rather than silently become a no-op.
    let p = ws();
    let p = p.display().to_string();
    let json = format!(r#"{{"filesystem":{{"allowWrite":["{p}"],"denyWrite":["**/node_modules"]}}}}"#);
    assert_eq!(explain_settings("anydepth", &json), 78, "an uncovered **/ glob must refuse, not no-op");
}

#[test]
fn refused_glob_in_allow_write() {
    // A glob in an ALLOW is always refused: we only ever re-open concrete paths.
    let json = format!(
        r#"{{"filesystem":{{"allowWrite":["{}/*/build"]}}}}"#,
        std::env::temp_dir().display()
    );
    assert_eq!(explain_settings("allowglob", &json), 78, "a glob in allowWrite must refuse");
}

#[test]
fn refused_glob_in_allow_read() {
    let p = ws();
    let p = p.display().to_string();
    let json = format!(r#"{{"filesystem":{{"allowWrite":["{p}"],"allowRead":["{p}/**"]}}}}"#);
    assert_eq!(explain_settings("readglob", &json), 78, "a glob in allowRead must refuse");
}

#[test]
fn refused_denied_domains() {
    // Per-domain DENY lists cannot be enforced in-sandbox (default-deny egress is
    // the model), so they must refuse rather than be silently ignored.
    let json = r#"{"network":{"deniedDomains":["evil.com"]}}"#;
    assert_eq!(explain_settings("denydom", json), 78, "deniedDomains must refuse");
}

// ---- OS-DIFFERENTIAL but never permissive ----

#[test]
fn single_glob_deny_write_is_enforced_or_refused_never_ignored() {
    // A single-segment glob in denyWrite: macOS compiles it to a Seatbelt regex
    // (applied -> exit 0), Linux has no glob engine (refused -> exit 78). Either
    // way it is non-permissive — it is never silently dropped.
    let p = ws();
    let p = p.display().to_string();
    let json = format!(r#"{{"filesystem":{{"allowWrite":["{p}"],"denyWrite":["{p}/*.log"]}}}}"#);
    let code = explain_settings("singleglob", &json);
    if cfg!(target_os = "macos") {
        assert_eq!(code, 0, "macOS compiles a single-* deny to a Seatbelt regex (applied)");
    } else {
        assert_eq!(code, 78, "Linux has no glob engine, so a single-* deny must refuse");
    }
}

// ---- masked credentials: env-var masking applies; the rest is refused by name ----

fn masked(w: &std::path::Display<'_>, creds: &str, tls: &str) -> String {
    format!(r#"{{"filesystem":{{"allowWrite":["{w}"]}},"network":{{"allowedDomains":["api.github.com",".example.com"],"tlsTerminate":{tls}}},"credentials":{creds}}}"#)
}

#[test]
fn applied_masked_env_credentials() {
    let w = ws();
    let w = w.display();
    let env = r#"{"envVars":[{"name":"GH_TOKEN","mode":"mask","injectHosts":["api.github.com"]}]}"#;
    assert_eq!(explain_settings("cred-env", &masked(&w, env, r#"{"excludeDomains":[]}"#)), 0, "env-var masking is enforced");
    let wild = r#"{"envVars":[{"name":"T","mode":"mask","injectHosts":["*.example.com"]}]}"#;
    assert_eq!(explain_settings("cred-wild", &masked(&w, wild, "null")), 0, "a domain pattern the allow-list covers");
    // An AWS pair is re-signed (broker/src/sigv4.rs): named explicitly, or the conventional pair.
    let aws = r#"{"envVars":[{"name":"MY_ID","mode":"mask","injectHosts":["api.github.com"]},{"name":"MY_SECRET","mode":"mask","injectHosts":["api.github.com"]}],"awsPairs":[{"accessKeyIdVar":"MY_ID","secretAccessKeyVar":"MY_SECRET"}]}"#;
    assert_eq!(explain_settings("cred-aws", &masked(&w, aws, "null")), 0, "an AWS pair of masked variables");
}

#[test]
fn refused_what_masking_does_not_cover() {
    let w = ws();
    let w = w.display();
    let cases = [
        ("cred-files", r#"{"envVars":[],"files":[{"path":"/x","mode":"mask","injectHosts":["api.github.com"]}]}"#, "null"),
        ("cred-aws-unmasked", r#"{"envVars":[{"name":"T","mode":"mask","injectHosts":["api.github.com"]}],"awsPairs":[{"accessKeyIdVar":"A","secretAccessKeyVar":"B"}]}"#, "null"),
        ("cred-mode", r#"{"envVars":[{"name":"T","mode":"pass","injectHosts":["api.github.com"]}]}"#, "null"),
        ("cred-nohost", r#"{"envVars":[{"name":"T","mode":"mask","injectHosts":[]}]}"#, "null"),
        ("cred-unreach", r#"{"envVars":[{"name":"T","mode":"mask","injectHosts":["evil.com"]}]}"#, "null"),
        ("cred-ca", r#"{"envVars":[{"name":"T","mode":"mask","injectHosts":["api.github.com"]}]}"#, r#"{"caCertPath":"/ca.pem"}"#),
        ("cred-tls-only", "null", r#"{"excludeDomains":["x.example"]}"#),
        ("cred-badname", r#"{"envVars":[{"name":"1X","mode":"mask","injectHosts":["api.github.com"]}]}"#, "null"),
    ];
    for (tag, creds, tls) in cases {
        assert_eq!(explain_settings(tag, &masked(&w, creds, tls)), 78, "{tag} must be refused by name");
    }
}

#[test]
fn applied_empty_credentials_ask_for_nothing() {
    let w = ws();
    let w = w.display();
    let json = format!(r#"{{"filesystem":{{"allowWrite":["{w}"]}},"network":{{"tlsTerminate":null}},"credentials":{{"envVars":[],"files":[]}}}}"#);
    assert_eq!(explain_settings("cred-empty", &json), 0, "an empty credentials block asks for nothing");
}
