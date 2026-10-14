//! Drive a `security-bench` corpus scenario through the microVM OCI config so it can
//! be executed under a real runtime (`runsc`). This is the "scripted bundle per
//! scenario" the M-µ1 verification contract asks for: the SAME corpus TOML the
//! shared-kernel backends use, compiled to a microVM bundle instead.
//!
//! It parses only the subset of the corpus schema the gVisor M-µ1 config CLAIMS to
//! enforce (writable roots, read-denies, trust-handoff within them, fixtures, and
//! the attack/control commands). Scenarios that exercise the broker, VM-size
//! resource caps, or servers are M-µ2 work and are skipped by the bash driver, not
//! here.
//!
//! Usage:
//!   corpus_runsc <toml> <root> fixtures            # materialize fixtures under root
//!   corpus_runsc <toml> <root> config <attack|control>  # print config.json
use std::path::PathBuf;
use serde::Deserialize;
use tartaros_core::{Access, FsRule, Network, Policy};
use tartaros_microvm::{to_oci_config, GuestUser};

extern "C" {
    fn geteuid() -> u32;
    fn getegid() -> u32;
}

#[derive(Deserialize)]
struct Contract {
    #[serde(default)]
    policy: PolicySpec,
    #[serde(default)]
    fixture: Vec<Fixture>,
    attack: Op,
    control: Op,
    #[serde(default)]
    assert: AssertSpec,
}
#[derive(Deserialize, Default)]
struct AssertSpec {
    #[serde(default)]
    unchanged: Option<String>,
    #[serde(default)]
    absent: Option<String>,
    #[serde(default)]
    present: Option<String>,
}
#[derive(Deserialize, Default)]
struct PolicySpec {
    #[serde(default)]
    writable_roots: Vec<String>,
    #[serde(default)]
    read_denies: Vec<String>,
    #[serde(default)]
    read_allows: Vec<String>,
    #[serde(default)]
    write_denies: Vec<String>,
}
#[derive(Deserialize)]
struct Fixture {
    path: String,
    #[serde(default)]
    dir: bool,
    #[serde(default)]
    content: Option<String>,
}
#[derive(Deserialize)]
struct Op {
    cmd: String,
}

fn subst(s: &str, root: &str) -> String {
    s.replace("{root}", root)
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let toml_path = &a[0];
    let root = &a[1];
    let mode = &a[2];
    let text = std::fs::read_to_string(toml_path).expect("read toml");
    let c: Contract = toml::from_str(&text).expect("parse toml");

    if mode == "assert" {
        if let Some(p) = &c.assert.unchanged { println!("unchanged\t{}", subst(p, root)); }
        if let Some(p) = &c.assert.absent { println!("absent\t{}", subst(p, root)); }
        if let Some(p) = &c.assert.present { println!("present\t{}", subst(p, root)); }
        return;
    }

    if mode == "fixtures" {
        std::fs::create_dir_all(root).unwrap();
        for f in &c.fixture {
            let p = PathBuf::from(subst(&f.path, root));
            if f.dir {
                std::fs::create_dir_all(&p).unwrap();
            } else {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent).unwrap();
                }
                std::fs::write(&p, c_content(f)).unwrap();
            }
        }
        // Ensure every writable root exists even without a fixture for it.
        for w in &c.policy.writable_roots {
            std::fs::create_dir_all(subst(w, root)).unwrap();
        }
        return;
    }

    // config mode
    let cmd_str = match mode.as_str() {
        "config" => {
            let which = &a[3];
            match which.as_str() {
                "attack" => subst(&c.attack.cmd, root),
                "control" => subst(&c.control.cmd, root),
                _ => panic!("attack|control"),
            }
        }
        _ => panic!("fixtures|config"),
    };
    let policy = Policy {
        writable_roots: c.policy.writable_roots.iter().map(|w| PathBuf::from(subst(w, root))).collect(),
        read_denies: c.policy.read_denies.iter().map(|d| PathBuf::from(subst(d, root))).collect(),
        read_allows: c.policy.read_allows.iter().map(|a| PathBuf::from(subst(a, root))).collect(),
        fs_rules: c.policy.write_denies.iter().map(|w| FsRule {
            path: PathBuf::from(subst(w, root)),
            access: Access::Deny,
            even_if_absent: true,
        }).collect(),
        network: Some(Network::Denied),
        ..Default::default()
    };
    // Run the scenario command through a shell inside the guest.
    let command = vec!["/bin/sh".to_string(), "-c".to_string(), cmd_str];
    // The guest's non-root uid: TARTAROS_UID/GID override (so the driver can run the
    // emitter as root yet target a non-root guest that owns the chowned workspace),
    // else the launcher's own euid/egid.
    // SAFETY: geteuid/getegid take no args and always succeed.
    let uid = std::env::var("TARTAROS_UID").ok().and_then(|v| v.parse().ok()).unwrap_or_else(|| unsafe { geteuid() });
    let gid = std::env::var("TARTAROS_GID").ok().and_then(|v| v.parse().ok()).unwrap_or_else(|| unsafe { getegid() });
    let user = GuestUser::Direct { uid, gid };
    print!("{}", to_oci_config(&policy, &command, "/tmp/bundle/rootfs", &user));
}

fn c_content(f: &Fixture) -> String {
    f.content.clone().unwrap_or_default()
}
