//! P1-2 mitigation check (Linux): with `materialize_absent_handoff`, the agent
//! cannot create a trust-handoff config file that did not exist at launch (a
//! surface a trusted tool would later run). `cargo run -p tartaros-linux
//! --example p1_materialize`

use tartaros_core::{Backend, Network, Policy};
use tartaros_linux::LandlockBackend;

fn main() {
    let work = std::env::temp_dir().join(format!("sbx-mat-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let be = LandlockBackend;
    let pass = |b: bool| if b { "PASS" } else { "FAIL" };

    for (label, materialize) in [("sin materializar", false), ("con materializar", true)] {
        // fresh workspace each round, with a pre-existing src/ subdir (the normal
        // place an agent works; new TOP-LEVEL entries in a root that contains a
        // protected path are not creatable — inherent Landlock carve tradeoff)
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(work.join("src")).unwrap();
        let policy = Policy {
            role: "qa".into(),
            writable_roots: vec![work.clone()],
            network: Some(Network::Denied),
            materialize_absent_handoff: materialize,
            ..Default::default()
        };
        let sh = |s: String| be.run(&policy, &["/bin/sh".into(), "-c".into(), s]).map(|o| o.exit_code).unwrap_or(-1);
        let target = work.join(".claude/settings.json");

        println!("=== {label} ===");
        // agent tries to create the (initially absent) config
        let rc = sh(format!("mkdir -p {}/.claude && echo 'EVIL' > {} 2>/dev/null", work.display(), target.display()));
        let created_evil = std::fs::read_to_string(&target).map(|c| c.contains("EVIL")).unwrap_or(false);
        println!("  crear .claude/settings.json con EVIL: rc={rc} contiene-EVIL={created_evil}  {}",
            pass(!created_evil));
        // control: write in a pre-existing subdir still works
        let rc = sh(format!("echo ok > {}/src/f.txt", work.display()));
        println!("  escribir en work/src/f.txt:           rc={rc}  {}", pass(rc == 0));
    }
    std::fs::remove_dir_all(&work).ok();
}
