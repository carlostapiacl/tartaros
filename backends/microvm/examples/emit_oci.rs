//! Emit the OCI `config.json` the microVM backend generates, for a given rootfs,
//! workspace and read-denied dir, so it can be run under a real runtime (runsc) to
//! validate M-µ1. Usage:
//!   emit_oci <rootfs> <workspace> <read_deny_dir> -- <cmd...>
use std::path::PathBuf;
use tartaros_core::{Network, Policy};
use tartaros_microvm::to_oci_config;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dd = args.iter().position(|a| a == "--").expect("need -- before the command");
    let rootfs = args[0].clone();
    let workspace = args[1].clone();
    let read_deny = args[2].clone();
    let command: Vec<String> = args[dd + 1..].to_vec();
    let policy = Policy {
        writable_roots: vec![PathBuf::from(&workspace)],
        read_denies: vec![PathBuf::from(&read_deny)],
        network: Some(Network::Denied),
        ..Default::default()
    };
    print!("{}", to_oci_config(&policy, &command, &rootfs));
}
