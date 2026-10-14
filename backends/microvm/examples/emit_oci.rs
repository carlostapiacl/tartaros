//! Emit the OCI `config.json` the microVM backend generates, for a given rootfs,
//! workspace and read-denied dir, so it can be run under a real runtime (runsc) to
//! validate M-µ1. Usage:
//!   emit_oci [--root|--mapped] <rootfs> <workspace> <read_deny_dir> -- <cmd...>
//! Default: the guest runs as the launcher's own (non-root) uid directly, with NO
//! user namespace — the gVisor-native least-privilege form (the workspace must be
//! owned by that uid). `--root` emits the legacy uid-0-in-guest posture; `--mapped`
//! emits the OCI/runc userns form (which this gVisor build rejects — see the doc).
use std::path::PathBuf;
use tartaros_core::{Network, Policy};
use tartaros_microvm::{to_oci_config, GuestUser, UserMapping};

// Launcher identity — unix (Linux + macOS). Used as the non-root guest uid (Direct)
// or the userns host target (Mapped).
extern "C" {
    fn geteuid() -> u32;
    fn getegid() -> u32;
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let flag = match args.first().map(String::as_str) {
        Some("--root") => { args.remove(0); "root" }
        Some("--mapped") => { args.remove(0); "mapped" }
        _ => "direct",
    };
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
    // SAFETY: geteuid/getegid are always-succeeding libc calls with no args.
    let (uid, gid) = unsafe { (geteuid(), getegid()) };
    let user = match flag {
        "root" => GuestUser::Root,
        "mapped" => GuestUser::Mapped(UserMapping::to_host(uid, gid)),
        _ => GuestUser::Direct { uid, gid },
    };
    print!("{}", to_oci_config(&policy, &command, &rootfs, &user));
}
