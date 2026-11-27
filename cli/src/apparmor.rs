//! `tartaros setup apparmor`: let this binary create user namespaces on a host
//! that restricts them (Ubuntu 23.10+). Needs root; Linux only.

use std::process::exit;
#[cfg(target_os = "linux")]
use crate::EXIT_POLICY_REFUSED;

pub(crate) fn cmd_setup(args: &[String]) -> ! {
    match args.first().map(String::as_str) {
        Some("apparmor") => setup_apparmor(&args[1..]),
        _ => {
            eprintln!("tartaros: usage: tartaros setup apparmor [--print]");
            exit(2);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn setup_apparmor(_args: &[String]) -> ! {
    eprintln!("tartaros: AppArmor is Linux only; nothing to set up on this system");
    exit(1);
}

/// First line of the profile `setup apparmor` writes: an existing file without
/// it is someone else's, and is never overwritten.
#[cfg(any(target_os = "linux", test))]
const APPARMOR_HEADER: &str = "# Written by `tartaros setup apparmor`.";
#[cfg(target_os = "linux")]
const APPARMOR_DEST: &str = "/etc/apparmor.d/tartaros";

/// The profile: user namespaces for this binary and nothing else, unconfined
/// otherwise, the shape Ubuntu ships for programs that need them
/// (`/etc/apparmor.d/lxc-usernsexec`). What tartaros runs inherits it, and is
/// still refused new user namespaces by tartaros's own confinement (corpus:
/// `isolation-no-nested-userns`, `seccomp-clone-newuser-denied`).
#[cfg(any(target_os = "linux", test))]
fn apparmor_profile(bin: &std::path::Path) -> String {
    format!(
        "{APPARMOR_HEADER}\n\
         # Lets this binary create the user and mount namespaces it confines with, on a\n\
         # host that restricts them (kernel.apparmor_restrict_unprivileged_userns=1).\n\
         abi <abi/4.0>,\n\
         include <tunables/global>\n\
         \n\
         profile tartaros {} flags=(unconfined) {{\n\
         \x20 userns,\n\
         \n\
         \x20 include if exists <local/tartaros>\n\
         }}\n",
        bin.display()
    )
}

/// Why `bin` must not get the profile, if it must not: a path AppArmor cannot
/// name plainly, or one that anyone but root can change. Granting user
/// namespaces to a binary its user can replace would lift the host's
/// restriction for that user, which is what it is there to prevent.
#[cfg(any(target_os = "linux", test))]
fn apparmor_unsafe_path(bin: &std::path::Path, meta: impl Fn(&std::path::Path) -> std::io::Result<(u32, u32)>) -> Option<String> {
    let plain = bin.to_str().is_some_and(|s| s.starts_with('/') && s.chars().all(|c| c.is_ascii_alphanumeric() || "/._+-".contains(c)));
    if !plain {
        return Some(format!("{} is not a plain absolute path AppArmor can name", bin.display()));
    }
    let mut p = Some(bin);
    while let Some(cur) = p {
        match meta(cur) {
            Ok((uid, mode)) if uid == 0 && mode & 0o022 == 0 => {}
            Ok(_) => return Some(format!("{} can be changed by a user other than root", cur.display())),
            Err(e) => return Some(format!("{}: {e}", cur.display())),
        }
        p = cur.parent();
    }
    None
}

#[cfg(target_os = "linux")]
fn setup_apparmor(args: &[String]) -> ! {
    use std::os::unix::fs::MetadataExt;
    let print_only = args.iter().any(|a| a == "--print");
    if let Some(a) = args.iter().find(|a| *a != "--print") {
        eprintln!("tartaros: setup apparmor: unknown option `{a}`");
        exit(2);
    }
    let bin = std::env::current_exe().and_then(std::fs::canonicalize).unwrap_or_else(|e| {
        eprintln!("tartaros: cannot tell where this binary is: {e}");
        exit(1);
    });
    if let Some(why) = apparmor_unsafe_path(&bin, |p| std::fs::metadata(p).map(|m| (m.uid(), m.mode()))) {
        eprintln!(
            "tartaros: refusing: {why}. A profile that grants user namespaces to it would lift the \
             host's restriction for whoever can replace it. Install a copy only root can change, \
             and set up that one:\n  sudo install -m755 {} /usr/local/bin/tartaros\n  \
             sudo /usr/local/bin/tartaros setup apparmor",
            bin.display()
        );
        exit(EXIT_POLICY_REFUSED);
    }
    let profile = apparmor_profile(&bin);
    if print_only {
        print!("{profile}");
        eprintln!("tartaros: save it as {APPARMOR_DEST} and load it with: sudo apparmor_parser -r {APPARMOR_DEST}");
        exit(0);
    }
    if !std::path::Path::new("/sys/kernel/security/apparmor").exists() {
        eprintln!("tartaros: AppArmor is not enabled on this host; nothing to set up");
        exit(1);
    }
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("tartaros: setup apparmor writes {APPARMOR_DEST}, which needs root:\n  sudo {} setup apparmor\n(or --print to see the profile)", bin.display());
        exit(1);
    }
    if let Ok(old) = std::fs::read_to_string(APPARMOR_DEST) {
        if !old.starts_with(APPARMOR_HEADER) {
            eprintln!("tartaros: {APPARMOR_DEST} exists and was not written by tartaros; leaving it as it is");
            exit(1);
        }
    }
    if let Err(e) = std::fs::write(APPARMOR_DEST, &profile) {
        eprintln!("tartaros: writing {APPARMOR_DEST}: {e}");
        exit(1);
    }
    match std::process::Command::new("apparmor_parser").args(["-r", APPARMOR_DEST]).status() {
        Ok(s) if s.success() => {}
        Ok(s) => {
            eprintln!("tartaros: apparmor_parser -r {APPARMOR_DEST} failed ({s}); the file is written but not loaded");
            exit(1);
        }
        Err(e) => {
            eprintln!("tartaros: running apparmor_parser: {e}; the file is written but not loaded");
            exit(1);
        }
    }
    println!(
        "tartaros: profile loaded for {} ({APPARMOR_DEST}). `tartaros explain` now says whether runs \
         get their namespaces. A tartaros at another path, or this one moved, needs its own setup.",
        bin.display()
    );
    exit(0);
}


#[cfg(test)]
mod apparmor_tests {
    use super::{apparmor_profile, apparmor_unsafe_path, APPARMOR_HEADER};
    use std::path::Path;

    #[test]
    fn the_profile_grants_userns_to_that_path_and_nothing_else() {
        let p = apparmor_profile(Path::new("/usr/local/bin/tartaros"));
        assert!(p.starts_with(APPARMOR_HEADER));
        assert!(p.contains("profile tartaros /usr/local/bin/tartaros flags=(unconfined) {\n  userns,\n"));
        let rules: Vec<&str> = p.lines().map(str::trim).filter(|l| l.ends_with(',')).collect();
        assert_eq!(rules, ["abi <abi/4.0>,", "userns,"]);
    }

    #[test]
    fn only_a_path_root_alone_can_change_gets_it() {
        let root = |_: &Path| Ok((0, 0o755));
        assert_eq!(apparmor_unsafe_path(Path::new("/usr/local/bin/tartaros"), root), None);
        // A user's npm prefix, a group-writable dir, a world-writable one.
        let home = |p: &Path| Ok((if p.starts_with("/home") && p != Path::new("/home") { 1000 } else { 0 }, 0o755));
        assert!(apparmor_unsafe_path(Path::new("/home/u/.npm/bin/tartaros"), home).is_some());
        let group = |p: &Path| Ok((0, if p == Path::new("/opt/t") { 0o775 } else { 0o755 }));
        assert!(apparmor_unsafe_path(Path::new("/opt/t/tartaros"), group).is_some());
        let tmp = |p: &Path| Ok((0, if p == Path::new("/tmp") { 0o1777 } else { 0o755 }));
        assert!(apparmor_unsafe_path(Path::new("/tmp/tartaros"), tmp).is_some());
        // Names AppArmor would need quoted or would read as a pattern.
        for odd in ["/opt/my tools/tartaros", "/opt/t*/tartaros", "relative/tartaros"] {
            assert!(apparmor_unsafe_path(Path::new(odd), root).is_some(), "{odd}");
        }
    }
}
