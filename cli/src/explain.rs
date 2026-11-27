//! `tartaros explain` and `tartaros why`: what a policy grants, as text or JSON,
//! and which rule decides one access.

use tartaros_core::Access;
use crate::EXIT_POLICY_REFUSED;
use crate::policy_file::MASKED;
use std::path::PathBuf;
use tartaros_core::Policy;
use tartaros_core::Profile;
use crate::policy_file::REQUEST_RULES;
use crate::backend_os;
use crate::build_policy;
use std::process::exit;

pub(crate) fn cmd_explain(opts: &[String]) -> ! {
    // `--json`: the same answer for a program (a launcher reads the handoff set
    // and the egress allow-list from here instead of parsing the text).
    let json = opts.iter().any(|o| o == "--json");
    let opts: Vec<String> = opts.iter().filter(|o| *o != "--json").cloned().collect();
    let (p, _, profile) = build_policy(&opts, !json); // explain: verbose
    #[cfg(target_os = "linux")]
    let blocked = tartaros_linux::host_blocks_run(&p);
    #[cfg(target_os = "macos")]
    let blocked = tartaros_macos::host_blocks_run(&p);
    #[cfg(target_os = "windows")]
    let blocked = {
        use tartaros_core::Backend;
        tartaros_windows::WindowsBackend.validate(&p).err().map(|e| e.reason)
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let blocked: Option<String> = None;
    if json {
        println!("{}", serde_json::to_string_pretty(&explain_json(&p, profile.as_ref(), blocked.as_deref())).unwrap_or_default());
        exit(if blocked.is_some() { EXIT_POLICY_REFUSED } else { 0 });
    }
    if let Some(pr) = profile {
        println!("profile: {} — {}", pr.name(), pr.tier());
        if let Some(c) = pr.caveat() {
            println!("profile caveat: {c}");
        }
        println!();
    }
    explain(&p);
    // Exit non-zero wherever `run` would refuse on THIS host, so an audit
    // (an external audit) never shows a green ✓ for a policy this host cannot enforce
    // (e.g. no Landlock on Docker Desktop's linuxkit kernel). Same fail-closed
    // contract as `run`, just without spawning anything.
    if let Some(reason) = blocked {
        eprintln!("\ntartaros: this host cannot enforce this policy: {reason}");
        exit(EXIT_POLICY_REFUSED);
    }
    exit(0);
}


/// `tartaros why read|write PATH [options]`: the rule that decides one access,
/// from the policy (`Policy::why`) and, on Linux, from the carve the run would
/// install. For the agent, or the person, who got an
/// EACCES and wants to know which line of the policy to change: Landlock says
/// nothing about it, and Seatbelt only to the unified log. Exit 0 allowed, 1
/// denied.
pub(crate) fn cmd_why(opts: &[String]) -> ! {
    let usage = || -> ! {
        eprintln!("tartaros: usage: tartaros why read|write PATH [policy options]");
        exit(2);
    };
    let write = match opts.first().map(String::as_str) {
        Some("read") => false,
        Some("write") => true,
        _ => usage(),
    };
    let Some(path) = opts.get(1).filter(|p| !p.starts_with("--")) else { usage() };
    let (p, _, _) = build_policy(&opts[2..], false);
    let path = std::path::absolute(path).unwrap_or_else(|_| PathBuf::from(path));
    #[cfg(target_os = "linux")]
    let held = |a: &std::path::Path| tartaros_linux::absent_handoff_held(&p, a);
    #[cfg(target_os = "windows")]
    let held = |a: &std::path::Path| tartaros_windows::placeholder_plan(&p).iter().any(|h| a.starts_with(h));
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let held = |_: &std::path::Path| true;
    let (allowed, why) = p.why(&path, write, &held);
    #[cfg(target_os = "linux")]
    let (allowed, why) = match (allowed && write).then(|| tartaros_linux::carve_denies_write(&p, &path)).flatten() {
        Some(carve) => (false, carve),
        None => (allowed, why),
    };
    println!("{} {}: {} ({why})", if write { "write" } else { "read" }, path.display(), if allowed { "allowed" } else { "denied" });
    exit(if allowed { 0 } else { 1 });
}


/// Print exactly what a policy grants, without running anything — so a security
/// team can audit a profile before deploying it.
/// `explain --json`: what `explain` prints, as data. Paths as strings, the
/// environment by NAME only (a `--env KEY=VALUE` value is never shown), and the
/// trust-handoff set as the names protected at any depth under each root.
fn explain_json(p: &Policy, profile: Option<&Profile>, blocked: Option<&str>) -> serde_json::Value {
    let paths = |v: &[std::path::PathBuf]| v.iter().map(|x| x.display().to_string()).collect::<Vec<_>>();
    let masked = MASKED.get().map(|m| {
        m.creds.iter().map(|(n, h)| serde_json::json!({ "name": n, "hosts": h })).collect::<Vec<_>>()
    }).unwrap_or_default();
    #[cfg(target_os = "macos")]
    let enforcement = tartaros_macos::enforcement_report(p);
    #[cfg(target_os = "linux")]
    let enforcement = tartaros_linux::enforcement_report(p);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let enforcement: Vec<String> = Vec::new();
    #[cfg(target_os = "linux")]
    let (engine, abi) = ("landlock+seccomp", tartaros_linux::landlock_abi());
    #[cfg(target_os = "macos")]
    let (engine, abi) = ("seatbelt", None::<u32>);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let (engine, abi) = (backend_os(), None::<u32>);
    serde_json::json!({
        "tartaros": env!("CARGO_PKG_VERSION"),
        "backend": backend_os(),
        // The short answer for a launcher that shows or logs whether a command is
        // confined (goose#12805): `active` is false exactly when `run` would refuse
        // on this host, with the reason in `refused`. The confinement covers the
        // command and every process it starts; what the launcher runs outside
        // tartaros is the launcher's to report.
        "confinement": {
            "active": blocked.is_none(),
            "engine": engine,
            "landlock_abi": abi,
            "covers": "process-tree",
            "refused": blocked,
        },
        "profile": profile.map(|pr| pr.name()),
        "role": p.role,
        "network": format!("{:?}", p.network),
        "egress_domains": p.allow_domains,
        "masked_credentials": masked,
        "request_rules": REQUEST_RULES.lock().unwrap().iter()
            .map(|r| serde_json::json!({ "host": r.host, "methods": r.methods, "paths": r.paths }))
            .collect::<Vec<_>>(),
        "local_ports": p.local_ports,
        "listen_ports": p.listen_ports,
        "listen_any": p.listen_any,
        "writable_roots": paths(&p.writable_roots),
        "write_denied": p.fs_rules.iter().filter(|r| r.access == Access::Deny).map(|r| r.path.display().to_string()).collect::<Vec<_>>(),
        "read_denied": paths(&p.read_denies),
        "read_allowed": paths(&p.read_allows),
        "trust_handoff": {
            "names": p.handoff_config_names(),
            "allowed": p.handoff_allow,
            "git": tartaros_core::HANDOFF_GIT_NAMES,
            "home": if p.protect_home_handoff { tartaros_core::HANDOFF_HOME_NAMES.to_vec() } else { Vec::new() },
            "exempt": paths(&p.handoff_exempt),
            "scratch": paths(&p.handoff_scratch),
        },
        "isolate_pids": p.isolate_pids,
        "isolate_network": p.isolate_network,
        "isolate_process_info": p.isolate_process_info,
        "harden_syscalls": p.harden_syscalls,
        "strict": p.strict,
        "private_tmp": p.private_tmp,
        "deny_unix_sockets": p.deny_unix_sockets,
        "environment": {
            "inherit": p.inherit_env,
            "allowlist": tartaros_core::ENV_ALLOWLIST,
            "passthrough": p.env_passthrough.iter().map(|e| e.split_once('=').map(|(k, _)| k).unwrap_or(e).to_string()).collect::<Vec<_>>(),
        },
        "limits": {
            "timeout_secs": p.timeout.map(|t| t.as_secs()),
            "max_memory_bytes": p.max_memory_bytes,
            "max_processes": p.max_processes,
            "max_cpu_secs": p.max_cpu_secs,
        },
        "enforcement": enforcement,
        "blocked": blocked,
    })
}

pub(crate) fn explain(p: &Policy) {
    println!("role: {}", if p.role.is_empty() { "(unset)" } else { &p.role });
    println!("network: {:?}", p.network);
    if !p.local_ports.is_empty() {
        println!("loopback ports (connect only): {:?}", p.local_ports);
    }
    if p.listen_any {
        println!("listen: any port (Linux, only inside the run's own network namespace)");
    }
    if !p.listen_ports.is_empty() {
        println!("listen ports (bind + accept, opt-in): {:?}", p.listen_ports);
    }
    if !p.allow_domains.is_empty() {
        println!("egress domains (via broker, HTTPS/CONNECT + SSRF defense): {}", p.allow_domains.join(", "));
        if let Some(m) = MASKED.get() {
            for (name, hosts) in &m.creds {
                println!(
                    "masked credential {name}: the agent holds a sentinel; the broker terminates TLS to {} and swaps in the real value (headers and body)",
                    hosts.join(", ")
                );
            }
            if !m.exclude.is_empty() {
                println!("never terminated (tlsTerminate.excludeDomains): {}", m.exclude.join(", "));
            }
        }
        for r in REQUEST_RULES.lock().unwrap().iter() {
            let methods = if r.methods.is_empty() { "any method".to_string() } else { r.methods.join(",") };
            let paths = if r.paths.is_empty() { "any path".to_string() } else { r.paths.join(", ") };
            println!("request rule {}: {methods} on {paths} (TLS terminated; anything else refused, 403)", r.host);
        }
    }
    println!("deny AF_UNIX sockets: {}", p.deny_unix_sockets);
    if !p.allow_mach_register.is_empty() {
        println!("macOS Mach register (prefix): {}", p.allow_mach_register.join(", "));
    }
    if !p.allow_mach_lookup.is_empty() {
        let base = if p.mach_lookup_only { "only these" } else { "curated base +" };
        println!("macOS Mach lookup ({base} prefix): {}", p.allow_mach_lookup.join(", "));
    }
    if p.private_tmp {
        println!("private tmp: a run-private TMPDIR is created, made writable, and AF_UNIX-scoped (macOS)");
    }
    for d in &p.unix_socket_subpaths {
        println!("AF_UNIX bind/connect scoped to (subpath): {}", d.display());
    }
    println!("isolate PID namespace: {}", p.isolate_pids);
    println!("isolate network (no egress): {}", p.isolate_network);
    println!("seccomp attack-surface reduction: {}", p.harden_syscalls);
    println!("strict (guaranteed-or-abort): {}", p.strict);
    println!("isolate /proc (env reads): {}", p.isolate_process_info);
    if p.inherit_env {
        println!("environment: FULL passthrough (--inherit-env) — launcher env, incl. any secrets, is inherited");
    } else {
        println!("environment: scrubbed to safe allowlist ({})", tartaros_core::ENV_ALLOWLIST.join(", "));
        println!("  + LC_* (locale)");
        // Show only NAMES, never values: a `--env KEY=VALUE` carries a literal secret,
        // and explain output lands in logs/CI. Distinguish inherited (KEY) from
        // explicitly-set (KEY=…, value redacted).
        if !p.env_passthrough.is_empty() {
            let shown: Vec<String> = p
                .env_passthrough
                .iter()
                .map(|e| match e.split_once('=') {
                    Some((k, _)) => format!("{k}=<redacted>"),
                    None => format!("{e} (inherited)"),
                })
                .collect();
            println!("  + explicit --env: {}", shown.join(", "));
        }
    }
    if let Some(t) = p.timeout { println!("timeout: {}s", t.as_secs()); }
    if let Some(m) = p.max_memory_bytes { println!("max memory: {m} bytes"); }
    if let Some(n) = p.max_processes { println!("max processes: {n}"); }
    if let Some(c) = p.max_cpu_secs { println!("max cpu: {c}s (RLIMIT_CPU)"); }
    println!("\nwritable roots:");
    for r in &p.writable_roots { println!("  + {}", r.display()); }
    println!("\nwrite-denied (inside writable roots):");
    for r in p.fs_rules.iter().filter(|r| r.access == Access::Deny) {
        println!("  x {}", r.path.display());
    }
    println!("\nread-denied (secrets):");
    for r in &p.read_denies { println!("  - {}", r.display()); }
    if !p.read_allows.is_empty() {
        println!("\nread re-allowed (inside a read-deny):");
        for r in &p.read_allows { println!("  + {}", r.display()); }
    }
    // The handoff set is protected by NAME at any depth under each writable root.
    // We list the names themselves, not an enumeration of matching paths on disk:
    // the protection covers paths that do not exist yet (pre-planting defense), and
    // walking a large writable tree (e.g. --write /tmp) just to print it would be a
    // needless stat storm.
    if !p.handoff_exempt.is_empty() {
        println!("\ntrust-handoff NOT protected inside (--handoff-exempt):");
        for e in &p.handoff_exempt { println!("  ~ {}", e.display()); }
    }
    if !p.handoff_scratch.is_empty() {
        println!("\ntrust-handoff NOT protected inside (--handoff-scratch, discarded after the run):");
        for e in &p.handoff_scratch { println!("  ~ {}", e.display()); }
    }
    if !p.handoff_allow.is_empty() {
        println!("\ntrust-handoff names NOT protected in this run (--allow-handoff):");
        for n in &p.handoff_allow { println!("  ~ **/{n}"); }
    }
    println!("\ntrust-handoff protected (deny write at any depth under each writable root):");
    for name in p.handoff_config_names() { println!("  ! **/{name}"); }
    for name in tartaros_core::HANDOFF_GIT_NAMES { println!("  ! **/{name}  (in any git repo)"); }

    // What this policy ACTUALLY enforces on THIS host (probed), so guarantees can
    // be verified up front rather than discovered from stderr warnings at runtime.
    println!("\nenforcement on this host:");
    #[cfg(target_os = "macos")]
    for line in tartaros_macos::enforcement_report(p) { println!("  · {line}"); }
    #[cfg(target_os = "linux")]
    for line in tartaros_linux::enforcement_report(p) { println!("  · {line}"); }

    #[cfg(target_os = "macos")]
    {
        println!("\n--- macOS Seatbelt profile ---");
        println!("{}", tartaros_macos::compile_profile(p));
    }
    #[cfg(target_os = "linux")]
    {
        let bind = tartaros_linux::uses_bind_mounts(p);
        if bind {
            println!("\n--- Linux enforcement: whole workspace writable + read-only bind mounts ---");
            println!("The EXISTING trust-handoff set is protected by read-only bind mounts (mount");
            println!("namespace), so new entries CAN be created at a writable root while existing");
            println!("handoff paths stay unwritable.");
            println!("warning: because the whole root is writable, a NOT-YET-EXISTING handoff path");
            println!("(e.g. a new top-level .claude/settings.json, or a newly-created nested git");
            println!("repo's .git/hooks) is NOT protected under this strategy — only paths that");
            println!("exist when the sandbox starts are bound read-only. Pre-planting defense for");
            println!("absent paths is a macOS (Seatbelt regex) property; on Linux it needs the carve");
            println!("+ --materialize (top-level only), which is mutually exclusive with whole-root");
            println!("create-at-root. The real-world attack (poisoning an EXISTING repo config) is");
            println!("blocked; seeding a brand-new config/repo for a later trusted tool is not.");
        } else {
            println!("\n--- Linux Landlock allow-lists (based on the current filesystem) ---");
            println!("write (carved):");
            for a in p.linux_write_allowlist() { println!("  w {}", a.display()); }
            println!("read (carved):");
            for a in p.linux_read_allowlist() { println!("  r {}", a.display()); }
            println!("note: writes grant write-only; reads are governed by the read carve.");
            // Warn where the carve cannot allow creating NEW entries directly at a
            // writable root (a trust-handoff or explicit deny sits below, existing
            // or not). This is LESS permission, not a contract break — a consumer
            // surfaces it as a notice. The backend answers from the carve the run
            // uses, so the warning is said exactly when the run will refuse.
            for w in tartaros_linux::roots_without_new_entries(p) {
                let mut named: Vec<String> = w.denies.iter().take(3).map(|d| d.display().to_string()).collect();
                if w.denies.len() > 3 { named.push(format!("{} more", w.denies.len() - 3)); }
                println!(
                    "warning: on Linux, new entries cannot be created directly in {} (Landlock cannot grant a directory minus what is below it: {}); existing files and subdirectories are writable. Write into a subdirectory instead. The read-only bind mounts that lift this are not used: {}.",
                    w.root.display(),
                    named.join(", "),
                    w.because
                );
            }
        }
    }
}
