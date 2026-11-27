//! tartaros CLI — run a command confined by a policy, on the OS backend.
//!
//! Usage:
//!   tartaros run [options] -- <command> [args...]
//!
//! Options:
//!   --profile NAME         threat-model preset: local-agent | hostile-code | multi-tenant
//!   --role NAME            label for effect-log attribution
//!   --write DIR            a writable root (repeatable)
//!   --read-deny DIR        deny reads of this path (repeatable; secrets)
//!   --read-allow DIR       re-allow reading this path inside a read-deny (repeatable)
//!   --write-deny DIR       deny writes to this path inside a writable root (repeatable)
//!   --port N               allow connecting to this loopback TCP port (repeatable; never listening)
//!   --listen N             allow listening on this TCP port, and connecting to it (repeatable;
//!                          opt-in: an inbound channel, see docs/limits.md)
//!   --listen any           any port, ephemeral included; Linux only, inside the run's own
//!                          empty network namespace (refused where it would reach the LAN)
//!   --allow-domain HOST    egress ONLY to this domain, via the capability broker
//!                          (CONNECT/HTTPS + SSRF defense); repeatable
//!   --net                  allow all network (default: denied)
//!   --deny-unix            deny AF_UNIX sockets (Linux, seccomp; the default there)
//!   --allow-unix           let the agent create AF_UNIX sockets (Linux; reaches host daemons)
//!   --isolate-pids         run in a private PID+mount namespace (Linux; hides host processes)
//!   --isolate-net          run in an empty network namespace (Linux; no egress at all, loopback only)
//!   --seccomp-strict       deny dangerous syscalls to shrink kernel attack surface (Linux)
//!   --strict               a requested guarantee that cannot be installed aborts the run
//!   --materialize          pre-create absent trust-handoff placeholders (Linux)
//!   --allow-home-handoff   allow writing shell rc / .gitconfig / .ripgreprc (denied by default)
//!   --handoff-exempt DIR   no trust-handoff protection inside DIR, a dependency tree (repeatable)
//!   --allow-handoff NAME   do not protect this one trust-handoff name, e.g. .goose (repeatable)
//!   --handoff-scratch DIR  DIR is a writable root thrown away after the run: no trust-handoff protection in it
//!   --allow-request SPEC   "METHODS host[/path]": the only requests an allowed domain gets (repeatable)
//!   --private-tmp          run-private TMPDIR, AF_UNIX scoped to it (headless browsers)
//!   --mach-lookup-only     macOS: allowMachLookup opens ONLY its prefixes (no curated base)
//!   --env KEY[=VALUE]      carry one launcher var through, or set it (default: env is scrubbed)
//!   --inherit-env          inherit the full launcher env (opt into leaking secrets)
//!   --allow-exposed-secrets  run even if another process's exec record holds a run's secret
//!   --timeout SECS         kill the process group after SECS (exit 124)
//!   --max-mem BYTES        address-space limit
//!   --max-procs N          process limit
//!   --max-cpu SECS         total CPU-seconds limit (RLIMIT_CPU; root-proof)
//!   --log FILE             write the effect log here, the egress broker's decisions included
//!   --egress-log FILE      only the egress broker's decisions (JSON Lines), no effect collectors
//!   --log-format F         jsonl (default) or otlp (OpenTelemetry, with the launcher's TRACEPARENT)
//!   --settings FILE        map a sandbox-runtime settings.json onto the generic
//!                          policy; refuses (exit 78) on anything it can't guarantee
//!
//! Exit code is the command's (128+signal on signal death, 124 on timeout); TartarOS's
//! own are 78 (policy refused, nothing ran), 2 (bad command line), 1 (could not run).

use tartaros_core::{Access, FsRule, Network, Policy, Profile};

#[cfg(target_os = "linux")]
mod egress_ns;
mod snapshot;

mod apparmor;
mod brokers;
mod explain;
mod log;
mod policy_file;
mod run;
mod secrets;
mod settings;
use apparmor::*;
use brokers::*;
use explain::*;
use log::*;
use policy_file::*;
use run::*;
use secrets::*;
use settings::*;

/// Teardown guard for scoped-egress state held across the run. On Linux it owns the
/// network namespace (NET-01); elsewhere there is nothing to tear down.
#[cfg(target_os = "linux")]
type EgressGuard = Option<egress_ns::EgressNs>;
#[cfg(not(target_os = "linux"))]
type EgressGuard = ();
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;

/// Exit code when TartarOS refuses the POLICY — a field or combination this backend
/// cannot enforce, so nothing ran. Distinct from 1 (TartarOS could not start or run:
/// broker, log, temp dir, a host missing a requested guarantee) and 2 (bad command
/// line). 78 is sysexits' EX_CONFIG.
const EXIT_POLICY_REFUSED: i32 = 78;

fn main() {
    #[cfg(unix)]
    take_secrets_from_pipe();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("run") => cmd_run(&args[1..]),
        Some("explain") => cmd_explain(&args[1..]),
        Some("why") => cmd_why(&args[1..]),
        Some("snapshot") => cmd_snapshot(&args[1..]),
        Some("rollback") => cmd_rollback(&args[1..]),
        Some("setup") => cmd_setup(&args[1..]),
        Some("version" | "--version" | "-V") => {
            println!("tartaros {} ({})", env!("CARGO_PKG_VERSION"), backend_os());
            exit(0);
        }
        Some("help" | "--help" | "-h") | None => {
            print!("{HELP}");
            exit(if args.is_empty() { 2 } else { 0 });
        }
        Some(other) => {
            eprintln!("tartaros: unknown command `{other}`\n");
            print!("{HELP}");
            exit(2);
        }
    }
}

fn backend_os() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux/landlock+seccomp+cgroup+ns"
    } else if cfg!(target_os = "macos") {
        "macos/seatbelt"
    } else if cfg!(target_os = "windows") {
        #[cfg(target_os = "windows")]
        {
            match tartaros_windows::Tier::from_env() {
                tartaros_windows::Tier::AppContainer => "windows/appcontainer",
                tartaros_windows::Tier::SandboxUser => "windows/sandbox-user",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            "windows"
        }
    } else {
        "unsupported"
    }
}

const HELP: &str = "\
TartarOS — secure agent runtime. NOTHING ESCAPES THE BOUNDARY.

USAGE:
  tartaros run [options] -- <command> [args...]   run a command confined by a policy
  tartaros explain [options]                      print what a policy grants, without running
  tartaros why read|write PATH [options]          which rule of the policy allows or denies that access
  tartaros snapshot list | diff ID                the snapshots taken with run --snapshot
  tartaros rollback ID [--dry-run]                put the writable roots back as snapshot ID found them
  tartaros setup apparmor [--print]               Linux: let this binary make user namespaces on a host
                                                  that restricts them (Ubuntu 23.10+); needs root
  tartaros version                                print version and backend
  tartaros help                                   this help

PROFILE (preset threat model; flags still extend it):
  --profile local-agent|hostile-code|multi-tenant

POLICY:
  --config FILE          load a TOML policy (flags override it); its [broker]
                         table starts the credential broker (docs/broker.md)
  --settings FILE        map a sandbox-runtime settings.json onto the generic
                         policy; refuses (exit 78) on anything it can't guarantee
  --role NAME            label for the effect log
  --write DIR            a writable root (repeatable)
  --read-deny DIR        deny reads of this path, e.g. a secret dir (repeatable)
  --read-allow DIR       re-allow reading this path inside a read-deny (repeatable)
  --write-deny DIR       deny writes to this path inside a writable root (repeatable)
  --port N               allow connecting to this loopback TCP port (repeatable;
                         never listening on it)
  --listen N             allow listening on this TCP port, and connecting to it
                         (repeatable; opt-in, an inbound channel: docs/limits.md)
  --listen any           any port, ephemeral (0) included, for test suites. Linux
                         only, in the run's own empty network namespace; refused
                         (exit 78) where a listener would be reachable from the LAN
  --allow-domain HOST    egress ONLY to this domain through the broker (HTTPS via
                         CONNECT, SSRF-defended); .example.com matches subdomains
  --net                  allow all network (default: denied)

HARDENING (Linux; the hostile/multi-tenant profiles set these):
  --isolate-pids         private PID+mount namespace (hide host processes)
  --isolate-net          empty network namespace (no egress, any protocol)
  --seccomp-strict       deny dangerous syscalls (shrink kernel attack surface)
  --strict               a requested guarantee that cannot be installed aborts the run
  --deny-unix            deny AF_UNIX sockets (the default on Linux)
  --allow-unix           let the agent create AF_UNIX sockets (Linux): it can then
                         reach host daemons (D-Bus, systemd --user, docker)
  --isolate-proc         deny reads of other processes' /proc
  --materialize          pre-create absent trust-handoff placeholders
  --allow-home-handoff   let the agent write shell rc / .gitconfig / .ripgreprc in its
                         roots (denied by default; for dotfiles repos)
  --allow-request SPEC   'METHODS host[/path]' (METHODS: GET,POST… or *): the requests the
                         agent may send to an allowed domain. Its TLS is terminated with
                         the run's CA and any other request is refused (403). Repeatable
  --handoff-exempt DIR   no trust-handoff protection inside DIR (strictly inside a
                         writable root): a dependency tree a setup phase fills, whose
                         packages ship .gitattributes/.github/.git. Repeatable; said
                         at start and in explain
  --allow-handoff NAME   do not protect this one name of the trust-handoff set, at any
                         depth (e.g. .goose where the agent writes goose recipes).
                         Only names `explain` lists, not the git ones; an unknown name
                         is refused (exit 78). Repeatable; said at start and in explain
  --handoff-scratch DIR  DIR (also a --write root) is thrown away after the run, so no
                         trust-handoff protection in it: a run's TMPDIR, where tests
                         create repos and conftest.py. Refused if it overlaps another
                         writable root, holds $HOME or the starting directory, or is a
                         git repo. Repeatable; said at start and in explain
  --private-tmp          run-private TMPDIR; AF_UNIX scoped to it (headless browsers)
  --browser              macOS: minimal extra Seatbelt grants for headless Chromium/Chrome
  --mach-lookup-only     macOS: allowMachLookup opens ONLY its prefixes, without the
                         curated base of system services (breaks the keychain, etc.)

ENVIRONMENT (secrets in the launcher's env are NOT governed by Landlock/Seatbelt):
  (default)              scrub env to a safe allowlist (PATH/HOME/LANG/... + LC_*)
  --env KEY              carry one var through from the launcher's environment
  --env KEY=VALUE        set one var explicitly for the agent
  --inherit-env          FULL passthrough: inherit the launcher env, secrets and all
  --allow-exposed-secrets  run even if another process's exec record (a shell that
                         exported it) holds a masked credential's or the broker's secret

SNAPSHOTS:
  --snapshot             snapshot the writable roots before the run; `tartaros rollback ID`
                         restores them (the store, outside the roots, is read-denied)
  --snapshot-exclude N   leave directories named N out (node_modules, target); repeatable
  --snapshot-max-bytes B refuse the run (78) if the roots hold more (default 2 GiB)

LIMITS:
  --timeout SECS         kill the run after SECS (exit 124)
  --max-mem BYTES        address-space / cgroup memory cap
  --max-procs N          process cap (cgroup pids.max; root-proof)
  --max-cpu SECS         total CPU-seconds cap

OBSERVABILITY:
  --log FILE             write the first-hand effect log (JSON Lines), the egress
                         broker's connect decisions included
  --egress-log FILE      only the egress broker's decisions (JSON Lines): no effect
                         collectors, so it costs a run nothing extra
  --log-format F         jsonl (default) or otlp: OpenTelemetry log records in the
                         open effect schema, with the launcher's TRACEPARENT

Exit code is the command's (128+signal on signal death, 124 on timeout). TartarOS's own:
  78  the policy was refused (this backend cannot enforce it); nothing ran
  2   bad command line
  1   TartarOS could not start or run the command
";

fn cmd_run(rest: &[String]) -> ! {
    let split = rest.iter().position(|a| a == "--");
    let (opts, cmd): (&[String], Vec<String>) = match split {
        Some(i) => (&rest[..i], rest[i + 1..].to_vec()),
        None => {
            eprintln!("error: missing `--` before the command");
            exit(2);
        }
    };
    if cmd.is_empty() {
        eprintln!("error: no command after `--`");
        exit(2);
    }
    let (opts, snap_spec) = snapshot_flags(opts);
    let (mut p, log, profile) = build_policy(&opts, false); // run: quiet
    // Secrets out of tartaros's exec environment before anything can read it.
    #[cfg(unix)]
    reexec_without_secrets();
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    refuse_exposed_secrets(&p);
    if p.writable_roots.is_empty() {
        eprintln!("warning: no --write roots; the command cannot write anywhere");
    }
    let snap = snap_spec.on.then(|| take_run_snapshot(&mut p, &snap_spec));
    // Note: the environment is scrubbed to a safe allowlist by the BACKEND at spawn
    // (F-13, `Policy::child_env`), so secrets in the launcher's env never reach the
    // agent and the guarantee holds for any embedder, not just this CLI. The broker
    // and --private-tmp set their vars (proxy, TMPDIR) in this process's env below;
    // those names are in the allowlist, so they survive into the child.
    // Domain-scoped egress: start the capability broker and route the agent
    // through it. On Linux-as-root this builds a scoped network namespace (NET-01);
    // the returned guard tears it (netns + veth + firewall rule) down after the run.
    // The broker writes to --log when there is one, else to --egress-log alone.
    let broker_log = log.clone().or_else(|| EGRESS_LOG.get().map(|path| LogSpec { path: path.clone(), format: LogFormat::Jsonl }));
    let egress_guard = start_egress_broker(&mut p, broker_log.as_ref());
    start_credential_broker(&mut p);
    // A handoff exemption is said every time: it is an opening, and a log of the
    // run should show it was there.
    for e in &p.handoff_exempt {
        eprintln!("tartaros: trust-handoff not protected inside {} (--handoff-exempt)", e.display());
    }
    // Refuse an --allow-handoff name that is not in the set before saying it is
    // open: the backends refuse it too, but only after this line was printed.
    if let Err(reason) = p.check_handoff_allow() {
        eprintln!("tartaros: {reason}");
        exit(EXIT_POLICY_REFUSED);
    }
    for n in &p.handoff_allow {
        eprintln!("tartaros: trust-handoff name {n} not protected anywhere in this run (--allow-handoff)");
    }
    for e in &p.handoff_scratch {
        eprintln!("tartaros: trust-handoff not protected inside {} (--handoff-scratch, discarded after the run)", e.display());
    }
    // Print the profile's honest caveat before running — a tier must never
    // silently overclaim (esp. multi-tenant on a shared kernel).
    if let Some(pr) = profile {
        if let Some(c) = pr.caveat() {
            eprintln!("tartaros: profile {} — {}", pr.name(), c);
        }
    }
    let private_tmp = setup_private_tmp(&mut p);
    warn_reachable_host_sockets(&p);
    #[cfg(target_os = "linux")]
    warn_roots_without_new_entries(&p);
    let code = run(&p, &cmd, log.as_ref());
    // What the broker decided is in its log before the launcher exits: a refusal
    // in the run's last milliseconds was lost (`--egress-log` came back empty).
    tartaros_broker::flush(std::time::Duration::from_secs(2));
    if let Some(m) = &snap {
        match snapshot::diff(m) {
            Ok(d) => eprintln!(
                "tartaros: since snapshot {}: {} added, {} changed, {} removed (tartaros snapshot diff {0}; tartaros rollback {0})",
                m.id,
                d.added.len(),
                d.changed.len(),
                d.removed.len()
            ),
            Err(e) => eprintln!("tartaros: snapshot {}: {e}", m.id),
        }
    }
    // Tear down the run-private temp dir (our own ephemeral scratch for this run).
    if let Some(dir) = private_tmp {
        let _ = std::fs::remove_dir_all(&dir);
    }
    // And the masked credentials' CA directory (its certificate and trust bundle).
    if let Some(dir) = MASK_DIR.get() {
        let _ = std::fs::remove_dir_all(dir);
    }
    // Drop the egress guard here: `process::exit` below skips destructors, so the
    // scoped network namespace (+ veth + firewall rule) would otherwise leak. The
    // `let _ =` binding drops it immediately (a no-op on non-Linux, where it is ()).
    #[cfg(target_os = "linux")]
    std::mem::drop(egress_guard);
    #[cfg(not(target_os = "linux"))]
    let _ = egress_guard;
    exit(code);
}

/// `--private-tmp`: give the run its own temp dir, export it as TMPDIR, make it
/// writable, and (macOS) scope AF_UNIX bind/connect to it — so a headless
/// browser's control socket (Playwright publishes under `$TMPDIR`) lands in a
/// run-private dir instead of the shared temp where other runs' sockets live.
/// Returns the dir for teardown. No Playwright internals: we only set TMPDIR.
fn setup_private_tmp(p: &mut Policy) -> Option<std::path::PathBuf> {
    if !p.private_tmp {
        return None;
    }
    let dir = match create_private_tmp() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("tartaros: cannot create private tmp dir: {e}");
            exit(1);
        }
    };
    // The child (and any tool that reads os.tmpdir()/TMPDIR) publishes here.
    for k in ["TMPDIR", "TMP", "TEMP"] {
        std::env::set_var(k, &dir);
    }
    p.writable_roots.push(dir.clone());
    p.unix_socket_subpaths.push(dir.clone());
    eprintln!(
        "tartaros: private tmp {} (exported as TMPDIR; AF_UNIX scoped to it on macOS)",
        dir.display()
    );
    Some(dir)
}

/// Create the run-private temp dir with a SHORT path. AF_UNIX socket paths are
/// capped at 104 bytes (macOS) / 108 (Linux), and tools nest their sockets a few
/// levels under `$TMPDIR` (Playwright's socket dir landed at 107 bytes under a
/// `/var/folders/…` TMPDIR). So: a short per-user base, `/private/tmp/tartaros-<uid>`
/// (`/tmp/…` on Linux), 0700 and verified to be ours, holding `tt-<6 random>`.
#[cfg(unix)]
fn create_private_tmp() -> std::io::Result<std::path::PathBuf> {
    use std::io::{Error, ErrorKind, Read};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let uid = unsafe { libc::getuid() };
    let root = if cfg!(target_os = "macos") { "/private/tmp" } else { "/tmp" };
    let base = std::path::PathBuf::from(format!("{root}/tartaros-{uid}"));
    match std::fs::DirBuilder::new().mode(0o700).create(&base) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Error::new(e.kind(), format!("{}: {e}", base.display()))),
    }
    // /tmp is world-writable: the base may have been planted by someone else, or be
    // a symlink. lstat (never follow) and require a real dir we own, then 0700.
    let md = std::fs::symlink_metadata(&base)?;
    if !md.file_type().is_dir() || md.uid() != uid {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("{} is not a directory owned by uid {uid}; refusing to use it", base.display()),
        ));
    }
    if md.mode() & 0o077 != 0 {
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))?;
    }
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut urandom = std::fs::File::open("/dev/urandom")?;
    for _ in 0..16 {
        let mut b = [0u8; 6];
        urandom.read_exact(&mut b)?;
        let suffix: String = b.iter().map(|x| ALPHABET[*x as usize % ALPHABET.len()] as char).collect();
        let dir = base.join(format!("tt-{suffix}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(Error::new(e.kind(), format!("{}: {e}", dir.display()))),
        }
    }
    Err(Error::new(ErrorKind::AlreadyExists, format!("no free name under {}", base.display())))
}

#[cfg(not(unix))]
fn create_private_tmp() -> std::io::Result<std::path::PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("tt-{}-{}", std::process::id(), nanos));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Never leave a host-escape silent (F-3). On Linux there is no per-path AF_UNIX
/// filtering — Landlock does not govern `connect()` to a pathname socket, and the
/// seccomp AF_UNIX deny is all-or-nothing — so a confined agent can still reach a
/// host daemon's unix socket (docker.sock, containerd, dbus, systemd), which is a
/// full host-escape vector. AF_UNIX is denied by default; when `--allow-unix`
/// opens it and a dangerous socket is present, we warn loudly and point to the fix. macOS denies AF_UNIX egress in the Seatbelt
/// profile natively, so this is Linux-only.
fn warn_reachable_host_sockets(p: &Policy) {
    if cfg!(not(target_os = "linux")) {
        return;
    }
    // The network grant does not matter: a unix socket is not on the network.
    if p.deny_unix_sockets {
        return;
    }
    const DANGEROUS: &[&str] = &[
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/run/podman/podman.sock",
        "/var/run/podman/podman.sock",
        "/run/dbus/system_bus_socket",
        "/run/systemd/private",
        "/var/run/libvirt/libvirt-sock",
    ];
    // The user's own daemons (goose#12805: the session bus starts an unconfined
    // `systemd-run --user`, measured 2026-11-27 on Ubuntu 24.04). The agent's
    // environment is scrubbed of XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS, but
    // it can spell the path itself.
    #[cfg(unix)]
    let uid = unsafe { libc::getuid() };
    #[cfg(not(unix))]
    let uid = 0;
    let per_user: Vec<String> = ["bus", "systemd/private", "docker.sock", "podman/podman.sock"]
        .iter()
        .map(|s| format!("/run/user/{uid}/{s}"))
        .collect();
    let found: Vec<&str> = DANGEROUS
        .iter()
        .copied()
        .chain(per_user.iter().map(String::as_str))
        .filter(|s| std::path::Path::new(s).exists())
        .collect();
    if !found.is_empty() {
        eprintln!(
            "tartaros: warning: a host daemon socket is present and reachable by the \
             agent over AF_UNIX ({}) — Landlock cannot filter unix sockets by path, so \
             this is a host-escape vector. Drop --allow-unix (AF_UNIX is denied by \
             default), or do not expose the socket.",
            found.join(", ")
        );
    }
}

/// Say before the run, not after the first EACCES, where the Landlock carve will
/// refuse new entries: directly in a writable root with a deny below it, and in
/// a repository's `.git` (its hooks and config are denied), which makes
/// `git add` and `git commit` fail on `.git/index.lock`. Measured 2026-11-27 on
/// Ubuntu 24.04 without root. `explain` said it; `run` did not.
#[cfg(target_os = "linux")]
fn warn_roots_without_new_entries(p: &Policy) {
    let roots = tartaros_linux::roots_without_new_entries(p);
    let gits = tartaros_linux::git_dirs_without_new_entries(p);
    if roots.is_empty() && gits.is_empty() {
        return;
    }
    let mut what: Vec<String> = roots.iter().map(|w| w.root.display().to_string()).collect();
    what.extend(gits.iter().map(|g| format!("{} (git add/commit will fail)", g.display())));
    let because = roots.first().map(|w| w.because.clone()).unwrap_or_else(|| tartaros_linux::carve_reason(p));
    eprintln!(
        "tartaros: warning: new files cannot be created directly in {}; existing files and subdirectories \
         are writable. Why: {}",
        what.join(", "),
        if because.ends_with('.') { because.clone() } else { format!("{because}.") }
    );
}

/// `run`'s snapshot flags, taken out of the policy options.
fn snapshot_flags(opts: &[String]) -> (Vec<String>, snapshot::Spec) {
    let mut spec = snapshot::Spec { max_bytes: snapshot::DEFAULT_MAX_BYTES, ..Default::default() };
    let mut rest = Vec::new();
    let mut it = opts.iter();
    while let Some(o) = it.next() {
        match o.as_str() {
            "--snapshot" => spec.on = true,
            "--snapshot-exclude" | "--snapshot-max-bytes" => {
                let Some(v) = it.next() else {
                    eprintln!("tartaros: {o} needs a value");
                    exit(2);
                };
                if o == "--snapshot-exclude" {
                    if v.is_empty() || v.contains('/') || v == "." || v == ".." {
                        eprintln!("tartaros: --snapshot-exclude takes a directory name, not a path");
                        exit(2);
                    }
                    spec.exclude.push(v.clone());
                } else {
                    spec.max_bytes = v.parse().unwrap_or_else(|_| {
                        eprintln!("tartaros: --snapshot-max-bytes takes a number of bytes");
                        exit(2);
                    });
                }
            }
            _ => rest.push(o.clone()),
        }
    }
    if !spec.on && (!spec.exclude.is_empty() || spec.max_bytes != snapshot::DEFAULT_MAX_BYTES) {
        eprintln!("tartaros: --snapshot-exclude and --snapshot-max-bytes go with --snapshot");
        exit(2);
    }
    (rest, spec)
}

/// Snapshot the roots before the run, or refuse it (78): a run asked to be
/// undoable never starts without its snapshot.
fn take_run_snapshot(p: &mut Policy, spec: &snapshot::Spec) -> snapshot::Manifest {
    use tartaros_core::resolve_best_effort;
    let store = snapshot::store();
    if let Err(e) = std::fs::create_dir_all(&store) {
        eprintln!("tartaros: snapshot store {}: {e}; refusing to run", store.display());
        exit(EXIT_POLICY_REFUSED);
    }
    let store = resolve_best_effort(&store);
    let roots: Vec<PathBuf> = p.writable_roots.iter().map(|r| resolve_best_effort(r)).collect();
    if let Some(r) = roots.iter().find(|r| store.starts_with(r)) {
        eprintln!(
            "tartaros: the snapshot store {} lies inside the writable root {}: the agent could alter it. Set TARTAROS_STATE_DIR elsewhere; refusing to run",
            store.display(),
            r.display()
        );
        exit(EXIT_POLICY_REFUSED);
    }
    let skipped: Vec<PathBuf> = p.read_denies.iter().map(|d| resolve_best_effort(d)).collect();
    match snapshot::take(&roots, &spec.exclude, &skipped, spec.max_bytes) {
        Ok(m) => {
            let files: usize = m.roots.iter().map(|r| r.entries.values().filter(|e| matches!(e, snapshot::Entry::File { .. })).count()).sum();
            eprintln!("tartaros: snapshot {} of the writable roots ({files} files); `tartaros rollback {}` restores them", m.id, m.id);
            p.read_denies.push(store);
            m
        }
        Err(e) => {
            eprintln!("tartaros: {e}; refusing to run");
            exit(EXIT_POLICY_REFUSED);
        }
    }
}

fn cmd_snapshot(args: &[String]) -> ! {
    match (args.first().map(String::as_str), args.get(1)) {
        (Some("list"), None) => {
            for m in snapshot::list() {
                let roots: Vec<String> = m.roots.iter().map(|r| r.path.display().to_string()).collect();
                println!("{}  {}  {}", m.id, snapshot::stamp(m.created_unix), roots.join(" "));
            }
            exit(0);
        }
        (Some("diff"), Some(id)) => {
            let m = snapshot::load(id).unwrap_or_else(|e| {
                eprintln!("tartaros: {e}");
                exit(1);
            });
            let d = snapshot::diff(&m).unwrap_or_else(|e| {
                eprintln!("tartaros: {e}");
                exit(1);
            });
            for (tag, v) in [("added", &d.added), ("changed", &d.changed), ("removed", &d.removed)] {
                for p in v {
                    println!("{tag}\t{}", p.display());
                }
            }
            exit(0);
        }
        _ => {
            eprintln!("tartaros: usage: tartaros snapshot list | tartaros snapshot diff ID");
            exit(2);
        }
    }
}

fn cmd_rollback(args: &[String]) -> ! {
    let dry = args.iter().any(|a| a == "--dry-run");
    let ids: Vec<&String> = args.iter().filter(|a| *a != "--dry-run").collect();
    let [id] = ids.as_slice() else {
        eprintln!("tartaros: usage: tartaros rollback ID [--dry-run]");
        exit(2);
    };
    let m = snapshot::load(id).unwrap_or_else(|e| {
        eprintln!("tartaros: {e}");
        exit(1);
    });
    match snapshot::rollback(&m, dry) {
        Ok((before, d, failed)) => {
            for (tag, v) in [("remove", &d.added), ("restore", &d.changed), ("re-create", &d.removed)] {
                for p in v {
                    println!("{tag}\t{}", p.display());
                }
            }
            if let Some(b) = before {
                eprintln!("tartaros: rolled back to {}; the state it replaced is snapshot {b} (`tartaros rollback {b}` undoes this)", m.id);
            }
            for f in &failed {
                eprintln!("tartaros: not restored: {f}");
            }
            exit(if failed.is_empty() { 0 } else { 1 });
        }
        Err(e) => {
            eprintln!("tartaros: {e}");
            exit(1);
        }
    }
}

/// Parse a numeric flag value or exit with a clear message — never silently fall
/// back to 0, which would turn `--timeout 10m` into "no timeout" (a fail-open).
fn parse_num_or_exit<T: std::str::FromStr>(v: &str, flag: &str) -> T {
    v.parse().unwrap_or_else(|_| {
        eprintln!("error: {flag} expects a number, got '{v}'");
        exit(2);
    })
}

/// Build the Policy from --config (if any) + --profile + flags. Returns the
/// policy, the optional --log (path and format), and the selected profile (for its caveat).
fn build_policy(opts: &[String], verbose: bool) -> (Policy, Option<LogSpec>, Option<Profile>) {
    // Shell rc files, .gitconfig and .ripgreprc in a writable root are protected
    // by default, as sandbox-runtime does: a trusted shell or git later runs what
    // the agent planted there. --allow-home-handoff is the dotfiles-repo opt-out.
    let mut p = Policy { network: Some(Network::Denied), protect_home_handoff: true, ..Default::default() };
    // AF_UNIX is denied by default on Linux, as Seatbelt denies it on macOS:
    // Landlock cannot scope a unix socket by path, and a reachable daemon socket
    // is a way out (the session bus starts an unconfined `systemd-run --user`,
    // measured 2026-11-27 on Ubuntu 24.04). socketpair() keeps working, so
    // multiprocessing, asyncio and child pipes are unaffected. --allow-unix opens it.
    #[cfg(target_os = "linux")]
    {
        p.deny_unix_sockets = true;
    }
    let mut profile: Option<Profile> = None;

    // First pass: load --config (a policy file), so flags can override it.
    if let Some(i) = opts.iter().position(|a| a == "--config") {
        let path = opts.get(i + 1).unwrap_or_else(|| { eprintln!("--config needs a path"); exit(2); });
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| { eprintln!("read {path}: {e}"); exit(2); });
        let pf: PolicyFile = toml::from_str(&text).unwrap_or_else(|e| { eprintln!("parse {path}: {e}"); exit(2); });
        p.role = pf.role;
        p.writable_roots = pf.writable_roots.iter().map(|s| PathBuf::from(expand_path(s))).collect();
        p.read_denies = pf.read_denies.iter().map(|s| PathBuf::from(expand_path(s))).collect();
        p.read_allows = pf.read_allows.iter().map(|s| PathBuf::from(expand_path(s))).collect();
        p.fs_rules.extend(pf.write_denies.iter().map(|s| FsRule { path: PathBuf::from(expand_path(s)), access: Access::Deny, even_if_absent: true }));
        p.local_ports = pf.local_ports;
        p.listen_ports = pf.listen_ports;
        p.listen_any = pf.listen_any;
        p.network = Some(if pf.net { Network::Allowed } else { Network::Denied });
        if let Some(deny) = pf.deny_unix_sockets {
            p.deny_unix_sockets = deny;
        }
        p.isolate_pids = pf.isolate_pids;
        p.isolate_network = pf.isolate_network;
        p.harden_syscalls = pf.harden_syscalls;
        p.strict = pf.strict;
        p.materialize_absent_handoff = pf.materialize_absent_handoff;
        p.handoff_exempt = pf.handoff_exempt.iter().map(|s| PathBuf::from(expand_path(s))).collect();
        p.handoff_allow = pf.handoff_allow.clone();
        p.handoff_scratch = pf.handoff_scratch.iter().map(|s| PathBuf::from(expand_path(s))).collect();
        for r in &pf.request_rule {
            add_request_rule(r.host.clone(), r.methods.clone(), r.paths.clone());
        }
        if let Some(on) = pf.protect_home_handoff {
            p.protect_home_handoff = on;
        }
        p.isolate_process_info = pf.isolate_process_info;
        if let Some(b) = pf.broker {
            let _ = BROKER.set(b);
        }
        p.timeout = pf.timeout_secs.map(Duration::from_secs);
        p.max_memory_bytes = pf.max_memory_bytes;
        p.max_processes = pf.max_processes;
        p.max_cpu_secs = pf.max_cpu_secs;
        if let Some(name) = &pf.profile {
            profile = Some(Profile::parse(name).unwrap_or_else(|| {
                eprintln!("unknown profile in config: {name} (local-agent|hostile-code|multi-tenant)");
                exit(2);
            }));
        }
    }

    // --settings: apply a sandbox-runtime settings file through the generic
    // policy, strictly (guaranteed-or-refuse). It is just an adapter over the same
    // flags; the capabilities live in the sandbox, not in this shortcut.
    if let Some(i) = opts.iter().position(|a| a == "--settings") {
        let path = opts.get(i + 1).unwrap_or_else(|| { eprintln!("--settings needs a path"); exit(2); });
        apply_settings_file(&mut p, path, verbose);
    }

    // --profile on the command line overrides a config profile.
    if let Some(i) = opts.iter().position(|a| a == "--profile") {
        let name = opts.get(i + 1).unwrap_or_else(|| { eprintln!("--profile needs a name"); exit(2); });
        profile = Some(Profile::parse(name).unwrap_or_else(|| {
            eprintln!("unknown profile: {name} (local-agent|hostile-code|multi-tenant)");
            exit(2);
        }));
    }
    // Apply the profile baseline BEFORE flags, so explicit flags can still extend
    // it. Profiles only tighten; they never grant.
    if let Some(pr) = profile {
        pr.apply(&mut p);
    }

    let mut log: Option<String> = None;
    let mut log_format: Option<LogFormat> = None;
    let mut it = opts.iter();
    while let Some(o) = it.next() {
        let mut val = || it.next().cloned().unwrap_or_else(|| { eprintln!("error: {o} needs a value"); exit(2); });
        match o.as_str() {
            "--config" => { let _ = val(); } // handled in the first pass
            "--settings" => { let _ = val(); } // handled above
            "--profile" => { let _ = val(); } // handled in the pre-scan above
            "--role" => p.role = val(),
            "--write" => p.writable_roots.push(PathBuf::from(expand_path(&val()))),
            "--read-deny" => p.read_denies.push(PathBuf::from(expand_path(&val()))),
            "--read-allow" => p.read_allows.push(PathBuf::from(expand_path(&val()))),
            "--write-deny" => p.fs_rules.push(FsRule { path: PathBuf::from(expand_path(&val())), access: Access::Deny, even_if_absent: true }),
            "--port" => p.local_ports.push(val().parse().unwrap_or_else(|_| { eprintln!("bad --port"); exit(2); })),
            "--listen" => match val().as_str() {
                "any" => p.listen_any = true,
                v => p.listen_ports.push(v.parse().unwrap_or_else(|_| { eprintln!("bad --listen (a port, or `any`)"); exit(2); })),
            },
            "--allow-domain" => p.allow_domains.push(val()),
            "--net" => p.network = Some(Network::Allowed),
            "--deny-unix" => p.deny_unix_sockets = true,
            "--allow-unix" => p.deny_unix_sockets = false,
            "--isolate-pids" => p.isolate_pids = true,
            "--isolate-net" => p.isolate_network = true,
            "--seccomp-strict" => p.harden_syscalls = true,
            "--strict" => p.strict = true,
            "--materialize" => p.materialize_absent_handoff = true,
            "--protect-home-handoff" => p.protect_home_handoff = true, // the default since 0.1.0-alpha.7
            "--allow-home-handoff" => p.protect_home_handoff = false,
            "--private-tmp" => p.private_tmp = true,
            "--browser" => p.browser = true,
            "--mach-lookup-only" => p.mach_lookup_only = true,
            "--inherit-env" => p.inherit_env = true,
            "--allow-exposed-secrets" => ALLOW_EXPOSED_SECRETS.store(true, std::sync::atomic::Ordering::Relaxed),
            "--env" => p.env_passthrough.push(val()),
            "--timeout" => p.timeout = Some(Duration::from_secs(parse_num_or_exit(&val(), "--timeout (seconds)"))),
            "--max-mem" => p.max_memory_bytes = Some(parse_num_or_exit(&val(), "--max-mem (bytes)")),
            "--max-procs" => p.max_processes = Some(parse_num_or_exit(&val(), "--max-procs")),
            "--max-cpu" => p.max_cpu_secs = Some(parse_num_or_exit(&val(), "--max-cpu (seconds)")),
            "--isolate-proc" => p.isolate_process_info = true,
            "--log" => log = Some(val()),
            "--egress-log" => { let _ = EGRESS_LOG.set(val()); }
            "--handoff-exempt" => p.handoff_exempt.push(PathBuf::from(expand_path(&val()))),
            "--allow-handoff" => p.handoff_allow.push(val()),
            "--handoff-scratch" => p.handoff_scratch.push(PathBuf::from(expand_path(&val()))),
            "--allow-request" => parse_allow_request(&val()),
            "--log-format" => log_format = Some(match val().as_str() {
                "jsonl" => LogFormat::Jsonl,
                "otlp" => LogFormat::Otlp,
                other => { eprintln!("error: --log-format is jsonl or otlp, not {other:?}"); exit(2); }
            }),
            other => { eprintln!("unknown option: {other}"); exit(2); }
        }
    }
    // Any-depth denies, now that every writable root is known (a backend that
    // matches by inode takes them as concrete paths).
    let any_depth = p.any_depth_rules();
    p.fs_rules.extend(any_depth);
    if log_format.is_some() && log.is_none() {
        eprintln!("error: --log-format needs --log FILE");
        exit(2);
    }
    let log = log.map(|path| LogSpec { path, format: log_format.unwrap_or(LogFormat::Jsonl) });
    (p, log, profile)
}
