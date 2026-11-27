//! Secrets handed to tartaros in its own environment: moved to a pipe across a
//! clean re-exec, and the run refused while another process's exec record holds one
//! (`--allow-exposed-secrets`).

#[cfg(unix)]
use crate::policy_file::{BROKER, MASKED};
#[cfg(unix)]
use crate::EXIT_POLICY_REFUSED;
#[cfg(unix)]
use std::process::exit;
#[cfg(unix)]
use tartaros_core::Policy;

/// Secrets this process was handed through a pipe by its own clean re-exec
/// (`reexec_without_secrets`), by variable name. Read with [`secret_var`].
static SECRETS: std::sync::OnceLock<std::collections::HashMap<String, String>> = std::sync::OnceLock::new();

/// The internal variable naming the pipe's fd across the re-exec. Holds a
/// number, never a secret; removed as soon as it is read.
#[cfg(unix)]
const SECRETS_FD_VAR: &str = "TARTAROS_INTERNAL_SECRETS_FD";

/// A secret by variable name: from the pipe after a clean re-exec, otherwise
/// from this process's environment.
pub(crate) fn secret_var(name: &str) -> Option<String> {
    SECRETS.get().and_then(|m| m.get(name).cloned()).or_else(|| std::env::var(name).ok())
}

/// After a re-exec: read the secrets the pre-exec image wrote to the pipe
/// (`name\0value\0`…), close it, forget the fd's number.
#[cfg(unix)]
pub(crate) fn take_secrets_from_pipe() {
    use std::io::Read;
    use std::os::fd::FromRawFd;
    let Some(fd) = std::env::var(SECRETS_FD_VAR).ok().and_then(|v| v.parse::<i32>().ok()) else { return };
    std::env::remove_var(SECRETS_FD_VAR);
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        eprintln!("tartaros: cannot read the secrets handed over the re-exec");
        exit(1);
    }
    drop(f); // closes the fd: the agent never inherits it
    let parts: Vec<&[u8]> = buf.split(|b| *b == 0).collect();
    let mut map = std::collections::HashMap::new();
    for kv in parts.chunks(2) {
        if let [k, v] = kv {
            if !k.is_empty() {
                map.insert(String::from_utf8_lossy(k).into_owned(), String::from_utf8_lossy(v).into_owned());
            }
        }
    }
    let _ = SECRETS.set(map);
}

/// The secrets a run will read from the environment: masked credentials' values
/// and the `[broker]`'s `value_env` / `token_env`.
#[cfg(unix)]
fn secret_names() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if let Some(m) = MASKED.get() {
        names.extend(m.creds.iter().map(|(n, _)| n.clone()));
    }
    if let Some(b) = BROKER.get() {
        names.extend(b.token_env.iter().cloned());
        names.extend(b.inject.iter().map(|i| i.value_env.clone()));
        names.extend(b.capability.iter().flat_map(|c| c.inject.iter().map(|i| i.value_env.clone())));
    }
    names.sort();
    names.dedup();
    names
}

/// Clean re-exec (macOS and Linux): a process's exec-time environment can stay
/// readable for its whole life by other processes of the same user
/// (`/proc/<pid>/environ` on Linux), whatever it later does with `remove_var`. The agent is a descendant running as the same
/// user, so a secret in tartaros's exec environment is a secret the agent can
/// read. When a run will hold one, tartaros takes the values out of its
/// environment, writes them to a pipe, and `execve`s itself (same pid) with an
/// environment without them, naming the pipe's fd in [`SECRETS_FD_VAR`]; the new
/// image reads them into memory and closes the fd. All of it before the broker
/// starts or the agent exists. The launcher's own exec environment is outside
/// tartaros's reach (docs/broker.md).
#[cfg(unix)]
pub(crate) fn reexec_without_secrets() {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    if SECRETS.get().is_some() {
        return; // this IS the clean image
    }
    let present: Vec<(String, String)> =
        secret_names().into_iter().filter_map(|n| std::env::var(&n).ok().map(|v| (n, v))).collect();
    if present.is_empty() {
        return;
    }
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        eprintln!("tartaros: cannot hand the secrets to a clean re-exec: {}", std::io::Error::last_os_error());
        exit(1);
    }
    let (r, w) = (unsafe { std::fs::File::from_raw_fd(fds[0]) }, unsafe { std::fs::File::from_raw_fd(fds[1]) });
    let mut payload = Vec::new();
    for (k, v) in &present {
        payload.extend_from_slice(k.as_bytes());
        payload.push(0);
        payload.extend_from_slice(v.as_bytes());
        payload.push(0);
    }
    // A pipe holds at least 16 KiB (64 KiB on Linux and macOS): enough for
    // credentials; larger refuses rather than blocking before the exec.
    if payload.len() > 16 * 1024 {
        eprintln!("tartaros: the run's secrets are larger than 16 KiB; refusing to hand them over");
        exit(EXIT_POLICY_REFUSED);
    }
    let mut w = w;
    if w.write_all(&payload).is_err() {
        eprintln!("tartaros: cannot hand the secrets to a clean re-exec");
        exit(1);
    }
    drop(w);
    // The read end must survive the exec; everything else keeps CLOEXEC.
    unsafe {
        let flags = libc::fcntl(r.as_raw_fd(), libc::F_GETFD);
        libc::fcntl(r.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }
    let exe = std::env::current_exe().unwrap_or_else(|e| {
        eprintln!("tartaros: cannot find its own binary for a clean re-exec: {e}");
        exit(1);
    });
    let names: Vec<&String> = present.iter().map(|(k, _)| k).collect();
    let env: Vec<(String, String)> = std::env::vars().filter(|(k, _)| !names.contains(&k)).collect();
    let err = std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env_clear()
        .envs(env)
        .env(SECRETS_FD_VAR, r.as_raw_fd().to_string())
        .exec();
    eprintln!("tartaros: clean re-exec failed: {err}");
    exit(1);
}

/// Set by `--allow-exposed-secrets`: run even when another process's exec
/// record holds one of the run's secrets.
pub(crate) static ALLOW_EXPOSED_SECRETS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Secrets shorter than this are not looked for: too many chance matches.
#[cfg(unix)]
const EXPOSED_MIN_LEN: usize = 8;

/// The exec records (arguments and environment) of this user's processes, as the
/// agent could read them, with each process's name. On macOS that is
/// `KERN_PROCARGS2`, which no Seatbelt rule we found denies (measured on macOS 15:
/// neither `sysctl-read` nor `process-info*`); on Linux, `/proc/<pid>/cmdline` and
/// `environ`.
#[cfg(target_os = "macos")]
fn exec_records() -> Vec<(u32, String, Vec<u8>)> {
    let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if n <= 0 {
        return Vec::new();
    }
    let mut pids = vec![0i32; n as usize + 64];
    let bytes = (pids.len() * std::mem::size_of::<i32>()) as i32;
    let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) }.max(0) as usize;
    let mut buf = vec![0u8; 1 << 20]; // ARG_MAX
    let mut out = Vec::new();
    for &pid in &pids[..n.min(pids.len())] {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        let mut size = buf.len();
        let rc = unsafe { libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr().cast(), &mut size, std::ptr::null_mut(), 0) };
        if rc != 0 || size <= 4 {
            continue;
        }
        let rec = buf[..size].to_vec();
        // argc (4 bytes), then the exec path.
        let name = rec[4..].split(|b| *b == 0).next().map(|p| String::from_utf8_lossy(p).into_owned()).unwrap_or_default();
        out.push((pid as u32, name, rec));
    }
    out
}

#[cfg(target_os = "linux")]
fn exec_records() -> Vec<(u32, String, Vec<u8>)> {
    let Ok(dir) = std::fs::read_dir("/proc") else { return Vec::new() };
    let mut out = Vec::new();
    for e in dir.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let mut rec = std::fs::read(e.path().join("cmdline")).unwrap_or_default();
        rec.extend(std::fs::read(e.path().join("environ")).unwrap_or_default());
        if rec.is_empty() {
            continue;
        }
        let name = std::fs::read_to_string(e.path().join("comm")).unwrap_or_default().trim().to_string();
        out.push((pid, name, rec));
    }
    out
}

/// Refuse the run (exit 78) when another process's exec record holds one of its
/// secrets: the agent could read it there, and the masked credential or the
/// broker would hide nothing. Most often the launcher: a shell that `export`ed
/// the value, or named it on its command line. On Linux a run that hides other
/// processes (`--isolate-pids`, `--isolate-proc`) is not checked.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn refuse_exposed_secrets(p: &Policy) {
    if ALLOW_EXPOSED_SECRETS.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    #[cfg(target_os = "linux")]
    if p.isolate_pids || p.isolate_process_info {
        return;
    }
    #[cfg(target_os = "macos")]
    let _ = p;
    let secrets: Vec<(String, String)> = secret_names()
        .into_iter()
        .filter_map(|n| secret_var(&n).map(|v| (n, v)))
        .filter(|(_, v)| v.len() >= EXPOSED_MIN_LEN)
        .collect();
    if secrets.is_empty() {
        return;
    }
    let me = std::process::id();
    let mut exposed = Vec::new();
    for (pid, name, rec) in exec_records() {
        if pid == me {
            continue;
        }
        for (var, v) in &secrets {
            if rec.windows(v.len()).any(|w| w == v.as_bytes()) {
                exposed.push(format!("{var} in pid {pid} ({name})"));
            }
        }
    }
    if exposed.is_empty() {
        return;
    }
    for e in &exposed {
        eprintln!("tartaros: secret exposed: the value of {e}, whose arguments or environment the agent can read");
    }
    eprintln!(
        "tartaros: refusing to run. Give the value to tartaros's environment only (`VAR=\"$(…)\" tartaros run …`, \
         not `export`), or pass --allow-exposed-secrets"
    );
    exit(EXIT_POLICY_REFUSED);
}
