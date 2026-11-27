//! Run the confined command on this OS's backend, with or without the effect log.

use crate::EXIT_POLICY_REFUSED;
use crate::log::LogSpec;
use tartaros_core::Policy;
#[cfg(target_os = "linux")]

pub(crate) fn run(policy: &Policy, cmd: &[String], log: Option<&LogSpec>) -> i32 {
    run_common(&tartaros_linux::LandlockBackend, policy, cmd, log, true)
}

#[cfg(target_os = "macos")]
pub(crate) fn run(policy: &Policy, cmd: &[String], log: Option<&LogSpec>) -> i32 {
    run_common(&tartaros_macos::SeatbeltBackend, policy, cmd, log, true)
}

/// Shared run path (both OS): `--log` goes through `run_observed`, which uses the
/// SAME supervisor (timeout, limits, reaping) as `run` — enabling the log never
/// changes the enforcement guarantees (review P0). `net` selects whether to add
/// the network collector.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_common<B>(be: &B, policy: &Policy, cmd: &[String], log: Option<&LogSpec>, net: bool) -> i32
where
    B: RunObserved,
{
    use tartaros_collect::{FileCollector, NetworkCollector, ProcessCollector, SecretCollector};
    use tartaros_core::{Collector, FilterSink, RecordMode};
    // Refuse an unenforceable policy before anything starts, with its own exit
    // code, so a caller can tell "refused your policy" from "could not start".
    if let Err(e) = be.validate(policy) {
        eprintln!("tartaros: {}", e.reason);
        return EXIT_POLICY_REFUSED;
    }
    match log {
        Some(spec) => {
            let s = match spec.open() {
                Ok(s) => s,
                Err(e) => { eprintln!("tartaros: cannot open log {}: {e}", spec.path); return 1; }
            };
            let mut sink = FilterSink::new(s, RecordMode::Boundary);
            let pol = policy.clone();
            let res = be.run_observed(policy, cmd, &mut sink, move |pid| {
                let mut v: Vec<Box<dyn Collector>> = Vec::new();
                if net { v.push(Box::new(NetworkCollector::for_policy(pid, &pol))); }
                v.push(Box::new(SecretCollector::for_policy(pid, &pol)));
                v.push(Box::new(ProcessCollector::for_policy(pid, &pol)));
                v.push(Box::new(FileCollector::for_policy(pid, &pol)));
                v
            });
            match res { Ok(o) => o.exit_code, Err(e) => { eprintln!("tartaros: {}", e.reason); 1 } }
        }
        None => match be.run(policy, cmd) {
            Ok(o) => o.exit_code,
            Err(e) => { eprintln!("tartaros: {}", e.reason); 1 }
        },
    }
}

/// Minimal trait so `run_common` can call either backend's `run_observed`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
trait RunObserved: tartaros_core::Backend {
    fn run_observed<F>(
        &self,
        policy: &Policy,
        command: &[String],
        sink: &mut dyn tartaros_core::EffectSink,
        make: F,
    ) -> Result<tartaros_core::RunOutcome, tartaros_core::RunError>
    where
        F: FnOnce(u32) -> Vec<Box<dyn tartaros_core::Collector>>;
}

#[cfg(target_os = "linux")]
impl RunObserved for tartaros_linux::LandlockBackend {
    fn run_observed<F>(&self, policy: &Policy, command: &[String], sink: &mut dyn tartaros_core::EffectSink, make: F)
        -> Result<tartaros_core::RunOutcome, tartaros_core::RunError>
    where F: FnOnce(u32) -> Vec<Box<dyn tartaros_core::Collector>> {
        tartaros_linux::LandlockBackend::run_observed(self, policy, command, sink, make)
    }
}

#[cfg(target_os = "macos")]
impl RunObserved for tartaros_macos::SeatbeltBackend {
    fn run_observed<F>(&self, policy: &Policy, command: &[String], sink: &mut dyn tartaros_core::EffectSink, make: F)
        -> Result<tartaros_core::RunOutcome, tartaros_core::RunError>
    where F: FnOnce(u32) -> Vec<Box<dyn tartaros_core::Collector>> {
        tartaros_macos::SeatbeltBackend::run_observed(self, policy, command, sink, make)
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn run(policy: &Policy, cmd: &[String], log: Option<&LogSpec>) -> i32 {
    use tartaros_core::Backend;
    // The effect log goes through collectors that sample the process tree; there
    // are none for Windows yet. Enabling the log must never change what is
    // enforced, so rather than silently ignore --log we refuse it (fail-closed).
    if log.is_some() {
        eprintln!("tartaros: --log is not available on the Windows backend yet (no effect-log collectors); run without it.");
        return 2;
    }
    if let Err(e) = tartaros_windows::WindowsBackend.validate(policy) {
        eprintln!("tartaros: {}", e.reason);
        return EXIT_POLICY_REFUSED;
    }
    match tartaros_windows::WindowsBackend.run(policy, cmd) {
        Ok(o) => o.exit_code,
        Err(e) => {
            eprintln!("tartaros: {}", e.reason);
            1
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn run(_policy: &Policy, _cmd: &[String], _log: Option<&LogSpec>) -> i32 {
    eprintln!("tartaros: unsupported OS");
    1
}
