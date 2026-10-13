//! Effect collectors — observe what an agent attempts, from outside the agent,
//! and emit [`EffectEvent`]s. Collectors attach to a process tree by pid; they
//! do **not** depend on seisin-sandbox's enforcement, and nothing here depends
//! on the intent layer. The effect log (JSON Lines) is the neutral interface: a collector
//! writes it, the intent layer (or anything) reads it via its own adapter.
//!
//! Modular and extensible: each axis is a [`Collector`]. Add one by implementing
//! the trait; `core::catalog` is the shared classification so they agree on what
//! counts as "outside the territory".
//!
//! [`EffectEvent`]: seisin_sandbox_core::EffectEvent
//! [`Collector`]: seisin_sandbox_core::Collector

mod proc;

pub mod mcp;
pub mod net;
pub mod process;
pub mod secret;

pub use mcp::McpCollector;
pub use net::NetworkCollector;
pub use process::ProcessCollector;
pub use secret::SecretCollector;

use seisin_sandbox_core::{Collector, EffectSink};
use std::process::Child;
use std::time::Duration;

/// NOTE: this does NOT supervise (no timeout/limits). For an enforced run with
/// observation, use a backend `run_observed` (same supervisor as `run`).
/// Drive a set of collectors while a child runs: poll them on `interval` until
/// the child exits, then poll once more to catch late effects. Returns the
/// child's exit code (128 + signal when killed by a signal).
pub fn observe_until_exit(
    child: &mut Child,
    collectors: &mut [Box<dyn Collector>],
    sink: &mut dyn EffectSink,
    interval: Duration,
) -> i32 {
    loop {
        for c in collectors.iter_mut() {
            c.poll(sink);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                for c in collectors.iter_mut() {
                    c.poll(sink);
                }
                return exit_code_of(status);
            }
            Ok(None) => std::thread::sleep(interval),
            Err(_) => return -1,
        }
    }
}

#[cfg(unix)]
fn exit_code_of(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}
#[cfg(not(unix))]
fn exit_code_of(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
}
