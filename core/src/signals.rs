//! Signals the launcher passes on to the run instead of dying of them: a
//! terminal's Ctrl-C (SIGINT) and Ctrl-\ (SIGQUIT), a hangup, a parent's
//! SIGTERM. The run has a process group of its own (so teardown reaps it whole),
//! so one sent to the launcher's group never reached it: before 0.1.0-alpha.20
//! Ctrl-C killed the launcher, and the agent with it, even one that catches
//! SIGINT to interrupt rather than quit.
//!
//! `install` before the child is made: a caught signal is reset to its default
//! by exec, so the agent keeps its own dispositions, while a helper that forks
//! without exec (the PID-namespace init shim) keeps recording instead of dying
//! of a signal meant for the agent. The handler only counts; the supervisor
//! forwards (`take`) and, once the run is over, `restore`s the defaults, so a
//! signal during what follows (a snapshot diff) acts as it always did.
use std::sync::atomic::{AtomicU32, Ordering};

/// The signals passed on, in the order `take` reports them.
pub const FORWARDED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

static COUNTS: [AtomicU32; 4] = [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

extern "C" fn count(sig: libc::c_int) {
    if let Some(i) = FORWARDED.iter().position(|s| *s == sig) {
        COUNTS[i].fetch_add(1, Ordering::SeqCst);
    }
}

fn set(handler: libc::sighandler_t) {
    for s in FORWARDED {
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = handler;
            act.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut act.sa_mask);
            libc::sigaction(s, &act, std::ptr::null_mut());
        }
    }
}

/// Count the forwarded signals from now on instead of dying of them.
pub fn install() {
    for c in &COUNTS {
        c.store(0, Ordering::SeqCst);
    }
    set(count as *const () as libc::sighandler_t);
}

/// Each signal received since the last call, once per delivery.
pub fn take() -> Vec<libc::c_int> {
    let mut out = Vec::new();
    for (i, c) in COUNTS.iter().enumerate() {
        for _ in 0..c.swap(0, Ordering::SeqCst) {
            out.push(FORWARDED[i]);
        }
    }
    out
}

/// Back to the default dispositions, dropping what was counted for a run that
/// has ended.
pub fn restore() {
    set(libc::SIG_DFL);
    for c in &COUNTS {
        c.store(0, Ordering::SeqCst);
    }
}
