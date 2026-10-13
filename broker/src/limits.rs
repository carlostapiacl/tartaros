//! Limits on untrusted input and relayed data, isolated from the credential and
//! capability logic. The broker parses requests from the (confined) agent, so
//! these are the bounds that keep adversarial input from exhausting the
//! supervisor the broker runs in.

use std::io::{BufRead, Read};

/// Largest upstream response the broker relays back (both proxy modes).
pub(crate) const MAX_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

/// Timeout for the upstream connect and each read/write in the HTTP forward
/// proxy, so a slow or unresponsive upstream cannot pin a broker thread.
pub(crate) const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Caps on the agent-supplied request head.
pub(crate) const MAX_LINE_BYTES: usize = 8 * 1024;
pub(crate) const MAX_HEADERS: usize = 100;

/// Read one line but never more than `max` bytes. Returns `None` on EOF or when
/// the line exceeds `max` without a terminating newline (an oversized request),
/// so the caller can reject it instead of buffering without bound.
pub(crate) fn read_line_capped(r: &mut impl BufRead, max: usize) -> std::io::Result<Option<String>> {
    let mut s = String::new();
    let n = r.by_ref().take(max as u64).read_line(&mut s)?;
    if n == 0 {
        return Ok(None); // EOF
    }
    if n >= max && !s.ends_with('\n') {
        return Ok(None); // hit the cap with no newline: oversized line
    }
    Ok(Some(s))
}
