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

/// Availability bounds for the trusted broker (ADV-01). The agent is adversarial
/// input, so one client must never be able to block others or pin the broker.
///
/// Per-client read/write timeout on the request head and the forward-proxy
/// response: a slowloris client (dribbling headers, or reading the response one
/// byte at a time) times out instead of holding a worker open.
pub(crate) const CLIENT_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Idle read timeout on an established CONNECT tunnel: a tunnel with NO bytes in
/// either direction for this long is torn down. Generous so a legitimately quiet
/// but live transfer is not killed, while a client that opens a tunnel and sits
/// on it cannot hold it (and its worker slot) indefinitely.
pub(crate) const CONNECT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Max connections handled concurrently. Each runs on its own worker thread;
/// beyond this the broker sheds load with 503 rather than queueing unboundedly or
/// letting slow clients starve others. Bounds worker threads and memory.
pub(crate) const MAX_CONCURRENT_SESSIONS: u32 = 64;

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
