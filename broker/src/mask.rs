//! Masked credentials — the agent holds a sentinel, the broker swaps it for the
//! real value on egress to that credential's hosts.
//!
//! The scheme is sandbox-runtime's (`credentials.envVars` with `mode: "mask"`):
//! the sandboxed process sees `fake_value_<uuid4>` (padded to the real value's
//! length with `[a-z0-9_-]`, so a length-matched swap keeps `Content-Length`), and
//! the broker, which terminates TLS for those hosts (see `mitm.rs`), replaces it
//! in the request's headers and body. The map lives only in this process's
//! memory: never on disk, never in a log line.
//!
//! The swap is gated **per credential**: a sentinel becomes its real value only
//! when the destination is one of *its* hosts, so one credential's sentinel sent
//! to another credential's host travels as the useless fake. Every failure goes
//! the same way: a sentinel the scan misses (a compressed or base64 body) reaches
//! the upstream as the fake and authentication fails; the real value is never
//! sent anywhere it was not declared for.

use std::io::{self, Write};

pub const SENTINEL_PREFIX: &str = "fake_value_";
const SENTINEL_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_-";

/// One masked credential.
#[derive(Clone)]
pub struct MaskedCredential {
    pub name: String,
    /// Host patterns, as the egress allow-list spells them: an exact host, or a
    /// leading `.` for a domain and its subdomains.
    pub hosts: Vec<String>,
    real: String,
    sentinel: String,
}

// The real value is the secret: a derived Debug would print it.
impl std::fmt::Debug for MaskedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaskedCredential")
            .field("name", &self.name)
            .field("hosts", &self.hosts)
            .field("real", &"<redacted>")
            .field("sentinel", &self.sentinel)
            .finish()
    }
}

impl MaskedCredential {
    /// Mint a sentinel for `real` (see [`mint_sentinel`]).
    pub fn new(name: impl Into<String>, real: impl Into<String>, hosts: Vec<String>) -> io::Result<Self> {
        let real = real.into();
        let sentinel = mint_sentinel(&real)?;
        Ok(MaskedCredential { name: name.into(), hosts, real, sentinel })
    }
    /// What the agent's environment holds instead of the real value.
    pub fn sentinel(&self) -> &str {
        &self.sentinel
    }
    fn applies_to(&self, host: &str) -> bool {
        crate::egress::host_allowed_nonempty(&self.hosts, host)
    }
}

/// `fake_value_<uuid4>`, padded with random alphabet characters up to the real
/// value's byte length when that is longer. The uuid4 carries the entropy; the
/// padding only keeps the length, so a substitution leaves `Content-Length` as is.
pub fn mint_sentinel(real: &str) -> io::Result<String> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut u = [0u8; 16];
    rng.fill(&mut u).map_err(|_| io::Error::other("no randomness for a sentinel"))?;
    u[6] = (u[6] & 0x0f) | 0x40; // version 4
    u[8] = (u[8] & 0x3f) | 0x80; // RFC 4122 variant
    let h = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let mut s = format!(
        "{SENTINEL_PREFIX}{}-{}-{}-{}-{}",
        h(&u[0..4]),
        h(&u[4..6]),
        h(&u[6..8]),
        h(&u[8..10]),
        h(&u[10..16])
    );
    let pad = real.len().saturating_sub(s.len());
    if pad > 0 {
        let mut r = vec![0u8; pad];
        rng.fill(&mut r).map_err(|_| io::Error::other("no randomness for a sentinel"))?;
        s.extend(r.iter().map(|b| SENTINEL_ALPHABET[*b as usize % SENTINEL_ALPHABET.len()] as char));
    }
    Ok(s)
}

/// The masked credentials of one run.
#[derive(Clone, Debug, Default)]
pub struct Masks {
    creds: Vec<MaskedCredential>,
}

impl Masks {
    pub fn new(creds: Vec<MaskedCredential>) -> Self {
        Masks { creds }
    }
    pub fn is_empty(&self) -> bool {
        self.creds.is_empty()
    }
    /// The agent's view: each credential's variable, holding its sentinel.
    pub fn sentinel_env(&self) -> Vec<(String, String)> {
        self.creds.iter().map(|c| (c.name.clone(), c.sentinel.clone())).collect()
    }
    /// Does any credential inject into `host`? Those are the hosts whose TLS the
    /// broker terminates.
    pub fn injects_into(&self, host: &str) -> bool {
        self.creds.iter().any(|c| c.applies_to(host))
    }
    /// The swaps that apply on egress to `host`: (sentinel, real value, name).
    pub fn pairs_for(&self, host: &str) -> Pairs {
        Pairs(
            self.creds
                .iter()
                .filter(|c| c.applies_to(host))
                .map(|c| (c.sentinel.as_bytes().to_vec(), c.real.as_bytes().to_vec(), c.name.clone()))
                .collect(),
        )
    }
}

/// The swaps for one destination.
#[derive(Default)]
pub struct Pairs(Vec<(Vec<u8>, Vec<u8>, String)>);

impl Pairs {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// True when no swap can change a body's length.
    pub fn length_matched(&self) -> bool {
        self.0.iter().all(|(s, r, _)| s.len() == r.len())
    }
    fn longest(&self) -> usize {
        self.0.iter().map(|(s, _, _)| s.len()).max().unwrap_or(0)
    }
    /// Swap every sentinel in `text`; returns the text and the names of the
    /// credentials that were swapped.
    pub fn swap_str(&self, text: &str) -> (String, Vec<String>) {
        let mut out = text.to_string();
        let mut used = Vec::new();
        for (s, r, name) in &self.0 {
            let (s, r) = (String::from_utf8_lossy(s), String::from_utf8_lossy(r));
            if out.contains(s.as_ref()) {
                out = out.replace(s.as_ref(), r.as_ref());
                used.push(name.clone());
            }
        }
        (out, used)
    }
}

/// Streaming swap over a body: bytes go through to `inner` with every sentinel
/// replaced, holding back at most `longest sentinel - 1` bytes across writes so
/// a sentinel split between two chunks is still found. Memory is bounded by one
/// write plus that hold-back.
pub struct SwapWriter<'a, W: Write> {
    pairs: &'a Pairs,
    inner: W,
    hold: Vec<u8>,
    keep: usize,
    pub swapped: Vec<String>,
}

impl<'a, W: Write> SwapWriter<'a, W> {
    pub fn new(pairs: &'a Pairs, inner: W) -> Self {
        let keep = pairs.longest().saturating_sub(1);
        SwapWriter { pairs, inner, hold: Vec::new(), keep, swapped: Vec::new() }
    }

    /// Scan `self.hold`, write out everything that can no longer start a
    /// sentinel (all of it when `last`), keep the rest.
    fn drain(&mut self, last: bool) -> io::Result<()> {
        let buf = std::mem::take(&mut self.hold);
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        'scan: while i < buf.len() {
            for (s, r, name) in &self.pairs.0 {
                if buf[i..].starts_with(s) {
                    out.extend_from_slice(r);
                    if !self.swapped.contains(name) {
                        self.swapped.push(name.clone());
                    }
                    i += s.len();
                    continue 'scan;
                }
            }
            // Could a sentinel start here and run past the end of what we have?
            if !last && buf.len() - i <= self.keep && self.pairs.0.iter().any(|(s, _, _)| s.starts_with(&buf[i..])) {
                self.hold = buf[i..].to_vec();
                break;
            }
            out.push(buf[i]);
            i += 1;
        }
        self.inner.write_all(&out)
    }

    /// Flush the hold-back and hand the inner writer back.
    pub fn finish(mut self) -> io::Result<(W, Vec<String>)> {
        self.drain(true)?;
        Ok((self.inner, self.swapped))
    }
}

impl<W: Write> Write for SwapWriter<'_, W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.hold.extend_from_slice(data);
        self.drain(false)?;
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Writes what it is given as HTTP/1.1 chunks, and the last chunk on `finish`.
/// Used when a swap may change the body's length and its `Content-Length` can no
/// longer be forwarded as it was.
pub struct ChunkedWriter<W: Write>(pub W);

impl<W: Write> ChunkedWriter<W> {
    pub fn finish(mut self) -> io::Result<W> {
        self.0.write_all(b"0\r\n\r\n")?;
        Ok(self.0)
    }
}

impl<W: Write> Write for ChunkedWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if !data.is_empty() {
            write!(self.0, "{:x}\r\n", data.len())?;
            self.0.write_all(data)?;
            self.0.write_all(b"\r\n")?;
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(name: &str, real: &str, host: &str) -> MaskedCredential {
        MaskedCredential::new(name, real, vec![host.into()]).unwrap()
    }

    #[test]
    fn sentinel_shape_and_padding() {
        let short = mint_sentinel("abc").unwrap();
        assert!(short.starts_with(SENTINEL_PREFIX));
        assert_eq!(short.len(), SENTINEL_PREFIX.len() + 36);
        assert_eq!(&short[SENTINEL_PREFIX.len() + 14..SENTINEL_PREFIX.len() + 15], "4", "uuid version 4");
        let real = "ghp_".to_string() + &"x".repeat(80);
        let long = mint_sentinel(&real).unwrap();
        assert_eq!(long.len(), real.len(), "a longer real value is length-matched");
        assert!(long.bytes().all(|b| SENTINEL_ALPHABET.contains(&b) || b == b'-'));
        assert_ne!(mint_sentinel("abc").unwrap(), short, "fresh per mint");
    }

    #[test]
    fn debug_never_prints_the_real_value() {
        let c = cred("GH_TOKEN", "ghp_secret_value", "api.github.com");
        assert!(!format!("{c:?}").contains("ghp_secret_value"));
        assert!(!format!("{:?}", Masks::new(vec![c])).contains("ghp_secret_value"));
    }

    #[test]
    fn swaps_are_gated_per_credential() {
        let a = cred("A", "real-a", "a.example");
        let b = cred("B", "real-b", "b.example");
        let (sa, sb) = (a.sentinel().to_string(), b.sentinel().to_string());
        let m = Masks::new(vec![a, b]);
        let text = format!("Bearer {sa} and {sb}");
        let (to_a, used) = m.pairs_for("a.example").swap_str(&text);
        assert_eq!(to_a, format!("Bearer real-a and {sb}"), "B's sentinel to A's host stays fake");
        assert_eq!(used, vec!["A".to_string()]);
        let (elsewhere, used) = m.pairs_for("other.example").swap_str(&text);
        assert_eq!(elsewhere, text);
        assert!(used.is_empty());
        assert!(m.injects_into("a.example") && !m.injects_into("other.example"));
    }

    #[test]
    fn a_domain_pattern_covers_subdomains() {
        let m = Masks::new(vec![MaskedCredential::new("T", "r", vec![".example.com".into()]).unwrap()]);
        assert!(m.injects_into("api.example.com") && m.injects_into("example.com"));
        assert!(!m.injects_into("evilexample.com"));
    }

    #[test]
    fn body_swap_finds_a_sentinel_split_across_writes() {
        let c = cred("T", "the-real-token", "h");
        let s = c.sentinel().to_string();
        let m = Masks::new(vec![c]);
        let pairs = m.pairs_for("h");
        let body = format!("{{\"token\":\"{s}\",\"again\":\"{s}\"}}");
        for cut in 1..body.len() {
            let mut w = SwapWriter::new(&pairs, Vec::new());
            w.write_all(&body.as_bytes()[..cut]).unwrap();
            w.write_all(&body.as_bytes()[cut..]).unwrap();
            let (out, used) = w.finish().unwrap();
            assert_eq!(
                String::from_utf8(out).unwrap(),
                "{\"token\":\"the-real-token\",\"again\":\"the-real-token\"}",
                "cut at {cut}"
            );
            assert_eq!(used, vec!["T".to_string()]);
        }
    }

    #[test]
    fn body_swap_one_byte_at_a_time_and_a_false_start() {
        let c = cred("T", "R", "h");
        let s = c.sentinel().to_string();
        let m = Masks::new(vec![c]);
        let pairs = m.pairs_for("h");
        let body = format!("fake_value_ not one, {s}, fake_");
        let mut w = SwapWriter::new(&pairs, Vec::new());
        for b in body.bytes() {
            w.write_all(&[b]).unwrap();
        }
        let (out, _) = w.finish().unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "fake_value_ not one, R, fake_");
    }

    /// Random bodies salted with sentinels (whole, cut short, and both of two
    /// credentials'), written in random pieces: the streamed swap must equal a
    /// whole-buffer replace of this host's sentinels only, and never panic.
    #[test]
    fn fuzz_swap_writer_matches_a_whole_buffer_replace() {
        let mut state: u64 = 0x2545f4914f6cdd1d;
        let mut rng = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..400 {
            let a = cred("A", if round % 2 == 0 { "short" } else { "a-much-longer-real-value-than-the-sentinel-is-0123456789" }, "h");
            let b = cred("B", "other", "elsewhere");
            let (sa, sb) = (a.sentinel().to_string(), b.sentinel().to_string());
            let m = Masks::new(vec![a, b]);
            let pairs = m.pairs_for("h");
            let mut body = Vec::new();
            for _ in 0..(rng() % 12) {
                match rng() % 5 {
                    0 => body.extend_from_slice(sa.as_bytes()),
                    1 => body.extend_from_slice(sb.as_bytes()),
                    2 => body.extend_from_slice(&sa.as_bytes()[..(rng() as usize % sa.len())]),
                    3 => body.extend_from_slice(b"fake_value_"),
                    _ => body.extend((0..rng() % 40).map(|_| (rng() & 0xff) as u8)),
                }
            }
            let want = {
                let mut out = Vec::new();
                let mut i = 0;
                while i < body.len() {
                    if body[i..].starts_with(sa.as_bytes()) {
                        out.extend_from_slice(if round % 2 == 0 { b"short" } else { b"a-much-longer-real-value-than-the-sentinel-is-0123456789" });
                        i += sa.len();
                    } else {
                        out.push(body[i]);
                        i += 1;
                    }
                }
                out
            };
            let mut w = SwapWriter::new(&pairs, Vec::new());
            let mut i = 0;
            while i < body.len() {
                let n = 1 + (rng() as usize % 17).min(body.len() - i - 1);
                w.write_all(&body[i..i + n]).unwrap();
                i += n;
            }
            let (got, _) = w.finish().unwrap();
            assert_eq!(got, want, "round {round}");
            assert!(!got.windows(5).any(|x| x == b"other"), "B's real value never appears on A's host");
        }
    }

    #[test]
    fn chunked_writer_frames_and_ends() {
        let mut w = ChunkedWriter(Vec::new());
        w.write_all(b"hello").unwrap();
        w.write_all(b"").unwrap();
        w.write_all(b"0123456789abcdef!").unwrap();
        let out = w.finish().unwrap();
        assert_eq!(out, b"5\r\nhello\r\n11\r\n0123456789abcdef!\r\n0\r\n\r\n");
    }
}
