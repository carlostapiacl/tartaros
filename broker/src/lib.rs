//! Capability gateway — the one door out of the box.
//!
//! The agent is denied direct egress and allowed to reach only this broker's
//! loopback port. The broker is an HTTP forward proxy: for a request to an
//! upstream it is configured for, it **injects** a secret header and forwards.
//! The agent thus *uses* a credential it never *holds* — "the capability, not
//! the secret".
//!
//! Prototype scope: plain HTTP forward-proxy requests (`GET http://host/…`),
//! one request per connection, std-only. HTTPS (`CONNECT`) would need TLS
//! termination (a trusted CA) to inject into, or a capability-endpoint style;
//! out of scope here. Every forwarded request is logged as an `EffectEvent`.

use tartaros_core::{Axis, Direction, EffectEvent, EffectSink, Outcome};
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Inject `header: value` on requests to `host` (or to any host when `host` is
/// None). The value is the secret; it lives here, never in the agent.
#[derive(Debug, Clone)]
pub struct Injection {
    pub host: Option<String>,
    pub header: String,
    pub value: String,
}

impl Injection {
    fn applies_to(&self, host: &str) -> bool {
        match &self.host {
            Some(h) => h.eq_ignore_ascii_case(host),
            None => true,
        }
    }
}

/// A capability endpoint: the agent speaks plain HTTP to the broker at
/// `/<prefix>/…`, and the broker makes the real **HTTPS** request to
/// `upstream_base/…` with the secret injected. The agent never does TLS and
/// never holds the token. This is how a secret used over HTTPS (a GitHub token,
/// an OAuth bearer) is brokered without MITM.
#[derive(Debug, Clone)]
pub struct Capability {
    pub prefix: String,
    pub upstream_base: String,
    /// HTTP methods this capability permits (uppercase). Anything else is denied
    /// with 405 — unknown methods are NOT silently treated as GET (P0-B).
    pub methods: Vec<String>,
    pub injections: Vec<Injection>,
}

// Untrusted-input/relay limits and egress destination policy live in their own
// modules, kept apart from the credential and capability code below.
mod egress;
mod limits;
use limits::{read_line_capped, MAX_HEADERS, MAX_LINE_BYTES, MAX_RESPONSE_BYTES, UPSTREAM_TIMEOUT};

pub struct Broker {
    injections: Vec<Injection>,
    capabilities: Vec<Capability>,
    auth_token: Option<String>,
    insecure: bool,
    role: String,
    /// Grant deadline: after this instant every request is refused (403). Models
    /// a short-lived, session-scoped capability — a leaked token stops working.
    deadline: Option<Instant>,
    /// Max authorized requests over the broker's life (quota). Beyond it, 429.
    quota: Option<u32>,
    /// Authorized requests served so far (quota counter).
    used: AtomicU32,
    /// Forward-proxy egress allow-list. Empty = allow any host (back-compat).
    /// Non-empty = only these hosts; everything else is 403. An entry beginning
    /// with `.` (e.g. `.github.com`) matches that domain and its subdomains.
    allowed_hosts: Vec<String>,
    /// Permit forwarding to internal/private IPs (loopback, RFC1918, link-local
    /// incl. cloud metadata, ULA). Default false: an allowed hostname that
    /// resolves to an internal address is refused (SSRF / DNS-rebinding defense).
    allow_internal: bool,
}

impl Broker {
    pub fn new(role: impl Into<String>, injections: Vec<Injection>) -> Self {
        Broker {
            injections,
            capabilities: Vec::new(),
            auth_token: None,
            insecure: false,
            role: role.into(),
            deadline: None,
            quota: None,
            used: AtomicU32::new(0),
            allowed_hosts: Vec::new(),
            allow_internal: false,
        }
    }

    /// Allow forwarding to internal/private IP ranges (off by default). Only for
    /// brokering to an intentional internal service; leaving it off blocks SSRF
    /// to loopback, RFC1918, link-local (169.254.x, cloud metadata) and ULA.
    pub fn with_allow_internal(mut self, allow: bool) -> Self {
        self.allow_internal = allow;
        self
    }

    /// Restrict forward-proxy egress to these hosts (host-based mediation). An
    /// entry beginning with `.` matches that domain and its subdomains. Empty
    /// (the default) allows any host, preserving the prototype's behaviour.
    pub fn with_allowed_hosts(mut self, hosts: Vec<String>) -> Self {
        self.allowed_hosts = hosts;
        self
    }

    /// Is `host` permitted by the egress allow-list? Empty list = allow all.
    fn host_allowed(&self, host: &str) -> bool {
        egress::host_allowed(&self.allowed_hosts, host)
    }

    /// Expire the broker's grant after `ttl` from now: a short-lived capability.
    /// Once elapsed, every request is refused with 403 even with a valid token.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.deadline = Some(Instant::now() + ttl);
        self
    }

    /// Cap the number of authorized requests this broker will serve; further
    /// requests get 429. Bounds the blast radius of a capability.
    pub fn with_quota(mut self, max_requests: u32) -> Self {
        self.quota = Some(max_requests);
        self
    }

    /// Gate an authenticated request on expiry and quota. Returns an HTTP status
    /// line + reason to refuse with, or `None` to allow (consuming one quota
    /// unit). Checked AFTER auth so unauthorized callers never consume quota.
    fn gate(&self) -> Option<(&'static str, &'static str)> {
        if let Some(d) = self.deadline {
            if Instant::now() >= d {
                return Some(("403 Forbidden", "capability expired"));
            }
        }
        if let Some(max) = self.quota {
            // fetch_add returns the prior value; the (max+1)-th request is over.
            if self.used.fetch_add(1, Ordering::SeqCst) >= max {
                return Some(("429 Too Many Requests", "capability quota exceeded"));
            }
        }
        None
    }

    /// Require every request to carry `X-Tartaros-Auth: <token>`. Give the token
    /// only to the authorized agent; others reaching the port get 403.
    pub fn with_auth(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Explicitly allow running WITHOUT client auth (P0-A). Auth is mandatory by
    /// default: `serve` refuses to start otherwise. Use this only for tests/demos.
    pub fn insecure_no_auth(mut self) -> Self {
        self.insecure = true;
        self
    }

    /// Add capability endpoints (HTTPS upstreams reached by plain HTTP to the
    /// broker). See [`Capability`].
    pub fn with_capabilities(mut self, caps: Vec<Capability>) -> Self {
        self.capabilities = caps;
        self
    }

    /// Bind to a loopback port (0 = any free port). Returns the broker's port.
    pub fn bind(&self, port: u16) -> std::io::Result<(TcpListener, u16)> {
        let l = TcpListener::bind(("127.0.0.1", port))?;
        let p = l.local_addr()?.port();
        Ok((l, p))
    }

    /// Serve forever, logging each forwarded request into `sink`. Fails closed
    /// (P0-A): refuses to start without client auth unless `insecure_no_auth()`
    /// was set explicitly.
    pub fn serve(&self, listener: TcpListener, sink: &mut dyn EffectSink) -> Result<(), String> {
        if self.auth_token.is_none() && !self.insecure {
            return Err(
                "broker refuses to start without client auth; call with_auth(token) or, for tests, insecure_no_auth()".into(),
            );
        }
        for stream in listener.incoming().flatten() {
            if let Err(e) = self.handle(stream, sink) {
                // a logging/forward failure must not take the broker down
                let _ = e;
            }
        }
        Ok(())
    }

    fn handle(&self, client: TcpStream, sink: &mut dyn EffectSink) -> std::io::Result<()> {
        let mut reader = BufReader::new(client.try_clone()?);
        let mut client = client;

        // The request comes from the (confined) agent, so it is adversarial input
        // against the broker — which runs in the TRUSTED supervisor. Bound every
        // read so a giant line or a flood of headers cannot exhaust the broker's
        // memory (a DoS on the supervisor). Oversized => 400, no allocation blowup.
        let bad_request = |c: &mut TcpStream| -> std::io::Result<()> {
            let _ = c.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            Ok(())
        };

        // Request line: METHOD ABS_URI HTTP/1.1
        let line = match read_line_capped(&mut reader, MAX_LINE_BYTES)? {
            Some(l) => l,
            None => return bad_request(&mut client), // EOF or oversized
        };
        let parts: Vec<&str> = line.trim_end().split_whitespace().collect();
        if parts.len() < 3 {
            return bad_request(&mut client);
        }
        let (method, abs_uri, version) = (parts[0], parts[1], parts[2]);

        // Read all request headers once, with a count and per-line cap.
        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let h = match read_line_capped(&mut reader, MAX_LINE_BYTES)? {
                Some(h) => h,
                None => return bad_request(&mut client), // oversized header line
            };
            if h.is_empty() || h == "\r\n" || h == "\n" {
                break; // end of headers (or EOF)
            }
            if headers.len() >= MAX_HEADERS {
                return bad_request(&mut client);
            }
            if let Some((k, v)) = h.trim_end().split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }

        // Client authentication (P1-1): when a per-run token is set, require it,
        // so a stray local process that reaches the port cannot use the
        // credential. The token is stripped before forwarding upstream.
        if let Some(tok) = &self.auth_token {
            let ok = headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("x-tartaros-auth") && v == tok);
            if !ok {
                let _ = client
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                return Ok(());
            }
        }
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("x-tartaros-auth"));

        // Session gate (expiry + quota): a valid token is necessary but not
        // sufficient — a capability can still be past its TTL or over its quota.
        if let Some((status, reason)) = self.gate() {
            let body = reason.as_bytes();
            let _ = client.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = client.write_all(body);
            return Ok(());
        }

        // CONNECT tunnel (HTTPS egress): establish a blind TCP tunnel to an
        // allow-listed authority WITHOUT terminating TLS. This is what makes
        // domain-scoped egress work for real agents — git-over-https, fetch, pip,
        // npm — which all speak HTTPS through a proxy via CONNECT. The broker
        // never sees plaintext; it mediates only the destination (allow-list +
        // SSRF), which is exactly the egress boundary we want.
        if method.eq_ignore_ascii_case("CONNECT") {
            return self.handle_connect(abs_uri, reader, client, sink);
        }

        // Capability mode: origin-form request (/prefix/…) to an HTTPS upstream.
        if abs_uri.starts_with('/') {
            return self.handle_capability(method, abs_uri, &mut client, sink);
        }

        let (host, port, path) = match parse_abs_uri(abs_uri) {
            Some(t) => t,
            None => {
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
                return Ok(());
            }
        };

        // Egress allow-list (host-based mediation): a host off the list is
        // refused here, before any connection or secret injection.
        if !self.host_allowed(&host) {
            sink.emit(&EffectEvent::now(
                self.role.clone(),
                Axis::Network,
                "broker-egress-denied",
                format!("{host}:{port}{path}"),
                Direction::OutsideTerritory,
                Outcome::Denied,
                "broker",
            ));
            let body = b"host not allowed";
            let _ = client.write_all(
                format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = client.write_all(body);
            return Ok(());
        }

        // Inject the secret(s) for this host — the agent never saw them.
        let mut injected = false;
        for inj in &self.injections {
            if inj.applies_to(&host) {
                headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&inj.header));
                headers.push((inj.header.clone(), inj.value.clone()));
                injected = true;
            }
        }

        sink.emit(&EffectEvent::now(
            self.role.clone(),
            Axis::Secret,
            if injected { "broker-inject" } else { "broker-forward" },
            format!("{host}:{port}{path}"),
            Direction::OutsideTerritory,
            Outcome::Allowed,
            "broker",
        ));

        // Resolve the host ourselves and refuse internal destinations (SSRF /
        // DNS-rebinding defense): an allowed hostname that resolves to loopback,
        // RFC1918, link-local (169.254.x — cloud metadata) or ULA is blocked.
        // Connect to the resolved address, not the name, so there is no
        // resolve-then-reresolve rebinding window.
        use std::net::ToSocketAddrs;
        let addrs: Vec<std::net::SocketAddr> =
            (host.as_str(), port).to_socket_addrs().map(|i| i.collect()).unwrap_or_default();
        let target = addrs
            .iter()
            .find(|a| self.allow_internal || !egress::is_internal_ip(&a.ip()))
            .copied();
        let target = match target {
            Some(a) => a,
            None => {
                sink.emit(&EffectEvent::now(
                    self.role.clone(),
                    Axis::Network,
                    "broker-internal-destination-denied",
                    format!("{host}:{port}"),
                    Direction::OutsideTerritory,
                    Outcome::Denied,
                    "broker",
                ));
                let body = b"internal destination blocked";
                let _ = client.write_all(
                    format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                );
                let _ = client.write_all(body);
                return Ok(());
            }
        };

        // Forward to the real upstream (the verified, non-internal address).
        // Bound the connect and every read/write with a timeout so a slow or
        // unresponsive upstream cannot pin a broker thread (the broker runs in
        // the trusted supervisor). connect_timeout needs a SocketAddr, which we
        // already have (resolved + SSRF-checked above).
        let mut upstream = TcpStream::connect_timeout(&target, UPSTREAM_TIMEOUT)?;
        upstream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
        upstream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;
        let mut req = format!("{method} {path} {version}\r\n");
        // ensure Host header
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            req.push_str(&format!("Host: {host}\r\n"));
        }
        for (k, v) in &headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("Connection: close\r\n\r\n");
        upstream.write_all(req.as_bytes())?;

        // Stream the response back to the client, bounded to MAX_RESPONSE_BYTES
        // (P0): the HTTP forward-proxy must cap the body like the capability
        // endpoint does, or an authorized-but-huge upstream response could grow
        // the supervisor's memory without bound. io::copy streams, so we never
        // buffer the whole body, and `take` enforces the ceiling.
        let mut limited = upstream.take(MAX_RESPONSE_BYTES);
        let copied = std::io::copy(&mut limited, &mut client)?;
        if copied == MAX_RESPONSE_BYTES {
            // hit the ceiling: the response may be truncated; close the client so
            // it does not treat a cut body as complete. (Connection: close above.)
            let _ = client.flush();
        }
        client.flush()?;
        Ok(())
    }

    /// Resolve `host:port` and return the first address that passes the SSRF
    /// policy (non-internal, unless `allow_internal`). None = no acceptable
    /// address (unresolvable, or every address is internal and internal is off).
    /// Connecting to the resolved address (not the name) closes the
    /// resolve-then-reresolve rebinding window.
    fn resolve_external(&self, host: &str, port: u16) -> Option<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<std::net::SocketAddr> =
            (host, port).to_socket_addrs().map(|i| i.collect()).unwrap_or_default();
        addrs
            .into_iter()
            .find(|a| self.allow_internal || !egress::is_internal_ip(&a.ip()))
    }

    /// Handle a CONNECT tunnel: `CONNECT host:port`. Mediate the destination
    /// (allow-list + SSRF), then, if permitted, reply 200 and copy bytes blindly
    /// in both directions until either side closes. TLS is tunneled end-to-end;
    /// the broker never terminates it, so no CA and no plaintext — only the
    /// destination is policed. The broker is per-run and dies with it, so an idle
    /// tunnel is bounded by the run's lifetime (no per-read timeout, which would
    /// otherwise break a legitimately long or quiet transfer).
    fn handle_connect(
        &self,
        authority: &str,
        client_reader: BufReader<TcpStream>,
        mut client: TcpStream,
        sink: &mut dyn EffectSink,
    ) -> std::io::Result<()> {
        let refuse = |c: &mut TcpStream, status: &str, body: &[u8]| -> std::io::Result<()> {
            let _ = c.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = c.write_all(body);
            Ok(())
        };

        // Parse host:port (rsplit so IPv6 literals like [::1]:443 keep their colons).
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let h = h.trim_start_matches('[').trim_end_matches(']');
                match p.parse::<u16>() {
                    Ok(p) => (h.to_string(), p),
                    Err(_) => return refuse(&mut client, "400 Bad Request", b"bad authority"),
                }
            }
            None => return refuse(&mut client, "400 Bad Request", b"bad authority"),
        };

        // Egress allow-list — refuse before any DNS or connection.
        if !self.host_allowed(&host) {
            sink.emit(&EffectEvent::now(
                self.role.clone(),
                Axis::Network,
                "broker-connect-denied",
                format!("{host}:{port}"),
                Direction::OutsideTerritory,
                Outcome::Denied,
                "broker",
            ));
            return refuse(&mut client, "403 Forbidden", b"host not allowed");
        }

        // SSRF / DNS-rebinding defense: refuse internal destinations.
        let target = match self.resolve_external(&host, port) {
            Some(a) => a,
            None => {
                sink.emit(&EffectEvent::now(
                    self.role.clone(),
                    Axis::Network,
                    "broker-connect-internal-denied",
                    format!("{host}:{port}"),
                    Direction::OutsideTerritory,
                    Outcome::Denied,
                    "broker",
                ));
                return refuse(&mut client, "403 Forbidden", b"internal destination blocked");
            }
        };

        // Connect upstream (bounded connect; no per-read timeout on the tunnel).
        let upstream = match TcpStream::connect_timeout(&target, UPSTREAM_TIMEOUT) {
            Ok(s) => s,
            Err(_) => return refuse(&mut client, "502 Bad Gateway", b"upstream connect failed"),
        };

        sink.emit(&EffectEvent::now(
            self.role.clone(),
            Axis::Network,
            "broker-connect",
            format!("{host}:{port}"),
            Direction::OutsideTerritory,
            Outcome::Allowed,
            "broker",
        ));
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        client.flush()?;

        // Blind bidirectional copy. One direction runs on a thread; the other on
        // this one. Each closes its write half on EOF so the peer sees the close.
        // client_reader carries any bytes BufReader already read past the headers
        // (a pipelined client), so we copy FROM it, not from a fresh clone.
        let upstream_w = upstream.try_clone()?;
        let mut upstream_r = upstream;
        let mut client_w = client.try_clone()?;
        let t = std::thread::spawn(move || {
            let mut cr = client_reader;
            let mut uw = upstream_w;
            let _ = std::io::copy(&mut cr, &mut uw);
            let _ = uw.shutdown(std::net::Shutdown::Write);
        });
        let _ = std::io::copy(&mut upstream_r, &mut client_w);
        let _ = client_w.shutdown(std::net::Shutdown::Write);
        let _ = t.join();
        Ok(())
    }
}

impl Broker {
    /// Serve a capability: plain-HTTP `/<prefix>/rest` from the agent becomes an
    /// HTTPS request to `upstream_base/rest` with the secret injected. The agent
    /// never does TLS and never sees the token.
    fn handle_capability(
        &self,
        method: &str,
        path: &str,
        client: &mut TcpStream,
        sink: &mut dyn EffectSink,
    ) -> std::io::Result<()> {
        let cap = self.capabilities.iter().find(|c| {
            path == c.prefix || path.starts_with(&format!("{}/", c.prefix))
        });
        let cap = match cap {
            Some(c) => c,
            None => {
                let _ = client.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                return Ok(());
            }
        };
        // P0-B: deny a method this capability did not declare. Unknown methods
        // are NOT silently treated as GET.
        if !cap.methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
            let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return Ok(());
        }
        // P0-B: keep the path within the capability's upstream — no traversal out.
        let rest = &path[cap.prefix.len()..];
        let rest = if rest.is_empty() { "/" } else { rest };
        if rest.contains("..") {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return Ok(());
        }
        let url = format!("{}{}", cap.upstream_base.trim_end_matches('/'), rest);

        sink.emit(&EffectEvent::now(
            self.role.clone(),
            Axis::Secret,
            "broker-inject",
            format!("{method} {url}"),
            Direction::OutsideTerritory,
            Outcome::Allowed,
            "broker/capability",
        ));

        // The broker does the TLS. No redirects (P0-B: a 3xx must not send the
        // credential to a different destination). Inject the secret header(s).
        let agent = ureq::AgentBuilder::new().redirects(0).build();
        let mut req = agent.request(&method.to_uppercase(), &url);
        for inj in &cap.injections {
            req = req.set(&inj.header, &inj.value);
        }
        let (status, body) = match req.call() {
            Ok(resp) => (resp.status(), read_capped(resp)),
            Err(ureq::Error::Status(code, resp)) => (code, read_capped(resp)),
            Err(e) => (502, format!("broker upstream error: {e}")),
        };
        let resp = format!(
            "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        client.write_all(resp.as_bytes())?;
        client.flush()?;
        Ok(())
    }
}

/// Read an upstream response body, bounded to `MAX_RESPONSE_BYTES` (P0-B).
fn read_capped(resp: ureq::Response) -> String {
    use std::io::Read;
    let mut buf = Vec::new();
    let _ = resp.into_reader().take(MAX_RESPONSE_BYTES).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// "http://host:port/path" -> (host, port, "/path"). Defaults port 80.
fn parse_abs_uri(uri: &str) -> Option<(String, u16, String)> {
    let rest = uri.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), 80u16),
    };
    Some((host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_absolute_uri() {
        assert_eq!(
            parse_abs_uri("http://127.0.0.1:9000/x"),
            Some(("127.0.0.1".into(), 9000, "/x".into()))
        );
        assert_eq!(parse_abs_uri("http://example.com/"), Some(("example.com".into(), 80, "/".into())));
        assert_eq!(parse_abs_uri("https://x/"), None);
    }

    #[test]
    fn serve_refuses_without_auth() {
        use std::net::TcpListener;
        let b = Broker::new("qa", vec![]);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut sink = tartaros_core::VecSink::default();
        // no auth, not insecure -> must refuse immediately
        assert!(b.serve(l, &mut sink).is_err());
    }

    #[test]
    fn serve_allowed_with_explicit_insecure() {
        // the guard passes when insecure is explicit (we don't actually loop:
        // just check the guard logic by constructing and inspecting)
        let b = Broker::new("qa", vec![]).insecure_no_auth();
        assert!(b.insecure);
        let b2 = Broker::new("qa", vec![]).with_auth("t");
        assert!(b2.auth_token.is_some());
    }

    #[test]
    fn quota_gate_refuses_after_limit() {
        let b = Broker::new("qa", vec![]).with_quota(2);
        assert!(b.gate().is_none(), "1st allowed");
        assert!(b.gate().is_none(), "2nd allowed");
        let r = b.gate().expect("3rd refused");
        assert!(r.0.starts_with("429"), "quota exceeded => 429");
    }

    #[test]
    fn ttl_gate_refuses_after_expiry() {
        let mut b = Broker::new("qa", vec![]).with_ttl(Duration::from_secs(3600));
        assert!(b.gate().is_none(), "within TTL");
        // force the deadline into the past
        b.deadline = Some(Instant::now() - Duration::from_secs(1));
        let r = b.gate().expect("expired");
        assert!(r.0.starts_with("403") && r.1.contains("expired"));
    }

    #[test]
    fn blocks_internal_destinations() {
        let internal = [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "0.0.0.0", "100.100.0.1", // CGNAT
            "::1", "fe80::1", "fc00::1",
        ];
        for s in internal {
            let ip: std::net::IpAddr = s.parse().unwrap();
            assert!(egress::is_internal_ip(&ip), "{s} must be internal");
        }
        let public = ["1.1.1.1", "8.8.8.8", "140.82.112.3", "2606:4700:4700::1111"];
        for s in public {
            let ip: std::net::IpAddr = s.parse().unwrap();
            assert!(!egress::is_internal_ip(&ip), "{s} must be public");
        }
    }

    #[test]
    fn live_blocks_ssrf_to_loopback() {
        let b = Broker::new("qa", vec![]).insecure_no_auth();
        let (l, port) = b.bind(0).unwrap();
        std::thread::spawn(move || {
            let mut s = tartaros_core::VecSink::default();
            let _ = b.serve(l, &mut s);
        });
        std::thread::sleep(Duration::from_millis(150));
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        // forward-proxy request whose target resolves to loopback -> SSRF blocked
        c.write_all(b"GET http://127.0.0.1:9/x HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut resp = String::new();
        let _ = c.read_to_string(&mut resp);
        assert!(resp.contains("403"), "SSRF to loopback must be 403, got: {resp:?}");
        assert!(resp.contains("internal destination"), "got: {resp:?}");
    }

    #[test]
    fn live_caps_forward_proxy_response() {
        // Upstream that offers an UNBOUNDED body: it keeps writing until the
        // broker closes the connection (which it does on hitting the cap). A
        // single fixed write_all is timing-fragile on loopback — the broker may
        // read fewer than the cap before the close propagates (seen on Docker
        // Linux: ~7.8 MiB) — so instead we stream forever and let the broker's
        // cap be the thing that stops it. That makes "relayed exactly the cap"
        // deterministic on every OS, while still proving truncation.
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let up_port = up.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in up.incoming().flatten() {
                let mut s = s;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
                let chunk = vec![b'A'; 64 * 1024];
                // Keep feeding until the broker hits its cap and closes -> our
                // write_all returns an error (EPIPE/ECONNRESET) and we stop.
                while s.write_all(&chunk).is_ok() {}
            }
        });
        // allow_internal so the broker will connect to the loopback test upstream.
        let b = Broker::new("qa", vec![]).insecure_no_auth().with_allow_internal(true);
        let (l, port) = b.bind(0).unwrap();
        std::thread::spawn(move || {
            let mut s = tartaros_core::VecSink::default();
            let _ = b.serve(l, &mut s);
        });
        std::thread::sleep(Duration::from_millis(150));
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(format!("GET http://127.0.0.1:{up_port}/ HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .unwrap();
        let mut got = Vec::new();
        let _ = c.read_to_end(&mut got);
        // The forward proxy must cap what it relays: never more than the ceiling.
        assert!(
            (got.len() as u64) <= MAX_RESPONSE_BYTES,
            "forward-proxy relayed {} bytes, over the {} cap",
            got.len(),
            MAX_RESPONSE_BYTES
        );
        // And it should have reached the cap (upstream sent more), proving it
        // actually truncated rather than the upstream being small.
        assert_eq!(got.len() as u64, MAX_RESPONSE_BYTES, "should relay exactly up to the cap");
    }

    #[test]
    fn live_rejects_oversized_request_line() {
        let b = Broker::new("qa", vec![]).insecure_no_auth();
        let (l, port) = b.bind(0).unwrap();
        std::thread::spawn(move || {
            let mut s = tartaros_core::VecSink::default();
            let _ = b.serve(l, &mut s);
        });
        std::thread::sleep(Duration::from_millis(150));
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        // a request line far larger than MAX_LINE_BYTES, no newline yet
        let giant = format!("GET http://x/{} HTTP/1.1", "a".repeat(MAX_LINE_BYTES * 2));
        c.write_all(giant.as_bytes()).unwrap();
        c.write_all(b"\r\n\r\n").unwrap();
        let mut resp = String::new();
        let _ = c.read_to_string(&mut resp);
        // bounded read -> 400, not an OOM / hang
        assert!(resp.contains("400"), "oversized line must be 400, got: {resp:?}");
    }

    #[test]
    fn egress_allowlist() {
        // empty = allow any (back-compat)
        let open = Broker::new("qa", vec![]);
        assert!(open.host_allowed("anything.com"));
        // exact host
        let b = Broker::new("qa", vec![]).with_allowed_hosts(vec!["api.github.com".into()]);
        assert!(b.host_allowed("api.github.com"));
        assert!(b.host_allowed("API.GitHub.com"), "case-insensitive");
        assert!(!b.host_allowed("evil.com"));
        assert!(!b.host_allowed("notapi.github.com"), "no accidental suffix match");
        // domain wildcard (.github.com matches the domain and subdomains)
        let w = Broker::new("qa", vec![]).with_allowed_hosts(vec![".github.com".into()]);
        assert!(w.host_allowed("github.com"));
        assert!(w.host_allowed("api.github.com"));
        assert!(w.host_allowed("uploads.api.github.com"));
        assert!(!w.host_allowed("github.com.evil.com"));
        assert!(!w.host_allowed("evilgithub.com"));
    }

    #[test]
    fn live_connect_tunnels_to_allowed_host() {
        // A raw TCP "upstream" that echoes one line — stands in for a TLS server;
        // CONNECT tunnels bytes blindly, so the payload need not be TLS.
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let up_port = up.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in up.incoming().flatten() {
                let mut s = s;
                let mut buf = [0u8; 16];
                if let Ok(n) = s.read(&mut buf) {
                    let _ = s.write_all(&buf[..n]); // echo
                }
            }
        });
        // allow_internal so the broker will tunnel to the loopback test upstream,
        // and allow-list the loopback host it lives on.
        let b = Broker::new("qa", vec![])
            .insecure_no_auth()
            .with_allow_internal(true)
            .with_allowed_hosts(vec!["127.0.0.1".into()]);
        let (l, port) = b.bind(0).unwrap();
        std::thread::spawn(move || {
            let mut s = tartaros_core::VecSink::default();
            let _ = b.serve(l, &mut s);
        });
        std::thread::sleep(Duration::from_millis(150));
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
            .unwrap();
        // Read the 200 status line.
        let mut status = [0u8; 12];
        c.read_exact(&mut status).unwrap();
        assert_eq!(&status, b"HTTP/1.1 200", "CONNECT to allowed host must be established");
        // Drain the rest of the status line / blank line, then tunnel a payload.
        let mut hdr = [0u8; 64];
        let _ = c.read(&mut hdr);
        c.write_all(b"ping").unwrap();
        let mut echo = [0u8; 4];
        c.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ping", "tunnel must carry bytes end-to-end");
    }

    #[test]
    fn live_connect_refuses_disallowed_host() {
        let b = Broker::new("qa", vec![])
            .insecure_no_auth()
            .with_allowed_hosts(vec!["github.com".into()]);
        let (l, port) = b.bind(0).unwrap();
        std::thread::spawn(move || {
            let mut s = tartaros_core::VecSink::default();
            let _ = b.serve(l, &mut s);
        });
        std::thread::sleep(Duration::from_millis(150));
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        c.write_all(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n").unwrap();
        let mut resp = String::new();
        let _ = c.read_to_string(&mut resp);
        assert!(resp.contains("403"), "CONNECT to a host off the allow-list must be 403, got: {resp:?}");
    }

    #[test]
    fn injection_host_scope() {
        let any = Injection { host: None, header: "A".into(), value: "x".into() };
        let one = Injection { host: Some("api.github.com".into()), header: "A".into(), value: "x".into() };
        assert!(any.applies_to("whatever"));
        assert!(one.applies_to("api.github.com"));
        assert!(!one.applies_to("evil.com"));
    }
}
