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

use seisin_sandbox_core::{Axis, Direction, EffectEvent, EffectSink, Outcome};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

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

/// Largest upstream response the broker relays back (P0-B: bound the response).
const MAX_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

pub struct Broker {
    injections: Vec<Injection>,
    capabilities: Vec<Capability>,
    auth_token: Option<String>,
    insecure: bool,
    role: String,
}

impl Broker {
    pub fn new(role: impl Into<String>, injections: Vec<Injection>) -> Self {
        Broker {
            injections,
            capabilities: Vec::new(),
            auth_token: None,
            insecure: false,
            role: role.into(),
        }
    }

    /// Require every request to carry `X-Seisin-Auth: <token>`. Give the token
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

        // Request line: METHOD ABS_URI HTTP/1.1
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let parts: Vec<&str> = line.trim_end().split_whitespace().collect();
        if parts.len() < 3 {
            return Ok(());
        }
        let (method, abs_uri, version) = (parts[0], parts[1], parts[2]);

        // Read all request headers once.
        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
                break;
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
                .any(|(k, v)| k.eq_ignore_ascii_case("x-seisin-auth") && v == tok);
            if !ok {
                let _ = client
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                return Ok(());
            }
        }
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("x-seisin-auth"));

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

        // Forward to the real upstream.
        let mut upstream = TcpStream::connect((host.as_str(), port))?;
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

        // Stream the response back to the client.
        let mut buf = Vec::new();
        upstream.read_to_end(&mut buf)?;
        client.write_all(&buf)?;
        client.flush()?;
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
        let mut sink = seisin_sandbox_core::VecSink::default();
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
    fn injection_host_scope() {
        let any = Injection { host: None, header: "A".into(), value: "x".into() };
        let one = Injection { host: Some("api.github.com".into()), header: "A".into(), value: "x".into() };
        assert!(any.applies_to("whatever"));
        assert!(one.applies_to("api.github.com"));
        assert!(!one.applies_to("evil.com"));
    }
}
