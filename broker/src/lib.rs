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

pub struct Broker {
    injections: Vec<Injection>,
    role: String,
}

impl Broker {
    pub fn new(role: impl Into<String>, injections: Vec<Injection>) -> Self {
        Broker { injections, role: role.into() }
    }

    /// Bind to a loopback port (0 = any free port). Returns the broker's port.
    pub fn bind(&self, port: u16) -> std::io::Result<(TcpListener, u16)> {
        let l = TcpListener::bind(("127.0.0.1", port))?;
        let p = l.local_addr()?.port();
        Ok((l, p))
    }

    /// Serve forever, logging each forwarded request into `sink`.
    pub fn serve(&self, listener: TcpListener, sink: &mut dyn EffectSink) {
        for stream in listener.incoming().flatten() {
            if let Err(e) = self.handle(stream, sink) {
                // a logging/forward failure must not take the broker down
                let _ = e;
            }
        }
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

        let (host, port, path) = match parse_abs_uri(abs_uri) {
            Some(t) => t,
            None => {
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
                return Ok(());
            }
        };

        // Read headers (we drop any client-supplied auth and set our own).
        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h)? == 0 {
                break;
            }
            if h == "\r\n" || h == "\n" {
                break;
            }
            if let Some((k, v)) = h.trim_end().split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
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
    fn injection_host_scope() {
        let any = Injection { host: None, header: "A".into(), value: "x".into() };
        let one = Injection { host: Some("api.github.com".into()), header: "A".into(), value: "x".into() };
        assert!(any.applies_to("whatever"));
        assert!(one.applies_to("api.github.com"));
        assert!(!one.applies_to("evil.com"));
    }
}
