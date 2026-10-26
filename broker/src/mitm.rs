//! TLS termination for masked credentials — only toward a credential's hosts.
//!
//! A CONNECT to a host a masked credential injects into is not tunneled blind:
//! the broker answers the client's TLS with a leaf for that host signed by a CA
//! made for this run, reads ONE HTTP/1.1 request, swaps the credential's
//! sentinel for its real value in the headers and the body (`mask.rs`), and
//! sends it upstream over real, verified TLS. The response comes back as it was.
//! Every other host keeps the blind tunnel.
//!
//! The CA's private key exists only in this process's memory. Its certificate,
//! and a trust bundle of it plus the system's roots, are written to a run
//! directory so the agent's HTTPS clients can trust the leaves
//! ([`CA_TRUST_VARS`]).
//!
//! One request per terminated connection: the upstream request carries
//! `Connection: close`, the response is relayed until the upstream closes, and
//! the client's TLS is closed after it. No keep-alive state to get wrong across
//! requests; clients reconnect.

use crate::limits::{read_line_capped, CONNECT_IDLE_TIMEOUT, MAX_HEADERS, MAX_LINE_BYTES, UPSTREAM_TIMEOUT};
use crate::mask::{ChunkedWriter, SwapWriter};
use crate::{body_framing, is_hop_by_hop, BodyFraming, Broker};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tartaros_core::{Axis, Direction, EffectEvent, Outcome};

/// The per-tool trust-store variables pointed at the trust bundle, so HTTPS
/// clients inside accept the leaves. sandbox-runtime's list.
pub const CA_TRUST_VARS: &[&str] = &[
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "PIP_CERT",
    "GIT_SSL_CAINFO",
    "AWS_CA_BUNDLE",
    "CARGO_HTTP_CAINFO",
    "DENO_CERT",
    "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE",
    "NIX_SSL_CERT_FILE",
];

/// Where a system's PEM bundle of trusted roots usually is.
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/cert.pem",                  // macOS, Alpine, BSDs
    "/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
    "/etc/ssl/ca-bundle.pem",             // openSUSE
];

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The CA of one run, and the leaves it has signed.
pub struct MitmCa {
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl std::fmt::Debug for MitmCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MitmCa").field("key", &"<in memory only>").finish()
    }
}

/// Validity window: from a day ago (clock skew) to `days` ahead.
fn validity(params: &mut rcgen::CertificateParams, days: u64) {
    let now = std::time::SystemTime::now();
    let day = std::time::Duration::from_secs(86_400);
    params.not_before = (now - day).into();
    params.not_after = (now + day * days as u32).into();
}

impl MitmCa {
    pub fn new() -> io::Result<Self> {
        let e = |x: rcgen::Error| io::Error::other(format!("cannot make the run's CA: {x}"));
        let key = rcgen::KeyPair::generate().map_err(e)?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(e)?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(rcgen::DnType::CommonName, "tartaros run CA (masked credentials)");
        validity(&mut params, 30);
        let cert = params.self_signed(&key).map_err(e)?;
        Ok(MitmCa {
            cert_pem: cert.pem(),
            cert_der: cert.der().clone(),
            issuer: rcgen::Issuer::new(params, key),
            leaves: Mutex::new(HashMap::new()),
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// The server config that answers as `host`: a leaf for it, made once.
    pub fn server_config(&self, host: &str) -> io::Result<Arc<ServerConfig>> {
        let key_name = host.to_ascii_lowercase();
        if let Some(c) = self.leaves.lock().unwrap().get(&key_name) {
            return Ok(c.clone());
        }
        let e = |x: rcgen::Error| io::Error::other(format!("cannot make a leaf for {host}: {x}"));
        let key = rcgen::KeyPair::generate().map_err(e)?;
        let mut params = rcgen::CertificateParams::new(vec![key_name.clone()]).map_err(e)?;
        params.distinguished_name.push(rcgen::DnType::CommonName, key_name.clone());
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.use_authority_key_identifier_extension = true;
        validity(&mut params, 7);
        let cert = params.signed_by(&key, &self.issuer).map_err(e)?;
        let chain = vec![cert.der().clone(), self.cert_der.clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut cfg = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(io::Error::other)?;
        // HTTP/1.1 only: an HTTP/2 client falls back, and the broker parses one
        // request in one framing.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.leaves.lock().unwrap().insert(key_name, cfg.clone());
        Ok(cfg)
    }

    /// Write `ca.pem` and `bundle.pem` (the CA, the system's roots, and the
    /// launcher's `NODE_EXTRA_CA_CERTS` when set) into `dir`, readable by the
    /// agent. Returns the bundle's path, which the trust variables point at.
    pub fn write_trust_files(&self, dir: &Path) -> io::Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("ca.pem"), &self.cert_pem)?;
        let mut bundle = self.cert_pem.trim_end().to_string();
        bundle.push('\n');
        if let Some(sys) = SYSTEM_BUNDLES.iter().find_map(|p| std::fs::read_to_string(p).ok()) {
            bundle.push_str(sys.trim_end());
            bundle.push('\n');
        }
        if let Some(extra) = std::env::var_os("NODE_EXTRA_CA_CERTS").and_then(|p| std::fs::read_to_string(p).ok()) {
            bundle.push_str(extra.trim_end());
            bundle.push('\n');
        }
        let path = dir.join("bundle.pem");
        std::fs::write(&path, bundle)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in ["ca.pem", "bundle.pem"] {
                std::fs::set_permissions(dir.join(f), std::fs::Permissions::from_mode(0o644))?;
            }
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
        }
        Ok(path)
    }
}

/// The upstream side's TLS: the webpki roots, plus `extra` (a test's own CA).
pub fn upstream_tls(extra: &[CertificateDer<'static>]) -> io::Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    for c in extra {
        roots.add(c.clone()).map_err(io::Error::other)?;
    }
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// The client connection as one stream: reads from the reader that may already
/// hold bytes past the CONNECT line (the ClientHello), writes to the socket.
struct Duplex {
    r: BufReader<TcpStream>,
    w: TcpStream,
}
impl Read for Duplex {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.r.read(b)
    }
}
impl Write for Duplex {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.w.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

/// Does `authority` (`host` or `host:port`, IPv6 bracketed) name `host:port`,
/// with no port meaning 443? The same test sandbox-runtime makes of the Host
/// header and an absolute request-target.
fn names_target(authority: &str, host: &str, port: u16) -> bool {
    let (h, p) = if let Some(rest) = authority.strip_prefix('[') {
        match rest.split_once(']') {
            Some(x) => x,
            None => return false,
        }
    } else {
        match authority.rfind(':') {
            Some(i) => (&authority[..i], &authority[i..]),
            None => (authority, ""),
        }
    };
    if !h.eq_ignore_ascii_case(host.trim_start_matches('[').trim_end_matches(']')) {
        return false;
    }
    if p.is_empty() {
        return port == 443;
    }
    p.strip_prefix(':').and_then(|n| n.parse::<u16>().ok()) == Some(port)
}

/// Read a body as framed and write its bytes (chunked: the chunk data only,
/// trailers dropped) to `to`. Streamed; a body that ends early is an error.
fn copy_decoded(framing: &BodyFraming, from: &mut impl BufRead, to: &mut impl Write) -> io::Result<()> {
    let short = || io::Error::new(io::ErrorKind::UnexpectedEof, "request body ended early");
    match framing {
        BodyFraming::None => Ok(()),
        BodyFraming::Length(n) => {
            if io::copy(&mut from.take(*n), to)? < *n {
                return Err(short());
            }
            Ok(())
        }
        BodyFraming::Chunked => loop {
            let line = read_line_capped(from, MAX_LINE_BYTES)?.ok_or_else(short)?;
            let size = line.trim_end().split(';').next().unwrap_or("").trim();
            let size = u64::from_str_radix(size, 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                loop {
                    let t = read_line_capped(from, MAX_LINE_BYTES)?.ok_or_else(short)?;
                    if t == "\r\n" || t == "\n" {
                        return Ok(());
                    }
                }
            }
            if io::copy(&mut from.by_ref().take(size), to)? < size {
                return Err(short());
            }
            let mut crlf = [0u8; 2];
            from.read_exact(&mut crlf)?;
            if &crlf != b"\r\n" {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk without CRLF"));
            }
        },
    }
}

impl Broker {
    /// Should a CONNECT to `host` be terminated? Only when a masked credential
    /// injects into it and `tlsTerminate.excludeDomains` does not exclude it.
    pub(crate) fn terminates(&self, host: &str) -> bool {
        match (&self.masks, &self.mitm) {
            (Some(m), Some(_)) => m.injects_into(host) && !crate::host_covered(&self.tls_exclude, host),
            _ => false,
        }
    }

    /// Serve one terminated CONNECT (see the module doc). `target` is the
    /// address the policy checks already resolved and allowed.
    pub(crate) fn terminate(
        &self,
        host: &str,
        port: u16,
        target: SocketAddr,
        client_reader: BufReader<TcpStream>,
        mut client: TcpStream,
        tx: &std::sync::mpsc::Sender<EffectEvent>,
    ) -> io::Result<()> {
        let (Some(masks), Some(ca)) = (self.masks.as_ref(), self.mitm.as_ref()) else {
            return Err(io::Error::other("termination without masks"));
        };
        let cfg = ca.server_config(host)?;
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        client.flush()?;
        let _ = client.set_read_timeout(Some(CONNECT_IDLE_TIMEOUT));
        let w = client.try_clone()?;
        let conn = ServerConnection::new(cfg).map_err(io::Error::other)?;
        let mut tls = StreamOwned::new(conn, Duplex { r: client_reader, w });
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock)?;
        }
        let refuse = |s: &mut StreamOwned<ServerConnection, Duplex>, status: &str, why: &str| -> io::Result<()> {
            let _ = tx.send(EffectEvent::now(
                self.role.clone(),
                Axis::Network,
                "broker-terminate-refused",
                format!("{host}:{port} ({why})"),
                Direction::OutsideTerritory,
                Outcome::Denied,
                "broker/mask",
            ));
            let _ = write!(s, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{why}", why.len());
            s.conn.send_close_notify();
            let _ = s.flush();
            // Close the write side, then read what the client still sends (its
            // request, refused unread) until it closes: a socket closed with unread
            // input sends a reset on Linux, and the client loses the refusal it was
            // about to read. Bounded: two seconds, 64 KiB.
            let _ = s.sock.w.shutdown(std::net::Shutdown::Write);
            let _ = s.sock.w.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let _ = io::copy(&mut (&mut s.sock.r).take(64 * 1024), &mut io::sink());
            Ok(())
        };
        if let Some(sni) = tls.conn.server_name() {
            if !sni.eq_ignore_ascii_case(host) {
                return refuse(&mut tls, "421 Misdirected Request", "TLS server name does not match the CONNECT target");
            }
        }
        let mut r = BufReader::new(tls);

        // The request head: adversarial input, capped as the plain proxy caps it.
        let Some(line) = read_line_capped(&mut r, MAX_LINE_BYTES)? else {
            return refuse(r.get_mut(), "400 Bad Request", "request line missing or too long");
        };
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 || !parts[2].starts_with("HTTP/1.") {
            return refuse(r.get_mut(), "400 Bad Request", "not an HTTP/1.1 request line");
        }
        let (method, target_path) = (parts[0].to_string(), parts[1].to_string());
        let path = if target_path.starts_with('/') {
            target_path.clone()
        } else if let Some(rest) = target_path.strip_prefix("https://") {
            let (auth, p) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            if !names_target(auth, host, port) {
                return refuse(r.get_mut(), "421 Misdirected Request", "request-target authority does not match the CONNECT target");
            }
            if p.is_empty() { "/".to_string() } else { p.to_string() }
        } else {
            return refuse(r.get_mut(), "400 Bad Request", "request-target must be origin-form or https://");
        };
        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let Some(h) = read_line_capped(&mut r, MAX_LINE_BYTES)? else {
                return refuse(r.get_mut(), "400 Bad Request", "header line missing or too long");
            };
            if h == "\r\n" || h == "\n" {
                break;
            }
            if headers.len() >= MAX_HEADERS {
                return refuse(r.get_mut(), "431 Request Header Fields Too Large", "too many headers");
            }
            match h.trim_end().split_once(':') {
                Some((k, v)) if !k.is_empty() && !k.contains(char::is_whitespace) => {
                    headers.push((k.to_string(), v.trim().to_string()))
                }
                _ => return refuse(r.get_mut(), "400 Bad Request", "malformed header line"),
            }
        }
        let hosts: Vec<&String> = headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v).collect();
        if hosts.len() > 1 {
            return refuse(r.get_mut(), "400 Bad Request", "more than one Host header");
        }
        if let Some(h) = hosts.first() {
            if !names_target(h, host, port) {
                return refuse(r.get_mut(), "421 Misdirected Request", "Host header does not match the CONNECT target");
            }
        }
        let Some(framing) = body_framing(&headers) else {
            return refuse(r.get_mut(), "400 Bad Request", "ambiguous body framing");
        };

        // What goes upstream: the headers with the sentinels swapped, minus the
        // hop-by-hop ones, the proxy's own, and the framing (set again below).
        let pairs = masks.pairs_for(host);
        let mut swapped: Vec<String> = Vec::new();
        let expect_continue = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("expect") && v.eq_ignore_ascii_case("100-continue"));
        let mut head = format!("{method} {path} HTTP/1.1\r\n");
        if hosts.is_empty() {
            head.push_str(&format!("Host: {host}{}\r\n", if port == 443 { String::new() } else { format!(":{port}") }));
        }
        for (k, v) in &headers {
            let lk = k.to_ascii_lowercase();
            if is_hop_by_hop(k)
                || lk.starts_with("proxy-")
                || lk == "expect"
                || lk == "content-length"
                || lk == "transfer-encoding"
            {
                continue;
            }
            let (v, used) = pairs.swap_str(v);
            for u in used {
                if !swapped.contains(&u) {
                    swapped.push(u);
                }
            }
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        // A swap that can change the length re-frames the body as chunked.
        let out_framing = match framing {
            BodyFraming::None => BodyFraming::None,
            BodyFraming::Length(n) if pairs.is_empty() || pairs.length_matched() => BodyFraming::Length(n),
            _ => BodyFraming::Chunked,
        };
        match out_framing {
            BodyFraming::Length(n) => head.push_str(&format!("Content-Length: {n}\r\n")),
            BodyFraming::Chunked => head.push_str("Transfer-Encoding: chunked\r\n"),
            BodyFraming::None => {}
        }
        head.push_str("Connection: close\r\n\r\n");

        // Upstream: real TLS, verified, to the address the policy allowed.
        let sock = match TcpStream::connect_timeout(&target, UPSTREAM_TIMEOUT) {
            Ok(s) => s,
            Err(_) => return refuse(r.get_mut(), "502 Bad Gateway", "upstream connect failed"),
        };
        let _ = sock.set_read_timeout(Some(CONNECT_IDLE_TIMEOUT));
        let _ = sock.set_write_timeout(Some(UPSTREAM_TIMEOUT));
        let name = match ServerName::try_from(host.trim_start_matches('[').trim_end_matches(']').to_string()) {
            Ok(n) => n,
            Err(_) => return refuse(r.get_mut(), "400 Bad Request", "not a TLS server name"),
        };
        let up_cfg = match &self.upstream_tls {
            Some(c) => c.clone(),
            None => upstream_tls(&[])?,
        };
        let mut up = StreamOwned::new(ClientConnection::new(up_cfg, name).map_err(io::Error::other)?, sock);
        if let Err(e) = up.write_all(head.as_bytes()) {
            let why = format!("upstream TLS failed: {e}");
            return refuse(r.get_mut(), "502 Bad Gateway", &why);
        }
        if expect_continue {
            r.get_mut().write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            r.get_mut().flush()?;
        }
        match out_framing {
            BodyFraming::None => {}
            BodyFraming::Length(_) => {
                let mut sw = SwapWriter::new(&pairs, &mut up);
                copy_decoded(&framing, &mut r, &mut sw)?;
                let (_, used) = sw.finish()?;
                swapped.extend(used.into_iter().filter(|u| !swapped.contains(u)).collect::<Vec<_>>());
            }
            BodyFraming::Chunked => {
                let mut sw = SwapWriter::new(&pairs, ChunkedWriter(&mut up));
                copy_decoded(&framing, &mut r, &mut sw)?;
                let (chunked, used) = sw.finish()?;
                chunked.finish()?;
                swapped.extend(used.into_iter().filter(|u| !swapped.contains(u)).collect::<Vec<_>>());
            }
        }
        up.flush()?;

        let _ = tx.send(EffectEvent::now(
            self.role.clone(),
            if swapped.is_empty() { Axis::Network } else { Axis::Secret },
            if swapped.is_empty() { "broker-terminate" } else { "broker-mask" },
            if swapped.is_empty() {
                format!("{method} {host}:{port}")
            } else {
                format!("{method} {host}:{port} ({})", swapped.join(", "))
            },
            Direction::OutsideTerritory,
            Outcome::Allowed,
            "broker/mask",
        ));

        // The response, as it comes, until the upstream closes.
        let client_tls = r.get_mut();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = match up.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                // An upstream that closes without close_notify still ended its
                // response (Connection: close); anything else ends the relay too.
                Err(_) => break,
            };
            if client_tls.write_all(&buf[..n]).is_err() {
                break;
            }
        }
        client_tls.conn.send_close_notify();
        let _ = client_tls.flush();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_target_matches_host_and_default_port() {
        assert!(names_target("api.github.com", "api.github.com", 443));
        assert!(names_target("API.github.com:443", "api.github.com", 443));
        assert!(!names_target("api.github.com", "api.github.com", 8443));
        assert!(names_target("api.github.com:8443", "api.github.com", 8443));
        assert!(!names_target("evil.com", "api.github.com", 443));
        assert!(!names_target("api.github.com:x", "api.github.com", 443));
        assert!(names_target("[::1]:443", "::1", 443));
        assert!(!names_target("[::1", "::1", 443));
    }

    #[test]
    fn fuzz_names_target_and_copy_decoded_panic_free() {
        let mut state: u64 = 0x853c49e6748fea9b;
        let mut rng = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet = b"[]:0123456789abc.-\r\n;xX ";
        for _ in 0..5000 {
            let s: String = (0..rng() % 24).map(|_| alphabet[rng() as usize % alphabet.len()] as char).collect();
            let _ = names_target(&s, "a.b", 443);
            let body: Vec<u8> = (0..rng() % 64).map(|_| alphabet[rng() as usize % alphabet.len()]).collect();
            let mut r = BufReader::new(&body[..]);
            let mut out = Vec::new();
            let _ = copy_decoded(&BodyFraming::Chunked, &mut r, &mut out);
            assert!(out.len() <= body.len(), "a decoded body is never longer than its encoding");
        }
    }

    #[test]
    fn copy_decoded_unchunks_and_refuses_short_bodies() {
        let mut out = Vec::new();
        let mut r = BufReader::new(&b"5\r\nhello\r\n3;ext=1\r\n!!!\r\n0\r\nX-Trailer: t\r\n\r\n"[..]);
        copy_decoded(&BodyFraming::Chunked, &mut r, &mut out).unwrap();
        assert_eq!(out, b"hello!!!");
        let mut r = BufReader::new(&b"abc"[..]);
        assert!(copy_decoded(&BodyFraming::Length(5), &mut r, &mut Vec::new()).is_err());
        let mut r = BufReader::new(&b"5\r\nhelloXX0\r\n\r\n"[..]);
        assert!(copy_decoded(&BodyFraming::Chunked, &mut r, &mut Vec::new()).is_err(), "chunk without CRLF");
    }

    #[test]
    fn the_ca_signs_a_leaf_per_host_once() {
        let ca = MitmCa::new().unwrap();
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
        let a = ca.server_config("api.example.com").unwrap();
        let b = ca.server_config("API.example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b), "one leaf per host");
        assert!(!format!("{ca:?}").contains("PRIVATE"));
    }

    // ---- live: a broker in front of a local TLS upstream with its own test CA ----

    use crate::mask::{MaskedCredential, Masks};
    use std::net::TcpListener;
    use std::time::Duration;

    /// A TLS upstream for `127.0.0.1` and `localhost`, signed by its own test CA.
    /// It answers each request with what it received: the head, a blank line,
    /// and the body decoded. With `status` set it answers that instead.
    fn tls_upstream(status: Option<&'static str>) -> (u16, CertificateDer<'static>) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut cap = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        cap.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        cap.distinguished_name.push(rcgen::DnType::CommonName, "test upstream CA");
        let ca_cert = cap.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(cap, ca_key);
        let key = rcgen::KeyPair::generate().unwrap();
        let lp = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
        let leaf = lp.signed_by(&key, &issuer).unwrap();
        let cfg = Arc::new(
            ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .unwrap(),
        );
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let cfg = cfg.clone();
                std::thread::spawn(move || {
                    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                    let mut tls = StreamOwned::new(ServerConnection::new(cfg).unwrap(), s);
                    let mut r = BufReader::new(&mut tls);
                    let mut head = String::new();
                    let mut hdrs = Vec::new();
                    loop {
                        let mut l = String::new();
                        if r.read_line(&mut l).unwrap_or(0) == 0 || l == "\r\n" {
                            break;
                        }
                        if let Some((k, v)) = l.trim_end().split_once(':') {
                            hdrs.push((k.to_string(), v.trim().to_string()));
                        }
                        head.push_str(&l);
                    }
                    let mut body = Vec::new();
                    if let Some(f) = body_framing(&hdrs) {
                        let _ = copy_decoded(&f, &mut r, &mut body);
                    }
                    let tls = r.into_inner();
                    let reply = match status {
                        Some(st) => format!("HTTP/1.1 {st}\r\nLocation: https://localhost:9/elsewhere\r\nContent-Length: 2\r\nConnection: close\r\n\r\nup"),
                        None => {
                            let echo = format!("{head}\r\n{}", String::from_utf8_lossy(&body));
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{echo}", echo.len())
                        }
                    };
                    let _ = tls.write_all(reply.as_bytes());
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
        (port, ca_cert.der().clone())
    }

    /// A broker on loopback with `creds`, trusting the upstream's test CA.
    fn masked_broker(creds: Vec<MaskedCredential>, up_ca: &CertificateDer<'static>) -> (u16, Arc<MitmCa>) {
        let ca = Arc::new(MitmCa::new().unwrap());
        let b = Broker::new("qa", vec![])
            .insecure_no_auth()
            .with_allow_internal(true)
            .with_allowed_hosts(vec!["127.0.0.1".into(), "localhost".into()])
            .with_upstream_roots(std::slice::from_ref(up_ca))
            .unwrap()
            .with_masks(Arc::new(Masks::new(creds)), ca.clone(), vec![])
            .unwrap();
        let (l, port) = b.bind(0).unwrap();
        std::thread::spawn(move || {
            let mut s = tartaros_core::VecSink::default();
            let _ = b.serve(l, &mut s);
        });
        std::thread::sleep(Duration::from_millis(100));
        (port, ca)
    }

    #[derive(Debug)]
    struct AnyCert;
    impl rustls::client::danger::ServerCertVerifier for AnyCert {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            provider().signature_verification_algorithms.supported_schemes()
        }
    }

    /// CONNECT `authority` through the broker, speak TLS as `sni` trusting
    /// `trust` (or anything, when None), send `parts` one write each, and return
    /// what came back (or the CONNECT refusal).
    fn through(broker: u16, authority: &str, sni: &str, trust: Option<&CertificateDer<'static>>, parts: &[Vec<u8>]) -> String {
        let mut c = TcpStream::connect(("127.0.0.1", broker)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(c, "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if c.read(&mut b).unwrap() == 0 {
                break;
            }
            head.push(b[0]);
        }
        let head = String::from_utf8_lossy(&head).to_string();
        if !head.starts_with("HTTP/1.1 200") {
            return head;
        }
        let builder = ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap();
        let cfg = match trust {
            Some(t) => {
                let mut roots = RootCertStore::empty();
                roots.add(t.clone()).unwrap();
                builder.with_root_certificates(roots).with_no_client_auth()
            }
            None => builder.dangerous().with_custom_certificate_verifier(Arc::new(AnyCert)).with_no_client_auth(),
        };
        let conn = ClientConnection::new(Arc::new(cfg), ServerName::try_from(sni.to_string()).unwrap()).unwrap();
        let mut tls = StreamOwned::new(conn, c);
        for p in parts {
            tls.write_all(p).unwrap();
            tls.flush().unwrap();
            std::thread::sleep(Duration::from_millis(30));
        }
        let mut out = Vec::new();
        let _ = tls.read_to_end(&mut out);
        String::from_utf8_lossy(&out).to_string()
    }

    fn get(host: &str, port: u16, extra: &str) -> Vec<Vec<u8>> {
        vec![format!("GET /x HTTP/1.1\r\nHost: {host}:{port}\r\n{extra}\r\n").into_bytes()]
    }

    #[test]
    fn a_sentinel_in_a_header_reaches_its_host_as_the_real_value() {
        let (up, up_ca) = tls_upstream(None);
        let a = MaskedCredential::new("GH_TOKEN", "ghp_real_value_123", vec!["127.0.0.1".into()]).unwrap();
        let s = a.sentinel().to_string();
        let (b, ca) = masked_broker(vec![a], &up_ca);
        let out = through(b, &format!("127.0.0.1:{up}"), "127.0.0.1", Some(ca.cert_der()), &get("127.0.0.1", up, &format!("Authorization: Bearer {s}\r\n")));
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(out.contains("Authorization: Bearer ghp_real_value_123"), "real value upstream: {out}");
        assert!(!out.contains(&s), "the sentinel must not reach its host: {out}");
        assert!(out.contains("Connection: close"));
    }

    #[test]
    fn a_host_without_the_credential_gets_the_sentinel_through_a_blind_tunnel() {
        let (up, up_ca) = tls_upstream(None);
        let a = MaskedCredential::new("GH_TOKEN", "ghp_real_value_123", vec!["localhost".into()]).unwrap();
        let s = a.sentinel().to_string();
        let (b, _ca) = masked_broker(vec![a], &up_ca);
        // 127.0.0.1 is allowed but injects nothing: not terminated, so the client
        // must trust the upstream's own CA, and the upstream sees the sentinel.
        let out = through(b, &format!("127.0.0.1:{up}"), "127.0.0.1", Some(&up_ca), &get("127.0.0.1", up, &format!("Authorization: Bearer {s}\r\n")));
        assert!(out.contains(&format!("Authorization: Bearer {s}")), "{out}");
        assert!(!out.contains("ghp_real_value_123"));
    }

    #[test]
    fn one_credentials_sentinel_is_not_swapped_on_anothers_host() {
        let (up, up_ca) = tls_upstream(None);
        let a = MaskedCredential::new("A", "real-a", vec!["127.0.0.1".into()]).unwrap();
        let bc = MaskedCredential::new("B", "real-b", vec!["localhost".into()]).unwrap();
        let (sa, sb) = (a.sentinel().to_string(), bc.sentinel().to_string());
        let (b, ca) = masked_broker(vec![a, bc], &up_ca);
        let out = through(b, &format!("127.0.0.1:{up}"), "127.0.0.1", Some(ca.cert_der()), &get("127.0.0.1", up, &format!("X-A: {sa}\r\nX-B: {sb}\r\n")));
        assert!(out.contains("X-A: real-a"), "{out}");
        assert!(out.contains(&format!("X-B: {sb}")), "B's sentinel to A's host must stay fake: {out}");
        assert!(!out.contains("real-b"));
    }

    #[test]
    fn a_host_or_server_name_other_than_the_connect_target_is_refused() {
        let (up, up_ca) = tls_upstream(None);
        let a = MaskedCredential::new("T", "real", vec!["127.0.0.1".into()]).unwrap();
        let s = a.sentinel().to_string();
        let (b, ca) = masked_broker(vec![a], &up_ca);
        let out = through(b, &format!("127.0.0.1:{up}"), "127.0.0.1", Some(ca.cert_der()), &get("evil.example", 443, &format!("Authorization: {s}\r\n")));
        assert!(out.starts_with("HTTP/1.1 421"), "Host mismatch: {out}");
        let out = through(b, &format!("127.0.0.1:{up}"), "evil.example", None, &get("127.0.0.1", up, &format!("Authorization: {s}\r\n")));
        assert!(out.starts_with("HTTP/1.1 421"), "SNI mismatch: {out}");
        let req = vec![format!("GET https://evil.example/x HTTP/1.1\r\nAuthorization: {s}\r\n\r\n").into_bytes()];
        let out = through(b, &format!("127.0.0.1:{up}"), "127.0.0.1", Some(ca.cert_der()), &req);
        assert!(out.starts_with("HTTP/1.1 421"), "absolute target mismatch: {out}");
        let two = get("127.0.0.1", up, &format!("Host: 127.0.0.1:{up}\r\n"));
        assert!(through(b, &format!("127.0.0.1:{up}"), "127.0.0.1", Some(ca.cert_der()), &two).starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn a_sentinel_split_across_body_writes_is_swapped() {
        let (up, up_ca) = tls_upstream(None);
        let a = MaskedCredential::new("T", "the-real-token", vec!["127.0.0.1".into()]).unwrap();
        let s = a.sentinel().to_string();
        let (b, ca) = masked_broker(vec![a], &up_ca);
        let body = format!("{{\"token\":\"{s}\"}}");
        let cut = body.find(&s).unwrap() + 20;
        let parts = vec![
            format!("POST /x HTTP/1.1\r\nHost: 127.0.0.1:{up}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
            body.as_bytes()[..cut].to_vec(),
            body.as_bytes()[cut..].to_vec(),
        ];
        let out = through(b, &format!("127.0.0.1:{up}"), "127.0.0.1", Some(ca.cert_der()), &parts);
        assert!(out.ends_with("{\"token\":\"the-real-token\"}"), "{out}");
        assert!(out.contains("Transfer-Encoding: chunked"), "a shorter real value re-frames as chunked: {out}");
        // A length-matched value keeps Content-Length.
        let (up2, up_ca2) = tls_upstream(None);
        let long = "z".repeat(60);
        let a = MaskedCredential::new("T", long.clone(), vec!["127.0.0.1".into()]).unwrap();
        let s = a.sentinel().to_string();
        let (b, ca) = masked_broker(vec![a], &up_ca2);
        let parts = vec![format!("POST /x HTTP/1.1\r\nHost: 127.0.0.1:{up2}\r\nContent-Length: {}\r\n\r\n{s}", s.len()).into_bytes()];
        let out = through(b, &format!("127.0.0.1:{up2}"), "127.0.0.1", Some(ca.cert_der()), &parts);
        assert!(out.contains(&format!("Content-Length: {}", long.len())) && out.ends_with(&long), "{out}");
    }

    #[test]
    fn a_redirect_is_relayed_not_followed() {
        let (up, up_ca) = tls_upstream(Some("302 Found"));
        let a = MaskedCredential::new("T", "real", vec!["127.0.0.1".into()]).unwrap();
        let s = a.sentinel().to_string();
        let (b, ca) = masked_broker(vec![a], &up_ca);
        let out = through(b, &format!("127.0.0.1:{up}"), "127.0.0.1", Some(ca.cert_der()), &get("127.0.0.1", up, &format!("Authorization: {s}\r\n")));
        assert!(out.starts_with("HTTP/1.1 302") && out.ends_with("up"), "{out}");
    }

    #[test]
    fn trust_files_hold_the_ca_first() {
        let ca = MitmCa::new().unwrap();
        let dir = std::env::temp_dir().join(format!("tartaros-mitm-test-{}", std::process::id()));
        let bundle = ca.write_trust_files(&dir).unwrap();
        let text = std::fs::read_to_string(&bundle).unwrap();
        assert!(text.starts_with(ca.cert_pem().trim_end()));
        assert!(std::fs::read_to_string(dir.join("ca.pem")).unwrap().contains("BEGIN CERTIFICATE"));
        assert!(!text.contains("PRIVATE KEY"), "the CA key never reaches disk");
        let _ = std::fs::remove_dir_all(dir);
    }
}
