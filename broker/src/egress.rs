//! Egress destination policy for the forward proxy — pure, side-effect-free
//! decisions kept apart from the transport and credential code: which hosts are
//! allowed, and which resolved IPs are internal (SSRF / DNS-rebinding defense).

/// Is `host` permitted by the egress allow-list? Empty list = allow all. An
/// entry beginning with `.` (e.g. `.github.com`) matches that domain and its
/// subdomains; otherwise it is an exact, case-insensitive host match.
pub(crate) fn host_allowed(allowed: &[String], host: &str) -> bool {
    if allowed.is_empty() {
        return true;
    }
    allowed.iter().any(|h| {
        if let Some(suffix) = h.strip_prefix('.') {
            host.eq_ignore_ascii_case(suffix)
                || host
                    .to_ascii_lowercase()
                    .ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
        } else {
            host.eq_ignore_ascii_case(h)
        }
    })
}

/// [`host_allowed`] without its "empty list = every host" rule: an empty list
/// covers nothing. For lists that grant something to a host (a credential's
/// hosts), where empty must mean none.
pub(crate) fn host_allowed_nonempty(patterns: &[String], host: &str) -> bool {
    !patterns.is_empty() && host_allowed(patterns, host)
}

/// Is `ip` an internal/private destination an egress broker should refuse by
/// default? Covers loopback, RFC1918, link-local (169.254.x — cloud metadata at
/// 169.254.169.254), CGNAT, "this host" 0.0.0.0, IPv6 loopback/link-local and
/// unique-local (fc00::/7), and v4-mapped IPv6.
pub(crate) fn is_internal_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()            // 127.0.0.0/8
                || v4.is_private()      // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()   // 169.254/16 (incl. cloud metadata)
                || v4.is_broadcast()
                || v4.is_unspecified()  // 0.0.0.0
                || o[0] == 100 && (o[1] & 0xc0) == 64 // 100.64/10 CGNAT
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || v6.to_ipv4_mapped().map(|m| is_internal_ip(&m.into())).unwrap_or(false)
        }
    }
}
