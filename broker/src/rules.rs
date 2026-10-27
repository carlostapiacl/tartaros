//! Request rules: which methods and paths the agent may send to a host.
//!
//! An allowed domain is a capability to speak HTTPS to it, all of it: allowing
//! `api.github.com` lets an agent push to any repository its token reaches. A
//! host with rules is terminated like a masked credential's host (`mitm.rs`),
//! and every request on it must match one: its method among the rule's (none
//! listed = any) and its path under one of the rule's prefixes (none listed =
//! any). Anything else is refused with 403 before it leaves. Hosts without rules
//! keep the blind tunnel.
//!
//! The path is checked as sent, before any decoding the upstream might do, and
//! fails closed: a `.` or `..` segment in any spelling is refused (the client or
//! the upstream would resolve it out of the prefix), a prefix matches only at a
//! segment boundary (`/repos/acme` is not `/repos/acme-evil`), and a path spelled
//! differently from the prefix (another case, percent-encoded letters) does not
//! match it. The query is not part of the path.

use std::io;

/// One rule: a host (exact, or `.domain` for it and its subdomains), the methods
/// and the path prefixes it allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRule {
    pub host: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
}

/// The rules of a run.
#[derive(Debug, Clone, Default)]
pub struct Rules(Vec<RequestRule>);

impl Rules {
    /// Validated: a host, upper-case method tokens, prefixes that start with `/`
    /// and hold no dot segment and no query.
    pub fn new(rules: Vec<RequestRule>) -> io::Result<Self> {
        for r in &rules {
            let bad = |why: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("request rule for {:?}: {why}", r.host));
            if r.host.trim().is_empty() || r.host.contains('/') || r.host.contains(':') {
                return Err(bad("the host is a name, with no scheme, port or path"));
            }
            for m in &r.methods {
                if m.is_empty() || !m.bytes().all(|b| b.is_ascii_uppercase()) {
                    return Err(bad("methods are upper-case tokens (GET, POST…)"));
                }
            }
            for p in &r.paths {
                if !p.starts_with('/') || p.contains('?') || p.contains('#') || crate::has_dot_segment(p) {
                    return Err(bad("a path prefix starts with / and holds no query and no . or .. segment"));
                }
            }
        }
        Ok(Rules(rules))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Does any rule speak for `host`? Then its requests are checked.
    pub fn covers(&self, host: &str) -> bool {
        self.0.iter().any(|r| crate::host_covered(std::slice::from_ref(&r.host), host))
    }

    /// The hosts the rules name, as written.
    pub fn hosts(&self) -> Vec<String> {
        self.0.iter().map(|r| r.host.clone()).collect()
    }

    /// `Ok` when a rule for `host` allows `method` on `target` (origin-form);
    /// otherwise the reason it is refused.
    pub fn check(&self, host: &str, method: &str, target: &str) -> Result<(), String> {
        let path = target.split(['?', '#']).next().unwrap_or("");
        if !path.starts_with('/') {
            return Err("not an origin-form path".into());
        }
        if crate::has_dot_segment(path) {
            return Err("a . or .. segment in the path".into());
        }
        let mine: Vec<&RequestRule> =
            self.0.iter().filter(|r| crate::host_covered(std::slice::from_ref(&r.host), host)).collect();
        let ok = mine.iter().any(|r| {
            (r.methods.is_empty() || r.methods.iter().any(|m| m == method))
                && (r.paths.is_empty() || r.paths.iter().any(|p| under_prefix(path, p)))
        });
        if ok {
            Ok(())
        } else {
            Err(format!("{method} {path} is not allowed by the request rules for {host}"))
        }
    }
}

/// `path` is `prefix`, or under it at a segment boundary.
fn under_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    let p = prefix.trim_end_matches('/');
    path == p || path.starts_with(&format!("{p}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Rules {
        Rules::new(vec![
            RequestRule { host: "api.github.com".into(), methods: vec!["GET".into()], paths: vec![] },
            RequestRule {
                host: "api.github.com".into(),
                methods: vec!["POST".into(), "PATCH".into()],
                paths: vec!["/repos/acme/".into()],
            },
            RequestRule { host: ".pypi.org".into(), methods: vec![], paths: vec!["/simple".into()] },
        ])
        .unwrap()
    }

    #[test]
    fn methods_and_prefixes_are_what_is_allowed() {
        let r = rules();
        assert!(r.check("api.github.com", "GET", "/user").is_ok());
        assert!(r.check("api.github.com", "POST", "/repos/acme/app/issues").is_ok());
        assert!(r.check("api.github.com", "POST", "/repos/acme").is_ok());
        assert!(r.check("api.github.com", "POST", "/repos/evil/app/issues").is_err());
        assert!(r.check("api.github.com", "DELETE", "/repos/acme/app").is_err());
        assert!(r.check("files.pypi.org", "GET", "/simple/requests/").is_ok());
        assert!(r.check("files.pypi.org", "GET", "/packages/x").is_err());
    }

    #[test]
    fn a_prefix_matches_at_a_segment_boundary_and_as_spelled() {
        let r = rules();
        assert!(r.check("api.github.com", "POST", "/repos/acme-evil/app").is_err());
        assert!(r.check("api.github.com", "POST", "/repos/ACME/app").is_err());
        assert!(r.check("api.github.com", "POST", "/repos/%61cme/app").is_err());
        assert!(r.check("files.pypi.org", "GET", "/simplex").is_err());
    }

    #[test]
    fn dot_segments_and_queries_do_not_leave_a_prefix() {
        let r = rules();
        for p in ["/repos/acme/../evil/app", "/repos/acme/%2e%2e/evil", "/repos/acme/..%2fevil", "/repos/acme/.%2e/evil"] {
            assert!(r.check("api.github.com", "POST", p).is_err(), "{p}");
        }
        assert!(r.check("api.github.com", "POST", "/repos/acme/app?x=/repos/evil").is_ok());
        assert!(r.check("api.github.com", "POST", "/repos/evil/app?x=/repos/acme/").is_err());
    }

    #[test]
    fn rules_are_validated() {
        let one = |host: &str, m: &str, p: &str| {
            Rules::new(vec![RequestRule { host: host.into(), methods: vec![m.into()], paths: vec![p.into()] }])
        };
        assert!(one("https://api.github.com", "GET", "/").is_err());
        assert!(one("api.github.com:443", "GET", "/").is_err());
        assert!(one("api.github.com", "get", "/").is_err());
        assert!(one("api.github.com", "GET", "repos").is_err());
        assert!(one("api.github.com", "GET", "/repos/../x").is_err());
        assert!(one("api.github.com", "GET", "/repos?x").is_err());
        assert!(one("api.github.com", "GET", "/repos/").is_ok());
    }
}
