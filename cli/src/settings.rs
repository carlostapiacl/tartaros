//! `--settings`: map a sandbox-runtime settings.json onto the generic policy,
//! refusing (exit 78) anything it cannot guarantee.

use serde::Deserialize;
#[cfg(not(target_os = "macos"))]
use crate::policy_file::glob_base;
use tartaros_core::Access;
use crate::EXIT_POLICY_REFUSED;
use tartaros_core::FsRule;
use crate::policy_file::MASKED;
use tartaros_core::Network;
use std::path::PathBuf;
use tartaros_core::Policy;
use crate::policy_file::RequestRuleFile;
use crate::policy_file::add_request_rule;
use crate::policy_file::anchor_glob;
use std::process::exit;
use crate::policy_file::expand_path;
use crate::policy_file::mask_spec;

/// sandbox-runtime settings schema (the subset we read). An adapter maps it onto
/// the generic Policy; anything we cannot enforce makes the launch refuse.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SandboxSettings {
    #[serde(default)]
    pub(crate) filesystem: SandboxFs,
    #[serde(default)]
    pub(crate) network: SandboxNet,
    /// sandbox-runtime's masked credentials (`envVars`/`files` with `mode: "mask"`,
    /// AWS pairs): a sentinel in the sandbox, swapped for the real value on egress
    /// to the credential's hosts. Env-var masking is done by the broker; the rest
    /// is refused by name (docs/broker.md). The TLS termination it needs is
    /// `network.tlsTerminate`, where sandbox-runtime's schema puts it.
    #[serde(default)]
    pub(crate) credentials: Option<serde_json::Value>,
}

/// Does a settings value ask for anything? `null`, `{}`, `[]` and objects made
/// only of those ask for nothing; anything else does.
pub(crate) fn asks_for_something(v: &serde_json::Value) -> bool {
    use serde_json::Value;
    match v {
        Value::Null => false,
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => o.values().any(asks_for_something),
        _ => true,
    }
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SandboxFs {
    #[serde(default, rename = "allowWrite")]
    pub(crate) allow_write: Vec<String>,
    #[serde(default, rename = "denyWrite")]
    pub(crate) deny_write: Vec<String>,
    #[serde(default, rename = "allowRead")]
    pub(crate) allow_read: Vec<String>,
    #[serde(default, rename = "denyRead")]
    pub(crate) deny_read: Vec<String>,
    /// tartaros's own extension (sandbox-runtime has no such field): directories
    /// where the trust-handoff set is not protected — `--handoff-exempt`.
    #[serde(default, rename = "handoffExempt")]
    pub(crate) handoff_exempt: Vec<String>,
    /// tartaros's own extension: writable roots thrown away after the run, where
    /// the trust-handoff set is not protected — `--handoff-scratch`.
    #[serde(default, rename = "handoffScratch")]
    pub(crate) handoff_scratch: Vec<String>,
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
// Some fields drive the macOS/Linux settings path only; on Windows that code is
// cfg'd out, so they read as dead there without being removed from the schema.
#[cfg_attr(target_os = "windows", allow(dead_code))]
struct SandboxNet {
    #[serde(default, rename = "allowedDomains")]
    pub(crate) allowed_domains: Vec<String>,
    /// tartaros's own extension: `[{host, methods, paths}]`, see --allow-request.
    #[serde(default, rename = "requestRules")]
    pub(crate) request_rules: Vec<RequestRuleFile>,
    #[serde(default, rename = "deniedDomains")]
    pub(crate) denied_domains: Vec<String>,
    #[serde(default, rename = "allowUnixSockets")]
    pub(crate) allow_unix_sockets: Vec<String>,
    #[serde(default, rename = "allowLocalBinding")]
    pub(crate) allow_local_binding: bool,
    #[serde(default, rename = "allowMachLookup")]
    pub(crate) allow_mach_lookup: Vec<String>,
    #[serde(default, rename = "allowMachRegister")]
    pub(crate) allow_mach_register: Vec<String>,
    /// `tlsTerminate`: the TLS termination masked credentials need. Under
    /// `network`, as in sandbox-runtime's schema (and as seisin writes it).
    #[serde(default, rename = "tlsTerminate")]
    pub(crate) tls_terminate: Option<serde_json::Value>,
}

/// Apply a sandbox-runtime settings file strictly: map the fields we can enforce
/// onto the generic policy, and REFUSE (exit) on any field we cannot guarantee,
/// rather than running under-enforced. "Apply fully or do not start."
/// How a settings path pattern resolves after unwrapping single-char classes.
#[derive(PartialEq, Clone, Copy)]
enum PatKind {
    /// A concrete path (no remaining metacharacters).
    Literal,
    /// Any-depth pattern (contains `**`).
    AnyDepth,
    /// Single-segment glob (`*`/`?`/a real class, no `**`).
    SingleGlob,
}

/// Unwrap single-character classes `[x]` → `x`. sandbox-runtime callers
/// write `.vscod[e]` so a literal path is treated as a pattern (one class costs
/// fewer rules than a per-parent escape); such a pattern IS the literal path.
/// A multi-char class `[abc]` or a range is left intact (a real glob).
fn unwrap_char_classes(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '[' {
            let mut cls = String::new();
            let mut closed = false;
            while let Some(&n) = chars.peek() {
                chars.next();
                if n == ']' { closed = true; break; }
                cls.push(n);
            }
            if closed && cls.chars().count() == 1 {
                out.push_str(&cls); // single-char class == that literal char
            } else {
                out.push('['); out.push_str(&cls); if closed { out.push(']'); }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Classify a pattern (after unwrapping single-char classes). Returns the
/// normalized string and its kind.
fn classify(pattern: &str) -> (String, PatKind) {
    let s = unwrap_char_classes(pattern);
    let kind = if s.contains("**") {
        PatKind::AnyDepth
    } else if s.contains('*') || s.contains('?') || s.contains('[') {
        PatKind::SingleGlob
    } else {
        PatKind::Literal
    };
    (s, kind)
}

/// An any-depth pattern the trust-handoff set holds exactly, as a whole: a
/// submodule's hooks and config, a linked worktree's `config.worktree` and
/// `commondir`, or `**/<name>` for a handoff name. Matched on the whole suffix,
/// not on a name it contains: `**/.git/worktrees/**/HEAD` is not held, and refused.
#[cfg(not(target_os = "macos"))]
fn git_handoff_pattern(pattern: &str) -> bool {
    use tartaros_core::{HANDOFF_CONFIG_NAMES, HANDOFF_GIT_NAMES};
    let suffix = match pattern.strip_prefix("**/") {
        Some(rest) => rest,
        None => match pattern.split_once("/**/") { Some((_, rest)) => rest, None => return false },
    };
    let suffix = suffix.strip_suffix("/**").unwrap_or(suffix);
    [".git/modules/**/config", ".git/modules/**/hooks", ".git/worktrees/**/config.worktree", ".git/worktrees/**/commondir"]
        .contains(&suffix)
        // `**/<name>` with no base: a handoff name, held under every writable root.
        || (pattern.starts_with("**/") && HANDOFF_CONFIG_NAMES.iter().chain(HANDOFF_GIT_NAMES).any(|n| *n == suffix))
}

pub(crate) fn apply_settings_file(p: &mut Policy, path: &str, verbose: bool) {
    #[cfg(target_os = "macos")]
    let _ = verbose; // only the Linux any-depth path reports
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| { eprintln!("read {path}: {e}"); exit(2); });
    let s: SandboxSettings = serde_json::from_str(&text).unwrap_or_else(|e| { eprintln!("parse {path}: {e}"); exit(2); });
    let refuse = |what: &str| -> ! {
        eprintln!("tartaros: --settings: cannot guarantee {what} on this backend; refusing to run (apply-fully-or-refuse).");
        exit(EXIT_POLICY_REFUSED);
    };
    let refuse_glob = |x: &str| -> ! {
        eprintln!("tartaros: --settings: cannot enforce the glob pattern '{x}' on this backend — TartarOS has no general glob engine (Landlock matches by inode). Use a concrete path, the built-in trust-handoff set (.git/.claude/.codex/.mcp.json/…), or the macOS backend for single-* globs. Refusing (apply-fully-or-refuse).");
        exit(EXIT_POLICY_REFUSED);
    };
    // Filesystem. Each pattern is classified after unwrapping single-char classes
    // (a caller.s `.vscod[e]` is really a literal path). Literals map to the generic
    // carve; any-depth patterns must be covered by the trust-handoff set (else
    // refused — a `**` taken literally would protect nothing); single-* globs go to
    // the macOS regex backend, and are refused on Linux.
    // An ALLOW with any kind of glob is refused (we only re-allow concrete paths).
    for x in &s.filesystem.allow_write {
        match classify(x) { (n, PatKind::Literal) => p.writable_roots.push(PathBuf::from(expand_path(&n))), _ => refuse_glob(x) }
    }
    for x in &s.filesystem.allow_read {
        match classify(x) { (n, PatKind::Literal) => p.read_allows.push(PathBuf::from(expand_path(&n))), _ => refuse_glob(x) }
    }
    let map_deny = |x: &str, write: bool, read: bool, p: &mut Policy| {
        let (n, kind) = classify(x);
        // A class of more than one character (`secret[12].txt`) is matched by no
        // engine here; taken as literal text it would protect neither name.
        if kind != PatKind::Literal && n.contains('[') {
            refuse_glob(x);
        }
        let n = if kind == PatKind::Literal { n } else { anchor_glob(&n) };
        match kind {
            PatKind::Literal => {
                let path = PathBuf::from(expand_path(&n));
                if write { p.fs_rules.push(FsRule { path: path.clone(), access: Access::Deny, even_if_absent: true }); }
                if read { p.read_denies.push(path); }
            }
            PatKind::AnyDepth => {
                // macOS: the pattern itself, as an anchored regex, read or write:
                // exactly what it names, at any depth, present or not.
                #[cfg(target_os = "macos")]
                { p.glob_denies.push(tartaros_core::GlobDeny { pattern: n.clone(), read, write }); }
                #[cfg(not(target_os = "macos"))]
                {
                    // No any-depth read rule without a pattern engine (POL-01):
                    // accepting it as a write deny would leave the path readable.
                    if read {
                        refuse(&format!(
                            "an any-depth read-deny pattern '{x}' (no any-depth read rule \
                             on this backend); use a concrete path under denyRead"
                        ));
                    }
                    // Held on every existing match (any_depth_rules, once the
                    // writable roots are known); a new one where the trust-handoff
                    // set holds that name, so only such patterns are taken.
                    let based = !n.starts_with("**");
                    if based && (tartaros_core::any_depth_split(&n).is_some() || git_handoff_pattern(&n)) {
                        p.any_depth_denies.push((glob_base(&n), n.clone()));
                    } else if !git_handoff_pattern(&n) {
                        refuse_glob(x);
                    }
                    if verbose {
                        eprintln!("tartaros: --settings: '{x}' is held on what exists at the start and, for a new one, where the trust-handoff set holds that name.");
                    }
                }
            }
            PatKind::SingleGlob => {
                // macOS compiles single-* globs to anchored regexes; Linux cannot.
                #[cfg(target_os = "macos")]
                { p.glob_denies.push(tartaros_core::GlobDeny { pattern: n.clone(), read, write }); }
                #[cfg(not(target_os = "macos"))]
                { let _ = (read, write); refuse_glob(x); }
            }
        }
    };
    for x in &s.filesystem.deny_read.clone() { map_deny(x, false, true, p); }
    for x in &s.filesystem.deny_write.clone() { map_deny(x, true, false, p); }
    for x in &s.filesystem.handoff_exempt { p.handoff_exempt.push(PathBuf::from(expand_path(x))); }
    for x in &s.filesystem.handoff_scratch { p.handoff_scratch.push(PathBuf::from(expand_path(x))); }
    for r in &s.network.request_rules { add_request_rule(r.host.clone(), r.methods.clone(), r.paths.clone()); }
    // Network: we default-deny. Anything we cannot enforce in-sandbox is refused.
    p.network = Some(Network::Denied);
    // Per-domain egress IS enforceable: the broker runs as a CONNECT/forward proxy
    // scoped to these hosts and the agent gets no other egress. Map it through.
    //
    // Exception, matching srt: a loopback literal with an explicit port
    // (`localhost:N`, `127.0.0.1:N`, `[::1]:N`) is NOT an external domain — it
    // grants a LOCAL service on that port, exactly like `--port N` (a kernel grant
    // to that loopback port plus a broker loopback-port forward, so the broker
    // never treats it as an external host and rejects it 403). Route those to
    // `local_ports`; send everything else to the egress allow-list. A bare loopback
    // host (no port) or a loopback wildcard (`localhost:*`, `*.localhost`) is
    // unbounded, so refuse it (apply-fully-or-refuse), as srt does.
    let mut domains: Vec<String> = Vec::new();
    for e in &s.network.allowed_domains {
        match classify_loopback_entry(e) {
            LoopbackEntry::Port(n) => p.local_ports.push(n),
            LoopbackEntry::External => domains.push(e.clone()),
            LoopbackEntry::Unbounded => {
                eprintln!(
                    "tartaros: --settings: loopback allowedDomains entry '{e}' is unbounded — \
                     grant a local service by an explicit port (localhost:N / 127.0.0.1:N / [::1]:N), \
                     not a bare host or a wildcard. Refusing (apply-fully-or-refuse)."
                );
                exit(EXIT_POLICY_REFUSED);
            }
        }
    }
    p.allow_domains = domains;
    // Masked credentials: what this backend does (env-var masking through the
    // egress broker) is checked here; what it does not (files, AWS pairs, a CA of
    // the caller's) is refused by name, so a caller hands the role elsewhere.
    match mask_spec(s.credentials.as_ref(), s.network.tls_terminate.as_ref(), &p.allow_domains) {
        Ok(Some(spec)) => {
            let _ = MASKED.set(spec);
        }
        Ok(None) => {}
        Err(what) => refuse(&what),
    }
    p.local_ports.sort_unstable();
    p.local_ports.dedup();
    if !s.network.denied_domains.is_empty() {
        refuse("per-domain deny lists");
    }
    // AF_UNIX: macOS Seatbelt allows specific socket paths; the Linux/seccomp
    // backend filters AF_UNIX all-or-nothing (cannot allow one socket by path).
    #[cfg(target_os = "macos")]
    {
        p.allow_unix_socket_paths =
            s.network.allow_unix_sockets.iter().map(|x| PathBuf::from(expand_path(x))).collect();
    }
    #[cfg(target_os = "linux")]
    {
        if s.network.allow_unix_sockets.is_empty() {
            p.deny_unix_sockets = true; // [] = no AF_UNIX at all
        } else {
            eprintln!("tartaros: --settings: cannot allow a specific AF_UNIX socket by path — the Linux/seccomp backend filters AF_UNIX all-or-nothing, not per path. Use an empty list to deny all, or run the macOS (Seatbelt) backend for per-path allow. Refusing (apply-fully-or-refuse).");
            exit(EXIT_POLICY_REFUSED);
        }
    }
    if s.network.allow_local_binding {
        refuse("blanket local binding (grant a concrete port with a port rule instead)");
    }
    // Mach rendezvous (headless browsers): sandbox-runtime writes a name with a
    // trailing `*` meaning a prefix; map it to a global-name-prefix. As in
    // sandbox-runtime, lookups ADD to the curated base of system services (the
    // backend emits it); `--mach-lookup-only` is the strict variant. macOS-only —
    // Mach is a Darwin primitive, so a non-empty list refuses on Linux.
    #[cfg(target_os = "macos")]
    {
        let to_prefix = |x: &str| x.strip_suffix('*').unwrap_or(x).to_string();
        p.allow_mach_lookup = s.network.allow_mach_lookup.iter().map(|x| to_prefix(x)).collect();
        p.allow_mach_register = s.network.allow_mach_register.iter().map(|x| to_prefix(x)).collect();
    }
    #[cfg(target_os = "linux")]
    {
        if !s.network.allow_mach_lookup.is_empty() || !s.network.allow_mach_register.is_empty() {
            eprintln!("tartaros: --settings: allowMachLookup/allowMachRegister are macOS-only (Mach is a Darwin IPC primitive with no Linux equivalent). Run a headless-browser role under the macOS (Seatbelt) backend. Refusing (apply-fully-or-refuse).");
            exit(EXIT_POLICY_REFUSED);
        }
    }
    // Strict: a settings-driven run is guaranteed-or-abort.
    p.strict = true;
}

/// How a `--settings` `allowedDomains` entry maps into TartarOS's model.
enum LoopbackEntry {
    /// A loopback literal with an explicit port -> a local-service grant (local_ports).
    Port(u16),
    /// A bare loopback host, or a loopback wildcard -> unbounded, must be refused.
    Unbounded,
    /// Any non-loopback host -> an external domain for the egress broker.
    External,
}

/// Classify an srt `allowedDomains` entry. A loopback literal
/// (`localhost` / `127.0.0.1` / `::1`, the last optionally bracketed) with an
/// explicit numeric port is a local-service grant; the same host with no port, or
/// any entry that references loopback through a wildcard, is unbounded; everything
/// else is an external domain.
fn classify_loopback_entry(entry: &str) -> LoopbackEntry {
    // A wildcard that touches loopback (`localhost:*`, `*.localhost`, `127.0.0.1:*`)
    // is never a concrete port grant — refuse before any port parse.
    if entry.contains('*')
        && (entry.contains("localhost") || entry.contains("127.0.0.1") || entry.contains("::1"))
    {
        return LoopbackEntry::Unbounded;
    }
    let (host, port) = split_host_port(entry);
    let is_loopback = matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]");
    if !is_loopback {
        return LoopbackEntry::External;
    }
    match port.and_then(|s| s.parse::<u16>().ok()) {
        Some(n) => LoopbackEntry::Port(n),
        None => LoopbackEntry::Unbounded, // bare loopback host, or a non-numeric port
    }
}

/// Split `host:port` into its parts, handling bracketed IPv6 (`[::1]:N` -> `[::1]`,
/// `N`). Returns the port only when one is present after the host.
fn split_host_port(e: &str) -> (&str, Option<&str>) {
    if e.starts_with('[') {
        if let Some(close) = e.find(']') {
            let host = &e[..=close];
            let port = e[close + 1..].strip_prefix(':');
            return (host, port);
        }
        return (e, None);
    }
    match e.rfind(':') {
        Some(i) => (&e[..i], Some(&e[i + 1..])),
        None => (e, None),
    }
}


#[cfg(test)]
mod tests {
    use super::{classify_loopback_entry, LoopbackEntry};

    fn port(e: &str) -> Option<u16> {
        match classify_loopback_entry(e) {
            LoopbackEntry::Port(n) => Some(n),
            _ => None,
        }
    }
    fn is_unbounded(e: &str) -> bool {
        matches!(classify_loopback_entry(e), LoopbackEntry::Unbounded)
    }
    fn is_external(e: &str) -> bool {
        matches!(classify_loopback_entry(e), LoopbackEntry::External)
    }

    #[test]
    fn loopback_literal_with_port_becomes_a_local_port() {
        assert_eq!(port("localhost:18769"), Some(18769));
        assert_eq!(port("127.0.0.1:18769"), Some(18769));
        assert_eq!(port("[::1]:18769"), Some(18769));
    }

    #[test]
    fn non_loopback_stays_an_external_domain() {
        assert!(is_external("example.com"));
        assert!(is_external("api.example.com:443"));
        // A non-loopback wildcard is a normal domain pattern, not refused.
        assert!(is_external("*.github.com"));
        // A real external IPv6 literal is not loopback.
        assert!(is_external("[2001:db8::1]:443"));
    }

    #[test]
    fn bare_loopback_or_wildcard_is_refused() {
        assert!(is_unbounded("localhost"));
        assert!(is_unbounded("127.0.0.1"));
        assert!(is_unbounded("[::1]"));
        assert!(is_unbounded("localhost:*"));
        assert!(is_unbounded("*.localhost"));
        assert!(is_unbounded("127.0.0.1:*"));
    }
}
