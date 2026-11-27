//! The TOML policy file (`--config`): its `[broker]` table, request rules and
//! masked credentials, and the path expansion the settings adapter shares.

use serde::Deserialize;
#[cfg(not(target_os = "macos"))]
use std::path::PathBuf;
use crate::EXIT_POLICY_REFUSED;
use tartaros_core::Policy;
use crate::settings::asks_for_something;
use std::process::exit;

/// A policy file (TOML) — declare a role's confinement once, apply it on any OS.
/// Flags on the command line override / append to it.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyFile {
    #[serde(default)]
    pub(crate) profile: Option<String>,
    #[serde(default)]
    pub(crate) role: String,
    #[serde(default)]
    pub(crate) writable_roots: Vec<String>,
    #[serde(default)]
    pub(crate) read_denies: Vec<String>,
    #[serde(default)]
    pub(crate) read_allows: Vec<String>,
    #[serde(default)]
    pub(crate) write_denies: Vec<String>,
    #[serde(default)]
    pub(crate) local_ports: Vec<u16>,
    /// Ports the agent may listen on (opt-in). See --listen.
    #[serde(default)]
    pub(crate) listen_ports: Vec<u16>,
    /// `--listen any` (Linux, private network namespace only).
    #[serde(default)]
    pub(crate) listen_any: bool,
    #[serde(default)]
    pub(crate) net: bool,
    /// Unset keeps the default (denied on Linux); `false` is --allow-unix.
    #[serde(default)]
    pub(crate) deny_unix_sockets: Option<bool>,
    #[serde(default)]
    pub(crate) isolate_pids: bool,
    #[serde(default)]
    pub(crate) isolate_network: bool,
    #[serde(default)]
    pub(crate) harden_syscalls: bool,
    #[serde(default)]
    pub(crate) strict: bool,
    #[serde(default)]
    pub(crate) materialize_absent_handoff: bool,
    /// Directories inside a writable root where the trust-handoff set is not
    /// protected (dependency trees: `vendor`, `node_modules`). See --handoff-exempt.
    #[serde(default)]
    pub(crate) handoff_exempt: Vec<String>,
    /// Trust-handoff names not protected in this run (`.goose`, `.vscode`). See
    /// --allow-handoff.
    #[serde(default)]
    pub(crate) handoff_allow: Vec<String>,
    /// Writable roots discarded after the run, where the trust-handoff set is not
    /// protected (a run's TMPDIR). See --handoff-scratch.
    #[serde(default)]
    pub(crate) handoff_scratch: Vec<String>,
    /// `[[request_rule]]`: host, methods, path prefixes. See --allow-request.
    #[serde(default)]
    pub(crate) request_rule: Vec<RequestRuleFile>,
    /// Unset keeps the default (protected); `false` is the dotfiles-repo opt-out.
    #[serde(default)]
    pub(crate) protect_home_handoff: Option<bool>,
    #[serde(default)]
    pub(crate) isolate_process_info: bool,
    #[serde(default)]
    pub(crate) timeout_secs: Option<u64>,
    #[serde(default)]
    pub(crate) max_memory_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) max_processes: Option<u64>,
    #[serde(default)]
    pub(crate) max_cpu_secs: Option<u64>,
    /// The credential broker: capabilities the agent uses without holding their
    /// secret. Only in a policy file (it needs nested tables).
    #[serde(default)]
    pub(crate) broker: Option<BrokerFile>,
}

/// `[broker]`: a loopback HTTP broker for this run. The agent sends a per-run
/// token; the broker serves `[[broker.capability]]` endpoints, injecting secrets
/// it reads from the launcher's environment (never from the file, never into the
/// agent's). With `allowed_hosts` it also forwards plain HTTP and CONNECT to those
/// hosts; without, it forwards nothing.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrokerFile {
    /// Loopback port to listen on (0 or unset: any free port). Granted to the agent.
    #[serde(default)]
    pub(crate) port: u16,
    /// Launcher env var holding the token the agent must send. Unset: a random
    /// per-run token. Either way the agent gets it as TARTAROS_BROKER_TOKEN.
    #[serde(default)]
    pub(crate) token_env: Option<String>,
    /// Header that carries the token (default X-Tartaros-Auth).
    #[serde(default)]
    pub(crate) auth_header: Option<String>,
    #[serde(default)]
    pub(crate) allowed_hosts: Vec<String>,
    /// Let an allowed host that resolves to an internal address be reached
    /// (off: the SSRF defense).
    #[serde(default)]
    pub(crate) allow_internal: bool,
    #[serde(default)]
    pub(crate) capability: Vec<CapabilityFile>,
    /// Headers injected into plain-HTTP requests forwarded to an allowed host
    /// (HTTPS through CONNECT is a blind tunnel: use a capability for it).
    #[serde(default)]
    pub(crate) inject: Vec<HostInjectFile>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostInjectFile {
    pub(crate) host: String,
    pub(crate) header: String,
    pub(crate) value_env: String,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapabilityFile {
    /// `/prefix`: the agent asks the broker for `/prefix/rest`.
    pub(crate) prefix: String,
    /// The real endpoint: `/prefix/rest` becomes `upstream/rest`.
    pub(crate) upstream: String,
    /// Methods allowed (default GET only).
    #[serde(default)]
    pub(crate) methods: Vec<String>,
    #[serde(default)]
    pub(crate) inject: Vec<InjectFile>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct InjectFile {
    pub(crate) header: String,
    /// Launcher env var holding the header's value (the secret).
    pub(crate) value_env: String,
}

/// The `[broker]` of the policy file, if any (set while the policy is built).
pub(crate) static BROKER: std::sync::OnceLock<BrokerFile> = std::sync::OnceLock::new();

/// `--settings` masked credentials (sandbox-runtime's `credentials.envVars` with
/// `mode: "mask"`), checked while the policy is built and set up by the egress
/// broker at `run` (docs/broker.md).
#[derive(Clone, Debug, Default)]
pub(crate) struct MaskSpec {
    /// (variable name, host patterns in the allow-list's spelling).
    pub(crate) creds: Vec<(String, Vec<String>)>,
    /// `tlsTerminate.excludeDomains`, same spelling.
    pub(crate) exclude: Vec<String>,
    /// `tlsTerminate.extraCaCertPaths`: appended to the agent's trust bundle.
    pub(crate) extra_ca: Vec<String>,
    /// AWS pairs (access key id, secret access key) by variable name, re-signed.
    pub(crate) aws: Vec<(String, String)>,
}
pub(crate) static MASKED: std::sync::OnceLock<MaskSpec> = std::sync::OnceLock::new();

/// Request rules (`--allow-request`, `[[request_rule]]`, `network.requestRules`):
/// the methods and path prefixes the agent may send to a host. The broker
/// terminates those hosts and refuses any other request (broker/src/rules.rs).
pub(crate) static REQUEST_RULES: std::sync::Mutex<Vec<tartaros_broker::rules::RequestRule>> = std::sync::Mutex::new(Vec::new());

/// A rule from a policy file or `--settings`.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestRuleFile {
    pub(crate) host: String,
    #[serde(default)]
    pub(crate) methods: Vec<String>,
    #[serde(default)]
    pub(crate) paths: Vec<String>,
}

pub(crate) fn add_request_rule(host: String, methods: Vec<String>, paths: Vec<String>) {
    REQUEST_RULES.lock().unwrap().push(tartaros_broker::rules::RequestRule { host, methods, paths });
}

/// `--allow-request "GET,POST api.github.com/repos/acme/"`: methods (`*` for any),
/// a space, the host and an optional path prefix.
pub(crate) fn parse_allow_request(spec: &str) {
    let Some((methods, rest)) = spec.trim().split_once(char::is_whitespace) else {
        eprintln!("error: --allow-request \"METHODS host[/path]\", e.g. \"GET api.github.com\" or \"POST api.github.com/repos/acme/\"");
        exit(2);
    };
    let methods: Vec<String> = if methods == "*" { Vec::new() } else { methods.split(',').map(|m| m.trim().to_string()).collect() };
    let rest = rest.trim();
    let (host, path) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), vec![rest[i..].to_string()]),
        None => (rest.to_string(), Vec::new()),
    };
    add_request_rule(host, methods, path);
}

/// The rules, validated, and each host checked against the policy: it must be
/// an allowed egress domain, and one TLS termination may reach. Refused (78) otherwise.
pub(crate) fn request_rules(p: &Policy) -> Option<std::sync::Arc<tartaros_broker::rules::Rules>> {
    let list = REQUEST_RULES.lock().unwrap().clone();
    if list.is_empty() {
        return None;
    }
    let rules = tartaros_broker::rules::Rules::new(list.clone()).unwrap_or_else(|e| {
        eprintln!("tartaros: {e}; refusing to run.");
        exit(EXIT_POLICY_REFUSED);
    });
    let excluded = MASKED.get().map(|m| m.exclude.clone()).unwrap_or_default();
    for r in &list {
        let name = r.host.trim_start_matches('.');
        if !tartaros_broker::host_covered(&p.allow_domains, name) {
            eprintln!("tartaros: request rule for {}: not an allowed egress domain (--allow-domain); refusing to run.", r.host);
            exit(EXIT_POLICY_REFUSED);
        }
        if tartaros_broker::host_covered(&excluded, name) {
            eprintln!("tartaros: request rule for {}: tlsTerminate.excludeDomains excludes it, so its requests cannot be read; refusing to run.", r.host);
            exit(EXIT_POLICY_REFUSED);
        }
    }
    Some(std::sync::Arc::new(rules))
}
/// The run's CA directory, removed when the run ends.
pub(crate) static MASK_DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// A settings host pattern in the egress allow-list's spelling: `*.x` -> `.x`.
fn as_allow_pattern(h: &str) -> String {
    match h.strip_prefix("*.") {
        Some(rest) => format!(".{}", rest.to_ascii_lowercase()),
        None => h.to_ascii_lowercase(),
    }
}

/// Read `credentials` / `tlsTerminate` into a [`MaskSpec`], or say which part
/// this backend cannot guarantee. `allow` is the role's egress allow-list: a
/// credential host it does not cover could never be reached, so it is refused.
pub(crate) fn mask_spec(
    creds: Option<&serde_json::Value>,
    tls: Option<&serde_json::Value>,
    allow: &[String],
) -> Result<Option<MaskSpec>, String> {
    use serde_json::Value;
    let creds_asked = creds.is_some_and(asks_for_something);
    let tls_asked = tls.is_some_and(asks_for_something);
    if !creds_asked && !tls_asked {
        return Ok(None);
    }
    if !creds_asked {
        return Err("TLS termination without masked credentials (tlsTerminate alone)".into());
    }
    // Windows: only the sandbox-user tier has the broker channel (a WFP-permitted
    // loopback port) the swap runs through, and its agent is another user, who
    // cannot read this process's environment. The AppContainer has no channel.
    #[cfg(target_os = "windows")]
    if tartaros_windows::Tier::from_env() != tartaros_windows::Tier::SandboxUser {
        return Err("masked credentials on the appcontainer tier (they need TARTAROS_WINDOWS_TIER=sandbox-user and its broker channel)".into());
    }
    if cfg!(not(any(unix, target_os = "windows"))) {
        return Err("masked credentials on this OS".into());
    }
    let strings = |v: &Value, what: &str| -> Result<Vec<String>, String> {
        v.as_array()
            .ok_or_else(|| format!("{what} that is not a list"))?
            .iter()
            .map(|x| x.as_str().map(str::to_string).ok_or_else(|| format!("{what} with a non-string entry")))
            .collect()
    };
    let mut spec = MaskSpec::default();
    let Some(obj) = creds.and_then(Value::as_object) else {
        return Err("credentials that is not an object".into());
    };
    for (k, v) in obj {
        if !asks_for_something(v) {
            continue;
        }
        match k.as_str() {
            "envVars" => {}
            "files" => return Err("masked credential files (credentials.files)".into()),
            "awsPairs" => {}
            other => return Err(format!("credentials.{other}")),
        }
    }
    let covered = |h: &str| -> bool {
        let allow: Vec<String> = allow.iter().map(|a| as_allow_pattern(a)).collect();
        match h.strip_prefix('.') {
            // A domain pattern: covered by the same pattern or a broader one.
            Some(d) => allow.iter().any(|a| a.strip_prefix('.').is_some_and(|ad| d == ad || d.ends_with(&format!(".{ad}")))),
            None => tartaros_broker::host_covered(&allow, h),
        }
    };
    for e in obj.get("envVars").and_then(Value::as_array).into_iter().flatten() {
        let Some(e) = e.as_object() else { return Err("credentials.envVars entry that is not an object".into()) };
        let name = e.get("name").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') || name.as_bytes()[0].is_ascii_digit() {
            return Err(format!("credentials.envVars entry with an invalid name {name:?}"));
        }
        match e.get("mode").and_then(Value::as_str) {
            Some("mask") => {}
            m => return Err(format!("credential {name} with mode {m:?} (only \"mask\")")),
        }
        for k in e.keys() {
            if !["name", "mode", "injectHosts"].contains(&k.as_str()) && asks_for_something(&e[k]) {
                return Err(format!("credential {name}: {k}"));
            }
        }
        let hosts = strings(e.get("injectHosts").unwrap_or(&Value::Null), &format!("credential {name}: injectHosts"))
            .unwrap_or_default();
        if hosts.is_empty() {
            return Err(format!("credential {name} with no injectHosts (a masked credential must name where it goes)"));
        }
        let hosts: Vec<String> = hosts.iter().map(|h| as_allow_pattern(h)).collect();
        for h in &hosts {
            if !covered(h) {
                return Err(format!("credential {name}: inject host {h} is not in allowedDomains, so it could never be reached"));
            }
        }
        if spec.creds.iter().any(|(n, _)| n == name) {
            return Err(format!("credential {name} declared twice"));
        }
        spec.creds.push((name.to_string(), hosts));
    }
    if spec.creds.is_empty() {
        return Err("credentials with nothing in envVars".into());
    }
    // AWS pairs: re-signed on egress (broker/src/sigv4.rs). Explicit
    // `awsPairs` entries, and the conventional AWS_ACCESS_KEY_ID /
    // AWS_SECRET_ACCESS_KEY when both are masked and no entry names them, as
    // sandbox-runtime pairs them. A session token is masked like any variable.
    let masked = |n: &str| spec.creds.iter().any(|(c, _)| c == n);
    for p in obj.get("awsPairs").and_then(Value::as_array).into_iter().flatten() {
        let Some(p) = p.as_object() else { return Err("credentials.awsPairs entry that is not an object".into()) };
        let get = |k: &str| p.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        for k in p.keys() {
            if !["accessKeyIdVar", "secretAccessKeyVar", "sessionTokenVar"].contains(&k.as_str()) {
                return Err(format!("credentials.awsPairs: {k}"));
            }
        }
        let (id, secret) = (get("accessKeyIdVar"), get("secretAccessKeyVar"));
        for n in [&id, &secret] {
            if !masked(n) {
                return Err(format!("credentials.awsPairs names {n:?}, which is not a masked credential in envVars"));
            }
        }
        let token = get("sessionTokenVar");
        if !token.is_empty() && !masked(&token) {
            return Err(format!("credentials.awsPairs names {token:?}, which is not a masked credential in envVars"));
        }
        spec.aws.push((id, secret));
    }
    if spec.aws.is_empty() && masked("AWS_ACCESS_KEY_ID") && masked("AWS_SECRET_ACCESS_KEY") {
        spec.aws.push(("AWS_ACCESS_KEY_ID".into(), "AWS_SECRET_ACCESS_KEY".into()));
    }
    if let Some(t) = tls.filter(|t| asks_for_something(t)) {
        let Some(t) = t.as_object() else { return Err("tlsTerminate that is not an object".into()) };
        for (k, v) in t {
            if !asks_for_something(v) {
                continue;
            }
            match k.as_str() {
                "excludeDomains" => spec.exclude = strings(v, "tlsTerminate.excludeDomains")?.iter().map(|h| as_allow_pattern(h)).collect(),
                "extraCaCertPaths" => spec.extra_ca = strings(v, "tlsTerminate.extraCaCertPaths")?,
                other => return Err(format!("tlsTerminate.{other} (the broker makes its own CA per run)")),
            }
        }
    }
    Ok(Some(spec))
}

/// Expand a leading `~` to $HOME so policy files are portable.
pub(crate) fn expand(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    s.to_string()
}

/// Like [`expand`], but also resolve a relative path to absolute against the
/// current working directory. The backends require absolute writable/deny roots
/// (the sandbox profile must be unambiguous), and cwd is well-defined at launch —
/// so a user's `./repo` is resolved here rather than rejected with "must be
/// absolute". Used only for concrete path flags, never for glob patterns (which
/// stay relative by design, e.g. `**/*.pem`).
/// A glob made to name what the kernel will see: `~` expanded, a relative base
/// taken from the working directory (as a literal path is), and the literal
/// prefix resolved (`/tmp` → `/private/tmp`, a symlinked directory → its
/// target). A pattern that starts with `**` has no prefix and is left as is.
pub(crate) fn anchor_glob(pattern: &str) -> String {
    let s = expand(pattern);
    if s.starts_with("**") {
        return s;
    }
    let s = expand_path(&s);
    let comps: Vec<&str> = s.split('/').collect();
    let glob = |c: &str| c.contains('*') || c.contains('?') || c.contains('[');
    let Some(first) = comps.iter().position(|c| glob(c)) else { return s };
    let prefix = comps[..first].join("/");
    let base = tartaros_core::resolve_best_effort(std::path::Path::new(if prefix.is_empty() { "/" } else { &prefix }));
    format!("{}/{}", base.display().to_string().trim_end_matches('/'), comps[first..].join("/"))
}

/// The literal part of an anchored glob, before its first glob component.
#[cfg(not(target_os = "macos"))]
pub(crate) fn glob_base(pattern: &str) -> PathBuf {
    let glob = |c: &str| c.contains('*') || c.contains('?') || c.contains('[');
    PathBuf::from(pattern.split('/').take_while(|c| !glob(c)).collect::<Vec<_>>().join("/"))
}

pub(crate) fn expand_path(s: &str) -> String {
    let s = expand(s);
    let p = std::path::Path::new(&s);
    if p.is_absolute() {
        return s;
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(p).to_string_lossy().into_owned(),
        Err(_) => s,
    }
}
