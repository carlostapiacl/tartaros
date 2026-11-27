//! The agent's environment: scrubbed to an allowlist by default, with the
//! variables that inject code into a process refused.

use crate::Policy;

/// Env vars kept by default (F-13). Everything else in the launcher's environment
/// is dropped before the agent is spawned, because `exec` inheritance is NOT
/// governed by Landlock/Seatbelt and a launcher's env routinely holds secrets
/// (AWS_*, GITHUB_TOKEN, …) that would otherwise leak to the agent and via
/// `/proc/self/environ`. These are the vars ordinary tools need to run at all and
/// that carry no credential: path, home, identity, locale, shell, terminal, temp,
/// and the proxy vars the egress broker sets (proxy config is not a secret and the
/// agent needs it to reach the broker), and the W3C trace context (`TRACEPARENT`,
/// `TRACESTATE`: ids that join a run to its launcher's trace, by spec not secrets),
/// and `AGENT_ID` (a SPIFFE-style URI naming the agent workload, for the agent's
/// own logs and telemetry). `AGENT_ID` is a label passed through: tartaros does not
/// verify it and grants nothing because of it.
/// `LC_*` is matched by prefix, not listed.
pub const ENV_ALLOWLIST: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "TERM", "TZ", "PWD",
    "TMPDIR", "TMP", "TEMP",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "TRACEPARENT", "TRACESTATE",
    "AGENT_ID",
];

/// Loader and interpreter injection vars: inherited, each one makes every child
/// the agent starts load or run code it names (a preload library, a startup
/// script, extra interpreter flags or module paths). Dropped even under
/// `inherit_env`. The list follows nono's `is_dangerous_env_var` (Apache-2.0).
pub const INJECTION_ENV_PREFIXES: &[&str] = &["LD_", "DYLD_", "BASH_FUNC_"];
pub const INJECTION_ENV_VARS: &[&str] = &[
    "BASH_ENV", "ENV", "CDPATH", "GLOBIGNORE", "PROMPT_COMMAND", "IFS",
    "PYTHONSTARTUP", "PYTHONPATH",
    "NODE_OPTIONS", "NODE_PATH",
    "PERL5OPT", "PERL5LIB",
    "RUBYOPT", "RUBYLIB", "GEM_PATH", "GEM_HOME",
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
    "DOTNET_STARTUP_HOOKS",
    "GOFLAGS",
];

pub fn is_injection_env_var(name: &str) -> bool {
    INJECTION_ENV_PREFIXES.iter().any(|p| name.starts_with(p)) || INJECTION_ENV_VARS.contains(&name)
}

impl Policy {
    /// Compute the exact environment the agent should be spawned with (F-13).
    ///
    /// By default the current process environment is filtered to
    /// [`ENV_ALLOWLIST`] (plus `LC_*`). With `inherit_env` the whole environment
    /// passes through (secrets and all, the caller opted in) EXCEPT the
    /// loader/interpreter injection vars of [`is_injection_env_var`]: those turn
    /// an inherited env into code execution in every child the agent starts, and
    /// no workflow needs them inherited silently. Then `env_passthrough` is
    /// applied — `KEY` carries the launcher's value through, `KEY=VALUE` sets it
    /// explicitly (overrides win over the allowlist, and naming an injection var
    /// there is explicit operator intent, so it is honoured). The backend applies
    /// the result with `env_clear()` + `envs(..)`, so enforcement does not depend
    /// on the CLI pre-scrubbing its own process env. Always `Some` today; the
    /// `Option` is kept for backends that may one day leave the env untouched.
    pub fn child_env(&self) -> Option<Vec<(String, String)>> {
        let original: Vec<(String, String)> = std::env::vars().collect();
        self.child_env_from(&original)
    }

    /// Pure core of [`child_env`]: given the launcher's environment `original`,
    /// compute the child's. Split out so the allowlist/passthrough logic is
    /// deterministically testable without touching the process environment.
    pub fn child_env_from(&self, original: &[(String, String)]) -> Option<Vec<(String, String)>> {
        let mut out: Vec<(String, String)> = original
            .iter()
            .filter(|(k, _)| {
                if self.inherit_env {
                    !is_injection_env_var(k)
                } else {
                    ENV_ALLOWLIST.contains(&k.as_str()) || k.starts_with("LC_")
                }
            })
            .cloned()
            .collect();
        let set = |out: &mut Vec<(String, String)>, k: &str, v: String| {
            if let Some(e) = out.iter_mut().find(|(ek, _)| ek == k) {
                e.1 = v;
            } else {
                out.push((k.to_string(), v));
            }
        };
        for entry in &self.env_passthrough {
            match entry.split_once('=') {
                Some((k, v)) => set(&mut out, k, v.to_string()),
                None => {
                    if let Some((_, v)) = original.iter().find(|(k, _)| k == entry) {
                        set(&mut out, entry, v.clone());
                    }
                }
            }
        }
        for (k, v) in &self.env_set {
            set(&mut out, k, v.clone());
        }
        Some(out)
    }
}
