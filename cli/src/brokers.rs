//! The run's brokers: the egress broker behind `--allow-domain`, the credential
//! broker of a policy file's `[broker]` table, and the masked credentials they serve.

use crate::policy_file::BROKER;
use crate::EXIT_POLICY_REFUSED;
use crate::EgressGuard;
#[cfg(target_os = "linux")]
use crate::egress_ns;
use crate::log::LogSpec;
use crate::policy_file::MASKED;
use crate::policy_file::MASK_DIR;
use crate::policy_file::MaskSpec;
use tartaros_core::Network;
use tartaros_core::Policy;
use crate::policy_file::REQUEST_RULES;
use crate::log::Tee;
use crate::create_private_tmp;
use std::process::exit;
use crate::policy_file::expand;
use crate::policy_file::request_rules;
use crate::secrets::secret_var;

/// How the broker treats HTTPS, for its start-up line.
fn tunnel_note(masked: bool) -> &'static str {
    if masked {
        "TCP tunnel, no TLS inspection, except TLS terminated toward the hosts of masked credentials and request rules"
    } else {
        "TCP tunnel, no TLS inspection"
    }
}

/// `--settings` masked credentials at `run`: read each real value from this
/// process's environment (where the caller put it), mint its sentinel, make the
/// run's CA and write its trust bundle, and set what the agent sees — each
/// variable holding its sentinel and the trust-store variables pointing at the
/// bundle — in `env_set`, which wins over `--inherit-env`. The real values stay
/// in the broker's memory.
type MaskedSetup = (
    std::sync::Arc<tartaros_broker::mask::Masks>,
    std::sync::Arc<tartaros_broker::mitm::MitmCa>,
    Vec<String>,
);
fn setup_masked_credentials(p: &mut Policy) -> Option<MaskedSetup> {
    use std::sync::Arc;
    // Request rules need the run's CA too, with or without a masked credential.
    let ruled = !REQUEST_RULES.lock().unwrap().is_empty();
    let spec = match MASKED.get() {
        Some(s) => s.clone(),
        None if ruled => MaskSpec::default(),
        None => return None,
    };
    let mut creds = Vec::new();
    for (name, hosts) in &spec.creds {
        let Some(real) = secret_var(name) else {
            eprintln!("tartaros: --settings: masked credential {name} is not set in the launcher's environment; refusing to run.");
            exit(EXIT_POLICY_REFUSED);
        };
        creds.push(tartaros_broker::mask::MaskedCredential::new(name.clone(), real, hosts.clone()).unwrap_or_else(|e| {
            eprintln!("tartaros: masked credential {name}: {e}");
            exit(1);
        }));
    }
    let masks = tartaros_broker::mask::Masks::new(creds).with_aws_pairs(spec.aws.clone()).unwrap_or_else(|e| {
        eprintln!("tartaros: masked credentials: {e}");
        exit(EXIT_POLICY_REFUSED);
    });
    let ca = tartaros_broker::mitm::MitmCa::new().unwrap_or_else(|e| {
        eprintln!("tartaros: masked credentials: {e}");
        exit(1);
    });
    let dir = create_private_tmp().unwrap_or_else(|e| {
        eprintln!("tartaros: masked credentials: cannot create the CA directory: {e}");
        exit(1);
    });
    let bundle = ca.write_trust_files(&dir).unwrap_or_else(|e| {
        eprintln!("tartaros: masked credentials: cannot write the trust bundle: {e}");
        exit(1);
    });
    if !spec.extra_ca.is_empty() {
        let mut text = std::fs::read_to_string(&bundle).unwrap_or_default();
        for x in &spec.extra_ca {
            match std::fs::read_to_string(expand(x)) {
                Ok(pem) => {
                    text.push_str(pem.trim_end());
                    text.push('\n');
                }
                Err(e) => eprintln!("tartaros: tlsTerminate.extraCaCertPaths: skipping {x}: {e}"),
            }
        }
        let _ = std::fs::write(&bundle, text);
    }
    let _ = MASK_DIR.set(dir.clone());
    p.read_allows.push(dir);
    p.env_set.extend(masks.sentinel_env());
    let bundle = bundle.display().to_string();
    for v in tartaros_broker::mitm::CA_TRUST_VARS {
        p.env_set.push((v.to_string(), bundle.clone()));
    }
    let names: Vec<String> = spec.creds.iter().map(|(n, h)| format!("{n} → {}", h.join(", "))).collect();
    if !names.is_empty() {
        eprintln!(
            "tartaros: masked credentials: {} (the agent holds sentinels; TLS to those hosts is terminated by the broker with this run's CA)",
            names.join("; ")
        );
    }
    Some((Arc::new(masks), Arc::new(ca), spec.exclude.clone()))
}
/// If the policy names allowed egress domains, start the capability broker on
/// host side as a CONNECT/forward proxy scoped to those hosts (with SSRF defense)
/// and point the agent's HTTP(S)_PROXY at it. NET-01: a Landlock port grant alone
/// cannot stop the agent reaching an external host on the broker's port, so on
/// Linux-as-root we instead run the agent in a network namespace whose only route
/// is a veth to the broker (no default route) — the broker becomes the one door out
/// at the network layer, fail-closed. macOS filters egress by address (no gap). The
/// non-root fallback is the bare port grant with a loud NET-01 warning.
pub(crate) fn start_egress_broker(p: &mut Policy, log: Option<&LogSpec>) -> EgressGuard {
    if p.allow_domains.is_empty() {
        return Default::default();
    }
    // `--net` opens all egress, which would make the domain scope meaningless.
    if p.network == Some(Network::Allowed) {
        eprintln!("tartaros: --allow-domain scopes egress; it contradicts --net (allow all). Pick one.");
        exit(2);
    }
    if p.isolate_network {
        eprintln!("tartaros: --allow-domain runs the broker and bridges it into the agent's network namespace; it contradicts --isolate-net (no egress at all). Drop one.");
        exit(2);
    }
    let hosts = p.allow_domains.clone();
    // The broker's decisions go to the run's --log (its own append handle, the same
    // filter as the supervisor's), or nowhere: before, they went to an in-memory sink
    // nobody read, so a run's egress decisions were lost.
    let open_sink = {
        let log = log.cloned();
        move || -> Box<dyn tartaros_core::EffectSink> {
            match log.as_ref().map(|l| (l, l.open())) {
                Some((_, Ok(s))) => Box::new(tartaros_core::FilterSink::new(s, tartaros_core::RecordMode::Boundary)),
                Some((l, Err(e))) => {
                    eprintln!("tartaros: cannot open log {} for the egress broker: {e}", l.path);
                    Box::new(tartaros_core::DiscardSink)
                }
                None => Box::new(tartaros_core::DiscardSink),
            }
        }
    };
    // The role's declared loopback ports (--port): the agent may reach these local
    // services (MCP core, model proxy) THROUGH the broker too, for clients that
    // route everything via HTTP_PROXY. Captured before the broker's own port is
    // appended to local_ports below, so the broker never forwards to itself.
    let loopback_ports = p.local_ports.clone();
    let rules = request_rules(p);
    let masked = setup_masked_credentials(p);
    if let Some(r) = &rules {
        eprintln!(
            "tartaros: request rules for {}: TLS to those hosts is terminated with this run's CA, and a request no rule allows is refused (403)",
            r.hosts().join(", ")
        );
    }
    let make_broker = || {
        let b = tartaros_broker::Broker::new(p.role.clone(), vec![])
            .insecure_no_auth() // the sandbox boundary is the auth; no secret to send
            .with_allowed_hosts(hosts.clone())
            .with_connect_ports(vec![443]) // HTTPS only (ADV-03)
            .with_allow_internal(false) // SSRF / rebinding defense stays on
            .with_loopback_ports(loopback_ports.clone()); // declared local_ports (N1)
        let b = match &masked {
            None => b,
            Some((masks, ca, exclude)) => b.with_masks(masks.clone(), ca.clone(), exclude.clone()).unwrap_or_else(|e| {
                eprintln!("tartaros: masked credentials: cannot set up the upstream TLS: {e}");
                exit(1);
            }),
        };
        match (&rules, &masked) {
            (Some(r), Some((_, ca, _))) => b.with_request_rules(r.clone(), ca.clone()).unwrap_or_else(|e| {
                eprintln!("tartaros: request rules: cannot set up the upstream TLS: {e}");
                exit(1);
            }),
            _ => b,
        }
    };
    // `exempt_loopback`: whether to put loopback in NO_PROXY so the agent connects
    // to a declared local_port DIRECTLY. True in the loopback-broker posture (macOS,
    // non-root Linux): the broker and the local services share the agent's loopback,
    // so a direct connection is correct. FALSE in the NET-01 netns posture: there the
    // agent's loopback is its OWN (empty) netns loopback, NOT the host's where the
    // local services live — so loopback must route THROUGH the broker, which forwards
    // to the host loopback. Either way declared local_ports stay reachable.
    let set_proxy = |ip: &str, port: u16, exempt_loopback: bool| {
        let proxy = format!("http://{ip}:{port}");
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
            std::env::set_var(k, &proxy);
        }
        let no_proxy = if exempt_loopback { "127.0.0.1,localhost,::1" } else { "" };
        for k in ["NO_PROXY", "no_proxy"] {
            std::env::set_var(k, no_proxy);
        }
    };

    // NET-01 closure (Linux, root): run the agent in a network namespace whose only
    // route is a veth to the broker's host IP — no default route — so it reaches the
    // broker and nothing else. Fail-closed: if the namespace cannot be built AND
    // verified isolating, tear down and fall back to the loopback broker with the
    // documented NET-01 warning (a known, honest non-guarantee), never a silent
    // weaker mode.
    #[cfg(target_os = "linux")]
    if !p.isolate_network && egress_ns::available() {
        let broker = make_broker();
        let hosts_for_log = hosts.clone();
        let open_ns_sink = open_sink.clone();
        let bind_on = move |ip: &str| -> std::io::Result<u16> {
            let (listener, port) = broker.bind_addr(ip, 0)?;
            std::thread::spawn(move || {
                let mut sink = Tee(tartaros_broker::RefusalReport::stderr(), open_ns_sink());
                let _ = broker.serve(listener, &mut sink);
            });
            let _ = &hosts_for_log;
            Ok(port)
        };
        match egress_ns::setup(bind_on) {
            Ok((ns, port)) => {
                p.local_ports.push(port); // reach the broker inside the netns
                p.egress_netns = Some(ns.name.clone());
                set_proxy(&ns.host_ip, port, false); // netns: loopback via broker
                eprintln!(
                    "tartaros: egress broker on {}:{port} in a scoped network namespace — allowed: {} (NET-01 closed: the agent has no route except to the broker)",
                    ns.host_ip,
                    hosts.join(", ")
                );
                return Some(ns);
            }
            Err(reason) => {
                eprintln!("tartaros: warning: could not build the scoped egress namespace ({reason}); falling back to the loopback broker. {}", NET01_FALLBACK);
            }
        }
    }

    // Windows: the agent runs as a separate user whose egress is blocked by a
    // per-SID WFP filter that permits exactly ONE loopback port (installed with
    // admin at setup). The broker must bind that fixed port, not a random one; a
    // run-time process cannot add a WFP permit (no admin). The port is not added
    // to local_ports — the WFP permit, not a port grant, is what lets the agent
    // reach it. Fail closed if the setup did not configure a broker channel.
    #[cfg(target_os = "windows")]
    {
        let Some(port) = tartaros_windows::configured_broker_port() else {
            eprintln!("tartaros: --allow-domain needs a broker channel; run setup/sandbox-user.ps1 install -BrokerPort <port> once (elevated).");
            exit(2);
        };
        let broker = make_broker();
        let listener = broker.bind_addr("127.0.0.1", port).map(|(l, _)| l).unwrap_or_else(|e| {
            eprintln!("tartaros: cannot start egress broker on 127.0.0.1:{port}: {e}");
            exit(1);
        });
        set_proxy("127.0.0.1", port, false); // route everything (incl. loopback) via the broker
        eprintln!("tartaros: egress broker on 127.0.0.1:{port} — allowed: {} (HTTPS/443; {})", hosts.join(", "), tunnel_note(masked.is_some()));
        std::thread::spawn(move || {
            let mut sink = Tee(tartaros_broker::RefusalReport::stderr(), open_sink());
            let _ = broker.serve(listener, &mut sink);
        });
        return Default::default();
    }

    // Fallback (macOS, non-root Linux, or netns setup failed): loopback broker.
    #[cfg(not(target_os = "windows"))]
    {
    let broker = make_broker();
    let (listener, port) = broker.bind(0).unwrap_or_else(|e| {
        eprintln!("tartaros: cannot start egress broker: {e}");
        exit(1);
    });
    p.local_ports.push(port);
    set_proxy("127.0.0.1", port, true); // loopback broker: direct loopback ok
    eprintln!("tartaros: egress broker on 127.0.0.1:{port} — allowed: {} (HTTPS/443; {})", hosts.join(", "), tunnel_note(masked.is_some()));
    #[cfg(target_os = "linux")]
    eprintln!("tartaros: warning: {NET01_FALLBACK}");
    std::thread::spawn(move || {
        let mut sink = Tee(tartaros_broker::RefusalReport::stderr(), open_sink());
        let _ = broker.serve(listener, &mut sink);
    });
    Default::default()
    }
}

/// Start the policy file's `[broker]`, if any, on loopback, and give the agent
/// its address and token (TARTAROS_BROKER_URL, TARTAROS_BROKER_TOKEN). A secret
/// named by `value_env` that is not set aborts the run: a capability that would
/// inject an empty credential is a misconfiguration, not a degraded mode.
pub(crate) fn start_credential_broker(p: &mut Policy) {
    let Some(cfg) = BROKER.get().cloned() else { return };
    let env = |name: &str, what: &str| -> String {
        secret_var(name).unwrap_or_else(|| {
            eprintln!("tartaros: [broker] {what} names ${name}, which is not set in the launcher's environment");
            exit(78);
        })
    };
    let token = match &cfg.token_env {
        Some(name) => env(name, "token_env"),
        None => random_token().unwrap_or_else(|e| {
            eprintln!("tartaros: [broker] cannot make a random token ({e}); set token_env");
            exit(1);
        }),
    };
    let mut caps = Vec::new();
    for c in &cfg.capability {
        if !c.prefix.starts_with('/') || c.prefix.len() < 2 || c.prefix.ends_with('/') {
            eprintln!("tartaros: [broker] capability prefix {:?} must look like /name", c.prefix);
            exit(2);
        }
        let methods = if c.methods.is_empty() { vec!["GET".into()] } else { c.methods.iter().map(|m| m.to_uppercase()).collect() };
        let injections = c
            .inject
            .iter()
            .map(|i| tartaros_broker::Injection { host: None, header: i.header.clone(), value: env(&i.value_env, "inject.value_env") })
            .collect();
        caps.push(tartaros_broker::Capability { prefix: c.prefix.clone(), upstream_base: c.upstream.clone(), methods, injections });
    }
    let host_injections = cfg
        .inject
        .iter()
        .map(|i| tartaros_broker::Injection { host: Some(i.host.clone()), header: i.header.clone(), value: env(&i.value_env, "inject.value_env") })
        .collect();
    let mut broker = tartaros_broker::Broker::new(p.role.clone(), host_injections)
        .with_auth(token.clone())
        .with_capabilities(caps)
        .with_allowed_hosts(cfg.allowed_hosts.clone())
        .with_allow_internal(cfg.allow_internal);
    if let Some(h) = &cfg.auth_header {
        broker = broker.with_auth_header(h.clone());
    }
    if cfg.allowed_hosts.is_empty() {
        broker = broker.without_forwarding();
    }
    let (listener, port) = broker.bind(cfg.port).unwrap_or_else(|e| {
        eprintln!("tartaros: cannot start the credential broker on 127.0.0.1:{}: {e}", cfg.port);
        exit(1);
    });
    if !p.local_ports.contains(&port) {
        p.local_ports.push(port);
    }
    p.env_passthrough.push(format!("TARTAROS_BROKER_URL=http://127.0.0.1:{port}"));
    p.env_passthrough.push(format!("TARTAROS_BROKER_TOKEN={token}"));
    eprintln!(
        "tartaros: credential broker on 127.0.0.1:{port} — {} capabilit{}{}",
        cfg.capability.len(),
        if cfg.capability.len() == 1 { "y" } else { "ies" },
        if cfg.allowed_hosts.is_empty() { String::new() } else { format!(", forwards to {}", cfg.allowed_hosts.join(", ")) }
    );
    std::thread::spawn(move || {
        let mut sink = tartaros_broker::RefusalReport::stderr();
        let _ = broker.serve(listener, &mut sink);
    });
}

/// 32 hex characters from the OS's random source.
fn random_token() -> std::io::Result<String> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut b = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
        Ok(b.iter().map(|x| format!("{x:02x}")).collect())
    }
    #[cfg(not(unix))]
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "no /dev/urandom here"))
}

#[cfg(target_os = "linux")]
const NET01_FALLBACK: &str = "egress scoping now relies on a port grant that Landlock cannot pin to loopback (NET-01) — a malicious agent that learns the port could reach an external host on it, bypassing the broker. Safe for a trusted-but-fallible agent; for hostile code run as root so the scoped network namespace can be used.";
