# The credential broker

The agent uses a credential without holding it. A `[broker]` table in the policy
file (`tartaros run --config policy.toml -- …`) starts a broker on loopback for
the run. The agent asks the broker; the broker makes the real request with the
secret added. The secret is read from the launcher's environment, so it is never
on a command line, in the policy file, in the agent's environment or in the log.

```toml
writable_roots = ["~/work/repo"]

[broker]
port = 18080                 # loopback port; unset = any free port
token_env = "BROKER_TOKEN"   # unset = a random per-run token
auth_header = "X-Tartaros-Auth"

# The agent asks for http://127.0.0.1:18080/gh/repos/o/r and the broker requests
# https://api.github.com/repos/o/r with the Authorization header added.
[[broker.capability]]
prefix = "/gh"
upstream = "https://api.github.com"
methods = ["GET"]            # default: GET only; anything else gets 405
[[broker.capability.inject]]
header = "Authorization"
value_env = "GH_AUTH"        # e.g. GH_AUTH="Bearer ghp_…" in the launcher's env
```

What the agent gets:

- `TARTAROS_BROKER_URL` (`http://127.0.0.1:<port>`) and `TARTAROS_BROKER_TOKEN` in
  its environment. The port is granted to it.
- Every request must carry the token in the auth header, or it gets 403. The token
  is removed before anything goes upstream.

What the broker guarantees:

- **The secret stays in the broker.** The agent's own copy of an injected header
  is not sent; the broker's value is. Upstream redirects are not followed, so a 3xx
  cannot carry the secret elsewhere.
- **A capability stays inside its upstream.** A path that leaves the prefix, or holds
  a `..` or `.` segment in any spelling (`%2e%2e`, `..%2f`), is refused with 400.
- **Only the declared methods.** Anything else is 405, unknown methods included.
- **Nothing else goes out through it.** Without `allowed_hosts` the broker forwards
  nothing: no plain-HTTP proxying, no CONNECT. With `allowed_hosts` (a leading `.`
  matches subdomains) it also forwards to those hosts, refuses lookalikes, and
  refuses an allowed name that resolves to an internal address unless
  `allow_internal = true`. `[[broker.inject]]` (`host`, `header`, `value_env`) adds
  a header to plain-HTTP requests forwarded to that host.
- A secret named by `value_env` or `token_env` that is not set refuses the run
  (exit 78).

Limits:

- `--inherit-env` passes the launcher's whole environment to the agent, the
  secrets included. Don't combine the two.
- Capability endpoints do not pass a request body upstream yet; they suit GET-style
  APIs.
- HTTPS through `allowed_hosts` is a blind CONNECT tunnel: TLS is end to end, so no
  header can be added to it. Use a capability for an HTTPS API.
- Masked credentials (below) cover environment variables only: no files, no AWS
  SigV4 re-signing.

## Masked credentials (`--settings`)

sandbox-runtime's masked credentials, for a tool that should keep calling the real
URL with its usual variable (`gh`, `curl` with `$GH_TOKEN`) without the agent ever
holding the value. seisin's `key_mode = "inject"` writes them.

```json
{
  "network": {
    "allowedDomains": ["api.github.com"],
    "tlsTerminate": { "excludeDomains": [] }
  },
  "credentials": {
    "envVars": [{ "name": "GH_TOKEN", "mode": "mask", "injectHosts": ["api.github.com"] }]
  }
}
```

- **The value** is read from the launcher's environment by name, at `run` (unset:
  exit 78). The agent's `GH_TOKEN` is a sentinel, `fake_value_<uuid4>` padded to the
  real value's length, **even with `--inherit-env`**: the sentinel is set after
  everything else the environment passes. The map lives in the broker's memory only.
- **The swap** happens only on egress to the credential's own `injectHosts`: there
  the broker terminates TLS, with a leaf for that host signed by a CA made for this
  run, and replaces the sentinel in the request's headers and in its body, streamed
  (a sentinel split across writes is still found). One credential's sentinel sent to
  another credential's host, or to any other host, travels as the useless fake.
  When the swap cannot change the body's length, `Content-Length` is kept; otherwise
  the body goes upstream chunked.
- **Upstream** is real TLS verified against the webpki roots, with no proxy from the
  environment and no redirects followed; the response comes back untouched. One
  request per terminated connection (`Connection: close`); clients reconnect.
- **Checks on the terminated side**, as sandbox-runtime makes them: the TLS server
  name, the `Host` header (one at most) and an absolute request-target must all name
  the CONNECT target, or 421. The head is capped like the plain proxy's (line length,
  header count). `Expect: 100-continue` is answered by the broker.
- **What the agent trusts:** the run's CA certificate and a bundle of it plus the
  system's roots (and the launcher's `NODE_EXTRA_CA_CERTS`, and
  `tlsTerminate.extraCaCertPaths`) are written to a short run directory, readable by
  the agent and removed when the run ends; `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`,
  `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO` and the rest of
  sandbox-runtime's list point at the bundle. The CA's private key never leaves memory.
- **Every other host** keeps the blind CONNECT tunnel. `tlsTerminate.excludeDomains`
  is never terminated, masked or not.

What it costs and what it does not do:

- **It is a MITM** over the credential's hosts, by design: the broker sees that
  traffic in the clear. A tool that pins certificates, or ignores the trust
  variables, fails there instead of sending anything.
- **Reflection is not closed:** a host that stores what the agent sends (an issue, a
  gist) and returns it later hands the real value back. Use a least-scope token.
- **Missed swaps fail closed:** a sentinel inside a compressed or encoded body reaches
  the upstream as the fake, and authentication fails; the real value is never sent
  where it was not declared. A sentinel in the URL (a query string) is not swapped.
- **Refused by name (exit 78):** `credentials.files`, `credentials.awsPairs`, a mode
  other than `mask`, a credential with no `injectHosts` or one `allowedDomains` does
  not cover, `tlsTerminate` without credentials, and a CA of the caller's
  (`tlsTerminate.caCertPath`).
- See *Secrets and exec environments* below for what the launcher must not do.

## Secrets and exec environments

A process's exec-time environment can stay readable, for the process's whole
life, by other processes of the same user (`/proc/<pid>/environ` on Linux), and the
agent is such a process. Do not count on the sandbox to hide another process's
environment from it.

So when a run will read secrets from its environment (masked credentials, a
`[broker]`'s `value_env` and `token_env`), tartaros first re-execs itself: it reads
them, writes them to a pipe, and `execve`s its own binary (same pid) with an
environment without them; the new image reads them into memory and closes the pipe.
This happens before the broker starts or the agent exists, so no tartaros process
the agent can read holds them in its exec record. Measured with a probe inside the
run that reads every record it can: no tartaros process holds the value, and the
probe does not inherit the pipe's fd (`cli/tests/secrets_not_in_exec_env.rs`).

What tartaros cannot clean is **the launcher**: the process that started tartaros
keeps its own exec environment. If a shell exports the secret
(`export GH_TOKEN=…; tartaros run …`), or names it on its own command line, that
shell's record holds it and the agent can read it. Give tartaros the value only in
its own environment, from something that does not itself hold it in its exec
record: seisin resolves the value through a provider and hands it to tartaros's
environment only; from a shell, `GH_TOKEN="$(…)" tartaros run …` scopes it to
tartaros, while `export` does not.
