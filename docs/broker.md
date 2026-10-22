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
