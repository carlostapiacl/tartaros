# Known gaps

Scenarios that currently FAIL on some backend. Kept out of `corpus/` (which is
green = verified) and tracked here transparently, each with a fix plan. Run them
explicitly: `cargo run -p seisin-security-bench -- security-bench/corpus-known-gaps`.

- **ipc-unix-socket-outside** — Linux: a confined process can connect to a
  pathname unix socket outside its territory (Landlock does not mediate it on
  kernel 6.8). macOS already blocks it. Fix: opt-in seccomp `deny_unix_sockets`.
