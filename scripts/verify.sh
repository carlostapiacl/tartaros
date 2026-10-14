#!/bin/sh
# Reproduce the TartarOS verification scorecard on THIS host, in one command.
# Builds the workspace, runs the unit/integration tests, the conformance corpus
# against the real OS backend (Landlock on Linux, Seatbelt on macOS), and the
# mutation check (every removable protection must flip a scenario). Prints the
# environment + host-capability stamp so the README's conformance numbers are
# auditable, not just claimed. Exits non-zero on ANY failure.
#
#   ./scripts/verify.sh
#
# On a Linux host with Landlock + cgroup v2 + user namespaces this exercises the
# full corpus; on macOS it runs the cross-platform subset (the rest report SKIPPED).
# For a release-gating run that must certify the whole Linux corpus, add:
#   ./scripts/verify.sh --require-caps landlock,cgroup,userns
set -eu

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

echo "== build (workspace) =="
cargo build --workspace

echo "== unit + integration tests (workspace) =="
cargo test --workspace

echo "== conformance corpus (real OS backend) =="
cargo run -q -p tartaros-bench -- security-bench/corpus "$@"

echo "== mutation check (the corpus must catch a removed protection) =="
cargo run -q -p tartaros-bench -- security-bench/corpus --mutate

echo
echo "verify: OK — build, tests, conformance corpus and mutation all passed on this host."
