#!/usr/bin/env bash
# Reproduce the nono side of the comparison on a Landlock host (not the dev Mac).
# Downloads nono 0.79, runs the 3 scenarios with idiomatic configs. the harness side
# is the security-bench corpus (all PASS). Keep "outside" paths OUT of /tmp (nono
# allows /tmp by default) so the comparison is fair.
set -e
D=$(mktemp -d /root/nono-cmp.XXXX); cd "$D"
curl -sL -o nono.tgz https://github.com/nolabs-ai/nono/releases/download/v0.79.0/nono-v0.79.0-x86_64-unknown-linux-gnu.tar.gz
tar xzf nono.tgz && chmod +x nono
mkdir -p "$D/work"
echo "1. write-outside:"; ./nono run --allow "$D/work" --block-net -- sh -c "echo EVIL > $D/outside" >/dev/null 2>&1; [ -f "$D/outside" ] && echo "   wrote outside" || echo "   blocked"
mkdir -p "$D/work/nested/.git/hooks"
echo "2. nested .git/hooks:"; ./nono run --allow "$D/work" --block-net -- sh -c "echo x > $D/work/nested/.git/hooks/pre-commit" >/dev/null 2>&1; [ -f "$D/work/nested/.git/hooks/pre-commit" ] && echo "   hook planted (allowed)" || echo "   blocked"
rm -rf "$D"
