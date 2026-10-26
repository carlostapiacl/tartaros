#!/bin/sh
# Measures, on the host it runs on, whether a `--settings` run can create a new
# entry directly in a writable root that has a write deny below it, and what
# `explain --settings` says about it beforehand. It asserts nothing: it prints
# what happened, so the log of one run is the evidence.
#
# usage: probe-root-write.sh path/to/tartaros
set -u
BIN=${1:?usage: probe-root-write.sh path/to/tartaros}
ROOT=${PROBE_ROOT:-/tmp}
n=$$

echo "== host"
id
uname -r
cat /sys/kernel/security/lsm 2>/dev/null; echo
for k in kernel/apparmor_restrict_unprivileged_userns kernel/unprivileged_userns_clone user/max_user_namespaces; do
  printf '%s=%s\n' "$k" "$(cat /proc/sys/$k 2>/dev/null || echo -)"
done
unshare -U -m true 2>/dev/null && echo "unshare -U -m: ok" || echo "unshare -U -m: refused"

mkdir -p "$ROOT/claude" "$ROOT/probe-sub-$n"
dir=$(mktemp -d)

# name | denyWrite entries (JSON, without brackets)
cases="control|
existing-deny|\"$ROOT/claude\"
absent-below-only|\"$ROOT/absent-$n\"
existing+absent-below|\"$ROOT/claude\",\"$ROOT/absent-$n\"
existing+absent-elsewhere|\"$ROOT/claude\",\"$HOME/.absent-$n/x\"
absent-elsewhere-only|\"$HOME/.absent-$n/x\""

echo "$cases" | while IFS='|' read -r name denies; do
  f="$dir/$name.json"
  printf '{"filesystem":{"allowWrite":["%s"],"denyWrite":[%s]},"network":{"allowedDomains":[]}}\n' "$ROOT" "$denies" > "$f"
  echo
  echo "== case $name"
  cat "$f"
  "$BIN" explain --settings "$f" > "$dir/$name.explain" 2>&1
  echo "explain exit=$?"
  grep -E '^warning:|^--- Linux enforcement|^--- Linux Landlock' "$dir/$name.explain"
  sed -n '/^write (carved):/,/^read (carved):/p' "$dir/$name.explain" | head -20
  new="$ROOT/.probe-canary-$n-$name"
  sub="$ROOT/probe-sub-$n/f"
  "$BIN" run --settings "$f" -- /bin/sh -c "echo IN > '$new'; echo root-write-rc=\$?; echo IN > '$sub'; echo subdir-write-rc=\$?" 2>&1
  echo "run exit=$?"
  [ -f "$new" ] && echo "RESULT $name: new entry in $ROOT CREATED" || echo "RESULT $name: new entry in $ROOT NOT created"
  [ -f "$sub" ] && echo "RESULT $name: write in existing subdir OK" || echo "RESULT $name: write in existing subdir FAILED"
  rm -f "$new" "$sub"
done
