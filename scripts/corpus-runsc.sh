#!/bin/bash
# Run the M-µ1-applicable security-bench corpus under runsc (gVisor), one scripted
# bundle per scenario, with the SAME real-effect assertions the shared-kernel
# backends are scored on. The guest is a non-root uid (the gVisor-native `Direct`
# form, see docs/microvm-backend.md). Scenarios that need the broker, VM-size
# resource caps or servers are M-µ2 work: listed as DEFERRED, not run.
#
#   sudo ./scripts/corpus-runsc.sh
#
# Requirements (Linux host, as root): runsc on PATH, docker (to build the example
# in a rust image and to export a busybox rootfs), setpriv/useradd. It creates a
# throwaway user `tartuser` (uid 2000) and removes it on exit.
# Exits non-zero if any scenario is a VIOLATION or breaks its control.
set +e

H="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CORP=$H/security-bench/corpus
RUNSC="runsc --platform=systrap --network=none --ignore-cgroups"
BUNDLE=/tmp/bundle          # corpus_runsc emits root.path=/tmp/bundle/rootfs
BASE=/tmp/cx
GUEST_UID=2000

[ "$(id -u)" -eq 0 ] || { echo "run as root (runsc + chown of the guest workspaces)"; exit 2; }
command -v runsc >/dev/null || { echo "runsc not found on PATH"; exit 2; }

echo "=== build corpus_runsc ==="
docker run --rm -v "$H":/src -w /src rust:1-bookworm \
  cargo build -q -p tartaros-microvm --example corpus_runsc 2>&1 | tail -2
cp "$H"/target/debug/examples/corpus_runsc /tmp/corpus_runsc || exit 2
chmod 755 /tmp/corpus_runsc

if [ ! -d $BUNDLE/rootfs/bin ]; then
  echo "=== bundle: busybox rootfs ==="
  mkdir -p $BUNDLE/rootfs
  cid=$(docker create busybox:latest) || exit 2
  docker export "$cid" | tar -C $BUNDLE/rootfs -xf - 2>/dev/null
  docker rm "$cid" >/dev/null
fi

cleanup () {
  rm -rf $BASE /tmp/aout /tmp/cout /tmp/acfg.json
  userdel tartuser 2>/dev/null
}
trap cleanup EXIT

id tartuser >/dev/null 2>&1 || useradd -u $GUEST_UID -M -s /bin/false tartuser
# The corpus TOML may live under /root (0700, unreadable by the guest uid). Run the
# emitter as root targeting a non-root guest via TARTAROS_UID, and chown each
# workspace to it.
export TARTAROS_UID=$GUEST_UID TARTAROS_GID=$GUEST_UID
rm -rf $BASE; mkdir -p $BASE

APPLICABLE="fs-write-outside write-deny-inside-writable secret-read-deny secret-inside-writable \
read-allow-deny-nested read-allow-inside-deny read-deny-wins-exact-tie read-deny-proc-magic-symlink \
read-deny-symlink-bypass fs-symlink-escape fs-hardlink-escape trust-handoff-claude-commands \
trust-handoff-mcp-json trust-handoff-nested-git trust-handoff-rename-over-hook trust-handoff-submodule-hook \
trust-handoff-ancestor-rename root-mknod-device-denied env-secret-scrub isolate-pid-namespace"

RESIDUAL="handoff-materialize-absent"
DEFERRED="broker-credential egress-udp-raw-denied isolate-net-egress net-unauthorized-port \
resource-cpu resource-memory resource-procs ipc-unix-socket seccomp-hardening lifecycle-timeout \
lifecycle-daemon-escape"

pass=0; fail=0; ctlbreak=0; missing=0
printf "%-34s %-7s %-7s %s\n" SCENARIO ATTACK CONTROL VERDICT
for id in $APPLICABLE; do
  t=$CORP/$id.toml
  [ -f "$t" ] || { echo "$id  (MISSING TOML)"; missing=$((missing+1)); continue; }
  R=$BASE/$id
  rm -rf "$R"; /tmp/corpus_runsc "$t" "$R" fixtures
  chown -R $GUEST_UID:$GUEST_UID "$R"    # the guest owns its workspace
  # snapshot 'unchanged' baselines
  mapfile -t ASSERTS < <(/tmp/corpus_runsc "$t" "$R" assert)
  unset SHA0; declare -A SHA0
  for a in "${ASSERTS[@]}"; do
    k=${a%%$'\t'*}; p=${a#*$'\t'}
    [ "$k" = unchanged ] && SHA0["$p"]=$(sha256sum "$p" 2>/dev/null | cut -d' ' -f1)
  done
  # attack
  /tmp/corpus_runsc "$t" "$R" config attack > $BUNDLE/config.json
  cp $BUNDLE/config.json /tmp/acfg.json
  ( cd $BUNDLE && env AWS_SECRET_ACCESS_KEY=leak-me-if-you-can $RUNSC run cx-$id ) >/tmp/aout 2>&1; aexit=$?
  $RUNSC delete cx-$id 2>/dev/null
  # control
  /tmp/corpus_runsc "$t" "$R" config control > $BUNDLE/config.json
  ( cd $BUNDLE && $RUNSC run cc-$id ) >/tmp/cout 2>&1; cexit=$?
  $RUNSC delete cc-$id 2>/dev/null
  # evaluate asserts
  ok_assert=1
  for a in "${ASSERTS[@]}"; do
    k=${a%%$'\t'*}; p=${a#*$'\t'}
    case "$k" in
      absent)    [ -e "$p" ] && ok_assert=0 ;;
      present)   [ -e "$p" ] || ok_assert=0 ;;
      unchanged) [ "$(sha256sum "$p" 2>/dev/null | cut -d' ' -f1)" = "${SHA0[$p]}" ] || ok_assert=0 ;;
    esac
  done
  # Real-effect scoring (the corpus philosophy): an attack is a VIOLATION if it
  # leaked a secret sentinel, broke an effect assertion, or genuinely succeeded
  # (exit 0) WITHOUT a benign excuse. The one benign excuse is a masked secret FILE
  # (bind of /dev/null): the read exits 0 but returns EMPTY — no leak — so exit 0 is
  # not success there; we rely on the sentinel check instead.
  leaked=0; grep -qE 'TOPSECRET|leak-me-if-you-can' /tmp/aout && leaked=1
  maskfile=0; grep -q '"/dev/null"' /tmp/acfg.json && maskfile=1
  cv="ok"; [ $cexit -ne 0 ] && cv="BROKE"
  if [ $leaked -eq 1 ]; then av="LEAK!"; else av="blocked"; fi
  [ $aexit -eq 0 ] && [ $maskfile -eq 0 ] && [ $leaked -eq 0 ] && av="RAN!"
  verdict="PASS"
  if [ $leaked -eq 1 ] || [ $ok_assert -ne 1 ] || { [ $aexit -eq 0 ] && [ $maskfile -eq 0 ]; }; then
    verdict="VIOLATION"; fail=$((fail+1))
  elif [ $cexit -ne 0 ]; then verdict="control-broke"; ctlbreak=$((ctlbreak+1))
  else pass=$((pass+1)); fi
  printf "%-34s %-7s %-7s %s\n" "$id" "$av" "$cv" "$verdict"
done
echo
echo "M-µ1-applicable: PASS=$pass VIOLATION=$fail control-broke=$ctlbreak missing=$missing (of $(echo $APPLICABLE | wc -w))"
echo "known residual (future-handoff): $RESIDUAL"
echo "DEFERRED to M-µ2 (broker / VM-size caps / servers): $(echo $DEFERRED | wc -w) scenarios"
[ $fail -eq 0 ] && [ $ctlbreak -eq 0 ] && [ $missing -eq 0 ]
