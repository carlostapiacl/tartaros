#!/usr/bin/env bash
# Automated fair comparison: run the same scenarios under tartaros (CLI),
# nono, and (if present) Anthropic sandbox-runtime (srt). Print who blocks what.
# Run on a Landlock host (NOT the dev Mac). Uses /root paths (not /tmp — nono/srt
# allow /tmp by default) so the comparison is fair.
set -u
SEISIN="${SEISIN:-/src/target/debug/seisin-sandbox}"
NONO="${NONO:-./nono}"
SRT="${SRT:-$(command -v srt || true)}"
HAVE_SRT=0; [ -n "$SRT" ] && command -v bwrap >/dev/null 2>&1 && HAVE_SRT=1
t=""

srt_settings() { # $1=work  $2=extra denyRead (optional)
  printf '{ "filesystem": {"allowWrite":["%s"],"denyWrite":[],"allowRead":[],"denyRead":[%s]}, "network":{"allowedDomains":[],"deniedDomains":[],"allowUnixSockets":[],"allowLocalBinding":false} }' "$1" "$2"
}

hdr="scenario                        | tartaros | nono 0.79"
[ $HAVE_SRT -eq 1 ] && hdr="$hdr   | srt 0.0.78"
echo "$hdr"
echo "--------------------------------+----------+--------------+-------------"

row() { local line; local t4="${4:-}"; line=$(printf "%-31s | %-8s | %-12s" "$1" "$2" "$3"); [ $HAVE_SRT -eq 1 ] && line="$line | $t4"; echo "$line"; }

# 1. write outside territory
B=/root/c1; rm -rf $B; mkdir -p $B/work
$SEISIN run --write $B/work -- sh -c "echo E > $B/outside" >/dev/null 2>&1; s=$([ -f $B/outside ] && echo ALLOWED || echo blocked); rm -f $B/outside
$NONO run --allow $B/work --block-net -- sh -c "echo E > $B/outside" >/dev/null 2>&1; n=$([ -f $B/outside ] && echo ALLOWED || echo blocked); rm -f $B/outside
if [ $HAVE_SRT -eq 1 ]; then srt_settings "$B/work" > $B/s.json; ( cd $B && "$SRT" --settings $B/s.json -- sh -c "echo E > $B/outside" ) >/dev/null 2>&1; t=$([ -f $B/outside ] && echo ALLOWED || echo blocked); rm -f $B/outside; fi
row "write-outside" "$s" "$n" "$t"

# 2. nested .git/hooks (trust-handoff) — srt protects via glob; nono does not
B=/root/c2; rm -rf $B; mkdir -p $B/work/nested/.git/hooks
H=$B/work/nested/.git/hooks/pre-commit
$SEISIN run --write $B/work -- sh -c "echo x > $H" >/dev/null 2>&1; s=$([ -f $H ] && echo ALLOWED || echo blocked); rm -f $H
$NONO run --allow $B/work --block-net -- sh -c "echo x > $H" >/dev/null 2>&1; n=$([ -f $H ] && echo ALLOWED || echo blocked); rm -f $H
if [ $HAVE_SRT -eq 1 ]; then srt_settings "$B/work" > $B/s.json; ( cd $B/work && "$SRT" --settings $B/s.json -- sh -c "echo x > $H" ) >/dev/null 2>&1; t=$([ -f $H ] && echo ALLOWED || echo blocked); rm -f $H; fi
row "nested .git/hooks" "$s" "$n" "$t"

# 3. secret read-deny inside writable
B=/root/c3; rm -rf $B; mkdir -p $B/work/.secrets; echo S > $B/work/.secrets/token
$SEISIN run --write $B/work --read-deny $B/work/.secrets -- sh -c "cat $B/work/.secrets/token" >/dev/null 2>&1; s=$([ $? -eq 0 ] && echo ALLOWED || echo blocked)
cat > $B/p.json <<JSON
{ "meta":{"name":"c","version":"1"},"workdir":{"access":"none"},"filesystem":{"allow":["$B/work"],"deny":[{"path":"$B/work/.secrets","access":"all"}]},"network":{"block":true} }
JSON
O=$($NONO run -c $B/p.json -- cat $B/work/.secrets/token 2>&1); echo "$O" | grep -q "^S$" && n=ALLOWED || { echo "$O" | grep -qi "restructure\|error\|parse" && n="can't-express" || n=blocked; }
if [ $HAVE_SRT -eq 1 ]; then srt_settings "$B/work" "\"$B/work/.secrets\"" > $B/s.json; ( cd $B/work && "$SRT" --settings $B/s.json -- cat $B/work/.secrets/token ) 2>/dev/null | grep -q "^S$" && t=ALLOWED || t=blocked; fi
row "secret read-deny (in writable)" "$s" "$n" "$t"

rm -rf /root/c1 /root/c2 /root/c3
