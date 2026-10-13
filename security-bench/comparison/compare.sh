#!/usr/bin/env bash
# Automated fair comparison: run the same scenarios under seisin-sandbox (CLI) and
# nono, print who blocks what. Run on a Landlock host (NOT the dev Mac). Uses /root
# paths (not /tmp — nono allows /tmp by default) so the comparison is fair.
set -u
SEISIN="${SEISIN:-/src/target/debug/seisin-sandbox}"
NONO="${NONO:-./nono}"
res() { [ "$1" -eq 0 ] && echo "ALLOWED" || echo "blocked"; }  # effect-happened? 0=yes

row() { printf "%-28s | %-12s | %-12s\n" "$1" "$2" "$3"; }
echo "scenario                     | seisin       | nono 0.79"
echo "-----------------------------+--------------+-------------"

# 1. write outside territory
B=/root/c1; rm -rf $B; mkdir -p $B/work
$SEISIN run --write $B/work -- sh -c "echo E > $B/outside" >/dev/null 2>&1; s1=$([ -f $B/outside ] && echo ALLOWED || echo blocked); rm -f $B/outside
$NONO run --allow $B/work --block-net -- sh -c "echo E > $B/outside" >/dev/null 2>&1; n1=$([ -f $B/outside ] && echo ALLOWED || echo blocked)
row "write-outside" "$s1" "$n1"

# 2. nested .git/hooks (trust-handoff)
B=/root/c2; rm -rf $B; mkdir -p $B/work/nested/.git/hooks
$SEISIN run --write $B/work -- sh -c "echo x > $B/work/nested/.git/hooks/pre-commit" >/dev/null 2>&1; s2=$([ -f $B/work/nested/.git/hooks/pre-commit ] && echo ALLOWED || echo blocked); rm -f $B/work/nested/.git/hooks/pre-commit
$NONO run --allow $B/work --block-net -- sh -c "echo x > $B/work/nested/.git/hooks/pre-commit" >/dev/null 2>&1; n2=$([ -f $B/work/nested/.git/hooks/pre-commit ] && echo ALLOWED || echo blocked)
row "nested .git/hooks" "$s2" "$n2"

# 3. secret read-deny inside writable
B=/root/c3; rm -rf $B; mkdir -p $B/work/.secrets; echo S > $B/work/.secrets/token
$SEISIN run --write $B/work --read-deny $B/work/.secrets -- sh -c "cat $B/work/.secrets/token" >/dev/null 2>&1; s3=$([ $? -eq 0 ] && echo ALLOWED || echo blocked)
cat > $B/p.json <<JSON
{ "meta":{"name":"c","version":"1"},"workdir":{"access":"none"},"filesystem":{"allow":["$B/work"],"deny":[{"path":"$B/work/.secrets","access":"all"}]},"network":{"block":true} }
JSON
O=$($NONO run -c $B/p.json -- cat $B/work/.secrets/token 2>&1); echo "$O" | grep -q "^S$" && n3=ALLOWED || { echo "$O" | grep -qi "restructure\|error\|parse" && n3="can't-express" || n3=blocked; }
row "secret read-deny (in writable)" "$s3" "$n3"
rm -rf /root/c1 /root/c2 /root/c3
