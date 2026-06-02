#!/usr/bin/env bash
#
# Operating witnesses, end-to-end with the real binaries: a log operator (he-logd)
# serves signed checkpoints + consistency proofs; independent witnesses
# (he-witness) poll it, verify each checkpoint is a consistent append-only
# extension, and cosign only if so; the verifier (he-log cosign-verify) then
# requires a THRESHOLD of enrolled witness cosignatures. Finally the log is FORKED
# and the same witnesses, holding their persisted state, REFUSE to cosign the
# divergent history — anti-equivocation, demonstrated. Pure host; no hardware.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$ROOT/src/verifier"
W="$(mktemp -d /tmp/he-witness.XXXXXX)"
PORT="${HE_WITNESS_PORT:-8771}"
URL="http://127.0.0.1:$PORT"
ORIGIN="honest-ear.log/v1"
LOG="$W/log.json"
LOGD_PID=""
W2D_PID=""
W1D_PID=""
LOGDF_PID=""
W2F_PID=""
W1F_PID=""
pass=0; fail=0
ok()  { printf '  \033[1;32mok\033[0m:   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m: %s\n' "$1"; fail=$((fail+1)); }
cleanup() {
  [ -n "$LOGD_PID" ] && kill "$LOGD_PID" 2>/dev/null
  [ -n "$W2D_PID" ] && kill "$W2D_PID" 2>/dev/null
  [ -n "$W1D_PID" ] && kill "$W1D_PID" 2>/dev/null
  [ -n "$LOGDF_PID" ] && kill "$LOGDF_PID" 2>/dev/null
  [ -n "$W2F_PID" ] && kill "$W2F_PID" 2>/dev/null
  [ -n "$W1F_PID" ] && kill "$W1F_PID" 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT

echo "== build =="
( cd "$V" && GOPROXY=off go build -o "$W/he-log" ./cmd/he-log \
    && GOPROXY=off go build -o "$W/he-logd" ./cmd/he-logd \
    && GOPROXY=off go build -o "$W/he-witness" ./cmd/he-witness ) \
  || { echo "go build failed"; exit 1; }
echo "  built he-log, he-logd, he-witness"

# genkey -> last field of each line is the hex (priv / pub_x / pub_y).
gk() { "$W/he-log" genkey; }
LOGK=$(gk); LOG_PRIV=$(echo "$LOGK" | awk 'NR==1{print $NF}')
LOG_X=$(echo "$LOGK" | awk 'NR==2{print $NF}'); LOG_Y=$(echo "$LOGK" | awk 'NR==3{print $NF}')
for n in 1 2 3; do
  k=$(gk)
  eval "W${n}_PRIV=$(echo "$k" | awk 'NR==1{print $NF}')"
  eval "W${n}_X=$(echo "$k" | awk 'NR==2{print $NF}')"
  eval "W${n}_Y=$(echo "$k" | awk 'NR==3{print $NF}')"
done

echo
echo "== an honest log: 3 entries, served by he-logd =="
for e in 11aa22bb 33cc44dd 55ee66ff; do "$W/he-log" add --log "$LOG" "$e" >/dev/null; done
"$W/he-logd" --addr "127.0.0.1:$PORT" --log "$LOG" --key "$LOG_PRIV" --origin "$ORIGIN" >/dev/null 2>&1 &
LOGD_PID=$!
ready=""
for _ in $(seq 1 100); do
  curl -fsS "$URL/checkpoint" >/dev/null 2>&1 && { ready=1; break; }
  sleep 0.1
done
[ -n "$ready" ] && ok "he-logd is serving checkpoints" || { bad "he-logd never came up"; echo "== summary: $pass passed, $fail failed =="; exit 1; }

# Each witness polls + cosigns the current checkpoint (persisting its state).
wcheck() { # $1 = witness index
  local n="$1" privv xv yv
  eval "privv=\$W${n}_PRIV xv=\$W${n}_X yv=\$W${n}_Y"
  "$W/he-witness" check --name "w$n" --key "$privv" --log-url "$URL" \
    --log-pub-x "$LOG_X" --log-pub-y "$LOG_Y" --origin "$ORIGIN" --state "$W/w$n.json"
}
got=0
for n in 1 2 3; do
  if wcheck "$n" > "$W/cosig$n.json" 2>/dev/null; then got=$((got+1)); fi
done
[ "$got" -eq 3 ] && ok "all 3 witnesses cosigned the consistent checkpoint" || bad "only $got/3 witnesses cosigned"

# Assemble the cosignatures and the signed checkpoint body.
python3 -c "import json,sys; json.dump([json.load(open(f)) for f in sys.argv[1:]], open('$W/cosigs.json','w'))" \
  "$W/cosig1.json" "$W/cosig2.json" "$W/cosig3.json"
curl -fsS "$URL/checkpoint" | python3 -c "import sys,json; sys.stdout.write(json.load(sys.stdin)['body'])" > "$W/body.txt"

echo
echo "== verifier requires a 2-of-3 witness quorum =="
if "$W/he-log" cosign-verify --checkpoint "$W/body.txt" --cosigs "$W/cosigs.json" \
     --enrolled "w1:$W1_X:$W1_Y" --enrolled "w2:$W2_X:$W2_Y" --enrolled "w3:$W3_X:$W3_Y" \
     --witness-threshold 2 >/dev/null 2>&1; then
  ok "2-of-3 enrolled witness cosignatures verify"
else
  bad "threshold cosign-verify failed on honest log"
fi

echo
echo "== witness-to-witness cross-check (anti-equivocation) =="
# Run w2 as a serve daemon watching the SAME honest log, then have w1 cross-check
# the peer's published cosignature against w1's own view.
PORT2=$((PORT + 1))
URL2="http://127.0.0.1:$PORT2"
"$W/he-witness" serve --addr "127.0.0.1:$PORT2" --name w2 --key "$W2_PRIV" \
  --log-url "$URL" --log-pub-x "$LOG_X" --log-pub-y "$LOG_Y" --origin "$ORIGIN" \
  --state "$W/w2serve.json" --poll 1 >/dev/null 2>&1 &
W2D_PID=$!
ready=""
for _ in $(seq 1 100); do
  curl -fsS "$URL2/cosignature" >/dev/null 2>&1 && { ready=1; break; }
  sleep 0.1
done
[ -n "$ready" ] && ok "peer witness w2 is serving its cosignature" || bad "w2 daemon never came up"

cmp_peer() { # extra args -> run compare from w1's view against w2
  "$W/he-witness" compare --peer-url "$URL2" --peer-name w2 \
    --peer-pub-x "$W2_X" --peer-pub-y "$W2_Y" --origin "$ORIGIN" "$@"
}
if cmp_peer --state "$W/w1.json" >/dev/null 2>&1; then
  ok "w1 cross-check AGREES with peer w2 (same root, same size)"
else
  bad "honest peers disagreed in cross-check"
fi

# Wrong pinned peer key (w3's key, not w2's) -> the cosignature must not verify.
if "$W/he-witness" compare --peer-url "$URL2" --peer-name w2 \
     --peer-pub-x "$W3_X" --peer-pub-y "$W3_Y" --origin "$ORIGIN" --state "$W/w1.json" >/dev/null 2>&1; then
  bad "cross-check accepted the peer under a wrong pinned key"
else
  ok "cross-check rejects the peer under a wrong pinned key"
fi

# EQUIVOCATION: a view holding a DIFFERENT root at the same size as w2 -> detected.
python3 -c "import json; json.dump({'origin':'$ORIGIN','size':3,'root':'aa'*32}, open('$W/wfork.json','w'))"
if cmp_peer --state "$W/wfork.json" >/dev/null 2>&1; then
  bad "cross-check missed an equivocation (divergent root at same size)"
else
  ok "cross-check detects equivocation (divergent root at same size)"
fi

# Continuous cross-check IN the daemon: start w1 as a serve daemon with w2 as a
# pinned --peer; its /health must report the peer agreeing, no equivocation.
PORT3=$((PORT + 2))
"$W/he-witness" serve --addr "127.0.0.1:$PORT3" --name w1 --key "$W1_PRIV" \
  --log-url "$URL" --log-pub-x "$LOG_X" --log-pub-y "$LOG_Y" --origin "$ORIGIN" \
  --state "$W/w1serve.json" --poll 1 \
  --peer "w2,$URL2,$W2_X,$W2_Y" >/dev/null 2>&1 &
W1D_PID=$!
hready=""
for _ in $(seq 1 100); do curl -fsS "http://127.0.0.1:$PORT3/health" >/dev/null 2>&1 && { hready=1; break; }; sleep 0.1; done
H=$(curl -fsS "http://127.0.0.1:$PORT3/health" 2>/dev/null)
if [ -n "$hready" ] && echo "$H" | python3 -c "import sys,json;d=json.load(sys.stdin);import re;assert d.get('equivocation_detected') is False;assert 'agree' in d.get('peers',{}).get('w2','')" 2>/dev/null; then
  ok "serve daemon continuously cross-checks the pinned peer (/health: w2 agree, no equivocation)"
else
  bad "daemon peer cross-check /health did not report peer agreement"
fi
kill "$W1D_PID" 2>/dev/null; W1D_PID=""
kill "$W2D_PID" 2>/dev/null; W2D_PID=""

echo
echo "== split view: a TRANSFERABLE equivocation proof =="
# The SAME operator key serves a DIFFERENT root at the same size to a different
# witness. A forked log (size 3, divergent final leaf) signed by the SAME log key on
# a 2nd he-logd; w2 watches IT, w1 watches the honest log and pins w2. w1's daemon
# detects the same-size split and assembles a proof anyone can verify OFFLINE.
LOGF="$W/forklog.json"
for e in 11aa22bb 33cc44dd deadbeef; do "$W/he-log" add --log "$LOGF" "$e" >/dev/null; done
PORT4=$((PORT + 3)); URL4="http://127.0.0.1:$PORT4"
"$W/he-logd" --addr "127.0.0.1:$PORT4" --log "$LOGF" --key "$LOG_PRIV" --origin "$ORIGIN" >/dev/null 2>&1 &
LOGDF_PID=$!
for _ in $(seq 1 100); do curl -fsS "$URL4/checkpoint" >/dev/null 2>&1 && break; sleep 0.1; done

PORT6=$((PORT + 5)); URL6="http://127.0.0.1:$PORT6"
"$W/he-witness" serve --addr "127.0.0.1:$PORT6" --name w2 --key "$W2_PRIV" \
  --log-url "$URL4" --log-pub-x "$LOG_X" --log-pub-y "$LOG_Y" --origin "$ORIGIN" \
  --state "$W/w2fork.json" --poll 1 >/dev/null 2>&1 &
W2F_PID=$!
for _ in $(seq 1 100); do curl -fsS "$URL6/cosignature" >/dev/null 2>&1 && break; sleep 0.1; done

PORT5=$((PORT + 4)); URL5="http://127.0.0.1:$PORT5"
"$W/he-witness" serve --addr "127.0.0.1:$PORT5" --name w1 --key "$W1_PRIV" \
  --log-url "$URL" --log-pub-x "$LOG_X" --log-pub-y "$LOG_Y" --origin "$ORIGIN" \
  --state "$W/w1fork.json" --poll 1 --peer "w2,$URL6,$W2_X,$W2_Y" >/dev/null 2>&1 &
W1F_PID=$!
proof=""
for _ in $(seq 1 100); do
  if curl -fsS "$URL5/equivocation-proof" -o "$W/proof.json" 2>/dev/null \
     && python3 -c "import json;exit(0 if json.load(open('$W/proof.json')).get('schema') else 1)" 2>/dev/null; then proof=1; break; fi
  sleep 0.1
done
[ -n "$proof" ] && ok "w1 daemon served a transferable equivocation proof at /equivocation-proof" \
  || bad "no equivocation proof was served"

# Anyone verifies it OFFLINE under the two PINNED witness keys (no trust in w1).
if [ -n "$proof" ] && "$W/he-witness" verify-equivocation --file "$W/proof.json" \
     --a-pub-x "$W1_X" --a-pub-y "$W1_Y" --b-pub-x "$W2_X" --b-pub-y "$W2_Y" >/dev/null 2>&1; then
  ok "the proof verifies under the two pinned witness keys (log convicted of equivocating)"
else
  bad "the equivocation proof did not verify under the pinned keys"
fi
# A WRONG pinned key must NOT verify (a producer can't substitute a key it controls).
if [ -n "$proof" ] && "$W/he-witness" verify-equivocation --file "$W/proof.json" \
     --a-pub-x "$W3_X" --a-pub-y "$W3_Y" --b-pub-x "$W2_X" --b-pub-y "$W2_Y" >/dev/null 2>&1; then
  bad "the proof verified under a WRONG pinned key"
else
  ok "the proof rejects a wrong pinned key"
fi
kill "$W1F_PID" 2>/dev/null; W1F_PID=""
kill "$W2F_PID" 2>/dev/null; W2F_PID=""
kill "$LOGDF_PID" 2>/dev/null; LOGDF_PID=""

echo
echo "== the log FORKS: witnesses refuse the divergent history =="
# Same size (3) but a different final leaf -> not an append-only extension of
# what the witnesses already cosigned. he-logd re-reads the file each request.
python3 -c "import json; json.dump({'leaves':['11aa22bb','33cc44dd','deadbeef']}, open('$LOG','w'))"
refused=0
for n in 1 2 3; do
  if wcheck "$n" >/dev/null 2>&1; then :; else refused=$((refused+1)); fi
done
[ "$refused" -eq 3 ] && ok "all 3 witnesses REFUSED to cosign the forked log" || bad "only $refused/3 witnesses refused the fork"

# And a rewind (shorter log) is refused too.
python3 -c "import json; json.dump({'leaves':['11aa22bb']}, open('$LOG','w'))"
if wcheck 1 >/dev/null 2>&1; then bad "witness accepted a rewound log"; else ok "rewound log refused"; fi

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
