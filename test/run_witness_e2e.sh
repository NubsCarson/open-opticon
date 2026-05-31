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
pass=0; fail=0
ok()  { printf '  \033[1;32mok\033[0m:   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m: %s\n' "$1"; fail=$((fail+1)); }
cleanup() { [ -n "$LOGD_PID" ] && kill "$LOGD_PID" 2>/dev/null; rm -rf "$W"; }
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
