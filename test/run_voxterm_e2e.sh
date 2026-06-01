#!/usr/bin/env bash
#
# VoxTerm bridge / portable "restraint receipts" end-to-end (no hardware).
#
# Simulates a local-first transcription session (à la VoxTerm: audio in, only
# TEXT out, audio discarded). Each batch becomes a signed, hash-chained restraint
# receipt that commits {input_hash (processed-then-discarded), output_hash (the
# emitted text), retained=0, prev}. We then:
#   1. verify every receipt (signature + chain + not-retained),
#   2. feed the receipts as leaves into the transparency log (he-log) and prove a
#      batch is included under a SIGNED checkpoint — so the session's record is
#      append-only and anchorable with the existing machinery,
#   3. show a SUPPRESSED batch breaks the chain (gap detection), and a receipt
#      that admits retaining audio is rejected.
#
# This is the integration seam VoxTerm's `--hivemind-sink-url` already provides:
# point it at a receipt sink and a session becomes publicly verifiable. The
# signing key is a hardware-backed P-256 key in production (OP-TEE/CAAM on Arm,
# Secure Enclave on Apple, TPM on PC); here it's the host test key, like the rest
# of the PoC. HONEST SCOPE: this is accountability (tamper-evident, gap-free,
# signed input->output), not a hardware confidentiality proof — see docs/INTEGRATIONS.md.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$ROOT/src/verifier"
W="$(mktemp -d /tmp/he-voxterm.XXXXXX)"
ZERO="$(python3 -c 'print("0"*64)')"
pass=0; fail=0
ok()  { printf '  \033[1;32mok\033[0m:   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m: %s\n' "$1"; fail=$((fail+1)); }
trap 'rm -rf "$W"' EXIT

echo "== build =="
( cd "$V" && GOPROXY=off go build -o "$W/he-receipt" ./cmd/he-receipt \
    && GOPROXY=off go build -o "$W/he-log" ./cmd/he-log ) || { echo "go build failed"; exit 1; }
echo "  built he-receipt, he-log"

# Device key (P-256). Production: a Secure Enclave / TrustZone / TPM key.
K=$("$W/he-log" genkey)
PRIV=$(echo "$K" | awk 'NR==1{print $NF}')
PX=$(echo "$K" | awk 'NR==2{print $NF}'); PY=$(echo "$K" | awk 'NR==3{print $NF}')
LOG="$W/session.log.json"
SESSION="vox-$(python3 -c 'print(0xC0FFEE)')"

echo
echo "== a transcription session: 3 batches -> signed, chained restraint receipts =="
emit() { # $1 batch  $2 prev  -> echoes the new digest
  local n="$1" prev="$2"
  printf 'audio window %s (discarded after hashing)' "$n" > "$W/a$n.pcm"
  printf 'transcript text for batch %s' "$n" > "$W/t$n.txt"
  "$W/he-receipt" emit --session "$SESSION" --batch "$n" --audio "$W/a$n.pcm" \
      --text "$W/t$n.txt" --key "$PRIV" --prev "$prev" > "$W/r$n.json" 2>"$W/d$n.txt"
  awk '{print $2}' "$W/d$n.txt"
}
D1=$(emit 1 "$ZERO"); D2=$(emit 2 "$D1"); D3=$(emit 3 "$D2")
[ -n "$D1" ] && [ -n "$D2" ] && [ -n "$D3" ] && ok "emitted 3 chained receipts" || bad "receipt emission"

# Verify each receipt: signature + chain link + only-text-emitted.
verify_ok=0
"$W/he-receipt" verify --file "$W/r1.json" --expect-prev "$ZERO" --pin-x "$PX" --pin-y "$PY" --require-not-retained >/dev/null 2>&1 && verify_ok=$((verify_ok+1))
"$W/he-receipt" verify --file "$W/r2.json" --expect-prev "$D1" --require-not-retained >/dev/null 2>&1 && verify_ok=$((verify_ok+1))
"$W/he-receipt" verify --file "$W/r3.json" --expect-prev "$D2" --require-not-retained >/dev/null 2>&1 && verify_ok=$((verify_ok+1))
[ "$verify_ok" -eq 3 ] && ok "all 3 receipts verify (sig + chain + only-text-emitted)" || bad "only $verify_ok/3 receipts verified"

echo
echo "== the session record is an append-only transparency log =="
# Each receipt body becomes a log leaf; prove a batch is included under a SIGNED checkpoint.
for n in 1 2 3; do
  leaf=$(python3 -c "import json,sys;print(json.load(open('$W/r$n.json'))['body'].encode().hex())")
  "$W/he-log" add --log "$LOG" "$leaf" >/dev/null
done
"$W/he-log" prove --log "$LOG" --index 1 --key "$PRIV" > "$W/proof.json" 2>/dev/null
if "$W/he-log" verify --proof "$W/proof.json" >/dev/null 2>&1; then
  ok "batch 2's receipt is included under the log's signed checkpoint"
else
  bad "inclusion proof failed"
fi

echo
echo "== negatives: a suppressed batch breaks the chain; retained audio is rejected =="
# A monitor that recorded batch 1 expects batch 2 to chain from D1; show it to a
# receipt that chains from genesis instead (i.e. batch 1 was hidden) -> rejected.
if "$W/he-receipt" verify --file "$W/r2.json" --expect-prev "$ZERO" >/dev/null 2>&1; then
  bad "spliced (batch-1-suppressed) receipt accepted"
else
  ok "suppressed batch detected as a chain gap"
fi
# A receipt that ADMITS retaining the raw audio must fail --require-not-retained.
"$W/he-receipt" emit --session "$SESSION" --batch 9 --audio "$W/a1.pcm" --text "$W/t1.txt" \
    --key "$PRIV" --retained > "$W/r_ret.json" 2>/dev/null
if "$W/he-receipt" verify --file "$W/r_ret.json" --require-not-retained >/dev/null 2>&1; then
  bad "receipt admitting retained audio accepted under --require-not-retained"
else
  ok "receipt admitting retained audio rejected"
fi

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
