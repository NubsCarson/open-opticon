#!/usr/bin/env bash
#
# voxterm_demo.sh — a narrated, self-contained walkthrough of the restraint-receipt
# bridge (the credible-sensors Track-1/Track-6 hook for a local-first transcriber
# like VoxTerm: audio in, only TEXT out, audio discarded).
#
# It lives ENTIRELY in this repo — it does not touch or require the VoxTerm repo.
# It reuses the shipped `he-receipt` CLI verbatim. For a stable, readable demo it
# signs with a FIXED, OBVIOUSLY-FAKE key (32 bytes of 0x11); production uses a
# hardware-backed P-256 key (OP-TEE/CAAM on Arm, Secure Enclave on Apple, TPM on
# PC — the verifier is root-agnostic). The ECDSA signatures vary per run; the
# field values and PASS/FAIL outcomes shown below are deterministic.
#
# HONEST SCOPE: a restraint receipt is ACCOUNTABILITY — tamper-evident, gap-free,
# signed input->output, retained:0 — NOT a hardware confidentiality proof. "Which
# code actually ran / no covert copy" still needs firmware measurement (a TEE) or
# reproducible builds + open source. See docs/INTEGRATIONS.md.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$ROOT/src/verifier"
W="$(mktemp -d /tmp/he-voxterm-demo.XXXXXX)"
ZERO="$(python3 -c 'print("0"*64)')"
# An obviously-fake demo key. NEVER a real device/testnet key.
FAKE_KEY="$(python3 -c 'print("11"*32)')"
pass=0; fail=0
ok()  { printf '  \033[1;32mok\033[0m:   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m: %s\n' "$1"; fail=$((fail+1)); }
trap 'rm -rf "$W"' EXIT

echo "== build the verifier tools =="
( cd "$V" && GOPROXY=off go build -o "$W/he-receipt" ./cmd/he-receipt ) \
  || { echo "go build failed"; exit 1; }
echo "  built he-receipt (signing key = FAKE demo key 0x1111…, not a real key)"

SESSION="voxterm-demo"
echo
echo "== a transcription session: each batch emits a signed, chained restraint receipt =="
echo "   (the audio window is hashed then discarded; only the transcript text leaves)"
emit() { # $1 batch  $2 prev  -> echoes the new chain digest
  local n="$1" prev="$2"
  printf 'audio window %s — discarded after hashing' "$n" > "$W/a$n.pcm"
  printf 'transcript text for batch %s' "$n" > "$W/t$n.txt"
  "$W/he-receipt" emit --session "$SESSION" --batch "$n" --audio "$W/a$n.pcm" \
      --text "$W/t$n.txt" --key "$FAKE_KEY" --prev "$prev" > "$W/r$n.json" 2>"$W/d$n.txt"
  awk '{print $2}' "$W/d$n.txt"
}
D1=$(emit 1 "$ZERO"); D2=$(emit 2 "$D1"); D3=$(emit 3 "$D2")
if [ -n "$D1" ] && [ -n "$D2" ] && [ -n "$D3" ]; then
  ok "emitted 3 chained receipts (batch N's digest is batch N+1's prev)"
else
  bad "receipt emission"
fi
# The pinned device pubkey, read from the first receipt (any root works the same).
PX=$(python3 -c "import json;print(json.load(open('$W/r1.json'))['pub_x'])")
PY=$(python3 -c "import json;print(json.load(open('$W/r1.json'))['pub_y'])")

echo
echo "== verify the session: signature + hash-chain + retained:0 =="
v=0
"$W/he-receipt" verify --file "$W/r1.json" --expect-prev "$ZERO" --pin-x "$PX" --pin-y "$PY" --require-not-retained >/dev/null 2>&1 && v=$((v+1))
"$W/he-receipt" verify --file "$W/r2.json" --expect-prev "$D1" --pin-x "$PX" --pin-y "$PY" --require-not-retained >/dev/null 2>&1 && v=$((v+1))
"$W/he-receipt" verify --file "$W/r3.json" --expect-prev "$D2" --pin-x "$PX" --pin-y "$PY" --require-not-retained >/dev/null 2>&1 && v=$((v+1))
[ "$v" -eq 3 ] && ok "all 3 receipts verify (signed by the pinned key, chained, retained:0)" || bad "only $v/3 verified"

echo
echo "== negative 1: a suppressed batch is a detectable chain gap =="
# A monitor that saw batch 1 expects batch 2 to chain from D1; offer it a receipt
# that chains from genesis instead (i.e. batch 1 was hidden) -> rejected.
if "$W/he-receipt" verify --file "$W/r2.json" --expect-prev "$ZERO" >/dev/null 2>&1; then
  bad "suppressed-batch (spliced) receipt accepted"
else
  ok "suppressed batch detected (chain link does not match)"
fi

echo
echo "== negative 2: a tampered receipt is rejected =="
# Flip one hex char of the output_hash inside the signed body -> the P-256
# signature over the body no longer matches. The canonical ReceiptBody is seven
# newline-delimited value lines (origin, session, batch, input_hash, output_hash,
# retained, prev_digest); output_hash is line index 4.
python3 - "$W/r3.json" "$W/r3_tampered.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
lines = r["body"].split("\n")
oh = lines[4]                       # the output_hash hex value
lines[4] = oh[:-1] + ("0" if oh[-1] != "0" else "1")  # flip its last hex digit
r["body"] = "\n".join(lines)
json.dump(r, open(sys.argv[2], "w"))
PY
if "$W/he-receipt" verify --file "$W/r3_tampered.json" >/dev/null 2>&1; then
  bad "tampered receipt accepted"
else
  ok "tampered receipt rejected (signature no longer matches the body)"
fi

echo
echo "== negative 3: a receipt that ADMITS retaining audio fails --require-not-retained =="
"$W/he-receipt" emit --session "$SESSION" --batch 9 --audio "$W/a1.pcm" --text "$W/t1.txt" \
    --key "$FAKE_KEY" --retained > "$W/r_ret.json" 2>/dev/null
if "$W/he-receipt" verify --file "$W/r_ret.json" --require-not-retained >/dev/null 2>&1; then
  bad "receipt admitting retained audio accepted"
else
  ok "receipt admitting retained audio rejected"
fi

echo
echo "== what these receipts prove (the receipt-path answer to the 5 questions) =="
cat <<'TXT'
  1 what was captured : audio per batch, hashed (input_hash) then DISCARDED;
                        only the transcript text is emitted (output_hash).
  2 where it goes     : nowhere as audio — each receipt binds input_hash ->
                        output_hash; there is no audio field in the record.
  3 who can access it : no retained audio to access. integrity is enforced:
                        only the signing key can mint a valid receipt.
  4 how long kept     : retained:0, signed per batch. the chain (prev) makes the
                        session append-only, so a dropped batch is a visible gap.
  5 how it is used    : input->output accountability, signed and chainable into
                        the transparency log / on-chain anchor.

  HONEST SCOPE: accountability (tamper-evident, gap-free, signed input->output,
  retained:0) — NOT a hardware confidentiality proof. Which-code-ran / no-covert-
  copy still needs firmware measurement (a TEE) or reproducible builds. The seam
  is VoxTerm's existing --hivemind-sink-url; see docs/INTEGRATIONS.md.
TXT

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
