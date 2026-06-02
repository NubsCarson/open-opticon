#!/usr/bin/env bash
#
# PSA attestation-token (EAT) verification, end-to-end (no hardware): runs the
# advertised `he-attest-verify` CLI against a committed, deterministic PSA token
# fixture (test/fixtures/psa_token.json — a faithful COSE_Sign1 over PSA claims,
# minted with an obviously-FAKE 0x11.. key). Confirms the happy path and the four
# rejections: wrong nonce, wrong pinned key, missing reference measurement, and a
# tampered token. This is the offline subset of a Veraison appraisal (signature +
# profile + freshness + reference measurements); the full appraisal is the rig step.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$ROOT/src/verifier"
F="$ROOT/test/fixtures/psa_token.json"
W="$(mktemp -d /tmp/he-eat.XXXXXX)"
pass=0; fail=0
ok()  { printf '  \033[1;32mok\033[0m:   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m: %s\n' "$1"; fail=$((fail+1)); }
trap 'rm -rf "$W"' EXIT

echo "== build =="
( cd "$V" && GOPROXY=off go build -o "$W/he-attest-verify" ./cmd/he-attest-verify ) || { echo "go build failed"; exit 1; }
get() { python3 -c "import json;print(json.load(open('$F'))['$1'])"; }
TOKEN=$(get token); PINX=$(get pin_x); PINY=$(get pin_y); NONCE=$(get nonce); REF=$(get ref)
[ -n "$TOKEN" ] && ok "loaded the committed PSA token fixture" || { bad "fixture missing"; exit 1; }

echo
echo "== happy path: signature + profile + freshness + reference measurement =="
if "$W/he-attest-verify" --token "$TOKEN" --pin-x "$PINX" --pin-y "$PINY" --nonce "$NONCE" --ref "$REF" >/dev/null 2>&1; then
  ok "valid PSA token verifies under the pinned attestation key"
else
  bad "genuine PSA token rejected"
fi

echo
echo "== negatives (each must fail) =="
"$W/he-attest-verify" --token "$TOKEN" --pin-x "$PINX" --pin-y "$PINY" --nonce "deadbeefdeadbeef" --ref "$REF" >/dev/null 2>&1 \
  && bad "wrong nonce accepted" || ok "wrong freshness nonce rejected"
"$W/he-attest-verify" --token "$TOKEN" --pin-x "$PINY" --pin-y "$PINX" --nonce "$NONCE" --ref "$REF" >/dev/null 2>&1 \
  && bad "wrong pinned key accepted" || ok "wrong pinned attestation key rejected"
# A reference set that does NOT contain the token's measurement must reject (an
# empty --ref means "don't appraise measurements" by design, so use a WRONG ref).
"$W/he-attest-verify" --token "$TOKEN" --pin-x "$PINX" --pin-y "$PINY" --nonce "$NONCE" --ref "$(printf '00%.0s' $(seq 32))" >/dev/null 2>&1 \
  && bad "measurement not in the reference set accepted" || ok "measurement not in the reference set rejected"
# Flip a byte in the token's signature -> COSE verify fails.
BADTOK="${TOKEN%??}00"; [ "$BADTOK" = "$TOKEN" ] && BADTOK="${TOKEN%??}11"
"$W/he-attest-verify" --token "$BADTOK" --pin-x "$PINX" --pin-y "$PINY" --nonce "$NONCE" --ref "$REF" >/dev/null 2>&1 \
  && bad "tampered token accepted" || ok "tampered token rejected"

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
