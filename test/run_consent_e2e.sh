#!/usr/bin/env bash
#
# Track-6 consent mechanisms end-to-end (no hardware): exercises he-consent, which
# wraps the threshold-reveal + consent-gated-disclosure primitives in threshold.go.
#
#   - k-of-n THRESHOLD reveal: a full record is sealed; k shares reveal it, k-1
#     cannot (group agreement, enforced by math).
#   - CONSENT-GATED disclosure: one window of a logged predicate stream is revealed
#     with a Merkle inclusion proof under a trusted root; the other windows stay
#     hidden, and a tampered disclosure is rejected.
#
# HONEST SCOPE: mechanisms, not a solution to the joint-data conflicting-wishes
# problem; share custody + key lifecycle are operational policy, not enforced here.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$ROOT/src/verifier"
W="$(mktemp -d /tmp/he-consent-e2e.XXXXXX)"
pass=0; fail=0
ok()  { printf '  \033[1;32mok\033[0m:   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m: %s\n' "$1"; fail=$((fail+1)); }
trap 'rm -rf "$W"' EXIT

echo "== build =="
( cd "$V" && GOPROXY=off go build -o "$W/he-consent" ./cmd/he-consent ) || { echo "go build failed"; exit 1; }
echo "  built he-consent"

echo
echo "== k-of-n threshold reveal (group agreement) =="
printf 'FULL RECORD: the complete predicate stream + raw references' > "$W/record.txt"
"$W/he-consent" seal --in "$W/record.txt" --k 2 --n 3 --out-dir "$W/sealed" >/dev/null 2>&1
[ -s "$W/sealed/sealed.json" ] && [ -s "$W/sealed/share-1.json" ] && ok "sealed 2-of-3" || bad "seal"

got=$("$W/he-consent" reveal --sealed "$W/sealed/sealed.json" \
  --share "$W/sealed/share-1.json" --share "$W/sealed/share-3.json" 2>/dev/null)
[ "$got" = "FULL RECORD: the complete predicate stream + raw references" ] \
  && ok "2 shares reveal the exact record" || bad "k-share reveal mismatch"

if "$W/he-consent" reveal --sealed "$W/sealed/sealed.json" --share "$W/sealed/share-1.json" >/dev/null 2>&1; then
  bad "1 share revealed the record (threshold broken)"
else
  ok "1 share is refused (k-1 reveals nothing)"
fi

echo
echo "== consent-gated single-window disclosure =="
printf 'w0 presence=0 event=none\nw1 presence=1 event=alarm_tone\nw2 presence=1 event=voice\nw3 presence=0 event=none\n' > "$W/stream.txt"
"$W/he-consent" disclose --stream "$W/stream.txt" --index 1 > "$W/d.json" 2>/dev/null
ROOT=$(python3 -c "import json;print(json.load(open('$W/d.json'))['root'])")
[ -n "$ROOT" ] && ok "disclosed window 1 + inclusion proof under root ${ROOT:0:12}…" || bad "disclose"

if "$W/he-consent" verify-disclosure --disclosure "$W/d.json" --root "$ROOT" >/dev/null 2>&1; then
  ok "the disclosed window verifies under the trusted root"
else
  bad "honest disclosure did not verify"
fi

# Tamper the disclosed entry -> must fail under the same root (others stay hidden).
python3 -c "import json;d=json.load(open('$W/d.json'));d['entry']=d['entry'][:-2]+('00' if d['entry'][-2:]!='00' else '11');json.dump(d,open('$W/dbad.json','w'))"
if "$W/he-consent" verify-disclosure --disclosure "$W/dbad.json" --root "$ROOT" >/dev/null 2>&1; then
  bad "tampered disclosure accepted"
else
  ok "tampered disclosure rejected"
fi

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
