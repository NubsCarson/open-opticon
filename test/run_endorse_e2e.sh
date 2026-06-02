#!/usr/bin/env bash
#
# Signed endorsements, end-to-end (no hardware): an ENDORSER vouches for a device
# key by signing a canonical endorsement body; the SAME body is logged as a leaf;
# a verifier then confirms BOTH (a) the endorser genuinely signed it — `he-log
# endorse-verify` under the pinned endorser key — and (b) it is included in the
# log's signed checkpoint — `he-log verify`. This separates the endorser role
# (who vouched) from the log operator (who only appends).
#
# HONEST SCOPE: this is signed-endorsement-entry plumbing with stdlib P-256 (it
# reuses the project's one signing path). It is NOT the IETF-CoRIM/COSE wire
# format, and the endorser here is self-provisioned — a public manufacturer
# endorser root is future. The value today is the role separation + a checkable
# "who vouched for this key", not a new trust anchor.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$ROOT/src/verifier"
W="$(mktemp -d /tmp/he-endorse.XXXXXX)"
LOG="$W/log.json"
ORIGIN="honest-ear.log/v1"
pass=0; fail=0
ok()  { printf '  \033[1;32mok\033[0m:   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m: %s\n' "$1"; fail=$((fail+1)); }
trap 'rm -rf "$W"' EXIT

echo "== build =="
( cd "$V" && GOPROXY=off go build -o "$W/he-log" ./cmd/he-log ) || { echo "go build failed"; exit 1; }

gk() { "$W/he-log" genkey; }
EK=$(gk);  EPRIV=$(echo "$EK"|awk 'NR==1{print $NF}'); EX=$(echo "$EK"|awk 'NR==2{print $NF}'); EY=$(echo "$EK"|awk 'NR==3{print $NF}')
DK=$(gk);  DX=$(echo "$DK"|awk 'NR==2{print $NF}'); DY=$(echo "$DK"|awk 'NR==3{print $NF}')
LK=$(gk);  LPRIV=$(echo "$LK"|awk 'NR==1{print $NF}')

echo
echo "== endorser signs an endorsement for the device key =="
"$W/he-log" endorse --key "$EPRIV" --endorser "acme-provisioning" --device-x "$DX" --device-y "$DY" > "$W/end.json" 2>/dev/null
ENTRY=$(python3 -c "import json;print(json.load(open('$W/end.json'))['entry_hex'])")
[ -n "$ENTRY" ] && ok "signed endorsement produced" || bad "endorse produced no entry"

echo
echo "== the SAME signed body is logged + a checkpoint proves inclusion =="
"$W/he-log" add --log "$LOG" "$ENTRY" >/dev/null
"$W/he-log" prove --log "$LOG" --index 0 --key "$LPRIV" --origin "$ORIGIN" > "$W/proof.json" 2>/dev/null
if "$W/he-log" verify --proof "$W/proof.json" >/dev/null 2>&1; then
  ok "endorsement body is included under the signed checkpoint"
else
  bad "inclusion proof failed"
fi

echo
echo "== verifier confirms WHO vouched (endorser authenticity) =="
if "$W/he-log" endorse-verify --file "$W/end.json" --endorser-x "$EX" --endorser-y "$EY" >/dev/null 2>&1; then
  ok "endorser signature verifies under the pinned endorser key"
else
  bad "genuine endorser signature rejected"
fi

echo
echo "== negatives =="
# Wrong pinned endorser key (the device's key) must not verify.
if "$W/he-log" endorse-verify --file "$W/end.json" --endorser-x "$DX" --endorser-y "$DY" >/dev/null 2>&1; then
  bad "endorsement verified under a wrong endorser key"
else
  ok "wrong endorser key rejected"
fi
# Tamper the signed body (swap the device pub_x line) -> signature must break.
python3 -c "
import json
e = json.load(open('$W/end.json'))
lines = e['body'].split('\n')
lines[2] = ('0' if lines[2][:1] != '0' else '1') + lines[2][1:]  # corrupt device pub_x
e['body'] = '\n'.join(lines)
json.dump(e, open('$W/tampered.json','w'))
"
if "$W/he-log" endorse-verify --file "$W/tampered.json" --endorser-x "$EX" --endorser-y "$EY" >/dev/null 2>&1; then
  bad "tampered endorsement body verified"
else
  ok "tampered endorsement body rejected"
fi

echo
echo "== standards-aligned COSE_Sign1 endorsement (ES256) =="
"$W/he-log" endorse --cose --key "$EPRIV" --endorser "acme-provisioning" --device-x "$DX" --device-y "$DY" > "$W/cose.json" 2>/dev/null
HASCOSE=$(python3 -c "import json;print('1' if json.load(open('$W/cose.json')).get('cose') else '0')")
[ "$HASCOSE" = "1" ] && ok "COSE_Sign1 endorsement emitted" || bad "no cose field emitted"
if "$W/he-log" endorse-verify --cose --file "$W/cose.json" --endorser-x "$EX" --endorser-y "$EY" >/dev/null 2>&1; then
  ok "COSE endorsement verifies under the pinned endorser key"
else
  bad "genuine COSE endorsement rejected"
fi
if "$W/he-log" endorse-verify --cose --file "$W/cose.json" --endorser-x "$DX" --endorser-y "$DY" >/dev/null 2>&1; then
  bad "COSE endorsement verified under a wrong endorser key"
else
  ok "wrong endorser key rejected (COSE)"
fi

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
