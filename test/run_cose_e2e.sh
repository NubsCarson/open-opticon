#!/usr/bin/env bash
#
# COSE_Sign1 (RFC 9052) end-to-end: the host signer emits the standards-aligned
# COSE_Sign1 envelope (HE_COSE=1) using the SAME ECDSA-P256 test key and the
# SAME canonical he_payload inside — only the signed structure is the COSE
# Sig_structure instead of the bare payload. The stdlib-only Go verifier checks
# it via `he-verify --cose`, decodes the inner payload, and runs the identical
# gates. A tampered envelope and a stale nonce are rejected; the raw envelope
# still verifies (no regression). Pure host; no hardware.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$ROOT/test/fixtures"
CLIP="$FIX/alarm_short.pcm"
NONCE="cafef00dbaadf00d"
SIM="$ROOT/sim/bin/he-attest-sim"
HV=/tmp/he-verify-cose
pass=0; fail=0
ok()  { printf '  \033[1;32mok\033[0m:   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m: %s\n' "$1"; fail=$((fail+1)); }

echo "== build =="
make -C "$ROOT/sim" all >/dev/null || { echo "C build failed"; exit 1; }
( cd "$ROOT/src/verifier" && GOPROXY=off go build -o "$HV" ./cmd/he-verify ) \
    || { echo "go build failed"; exit 1; }
[ -f "$CLIP" ] || FIX="$FIX" python3 - <<'PY'
import math, os, struct
N = 256 * 12
s = [max(-32768, min(32767, int(8000 * math.sin(2 * math.pi * 3100 * i / 16000)))) for i in range(N)]  # amp 8000 == canonical clip
open(os.path.join(os.environ["FIX"], "alarm_short.pcm"), "wb").write(struct.pack("<%dh" % len(s), *s))
PY
echo "  built he-attest-sim, he-verify"
echo

echo "== COSE_Sign1 envelope: emit (C) -> verify (Go) =="
HE_COSE=1 "$SIM" "$CLIP" "$NONCE" 1 > /tmp/he-cose.json 2>/dev/null
schema=$(python3 -c "import json;print(json.load(open('/tmp/he-cose.json'))['schema'])")
[ "$schema" = "honest-ear/cose-sign1/v1" ] && ok "C emits a COSE_Sign1 bundle" || bad "expected cose schema, got $schema"
# The COSE message must start d2 84 43a10126 (tag18, array4, protected {1:-7}=ES256).
head=$(python3 -c "import json;print(json.load(open('/tmp/he-cose.json'))['cose'][:12])")
[ "$head" = "d28443a10126" ] && ok "COSE header is tag(18)+array(4)+ES256 protected" || bad "bad COSE header: $head"
if "$HV" --cose --nonce "$NONCE" /tmp/he-cose.json >/dev/null 2>&1; then
    ok "Go verifies the C-emitted COSE_Sign1 (sig over Sig_structure + gates)"
else
    bad "Go failed to verify the COSE bundle"
fi
echo

echo "== negative: binding holds for COSE too =="
if "$HV" --cose --nonce deadbeef /tmp/he-cose.json >/dev/null 2>&1; then
    bad "stale nonce accepted"
else
    ok "stale nonce rejected"
fi
# Flip one hex nibble inside the COSE message -> signature/decode must fail.
python3 - <<'PY'
import json
d = json.load(open('/tmp/he-cose.json'))
c = bytearray(bytes.fromhex(d['cose']))
c[20] ^= 0xff  # a byte inside the embedded payload
d['cose'] = c.hex()
json.dump(d, open('/tmp/he-cose-tampered.json', 'w'))
PY
if "$HV" --cose --nonce "$NONCE" /tmp/he-cose-tampered.json >/dev/null 2>&1; then
    bad "tampered COSE accepted"
else
    ok "tampered COSE rejected"
fi
echo

echo "== regression: the raw envelope still verifies =="
"$SIM" "$CLIP" "$NONCE" 1 > /tmp/he-raw.json 2>/dev/null
if "$HV" --nonce "$NONCE" /tmp/he-raw.json >/dev/null 2>&1; then
    ok "raw bound-output envelope still verifies"
else
    bad "raw envelope regression"
fi
echo

echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
