#!/usr/bin/env bash
#
# Honest Ear end-to-end test (host).
#
# Exercises the FULL application + crypto + verification pipeline with no TEE:
#   PCM fixture
#     -> he-attest-sim  (same detector + payload source the TA compiles,
#                         signed with the published QEMU test key exactly as
#                         optee-ra's sign_ecdsa_sha256 would)
#     -> he-verify      (Go verifier: signature + freshness + anti-replay)
#
# Positive cases assert the right event class AND a PASS verdict.
# Negative cases assert the verifier REJECTS tampering, stale nonces, replay,
# and a substituted key. Exits non-zero on any unexpected outcome.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIMBIN="$ROOT/sim/bin"
FIX="$ROOT/test/fixtures"
VERIFIER="$ROOT/src/verifier"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
ok()   { echo -e "  \033[1;32mok\033[0m:   $1"; pass=$((pass+1)); }
bad()  { echo -e "  \033[1;31mFAIL\033[0m: $1"; fail=$((fail+1)); }

# fresh random nonce (32 bytes hex)
nonce() { openssl rand -hex 32; }

echo "== build =="
make -C "$ROOT/sim" all >/dev/null || { echo "C build failed"; exit 1; }
( cd "$VERIFIER" && GOPROXY=off go build -o "$TMP/he-verify" ./cmd/he-verify ) \
    || { echo "go build failed"; exit 1; }
VERIFY="$TMP/he-verify"
echo "  built he-attest-sim, he-verify"

echo "== fixtures =="
python3 "$ROOT/test/gen_frames.py" "$FIX" >/dev/null || { echo "fixture gen failed"; exit 1; }
echo "  generated silence/alarm/voice/quiet"

# attest <pcm> <nonce> <counter> -> writes $TMP/bundle.json, echoes event.
# Fail loudly (bad + non-zero) if the sim itself errors, rather than letting an
# empty bundle.json surface as an opaque JSON error or a false negative-case pass.
attest() {
    if ! "$SIMBIN/he-attest-sim" "$1" "$2" "$3" > "$TMP/bundle.json"; then
        bad "he-attest-sim failed for $1"
        return 1
    fi
    python3 -c "import json,sys;print(json.load(open('$TMP/bundle.json'))['event'])"
}

echo "== positive: detect + bind + verify =="
declare -A want=( [silence]=none [alarm]=alarm_tone [voice]=voice [quiet]=none )
ctr=0
for name in silence alarm voice quiet; do
    ctr=$((ctr+1))
    nz="$(nonce)"
    ev="$(attest "$FIX/$name.pcm" "$nz" "$ctr")"
    if [ "$ev" != "${want[$name]}" ]; then
        bad "$name classified as '$ev' (want '${want[$name]}')"
    else
        ok "$name -> event=$ev"
    fi
    if "$VERIFY" --nonce "$nz" --last-counter "$((ctr-1))" "$TMP/bundle.json" >/dev/null 2>&1; then
        ok "$name -> verifier PASS (sig+freshness+counter)"
    else
        bad "$name -> verifier rejected a valid bundle"
    fi
done

echo "== negative: verifier must REJECT =="

# Use the alarm fixture for a fresh valid bundle, then attack it.
nz="$(nonce)"
attest "$FIX/alarm.pcm" "$nz" 100 >/dev/null

# 1) Tampered payload: flip a byte inside the signed nonce region (index 8 is a
#    nonce byte here, since this e2e uses a 32-byte nonce). Any mutation of the
#    signed bytes must break the ECDSA signature.
python3 - "$TMP/bundle.json" "$TMP/tampered.json" <<'PY'
import json,sys
b=json.load(open(sys.argv[1]))
p=bytearray.fromhex(b["payload"])
p[8]^=0xff          # corrupt a signed payload byte
b["payload"]=p.hex()
json.dump(b,open(sys.argv[2],"w"))
PY
if "$VERIFY" --nonce "$nz" "$TMP/tampered.json" >/dev/null 2>&1; then
    bad "tampered payload was ACCEPTED"
else
    ok "tampered payload rejected"
fi

# 2) Stale / wrong nonce.
if "$VERIFY" --nonce "$(nonce)" "$TMP/bundle.json" >/dev/null 2>&1; then
    bad "wrong nonce was ACCEPTED"
else
    ok "wrong nonce rejected"
fi

# 3) Replay: counter not greater than last seen.
if "$VERIFY" --nonce "$nz" --last-counter 100 "$TMP/bundle.json" >/dev/null 2>&1; then
    bad "replayed counter was ACCEPTED"
else
    ok "replayed counter rejected"
fi

# 4) Invalid key: perturb pub_x. Flipping one coordinate bit yields an off-curve
#    point, which the verifier rejects before ECDSA. (A substituted *valid* key is
#    covered by the Go unit test TestVerifyRejectsWrongKey.)
python3 - "$TMP/bundle.json" "$TMP/wrongkey.json" <<'PY'
import json,sys
b=json.load(open(sys.argv[1]))
x=bytearray.fromhex(b["pub_x"]); x[0]^=0x01; b["pub_x"]=x.hex()
json.dump(b,open(sys.argv[2],"w"))
PY
if "$VERIFY" --nonce "$nz" "$TMP/wrongkey.json" >/dev/null 2>&1; then
    bad "invalid (off-curve) key was ACCEPTED"
else
    ok "invalid (off-curve) key rejected"
fi

# 5) Endorsement pin mismatch (wrong device).
realx="$(python3 -c "import json;print(json.load(open('$TMP/bundle.json'))['pub_x'])")"
badx="$(python3 -c "print('ff'+'$realx'[2:])")"
if "$VERIFY" --nonce "$nz" --pin-x "$badx" --pin-y "00" "$TMP/bundle.json" >/dev/null 2>&1; then
    bad "pinned endorsement mismatch was ACCEPTED"
else
    ok "endorsement pin mismatch rejected"
fi

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
