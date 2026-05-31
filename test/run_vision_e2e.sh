#!/usr/bin/env bash
#
# Honest Ear vision end-to-end test (host).
#
# The audio e2e (run_e2e.sh) proves the detect -> bind -> verify pipeline and
# the verifier's full negative battery (tamper/nonce/replay/key/pin). This
# proves the SAME machinery generalizes to a camera: a grayscale frame
#   -> he-attest-vision  (he_vision detector + he_payload + the shared bundle
#                          path, signed with the published QEMU test key)
#   -> he-verify         (the IDENTICAL verifier: its sig/freshness/counter/pin
#                          gates are modality-agnostic. NB the verifier renders
#                          the audio field names, so a vision OCCUPIED verdict
#                          surfaces as event="voice" until a modality-tagged v2
#                          envelope — see he_vision_sign.c.)
#
# Asserts the right scene class AND a PASS verdict, plus one tamper to confirm
# the binding holds for vision too (the rest is covered modality-agnostically by
# run_e2e.sh, since the verifier is the same binary).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIMBIN="$ROOT/sim/bin"
FIX="$ROOT/test/fixtures"
VERIFIER="$ROOT/src/verifier"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
ok()  { echo -e "  \033[1;32mok\033[0m:   $1"; pass=$((pass+1)); }
bad() { echo -e "  \033[1;31mFAIL\033[0m: $1"; fail=$((fail+1)); }
nonce() { openssl rand -hex 32; }

echo "== build =="
make -C "$ROOT/sim" all >/dev/null || { echo "C build failed"; exit 1; }
( cd "$VERIFIER" && GOPROXY=off go build -o "$TMP/he-verify" ./cmd/he-verify ) \
    || { echo "go build failed"; exit 1; }
VERIFY="$TMP/he-verify"
echo "  built he-attest-vision, he-verify"

echo "== fixtures =="
python3 "$ROOT/test/gen_vision_frames.py" "$FIX" >/dev/null || { echo "fixture gen failed"; exit 1; }
echo "  generated empty/occupied frames"

# attest <pgm> <nonce> <counter> -> writes $TMP/bundle.json, echoes scene.
attest() {
    if ! "$SIMBIN/he-attest-vision" "$1" "$2" "$3" > "$TMP/bundle.json"; then
        bad "he-attest-vision failed for $1"
        return 1
    fi
    python3 -c "import json;print(json.load(open('$TMP/bundle.json'))['scene'])"
}

echo "== positive: detect + bind + verify (same he-verify) =="
declare -A want=( [empty]=empty [occupied]=occupied )
ctr=0
for name in empty occupied; do
    ctr=$((ctr+1))
    nz="$(nonce)"
    sc="$(attest "$FIX/$name.pgm" "$nz" "$ctr")"
    if [ "$sc" != "${want[$name]}" ]; then
        bad "$name classified as '$sc' (want '${want[$name]}')"
    else
        ok "$name -> scene=$sc"
    fi
    if "$VERIFY" --nonce "$nz" --last-counter "$((ctr-1))" "$TMP/bundle.json" >/dev/null 2>&1; then
        ok "$name -> verifier PASS (sig+freshness+counter)"
    else
        bad "$name -> verifier rejected a valid vision bundle"
    fi
done

echo "== negative: binding holds for vision too =="
nz="$(nonce)"
attest "$FIX/occupied.pgm" "$nz" 50 >/dev/null
python3 - "$TMP/bundle.json" "$TMP/tampered.json" <<'PY'
import json,sys
b=json.load(open(sys.argv[1]))
p=bytearray.fromhex(b["payload"])
p[8]^=0xff          # corrupt a signed payload byte
b["payload"]=p.hex()
json.dump(b,open(sys.argv[2],"w"))
PY
if "$VERIFY" --nonce "$nz" "$TMP/tampered.json" >/dev/null 2>&1; then
    bad "tampered vision payload was ACCEPTED"
else
    ok "tampered vision payload rejected"
fi

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
