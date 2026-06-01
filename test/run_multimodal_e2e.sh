#!/usr/bin/env bash
#
# Multi-modal co-attestation end-to-end (no hardware).
#
# Shows the SAME attested device producing TWO independent, separately-published
# detector verdicts — an AUDIO verdict (he-attest-sim over an alarm clip) and a
# VISION verdict (he-attest-vision over a frame) — each a fresh signature bound to
# the SAME challenge nonce, and the verifier accepting them as a 2-modality
# co-attestation (`he-verify --co-attest 2`).
#
# This is the cross-modal sibling of `he-verify --quorum`: a quorum requires k
# INDEPENDENT roots to AGREE on one event (redundancy); co-attestation requires k
# distinct modalities bound to one nonce and does NOT require agreement (an alarm
# tone and an occupied room are different facts about the same moment).
#
# HONEST SCOPE: this proves the signing key produced a fresh signed verdict for
# each modality bound to one challenge. It does NOT prove the modalities observed
# the same physical scene, nor (Tier-1, shared embedded test key) that they came
# from a specific physical device — only that they share the challenge and the key.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$ROOT/src/verifier"
W="$(mktemp -d /tmp/he-multimodal.XXXXXX)"
NONCE="d15ea5edc0ffee00"
pass=0; fail=0
ok()  { printf '  \033[1;32mok\033[0m:   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m: %s\n' "$1"; fail=$((fail+1)); }
trap 'rm -rf "$W"' EXIT

echo "== build sims + verifier =="
make -C "$ROOT/sim" >/dev/null 2>&1 || { echo "sim build failed"; exit 1; }
( cd "$V" && GOPROXY=off go build -o "$W/he-verify" ./cmd/he-verify ) || { echo "go build failed"; exit 1; }
echo "  built he-attest-sim, he-attest-vision, he-verify"

# A 1 s 3.1 kHz alarm clip (amp 8000) and a bright 16x16 frame.
python3 - "$W" <<'PY'
import struct, math, sys
W = sys.argv[1]
n = 16000
s = [max(-32768, min(32767, int(8000 * math.sin(2 * math.pi * 3100 * i / 16000)))) for i in range(n)]
open(W + "/clip.pcm", "wb").write(struct.pack("<%dh" % n, *s))
w = h = 16
open(W + "/frame.pgm", "wb").write(b"P5\n%d %d\n255\n" % (w, h) + bytes([200] * (w * h)))
PY

echo
echo "== two modalities, one challenge nonce =="
"$ROOT/sim/bin/he-attest-sim"    "$W/clip.pcm"  "$NONCE" 1 > "$W/audio.json"  2>/dev/null
"$ROOT/sim/bin/he-attest-vision" "$W/frame.pgm" "$NONCE" 1 > "$W/vision.json" 2>/dev/null
[ -s "$W/audio.json" ] && [ -s "$W/vision.json" ] && ok "audio + vision bundles signed for nonce $NONCE" || bad "bundle generation"

# Sanity: they really are distinct modalities (distinct input_hash) for one nonce.
AIH=$(python3 -c "import json;p=json.load(open('$W/audio.json'))['payload'];print(p)")
VIH=$(python3 -c "import json;p=json.load(open('$W/vision.json'))['payload'];print(p)")
[ "$AIH" != "$VIH" ] && ok "the two bundles are distinct (different sensor inputs)" || bad "bundles identical"

echo
echo "== verifier accepts the 2-modality co-attestation =="
if "$W/he-verify" --nonce "$NONCE" --co-attest 2 "$W/audio.json" "$W/vision.json" >/dev/null 2>&1; then
  ok "2 distinct modalities bound to the same nonce -> co-attestation reached"
else
  bad "co-attestation should have been reached"
fi

echo
echo "== negatives =="
# Same modality twice is NOT two modalities (identical input_hash).
if "$W/he-verify" --nonce "$NONCE" --co-attest 2 "$W/audio.json" "$W/audio.json" >/dev/null 2>&1; then
  bad "one modality replayed as two was accepted"
else
  ok "one modality replayed as two is rejected (distinct input_hash required)"
fi
# A vision bundle for a DIFFERENT nonce must not co-attest with the audio one.
"$ROOT/sim/bin/he-attest-vision" "$W/frame.pgm" "deadbeefdeadbeef" 1 > "$W/vision_other.json" 2>/dev/null
if "$W/he-verify" --nonce "$NONCE" --co-attest 2 "$W/audio.json" "$W/vision_other.json" >/dev/null 2>&1; then
  bad "a modality bound to a different nonce was accepted"
else
  ok "a modality bound to a different nonce is rejected (freshness)"
fi

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
