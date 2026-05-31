#!/usr/bin/env bash
#
# Streaming hash-chain end-to-end: prove that a device's bound-output stream is
# append-only. Each window carries prev_digest = SHA-256 of the previous signed
# payload (key 10), so the verifier can detect a SUPPRESSED window — not just a
# replayed one. A monitor that recorded one window's next_digest will reject the
# next window unless it chains from exactly that digest.
#
#   genesis (prev = 0..0) -> window2 (prev = H1) -> window3 (prev = H2)
#   drop window2, splice window3 after genesis -> chain break, REJECTED.
#
# Pure host sim + the stdlib Go verifier; no hardware, no network.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$ROOT/test/fixtures"
CLIP="$FIX/alarm_short.pcm"
ZERO="0000000000000000000000000000000000000000000000000000000000000000"
SIM="$ROOT/sim/bin/he-attest-sim"
HV=/tmp/he-verify-chain
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
s = [max(-32768, min(32767, int(12000 * math.sin(2 * math.pi * 3100 * i / 16000)))) for i in range(N)]
open(os.path.join(os.environ["FIX"], "alarm_short.pcm"), "wb").write(struct.pack("<%dh" % len(s), *s))
PY
echo "  built he-attest-sim, he-verify"
echo

# sign <out.json> <nonce> <counter> <prev_hex>
sign() { "$SIM" "$CLIP" "$2" "$3" "$4" > "$1"; }
# verify_next <bundle> <nonce> <last_counter> <expect_prev> -> prints next_digest, returns rc
verify_next() {
    "$HV" --nonce "$2" --last-counter "$3" --expect-prev "$4" "$1" 2>/dev/null \
        | awk '/next_digest/ {print $3}'
}

echo "== a genuine append-only stream verifies, link by link =="
sign /tmp/he-w1.json aa01 1 "$ZERO"
H1=$(verify_next /tmp/he-w1.json aa01 0 "$ZERO")
[ -n "$H1" ] && ok "genesis window verifies (prev_digest = 0..0)" || bad "genesis window"

sign /tmp/he-w2.json aa02 2 "$H1"
H2=$(verify_next /tmp/he-w2.json aa02 1 "$H1")
[ -n "$H2" ] && ok "window 2 chains from genesis (prev_digest = H1)" || bad "window 2 chain"

sign /tmp/he-w3.json aa03 3 "$H2"
H3=$(verify_next /tmp/he-w3.json aa03 2 "$H2")
[ -n "$H3" ] && ok "window 3 chains from window 2 (prev_digest = H2)" || bad "window 3 chain"
echo

echo "== a suppressed window breaks the chain (gap detection) =="
# An attacker drops window 2 and shows the monitor window 3 next. The monitor
# still expects H1 (the digest it last recorded), but window 3 carries H2.
if "$HV" --nonce aa03 --last-counter 1 --expect-prev "$H1" /tmp/he-w3.json >/dev/null 2>&1; then
    bad "spliced stream (window 2 dropped) accepted — gap NOT detected"
else
    ok "spliced stream rejected: window 3's prev_digest != last recorded digest"
fi

# Sanity: window 3 against its CORRECT predecessor still passes (not a false alarm).
if "$HV" --nonce aa03 --last-counter 2 --expect-prev "$H2" /tmp/he-w3.json >/dev/null 2>&1; then
    ok "window 3 against its true predecessor still verifies (no false positive)"
else
    bad "window 3 wrongly rejected against its true predecessor"
fi
echo

echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
