#!/usr/bin/env bash
#
# Honest Ear — C vs Rust detector differential test.
#
# The zk leg's guarantee rests on the Rust port (zk/oo-detector) being a FAITHFUL
# reimplementation of the published C detector (src/common/he_detector.c). This
# proves it: build both detector CLIs, run them over the SAME PCM fixtures, and
# assert their verdicts are byte-for-byte identical. Any divergence fails.
#
# Needs gcc (he-detect), cargo (oo-detect), python3 (fixtures). No risc0/proving.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$ROOT/test/fixtures"

pass=0
fail=0
ok()  { echo -e "  \033[1;32mok\033[0m:   $1"; pass=$((pass+1)); }
bad() { echo -e "  \033[1;31mFAIL\033[0m: $1"; fail=$((fail+1)); }

echo "== build =="
make -C "$ROOT/sim" all >/dev/null || { echo "C build failed"; exit 1; }
( cd "$ROOT/zk/oo-detect" && cargo build --release >/dev/null 2>&1 ) \
    || { echo "Rust build failed"; exit 1; }
HE="$ROOT/sim/bin/he-detect"
OO="$ROOT/zk/oo-detect/target/release/oo-detect"
echo "  built he-detect (C) and oo-detect (Rust)"

echo "== fixtures =="
python3 "$ROOT/test/gen_frames.py" "$FIX" >/dev/null || { echo "fixture gen failed"; exit 1; }
echo "  generated silence/alarm/voice/quiet"

echo "== C detector == Rust port (verdicts must be identical) =="
# Easy fixtures + boundary/adversarial cases (energy-floor edge, full-scale
# clipping, off-target tone, sub-frame) — the inputs most likely to expose an
# integer-port divergence.
for name in silence alarm voice quiet floor_active floor_silent clip tone700 subframe; do
    c="$("$HE" "$FIX/$name.pcm")"
    r="$("$OO" "$FIX/$name.pcm")"
    if [ "$c" = "$r" ]; then
        ok "$name -> $c"
    else
        bad "$name diverges:"
        echo "        C   : $c"
        echo "        Rust: $r"
    fi
done

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
