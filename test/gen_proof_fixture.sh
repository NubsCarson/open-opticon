#!/usr/bin/env bash
#
# Regenerate onchain/test/proof_fixture.json — a REAL RISC Zero Groth16 receipt
# of the detector over the alarm_short clip (imageId + journal + Ethereum seal),
# the input the on-chain HonestEarVerifier test checks.
#
# Heavy + slow: the STARK->SNARK wrap runs in Docker (x86) and takes ~minutes.
# Needs the risc0 toolchain (cargo + r0vm) and Docker. The committed fixture
# already exists; this script is the reproducible regeneration path (it is not
# run in CI). The short clip is the same one gen_quorum_fixture.sh signs, so the
# zk leg and the device leg provably describe the identical audio.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$ROOT/test/fixtures"

mkdir -p "$FIX"
FIX="$FIX" python3 - <<'PY'
import math, os, struct
fix = os.environ["FIX"]
N = 256 * 12  # 12 frames, == the zk/quorum short clip
p = os.path.join(fix, "alarm_short.pcm")
if not os.path.exists(p):
    s = [max(-32768, min(32767, int(8000 * math.sin(2 * math.pi * 3100 * i / 16000)))) for i in range(N)]  # amp 8000 == the canonical clip the committed proof is bound to
    with open(p, "wb") as f:
        f.write(struct.pack("<%dh" % len(s), *s))
PY

cd "$ROOT/zk"
echo "running he-zk-export (Groth16; needs Docker; ~minutes) ..."
cargo run --release --bin he-zk-export -- \
    "$FIX/alarm_short.pcm" "$ROOT/onchain/test/proof_fixture.json"
echo "wrote onchain/test/proof_fixture.json"
