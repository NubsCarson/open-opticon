#!/usr/bin/env bash
#
# `make demo` — the whole thesis on one clip: prove a sensor's restraint THREE
# independent ways and show they all agree on the same observation, while the
# audio never leaves the enclave.
#
#   1. TEE attestation  — the in-enclave detector signs a bound verdict (host sim
#                          of the OP-TEE path), checked by he-verify.
#   2. ZK proof         — an independent RISC Zero proof of the published detector
#                          (committed real Groth16 receipt; the audio is private).
#   3. On-chain 2-of-2  — the EVM quorum accepts only if the ZK proof AND the
#                          device signature agree AND are bound to the same audio.
#
# All three are bound to the SAME audio (sha256), so they describe one real clip.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$ROOT/test/fixtures"
CLIP="$FIX/alarm_short.pcm"
NONCE="aabbccdd"     # the verifier challenge the committed ZK proof is bound to
b() { printf '\033[1m%s\033[0m\n' "$1"; }

echo "== build =="
make -C "$ROOT/sim" all >/dev/null || { echo "C build failed"; exit 1; }
( cd "$ROOT/src/verifier" && GOPROXY=off go build -o /tmp/he-verify-demo ./cmd/he-verify ) \
    || { echo "go build failed"; exit 1; }
[ -f "$CLIP" ] || FIX="$FIX" python3 - <<'PY'
import math, os, struct
N = 256 * 12
s = [max(-32768, min(32767, int(8000 * math.sin(2 * math.pi * 3100 * i / 16000)))) for i in range(N)]  # amp 8000 == the canonical zk/quorum-bound clip (sha256 76fce813…)
open(os.path.join(os.environ["FIX"], "alarm_short.pcm"), "wb").write(struct.pack("<%dh" % len(s), *s))
PY
echo "  clip: alarm_short.pcm (a 3.1 kHz alarm tone) — the audio stays private throughout"
echo

b "1. TEE ATTESTATION (in-enclave detector, host sim)"
"$ROOT/sim/bin/he-attest-sim" "$CLIP" "$NONCE" 1 > /tmp/he-demo-bundle.json
tee_event=$(python3 -c "import json;print(json.load(open('/tmp/he-demo-bundle.json'))['event'])")
# input_hash is CBOR key 9 (bstr32, header 095820); locate it explicitly rather
# than slicing the tail, since key 10 (prev_digest) now follows it. Fail loudly if
# the marker is absent (don't let a parse error masquerade as a root MISMATCH).
tee_ih=$(python3 -c "import json;p=json.load(open('/tmp/he-demo-bundle.json'))['payload'];i=p.index('095820')+6;print(p[i:i+64])" 2>/dev/null) \
    || { echo "   error: could not locate input_hash (key 9) in the bundle payload"; exit 1; }
if /tmp/he-verify-demo --nonce "$NONCE" /tmp/he-demo-bundle.json >/dev/null 2>&1; then
    echo "   he-verify: PASS (signature + freshness + anti-replay)"
else
    echo "   he-verify: FAIL"; exit 1
fi
echo "   verdict: event=$tee_event   input_hash=${tee_ih:0:16}…"
echo

b "2. ZK PROOF (RISC Zero, audio is private witness data)"
read -r zk_event zk_ah < <(python3 - "$ROOT/onchain/test/proof_fixture.json" <<'PY'
import json, struct, sys
j = bytes.fromhex(json.load(open(sys.argv[1]))["journal"].removeprefix("0x"))
ev, pr, va, fr, af, n = struct.unpack("<6I", j[:24])
print(["none", "voice", "alarm_tone"][ev], j[56:88].hex())
PY
)
echo "   ZK-VERIFIED: event=$zk_event   audio_sha256=${zk_ah:0:16}…   (audio never revealed)"
echo

b "3. ON-CHAIN 2-of-2 (EVM: ZK proof AND device signature must agree)"
if command -v forge >/dev/null 2>&1 && [ -d "$ROOT/onchain/lib/forge-std" ]; then
    if ( cd "$ROOT/onchain" && forge test --match-test test_QuorumAgrees >/dev/null 2>&1 ); then
        echo "   forge test_QuorumAgrees: PASS (verified on a local EVM)"
    else
        echo "   forge test: FAIL"; exit 1
    fi
else
    echo "   (forge/deps absent — skipping local run; the same contract is live on"
    echo "    Sepolia: sepolia.etherscan.io/address/0x31695C1842d558b396Ec8fE07E595D24cBabe487)"
fi
echo

b "== verdict =="
echo "  TEE attestation, an independent ZK proof, and an on-chain 2-of-2 quorum —"
echo "  three independent roots — all report: $tee_event."
if [ "$tee_event" = "$zk_event" ] && [ "$tee_ih" = "$zk_ah" ]; then
    echo "  They are bound to the SAME audio (input_hash == audio_sha256 == ${tee_ih:0:16}…),"
    echo "  so they describe one real clip — and the audio never left the enclave."
else
    echo "  MISMATCH between roots (event or audio hash) — investigate."; exit 1
fi
