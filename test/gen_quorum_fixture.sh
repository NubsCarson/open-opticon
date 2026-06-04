#!/usr/bin/env bash
#
# Generate onchain/test/quorum_fixture.json — real device bound-output bundles
# (he-attest-sim, the published test key) for the SAME clips the zk proofs use,
# so the on-chain dual-root check can confirm the ZK leg and the device-signature
# leg agree. The P-256 signature is normalized to low-s (OZ P256 requires it).
# 0x-prefixed for Foundry; commit the output so forge test needs no C toolchain.
# Note: ECDSA signing uses a random nonce, so re-running yields a different but
# equally-valid signature — the committed fixture need not be byte-reproduced.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIM="$ROOT/sim/bin"
FIX="$ROOT/test/fixtures"

make -C "$ROOT/sim" all >/dev/null || { echo "C build failed"; exit 1; }

# Short 12-frame clips (3072 samples) — same ones the zk proofs use. Generate
# them deterministically if absent (they are gitignored), so this is self-contained.
mkdir -p "$FIX"
FIX="$FIX" python3 - <<'PY'
import math, os, struct
fix = os.environ["FIX"]
N = 256 * 12  # 12 frames
def w(name, samples):
    p = os.path.join(fix, name)
    if not os.path.exists(p):
        with open(p, "wb") as f:
            f.write(struct.pack("<%dh" % len(samples), *samples))
w("alarm_short.pcm", [max(-32768, min(32767, int(8000 * math.sin(2*math.pi*3100*i/16000)))) for i in range(N)])  # amp 8000 == canonical zk-bound clip
w("silence_short.pcm", [0]*N)
PY

# Device bundles for nonce aabbccdd (the nonce the zk proof is bound to). The
# alt-nonce alarm bundle is signed over a DIFFERENT nonce, to test the on-chain
# cross-root binding rejects mismatched sessions.
alarm_json="$("$SIM/he-attest-sim" "$FIX/alarm_short.pcm" aabbccdd 1)"
silence_json="$("$SIM/he-attest-sim" "$FIX/silence_short.pcm" aabbccdd 1)"
alarmalt_json="$("$SIM/he-attest-sim" "$FIX/alarm_short.pcm" ffeeddcc 1)"
# An otherwise-valid alarm bundle whose counter == type(uint64).max — for the
# on-chain anti-brick test: recordVerdict must REFUSE it so it can never store a
# counter that bricks every future "counter must advance".
alarmmax_json="$("$SIM/he-attest-sim" "$FIX/alarm_short.pcm" aabbccdd 18446744073709551615)"

OUT="$ROOT/onchain/test/quorum_fixture.json"
TMP_OUT="$(mktemp)"
trap 'rm -f "$TMP_OUT"' EXIT
ALARM="$alarm_json" SILENCE="$silence_json" ALARMALT="$alarmalt_json" ALARMMAX="$alarmmax_json" python3 - <<'PY' > "$TMP_OUT"
import json, os

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
HALF_N = N // 2
EVENT = {"none": 0, "voice": 1, "alarm_tone": 2}

def leg(raw):
    d = json.loads(raw)
    sig = bytes.fromhex(d["sig"])
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    # The C signer (sim/he_bundle.c sign_rs) now emits canonical low-s itself, so
    # this is a belt-and-suspenders guard (kept so fixtures stay valid even if
    # regenerated with an older sim). The C signer is guarded by he-gui's
    # TestSimEmitsLowS; here it should already hold.
    if s > HALF_N:                      # normalize to low-s for OZ P256
        s = N - s
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return {
        "payload": "0x" + d["payload"],
        "sig": "0x" + sig.hex(),
        "pubX": "0x" + d["pub_x"],
        "pubY": "0x" + d["pub_y"],
        "event": EVENT[d["event"]],
        "presence": d["presence"],
    }

print(json.dumps({"alarm": leg(os.environ["ALARM"]),
                  "silence": leg(os.environ["SILENCE"]),
                  "alarmAltNonce": leg(os.environ["ALARMALT"]),
                  "alarmMaxCounter": leg(os.environ["ALARMMAX"])}, indent=2))
PY

mv "$TMP_OUT" "$OUT" # only overwrite the committed fixture on full success
echo "wrote onchain/test/quorum_fixture.json"
python3 -c "import json;d=json.load(open('$OUT'));print('alarm event/presence:',d['alarm']['event'],d['alarm']['presence']);print('silence event/presence:',d['silence']['event'],d['silence']['presence'])"
