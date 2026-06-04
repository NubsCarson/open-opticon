#!/usr/bin/env bash
#
# Heterogeneous-root quorum, end-to-end (no hardware, no r0vm): TWO genuinely
# independent signing roots — a sim/embedded P-256 key AND a P-256 key generated
# INSIDE a software TPM (private half never exported) — both sign the SAME
# bound-output payload (same nonce, same event), and `he-verify --quorum 2`
# accepts only because two DISTINCT enrolled roots independently verify and agree.
# This is the first end-to-end exercise of the k-of-n heterogeneous-root path with
# two genuinely independent signing roots (a sim/embedded key + a swtpm-resident
# key) rather than synthetic in-process unit-test keys. NOTE: swtpm is a SOFTWARE
# TPM emulator — these are independent software roots, not separate hardware.
#
# HONEST SCOPE: this proves two INDEPENDENT SIGNING ROOTS agree on a fresh bound
# verdict. It does NOT prove two independent WITNESSES of the audio — the TPM did
# not observe anything; it re-signs the sim's payload bytes. It is a root-agnostic
# quorum demonstration, strictly weaker than two real sensors. (Same caveat as
# run_tpm_e2e.sh.) Needs swtpm + tpm2-tools + openssl; SKIPS cleanly if absent.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$ROOT/src/verifier"
NONCE="d15ea5edc0ffee00"

for t in swtpm swtpm_setup tpm2_getcap tpm2_createprimary tpm2_create tpm2_readpublic tpm2_sign openssl; do
  command -v "$t" >/dev/null 2>&1 || { echo "SKIP: heterogeneous quorum e2e needs swtpm + tpm2-tools + openssl (missing: $t)"; exit 0; }
done

W="$(mktemp -d /tmp/he-qhetero.XXXXXX)"
SWTPM_PID=""
pass=0; fail=0
ok()  { printf '  \033[1;32mok\033[0m:   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m: %s\n' "$1"; fail=$((fail+1)); }
cleanup() { [ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

echo "== build sim + verifier, start a software TPM =="
make -C "$ROOT/sim" >/dev/null 2>&1 || { echo "sim build failed"; exit 1; }
( cd "$V" && GOPROXY=off go build -o "$W/he-verify" ./cmd/he-verify ) || { echo "go build failed"; exit 1; }
mkdir -p "$W/state"
swtpm_setup --tpm2 --tpmstate "$W/state" --createek --create-spk --overwrite >/dev/null 2>&1
swtpm socket --tpm2 --tpmstate "dir=$W/state" \
  --ctrl "type=unixio,path=$W/swtpm.sock.ctrl" --server "type=unixio,path=$W/swtpm.sock" \
  --flags not-need-init,startup-clear >/dev/null 2>&1 &
SWTPM_PID=$!
export TPM2TOOLS_TCTI="swtpm:path=$W/swtpm.sock"
ready=0
for _ in $(seq 1 50); do tpm2_getcap properties-fixed >/dev/null 2>&1 && { ready=1; break; }; sleep 0.1; done
[ "$ready" -eq 1 ] && ok "software TPM up; sim + he-verify built" || { bad "swtpm did not start"; echo "== summary: $pass passed, $fail failed =="; exit 1; }

echo
echo "== root A: the sim/embedded P-256 key signs a bound output for the nonce =="
python3 -c '
import struct, math
n = 16000
s = [max(-32768, min(32767, int(8000 * math.sin(2 * math.pi * 3100 * i / 16000)))) for i in range(n)]
open("'"$W"'/clip.pcm","wb").write(struct.pack("<%dh" % n, *s))'
"$ROOT/sim/bin/he-attest-sim" "$W/clip.pcm" "$NONCE" 1 > "$W/simbundle.json" 2>/dev/null
SX=$(python3 -c "import json;print(json.load(open('$W/simbundle.json'))['pub_x'])")
SY=$(python3 -c "import json;print(json.load(open('$W/simbundle.json'))['pub_y'])")
PAYLOAD=$(python3 -c "import json;print(json.load(open('$W/simbundle.json'))['payload'])")
[ -n "$SX" ] && [ -n "$PAYLOAD" ] && ok "sim root signed (event bound to nonce $NONCE)" || bad "sim bundle"

echo
echo "== root B: a TPM-resident P-256 key signs the SAME payload (independent root) =="
tpm2_createprimary -C o -g sha256 -G ecc256 -c "$W/p.ctx" >/dev/null 2>&1
tpm2_create -C "$W/p.ctx" -g sha256 -G "ecc256:ecdsa-sha256" -u "$W/k.pub" -r "$W/k.priv" -c "$W/k.ctx" >/dev/null 2>&1
tpm2_flushcontext -t >/dev/null 2>&1
tpm2_readpublic -c "$W/k.ctx" -o "$W/k.pem" -f pem >/dev/null 2>&1
read -r TX TY < <(openssl ec -pubin -in "$W/k.pem" -text -noout 2>/dev/null | python3 -c '
import sys, re
t = sys.stdin.read(); m = re.search(r"pub:\s*((?:[0-9a-f:\s]+))", t)
b = bytes(int(x,16) for x in re.findall(r"[0-9a-f]{2}", m.group(1)))
assert b[0] == 0x04 and len(b) == 65
print(b[1:33].hex(), b[33:65].hex())')
# Sign SHA-256(payload) with the TPM; convert its DER ECDSA sig to raw 64-byte r||s.
# The TPM signs with a random s (high ~half the time); canonicalize to low-s
# (s' = N - s when s > N/2) so the verifier's Gate 1b and the on-chain P256 verifier
# accept this root — (r, N-s) is an equally valid ECDSA signature for the same key.
python3 -c "import sys;open('$W/payload.bin','wb').write(bytes.fromhex('$PAYLOAD'))"
openssl dgst -sha256 -binary "$W/payload.bin" > "$W/payload.dig"
tpm2_sign -c "$W/k.ctx" -g sha256 -d -f plain -o "$W/sig.der" "$W/payload.dig" >/dev/null 2>&1
TSIG=$(python3 - "$W/sig.der" <<'PY'
import sys
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
d = open(sys.argv[1], "rb").read()
assert d[0] == 0x30
i = 2 if d[1] < 0x80 else 2 + (d[1] & 0x7f)
assert d[i] == 0x02; rlen = d[i+1]; r = d[i+2:i+2+rlen]; i = i+2+rlen
assert d[i] == 0x02; slen = d[i+1]; s = d[i+2:i+2+slen]
sv = int.from_bytes(s, "big")
if sv > N // 2: sv = N - sv          # canonical low-s
fix = lambda x: (b"\x00"*(32-len(x.lstrip(b"\x00")))) + x.lstrip(b"\x00")
print((fix(r) + sv.to_bytes(32, "big")).hex())
PY
)
python3 -c "
import json
json.dump({'schema':'honest-ear/bound-output/v1','payload':'$PAYLOAD','sig':'$TSIG','pub_x':'$TX','pub_y':'$TY'}, open('$W/tpmbundle.json','w'))"
[ "${#TSIG}" -eq 128 ] && [ "$TX" != "$SX" ] && ok "TPM root signed the same payload (distinct key from the sim root)" || bad "TPM bundle / key not distinct"

echo
echo "== he-verify --quorum 2 accepts the two independent roots =="
if "$W/he-verify" --nonce "$NONCE" --quorum 2 \
     --root "sim:$SX:$SY" --root "tpm:$TX:$TY" "$W/simbundle.json" "$W/tpmbundle.json" >/dev/null 2>&1; then
  ok "2-of-2 heterogeneous quorum reached (sim P-256 + TPM-resident P-256 agree)"
else
  bad "heterogeneous quorum should have been reached"
fi

echo
echo "== negatives =="
# Only one root's bundle -> threshold 2 not met.
if "$W/he-verify" --nonce "$NONCE" --quorum 2 --root "sim:$SX:$SY" --root "tpm:$TX:$TY" "$W/simbundle.json" >/dev/null 2>&1; then
  bad "quorum reached with only one root's bundle"
else
  ok "one bundle alone does not reach the 2-of-2 quorum"
fi
# A tampered TPM signature -> that root drops out -> quorum not met.
python3 -c "
import json
b = json.load(open('$W/tpmbundle.json')); s = bytearray.fromhex(b['sig']); s[0] ^= 0xff; b['sig'] = s.hex()
json.dump(b, open('$W/tpmbad.json','w'))"
if "$W/he-verify" --nonce "$NONCE" --quorum 2 --root "sim:$SX:$SY" --root "tpm:$TX:$TY" "$W/simbundle.json" "$W/tpmbad.json" >/dev/null 2>&1; then
  bad "quorum reached with a tampered TPM signature"
else
  ok "a tampered TPM-root signature drops that root (quorum not reached)"
fi

echo
echo "  HONEST SCOPE: two independent SIGNING ROOTS agreed on a fresh bound verdict;"
echo "  this is NOT two independent witnesses of the audio (the TPM did not observe it)."
echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
