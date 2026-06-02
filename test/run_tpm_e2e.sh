#!/usr/bin/env bash
#
# Heterogeneous-root demo: a TPM-resident NIST P-256 key signs an Honest Ear
# artifact that the EXISTING stdlib-only verifier accepts — with the private key
# generated INSIDE the TPM and never exported. This substantiates the project's
# "TPM on PC (the verifier is root-agnostic)" claim with genuinely different
# silicon than the OP-TEE/QEMU test key.
#
# It runs against a SOFTWARE TPM (swtpm) so it needs no real-TPM access and never
# touches /dev/tpm0; on a box with a real TPM, set
#   TPM2TOOLS_TCTI=device:/dev/tpmrm0
# instead of the swtpm socket below. If swtpm / tpm2-tools are not installed, the
# script SKIPS cleanly (exit 0) — it is an optional, separate CI job.
#
# HONEST SCOPE: the TPM did NOT observe the audio. There is no measured-boot/PCR
# binding of the detector to this key. This demonstrates the verifier's
# ROOT-AGNOSTIC signing capability with independent silicon (private key
# TPM-resident); it is NOT a second WITNESS of the event, and is strictly weaker
# than the OP-TEE Tier-1 attest+bind+verify (which alone ties a key to in-enclave
# processing). It does not add a new "proven" hardware property.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$ROOT/src/verifier"

need="swtpm swtpm_setup tpm2_getcap tpm2_createprimary tpm2_create tpm2_readpublic tpm2_sign openssl"
for t in $need; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "SKIP: heterogeneous-root TPM demo needs swtpm + tpm2-tools + openssl (missing: $t)"
    exit 0
  fi
done

W="$(mktemp -d /tmp/he-tpm.XXXXXX)"
SWTPM_PID=""
pass=0; fail=0
ok()  { printf '  \033[1;32mok\033[0m:   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m: %s\n' "$1"; fail=$((fail+1)); }
cleanup() { [ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

echo "== start a software TPM (the real /dev/tpm0 is never touched) =="
mkdir -p "$W/state" # swtpm_setup requires the state dir to already exist
swtpm_setup --tpm2 --tpmstate "$W/state" --createek --create-spk --overwrite >/dev/null 2>&1
swtpm socket --tpm2 --tpmstate "dir=$W/state" \
  --ctrl "type=unixio,path=$W/swtpm.sock.ctrl" --server "type=unixio,path=$W/swtpm.sock" \
  --flags not-need-init,startup-clear >/dev/null 2>&1 &
SWTPM_PID=$!
export TPM2TOOLS_TCTI="swtpm:path=$W/swtpm.sock"
# Wait for the emulator to answer.
ready=0
for _ in $(seq 1 50); do
  if tpm2_getcap properties-fixed >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.1
done
[ "$ready" -eq 1 ] && ok "software TPM up (swtpm)" || { bad "swtpm did not start"; echo "== summary: $pass passed, $fail failed =="; exit 1; }

echo
echo "== create a P-256 signing key INSIDE the TPM (private half never leaves) =="
tpm2_createprimary -C o -g sha256 -G ecc256 -c "$W/primary.ctx" >/dev/null 2>&1
# -c creates AND loads in one call; then flush transient objects so later loads of
# the saved key context have a free slot (swtpm has few transient-object slots).
tpm2_create -C "$W/primary.ctx" -g sha256 -G "ecc256:ecdsa-sha256" \
  -u "$W/key.pub" -r "$W/key.priv" -c "$W/key.ctx" >/dev/null 2>&1
tpm2_flushcontext -t >/dev/null 2>&1
tpm2_readpublic -c "$W/key.ctx" -o "$W/key.pem" -f pem >/dev/null 2>&1
[ -s "$W/key.pem" ] && ok "TPM-resident P-256 key created" || { bad "TPM key creation"; echo "== summary: $pass passed, $fail failed =="; exit 1; }

# Extract the public point as 32-byte X,Y hex (uncompressed 04||X||Y).
read -r PX PY < <(openssl ec -pubin -in "$W/key.pem" -text -noout 2>/dev/null | python3 -c '
import sys, re
t = sys.stdin.read()
m = re.search(r"pub:\s*((?:[0-9a-f:\s]+))", t)
hexs = re.findall(r"[0-9a-f]{2}", m.group(1))
b = bytes(int(x,16) for x in hexs)
# uncompressed point: 0x04 || X(32) || Y(32)
assert b[0] == 0x04 and len(b) == 65, "unexpected EC point encoding"
print(b[1:33].hex(), b[33:65].hex())
')
[ "${#PX}" -eq 64 ] && [ "${#PY}" -eq 64 ] && ok "read TPM public key X,Y (32 bytes each)" || { bad "pubkey parse"; echo "== summary: $pass passed, $fail failed =="; exit 1; }

echo
echo "== build the canonical receipt body (reuse he-receipt; discard its host sig) =="
( cd "$V" && GOPROXY=off go build -o "$W/he-receipt" ./cmd/he-receipt ) || { bad "go build"; echo "== summary: $pass passed, $fail failed =="; exit 1; }
THROWAWAY="$(python3 -c 'print("22"*32)')"
printf 'audio window (discarded after hashing)' > "$W/a.pcm"
printf 'transcript text' > "$W/t.txt"
"$W/he-receipt" emit --session "tpm-demo" --batch 1 --audio "$W/a.pcm" --text "$W/t.txt" \
  --key "$THROWAWAY" > "$W/throwaway.json" 2>/dev/null
python3 -c "import json;print(json.load(open('$W/throwaway.json'))['body'], end='')" > "$W/body.txt"
[ -s "$W/body.txt" ] && ok "canonical receipt body produced" || { bad "receipt body extraction"; echo "== summary: $pass passed, $fail failed =="; exit 1; }

echo
echo "== the TPM signs SHA-256(body); assemble a bundle the unmodified verifier eats =="
openssl dgst -sha256 -binary "$W/body.txt" > "$W/body.dig"
# -d: the input is already a digest. The TPM returns the ECDSA signature as DER
# (SEQUENCE{ INTEGER r, INTEGER s }); the verifier wants raw 64-byte r||s, so
# convert it (strip each INTEGER's optional sign byte, left-pad to 32 bytes).
tpm2_sign -c "$W/key.ctx" -g sha256 -d -f plain -o "$W/sig.der" "$W/body.dig" >/dev/null 2>&1
SIG=$(python3 - "$W/sig.der" <<'PY'
import sys
d = open(sys.argv[1], "rb").read()
# Minimal DER ECDSA-Sig-Value parse: 0x30 len 0x02 rlen r 0x02 slen s.
assert d[0] == 0x30, "not a DER SEQUENCE"
i = 2 if d[1] < 0x80 else 2 + (d[1] & 0x7f)
assert d[i] == 0x02, "expected INTEGER r"
rlen = d[i+1]; r = d[i+2:i+2+rlen]; i = i+2+rlen
assert d[i] == 0x02, "expected INTEGER s"
slen = d[i+1]; s = d[i+2:i+2+slen]
def fix(x):
    x = x.lstrip(b"\x00")          # drop DER sign byte / leading zeros
    return (b"\x00"*(32-len(x))) + x  # left-pad to 32 bytes
print((fix(r)+fix(s)).hex())
PY
)
[ "${#SIG}" -eq 128 ] && ok "TPM ECDSA signature converted to 64-byte r||s" || bad "unexpected sig length (${#SIG} hex chars, want 128)"
python3 -c "
import json
body = open('$W/body.txt').read()
json.dump({'schema':'honest-ear/restraint-receipt/v1','body':body,'sig':'$SIG','pub_x':'$PX','pub_y':'$PY'}, open('$W/tpm_receipt.json','w'))
"

echo
echo "== the existing stdlib verifier accepts the TPM-signed receipt =="
if "$W/he-receipt" verify --file "$W/tpm_receipt.json" --pin-x "$PX" --pin-y "$PY" --require-not-retained >/dev/null 2>&1; then
  ok "he-receipt accepts a receipt signed by a TPM-resident key (root-agnostic)"
else
  bad "verifier rejected the TPM-signed receipt"
fi

echo
echo "== negative: a tampered TPM signature is rejected =="
python3 -c "
import json
r = json.load(open('$W/tpm_receipt.json'))
s = bytearray.fromhex(r['sig']); s[0] ^= 0xff
r['sig'] = s.hex()
json.dump(r, open('$W/tpm_bad.json','w'))
"
if "$W/he-receipt" verify --file "$W/tpm_bad.json" --pin-x "$PX" --pin-y "$PY" --require-not-retained >/dev/null 2>&1; then
  bad "tampered TPM signature accepted"
else
  ok "tampered TPM signature rejected"
fi

echo
echo "  HONEST SCOPE: this shows the verifier is root-agnostic — a TPM-resident key"
echo "  (independent silicon, private half never exported) signs an artifact the"
echo "  unmodified verifier accepts. The TPM did NOT observe the audio; this is a"
echo "  signing-root demonstration, NOT a second witness, and is weaker than the"
echo "  OP-TEE Tier-1 attest+bind."
echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] || exit 1
