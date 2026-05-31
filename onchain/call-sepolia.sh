#!/usr/bin/env bash
#
# Verify the LIVE deployment yourself — don't trust this repo. Calls the deployed
# HonestEarQuorum.verdict() on Ethereum Sepolia (a public chain you don't control)
# with the committed proof + device-bundle fixtures, and decodes (event, presence).
# View-only: no key, no funds, no state change. Needs `cast` (Foundry) + network.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)/onchain"
RPC="${RPC:-https://sepolia.drpc.org}"
QUORUM="${QUORUM:-0x05DAa5dc9C21f4d17e930a158A3fc636de5D1815}" # audio+nonce-bound 2-of-2

command -v cast >/dev/null || { echo "need Foundry's 'cast' (https://getfoundry.sh)"; exit 1; }

seal=$(python3 -c "import json;print(json.load(open('$ROOT/test/proof_fixture.json'))['seal'])")
journal=$(python3 -c "import json;print(json.load(open('$ROOT/test/proof_fixture.json'))['journal'])")
payload=$(python3 -c "import json;print(json.load(open('$ROOT/test/quorum_fixture.json'))['alarm']['payload'])")
sig=$(python3 -c "import json;print(json.load(open('$ROOT/test/quorum_fixture.json'))['alarm']['sig'])")

echo "calling HonestEarQuorum.verdict() at $QUORUM on $RPC ..."
out=$(cast call "$QUORUM" "verdict(bytes,bytes,bytes,bytes)(uint32,uint32)" \
        "$seal" "$journal" "$payload" "$sig" --rpc-url "$RPC")
ev=$(printf '%s\n' "$out" | sed -n '1p')
pres=$(printf '%s\n' "$out" | sed -n '2p')
case "$ev" in 2) name=alarm_tone ;; 1) name=voice ;; *) name=none ;; esac

echo
echo "  event    = $ev ($name)"
echo "  presence = $pres"
echo
echo "A public-chain contract — not this repo — just confirmed an independent ZK"
echo "proof and the device's P-256 signature, bound to the same nonce AND the same"
echo "audio, agree on this verdict. The audio was never on-chain or in the repo."
