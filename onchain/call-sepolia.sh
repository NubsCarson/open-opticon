#!/usr/bin/env bash
#
# Verify the LIVE deployment yourself — don't trust this repo. Calls the deployed
# HonestEarQuorum.verdict() on Ethereum Sepolia (a public chain you don't control)
# and decodes (event, presence). View-only: no key, no funds, no state change.
# Needs `cast` (Foundry) + network.
#
# IMPORTANT — schema freeze: the live contract is an IMMUTABLE PoC snapshot deployed
# from repo rev e47cf21, BEFORE commit 25b89ff added the streaming-hash-chain
# prev_digest (CBOR key 10) that grew the device payload from a 10-map to an 11-map.
# So this live check uses onchain/test/sepolia_fixture.json (the era-matched 10-map
# fixtures the contract was deployed against); the CURRENT 11-map fixtures
# (onchain/test/quorum_fixture.json) drive the LOCAL forge test at today's schema and
# would revert "not a 10-map" against the frozen deploy. See onchain/README.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)/onchain"
FIX="$ROOT/test/sepolia_fixture.json"
RPC="${RPC:-https://sepolia.drpc.org}"
QUORUM="${QUORUM:-0x05DAa5dc9C21f4d17e930a158A3fc636de5D1815}" # audio+nonce-bound 2-of-2

command -v cast >/dev/null || { echo "need Foundry's 'cast' (https://getfoundry.sh)"; exit 1; }

get() { python3 -c "import json;print(json.load(open('$FIX'))['$1'])"; }
seal=$(get seal); journal=$(get journal); payload=$(get payload); sig=$(get sig)
want_ev=$(get expect | python3 -c "import sys,ast;print(ast.literal_eval(sys.stdin.read())['event'])")

echo "calling HonestEarQuorum.verdict() at $QUORUM on $RPC ..."
out=$(cast call "$QUORUM" "verdict(bytes,bytes,bytes,bytes)(uint32,uint32)" \
        "$seal" "$journal" "$payload" "$sig" --rpc-url "$RPC")
ev=$(printf '%s\n' "$out" | sed -n '1p' | awk '{print $1}')
pres=$(printf '%s\n' "$out" | sed -n '2p' | awk '{print $1}')
case "$ev" in 2) name=alarm_tone ;; 1) name=voice ;; *) name=none ;; esac

echo
echo "  event    = $ev ($name)"
echo "  presence = $pres"
echo

# Fail loudly if the live chain didn't return the expected verdict — a silent wrong
# answer would defeat the whole "check, don't trust" point.
if [ "$ev" != "$want_ev" ]; then
  echo "MISMATCH: live verdict event=$ev, expected $want_ev" >&2
  exit 1
fi

echo "A public-chain contract — not this repo — just confirmed an independent ZK"
echo "proof and the device's P-256 signature, bound to the same nonce AND the same"
echo "audio, agree on this verdict. The audio was never on-chain or in the repo."
