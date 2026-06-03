#!/usr/bin/env bash
#
# Verify the LIVE deployment yourself — don't trust this repo. Calls the deployed
# HonestEarQuorum.verdict() on Ethereum Sepolia (a public chain you don't control)
# and decodes (event, presence). View-only: no key, no funds, no state change.
# Needs `cast` (Foundry) + network.
#
# The live contract speaks the CURRENT device-payload schema (11-map, with the
# streaming-hash-chain prev_digest at CBOR key 10), so this check feeds it the same
# fixtures the local `forge test` uses — no era-matched copy needed: the zk receipt
# (seal+journal) comes from test/proof_fixture.json and the device bundle
# (payload+sig) from test/quorum_fixture.json's alarm clip.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)/onchain"
PROOF="$ROOT/test/proof_fixture.json"
QF="$ROOT/test/quorum_fixture.json"
RPC="${RPC:-https://sepolia.drpc.org}"
QUORUM="${QUORUM:-0x31695C1842d558b396Ec8fE07E595D24cBabe487}" # audio+nonce-bound 2-of-2

command -v cast >/dev/null || { echo "need Foundry's 'cast' (https://getfoundry.sh)"; exit 1; }

jget() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))$1)" "$2"; }
seal=$(jget "['seal']" "$PROOF");   journal=$(jget "['journal']" "$PROOF")
payload=$(jget "['alarm']['payload']" "$QF"); sig=$(jget "['alarm']['sig']" "$QF")
want_ev=2; want_pres=1   # the alarm clip's agreed verdict: event=alarm_tone(2), presence=1

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
# answer would defeat the whole "check, don't trust" point. Guard the FULL (event,
# presence) tuple the banner + README advertise, not just the event.
if [ "$ev" != "$want_ev" ] || [ "$pres" != "$want_pres" ]; then
  echo "MISMATCH: live (event,presence)=($ev,$pres), expected ($want_ev,$want_pres)" >&2
  exit 1
fi

echo "A public-chain contract — not this repo — just confirmed an independent ZK"
echo "proof and the device's P-256 signature, bound to the same nonce AND the same"
echo "audio, agree on this verdict. The audio was never on-chain or in the repo."
