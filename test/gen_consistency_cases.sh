#!/usr/bin/env bash
#
# Generate onchain/test/consistency_cases.json — a TABLE of REAL RFC 9162
# consistency proofs over many (oldSize -> newSize) pairs from a he-log
# transparency log, so the hand-ported Solidity CheckpointAnchor._verifyConsistency
# can be differential-tested against the Go VerifyConsistency oracle (which
# TestConsistencyExhaustive already proves correct) for sizes the single committed
# 3->5 fixture never exercises. 0x-prefixed for Foundry; each case's proof nodes are
# concatenated into one bytes value (the forge test slices them back into bytes32[]).
# Commit the output so `forge test` needs no Go toolchain.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$ROOT/src/verifier"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/he-log"
( cd "$V" && GOPROXY=off go build -o "$BIN" ./cmd/he-log ) || { echo "he-log build failed"; exit 1; }

MAXN=12 BIN="$BIN" TMP="$TMP" python3 - > "$ROOT/onchain/test/consistency_cases.json" <<'PY'
import json, os, subprocess
binp, tmp, maxn = os.environ["BIN"], os.environ["TMP"], int(os.environ["MAXN"])
oldSize, newSize, oldRoot, newRoot, proof = [], [], [], [], []
for m in range(2, maxn + 1):
    log = os.path.join(tmp, f"log{m}.json")
    for i in range(1, m + 1):
        subprocess.run([binp, "add", "--log", log, "%02x" % i], check=True, stdout=subprocess.DEVNULL)
    for old in range(1, m):
        out = subprocess.run([binp, "consistency", "--log", log, "--index", str(old)],
                             check=True, capture_output=True, text=True).stdout
        d = json.loads(out)
        assert d["old_size"] == old and d["new_size"] == m, (d["old_size"], d["new_size"], old, m)
        oldSize.append(d["old_size"]); newSize.append(d["new_size"])
        oldRoot.append("0x" + d["old_root"]); newRoot.append("0x" + d["new_root"])
        proof.append("0x" + "".join(d["proof"]))  # concatenated 32-byte nodes (may be empty -> 0x)
print(json.dumps({"oldSize": oldSize, "newSize": newSize,
                  "oldRoot": oldRoot, "newRoot": newRoot, "proof": proof}, indent=0))
PY

n=$(python3 -c "import json;print(len(json.load(open('$ROOT/onchain/test/consistency_cases.json'))['oldSize']))")
echo "wrote onchain/test/consistency_cases.json: $n (oldSize->newSize) consistency cases"
