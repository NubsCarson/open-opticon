#!/usr/bin/env bash
#
# Generate onchain/test/checkpoint_fixture.json — a REAL RFC 9162 consistency
# proof (tree size 3 -> 5) from a he-log transparency log, 0x-prefixed for
# Foundry. Reproducible; commit the output so `forge test` needs no Go toolchain.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$ROOT/src/verifier"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
LOG="$TMP/log.json"

for h in aa bb cc dd ee; do
    ( cd "$V" && GOPROXY=off go run ./cmd/he-log add --log "$LOG" "$h" ) >/dev/null \
        || { echo "he-log add failed"; exit 1; }
done

( cd "$V" && GOPROXY=off go run ./cmd/he-log consistency --log "$LOG" --index 3 ) \
    | python3 -c "
import json, sys
d = json.load(sys.stdin)
out = {
    'oldSize': d['old_size'], 'newSize': d['new_size'],
    'oldRoot': '0x' + d['old_root'], 'newRoot': '0x' + d['new_root'],
    'proof': ['0x' + x for x in d['proof']],
}
print(json.dumps(out, indent=2))
" > "$ROOT/onchain/test/checkpoint_fixture.json" || { echo "gen failed"; exit 1; }

echo "wrote onchain/test/checkpoint_fixture.json:"
cat "$ROOT/onchain/test/checkpoint_fixture.json"
