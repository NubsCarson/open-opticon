#!/usr/bin/env bash
#
# Build the in-browser verifier: compile the stdlib-only Go verifier package to
# WebAssembly and drop it + the matching Go wasm runtime next to the static site
# (docs/), so docs/verify.html can verify a bundle entirely client-side — same
# code path as the he-verify CLI, no server, no install.
#
# Reproducible: -trimpath + stripped + cleared build id, like tools/repro.sh. The
# wasm_exec.js MUST come from the SAME Go toolchain that compiled the .wasm (the
# JS runtime and the binary are version-locked), so we copy it from this GOROOT.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/docs"
GOROOT="$(go env GOROOT)"

WASM_EXEC=""
for cand in "$GOROOT/lib/wasm/wasm_exec.js" "$GOROOT/misc/wasm/wasm_exec.js"; do
    [ -f "$cand" ] && WASM_EXEC="$cand" && break
done
[ -n "$WASM_EXEC" ] || { echo "error: wasm_exec.js not found under $GOROOT"; exit 1; }

echo "building docs/verify.wasm (GOOS=js GOARCH=wasm)"
( cd "$ROOT/src/verifier"
  GOOS=js GOARCH=wasm CGO_ENABLED=0 GOFLAGS="-buildvcs=false" \
    go build -trimpath -ldflags="-s -w -buildid=" -o "$OUT/verify.wasm" ./cmd/he-verify-wasm )

cp "$WASM_EXEC" "$OUT/wasm_exec.js"

echo "  $(go version)"
echo "  verify.wasm   $(wc -c < "$OUT/verify.wasm") bytes"
echo "  wasm_exec.js  copied from $WASM_EXEC"
echo "open docs/verify.html (served over HTTP — e.g. 'make sites') to verify a bundle in-browser."
