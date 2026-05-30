#!/usr/bin/env bash
#
# open-opticon — launch the browser GUI (click-to-listen).
#
# Builds the host simulator + the GUI server, then serves a clean web UI:
# tap the mic, it listens in ~1.5s windows, runs the real detect -> sign ->
# verify pipeline on each window, and shows a plain-language verified result.
# The browser only sends downsampled PCM to localhost; audio is discarded after
# the predicate is produced.
#
#   tools/run_gui.sh            # http://localhost:8095
#   HE_ADDR=:9000 tools/run_gui.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ADDR="${HE_ADDR:-:8095}"

command -v go  >/dev/null || { echo "need: go";  exit 2; }
command -v gcc >/dev/null || { echo "need: gcc"; exit 2; }

echo "building simulator + GUI..."
make -C "$ROOT/sim" all >/dev/null || { echo "sim build failed"; exit 1; }
( cd "$ROOT/src/verifier" && GOPROXY=off go build -o /tmp/he-gui ./cmd/he-gui ) || { echo "gui build failed"; exit 1; }

URL="http://localhost${ADDR}"
echo "open-opticon GUI ready → ${URL}"
# best-effort: open a browser (ignored if headless)
( command -v xdg-open >/dev/null && xdg-open "$URL" >/dev/null 2>&1 ) || true

exec /tmp/he-gui --addr "$ADDR" --sim "$ROOT/sim/bin/he-attest-sim"
