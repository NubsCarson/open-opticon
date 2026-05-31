#!/usr/bin/env bash
#
# Launch every local open-opticon web surface at once and print their URLs:
#   1. the landing site (static)         2. the click-to-listen web UI
#   3. the challenge server + phone /v page
# Ctrl-C stops all of them. Ports are overridable via env.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LANDING_PORT="${LANDING_PORT:-8099}"
GUI_PORT="${GUI_PORT:-8095}"
CHAL_PORT="${CHAL_PORT:-8090}"

command -v go      >/dev/null || { echo "need: go"; exit 2; }
command -v python3 >/dev/null || { echo "need: python3"; exit 2; }

pids=()
cleanup(){ echo; echo "stopping…"; for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done; exit 0; }
trap cleanup INT TERM

echo "building…"
make -C "$ROOT/sim" all >/dev/null || { echo "sim build failed"; exit 1; }
( cd "$ROOT/src/verifier" \
    && GOPROXY=off go build -o /tmp/oo-he-gui ./cmd/he-gui \
    && GOPROXY=off go build -o /tmp/oo-he-challenge ./cmd/he-challenge ) \
  || { echo "go build failed"; exit 1; }

python3 -m http.server -d "$ROOT/docs" "$LANDING_PORT" >/dev/null 2>&1 & pids+=($!)
/tmp/oo-he-gui --addr ":$GUI_PORT" --sim "$ROOT/sim/bin/he-attest-sim" >/dev/null 2>&1 & pids+=($!)
/tmp/oo-he-challenge --addr ":$CHAL_PORT" --base-url "http://localhost:$CHAL_PORT" >/dev/null 2>&1 & pids+=($!)
sleep 1.5

sid="$(curl -s "http://localhost:$CHAL_PORT/challenge" \
       | python3 -c 'import sys,json;print(json.load(sys.stdin).get("session",""))' 2>/dev/null)"

cat <<EOF

  open-opticon — local sites running

  Landing site       http://localhost:$LANDING_PORT
  Click-to-listen    http://localhost:$GUI_PORT
  Challenge server   http://localhost:$CHAL_PORT
  Phone verify (/v)  http://localhost:$CHAL_PORT/v?session=$sid

  Ctrl-C to stop all.
EOF
wait
