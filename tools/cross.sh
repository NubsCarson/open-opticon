#!/usr/bin/env bash
#
# Cross-compile the Go verifier tools for Raspberry Pi (and amd64).
#
# The verifier is pure Go stdlib with CGO disabled, so it cross-compiles to any
# target with no toolchain: arm64 (Pi 3B+/4/5 on a 64-bit OS) and armv7 (32-bit
# Raspberry Pi OS). The C detector/host code builds natively on the Pi with gcc
# (see docs/RUNBOOK.md); these are the off-device / on-Pi verifier binaries.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE/src/verifier"
export CGO_ENABLED=0 GOPROXY=off GOFLAGS="-trimpath -buildvcs=false"

tools=(he-verify he-log he-challenge he-gui)
targets=("linux amd64" "linux arm64" "linux arm 7")

for t in "${targets[@]}"; do
  read -r os arch arm <<<"$t"
  label="${os}-${arch}${arm:+v$arm}"
  out="$HERE/dist/$label"
  mkdir -p "$out"
  export GOOS="$os" GOARCH="$arch"
  if [ -n "$arm" ]; then export GOARM="$arm"; else unset GOARM; fi
  for c in "${tools[@]}"; do
    go build -ldflags=-buildid= -o "$out/$c" "./cmd/$c"
  done
  echo "built ${tools[*]}  ->  dist/$label/"
done
