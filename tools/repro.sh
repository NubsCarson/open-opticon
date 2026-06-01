#!/usr/bin/env bash
#
# Reproducible-build proof for the host artifacts.
#
# Builds the C simulator/detector + the Go verifier tools TWICE, in two separate
# trees at different absolute paths, with deterministic flags, then compares the
# SHA-256 of every binary. Identical hashes prove the build does not depend on
# the build path, the wall-clock time, or the machine — so anyone can recompute
# the exact bytes from source. This is the "verify, don't trust the maintainer's
# box" property applied to the parts that build on any laptop. (The OP-TEE TA's
# measurement is re-derived separately — see docs/REPRODUCIBLE.md.)
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
# A fixed epoch so any embedded timestamp is constant across rebuilds.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"

A="$(mktemp -d /tmp/oo-repro-a.XXXXXX)"
B="$(mktemp -d /tmp/oo-repro-bb.XXXXXX)"   # deliberately different-length path
trap 'rm -rf "$A" "$B"' EXIT

# Copy only the source needed for the host build (no .git, assets, or artifacts).
copy_src() {
  local dst="$1"
  tar -C "$HERE" \
      --exclude='.git' --exclude='docs/assets' --exclude='*/bin' --exclude='bin' \
      -cf - sim src test Makefile | tar -C "$dst" -xf -
}

# Build host artifacts in $1 with path-independent, deterministic flags.
build_tree() {
  local d="$1"
  local cflags="-O2 -std=c11 -g0 -fno-ident -ffile-prefix-map=$d=."
  make -C "$d/sim" all CFLAGS="$cflags" >/dev/null 2>&1
  ( cd "$d/src/verifier"
    export CGO_ENABLED=0 GOPROXY=off GOFLAGS="-trimpath -buildvcs=false"
    for c in he-verify he-log he-challenge he-gui he-dump he-logd he-witness he-attest-verify; do
      go build -ldflags=-buildid= -o "$d/bin-$c" "./cmd/$c"
    done
    # The in-browser verifier ships as a committed wasm artifact; prove it is
    # byte-reproducible too (same determinism flags as tools/build_wasm.sh).
    GOOS=js GOARCH=wasm go build -ldflags="-s -w -buildid=" -o "$d/verify.wasm" ./cmd/he-verify-wasm )
}

# Print "sha256  basename" for every produced binary, sorted by name.
hash_tree() {
  local d="$1"
  { sha256sum "$d"/sim/bin/* "$d"/bin-* "$d"/verify.wasm ; } |
    sed -E "s# .*/# #" | awk '{print $1"  "$2}' | sort -k2
}

echo "Building tree A: $A"
copy_src "$A"; build_tree "$A"
echo "Building tree B: $B"
copy_src "$B"; build_tree "$B"

echo
echo "artifact hashes:"
ha="$(hash_tree "$A")"; hb="$(hash_tree "$B")"
echo "$ha" | sed 's/^/  /'

if [ "$ha" = "$hb" ]; then
  echo
  echo -e "\033[1;32mREPRODUCIBLE\033[0m  all host artifacts are byte-identical across two independent build trees."
  exit 0
fi
echo
echo -e "\033[1;31mNOT REPRODUCIBLE\033[0m  hashes differ:"
diff <(echo "$ha") <(echo "$hb") || true
exit 1
