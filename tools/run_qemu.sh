#!/usr/bin/env bash
#
# Honest Ear — one-command driver for the QEMU bring-up (RUNBOOK Phase B).
#
# Automates the DETERMINISTIC, non-interactive setup:
#   preflight -> Veraison up -> provisioning -> relying party -> attester container.
# The final OP-TEE build+QEMU step (upstream README 4.4/4.5) is interactive
# (separate normal/secure terminals, guest login), so this script stages it and
# prints the exact remaining commands rather than pretending to drive the
# console unattended.
#
# Usage:  tools/run_qemu.sh /path/to/optee-ra
#
# SAFETY: refuses to run if free disk < MIN_FREE_GB (the OP-TEE+Veraison build
# needs 30-40 GB; running it on a near-full root filesystem can fill it to 100%).
set -euo pipefail

OPTEE="${1:-}"
VERAISON_COMMIT="8f5734c"   # pinned per upstream README
MIN_FREE_GB="${MIN_FREE_GB:-45}"

die() { echo "error: $*" >&2; exit 1; }
hr()  { printf '%s\n' "------------------------------------------------------------"; }

[ -n "$OPTEE" ] || die "usage: $0 /path/to/optee-ra"
[ -d "$OPTEE/attester" ] || die "$OPTEE does not look like an optee-ra checkout"
OPTEE="$(cd "$OPTEE" && pwd)"
HE="$(cd "$(dirname "$0")/.." && pwd)"

echo "== preflight =="
command -v docker >/dev/null || die "docker not installed"
docker info >/dev/null 2>&1 || die "docker daemon not running (try: sudo systemctl start docker)"
command -v jq >/dev/null || die "jq not installed (apt-get install jq)"
command -v git >/dev/null || die "git not installed"

# Disk guard — protects the host from a runaway 30-40 GB build.
free_gb=$(df -PBG "$OPTEE" | awk 'NR==2{gsub("G","",$4); print $4}')
echo "  free disk at $OPTEE: ${free_gb} GB (need >= ${MIN_FREE_GB} GB)"
if [ "${free_gb:-0}" -lt "$MIN_FREE_GB" ]; then
    die "insufficient disk (${free_gb} GB < ${MIN_FREE_GB} GB). Free space, point Docker's data-root at a larger volume, or set MIN_FREE_GB to override at your own risk."
fi
echo "  docker + jq + disk OK"

echo "== verify Honest Ear is staged into the tree =="
if ! grep -q "he_attest_audio" "$OPTEE/attester/remote_attestation/ta/remote_attestation_ta.c" 2>/dev/null; then
    echo "  staging not detected; running stage_optee.sh ..."
    bash "$HE/tools/stage_optee.sh" "$OPTEE"
    die "applied file copies; now apply the INTEGRATION.md edits (or use a pre-staged tree) and re-run"
fi
echo "  ATTEST_AUDIO dispatch present — tree looks staged"

cd "$OPTEE"

echo "== 1. Veraison services =="
if [ ! -d services ]; then
    git clone https://github.com/veraison/services.git
    ( cd services && git checkout "$VERAISON_COMMIT" )
fi
make -C services docker-deploy
# shellcheck disable=SC1091
source services/deployments/docker/env.bash
veraison status

echo "== 2. provisioning (QEMU reference values) =="
./provisoning/run.sh qemu

echo "== 3. relying party =="
./relying_party/container/start.sh

echo "== 4. attester container =="
./attester/container/start.sh

hr
cat <<EOF
SETUP COMPLETE. Finish the interactive QEMU step in TWO more terminals:

  # terminal A (normal world console):
  ${OPTEE}/attester/container/launch_soc_term.sh normal
  # terminal B (secure world console):
  ${OPTEE}/attester/container/launch_soc_term.sh secure

  # then, in the attester container shell, build + boot QEMU (builds our TA/PTA/host):
  make -C \${OPTEE_DIR}/build run CFG_REMOTE_ATTESTATION_PTA=y -j

  # in the QEMU NORMAL-world login (user: root), run:
  optee_remote_attestation                 # firmware attestation -> Veraison PASS
  he_host <clip.pcm> <nonce>               # Honest Ear bound output  (see RUNBOOK B3)

Generate a clip with: python3 ${HE}/test/gen_frames.py /tmp/fix  (then use /tmp/fix/alarm.pcm)
Get a fresh nonce from the verifier:  cd ${HE}/src/verifier && go run ./cmd/he-challenge
Verify the bundle:                    go run ./cmd/he-verify --nonce <N> bundle.json

Full walkthrough: ${HE}/docs/RUNBOOK.md  (Phase B3/B4/B5)
EOF
hr
