#!/usr/bin/env bash
#
# Stage Honest Ear sources into an optee-ra checkout so the TA/PTA/host can be
# built on the rig. Copies files only; the three small code edits per
# INTEGRATION.md still need to be applied (this script prints a checklist and
# verifies whether each edit is already present).
#
#   tools/stage_optee.sh /path/to/optee-ra
#
set -euo pipefail

OPTEE="${1:-}"
[ -n "$OPTEE" ] || { echo "usage: $0 /path/to/optee-ra"; exit 2; }
[ -d "$OPTEE/attester" ] || { echo "error: $OPTEE does not look like optee-ra"; exit 1; }

HE="$(cd "$(dirname "$0")/.." && pwd)"
COMMON="$HE/src/common"
TA_DIR="$OPTEE/attester/remote_attestation/ta"
PTA_DIR="$OPTEE/attester/pta_remote_attestation/remote_attestation"
HOST_DIR="$OPTEE/attester/remote_attestation/host"

echo "== copying shared sources into TA dir =="
cp -v "$COMMON/he_detector.c" "$COMMON/he_detector.h" \
      "$COMMON/he_payload.c"  "$COMMON/he_payload.h"  "$TA_DIR/"
cp -v "$HE/src/optee/ta/he_audio_ta.c" "$HE/src/optee/ta/he_audio_ta.h" "$TA_DIR/"

# The PTA client header must be on the TA's include path: the TA dev kit only
# exports PTA headers from lib/libutee/include, NOT core/include, so the TA (and
# he_audio_ta.c) cannot see core/include/pta_remote_attestation.h. The TA already
# does `global-incdirs-y += include`, so drop it there. (Verified necessary by a
# real on-rig build; see src/optee/ta/INTEGRATION.md.)
cp -v "$OPTEE/attester/pta_remote_attestation/pta_remote_attestation.h" "$TA_DIR/include/"

echo "== copying host client =="
# he_host.c is a normal-world libteec client: it needs only he_testkey.h plus
# the TA command ids from remote_attestation_ta.h (added per src/optee/ta/INTEGRATION.md).
cp -v "$HE/src/optee/host/he_host.c" "$COMMON/he_testkey.h" "$HOST_DIR/"

# The PTA cmd_sign_data() body is applied by hand into remote_attestation.c per
# pta/INTEGRATION.md (it is NOT a standalone source file). We intentionally do
# NOT copy a .c into the PTA dir, to avoid an accidental duplicate-symbol build.
echo "== PTA: apply cmd_sign_data() per src/optee/pta/INTEGRATION.md =="

echo
echo "== manual edit checklist =="
check() { # file pattern description
    if grep -q "$2" "$1" 2>/dev/null; then
        echo "  [done] $3"
    else
        echo "  [TODO] $3 -> $1"
    fi
}
check "$PTA_DIR/../pta_remote_attestation.h" "SIGN_DATA" "PTA: define PTA_REMOTE_ATTESTATION_SIGN_DATA 0x3"
check "$PTA_DIR/remote_attestation.c" "cmd_sign_data" "PTA: add cmd_sign_data() + dispatch case"
check "$TA_DIR/include/remote_attestation_ta.h" "ATTEST_AUDIO" "TA: define TA_REMOTE_ATTESTATION_CMD_ATTEST_AUDIO 3"
check "$TA_DIR/remote_attestation_ta.c" "he_attest_audio" "TA: include he_audio_ta.h + ATTEST_AUDIO dispatch case"
check "$TA_DIR/remote_attestation_ta.c" "he_trip_tamper" "TA: add TRIP_TAMPER dispatch case"
check "$TA_DIR/sub.mk" "he_audio_ta.c" "TA: add he_*.c to sub.mk"
echo
echo "Done staging. See src/optee/{pta,ta,host}/INTEGRATION.md for the edits."
