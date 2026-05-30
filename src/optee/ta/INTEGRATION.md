# TA integration — add `ATTEST_AUDIO` to optee-ra's user TA

Edits are in `optee-ra/attester/remote_attestation/ta/`. Run
`tools/stage_optee.sh /path/to/optee-ra` first to copy the shared sources
(`he_detector.[ch]`, `he_payload.[ch]`, `he_audio_ta.[ch]`) into the TA dir.

## 1. Command id — `include/remote_attestation_ta.h`

Add next to the existing command defines:

```c
#define TA_REMOTE_ATTESTATION_CMD_ATTEST_AUDIO 3
#define TA_REMOTE_ATTESTATION_CMD_TRIP_TAMPER  4
```

## 2. Dispatch + include — `remote_attestation_ta.c`

Near the top:

```c
#include "he_audio_ta.h"
```

In `TA_InvokeCommandEntryPoint`'s switch, add:

```c
    case TA_REMOTE_ATTESTATION_CMD_ATTEST_AUDIO:
        return he_attest_audio(param_types, params);
    case TA_REMOTE_ATTESTATION_CMD_TRIP_TAMPER:
        return he_trip_tamper();
```

## 3. Build — `ta/sub.mk`

```make
global-incdirs-y += include
srcs-y += remote_attestation_ta.c
srcs-y += he_audio_ta.c
srcs-y += he_detector.c
srcs-y += he_payload.c
```

## 4. Resources — `ta/user_ta_header_defines.h`

The command uses a small payload buffer, a SHA-256 op, a PTA session, and the
Trusted-Storage counter. Bump the provisioned sizes to be safe:

```c
#define TA_STACK_SIZE (4 * 1024)
#define TA_DATA_SIZE  (32 * 1024)
```

## 5. PTA prerequisite

Requires `PTA_REMOTE_ATTESTATION_SIGN_DATA` (see `../pta/INTEGRATION.md`).

## Gotchas (verified by a real on-rig build → green Veraison attestation)

1. **PTA header must be on the TA include path.** The TA dev kit only exports
   PTA headers from `lib/libutee/include`, not `core/include`, so the TA and
   `he_audio_ta.c` can't find `core/include/pta_remote_attestation.h`. Fix: copy
   `pta_remote_attestation.h` into `ta/include/` (the TA already adds `include`
   to its incdirs). `tools/stage_optee.sh` does this for you.
2. **GP 1.1 compat API uses `uint32_t *` length params.** The TA Makefile sets
   `CFG_TA_OPTEE_CORE_API_COMPAT_1_1=y`, so `TEE_ReadObjectData` and
   `TEE_DigestDoFinal` take `uint32_t *` (not `size_t *`) for their length/count
   out-params. `he_audio_ta.c` uses `uint32_t` accordingly — don't "modernize"
   these to `size_t` or you get a silent 4-vs-8-byte write on 64-bit.
3. **Reference values must match the TA's measurement.** Adding our in-enclave
   code changes the TA's measured hash, so re-provision the reference value to
   the measurement the run reports (status goes `warning` → `affirming`). See
   `../../docs/SAMPLE_ATTESTATION.md` and `RUNBOOK.md` §B2.

## Data flow recap

`he_attest_audio` runs the detector over the audio in the secure world,
zeroizes the audio (`TEE_MemFill`), builds the canonical payload (nonce +
predicate + monotonic counter + policy hash), and calls the PTA to sign it with
the attested key. It returns `u16_be(payload_len) || payload || sig[64]`. The
host (`he_host.c`) reframes that as the JSON bundle the verifier consumes.

The audio buffer is normal-world shared memory in this PoC (host reads a file).
For a production sensor the PCM must originate in the secure world (I2S/PDM into
secure RAM) so the normal world never sees it — see ARCHITECTURE.md.
