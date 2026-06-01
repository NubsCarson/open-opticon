# PTA integration — add `SIGN_DATA` to optee-ra's platform TA

All three edits are inside `optee-ra/attester/pta_remote_attestation/`.

## 1. Add the command id — `pta_remote_attestation.h`

After the existing command defines (`...GET_CBOR_EVIDENCE`, `...GENERATE_KEYPAIR`,
`...CONVERT_TO_BLACKKEY`):

```c
/*
 * Sign an arbitrary message with the attestation key (ECDSA-P256/SHA-256).
 * [in]      memref[0]  message
 * [out/inout] memref[1]  signature (INOUT or OUTPUT; >=64 bytes; 64-byte r||s on return)
 * [in]      memref[2]  (optional) packed key: PubX(32)||PubY(32)||blob(N)
 */
#define PTA_REMOTE_ATTESTATION_SIGN_DATA 0x3
```

## 2. Add the function — `remote_attestation/remote_attestation.c`

Paste the `cmd_sign_data()` body from `pta_sign_data.c` immediately **before**
`invoke_command()`. Note it is intentionally **outside** the `#ifdef
CFG_NXP_CAAM` block (it works on QEMU using the embedded key). It uses
`sign_ecdsa_sha256()` (already declared via the existing `#include "sign.h"`)
and the already-defined `MIN_KEY_PARAM_SIZE` / `PUBKEY_HEADER_SIZE`.

## 3. Add the dispatch case — `invoke_command()` in the same file

```c
    switch (cmd_id) {
    case PTA_REMOTE_ATTESTATION_GET_CBOR_EVIDENCE:
        return cmd_get_cbor_evidence(param_types, params);
    case PTA_REMOTE_ATTESTATION_SIGN_DATA:          /* <-- add this */
        return cmd_sign_data(param_types, params);  /*     (not CAAM-gated) */
#ifdef CFG_NXP_CAAM
    case PTA_REMOTE_ATTESTATION_GENERATE_KEYPAIR:
        return cmd_generate_keypair(param_types, params);
    case PTA_REMOTE_ATTESTATION_CONVERT_TO_BLACKKEY:
        return cmd_convert_to_blackkey(param_types, params);
#endif
    default:
        break;
    }
```

No `sub.mk` change is needed (same file). The PTA is already gated by
`CFG_REMOTE_ATTESTATION_PTA`.

## Security — two checks you MUST add

`cmd_sign_data` adds no new crypto: it forwards to `sign_ecdsa_sha256()`, the
exact primitive that already signs attestation evidence, validates param types,
rejects short output buffers (with a size hint), and reads only the documented
slice of the optional key blob.

But the signed message is **opaque** to the PTA, and because the canonical payload
format is fully public (`he_payload.h`), that opacity is a *liability*, not a
safety property: an unrestricted `SIGN_DATA` is a **forging oracle** — the normal
world could build any predicate it likes (any event/presence/counter/nonce) and
get a valid signature *without the in-TEE detector ever running*. So this command
is safe only with **both** of the following. They are mandatory, not optional:

1. **Restrict the caller to the audio TA.** Gate the command on the calling TA's
   identity/UUID so it is NOT reachable from the normal world the way
   `GET_CBOR_EVIDENCE` is. The audio TA opens its PTA session in the secure world;
   only that caller should be able to reach `SIGN_DATA`.
2. **Gate on the tamper flag.** Refuse to sign when the tamper latch is set — the
   same check `he_attest_audio` performs — so a tampered device whose embedded key
   was not physically destroyed (the QEMU case) cannot keep signing.

Without these, the bound-output guarantees in
[`THREAT_MODEL.md`](../../../docs/THREAT_MODEL.md) ("cannot forge the bound
output"; "tamper → attestation FAIL") do **not** hold. The audio path enforces
both today; doing so for every key-using command is tracked in
[`ROADMAP.md`](../../../docs/ROADMAP.md) ("centralized tamper gate").
