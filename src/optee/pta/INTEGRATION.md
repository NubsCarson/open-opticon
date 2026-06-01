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

## Why this is safe

`cmd_sign_data` adds no new crypto: it forwards to `sign_ecdsa_sha256()`, the
exact primitive that already signs attestation evidence. It validates param
types, rejects short output buffers (with a size hint), and only reads the
documented slice of the optional key blob. The signed message is opaque to the
PTA — binding semantics live entirely in the canonical payload the caller
builds.
