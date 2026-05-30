/*
 * Honest Ear — PTA_REMOTE_ATTESTATION_SIGN_DATA command.
 *
 * Add this command to optee-ra's platform TA so the enclave can sign an
 * arbitrary message (the canonical bound-output payload) with the SAME key it
 * uses for attestation evidence — the embedded test key on QEMU, or the
 * non-extractable CAAM black key on i.MX 8M Plus. This is what BINDS the
 * detector's output to the attested key.
 *
 * It is a thin, audited wrapper over the existing, already-tested
 * sign_ecdsa_sha256() (sign.c): SHA-256(msg) then ECDSA-P256, output 64-byte
 * r||s (RFC 7518). Crucially it lives OUTSIDE the CFG_NXP_CAAM guard, so it
 * works on the QEMU path too.
 *
 * INTEGRATION: paste this function into
 *   attester/pta_remote_attestation/remote_attestation/remote_attestation.c
 * (next to cmd_convert_to_blackkey), add the dispatch case in invoke_command(),
 * and add the command id to pta_remote_attestation.h. See INTEGRATION.md.
 *
 * This file is NOT compiled standalone; it documents the exact function body
 * to graft in. It relies on symbols already present in remote_attestation.c:
 *   sign_ecdsa_sha256()  (from sign.h, already #included)
 *   MIN_KEY_PARAM_SIZE, PUBKEY_HEADER_SIZE  (already #defined)
 */

/*
 * PTA_REMOTE_ATTESTATION_SIGN_DATA
 *   [in]  memref[0]  message to sign (canonical bound-output payload)
 *   [out] memref[1]  signature out; INOUT or OUTPUT; >= 64 bytes; r||s on return
 *   [in]  memref[2]  (optional) packed key: PubX(32)||PubY(32)||blob(N),
 *                    identical wire format to the evidence command's param[3].
 *                    Absent => use the embedded key (QEMU) / default.
 */
static TEE_Result cmd_sign_data(uint32_t param_types,
                                TEE_Param params[TEE_NUM_PARAMS])
{
    const uint8_t *msg = params[0].memref.buffer;
    size_t msg_len = params[0].memref.size;
    uint8_t *sig = params[1].memref.buffer;
    size_t sig_cap = params[1].memref.size;
    const uint8_t *black_key = NULL;
    size_t black_key_len = 0;
    size_t sig_len;
    TEE_Result res;

    /* Accept signature buffer as INOUT or OUTPUT, with or without a key. */
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_INOUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE) &&
        param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE) &&
        param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_INOUT,
                                       TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_NONE) &&
        param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (!msg || !msg_len || !sig)
        return TEE_ERROR_BAD_PARAMETERS;
    if (sig_cap < 64) {
        params[1].memref.size = 64;
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Optional key: PubX||PubY||blob — only the blob is used for signing. */
    if (TEE_PARAM_TYPE_GET(param_types, 2) == TEE_PARAM_TYPE_MEMREF_INPUT) {
        const uint8_t *p2 = params[2].memref.buffer;
        size_t p2_len = params[2].memref.size;

        if (!p2 || p2_len < MIN_KEY_PARAM_SIZE)
            return TEE_ERROR_BAD_PARAMETERS;
        black_key = p2 + PUBKEY_HEADER_SIZE;
        black_key_len = p2_len - PUBKEY_HEADER_SIZE;
    }

    sig_len = sig_cap;
    res = sign_ecdsa_sha256(msg, msg_len, sig, &sig_len, black_key,
                            black_key_len);
    if (res != TEE_SUCCESS)
        return res;

    params[1].memref.size = sig_len; /* 64 for P-256 r||s */
    return TEE_SUCCESS;
}
