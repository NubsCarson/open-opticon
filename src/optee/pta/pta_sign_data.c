/*
 * Honest Ear — PTA_REMOTE_ATTESTATION_SIGN_DATA command.
 *
 * Add this command to optee-ra's platform TA so the enclave can sign an
 * arbitrary message (the canonical bound-output payload) with the SAME key it
 * uses for attestation evidence — the embedded test key on QEMU, or the
 * non-extractable CAAM black key on i.MX 8M Plus. This is what BINDS the
 * detector's output to the attested key.
 *
 * It is a thin, reviewed wrapper over the existing, already-tested
 * sign_ecdsa_sha256() (sign.c): SHA-256(msg) then ECDSA-P256, output 64-byte
 * r||s (RFC 7518). Crucially it lives OUTSIDE the CFG_NXP_CAAM guard, so it
 * works on the QEMU path too.
 *
 * INTEGRATION: paste this function into
 *   attester/pta_remote_attestation/remote_attestation/remote_attestation.c
 * (next to cmd_convert_to_blackkey), add the dispatch case in invoke_command(),
 * and add the command id to pta_remote_attestation.h. See INTEGRATION.md.
 *
 * SECURITY (MANDATORY — the whole bound-output guarantee depends on these):
 *   1. RESTRICT THE CALLER. This command signs an ARBITRARY caller-supplied
 *      message with the attestation key, and the canonical payload format is
 *      fully public (see he_payload.h). An unrestricted command is therefore a
 *      forging oracle: the normal world could build any predicate it likes and
 *      get a valid signature WITHOUT the in-TEE detector ever running. It MUST be
 *      reachable only from the in-TEE audio TA — gate on the caller's UUID in the
 *      PTA; do NOT leave it normal-world invocable the way GET_CBOR_EVIDENCE is.
 *   2. GATE ON TAMPER. Refuse to sign when the tamper flag is latched, exactly as
 *      he_attest_audio does (he_audio_ta.c), so an opened device whose embedded
 *      key was not physically destroyed (the QEMU case) cannot keep signing. The
 *      latch must cover EVERY key-using command, not only the audio path.
 * Neither check is shown in the body below (the flag/identity live in the
 * optee-ra TA this snippet grafts into); both are required, not optional.
 *
 * This file is NOT compiled standalone; it documents the exact function body
 * to graft in. It relies on symbols already present in remote_attestation.c:
 *   sign_ecdsa_sha256()  (from sign.h, already #included)
 *   MIN_KEY_PARAM_SIZE, PUBKEY_HEADER_SIZE  (already #defined)
 */

/*
 * Normalize an ECDSA P-256 signature to canonical LOW-S in place: the signature
 * is 64 bytes r||s big-endian, so this operates on sig[32..63] (s). If s > N/2 it
 * is replaced with N - s. This is MANDATORY, not cosmetic: the host/WASM verifier
 * (VerifyBundle / VerifyCOSEBundle Gate 1b) and the on-chain OpenZeppelin P256
 * verifier BOTH reject high-s, while sign_ecdsa_sha256() returns a uniformly
 * random s that is high ~half the time. Without this, ~50% of honest device
 * bundles would be rejected by the very verifier they bind to. Done with plain
 * big-endian byte arithmetic so it needs no bignum/crypto API in the TA.
 */
static void he_normalize_low_s(uint8_t *sig)
{
    /* secp256r1 group order N and floor(N/2), big-endian 32-byte constants. */
    static const uint8_t N[32] = {
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51
    };
    static const uint8_t N_HALF[32] = {
        0x7F,0xFF,0xFF,0xFF,0x80,0x00,0x00,0x00,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xDE,0x73,0x7D,0x56,0xD3,0x8B,0xCF,0x42,0x79,0xDC,0xE5,0x61,0x7E,0x31,0x92,0xA8
    };
    uint8_t *s = sig + 32;
    int gt = 0; /* s > N/2 ? compare big-endian, MSB first */
    for (size_t i = 0; i < 32; i++) {
        if (s[i] != N_HALF[i]) { gt = s[i] > N_HALF[i]; break; }
    }
    if (!gt)
        return; /* already canonical low-s */
    int borrow = 0; /* s = N - s, big-endian subtraction */
    for (int i = 31; i >= 0; i--) {
        int d = (int)N[i] - (int)s[i] - borrow;
        if (d < 0) { d += 256; borrow = 1; } else { borrow = 0; }
        s[i] = (uint8_t)d;
    }
}

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
    if (sig_len != 64) /* P-256 r||s is exactly 64 bytes; refuse anything else */
        return TEE_ERROR_GENERIC;

    /* Canonicalize to low-s so the device matches the verifier/chain it binds to. */
    he_normalize_low_s(sig);

    params[1].memref.size = sig_len; /* 64 for P-256 r||s */
    return TEE_SUCCESS;
}
