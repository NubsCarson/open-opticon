/*
 * Honest Ear — TA-side attest-audio command.
 *
 * This is the heart of the non-panopticon guarantee, expressed in code:
 *   1. run the audited detector over the audio INSIDE the secure world,
 *   2. ZEROIZE the raw audio immediately,
 *   3. build the canonical bound-output payload (nonce + minimal predicate +
 *      monotonic counter + policy hash),
 *   4. have the PTA sign it with the SAME attested key (CAAM black key on
 *      i.MX, embedded key on QEMU),
 *   5. return only {payload, signature}. No audio, ever.
 *
 * Compiles inside the OP-TEE TA dev kit (not on a normal host). The detector
 * and payload encoder are the very same sources the host tests exercise.
 */
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <stdbool.h>
#include <string.h>

#include <pta_remote_attestation.h>
#include <remote_attestation_ta.h>

#include "he_audio_ta.h"
#include "he_detector.h"
#include "he_payload.h"

/* Persistent monotonic counter object id (Trusted Storage). */
static const char HE_COUNTER_ID[] = "honest-ear.counter.v1";
/* Persistent tamper-tripped marker object id. */
static const char HE_TAMPER_ID[] = "honest-ear.tamper.v1";

/*
 * True if the device is tampered. Fails CLOSED: only a clean "marker absent"
 * (ITEM_NOT_FOUND) re-enables attestation — a corrupt or unreadable marker
 * (exactly an attacker's signature) is treated as tripped.
 */
static bool he_tamper_tripped(void)
{
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    TEE_Result res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE, HE_TAMPER_ID, sizeof(HE_TAMPER_ID) - 1,
        TEE_DATA_FLAG_ACCESS_READ, &obj);
    if (res == TEE_SUCCESS) {
        TEE_CloseObject(obj);
        return true;
    }
    return res != TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result he_trip_tamper(void)
{
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    const uint8_t one = 1;
    TEE_Result res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE, HE_TAMPER_ID, sizeof(HE_TAMPER_ID) - 1,
        TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, &one, sizeof(one), &obj);
    if (res == TEE_SUCCESS)
        TEE_CloseObject(obj);
    else if (res == TEE_ERROR_ACCESS_CONFLICT)
        res = TEE_SUCCESS; /* already tripped */
    return res;
}

/*
 * Return the next monotonic counter value from secure storage.
 * NOTE: OP-TEE Trusted Storage is rollback-protected only if the platform
 * provides anti-rollback (RPMB on i.MX). On QEMU it is best-effort; the
 * counter still defeats in-session replay. See THREAT_MODEL.md.
 */
static TEE_Result he_counter_next(uint64_t *out)
{
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
    uint64_t val = 0;
    uint32_t got = 0; /* GP 1.1 compat API (CFG_TA_OPTEE_CORE_API_COMPAT_1_1) uses uint32_t* */
    TEE_Result res;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, HE_COUNTER_ID,
                                   sizeof(HE_COUNTER_ID) - 1, flags, &obj);
    if (res == TEE_ERROR_ITEM_NOT_FOUND) {
        val = 0;
        res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, HE_COUNTER_ID,
                                         sizeof(HE_COUNTER_ID) - 1, flags,
                                         TEE_HANDLE_NULL, &val, sizeof(val),
                                         &obj);
        if (res != TEE_SUCCESS)
            return res;
    } else if (res != TEE_SUCCESS) {
        return res;
    } else {
        res = TEE_ReadObjectData(obj, &val, sizeof(val), &got);
        if (res != TEE_SUCCESS || got != sizeof(val)) {
            TEE_CloseObject(obj);
            return (res != TEE_SUCCESS) ? res : TEE_ERROR_CORRUPT_OBJECT;
        }
    }

    val += 1;

    res = TEE_SeekObjectData(obj, 0, TEE_DATA_SEEK_SET);
    if (res == TEE_SUCCESS)
        res = TEE_WriteObjectData(obj, &val, sizeof(val));
    TEE_CloseObject(obj);
    if (res != TEE_SUCCESS)
        return res;

    *out = val;
    return TEE_SUCCESS;
}

static TEE_Result he_sha256(const uint8_t *in, size_t in_len, uint8_t out[32])
{
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t outlen = 32; /* uint32_t* length under GP 1.1 compat (see above) */
    TEE_Result res = TEE_AllocateOperation(&op, TEE_ALG_SHA256,
                                           TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
        return res;
    res = TEE_DigestDoFinal(op, in, in_len, out, &outlen);
    TEE_FreeOperation(op);
    return res;
}

/* Forward the payload to the PTA's SIGN_DATA command, returning r||s. */
static TEE_Result he_pta_sign(const uint8_t *payload, size_t payload_len,
                              const uint8_t *key, size_t key_len,
                              uint8_t sig[64], size_t *sig_len)
{
    TEE_TASessionHandle sess = TEE_HANDLE_NULL;
    TEE_UUID pta = PTA_REMOTE_ATTESTATION_UUID;
    uint32_t ret_orig = 0;
    TEE_Result res;
    uint32_t pt;
    TEE_Param p[TEE_NUM_PARAMS];

    res = TEE_OpenTASession(&pta, TEE_TIMEOUT_INFINITE, 0, NULL, &sess,
                            &ret_orig);
    if (res != TEE_SUCCESS)
        return res;

    memset(p, 0, sizeof(p));
    p[0].memref.buffer = (void *)payload;
    p[0].memref.size = payload_len;
    p[1].memref.buffer = sig;
    p[1].memref.size = *sig_len;

    if (key && key_len) {
        p[2].memref.buffer = (void *)key;
        p[2].memref.size = key_len;
        pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                             TEE_PARAM_TYPE_MEMREF_OUTPUT,
                             TEE_PARAM_TYPE_MEMREF_INPUT,
                             TEE_PARAM_TYPE_NONE);
    } else {
        pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                             TEE_PARAM_TYPE_MEMREF_OUTPUT,
                             TEE_PARAM_TYPE_NONE,
                             TEE_PARAM_TYPE_NONE);
    }

    res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
                              PTA_REMOTE_ATTESTATION_SIGN_DATA, pt, p,
                              &ret_orig);
    if (res == TEE_SUCCESS)
        *sig_len = p[1].memref.size;
    TEE_CloseTASession(sess);
    return res;
}

TEE_Result he_attest_audio(uint32_t param_types, TEE_Param params[4])
{
    const uint32_t want_nokey =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE);
    const uint32_t want_key =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT);
    if (param_types != want_nokey && param_types != want_key)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Refuse to attest on a tampered device, even with correct firmware. */
    if (he_tamper_tripped())
        return TEE_ERROR_SECURITY;

    int16_t *pcm = params[0].memref.buffer;
    size_t pcm_bytes = params[0].memref.size;
    const uint8_t *nonce = params[1].memref.buffer;
    size_t nonce_len = params[1].memref.size;
    uint8_t *out = params[2].memref.buffer;
    size_t out_cap = params[2].memref.size;

    if (!pcm || !nonce || !out)
        return TEE_ERROR_BAD_PARAMETERS;
    if (nonce_len == 0 || nonce_len > HE_NONCE_MAX)
        return TEE_ERROR_BAD_PARAMETERS;

    /* 1. detect (in secure world). */
    he_detector_config_t cfg;
    he_detector_default_config(&cfg);
    he_detect_result_t r;
    size_t n_samples = pcm_bytes / sizeof(int16_t);
    he_detector_run(&cfg, pcm, n_samples, &r);

    /* 1b. bind the output to the exact input: SHA-256 over the audio bytes the
     * detector consumed (n_samples*2 — a trailing odd byte is dropped, matching
     * the host signer and the zk guest), computed before zeroization, so an
     * independent prover can be tied to the SAME observation. The hash is not
     * the audio. */
    uint8_t input_hash[32];
    TEE_Result hres = he_sha256(pcm, n_samples * sizeof(int16_t), input_hash);
    if (hres != TEE_SUCCESS) {
        /* Never leave raw audio in the buffer, even on the hash-failure path —
         * this is the only post-detect early return before the scrub below. */
        TEE_MemFill(params[0].memref.buffer, 0, pcm_bytes);
        return hres;
    }

    /* 2. zeroize the raw audio immediately — nothing to leak afterwards. */
    TEE_MemFill(params[0].memref.buffer, 0, pcm_bytes);

    /* 3. build the canonical payload. */
    uint8_t blob[HE_CONFIG_BLOB_LEN];
    size_t blob_len = he_detector_config_blob(&cfg, blob, sizeof(blob));
    if (blob_len == 0)
        return TEE_ERROR_GENERIC;

    he_predicate_t pred;
    memset(&pred, 0, sizeof(pred));
    pred.version = HE_PAYLOAD_VERSION;
    memcpy(pred.nonce, nonce, nonce_len);
    pred.nonce_len = (uint32_t)nonce_len;
    pred.event_id = (uint32_t)r.event;
    pred.voice_active = r.voice_active;
    pred.presence = r.presence;
    pred.frames = r.frames;
    pred.window_ms = he_window_ms(&cfg, r.frames);

    TEE_Result res = he_sha256(blob, blob_len, pred.config_hash);
    if (res != TEE_SUCCESS)
        return res;
    memcpy(pred.input_hash, input_hash, sizeof(input_hash));
    /* prev_digest stays zero (genesis) here; per-window stream chaining needs a
     * Trusted-Storage "last payload digest" alongside he_counter_next (rig TODO).
     * The host sim demonstrates the chain; the verifier's Gate 4 enforces it. */
    res = he_counter_next(&pred.counter);
    if (res != TEE_SUCCESS)
        return res;

    uint8_t payload[HE_PAYLOAD_MAX_LEN];
    size_t payload_len = 0;
    if (he_payload_encode(&pred, payload, sizeof(payload), &payload_len) !=
        HE_PAYLOAD_OK)
        return TEE_ERROR_GENERIC;

    /* 4. sign with the attested key via the PTA. */
    const uint8_t *key = NULL;
    size_t key_len = 0;
    if (TEE_PARAM_TYPE_GET(param_types, 3) == TEE_PARAM_TYPE_MEMREF_INPUT) {
        key = params[3].memref.buffer;
        key_len = params[3].memref.size;
    }
    uint8_t sig[64];
    size_t sig_len = sizeof(sig);
    res = he_pta_sign(payload, payload_len, key, key_len, sig, &sig_len);
    if (res != TEE_SUCCESS)
        return res;

    /* 5. emit bundle: u16_be(payload_len) || payload || sig. */
    size_t need = 2 + payload_len + sig_len;
    if (out_cap < need) {
        params[2].memref.size = need;
        return TEE_ERROR_SHORT_BUFFER;
    }
    out[0] = (uint8_t)(payload_len >> 8);
    out[1] = (uint8_t)(payload_len & 0xff);
    memcpy(out + 2, payload, payload_len);
    memcpy(out + 2 + payload_len, sig, sig_len);
    params[2].memref.size = need;

    return TEE_SUCCESS;
}
