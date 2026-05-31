/*
 * Honest Ear — host simulator of the in-enclave attest-audio path.
 *
 * Mirrors, on the host, exactly what the device does:
 *   1. read int16 mono PCM from a file (stands in for the secure-world mic),
 *   2. run the SAME detector source the TA compiles (he_detector.c),
 *   3. build the SAME canonical payload the TA builds (he_payload.c) with the
 *      verifier-supplied nonce + monotonic counter + config hash,
 *   4. sign SHA-256(payload) + emit the bound-output bundle via the shared
 *      he_bundle path (the exact ECDSA P-256 r||s of optee-ra's
 *      sign_ecdsa_sha256() on the QEMU path, with the published test key),
 *   5. zeroize the audio buffer (as the TA does).
 *
 * This is a faithful stand-in for the TEE crypto path; the only thing it does
 * not exercise is OP-TEE itself (no Docker/30GB build needed to validate the
 * application + binding + verification logic). On real hardware steps 2-5 run
 * inside TrustZone and the key is a non-extractable CAAM black key. The vision
 * sibling (he_vision_sign.c) reuses steps 3-4 unchanged.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include "he_bundle.h"
#include "he_detector.h"
#include "he_payload.h"
#include "he_pcm.h"

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s <pcm_s16le_mono> <nonce_hex> [counter]\n", argv[0]);
        return 2;
    }
    const char *pcm_path = argv[1];
    const char *nonce_hex = argv[2];
    uint64_t counter = (argc >= 4) ? strtoull(argv[3], NULL, 10) : 1;

    int16_t *pcm = NULL;
    size_t n_samples = 0;
    if (he_read_pcm(pcm_path, &pcm, &n_samples)) {
        fprintf(stderr, "error: cannot read PCM file %s\n", pcm_path);
        return 1;
    }

    he_detector_config_t cfg;
    he_detector_default_config(&cfg);

    he_detect_result_t res;
    he_detector_run(&cfg, pcm, n_samples, &res);

    /* The device zeroizes the audio the moment the detector is done. */
    if (n_samples)
        memset(pcm, 0, n_samples * sizeof(int16_t));
    free(pcm);

    /* config hash binds the policy into the signed output */
    uint8_t cfg_blob[HE_CONFIG_BLOB_LEN];
    size_t cfg_blob_len = he_detector_config_blob(&cfg, cfg_blob, sizeof(cfg_blob));
    if (cfg_blob_len == 0) {
        fprintf(stderr, "error: config blob\n");
        return 1;
    }
    uint8_t cfg_hash[32];
    SHA256(cfg_blob, cfg_blob_len, cfg_hash);

    /* Build the predicate. */
    he_predicate_t pred;
    memset(&pred, 0, sizeof(pred));
    pred.version = HE_PAYLOAD_VERSION;
    size_t nlen = 0;
    if (he_hex2bin(nonce_hex, pred.nonce, HE_NONCE_MAX, &nlen)) {
        fprintf(stderr, "error: bad nonce hex (max %u bytes)\n", HE_NONCE_MAX);
        return 1;
    }
    pred.nonce_len = (uint32_t)nlen;
    pred.event_id = (uint32_t)res.event;
    pred.voice_active = res.voice_active;
    pred.presence = res.presence;
    pred.frames = res.frames;
    pred.window_ms = he_window_ms(&cfg, res.frames);
    pred.counter = counter;
    memcpy(pred.config_hash, cfg_hash, 32);

    if (he_bundle_emit_open(&pred) != HE_PAYLOAD_OK) {
        fprintf(stderr, "error: payload encode/sign\n");
        return 1;
    }
    printf("  \"event\": \"%s\",\n", he_event_name(res.event));
    printf("  \"presence\": %u,\n", res.presence);
    printf("  \"voice_active\": %u,\n", res.voice_active);
    printf("  \"frames\": %u,\n", res.frames);
    printf("  \"active_frames\": %u,\n", res.active_frames);
    printf("  \"tone_frames\": %u,\n", res.tone_frames);
    he_bundle_emit_close(counter);
    return 0;
}
