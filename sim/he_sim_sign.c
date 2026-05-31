/*
 * Honest Ear — host simulator of the in-enclave attest-audio path.
 *
 * Mirrors, on the host, exactly what the device does:
 *   1. read int16 mono PCM from a file (stands in for the secure-world mic),
 *   2. run the SAME detector source the TA compiles (he_detector.c),
 *   3. build the SAME canonical payload the TA builds (he_payload.c) with the
 *      verifier-supplied nonce + monotonic counter + config hash,
 *   4. sign SHA-256(payload) with ECDSA P-256, output as 64-byte r||s, using
 *      the published QEMU test key — i.e. the exact algorithm and key of
 *      optee-ra's sign_ecdsa_sha256() on the QEMU path,
 *   5. zeroize the audio buffer (as the TA does),
 *   6. emit a JSON "bound-output bundle" on stdout for the Go verifier.
 *
 * This is a faithful stand-in for the TEE crypto path; the only thing it does
 * not exercise is OP-TEE itself (no Docker/30GB build needed to validate the
 * application + binding + verification logic). On real hardware steps 2-5 run
 * inside TrustZone and the key is a non-extractable CAAM black key.
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "he_detector.h"
#include "he_payload.h"
#include "he_pcm.h"
#include "he_testkey.h"

static int hex2bin(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > out_cap)
        return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (uint8_t)v;
    }
    *out_len = n / 2;
    return 0;
}

static void print_hex(const char *key, const uint8_t *b, size_t n, int comma)
{
    printf("  \"%s\": \"", key);
    for (size_t i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\"%s\n", comma ? "," : "");
}

/* SHA-256(msg) then ECDSA P-256 sign with test key d; out = r(32)||s(32). */
static int sign_rs(const uint8_t *msg, size_t msg_len, uint8_t out_sig[64])
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    EC_KEY *key = NULL;
    BIGNUM *d = NULL;
    ECDSA_SIG *sig = NULL;
    const BIGNUM *r, *s;
    uint8_t dbin[32];
    size_t dlen = 0;
    int rc = -1;

    SHA256(msg, msg_len, digest);

    if (hex2bin(HE_TESTKEY_PRIV_D_HEX, dbin, sizeof(dbin), &dlen) || dlen != 32)
        return -1;

    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key)
        goto out;
    d = BN_bin2bn(dbin, 32, NULL);
    if (!d || !EC_KEY_set_private_key(key, d))
        goto out;

    sig = ECDSA_do_sign(digest, sizeof(digest), key);
    if (!sig)
        goto out;

    ECDSA_SIG_get0(sig, &r, &s);
    memset(out_sig, 0, 64);
    BN_bn2binpad(r, out_sig, 32);
    BN_bn2binpad(s, out_sig + 32, 32);
    rc = 0;

out:
    if (sig)
        ECDSA_SIG_free(sig);
    if (d)
        BN_free(d);
    if (key)
        EC_KEY_free(key);
    return rc;
}

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
    if (hex2bin(nonce_hex, pred.nonce, HE_NONCE_MAX, &nlen)) {
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

    uint8_t payload[HE_PAYLOAD_MAX_LEN];
    size_t payload_len = 0;
    if (he_payload_encode(&pred, payload, sizeof(payload), &payload_len) != HE_PAYLOAD_OK) {
        fprintf(stderr, "error: payload encode\n");
        return 1;
    }

    uint8_t sig[64];
    if (sign_rs(payload, payload_len, sig)) {
        fprintf(stderr, "error: signing failed\n");
        return 1;
    }

    /* Public key (test key) for the verifier to pin/verify against. */
    uint8_t px[32], py[32];
    size_t pxl = 0, pyl = 0;
    hex2bin(HE_TESTKEY_PUB_X_HEX, px, sizeof(px), &pxl);
    hex2bin(HE_TESTKEY_PUB_Y_HEX, py, sizeof(py), &pyl);

    const char *evname = he_event_name(res.event);

    printf("{\n");
    printf("  \"schema\": \"honest-ear/bound-output/v1\",\n");
    print_hex("payload", payload, payload_len, 1);
    print_hex("sig", sig, 64, 1);
    print_hex("pub_x", px, 32, 1);
    print_hex("pub_y", py, 32, 1);
    printf("  \"event\": \"%s\",\n", evname);
    printf("  \"presence\": %u,\n", res.presence);
    printf("  \"voice_active\": %u,\n", res.voice_active);
    printf("  \"frames\": %u,\n", res.frames);
    printf("  \"active_frames\": %u,\n", res.active_frames);
    printf("  \"tone_frames\": %u,\n", res.tone_frames);
    printf("  \"counter\": %llu\n", (unsigned long long)counter);
    printf("}\n");
    return 0;
}
