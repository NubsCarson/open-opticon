/*
 * Honest Ear — host simulator of the in-enclave attest-VISION path.
 *
 * The exact analogue of he_sim_sign.c, for a camera instead of a microphone:
 *   1. read an 8-bit grayscale PGM (P5) frame (stands in for the secure-world
 *      image sensor),
 *   2. run the SAME vision detector source the TA would compile (he_vision.c),
 *   3. build the SAME canonical payload (he_payload.c) with the verifier nonce +
 *      monotonic counter + config hash,
 *   4. sign + emit the bound-output bundle via the SHARED he_bundle path,
 *   5. zeroize the image buffer (as the TA does for audio).
 *
 * The signed verdict rides the identical envelope the audio path uses and is
 * checked by the identical he-verify — only the detector and the displayed
 * verdict fields differ. The occupancy verdict is mapped onto the shared
 * predicate slots: event_id = scene class (0=empty,1=occupied), presence =
 * subject present, frames = tiles scanned; voice_active/window_ms are unused
 * for vision (0). (A v2/COSE envelope would give these modality-neutral names;
 * see docs/ROADMAP.)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include "he_bundle.h"
#include "he_payload.h"
#include "he_vision.h"

/* Read the next P5 header token, skipping whitespace and #-comments. */
static int pgm_token(FILE *f, unsigned *out)
{
    int c;
    for (;;) {
        c = fgetc(f);
        if (c == '#') {
            while (c != '\n' && c != EOF)
                c = fgetc(f);
        } else if (c == EOF) {
            return -1;
        } else if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
            break;
        }
    }
    unsigned v = 0;
    int digits = 0;
    while (c >= '0' && c <= '9') {
        v = v * 10u + (unsigned)(c - '0');
        digits++;
        c = fgetc(f);
    }
    if (!digits)
        return -1;
    *out = v;
    return 0;
}

/* Read an 8-bit binary PGM into a freshly-allocated buffer. Returns 0 on ok. */
static int read_pgm(const char *path, uint8_t **out, uint32_t *w, uint32_t *h)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    int rc = -1;
    char magic[3] = {0};
    unsigned width = 0, height = 0, maxval = 0;
    if (fread(magic, 1, 2, f) != 2 || magic[0] != 'P' || magic[1] != '5')
        goto out;
    if (pgm_token(f, &width) || pgm_token(f, &height) || pgm_token(f, &maxval))
        goto out;
    if (width == 0 || height == 0 || maxval != 255)
        goto out; /* 8-bit grayscale only */

    size_t n = (size_t)width * height;
    uint8_t *buf = malloc(n);
    if (!buf)
        goto out;
    if (fread(buf, 1, n, f) != n) {
        free(buf);
        goto out;
    }
    *out = buf;
    *w = width;
    *h = height;
    rc = 0;
out:
    fclose(f);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <frame.pgm> <nonce_hex> [counter]\n", argv[0]);
        return 2;
    }
    const char *pgm_path = argv[1];
    const char *nonce_hex = argv[2];
    uint64_t counter = (argc >= 4) ? strtoull(argv[3], NULL, 10) : 1;

    uint8_t *frame = NULL;
    uint32_t width = 0, height = 0;
    if (read_pgm(pgm_path, &frame, &width, &height)) {
        fprintf(stderr, "error: cannot read 8-bit PGM frame %s\n", pgm_path);
        return 1;
    }

    he_vision_config_t cfg;
    he_vision_default_config(&cfg);
    cfg.width = width;   /* bind the actual frame geometry into config_hash */
    cfg.height = height;

    he_vision_result_t res;
    he_vision_run(&cfg, frame, (size_t)width * height, &res);

    /* The device zeroizes the image the moment the detector is done. */
    memset(frame, 0, (size_t)width * height);
    free(frame);

    uint8_t cfg_blob[HE_VISION_BLOB_LEN];
    size_t cfg_blob_len = he_vision_config_blob(&cfg, cfg_blob, sizeof(cfg_blob));
    if (cfg_blob_len == 0) {
        fprintf(stderr, "error: config blob\n");
        return 1;
    }
    uint8_t cfg_hash[32];
    SHA256(cfg_blob, cfg_blob_len, cfg_hash);

    he_predicate_t pred;
    memset(&pred, 0, sizeof(pred));
    pred.version = HE_PAYLOAD_VERSION;
    size_t nlen = 0;
    if (he_hex2bin(nonce_hex, pred.nonce, HE_NONCE_MAX, &nlen)) {
        fprintf(stderr, "error: bad nonce hex (max %u bytes)\n", HE_NONCE_MAX);
        return 1;
    }
    pred.nonce_len = (uint32_t)nlen;
    pred.event_id = (uint32_t)res.scene;
    pred.presence = res.presence;
    pred.frames = res.tiles;
    pred.counter = counter;
    memcpy(pred.config_hash, cfg_hash, 32);

    if (he_bundle_emit_open(&pred) != HE_PAYLOAD_OK) {
        fprintf(stderr, "error: payload encode/sign\n");
        return 1;
    }
    printf("  \"scene\": \"%s\",\n", he_scene_name(res.scene));
    printf("  \"presence\": %u,\n", res.presence);
    printf("  \"active_tiles\": %u,\n", res.active_tiles);
    printf("  \"tiles\": %u,\n", res.tiles);
    he_bundle_emit_close(counter);
    return 0;
}
