/*
 * Honest Ear — host client (CA) for the attest-audio command.
 *
 * Feeds an audio file to the TA, receives the signed bound-output bundle, and
 * prints it as JSON (same schema the verifier and the host simulator use).
 * For the full pipeline, also run the existing optee-ra attestation client
 * with the SAME nonce so Veraison verifies the firmware while this verifies
 * the bound output — both signed by the same attested key.
 *
 *   he_host <pcm_s16le_mono> <nonce_hex> [--key-hex <FullKey>] \
 *           [--pubx-hex <hex>] [--puby-hex <hex>]
 *
 * Builds with the OP-TEE host toolchain (libteec). See INTEGRATION.md.
 */
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>

#include <remote_attestation_ta.h> /* provides TA_REMOTE_ATTESTATION_CMD_* ids */
#include "he_testkey.h"            /* default QEMU pub coords for the JSON bundle */

static int parse_hex(const char *s, uint8_t **out, size_t *out_len)
{
    size_t n = strlen(s);
    if (n % 2)
        return -1;
    uint8_t *b = malloc(n / 2 ? n / 2 : 1);
    if (!b)
        return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) {
            free(b);
            return -1;
        }
        b[i] = (uint8_t)v;
    }
    *out = b;
    *out_len = n / 2;
    return 0;
}

static void print_hex_field(const char *k, const uint8_t *b, size_t n, int comma)
{
    printf("  \"%s\": \"", k);
    for (size_t i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\"%s\n", comma ? "," : "");
}

static uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(sz > 0 ? (size_t)sz : 1);
    if (!buf || (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz)) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = (size_t)sz;
    return buf;
}

static int do_trip(void)
{
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op = {0};
    TEEC_UUID uuid = TA_REMOTE_ATTESTATION_UUID;
    uint32_t err_origin = 0;
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext: 0x%x", res);
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
                           &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_OpenSession: 0x%x", res);
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(&sess, TA_REMOTE_ATTESTATION_CMD_TRIP_TAMPER, &op,
                             &err_origin);
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "trip_tamper: 0x%x", res);
    printf("tamper flag latched; device will refuse attestation\n");
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc >= 2 && !strcmp(argv[1], "--trip"))
        return do_trip();

    if (argc < 3)
        errx(1, "usage: %s <pcm_s16le_mono> <nonce_hex> [--key-hex H] "
                "[--pubx-hex H] [--puby-hex H]\n"
                "       %s --trip   (latch tamper flag)",
             argv[0], argv[0]);

    const char *pcm_path = argv[1];
    uint8_t *nonce = NULL, *key = NULL, *px = NULL, *py = NULL;
    size_t nonce_len = 0, key_len = 0, px_len = 0, py_len = 0;
    if (parse_hex(argv[2], &nonce, &nonce_len))
        errx(1, "bad nonce hex");

    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--key-hex") && i + 1 < argc) {
            if (parse_hex(argv[++i], &key, &key_len))
                errx(1, "bad --key-hex");
        } else if (!strcmp(argv[i], "--pubx-hex") && i + 1 < argc) {
            if (parse_hex(argv[++i], &px, &px_len))
                errx(1, "bad --pubx-hex");
        } else if (!strcmp(argv[i], "--puby-hex") && i + 1 < argc) {
            if (parse_hex(argv[++i], &py, &py_len))
                errx(1, "bad --puby-hex");
        }
        else
            errx(1, "unknown argument: %s", argv[i]);
    }

    size_t pcm_len = 0;
    uint8_t *pcm = read_file(pcm_path, &pcm_len);
    if (!pcm)
        errx(1, "cannot read %s", pcm_path);

    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op = {0};
    TEEC_UUID uuid = TA_REMOTE_ATTESTATION_UUID;
    uint32_t err_origin = 0;
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext: 0x%x", res);
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
                           &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_OpenSession: 0x%x origin 0x%x", res, err_origin);

    uint8_t bundle[512] = {0};
    if (key && key_len) {
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_MEMREF_TEMP_INPUT);
        op.params[3].tmpref.buffer = key;
        op.params[3].tmpref.size = key_len;
    } else {
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
    }
    op.params[0].tmpref.buffer = pcm;
    op.params[0].tmpref.size = pcm_len;
    op.params[1].tmpref.buffer = nonce;
    op.params[1].tmpref.size = nonce_len;
    op.params[2].tmpref.buffer = bundle;
    op.params[2].tmpref.size = sizeof(bundle);

    res = TEEC_InvokeCommand(&sess, TA_REMOTE_ATTESTATION_CMD_ATTEST_AUDIO, &op,
                             &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "attest_audio: 0x%x origin 0x%x", res, err_origin);

    size_t blen = op.params[2].tmpref.size;
    if (blen < 2 + 64)
        errx(1, "bundle too small (%zu)", blen);
    size_t payload_len = ((size_t)bundle[0] << 8) | bundle[1];
    if (2 + payload_len + 64 > blen)
        errx(1, "malformed bundle");
    const uint8_t *payload = bundle + 2;
    const uint8_t *sig = bundle + 2 + payload_len;

    /* Default pub coords to the published QEMU test key unless overridden /
     * derivable from a provided FullKey (PubX||PubY||blob). */
    uint8_t def_x[32], def_y[32];
    uint8_t *tk_x = NULL, *tk_y = NULL;
    size_t tklen = 0;
    if (!(px && py)) {
        if (key && key_len >= 64) {
            memcpy(def_x, key, 32);
            memcpy(def_y, key + 32, 32);
            px = def_x;
            py = def_y;
        } else if (parse_hex(HE_TESTKEY_PUB_X_HEX, &tk_x, &tklen) == 0 &&
                   parse_hex(HE_TESTKEY_PUB_Y_HEX, &tk_y, &tklen) == 0) {
            px = tk_x;
            py = tk_y;
        }
        px_len = py_len = 32;
    }

    printf("{\n");
    printf("  \"schema\": \"honest-ear/bound-output/v1\",\n");
    print_hex_field("payload", payload, payload_len, 1);
    print_hex_field("sig", sig, 64, 1);
    print_hex_field("pub_x", px, px_len, 1);
    print_hex_field("pub_y", py, py_len, 0);
    printf("}\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    free(pcm);
    free(nonce);
    free(key);
    free(tk_x);
    free(tk_y);
    return 0;
}
