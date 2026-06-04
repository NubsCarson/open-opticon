/*
 * Honest Ear — shared bound-output bundle emission. See he_bundle.h.
 *
 * Mirrors, on the host, exactly what the device does for the signing + binding
 * step: SHA-256 over the canonical payload, ECDSA P-256 with the published QEMU
 * test key, output as 64-byte r||s, emitted as a JSON bundle for the Go
 * verifier. On real hardware this runs inside TrustZone with a non-extractable
 * CAAM black key.
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "he_bundle.h"
#include "he_cose.h"
#include "he_payload.h"
#include "he_testkey.h"

int he_hex2bin(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len)
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

    if (he_hex2bin(HE_TESTKEY_PRIV_D_HEX, dbin, sizeof(dbin), &dlen) || dlen != 32)
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

    /* Normalize to low-s (s <= N/2). OpenSSL's ECDSA_do_sign returns a random s,
     * high ~half the time; the on-chain OpenZeppelin P256 verifier rejects
     * high-s (malleability), so without this the device would emit bundles the
     * Go/host verifier accepts but the contract rejects — the verifiers would
     * disagree. Canonical low-s (s' = N - s when s > N/2) makes all verifiers
     * accept the same signatures. */
    {
        const EC_GROUP *grp = EC_KEY_get0_group(key);
        const BIGNUM *order = grp ? EC_GROUP_get0_order(grp) : NULL;
        BIGNUM *half = BN_new();
        BIGNUM *slow = BN_new();
        if (!order || !half || !slow) {
            BN_free(half);
            BN_free(slow);
            goto out;
        }
        BN_rshift1(half, order);            /* half = N >> 1 */
        if (BN_cmp(s, half) > 0)
            BN_sub(slow, order, s);         /* slow = N - s  (low-s)  */
        else
            BN_copy(slow, s);
        memset(out_sig, 0, 64);
        BN_bn2binpad(r, out_sig, 32);
        BN_bn2binpad(slow, out_sig + 32, 32);
        BN_free(half);
        BN_free(slow);
    }
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

int he_bundle_emit_open(const he_predicate_t *pred)
{
    uint8_t payload[HE_PAYLOAD_MAX_LEN];
    size_t payload_len = 0;
    int rc = he_payload_encode(pred, payload, sizeof(payload), &payload_len);
    if (rc != HE_PAYLOAD_OK)
        return rc;

    uint8_t sig[64];
    if (sign_rs(payload, payload_len, sig))
        return -1;

    uint8_t px[32], py[32];
    size_t pxl = 0, pyl = 0;
    he_hex2bin(HE_TESTKEY_PUB_X_HEX, px, sizeof(px), &pxl);
    he_hex2bin(HE_TESTKEY_PUB_Y_HEX, py, sizeof(py), &pyl);

    printf("{\n");
    printf("  \"schema\": \"honest-ear/bound-output/v1\",\n");
    print_hex("payload", payload, payload_len, 1);
    print_hex("sig", sig, 64, 1);
    print_hex("pub_x", px, 32, 1);
    print_hex("pub_y", py, 32, 1);
    return HE_PAYLOAD_OK;
}

int he_bundle_emit_cose(const he_predicate_t *pred)
{
    uint8_t payload[HE_PAYLOAD_MAX_LEN];
    size_t payload_len = 0;
    int rc = he_payload_encode(pred, payload, sizeof(payload), &payload_len);
    if (rc != HE_PAYLOAD_OK)
        return rc;

    /* Sign the COSE Sig_structure (not the bare payload) with the same key. */
    uint8_t sigstruct[HE_COSE_MAX_LEN];
    size_t sigstruct_len = 0;
    if (he_cose_sig_structure(payload, payload_len, sigstruct, sizeof(sigstruct),
                              &sigstruct_len) != HE_COSE_OK)
        return -1;

    uint8_t sig[64];
    if (sign_rs(sigstruct, sigstruct_len, sig))
        return -1;

    uint8_t cose[HE_COSE_MAX_LEN];
    size_t cose_len = 0;
    if (he_cose_sign1(payload, payload_len, sig, cose, sizeof(cose), &cose_len) != HE_COSE_OK)
        return -1;

    uint8_t px[32], py[32];
    size_t pxl = 0, pyl = 0;
    he_hex2bin(HE_TESTKEY_PUB_X_HEX, px, sizeof(px), &pxl);
    he_hex2bin(HE_TESTKEY_PUB_Y_HEX, py, sizeof(py), &pyl);

    printf("{\n");
    printf("  \"schema\": \"honest-ear/cose-sign1/v1\",\n");
    print_hex("cose", cose, cose_len, 1);
    print_hex("pub_x", px, 32, 1);
    print_hex("pub_y", py, 32, 1);
    return HE_PAYLOAD_OK;
}

void he_bundle_emit_close(uint64_t counter)
{
    printf("  \"counter\": %llu\n", (unsigned long long)counter);
    printf("}\n");
}
