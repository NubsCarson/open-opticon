/*
 * Honest Ear — COSE_Sign1 (RFC 9052) envelope over the canonical he_payload.
 *
 * This is an ADDITIVE, standards-aligned alternative to the minimal raw-CBOR
 * bound-output envelope (he_payload.h / he_bundle). The cryptographic primitive
 * is IDENTICAL — ECDSA P-256 over SHA-256, 64-byte r||s (COSE alg ES256, -7) —
 * only the *signed structure* differs: instead of signing the bare payload, the
 * signer signs the COSE Sig_structure ["Signature1", protected, ext_aad, payload].
 *
 * The wire shape is:
 *
 *   COSE_Sign1 = 18([ protected: bstr .cbor {1: -7},   // ES256
 *                     unprotected: {},
 *                     payload: bstr .cbor he_payload,
 *                     signature: bstr .size 64 ])       // r||s
 *
 * All functions are pure, integer-only, allocation-free, no float, no third-party
 * CBOR/COSE library — so they compile unchanged into the OP-TEE TA and into host
 * tooling, exactly like he_payload.c. The TA emits this on the next rig build
 * (it re-measures); the host sim demonstrates it today and the Go verifier checks
 * it. Promoting endorsements/EAT to COSE reuses this same encoder.
 */
#ifndef HE_COSE_H
#define HE_COSE_H

#include <stddef.h>
#include <stdint.h>

/* Return codes (match he_payload.h conventions). */
#define HE_COSE_OK          0
#define HE_COSE_E_PARAM    -1
#define HE_COSE_E_OVERFLOW -2

/*
 * Build the COSE Sig_structure for the given canonical payload — the exact byte
 * string a signer must SHA-256-then-ECDSA-sign to produce a valid COSE_Sign1.
 * Writes the length to *out_len. Pure; TA- and host-safe.
 */
int he_cose_sig_structure(const uint8_t *payload, size_t payload_len,
                          uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * Build the final COSE_Sign1 message given the 64-byte ES256 signature (r||s)
 * produced over he_cose_sig_structure(). Writes the length to *out_len.
 */
int he_cose_sign1(const uint8_t *payload, size_t payload_len,
                  const uint8_t sig[64], uint8_t *out, size_t out_cap,
                  size_t *out_len);

/* Generous static upper bound for a v1 COSE_Sign1 around our payload (the
 * payload is <= HE_PAYLOAD_MAX_LEN 240; +headers/signature fit comfortably). */
#define HE_COSE_MAX_LEN 384u

#endif /* HE_COSE_H */
