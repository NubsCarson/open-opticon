/*
 * Honest Ear — shared bound-output bundle emission (host simulators).
 *
 * The audio (he_sim_sign) and vision (he_vision_sign) host simulators differ
 * ONLY in their detector. Both build a he_predicate_t, sign SHA-256(canonical
 * payload) with the published QEMU test key — the exact ECDSA P-256 r||s that
 * optee-ra's sign_ecdsa_sha256() emits on the QEMU path — and print the same
 * JSON bound-output bundle the Go verifier consumes. This is that one shared
 * path, so there is a single signing + envelope definition (not one per
 * modality), and the SAME he-verify checks both.
 */
#ifndef HE_BUNDLE_H
#define HE_BUNDLE_H

#include <stddef.h>
#include <stdint.h>

#include "he_payload.h"

/* Parse a hex string into bytes. Returns 0 on success, -1 on bad input. */
int he_hex2bin(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * Encode pred into the canonical CBOR payload, sign it with the published test
 * key, and print the OPENING of the JSON bundle to stdout:
 *
 *   {
 *     "schema": "honest-ear/bound-output/v1",
 *     "payload": <hex>,
 *     "sig":     <hex>,
 *     "pub_x":   <hex>,
 *     "pub_y":   <hex>,
 *
 * (every line comma-terminated). The caller then prints its modality-specific
 * verdict fields, each comma-terminated, and finally calls he_bundle_emit_close
 * to print the shared "counter" field and the closing brace. Returns
 * HE_PAYLOAD_OK on success, non-zero on encode/sign error.
 */
int he_bundle_emit_open(const he_predicate_t *pred);

/* Print the closing common field and brace: `  "counter": <counter>\n}`. */
void he_bundle_emit_close(uint64_t counter);

#endif /* HE_BUNDLE_H */
