/*
 * Honest Ear — canonical bound-output payload.
 *
 * This is the byte string that the enclave signs (via PTA_SIGN_DATA ->
 * sign_ecdsa_sha256) to BIND the detector's output to the same hardware-bound
 * key whose identity is proven by remote attestation. The verifier recomputes
 * SHA-256 over exactly these bytes and checks the signature against the
 * attested public key, then checks nonce freshness and the monotonic counter.
 *
 * Wire format: a single RFC 8949 *deterministic* CBOR map (definite length,
 * integer keys in ascending order, smallest-possible integer encodings). A
 * minimal hand-written encoder is used so that the TA (no external deps,
 * integer-only, OP-TEE libc subset) and the host/verifier produce and parse
 * byte-identical output with zero third-party libraries.
 *
 *   {
 *     0: version    (uint)   -- HE_PAYLOAD_VERSION
 *     1: nonce      (bstr)   -- verifier's fresh challenge (binds freshness)
 *     2: event_id   (uint)   -- he_event_t (0=none,1=voice,2=alarm_tone)
 *     3: voice_active (bool)
 *     4: presence   (uint)   -- 0/1 (any acoustic activity above noise floor)
 *     5: frames     (uint)   -- audio frames processed this window
 *     6: window_ms  (uint)   -- observation window length
 *     7: counter    (uint)   -- monotonic anti-replay counter
 *     8: config_hash(bstr32) -- SHA-256 of the detector policy/thresholds
 *     9: input_hash (bstr32) -- SHA-256 of the sensor input (the audio/frame
 *                              bytes the detector ran on), so an independent
 *                              prover (e.g. the zk leg) can be cryptographically
 *                              bound to the SAME observation, not just the verdict
 *    10: prev_digest(bstr32) -- SHA-256 of the PREVIOUS bound-output payload (32
 *                              zero bytes for the first), so the per-device stream
 *                              is an append-only hash chain: a suppressed window
 *                              breaks the chain (the verifier can't be silently
 *                              shown a gap), not just a replayed one
 *   }
 *
 * NOTE: this is deliberately NOT COSE_Sign1. It is a minimal, fully specified,
 * deterministic envelope so that the binding can be implemented and audited
 * with no CBOR/COSE library inside the TA. Promoting it to COSE_Sign1 is a
 * clean follow-up (the signing primitive is identical) — see docs/ROADMAP.
 */
#ifndef HE_PAYLOAD_H
#define HE_PAYLOAD_H

#include <stddef.h>
#include <stdint.h>

#define HE_PAYLOAD_VERSION 1u
#define HE_NONCE_MAX       64u
#define HE_CONFIG_HASH_LEN 32u
#define HE_INPUT_HASH_LEN  32u
#define HE_PREV_DIGEST_LEN 32u

/* Map keys (stable wire contract — never renumber). */
enum he_payload_key {
    HE_K_VERSION = 0,
    HE_K_NONCE = 1,
    HE_K_EVENT = 2,
    HE_K_VOICE = 3,
    HE_K_PRESENCE = 4,
    HE_K_FRAMES = 5,
    HE_K_WINDOW_MS = 6,
    HE_K_COUNTER = 7,
    HE_K_CONFIG_HASH = 8,
    HE_K_INPUT_HASH = 9,
    HE_K_PREV_DIGEST = 10,
};

typedef struct {
    uint32_t version;                       /* HE_PAYLOAD_VERSION */
    uint8_t nonce[HE_NONCE_MAX];
    uint32_t nonce_len;                     /* <= HE_NONCE_MAX */
    uint32_t event_id;                      /* he_event_t */
    uint32_t voice_active;                  /* 0/1 -> CBOR bool */
    uint32_t presence;                      /* 0/1 */
    uint32_t frames;
    uint32_t window_ms;
    uint64_t counter;                       /* monotonic, anti-replay */
    uint8_t config_hash[HE_CONFIG_HASH_LEN];
    uint8_t input_hash[HE_INPUT_HASH_LEN];  /* SHA-256 of the sensor input */
    uint8_t prev_digest[HE_PREV_DIGEST_LEN]; /* SHA-256 of the previous payload */
} he_predicate_t;

/* Return codes. */
#define HE_PAYLOAD_OK         0
#define HE_PAYLOAD_E_PARAM   -1
#define HE_PAYLOAD_E_OVERFLOW -2

/*
 * Encode `p` into deterministic CBOR at `out` (capacity `out_cap`).
 * On success writes the length to *out_len and returns HE_PAYLOAD_OK.
 * Pure function: no allocation, no globals, no float. TA- and host-safe.
 */
int he_payload_encode(const he_predicate_t *p, uint8_t *out, size_t out_cap,
                      size_t *out_len);

/* Maximum encoded size for a v1 payload (for static buffer sizing). */
#define HE_PAYLOAD_MAX_LEN 240u

#endif /* HE_PAYLOAD_H */
