/*
 * Honest Ear — shared big-endian serialization primitive.
 *
 * The detector config blobs (audio: he_detector_config_blob; vision:
 * he_vision_config_blob) are canonical fixed-layout byte strings that get
 * SHA-256'd into the signed payload's config_hash, so the verifier can confirm
 * exactly which policy produced a result. Both serialize their fields as
 * big-endian uint64s; this is the one shared store so there is a single
 * definition (no two functions with the same purpose). Integer-only, no libc.
 */
#ifndef HE_SERIALIZE_H
#define HE_SERIALIZE_H

#include <stdint.h>

/* Store v as 8 big-endian bytes at p. */
static inline void he_be64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
}

#endif /* HE_SERIALIZE_H */
