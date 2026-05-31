/*
 * Honest Ear — in-enclave VISION occupancy detector (shared, pure C).
 *
 * The audio detector proves a microphone only ever emits {none,voice,alarm}.
 * This proves the SAME discipline for a camera: over one 8-bit grayscale frame
 * it answers ONE narrow question —
 *   - is a foreground subject present in view?  (presence / OCCUPIED)
 * — and emits only that bit plus a coarse count of active image regions. It
 * NEVER emits, stores, or reconstructs the image. The published hash of this
 * code is what attestation proves is running, exactly as for the audio path;
 * the signed verdict rides the SAME he_payload envelope and is checked by the
 * SAME verifier and quorum. Only the detector is new — that is the point: the
 * primitive is not audio-specific.
 *
 * Method: tile the frame into a grid; a tile is "active" when its in-tile
 * gradient energy (sum of |dx|+|dy|) exceeds a floor — a flat background tile
 * reads inactive, a tile containing an edge/subject reads active. OCCUPIED when
 * enough tiles are active. Integer-only, no float, no allocation, no libc
 * beyond <string.h>: TA- and host-safe from one source, like he_detector.c.
 *
 * It is deliberately a simple threshold stub, like the acoustic detector. The
 * contribution is the PROVABLE RESTRAINT — bound, attested, emits only the
 * occupancy predicate, never the frame — not the sophistication of the model.
 */
#ifndef HE_VISION_H
#define HE_VISION_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    HE_SCENE_EMPTY = 0,
    HE_SCENE_OCCUPIED = 1,
} he_scene_t;

/*
 * Detector policy + frame geometry. Its canonical serialization
 * (he_vision_config_blob) is hashed into the signed payload (config_hash), so
 * the verifier confirms exactly which policy AND frame size produced a result.
 */
typedef struct {
    uint32_t width;             /* frame width in pixels */
    uint32_t height;            /* frame height in pixels */
    uint32_t tile;              /* square tile edge in pixels, e.g. 16 */
    uint32_t activity_floor;    /* per-tile gradient-energy threshold */
    uint32_t min_active_tiles;  /* active tiles required to assert OCCUPIED */
} he_vision_config_t;

typedef struct {
    uint32_t tiles;         /* total tiles examined */
    uint32_t active_tiles;  /* tiles with gradient energy above the floor */
    he_scene_t scene;       /* EMPTY / OCCUPIED */
    uint32_t presence;      /* 0/1 (== OCCUPIED) */
} he_vision_result_t;

/* Fill cfg with the default (documented) policy for a 64x64 frame. */
void he_vision_default_config(he_vision_config_t *cfg);

/* Canonical config blob length (5 x uint64 big-endian). */
#define HE_VISION_BLOB_LEN 40u

/*
 * Serialize cfg into a canonical, fixed byte layout suitable for hashing.
 * Returns the number of bytes written, or 0 on error. Crypto-free by design:
 * the caller computes SHA-256(blob) for the payload's config_hash.
 */
size_t he_vision_config_blob(const he_vision_config_t *cfg, uint8_t *out,
                             size_t cap);

/* Stable lowercase name for a scene class ("occupied" / "empty"). */
const char *he_scene_name(he_scene_t s);

/*
 * Run the detector over an 8-bit grayscale frame (row-major, width*height
 * bytes; n_pixels is the buffer length, must be >= width*height). Pure
 * function: reads frame, writes res, retains nothing. The caller is responsible
 * for zeroizing the frame buffer afterwards (the TA does this explicitly), just
 * as for audio.
 */
void he_vision_run(const he_vision_config_t *cfg, const uint8_t *frame,
                   size_t n_pixels, he_vision_result_t *res);

#endif /* HE_VISION_H */
