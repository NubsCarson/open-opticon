/*
 * Honest Ear — in-enclave acoustic detector (shared, pure C).
 *
 * Answers ONE narrow question per observation window over int16 PCM:
 *   - is there acoustic presence above the noise floor?  (presence)
 *   - does it look like voice (broadband, voiced)?        (voice_active / VOICE)
 *   - is a dominant alarm tone present?                   (ALARM_TONE)
 *
 * It deliberately does NOT transcribe, identify speakers, or retain audio. The
 * only things it emits are the small predicate fields above. By construction
 * there is no code path here that reconstructs speech — and the published hash
 * of this code is what attestation proves is running.
 *
 * Integer-only (Q15 fixed-point Goertzel), no floating point, no allocation,
 * no libc beyond <string.h>. Safe to compile into an OP-TEE TA and into host
 * tooling from the SAME source, so the host tests exercise production code.
 */
#ifndef HE_DETECTOR_H
#define HE_DETECTOR_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    HE_EVENT_NONE = 0,
    HE_EVENT_VOICE = 1,
    HE_EVENT_ALARM_TONE = 2,
} he_event_t;

/*
 * Detector policy. The canonical serialization of this struct
 * (he_detector_config_blob) is hashed into the signed payload (config_hash),
 * so the verifier can confirm exactly which policy produced a result.
 */
typedef struct {
    uint32_t sample_rate;       /* Hz, e.g. 16000 */
    uint32_t frame_samples;     /* per-frame window, e.g. 256 */
    uint32_t tone_freq_hz;      /* Goertzel band CENTER, e.g. 3100 (alarm) */
    uint32_t input_shift;       /* right-shift applied to each sample (scaling) */
    int64_t energy_floor;       /* per-frame energy threshold (scaled domain) */
    uint32_t min_active_frames; /* active frames required to assert presence */
    uint32_t tone_ratio_min;    /* tone if goertzel_power >= energy*ratio */
    uint32_t tone_bins;         /* # of probe frequencies across the band (>=1) */
    uint32_t tone_band_hz;      /* half-width of the probe band around tone_freq_hz */
} he_detector_config_t;

/* Upper bound on tone_bins (bounds the per-frame Goertzel state on the stack). */
#define HE_TONE_BINS_MAX 8u

typedef struct {
    uint32_t frames;        /* total frames examined */
    uint32_t active_frames; /* frames with energy above floor */
    uint32_t tone_frames;   /* active frames dominated by the target tone */
    uint32_t voice_frames;  /* active, broadband (non-tone) frames */
    he_event_t event;       /* aggregated classification */
    uint32_t voice_active;  /* 0/1 */
    uint32_t presence;      /* 0/1 */
} he_detect_result_t;

/* Fill cfg with the default (documented) policy. */
void he_detector_default_config(he_detector_config_t *cfg);

/*
 * Serialize cfg into a canonical, fixed byte layout suitable for hashing.
 * Returns the number of bytes written, or 0 on error. Crypto-free by design:
 * the caller computes SHA-256(blob) for the payload's config_hash.
 */
size_t he_detector_config_blob(const he_detector_config_t *cfg, uint8_t *out,
                               size_t cap);

/* Canonical config blob length (9 x uint64 big-endian). */
#define HE_CONFIG_BLOB_LEN 72u

/*
 * Run the detector over `n_samples` of int16 PCM. Pure function: reads pcm,
 * writes res, retains nothing. The caller is responsible for zeroizing the
 * audio buffer afterwards (the TA does this explicitly).
 */
void he_detector_run(const he_detector_config_t *cfg, const int16_t *pcm,
                     size_t n_samples, he_detect_result_t *res);

/* Stable lowercase name for an event class ("alarm_tone" / "voice" / "none"). */
const char *he_event_name(he_event_t ev);

/* Observation-window length in ms for `frames` frames under `cfg`. Single
 * definition shared by the TA and the host simulator so their signed payloads
 * are byte-identical. */
uint32_t he_window_ms(const he_detector_config_t *cfg, uint32_t frames);

#endif /* HE_DETECTOR_H */
