/*
 * Honest Ear — in-enclave acoustic detector implementation.
 * Integer-only, no float, no allocation. See he_detector.h.
 */
#include "he_detector.h"

#include "he_serialize.h"

#include <string.h>

/* ---- fixed-point cosine (Q28 angle/result), so we need no libm/float ---- */
/* 1.0 == (1 << 28). */
#define Q28_ONE      (1 << 28)
#define PI_Q28       843314857LL    /* round(pi      * 2^28) */
#define TWO_PI_Q28   1686629714LL   /* round(2*pi    * 2^28) */
#define HALF_PI_Q28  421657428LL    /* round(pi/2    * 2^28) */

/* Returns cos(angle) in Q28, angle given in Q28 radians. Integer-only. */
static int64_t cos_q28(int64_t a)
{
    int sign = 1;
    int64_t x2, t, acc;

    /* reduce to [0, 2pi) */
    a %= TWO_PI_Q28;
    if (a < 0)
        a += TWO_PI_Q28;
    /* cos(2pi - x) = cos(x): fold to [0, pi] */
    if (a > PI_Q28)
        a = TWO_PI_Q28 - a;
    /* cos(x) = -cos(pi - x): fold to [0, pi/2] */
    if (a > HALF_PI_Q28) {
        a = PI_Q28 - a;
        sign = -1;
    }

    /* 4-term Taylor on [0, pi/2]: 1 - x^2/2 + x^4/24 - x^6/720 (all Q28). */
    x2 = (a * a) >> 28;
    acc = Q28_ONE;             /* 1            */
    acc -= x2 / 2;             /* - x^2/2      */
    t = (x2 * x2) >> 28;       /* x^4          */
    acc += t / 24;             /* + x^4/24     */
    t = (t * x2) >> 28;        /* x^6          */
    acc -= t / 720;            /* - x^6/720    */

    return sign * acc;
}

void he_detector_default_config(he_detector_config_t *cfg)
{
    if (!cfg)
        return;
    cfg->sample_rate = 16000;
    cfg->frame_samples = 256;        /* 16 ms */
    cfg->tone_freq_hz = 3100;        /* residential smoke-alarm band */
    cfg->input_shift = 6;            /* int16 -> ~[-512,512] */
    cfg->energy_floor = 200000;      /* per-frame, scaled domain */
    cfg->min_active_frames = 8;
    cfg->tone_ratio_min = 40;        /* tone if goertzel_power >= energy*40 */
    cfg->tone_bins = 3;              /* probe 3 frequencies across the band ... */
    cfg->tone_band_hz = 200;         /* ... 2900 / 3100 / 3300 Hz (UL alarm drift) */
}

size_t he_detector_config_blob(const he_detector_config_t *cfg, uint8_t *out,
                               size_t cap)
{
    if (!cfg || !out || cap < HE_CONFIG_BLOB_LEN)
        return 0;
    he_be64(out + 0, cfg->sample_rate);
    he_be64(out + 8, cfg->frame_samples);
    he_be64(out + 16, cfg->tone_freq_hz);
    he_be64(out + 24, cfg->input_shift);
    he_be64(out + 32, (uint64_t)cfg->energy_floor);
    he_be64(out + 40, cfg->min_active_frames);
    he_be64(out + 48, cfg->tone_ratio_min);
    he_be64(out + 56, cfg->tone_bins);
    he_be64(out + 64, cfg->tone_band_hz);
    return HE_CONFIG_BLOB_LEN;
}

const char *he_event_name(he_event_t ev)
{
    switch (ev) {
    case HE_EVENT_ALARM_TONE:
        return "alarm_tone";
    case HE_EVENT_VOICE:
        return "voice";
    default:
        return "none";
    }
}

uint32_t he_window_ms(const he_detector_config_t *cfg, uint32_t frames)
{
    if (!cfg || cfg->sample_rate == 0)
        return 0;
    /* multiply before dividing (uint64) to avoid truncation on non-default rates */
    return (uint32_t)((uint64_t)cfg->frame_samples * 1000u * frames /
                      cfg->sample_rate);
}

/* Goertzel coefficient 2*cos(2*pi*f/fs) in Q15 for frequency f at rate fs. */
static int32_t he_coeff_q15(int64_t f, int64_t fs)
{
    int64_t theta_q28 = (TWO_PI_Q28 * f) / fs;
    int64_t cos_val = cos_q28(theta_q28);            /* Q28 */
    return (int32_t)((2 * cos_val) >> 13);           /* Q28 -> Q15, x2 */
}

/* The k-th probe frequency across [center-band, center+band] for `bins` probes
 * (integer arithmetic, so it is reproducible bit-for-bit in the Rust port). */
static int64_t he_probe_freq(const he_detector_config_t *cfg, uint32_t k, uint32_t bins)
{
    if (bins <= 1)
        return (int64_t)cfg->tone_freq_hz;
    return (int64_t)cfg->tone_freq_hz - (int64_t)cfg->tone_band_hz +
           (2 * (int64_t)cfg->tone_band_hz * (int64_t)k) / (int64_t)(bins - 1);
}

void he_detector_run(const he_detector_config_t *cfg, const int16_t *pcm,
                     size_t n_samples, he_detect_result_t *res)
{
    if (!res)
        return;
    memset(res, 0, sizeof(*res));
    if (!cfg || !pcm || cfg->frame_samples == 0)
        return;

    /* Probe a small BAND of frequencies around the configured center, not a
     * single bin, so a real alarm that sits slightly off the nominal frequency
     * (UL-217 alarms drift across ~3000-3400 Hz) is still detected. Per frame we
     * take the strongest Goertzel power across the probes. One coefficient per
     * probe, computed once. */
    uint32_t bins = cfg->tone_bins;
    if (bins < 1)
        bins = 1;
    if (bins > HE_TONE_BINS_MAX)
        bins = HE_TONE_BINS_MAX;
    int32_t coeff[HE_TONE_BINS_MAX];
    for (uint32_t k = 0; k < bins; k++)
        coeff[k] = he_coeff_q15(he_probe_freq(cfg, k, bins), (int64_t)cfg->sample_rate);

    const uint32_t fs_frame = cfg->frame_samples;
    const uint32_t shift = cfg->input_shift;
    size_t n_frames = n_samples / fs_frame;

    for (size_t f = 0; f < n_frames; f++) {
        const int16_t *frame = pcm + (size_t)f * fs_frame;
        int64_t s1[HE_TONE_BINS_MAX] = {0};
        int64_t s2[HE_TONE_BINS_MAX] = {0};
        int64_t energy = 0;

        for (uint32_t i = 0; i < fs_frame; i++) {
            int64_t x = (int64_t)(frame[i] >> shift);
            for (uint32_t k = 0; k < bins; k++) {
                int64_t s0 = x + ((coeff[k] * s1[k]) >> 15) - s2[k];
                s2[k] = s1[k];
                s1[k] = s0;
            }
            energy += x * x;
        }

        res->frames++;

        if (energy < cfg->energy_floor)
            continue; /* below noise floor: silent frame */

        res->active_frames++;

        /* Strongest Goertzel power across the probe band for this frame. */
        int64_t max_power = 0;
        for (uint32_t k = 0; k < bins; k++) {
            int64_t power = s1[k] * s1[k] + s2[k] * s2[k] - ((coeff[k] * s1[k]) >> 15) * s2[k];
            if (power < 0)
                power = 0;
            if (power > max_power)
                max_power = power;
        }

        if (max_power >= energy * (int64_t)cfg->tone_ratio_min)
            res->tone_frames++;
        else
            res->voice_frames++;
    }

    res->presence = (res->active_frames >= cfg->min_active_frames) ? 1u : 0u;

    if (res->presence && res->tone_frames * 2u >= res->active_frames) {
        res->event = HE_EVENT_ALARM_TONE;
    } else if (res->presence && res->voice_frames >= cfg->min_active_frames) {
        res->event = HE_EVENT_VOICE;
        res->voice_active = 1u;
    } else {
        res->event = HE_EVENT_NONE;
    }
}
