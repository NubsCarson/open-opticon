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

void he_detector_run(const he_detector_config_t *cfg, const int16_t *pcm,
                     size_t n_samples, he_detect_result_t *res)
{
    if (!res)
        return;
    memset(res, 0, sizeof(*res));
    if (!cfg || !pcm || cfg->frame_samples == 0)
        return;

    /* Goertzel coefficient: 2*cos(2*pi*f/fs), in Q15. Computed once. */
    int64_t theta_q28 =
        (TWO_PI_Q28 * (int64_t)cfg->tone_freq_hz) / (int64_t)cfg->sample_rate;
    int64_t cos_val = cos_q28(theta_q28);           /* Q28 */
    int32_t coeff_q15 = (int32_t)((2 * cos_val) >> 13); /* Q28 -> Q15, x2 */

    const uint32_t fs_frame = cfg->frame_samples;
    const uint32_t shift = cfg->input_shift;
    size_t n_frames = n_samples / fs_frame;

    for (size_t f = 0; f < n_frames; f++) {
        const int16_t *frame = pcm + (size_t)f * fs_frame;
        int64_t s1 = 0, s2 = 0;
        int64_t energy = 0;

        for (uint32_t i = 0; i < fs_frame; i++) {
            int64_t x = (int64_t)(frame[i] >> shift);
            int64_t s0 = x + ((coeff_q15 * s1) >> 15) - s2;
            s2 = s1;
            s1 = s0;
            energy += x * x;
        }

        res->frames++;

        if (energy < cfg->energy_floor)
            continue; /* below noise floor: silent frame */

        res->active_frames++;

        /* Goertzel power at target frequency for this frame. */
        int64_t power = s1 * s1 + s2 * s2 - ((coeff_q15 * s1) >> 15) * s2;
        if (power < 0)
            power = 0;

        if (power >= energy * (int64_t)cfg->tone_ratio_min)
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
