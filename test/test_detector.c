/*
 * Unit test: the in-enclave detector classifies synthetic signals correctly.
 * Generates silence, a 3100 Hz alarm tone, and broadband "voice-like" audio
 * in memory and asserts the predicate. Tones/noise are generated with libm
 * (test-only); the detector under test remains integer-only.
 */
#include <math.h>
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "he_detector.h"

static int fails = 0;
#define SR 16000
#define DUR_S 1
#define N (SR * DUR_S)

static void check(int cond, const char *msg)
{
    if (!cond) {
        printf("  FAIL: %s\n", msg);
        fails++;
    } else {
        printf("  ok:   %s\n", msg);
    }
}

/* Simple deterministic LCG so "noise" is reproducible. */
static uint32_t rng = 0x12345678u;
static int16_t noise_sample(int amp)
{
    rng = rng * 1664525u + 1013904223u;
    int v = (int)((rng >> 16) & 0xffff) - 32768;
    return (int16_t)((v * amp) / 32768);
}

int main(void)
{
    printf("test_detector:\n");
    he_detector_config_t cfg;
    he_detector_default_config(&cfg);
    he_detect_result_t res;

    int16_t *buf = malloc(N * sizeof(int16_t));
    if (!buf) {
        printf("  FAIL: alloc\n");
        return 1;
    }

    /* 1) Silence -> NONE, no presence. */
    memset(buf, 0, N * sizeof(int16_t));
    he_detector_run(&cfg, buf, N, &res);
    check(res.event == HE_EVENT_NONE, "silence => NONE");
    check(res.presence == 0, "silence => no presence");

    /* 2) Pure 3100 Hz tone -> ALARM_TONE. */
    for (int i = 0; i < N; i++)
        buf[i] = (int16_t)(12000.0 * sin(2.0 * M_PI * 3100.0 * i / SR));
    he_detector_run(&cfg, buf, N, &res);
    check(res.event == HE_EVENT_ALARM_TONE, "3100Hz tone => ALARM_TONE");
    check(res.presence == 1, "tone => presence");
    check(res.tone_frames > res.voice_frames, "tone => tone frames dominate");

    /* 3) Broadband noise (voice-like, no dominant tone) -> VOICE. */
    for (int i = 0; i < N; i++)
        buf[i] = noise_sample(14000);
    he_detector_run(&cfg, buf, N, &res);
    check(res.event == HE_EVENT_VOICE, "broadband => VOICE");
    check(res.voice_active == 1, "broadband => voice_active");
    check(res.voice_frames > res.tone_frames, "broadband => voice frames dominate");

    /* 4) Low-amplitude noise below the floor -> NONE (privacy: quiet room). */
    for (int i = 0; i < N; i++)
        buf[i] = noise_sample(150);
    he_detector_run(&cfg, buf, N, &res);
    check(res.event == HE_EVENT_NONE, "quiet noise below floor => NONE");

    /* 5) An off-target tone (700 Hz) must NOT register as the alarm tone. */
    for (int i = 0; i < N; i++)
        buf[i] = (int16_t)(12000.0 * sin(2.0 * M_PI * 700.0 * i / SR));
    he_detector_run(&cfg, buf, N, &res);
    check(res.event != HE_EVENT_ALARM_TONE, "700Hz tone => not ALARM_TONE");

    /* 5b) An alarm that sits OFF the nominal 3100 Hz center (real UL-217 alarms
     * drift across ~3000-3400 Hz) is still detected, thanks to the probe band —
     * a single 3100 Hz bin would under-detect it. */
    for (int i = 0; i < N; i++)
        buf[i] = (int16_t)(12000.0 * sin(2.0 * M_PI * 3300.0 * i / SR));
    he_detector_run(&cfg, buf, N, &res);
    check(res.event == HE_EVENT_ALARM_TONE, "3300Hz off-center alarm => ALARM_TONE (probe band)");

    /* 6) Buffer shorter than one frame -> zero frames, NONE, no crash. */
    memset(buf, 0x7f, 100 * sizeof(int16_t));
    he_detector_run(&cfg, buf, 100, &res);
    check(res.frames == 0 && res.event == HE_EVENT_NONE,
          "sub-frame buffer => 0 frames, NONE");

    /* 7) Full-scale clipping tone must not overflow the integer Goertzel. */
    for (int i = 0; i < N; i++)
        buf[i] = (int16_t)(i % 2 ? 32767 : -32768); /* worst-case amplitude */
    he_detector_run(&cfg, buf, N, &res);
    check(res.presence == 1, "full-scale signal => presence (no overflow/crash)");
    check(res.frames == (uint32_t)(N / 256), "frame count is n/frame_samples");

    /* 8) Energy-floor threshold: 1792>>6=28 -> 256*28^2=200704 >= floor (active);
     *    1728>>6=27 -> 256*27^2=186624 < floor (silent). Pins the strict '<'. */
    for (int i = 0; i < N; i++) buf[i] = 1792;
    he_detector_run(&cfg, buf, N, &res);
    check(res.presence == 1 && res.active_frames == res.frames,
          "energy just above floor => active");
    for (int i = 0; i < N; i++) buf[i] = 1728;
    he_detector_run(&cfg, buf, N, &res);
    check(res.presence == 0 && res.active_frames == 0,
          "energy just below floor => silent");

    /* 9) Non-multiple length: a tail shorter than a frame is dropped. */
    he_detector_run(&cfg, buf, 256 + 100, &res);
    check(res.frames == 1, "356 samples => 1 frame (tail dropped)");

    /* 10) Config blob is byte-stable (locks the policy bound into config_hash;
     *     also guards the shared big-endian serializer against regressions). */
    static const uint8_t cfg_golden[HE_CONFIG_BLOB_LEN] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x80, /* sample_rate=16000 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, /* frame_samples=256 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x1C, /* tone_freq_hz=3100 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, /* input_shift=6 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x0D, 0x40, /* energy_floor=200000 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, /* min_active_frames=8 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, /* tone_ratio_min=40 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, /* tone_bins=3 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC8, /* tone_band_hz=200 */
    };
    uint8_t cfg_blob[HE_CONFIG_BLOB_LEN];
    size_t cfg_blob_len = he_detector_config_blob(&cfg, cfg_blob, sizeof(cfg_blob));
    check(cfg_blob_len == HE_CONFIG_BLOB_LEN &&
              memcmp(cfg_blob, cfg_golden, HE_CONFIG_BLOB_LEN) == 0,
          "default config blob matches golden (be64 + field order)");

    free(buf);
    if (fails) {
        printf("test_detector: %d FAILURE(S)\n", fails);
        return 1;
    }
    printf("test_detector: all passed\n");
    return 0;
}
