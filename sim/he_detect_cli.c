/*
 * Honest Ear — standalone detector CLI (no crypto). Runs the SAME detector
 * source the TA compiles, over a PCM file, and prints the classification.
 * Useful for tuning/inspection and as a crypto-free smoke test.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "he_detector.h"
#include "he_pcm.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <pcm_s16le_mono>\n", argv[0]);
        return 2;
    }
    int16_t *pcm = NULL;
    size_t n_samples = 0;
    if (he_read_pcm(argv[1], &pcm, &n_samples)) {
        fprintf(stderr, "cannot read PCM file %s (need a readable, even byte count)\n", argv[1]);
        return 1;
    }

    he_detector_config_t cfg;
    he_detector_default_config(&cfg);
    he_detect_result_t res;
    he_detector_run(&cfg, pcm, n_samples, &res);

    const char *evname = he_event_name(res.event);
    printf("event=%s presence=%u voice_active=%u frames=%u active=%u tone=%u voice=%u\n",
           evname, res.presence, res.voice_active, res.frames,
           res.active_frames, res.tone_frames, res.voice_frames);
    free(pcm);
    return 0;
}
