/*
 * Honest Ear — standalone detector CLI (no crypto). Runs the SAME detector
 * source the TA compiles, over a PCM file, and prints the classification.
 * Useful for tuning/inspection and as a crypto-free smoke test.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "he_detector.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <pcm_s16le_mono>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", argv[1]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || (sz % 2) != 0) {
        fprintf(stderr, "bad PCM (need a positive, even byte count)\n");
        fclose(f);
        return 1;
    }
    int16_t *pcm = malloc((size_t)sz ? (size_t)sz : 1);
    if (!pcm || fread(pcm, 1, (size_t)sz, f) != (size_t)sz) {
        fprintf(stderr, "read error\n");
        fclose(f);
        free(pcm);
        return 1;
    }
    fclose(f);

    he_detector_config_t cfg;
    he_detector_default_config(&cfg);
    he_detect_result_t res;
    he_detector_run(&cfg, pcm, (size_t)sz / 2, &res);

    const char *evname = he_event_name(res.event);
    printf("event=%s presence=%u voice_active=%u frames=%u active=%u tone=%u voice=%u\n",
           evname, res.presence, res.voice_active, res.frames,
           res.active_frames, res.tone_frames, res.voice_frames);
    free(pcm);
    return 0;
}
